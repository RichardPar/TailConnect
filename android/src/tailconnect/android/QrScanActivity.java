package tailconnect.android;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.ImageFormat;
import android.graphics.Matrix;
import android.graphics.SurfaceTexture;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.hardware.display.DisplayManager;
import android.media.Image;
import android.media.ImageReader;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Size;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.Surface;
import android.view.TextureView;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * A full-screen camera view that looks for a QR code in every frame (with
 * {@link QrDecoder}) and returns its text as {@link #EXTRA_TEXT}. Uses the
 * back camera; asks for the camera permission itself.
 */
public class QrScanActivity extends Activity {
    static final String EXTRA_TEXT = "text";
    private static final int REQ_CAMERA = 1;

    private TextureView preview;
    private TextView hint;
    private HandlerThread thread;
    private Handler bg;
    private CameraDevice camera;
    private CameraCaptureSession session;
    private ImageReader reader;
    private Size size;
    private int sensorOrientation;
    private volatile boolean busy, done;
    private DisplayManager.DisplayListener rotation;

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(0xFF000000);
        preview = new TextureView(this);
        root.addView(preview, new FrameLayout.LayoutParams(-1, -1));

        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.VERTICAL);
        bar.setGravity(Gravity.CENTER_HORIZONTAL);
        bar.setBackgroundColor(0x99000000);
        int pad = dp(16);
        bar.setPadding(pad, pad, pad, pad);
        hint = new TextView(this);
        hint.setText("Point the camera at the auth key's QR code in the web portal.");
        hint.setTextColor(0xFFFFFFFF);
        hint.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        hint.setGravity(Gravity.CENTER);
        bar.addView(hint);
        Button cancel = new Button(this);
        cancel.setText("Cancel");
        cancel.setOnClickListener(v -> finish());
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-2, -2);
        lp.topMargin = dp(8);
        bar.addView(cancel, lp);
        root.addView(bar, new FrameLayout.LayoutParams(-1, -2, Gravity.BOTTOM));
        setContentView(root);

        preview.setSurfaceTextureListener(new TextureView.SurfaceTextureListener() {
            @Override public void onSurfaceTextureAvailable(SurfaceTexture s, int w, int h) { start(); }
            @Override public void onSurfaceTextureSizeChanged(SurfaceTexture s, int w, int h) { fitPreview(); }
            @Override public boolean onSurfaceTextureDestroyed(SurfaceTexture s) { return true; }
            @Override public void onSurfaceTextureUpdated(SurfaceTexture s) {}
        });
        // A 180° turn changes neither the configuration nor the view's size.
        rotation = new DisplayManager.DisplayListener() {
            @Override public void onDisplayAdded(int id) {}
            @Override public void onDisplayRemoved(int id) {}
            @Override public void onDisplayChanged(int id) { fitPreview(); }
        };
    }

    @Override
    protected void onResume() {
        super.onResume();
        ((DisplayManager) getSystemService(Context.DISPLAY_SERVICE)).registerDisplayListener(rotation, null);
        thread = new HandlerThread("qr-camera");
        thread.start();
        bg = new Handler(thread.getLooper());
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.CAMERA}, REQ_CAMERA);
            return;
        }
        if (preview.isAvailable()) start();
    }

    @Override
    protected void onPause() {
        ((DisplayManager) getSystemService(Context.DISPLAY_SERVICE)).unregisterDisplayListener(rotation);
        stop();
        thread.quitSafely();
        thread = null;
        bg = null;
        super.onPause();
    }

    @Override
    public void onRequestPermissionsResult(int request, String[] perms, int[] results) {
        if (request != REQ_CAMERA) return;
        if (results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED) {
            if (preview.isAvailable()) start();
        } else {
            hint.setText("TailConnect needs the camera to read the QR code. Allow it in Settings, or type the key in.");
        }
    }

    // ---- the camera ----

    private void start() {
        if (camera != null || bg == null || done) return;
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) return;
        CameraManager cm = (CameraManager) getSystemService(Context.CAMERA_SERVICE);
        try {
            String id = pickCamera(cm);
            if (id == null) {
                hint.setText("This device has no camera that can be used.");
                return;
            }
            CameraCharacteristics cc = cm.getCameraCharacteristics(id);
            Integer so = cc.get(CameraCharacteristics.SENSOR_ORIENTATION);
            sensorOrientation = so != null ? so : 90;
            StreamConfigurationMap map = cc.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
            size = pickSize(map);
            int[] af = cc.get(CameraCharacteristics.CONTROL_AF_AVAILABLE_MODES);
            boolean continuousAf = af != null && Arrays.stream(af).anyMatch(m -> m == CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE);

            reader = ImageReader.newInstance(size.getWidth(), size.getHeight(), ImageFormat.YUV_420_888, 2);
            reader.setOnImageAvailableListener(this::onFrame, bg);
            cm.openCamera(id, new CameraDevice.StateCallback() {
                @Override public void onOpened(CameraDevice d) {
                    camera = d;
                    startSession(continuousAf);
                }
                @Override public void onDisconnected(CameraDevice d) {
                    d.close();
                    if (camera == d) camera = null;
                }
                @Override public void onError(CameraDevice d, int error) {
                    d.close();
                    if (camera == d) camera = null;
                    runOnUiThread(() -> hint.setText("The camera couldn't be opened (it may be in use by another app)."));
                }
            }, bg);
            runOnUiThread(this::fitPreview);
        } catch (CameraAccessException | SecurityException | IllegalArgumentException e) {
            hint.setText("The camera couldn't be opened: " + e.getMessage());
        }
    }

    private void startSession(boolean continuousAf) {
        try {
            SurfaceTexture st = preview.getSurfaceTexture();
            if (st == null || camera == null) return;
            st.setDefaultBufferSize(size.getWidth(), size.getHeight());
            Surface view = new Surface(st), frames = reader.getSurface();
            CaptureRequest.Builder req = camera.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW);
            req.addTarget(view);
            req.addTarget(frames);
            if (continuousAf) req.set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE);
            CameraDevice dev = camera;
            dev.createCaptureSession(Arrays.asList(view, frames), new CameraCaptureSession.StateCallback() {
                @Override public void onConfigured(CameraCaptureSession s) {
                    if (camera != dev) { s.close(); return; }
                    session = s;
                    try {
                        s.setRepeatingRequest(req.build(), null, bg);
                    } catch (CameraAccessException | IllegalStateException e) {
                        // closed while starting: onPause tidies up
                    }
                }
                @Override public void onConfigureFailed(CameraCaptureSession s) {
                    runOnUiThread(() -> hint.setText("The camera couldn't be started."));
                }
            }, bg);
        } catch (CameraAccessException | IllegalStateException e) {
            runOnUiThread(() -> hint.setText("The camera couldn't be started: " + e.getMessage()));
        }
    }

    private void stop() {
        if (session != null) { session.close(); session = null; }
        if (camera != null) { camera.close(); camera = null; }
        if (reader != null) { reader.close(); reader = null; }
    }

    /** The back camera, or failing that any camera. */
    private static String pickCamera(CameraManager cm) throws CameraAccessException {
        String any = null;
        for (String id : cm.getCameraIdList()) {
            Integer facing = cm.getCameraCharacteristics(id).get(CameraCharacteristics.LENS_FACING);
            if (facing != null && facing == CameraCharacteristics.LENS_FACING_BACK) return id;
            if (any == null) any = id;
        }
        return any;
    }

    /**
     * The largest size up to 1920×1080 that both the preview and the frame
     * reader support: enough detail for a dense code, quick to scan.
     */
    private static Size pickSize(StreamConfigurationMap map) {
        Set<Size> views = new HashSet<>(Arrays.asList(map.getOutputSizes(SurfaceTexture.class)));
        Size best = null;
        for (Size s : map.getOutputSizes(ImageFormat.YUV_420_888)) {
            if (!views.contains(s) || s.getWidth() * s.getHeight() > 1920 * 1080) continue;
            if (best == null || s.getWidth() * s.getHeight() > best.getWidth() * best.getHeight()) best = s;
        }
        return best != null ? best : new Size(640, 480);
    }

    /**
     * Shows the preview upright and undistorted, filling the screen. The
     * view stretches the camera's picture (already turned for the device's
     * natural orientation) to its own shape; this undoes the stretch, turns
     * it for the current rotation and scales it to cover the view.
     */
    private void fitPreview() {
        if (size == null) return;
        float W = preview.getWidth(), H = preview.getHeight();
        if (W == 0 || H == 0) return;
        boolean sideways = sensorOrientation % 180 != 0;
        float nw = sideways ? size.getHeight() : size.getWidth(), nh = sideways ? size.getWidth() : size.getHeight();
        int deg = 90 * getDisplay().getRotation();
        float cw = deg % 180 == 0 ? nw : nh, ch = deg % 180 == 0 ? nh : nw;
        float cx = W / 2, cy = H / 2, s = Math.max(W / cw, H / ch);
        Matrix m = new Matrix();
        m.postScale(nw / W, nh / H, cx, cy);
        m.postRotate(-deg, cx, cy);
        m.postScale(s, s, cx, cy);
        preview.setTransform(m);
    }

    // ---- reading frames ----

    /** Copies a frame's brightness and looks for a code, skipping frames while busy. */
    private void onFrame(ImageReader r) {
        Image img = r.acquireLatestImage();
        if (img == null) return;
        if (busy || done) { img.close(); return; }
        Image.Plane y = img.getPlanes()[0];
        int w = img.getWidth(), h = img.getHeight();
        int rowStride = y.getRowStride(), pixStride = y.getPixelStride();
        ByteBuffer buf = y.getBuffer();
        byte[] lum = new byte[w * h];
        if (pixStride == 1) {
            for (int row = 0; row < h; row++) {
                buf.position(row * rowStride);
                buf.get(lum, row * w, w);
            }
        } else {
            for (int row = 0; row < h; row++)
                for (int col = 0; col < w; col++) lum[row * w + col] = buf.get(row * rowStride + col * pixStride);
        }
        img.close();
        busy = true;
        // Decode on a second thread, so the camera's thread keeps dropping stale frames.
        new Thread(() -> {
            String text = QrDecoder.decode(lum, w, h, w);
            busy = false;
            if (text != null && !done) {
                done = true;
                runOnUiThread(() -> {
                    setResult(RESULT_OK, new Intent().putExtra(EXTRA_TEXT, text));
                    finish();
                });
            }
        }, "qr-decode").start();
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
