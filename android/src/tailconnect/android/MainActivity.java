package tailconnect.android;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.graphics.Rect;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.DateFormat;
import java.util.Date;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The TailConnect screen. It tells phones from tablets (see {@link Form}): a
 * tablet with room shows the connection and the devices side by side; phones
 * and narrow tablet windows get one scrolling column. It re-lays itself out
 * when the window changes (rotation, split-screen), keeping what was typed.
 */
public class MainActivity extends Activity {
    private static final int REQ_VPN = 1, REQ_QR = 2;
    private static final long POLL_MS = 1500;
    // A peer counts as busy (brighter panel) when more than this many bytes
    // moved since the previous poll; a lone 32-byte keepalive doesn't count.
    private static final long BUSY_BYTES = 100;
    /** Each peer's Rx+Tx byte total at the previous poll, by node key. */
    private final Map<String, Long> lastBytes = new HashMap<>();
    private static final int GREEN = 0xFF2E9E5B, AMBER = 0xFFE0A030, GREY = 0xFF8A8A8A, RED = 0xFFD9453B,
            BLUE = 0xFF3B7DD8;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final ExecutorService io = Executors.newSingleThreadExecutor();
    private SharedPreferences prefs;

    private TextView stateText, selfName, selfAddr, errorText, peersTitle, logText;
    private View stateDot;
    // What the join pop-up holds (the auth key only until it is sent).
    private String joinServer = "", joinKey = "", joinHost = "";
    private AlertDialog loginDialog; // the join pop-up while it's open
    private Button connect, logout, showLog;
    private LinearLayout peers;
    private ScrollView logScroll; // two panes only: the log's own scroll
    private View logBox;          // what to show or hide for the log
    private Form form;
    private JSONObject lastStatus;
    private boolean running, polling, logShown;
    // joined: this device is a member of a network (the daemon's saved state
    // says so), so it needs no login and its name is fixed. joining: a join
    // with an auth key is in progress.
    private boolean joined, joining;
    // What the daemon saved last time it ran (see readSaved), for when it isn't running.
    private Saved disk;
    // A self-signed server certificate's fingerprint to pin (from a QR code,
    // or trusted by the user), the auth key of the last attempt (kept in
    // memory only, to retry once the certificate is trusted), and the
    // fingerprint last asked about (to ask only once).
    private String tlsFp = "", retryKey = "", askedFp = "";
    private static final Pattern FP_HINT = Pattern.compile("--tls-fingerprint (sha256:[A-Za-z0-9_-]{43})");

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        prefs = getSharedPreferences("settings", MODE_PRIVATE);
        disk = readSaved();
        joined = disk.registered;
        setContentView(buildLayout());
        joinServer = prefs.getString("server", "");
        joinHost = prefs.getString("hostname", defaultHostname());
        prefill(getIntent());
        // Not a member yet: go straight to the join pop-up.
        if (!joined && saved == null && loginDialog == null) showLogin();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        prefill(intent);
    }

    /**
     * Fills in the form from the launching intent, for setting a device up
     * over USB:  adb shell am start -n tailconnect.android/.MainActivity
     * -e server http://… -e authkey tc-auth-… -e hostname tablet
     * The user still presses Connect (and approves the VPN).
     */
    private void prefill(Intent i) {
        if (i == null) return;
        Uri link = i.getData();
        if (link != null && "tailconnect".equals(link.getScheme()) && "join".equals(link.getHost())) {
            if (joined) {
                Toast.makeText(this, "This device has already joined a network. Log out first to join with this code.", Toast.LENGTH_LONG).show();
                return;
            }
            applyJoinLink(link);
            return;
        }
        String v;
        if (joined) return; // the login form isn't used once joined
        boolean any = false;
        if ((v = i.getStringExtra("server")) != null) { joinServer = v; any = true; }
        if ((v = i.getStringExtra("authkey")) != null) { joinKey = v; any = true; }
        if ((v = i.getStringExtra("hostname")) != null) { joinHost = v; any = true; }
        if ((v = i.getStringExtra("fp")) != null) tlsFp = v.trim();
        if (any) showLogin();
    }

    @Override
    protected void onResume() {
        super.onResume();
        polling = true;
        poll();
    }

    @Override
    protected void onPause() {
        super.onPause();
        polling = false;
    }

    // ---- layout ----

    /** How the screen is laid out. */
    enum Form {
        /** A phone: one compact, scrolling column; devices below the form. */
        PHONE,
        /** A tablet with a narrow window (portrait split-screen, a small pop-up): one column. */
        TABLET_ONE_COLUMN,
        /** A tablet with room for two panes: the connection on the left, devices on the right. */
        TABLET_TWO_PANES
    }

    /**
     * Phone or tablet goes by the whole display's smallest side, 600 dp and up
     * being a tablet (Android's own rule for tablet layouts), so a tablet in a
     * narrow split-screen window is still a tablet. Whether two panes fit goes
     * by the window's current width.
     */
    private Form formFor(Configuration c) {
        if (deviceSmallestWidthDp() < 600) return Form.PHONE;
        return c.screenWidthDp >= 720 ? Form.TABLET_TWO_PANES : Form.TABLET_ONE_COLUMN;
    }

    private int deviceSmallestWidthDp() {
        float density = getResources().getDisplayMetrics().density;
        int w, h;
        if (Build.VERSION.SDK_INT >= 30) {
            Rect b = getWindowManager().getMaximumWindowMetrics().getBounds();
            w = b.width();
            h = b.height();
        } else {
            DisplayMetrics m = new DisplayMetrics();
            getWindowManager().getDefaultDisplay().getRealMetrics(m);
            w = m.widthPixels;
            h = m.heightPixels;
        }
        return Math.round(Math.min(w, h) / density);
    }

    @Override
    public void onConfigurationChanged(Configuration c) {
        super.onConfigurationChanged(c);
        if (formFor(c) != form) rebuild();
    }

    /** Lays the screen out again for the current form, keeping what was typed. */
    private void rebuild() {
        CharSequence err = errorText.getText();
        setContentView(buildLayout());
        setError(err.toString());
        if (logShown) setLogShown(true);
        show(lastStatus);
    }

    private View buildLayout() {
        form = formFor(getResources().getConfiguration());
        boolean phone = form == Form.PHONE, twoPanes = form == Form.TABLET_TWO_PANES;
        boolean compact = phone || getResources().getConfiguration().screenWidthDp < 600;
        int pad = dp(compact ? 16 : 40);

        // The connection: state, this device, the form.
        LinearLayout conn = column();
        LinearLayout stateRow = new LinearLayout(this);
        stateRow.setGravity(Gravity.CENTER_VERTICAL);
        stateDot = new View(this);
        stateRow.addView(stateDot, new LinearLayout.LayoutParams(dp(compact ? 12 : 14), dp(compact ? 12 : 14)));
        stateText = text("Starting…", compact ? 18 : 20, false);
        stateText.setPadding(dp(10), 0, 0, 0);
        stateRow.addView(stateText);
        conn.addView(stateRow);
        selfName = text("", compact ? 16 : 18, true);
        selfAddr = text("", compact ? 14 : 16, false);
        selfAddr.setTypeface(Typeface.MONOSPACE);
        selfAddr.setTextIsSelectable(true);
        conn.addView(selfName, margins(0, dp(compact ? 12 : 20), 0, 0));
        conn.addView(selfAddr);


        connect = new Button(this);
        connect.setTextSize(TypedValue.COMPLEX_UNIT_SP, compact ? 16 : 18);
        connect.setOnClickListener(v -> onConnectClicked());
        conn.addView(connect, margins(0, dp(compact ? 16 : 24), 0, 0));
        logout = new Button(this, null, android.R.attr.borderlessButtonStyle);
        logout.setText("Log out of this network");
        logout.setOnClickListener(v -> confirmLogout());
        conn.addView(logout);
        errorText = text("", compact ? 14 : 15, false);
        errorText.setTextColor(RED);
        conn.addView(errorText, margins(0, dp(8), 0, 0));
        TextView version = text(versionLine(), compact ? 12 : 13, false);
        version.setAlpha(0.6f);
        version.setTextIsSelectable(true);
        conn.addView(version, margins(0, dp(compact ? 16 : 28), 0, 0));

        // The other devices, and the log.
        LinearLayout header = new LinearLayout(this);
        header.setGravity(Gravity.CENTER_VERTICAL);
        peersTitle = text("Devices", compact ? 20 : 22, true);
        header.addView(peersTitle, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        showLog = new Button(this, null, android.R.attr.borderlessButtonStyle);
        showLog.setText("Show log");
        showLog.setOnClickListener(v -> setLogShown(!logShown));
        header.addView(showLog);
        TextView hint = text("Tap a device to copy its address.", compact ? 13 : 14, false);
        hint.setAlpha(0.7f);
        peers = column();
        logText = text("", compact ? 11 : 12, false);
        logText.setTypeface(Typeface.MONOSPACE);
        logText.setTextIsSelectable(true);

        if (twoPanes) {
            LinearLayout root = new LinearLayout(this);
            root.setOrientation(LinearLayout.HORIZONTAL);
            root.setPadding(pad, pad, pad, pad);
            ScrollView left = new ScrollView(this);
            left.addView(conn);
            root.addView(left, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 2));
            root.addView(new View(this), new LinearLayout.LayoutParams(dp(48), 1));
            LinearLayout right = column();
            right.addView(header);
            right.addView(hint);
            ScrollView peerScroll = new ScrollView(this);
            peerScroll.addView(peers);
            right.addView(peerScroll, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
            logScroll = new ScrollView(this);
            logScroll.addView(logText);
            logBox = logScroll;
            right.addView(logScroll, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
            root.addView(right, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 3));
            logBox.setVisibility(View.GONE);
            return root;
        }

        // One column (phones, narrow tablet windows): everything in one
        // scroll, the devices below the form.
        LinearLayout col = column();
        col.setPadding(pad, pad, pad, pad);
        col.addView(conn);
        col.addView(header, margins(0, dp(compact ? 20 : 32), 0, 0));
        col.addView(hint);
        col.addView(peers);
        logScroll = null;
        logBox = logText;
        col.addView(logText, margins(0, dp(12), 0, 0));
        logBox.setVisibility(View.GONE);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(col);
        return scroll;
    }

    /**
     * Fills in the join pop-up from a tailconnect://join link (an auth key's
     * QR code) and shows it. Never connects by itself: the user checks the
     * server (a link can come from anywhere) and taps Join.
     */
    private void applyJoinLink(Uri link) {
        String s = link.getQueryParameter("server"), k = link.getQueryParameter("key"), h = link.getQueryParameter("hostname");
        String fp = link.getQueryParameter("fp");
        if (fp != null) tlsFp = fp.trim();
        if (s != null && !s.isEmpty()) joinServer = s;
        if (k != null && !k.isEmpty()) joinKey = k;
        if (h != null && !h.isEmpty()) joinHost = h;
        Toast.makeText(this, "Filled in from the QR code" + (s != null ? " for " + s : "") + ". Check the name and tap Join.", Toast.LENGTH_LONG).show();
        showLogin();
    }

    /** What the camera read: a join link, or just an auth key. */
    private void onQrScanned(String text) {
        text = text.trim();
        Uri link = Uri.parse(text);
        if ("tailconnect".equals(link.getScheme()) && "join".equals(link.getHost())) {
            applyJoinLink(link);
            return;
        }
        if (text.startsWith("tc-auth-") && !text.contains(" ")) {
            joinKey = text;
            Toast.makeText(this, "Auth key read from the QR code.", Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(this, "That QR code isn't a TailConnect auth key.", Toast.LENGTH_LONG).show();
        }
        showLogin();
    }

    // ---- actions ----

    private void onConnectClicked() {
        if (running) {
            service(TcVpnService.ACTION_DISCONNECT);
            return;
        }
        if (!joined) {
            showLogin();
            return;
        }
        prepareAndConnect();
    }

    /** Asks (once) for permission to run a VPN, then connects. */
    private void prepareAndConnect() {
        Intent consent = VpnService.prepare(this); // asks once for permission to run a VPN
        if (consent != null) startActivityForResult(consent, REQ_VPN);
        else startConnect();
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == REQ_VPN) {
            if (result == RESULT_OK) startConnect();
            else setError("TailConnect needs permission to create a VPN.");
        } else if (request == REQ_QR && !joined) {
            String text = data != null ? data.getStringExtra(QrScanActivity.EXTRA_TEXT) : null;
            if (result == RESULT_OK && text != null) onQrScanned(text);
            else showLogin(); // cancelled: back to the form as it was
        }
    }

    private void startConnect() {
        setError("");
        TcVpnService.lastError = "";
        // Once joined, the daemon reconnects with what it saved: no server,
        // key or name is sent, so the device name can't change.
        String srv = "", key = "", host = "";
        if (!joined) {
            srv = joinServer;
            host = joinHost;
            key = joinKey;
            if (key.isEmpty()) key = retryKey;
            retryKey = key;
            joining = true;
        }
        Intent i = new Intent(this, TcVpnService.class).setAction(TcVpnService.ACTION_CONNECT)
                .putExtra(TcVpnService.EXTRA_SERVER, srv)
                .putExtra(TcVpnService.EXTRA_AUTHKEY, key)
                .putExtra(TcVpnService.EXTRA_HOSTNAME, host)
                .putExtra(TcVpnService.EXTRA_FP, tlsFp);
        startService(i);
        joinKey = ""; // used once; never stored
        stateText.setText(joined ? "Connecting…" : "Joining…");
        setDot(AMBER);
    }

    /**
     * The join pop-up: server, auth key and device name. It stays open until
     * all three are filled in; the name is fixed once the device has joined.
     */
    private void showLogin() {
        if (joined || isFinishing()) return;
        if (loginDialog != null) loginDialog.dismiss();
        LinearLayout box = column();
        int pad = dp(24), gap = dp(10);
        box.setPadding(pad, dp(8), pad, 0);
        box.addView(label("Server"));
        EditText srv = field("https://tailconnect.example.org:8443", InputType.TYPE_TEXT_VARIATION_URI, true);
        srv.setText(joinServer);
        box.addView(srv);
        box.addView(label("Auth key"), margins(0, gap, 0, 0));
        EditText key = field("tc-auth-…", InputType.TYPE_TEXT_VARIATION_PASSWORD, true);
        key.setText(joinKey.isEmpty() ? retryKey : joinKey);
        box.addView(key);
        Button scan = null;
        if (getPackageManager().hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)) {
            scan = new Button(this);
            scan.setText("Read QR from Camera");
            box.addView(scan, margins(0, dp(4), 0, 0));
        }
        box.addView(label("Device name"), margins(0, gap, 0, 0));
        EditText host = field(form == Form.PHONE ? "phone" : "tablet", InputType.TYPE_TEXT_VARIATION_NORMAL, true);
        host.setText(joinHost);
        box.addView(host);
        TextView note = text("The name can't be changed after joining (log out and join again to rename).", 13, false);
        note.setAlpha(0.7f);
        box.addView(note, margins(0, gap, 0, 0));
        TextView err = text("", 14, false);
        err.setTextColor(RED);
        err.setVisibility(View.GONE);
        box.addView(err, margins(0, gap, 0, 0));
        ScrollView scroll = new ScrollView(this);
        scroll.addView(box);

        AlertDialog d = new AlertDialog.Builder(this)
                .setTitle("Join a network")
                .setView(scroll)
                .setPositiveButton("Join", null) // set below, so a bad entry keeps it open
                .setNegativeButton("Cancel", null)
                .create();
        d.setOnDismissListener(x -> {
            if (loginDialog == d) loginDialog = null;
        });
        if (scan != null) scan.setOnClickListener(v -> {
            // Keep what's typed; the pop-up is shown again after scanning.
            joinServer = srv.getText().toString().trim();
            joinKey = key.getText().toString().trim();
            joinHost = host.getText().toString().trim();
            d.dismiss();
            startActivityForResult(new Intent(this, QrScanActivity.class), REQ_QR);
        });
        d.setOnShowListener(x -> d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String u = srv.getText().toString().trim(), k = key.getText().toString().trim(), h = host.getText().toString().trim();
            String problem = u.isEmpty() ? "Enter the server's address."
                    : k.isEmpty() ? "Enter an auth key (create one in the web portal)."
                    : h.isEmpty() ? "Enter a name for this device." : "";
            if (!problem.isEmpty()) {
                err.setText(problem);
                err.setVisibility(View.VISIBLE);
                return;
            }
            joinServer = u;
            joinKey = k;
            joinHost = h;
            prefs.edit().putString("server", u).putString("hostname", h).apply();
            d.dismiss();
            prepareAndConnect();
        }));
        loginDialog = d;
        d.show();
    }

    private void confirmLogout() {
        new AlertDialog.Builder(this)
                .setTitle("Log out of this network?")
                .setMessage("This device leaves the network. To join again you'll need a new auth key, and you can then choose its name again.")
                .setPositiveButton("Log out", (d, w) -> {
                    service(TcVpnService.ACTION_LOGOUT);
                    stateText.setText("Logging out…");
                    setDot(AMBER);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void service(String action) {
        startService(new Intent(this, TcVpnService.class).setAction(action));
    }

    private void setLogShown(boolean show) {
        logShown = show;
        logBox.setVisibility(show ? View.VISIBLE : View.GONE);
        showLog.setText(show ? "Hide log" : "Show log");
        if (show) refreshLog();
    }

    // ---- status ----

    private void poll() {
        if (!polling) return;
        io.execute(() -> {
            JSONObject st = null;
            try {
                st = LocalApi.status(TcVpnService.socketPath(getFilesDir()));
            } catch (IOException ignored) {
                // Not running: the daemon only runs while connected.
            }
            JSONObject s = st;
            Saved sv = readSaved();
            ui.post(() -> {
                disk = sv;
                show(s);
                ui.postDelayed(this::poll, POLL_MS);
            });
        });
    }

    private void show(JSONObject st) {
        lastStatus = st;
        String state = st == null ? "Off" : st.optString("State");
        String err = TcVpnService.lastError;
        if (st != null && !st.optString("Error").isEmpty()) err = st.optString("Error");
        if (st != null && !st.optString("Notice").isEmpty()) err = st.optString("Notice");
        running = st != null && !state.equals("Stopped") && !state.equals("NeedsLogin");
        // The running daemon knows best; otherwise go by what it saved.
        boolean wasJoined = joined;
        joined = st != null ? !state.equals("NeedsLogin") : disk.registered;
        if (joined) {
            joining = false;
            retryKey = "";
        }
        if (err != null && !err.isEmpty()) joining = false;
        if (joined && loginDialog != null) loginDialog.dismiss();
        if (wasJoined && !joined && !disk.hostname.isEmpty()) joinHost = disk.hostname;
        offerTrust(err);
        if (!joined) {
            stateText.setText(joining ? "Joining…" : "Not joined");
            setDot(joining ? AMBER : GREY);
        } else if (state.equals("Running")) {
            stateText.setText("Connected");
            setDot(GREEN);
        } else if (state.equals("Starting")) {
            stateText.setText("Connecting…");
            setDot(AMBER);
        } else {
            stateText.setText("Disconnected");
            setDot(GREY);
        }
        connect.setText(running ? "Disconnect" : joined ? "Connect" : "Join network…");
        connect.setEnabled(!joining);
        logout.setVisibility(joined ? View.VISIBLE : View.GONE);
        setError(err);

        // This device: from the daemon, or what it saved when it isn't running.
        JSONObject self = st == null ? null : st.optJSONObject("Self");
        if (self == null && joined) self = disk.self;
        String name = self != null ? self.optString("Name") : joined ? disk.hostname : "";
        selfName.setText(name);
        selfAddr.setText(self == null ? "" : String.join("   ", addresses(self)));
        selfName.setVisibility(name.isEmpty() ? View.GONE : View.VISIBLE);
        selfAddr.setVisibility(self == null ? View.GONE : View.VISIBLE);

        peers.removeAllViews();
        JSONArray ps = st == null ? null : st.optJSONArray("Peers");
        int n = ps == null ? 0 : ps.length();
        peersTitle.setText(n == 0 ? "Devices" : "Devices (" + n + ")");
        if (n == 0) {
            TextView none = text(running ? "No other devices yet." : joined ? "Connect to see your devices." : "Join a network to see your devices.", 16, false);
            none.setAlpha(0.7f);
            peers.addView(none, margins(0, dp(16), 0, 0));
        }
        for (int i = 0; i < n; i++) peers.addView(peerRow(ps.optJSONObject(i)));
        if (logShown) refreshLog();
    }

    private View peerRow(JSONObject p) {
        LinearLayout row = column();
        row.setPadding(dp(16), dp(12), dp(16), dp(12));
        // The panel's colour is the path from this device: grey idle, green
        // direct, blue relay; brighter while traffic is flowing.
        long total = p.optLong("RxBytes") + p.optLong("TxBytes");
        Long prev = lastBytes.put(p.optString("NodeKey"), total);
        boolean busy = prev != null && total - prev > BUSY_BYTES;
        String[] path = path(p, busy);
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(12));
        bg.setColor(Integer.parseInt(path[1]));
        row.setBackground(bg);

        LinearLayout top = new LinearLayout(this);
        top.setGravity(Gravity.CENTER_VERTICAL);
        String name = p.optString("Name");
        String shortName = p.optString("HostName", name);
        TextView nameView = text(shortName, 18, true);
        top.addView(nameView, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        row.addView(top);

        List<String> addrs = addresses(p);
        String detail = (addrs.isEmpty() ? "" : addrs.get(0)) + "   " + name;
        if (p.optBoolean("Shared")) detail += "   shared by " + p.optString("User");
        TextView sub = text(detail, 14, false);
        sub.setAlpha(0.75f);
        row.addView(sub, margins(0, dp(4), 0, 0));

        String copy = addrs.isEmpty() ? name : addrs.get(0);
        row.setOnClickListener(v -> {
            ClipboardManager cm = getSystemService(ClipboardManager.class);
            cm.setPrimaryClip(ClipData.newPlainText("TailConnect address", copy));
            Toast.makeText(this, "Copied " + copy, Toast.LENGTH_SHORT).show();
        });
        row.setContentDescription(shortName + ", " + path[0]);
        LinearLayout.LayoutParams lp = margins(0, dp(10), 0, 0);
        row.setLayoutParams(lp);
        return row;
    }

    /**
     * The path from this device to a peer, for screen readers, and its panel
     * colour: a light tint of grey (idle), green (direct) or blue (relay),
     * stronger when busy (traffic flowed since the last poll).
     */
    private static String[] path(JSONObject p, boolean busy) {
        if (!p.optBoolean("Active")) return new String[]{"idle", String.valueOf(0x14808080)};
        int alpha = busy ? 0x90000000 : 0x40000000;
        String ep = p.optString("CurrentEndpoint");
        if (!ep.isEmpty()) {
            double ms = p.optDouble("LatencyMS", 0);
            String label = ms > 0 ? String.format(Locale.ROOT, "direct, %.0f ms", ms) : "direct";
            return new String[]{label, String.valueOf(GREEN & 0x00FFFFFF | alpha)};
        }
        return new String[]{"through the relay", String.valueOf(BLUE & 0x00FFFFFF | alpha)};
    }

    private static List<String> addresses(JSONObject n) {
        List<String> out = new ArrayList<>();
        JSONArray a = n.optJSONArray("Addresses");
        if (a != null) {
            for (int i = 0; i < a.length(); i++) {
                String s = a.optString(i);
                int slash = s.indexOf('/');
                out.add(slash < 0 ? s : s.substring(0, slash));
            }
        }
        return out;
    }

    private void refreshLog() {
        StringBuilder b = new StringBuilder();
        synchronized (TcVpnService.log) {
            for (String l : TcVpnService.log) b.append(l).append('\n');
        }
        logText.setText(b.length() == 0 ? "(nothing yet)" : b);
        if (logScroll != null) logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
    }

    /** The parts of the daemon's saved state (state/state.json) the screen needs. */
    private static final class Saved {
        boolean registered;
        String hostname = "";
        JSONObject self; // this device as the server last described it, or null
    }

    /** Reads the daemon's saved state; nothing saved reads as not joined. */
    private Saved readSaved() {
        Saved s = new Saved();
        File f = new File(new File(getFilesDir(), "state"), "state.json");
        try {
            JSONObject j = new JSONObject(new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8));
            s.registered = j.optBoolean("Registered");
            s.hostname = j.optString("Hostname");
            s.self = j.optJSONObject("Self");
        } catch (IOException | org.json.JSONException ignored) {
        }
        return s;
    }

    // ---- small helpers ----

    private String defaultHostname() {
        String m = Build.MODEL == null ? "tablet" : Build.MODEL;
        return m.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-").replaceAll("^-|-$", "");
    }

    /**
     * "Version v0.6.0-dev · build 458903 (15 Nov 2026, 16:23)". The build
     * number is minutes since 2026-01-01 UTC (android/build.sh), so it also
     * says when the app was built.
     */
    private String versionLine() {
        try {
            PackageInfo pi = getPackageManager().getPackageInfo(getPackageName(), 0);
            long build = pi.getLongVersionCode();
            String when = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
                    .format(new Date((1767225600L + build * 60) * 1000));
            return "Version " + pi.versionName + " · build " + build + " (" + when + ")";
        } catch (PackageManager.NameNotFoundException e) {
            return "";
        }
    }

    /**
     * The server's certificate isn't from a trusted authority: show its
     * fingerprint and offer to pin it, like SSH's first connection to a host.
     */
    private void offerTrust(String err) {
        if (err == null) return;
        Matcher m = FP_HINT.matcher(err);
        if (!m.find()) return;
        String fp = m.group(1);
        if (fp.equals(askedFp) || isFinishing()) return;
        askedFp = fp;
        new AlertDialog.Builder(this)
                .setTitle("Trust this server's certificate?")
                .setMessage("The server uses a certificate that isn't from a trusted authority, such as a self-signed one. Its fingerprint is:\n\n"
                        + fp + "\n\nCompare it with the one the web portal shows (Auth keys tab) or tc-control logs. Only trust it if they match.")
                .setPositiveButton("They match: trust it", (d, w) -> {
                    tlsFp = fp;
                    startConnect();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void setError(String msg) {
        errorText.setText(msg);
        errorText.setVisibility(msg == null || msg.isEmpty() ? View.GONE : View.VISIBLE);
    }

    private void setDot(int color) {
        GradientDrawable d = new GradientDrawable();
        d.setShape(GradientDrawable.OVAL);
        d.setColor(color);
        stateDot.setBackground(d);
    }

    private LinearLayout column() {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        return l;
    }

    private TextView text(String s, int sp, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    private TextView label(String s) {
        TextView t = text(s, 14, false);
        t.setAlpha(0.75f);
        return t;
    }

    private EditText field(String hint, int variation, boolean compact) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setSingleLine(true);
        e.setInputType(InputType.TYPE_CLASS_TEXT | variation);
        e.setTextSize(TypedValue.COMPLEX_UNIT_SP, compact ? 16 : 17);
        return e;
    }

    private LinearLayout.LayoutParams margins(int l, int t, int r, int b) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p.setMargins(l, t, r, b);
        return p;
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
