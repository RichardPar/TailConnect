package tailconnect.android;

import android.app.PendingIntent;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.net.Network;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Runs the TailConnect daemon (the Go program packaged as libtcd.so) and
 * provides what it can't do itself as an app process: the VPN interface, and
 * the underlying network's DNS servers and addresses. See
 * internal/androidbridge for the protocol.
 */
public class TcVpnService extends VpnService {
    static final String ACTION_CONNECT = "tailconnect.android.CONNECT";
    static final String ACTION_DISCONNECT = "tailconnect.android.DISCONNECT";
    static final String ACTION_LOGOUT = "tailconnect.android.LOGOUT";
    static final String EXTRA_SERVER = "server", EXTRA_AUTHKEY = "authkey", EXTRA_HOSTNAME = "hostname";
    private static final String TAG = "TailConnect";

    /** The last error from connecting, shown by the UI ("" = none). */
    static volatile String lastError = "";
    /** Recent daemon log lines, for the UI's log view. */
    static final ArrayDeque<String> log = new ArrayDeque<>();
    private static final int LOG_LINES = 300;

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private Process daemon;
    private LocalSocket bridge;
    private OutputStream bridgeOut;
    private ParcelFileDescriptor vpn;
    private ConnectivityManager.NetworkCallback networkCallback;
    private volatile String networkMessage; // last "network" message for the daemon

    static String socketPath(File filesDir) {
        return new File(filesDir, "tcd.sock").getPath();
    }

    static void addLog(String line) {
        synchronized (log) {
            log.addLast(line);
            while (log.size() > LOG_LINES) log.removeFirst();
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (ACTION_DISCONNECT.equals(action)) {
            worker.execute(() -> stop(false));
        } else if (ACTION_LOGOUT.equals(action)) {
            worker.execute(() -> stop(true));
        } else {
            // ACTION_CONNECT from the UI, or the system starting an always-on VPN
            // (then there are no extras: the daemon reconnects with its saved state).
            String server = extra(intent, EXTRA_SERVER), key = extra(intent, EXTRA_AUTHKEY), host = extra(intent, EXTRA_HOSTNAME);
            worker.execute(() -> connect(server, key, host));
        }
        return START_STICKY;
    }

    private static String extra(Intent i, String name) {
        String v = i == null ? null : i.getStringExtra(name);
        return v == null ? "" : v.trim();
    }

    @Override
    public void onRevoke() {
        // Another VPN took over, or the user turned it off in Settings.
        worker.execute(() -> stop(false));
    }

    @Override
    public void onDestroy() {
        stopDaemon();
        closeVpn();
        worker.shutdownNow();
        super.onDestroy();
    }

    // ---- connect / disconnect ----

    private void connect(String server, String authKey, String hostname) {
        lastError = "";
        try {
            watchNetwork();
            startDaemon();
            connectBridge();
            LocalApi.up(socketPath(getFilesDir()), server, authKey, hostname);
        } catch (Exception e) {
            String msg = e.getMessage() == null ? e.toString() : e.getMessage();
            lastError = msg;
            addLog("connect: " + msg);
            Log.w(TAG, "connect", e);
            // A refused key doesn't undo an existing membership: if this device
            // was already a member, it's still connected. Say so, rather than
            // showing a bare error next to "Connected".
            if (!authKey.isEmpty() && stillConnected()) {
                lastError = "That auth key was refused (" + msg + "). This device is still connected: "
                        + "it's already a member, and a key is only needed to join.";
            }
        }
    }

    /** Whether the daemon is running with a working membership. */
    private boolean stillConnected() {
        try {
            String state = LocalApi.status(socketPath(getFilesDir())).optString("State");
            return state.equals("Running") || state.equals("Starting");
        } catch (IOException e) {
            return false;
        }
    }

    private void stop(boolean logout) {
        try {
            if (daemon != null && daemon.isAlive()) {
                String sock = socketPath(getFilesDir());
                if (logout) LocalApi.logout(sock);
                else LocalApi.down(sock);
            }
        } catch (IOException e) {
            addLog((logout ? "logout: " : "disconnect: ") + e.getMessage());
        }
        closeVpn();
        stopDaemon();
        unwatchNetwork();
        stopSelf();
    }

    // ---- the daemon process ----

    private void startDaemon() throws IOException, InterruptedException {
        if (daemon != null && daemon.isAlive()) return;
        File files = getFilesDir();
        File sock = new File(socketPath(files)), bridgeSock = new File(files, "bridge.sock");
        sock.delete();
        String bin = getApplicationInfo().nativeLibraryDir + "/libtcd.so";
        JSONObject net = currentNetwork();
        List<String> cmd = new ArrayList<>();
        cmd.add(bin);
        cmd.add("-state"); cmd.add(new File(files, "state").getPath());
        cmd.add("-socket"); cmd.add(sock.getPath());
        cmd.add("-bridge"); cmd.add(bridgeSock.getPath());
        cmd.add("-dns"); cmd.add(join(net.optJSONArray("DNS")));
        cmd.add("-addrs"); cmd.add(join(net.optJSONArray("Addresses")));
        ProcessBuilder pb = new ProcessBuilder(cmd).directory(files).redirectErrorStream(true);
        daemon = pb.start();
        Process p = daemon;
        Thread t = new Thread(() -> {
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                for (String line; (line = r.readLine()) != null; ) {
                    Log.i(TAG, line);
                    addLog(line);
                }
            } catch (IOException ignored) {
            }
            addLog("daemon exited");
        }, "tcd-log");
        t.setDaemon(true);
        t.start();
        // Wait for its sockets.
        for (int i = 0; i < 100 && !(sock.exists() && bridgeSock.exists()); i++) {
            if (!daemon.isAlive()) throw new IOException("the daemon failed to start (see the log)");
            Thread.sleep(50);
        }
        if (!sock.exists()) throw new IOException("the daemon did not start in time");
    }

    private void stopDaemon() {
        closeBridge();
        Process p = daemon;
        daemon = null;
        if (p == null) return;
        p.destroy(); // SIGTERM: it shuts the tunnel down cleanly
        try {
            if (!p.waitFor(3, TimeUnit.SECONDS)) p.destroyForcibly();
        } catch (InterruptedException e) {
            p.destroyForcibly();
        }
    }

    // ---- the bridge ----

    private synchronized void connectBridge() throws IOException {
        if (bridge != null) return;
        LocalSocket s = new LocalSocket();
        s.connect(new LocalSocketAddress(new File(getFilesDir(), "bridge.sock").getPath(), LocalSocketAddress.Namespace.FILESYSTEM));
        bridge = s;
        bridgeOut = s.getOutputStream();
        Thread t = new Thread(() -> readBridge(s), "tcd-bridge");
        t.setDaemon(true);
        t.start();
        String n = networkMessage;
        if (n != null) send(n, null);
    }

    private synchronized void closeBridge() {
        if (bridge == null) return;
        try {
            bridge.close();
        } catch (IOException ignored) {
        }
        bridge = null;
        bridgeOut = null;
    }

    private void readBridge(LocalSocket s) {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8))) {
            for (String line; (line = r.readLine()) != null; ) {
                JSONObject m = new JSONObject(line);
                String type = m.optString("Type");
                if (type.equals("tun")) establish(m);
                else if (type.equals("close")) closeVpn();
            }
        } catch (IOException | JSONException e) {
            if (bridge == s) addLog("bridge: " + e.getMessage());
        }
    }

    /** Sends one message, with fd attached if given. */
    private synchronized void send(String json, FileDescriptor fd) {
        if (bridge == null) return;
        try {
            if (fd != null) bridge.setFileDescriptorsForSend(new FileDescriptor[]{fd});
            bridgeOut.write((json + "\n").getBytes(StandardCharsets.UTF_8));
            bridgeOut.flush();
        } catch (IOException e) {
            addLog("bridge: " + e.getMessage());
        } finally {
            if (fd != null) bridge.setFileDescriptorsForSend(null);
        }
    }

    /** Creates the VPN interface the daemon asked for and hands it over. */
    private void establish(JSONObject m) {
        JSONObject reply = new JSONObject();
        ParcelFileDescriptor pfd = null;
        try {
            reply.put("Type", "tun-reply");
            Builder b = new Builder()
                    .setSession(getString(R.string.app_name))
                    .setMtu(m.optInt("MTU", 1280));
            for (String a : strings(m.optJSONArray("Addresses"))) b.addAddress(host(a), bits(a));
            for (String r : strings(m.optJSONArray("Routes"))) b.addRoute(host(r), bits(r));
            for (String d : strings(m.optJSONArray("DNS"))) b.addDnsServer(d);
            for (String s : strings(m.optJSONArray("Search"))) b.addSearchDomain(s);
            // The daemon's own traffic (WireGuard, control server) must not
            // loop into the VPN.
            b.addDisallowedApplication(getPackageName());
            Intent open = new Intent(this, MainActivity.class);
            b.setConfigureIntent(PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE));
            pfd = b.establish();
            if (pfd == null) throw new IllegalStateException("VPN permission not granted; open TailConnect and connect");
            reply.put("OK", true);
        } catch (Exception e) {
            try {
                reply.put("OK", false).put("Error", String.valueOf(e.getMessage()));
            } catch (JSONException ignored) {
            }
            addLog("VPN interface: " + e.getMessage());
        }
        synchronized (this) {
            ParcelFileDescriptor old = vpn;
            vpn = pfd;
            send(reply.toString(), pfd == null ? null : pfd.getFileDescriptor());
            closeQuietly(old);
        }
    }

    private synchronized void closeVpn() {
        closeQuietly(vpn);
        vpn = null;
    }

    private static void closeQuietly(ParcelFileDescriptor p) {
        if (p == null) return;
        try {
            p.close();
        } catch (IOException ignored) {
        }
    }

    // ---- the underlying network ----

    private void watchNetwork() {
        if (networkCallback != null) return;
        ConnectivityManager cm = getSystemService(ConnectivityManager.class);
        networkCallback = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onLinkPropertiesChanged(Network network, LinkProperties lp) {
                String msg = networkJSON(lp).toString();
                if (!msg.equals(networkMessage)) {
                    networkMessage = msg;
                    send(msg, null);
                }
            }
        };
        // This app is excluded from its own VPN, so its default network is
        // the real one (Wi-Fi, mobile data).
        cm.registerDefaultNetworkCallback(networkCallback);
    }

    private void unwatchNetwork() {
        if (networkCallback == null) return;
        try {
            getSystemService(ConnectivityManager.class).unregisterNetworkCallback(networkCallback);
        } catch (IllegalArgumentException ignored) {
        }
        networkCallback = null;
    }

    private JSONObject currentNetwork() {
        ConnectivityManager cm = getSystemService(ConnectivityManager.class);
        Network n = cm.getActiveNetwork();
        LinkProperties lp = n == null ? null : cm.getLinkProperties(n);
        return lp == null ? new JSONObject() : networkJSON(lp);
    }

    private static JSONObject networkJSON(LinkProperties lp) {
        JSONObject m = new JSONObject();
        JSONArray dns = new JSONArray(), addrs = new JSONArray();
        for (InetAddress a : lp.getDnsServers()) {
            if (!a.isLinkLocalAddress()) dns.put(a.getHostAddress());
        }
        for (LinkAddress la : lp.getLinkAddresses()) {
            InetAddress a = la.getAddress();
            if (!a.isLinkLocalAddress() && !a.isLoopbackAddress()) addrs.put(a.getHostAddress() + "/" + la.getPrefixLength());
        }
        try {
            m.put("Type", "network").put("DNS", dns).put("Addresses", addrs);
        } catch (JSONException ignored) {
        }
        return m;
    }

    // ---- helpers ----

    private static List<String> strings(JSONArray a) {
        List<String> out = new ArrayList<>();
        if (a != null) for (int i = 0; i < a.length(); i++) out.add(a.optString(i));
        return out;
    }

    private static String join(JSONArray a) {
        return String.join(",", strings(a));
    }

    private static String host(String prefix) {
        int i = prefix.indexOf('/');
        return i < 0 ? prefix : prefix.substring(0, i);
    }

    private static int bits(String prefix) {
        int i = prefix.indexOf('/');
        if (i >= 0) return Integer.parseInt(prefix.substring(i + 1));
        return prefix.contains(":") ? 128 : 32;
    }
}
