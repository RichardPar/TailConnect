package tailconnect.android;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Talks to the daemon's local API (the same one the Linux `tc` command uses)
 * over its Unix socket. Requests are HTTP/1.0, so responses are never chunked
 * and simply end when the daemon closes the connection.
 */
final class LocalApi {
    private LocalApi() {}

    static JSONObject status(String socket) throws IOException {
        return parse(request(socket, "GET", "/localapi/v1/status", null));
    }

    static void up(String socket, String server, String authKey, String hostname, String tlsFingerprint) throws IOException {
        JSONObject req = new JSONObject();
        try {
            if (!server.isEmpty()) req.put("ControlURL", server);
            if (!authKey.isEmpty()) req.put("AuthKey", authKey);
            if (!hostname.isEmpty()) req.put("Hostname", hostname);
            if (!tlsFingerprint.isEmpty()) req.put("TLSFingerprint", tlsFingerprint);
        } catch (JSONException e) {
            throw new IOException(e);
        }
        request(socket, "POST", "/localapi/v1/up", req.toString());
    }

    /** Chooses the exit node for this device's internet traffic ("" = none). */
    static void setExitNode(String socket, String name) throws IOException {
        JSONObject req = new JSONObject();
        try {
            req.put("ExitNode", name);
        } catch (JSONException e) {
            throw new IOException(e);
        }
        request(socket, "POST", "/localapi/v1/up", req.toString());
    }

    static void down(String socket) throws IOException {
        request(socket, "POST", "/localapi/v1/down", "{}");
    }

    static void logout(String socket) throws IOException {
        request(socket, "POST", "/localapi/v1/logout", "{}");
    }

    private static String request(String socket, String method, String path, String body) throws IOException {
        byte[] payload = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
        try (LocalSocket s = new LocalSocket()) {
            s.connect(new LocalSocketAddress(socket, LocalSocketAddress.Namespace.FILESYSTEM));
            s.setSoTimeout(60_000); // joining can take a while on a slow network
            OutputStream out = s.getOutputStream();
            String head = method + " " + path + " HTTP/1.0\r\nHost: tcd\r\n";
            if (body != null) {
                head += "Content-Type: application/json\r\nContent-Length: " + payload.length + "\r\n";
            }
            out.write((head + "\r\n").getBytes(StandardCharsets.US_ASCII));
            out.write(payload);
            out.flush();

            InputStream in = s.getInputStream();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            for (int n; (n = in.read(chunk)) > 0; ) buf.write(chunk, 0, n);
            String resp = buf.toString("UTF-8");

            int sp = resp.indexOf(' ');
            int split = resp.indexOf("\r\n\r\n");
            if (sp < 0 || split < 0) throw new IOException("bad response from the daemon");
            int code = Integer.parseInt(resp.substring(sp + 1, sp + 4));
            String respBody = resp.substring(split + 4);
            if (code != 200) {
                String msg = respBody.trim();
                try {
                    msg = new JSONObject(respBody).optString("Error", msg);
                } catch (JSONException ignored) {
                }
                throw new IOException(msg);
            }
            return respBody;
        }
    }

    private static JSONObject parse(String s) throws IOException {
        try {
            return new JSONObject(s);
        } catch (JSONException e) {
            throw new IOException("bad status from the daemon: " + e.getMessage());
        }
    }
}
