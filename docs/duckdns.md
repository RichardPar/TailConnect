# HOWTO: DuckDNS and Let's Encrypt

Make a server at home reachable from anywhere as `https://mytc.duckdns.org`, with a free, trusted HTTPS certificate. [DuckDNS](https://www.duckdns.org) gives you the name for free and keeps it pointing at your home's changing address. `tc-control` gets and renews the certificate itself.

**Everything here happens on the server.** Only the server has a certificate and updates DuckDNS. Devices (Linux, Android) install nothing: they just connect to `https://mytc.duckdns.org`, and trust its certificate like any website's.

This is the [home server reachable from outside](network-setups.md#home-server-reachable-from-outside) setup, step by step, with DuckDNS as the DNS name.

- [Before you start](#before-you-start)
- [1. Get a DuckDNS name](#1-get-a-duckdns-name)
- [2. Keep the name up to date](#2-keep-the-name-up-to-date)
- [3. Forward the ports](#3-forward-the-ports)
- [4. Turn on HTTPS](#4-turn-on-https)
- [5. Move your devices](#5-move-your-devices)
- [Problems](#problems)

## Before you start

- **A public address at home.** Compare the WAN address on your router's status page with `curl -4 ifconfig.me`. If they differ (often a WAN address starting with `100.64`–`100.127`, `10.` or `192.168.`), your provider shares one address between customers (carrier-grade NAT). Nothing from outside can reach you then, and DuckDNS can't change that: ask your provider for a public address, or put the server on a small cloud VM instead ([on the internet](network-setups.md#on-the-internet)).
- **A fixed LAN address for the server**, set as a DHCP reservation on your router. This guide uses `192.168.1.10`.
- **`tc-control` installed** on it ([installation](installation.md#install-the-control-server)).

## 1. Get a DuckDNS name

1. Go to [duckdns.org](https://www.duckdns.org) and sign in (with GitHub, Google and others).
2. Under **domains**, type a name, say `mytc`, and press **add domain**. Your server will be `mytc.duckdns.org`.
3. Copy the **token** shown at the top of the page. It's the password for updating your names: keep it private.

DuckDNS fills in the address you're browsing from, which at home is your home address. The next step keeps it right when your provider changes it.

## 2. Keep the name up to date

Pick one.

### Your router does it

Many routers have a DuckDNS client built in, under **Dynamic DNS** or **DDNS** (sometimes as a "custom" provider). Enter the name (`mytc`) and the token. Nothing to install on the server.

### The server does it (script)

`duckdns.sh` (in `packaging/linux/`, also in the release tarball) installs a small update script and a systemd timer that update DuckDNS every 5 minutes. It asks for the token without showing it, and keeps it in `/etc/duckdns/duckdns.conf`, readable only by root:

```sh
sudo ./packaging/linux/duckdns.sh install mytc
# DuckDNS token (from duckdns.org, top of the page; not shown):
# DuckDNS updater installed: mytc.duckdns.org is updated every 5 minutes.
```

It updates once straight away and stops with DuckDNS's answer if the name or token is wrong. Afterwards:

```sh
./packaging/linux/duckdns.sh status      # timer, last result, what the name resolves to
sudo ./packaging/linux/duckdns.sh update # update now
sudo ./packaging/linux/duckdns.sh uninstall
```

Failures show up in `journalctl -u duckdns.service`. The update passes the token to `curl` on standard input, so it never appears in the process list. It leaves `ip=` empty, which tells DuckDNS to use the address the update comes from: your home's public address.

### DuckDNS's own script (cron)

[DuckDNS's install page](https://www.duckdns.org/install.jsp) has the classic version: a script in your home directory run by cron. It does the same job as `duckdns.sh`; use one or the other, not both.

```sh
mkdir -p ~/duckdns && cd ~/duckdns
cat > duck.sh <<'EOF'
echo url="https://www.duckdns.org/update?domains=mytc&token=your-token-here&ip=" | curl -s -o ~/duckdns/duck.log -K -
EOF
chmod 700 duck.sh                  # the token is inside: only you may read it
./duck.sh && cat duck.log          # OK, or KO for a wrong name or token
```

Then run `crontab -e` and add this line at the bottom:

```
*/5 * * * * ~/duckdns/duck.sh >/dev/null 2>&1
```

- **Leave out `-k`.** DuckDNS's page has `curl -k`, which skips checking DuckDNS's certificate: anyone who can intercept your traffic could then pose as DuckDNS and collect your token. Without it, curl checks the certificate as usual.
- On Raspberry Pi OS cron runs already; check with `systemctl status cron`.
- `duck.log` holds only the last answer, and cron doesn't report failures. Look at it after your provider changes your address, or use `duckdns.sh`, whose failures show up in `journalctl -u duckdns.service`.

## 3. Forward the ports

On your router, forward these to the server (`192.168.1.10`):

| Outside port | Protocol | To | Why |
|---|---|---|---|
| 443 | TCP | 192.168.1.10:443 | Devices (control, and the relay when no direct path exists), and Let's Encrypt's check that the name is yours |
| 3478 | UDP | 192.168.1.10:3478 | STUN: devices learn their public address, for direct connections |
| 7741 | TCP | 192.168.1.10:7741 | Optional: the web portal from outside |

If the server has a firewall, open the same ports there:

```sh
sudo ufw allow 443/tcp
sudo ufw allow 3478/udp
sudo ufw allow 7741/tcp      # only if you forwarded it
```

Port 443 already used on your router? Forward another outside port, such as 8443, to the server's 8443, and TCP 80 to the server's 80 for Let's Encrypt. See step 4.

## 4. Turn on HTTPS

`letsencrypt.sh` (next to `duckdns.sh`) switches `tc-control` to a Let's Encrypt certificate for your name. `tc-control` then gets and renews the certificate itself; the script only changes its settings, restarts it and checks the result.

Try it first with Let's Encrypt's **test service**. Its limits are generous, so a mistake in the forwarding costs nothing, but devices won't trust its certificates:

```sh
sudo ./packaging/linux/letsencrypt.sh mytc.duckdns.org --staging
# HTTPS works: https://mytc.duckdns.org (issuer=… (STAGING) …)
```

When that works, get the real certificate:

```sh
sudo ./packaging/linux/letsencrypt.sh mytc.duckdns.org --email you@example.com
# HTTPS works: https://mytc.duckdns.org (issuer=C=US, O=Let's Encrypt, …)
```

What it does:
- **Keeps your other settings** (`-domain`, `-signup` and so on) and replaces the HTTPS ones: it sets `-listen :443 -acme-domain mytc.duckdns.org`, and removes `-tls-self-signed`, `-tls-cert`/`-tls-key` and `-public-url` (the public URL becomes `https://mytc.duckdns.org` by itself). `--dry-run` shows the new settings without changing anything.
- **Backs up** `/etc/default/tc-control` first. `sudo ./packaging/linux/letsencrypt.sh --restore` puts the previous settings back.
- **Clears the stored test certificate** when you move from `--staging` to the real one. Otherwise `tc-control` would keep serving it.
- **Fetches the certificate** by connecting to the server itself, so it works even if your router can't loop connections back in. If Let's Encrypt can't reach you, it shows why and what to check.
- **Another port:** `--port 8443` (forwarded to the server's 8443, with TCP 80 forwarded too, for Let's Encrypt's check).
- `--email` is optional: Let's Encrypt uses it only to warn about problems.

`tc-control` renews the certificate by itself, well before it expires, and keeps it in `acme/` next to the database. Back that folder up with the database. Your DuckDNS name counts as its own domain for Let's Encrypt's limits, so other DuckDNS users don't use yours up.

**By hand instead:** set `TC_CONTROL_ARGS="-domain home.internal -listen :443 -acme-domain mytc.duckdns.org"` in `/etc/default/tc-control` (keeping your other options), run `sudo systemctl restart tc-control`, then `curl https://mytc.duckdns.org/key`. Or run `sudo ./packaging/linux/install.sh server --reconfigure` and choose **2) From anywhere, over HTTPS**.

## 5. Move your devices

On each device, point it at the new address. It's the same server, so the device keeps its name and address, and needs no auth key:

```sh
sudo tc up --server https://mytc.duckdns.org
```

- **Android:** change the Server field to `https://mytc.duckdns.org` and tap Connect.
- **Devices that pinned a self-signed certificate** need nothing else. The certificate is now trusted anyway, and the old pin is harmless.
- **New devices** join with the command and QR code on the portal's Auth keys tab, which now use the new address.

Away from home (on mobile data, say), `tc status` should show `control: https://mytc.duckdns.org` and the state `Running`.

## Problems

| Symptom | Cause and fix |
|---|---|
| Works from outside, times out at home | Your router can't connect a LAN device to its own public address ("NAT loopback"). Make `mytc.duckdns.org` resolve to `192.168.1.10` at home, with a local DNS entry on the router ([details](network-setups.md#the-one-catch-reaching-the-public-name-from-inside)). The certificate is for the name, so HTTPS still works. |
| `getent hosts mytc.duckdns.org` shows an old address | The update isn't running or is refused: `./packaging/linux/duckdns.sh status` and `journalctl -u duckdns.service` (or `cat ~/duckdns/duck.log` with the cron script). `KO` from DuckDNS means a wrong name or token. |
| `letsencrypt.sh` says "No certificate yet", or `the certificate authority can't verify the domain` in the log | Let's Encrypt couldn't reach port 443 (or 80 with `-acme-http-listen`). Check the forwarding, the server's firewall, and that the name shows your current address. More in [HTTPS with Let's Encrypt](lets-encrypt.md#troubleshooting). |
| Nothing works from outside at all | Check for carrier-grade NAT ([before you start](#before-you-start)). Some providers also block incoming port 443 on home lines: try 8443 (step 3). |
| `400 Client sent an HTTP request to an HTTPS server` on a device | It still uses the old `http://` address: run step 5 on it. |

More: [HTTPS with Let's Encrypt](lets-encrypt.md) (all options, renewals, rate limits), [Network setups](network-setups.md), [Troubleshooting](troubleshooting.md).
