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

Let's Encrypt checks your name through DuckDNS, so it needs **no** open port. Only devices away from home need a way in. On your router, forward to the server (`192.168.1.10`):

| Outside port | Protocol | To | Why |
|---|---|---|---|
| 443, or any free port such as 8443 | TCP | the port `tc-control` listens on (443, or e.g. 7740) | Devices away from home: control, and the relay when no direct path exists |
| 3478 | UDP | 192.168.1.10:3478 | STUN: devices learn their public address, for direct connections |
| 7741 | TCP | 192.168.1.10:7741 | Optional: the web portal from outside |

The outside port and the server's port can differ: say your router already uses 443, and you forward outside **8443** to the server's **7740**. Step 4 tells `tc-control` about it.

If the server has a firewall, open its ports:

```sh
sudo ufw allow 7740/tcp      # or 443, whichever tc-control listens on
sudo ufw allow 3478/udp
sudo ufw allow 7741/tcp      # only if you forwarded it
```

## 4. Turn on HTTPS

`letsencrypt.sh` (next to `duckdns.sh`) switches `tc-control` to a Let's Encrypt certificate for your name. For a DuckDNS name it uses the **DNS check**: `tc-control` puts a code in your name's TXT record through DuckDNS, Let's Encrypt looks it up, and nothing connects in. The script takes the token from step 2.

Try it first with Let's Encrypt's **test service**. Its limits are generous, so a mistake costs nothing, but devices won't trust its certificates:

```sh
# outside 8443 forwarded to the server's 7740:
sudo ./packaging/linux/letsencrypt.sh mytc.duckdns.org --port 7740 --public-port 8443 --staging
# outside 443 forwarded to the server's 443: no options needed
sudo ./packaging/linux/letsencrypt.sh mytc.duckdns.org --staging
```

It takes a minute or two, then says `HTTPS works: https://mytc.duckdns.org:8443 (issuer=… (STAGING) …)`. Then the real certificate: the same command without `--staging` (add `--email you@example.com` if you like; Let's Encrypt uses it only to warn about problems).

What it does:
- **Keeps your other settings** (`-domain`, `-signup` and so on) and sets the HTTPS ones: `-listen :7740 -acme-domain mytc.duckdns.org -acme-dns duckdns -public-url https://mytc.duckdns.org:8443`. It removes `-tls-self-signed` and other HTTPS options. `--dry-run` shows the new settings without changing anything.
- **Stores the token** in `/etc/default/tc-control` as `TC_DUCKDNS_TOKEN`, and makes that file readable by root only.
- **Backs up** the settings first. `sudo ./packaging/linux/letsencrypt.sh --restore` puts the previous ones back.
- **Waits for the certificate** by asking the server itself, and if it doesn't come, shows `tc-control`'s reason.

`tc-control` renews the certificate by itself, in the last third of its life, the same way. It keeps it in `acme/` next to the database: back that folder up with the database. Your DuckDNS name counts as its own domain for Let's Encrypt's limits, so other DuckDNS users don't use yours up.

**By hand instead:** see [no open port: the DNS check](lets-encrypt.md#no-open-port-the-dns-check-duckdns).

## 5. Move your devices

On each device, point it at the new address. It's the same server, so the device keeps its name and address, and needs no auth key:

```sh
sudo tc up --server https://mytc.duckdns.org        # add :8443 (your outside port) if it isn't 443
```

- **Android:** change the Server field to `https://mytc.duckdns.org` and tap Connect.
- **Devices that pinned a self-signed certificate** need nothing else. The certificate is now trusted anyway, and the old pin is harmless.
- **New devices** join with the command and QR code on the portal's Auth keys tab, which now use the new address.

Away from home (on mobile data, say), `tc status` should show `control: https://mytc.duckdns.org` and the state `Running`.

## Problems

| Symptom | Cause and fix |
|---|---|
| Works from outside, times out at home | Your router can't connect a LAN device to its own public address ("NAT loopback"). Make `mytc.duckdns.org` resolve to the server's LAN address at home, with a local DNS entry on the router ([details](network-setups.md#the-one-catch-reaching-the-public-name-from-inside)). The certificate is for the name, so HTTPS still works. This only helps when the outside port and the server's port are the same: with 8443 forwarded to 7740, forward 8443 to 8443 instead and run `letsencrypt.sh` with `--port 8443`. |
| `getent hosts mytc.duckdns.org` shows an old address | The update isn't running or is refused: `./packaging/linux/duckdns.sh status` and `journalctl -u duckdns.service` (or `cat ~/duckdns/duck.log` with the cron script). `KO` from DuckDNS means a wrong name or token. |
| `letsencrypt.sh` says "No certificate yet" | The lines above it are `tc-control`'s reason. `DuckDNS refused the update … check the token`: the token is wrong (copy it again from duckdns.org and rerun `duckdns.sh install`, then `letsencrypt.sh`). `the CA's DNS check failed`: try again in a few minutes; `journalctl -u tc-control` has Let's Encrypt's answer. More in [HTTPS with Let's Encrypt](lets-encrypt.md#troubleshooting). |
| Works at home, not from outside | Check the router forwards the outside port to the server's port (step 3), and for carrier-grade NAT ([before you start](#before-you-start)). Some providers block incoming port 443 on home lines: use 8443. The certificate doesn't depend on this: it comes through DuckDNS. |
| `400 Client sent an HTTP request to an HTTPS server` on a device | It still uses the old `http://` address: run step 5 on it. |

More: [HTTPS with Let's Encrypt](lets-encrypt.md) (all options, renewals, rate limits), [Network setups](network-setups.md), [Troubleshooting](troubleshooting.md).
