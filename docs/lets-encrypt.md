# HTTPS with Let's Encrypt

`tc-control` and `tc-relay` can get free HTTPS certificates from [Let's Encrypt](https://letsencrypt.org) and renew them by themselves. Nothing else to install or run: no web server, no proxy, no certbot, no renewal cron job.

- [Why HTTPS](#why-https)
- [What you need](#what-you-need)
- [Set it up](#set-it-up)
- [Try it first with the test service](#try-it-first-with-the-test-service)
- [Check it](#check-it)
- [Move existing devices to HTTPS](#move-existing-devices-to-https)
- [The web portal](#the-web-portal)
- [Standalone relays](#standalone-relays)
- [Renewals, storage and backups](#renewals-storage-and-backups)
- [Rate limits](#rate-limits)
- [Troubleshooting](#troubleshooting)
- [Options](#options)

---

## Why HTTPS

Without HTTPS, the control channel is still encrypted and authenticated, with Noise. But the first time a device connects, it trusts whatever server key it's given ("trust on first use"), and an attacker on the network at that moment could pose as your server. With HTTPS, the device checks the server's certificate first, so that can't happen. HTTPS also:
- lets you serve on port 443, which almost every network allows;
- lets the web portal be used by other people, because they type passwords into it;
- carries the built-in relay too, so relayed traffic works wherever HTTPS does.

On a LAN-only server with no public name, Let's Encrypt can't work. Pin the server key instead ([LAN only](network-setups.md#lan-only)).

## What you need

1. **A DNS name** for the server, such as `vpn.example.com`. Any domain you control works. A dynamic DNS name works too, if your home address changes.
2. **The name pointing at the server.** At your DNS provider, add an `A` record with the server's public IPv4 address. Add an `AAAA` record only if the server is also reachable over IPv6 (see [the IPv6 trap](#the-ipv6-trap)).
   ```sh
   dig +short vpn.example.com A        # the server's public IPv4 address
   dig +short vpn.example.com AAAA     # empty, or an IPv6 address that reaches the server
   ```
3. **Port 443 reachable from the internet.** Let's Encrypt connects to it to check that the name is yours. If 443 isn't possible, port 80 works instead ([below](#on-a-port-other-than-443)).
   - On a cloud VM, open TCP 443 in its firewall and in the provider's security group.
   - At home, forward TCP 443 on your router to the server. That needs a public address at home: [check for carrier-grade NAT](network-setups.md#what-you-need).

Let's Encrypt issues certificates for names, not for addresses, so devices must use the name (`https://vpn.example.com`), never the IP address.

## Set it up

### On port 443 (recommended)

Set the options and restart:

```sh
# /etc/default/tc-control
TC_CONTROL_ARGS="-listen :443 -acme-domain vpn.example.com -acme-email you@example.com -domain home.internal"
```

```sh
sudo systemctl restart tc-control
```

- `-listen :443`: the control API and built-in relay on the HTTPS port. The packaged service is allowed to use ports below 1024; nothing else is needed.
- `-acme-domain`: the name to get a certificate for. For several names, separate them with commas: `vpn.example.com,vpn.example.org`.
- `-acme-email` (optional): the contact address for your Let's Encrypt account. Let's Encrypt uses it only for important notices about the account; it no longer sends expiry reminders, which renewal makes unnecessary anyway.
- `-public-url` isn't needed: it becomes `https://vpn.example.com`.

The certificate is fetched on the **first HTTPS request** for the name, which takes a few seconds. Make that request yourself:

```sh
curl https://vpn.example.com/key       # {"Version":2,"MachineKey":"mkey:…"}
```

Then open TCP 443 in the firewall, and close 7740 if nothing else uses it:

```sh
sudo ufw allow 443/tcp && sudo ufw allow 3478/udp
```

### On a port other than 443

Let's Encrypt only connects to ports 443 and 80. If 443 is taken (by another web server, or on your router), keep your port for HTTPS and let `tc-control` answer Let's Encrypt's checks on port 80:

```sh
# /etc/default/tc-control
TC_CONTROL_ARGS="-listen :8443 -acme-http-listen :80 -acme-domain vpn.example.com -domain home.internal"
```

- Open (or forward) TCP 8443 and TCP 80.
- Port 80 answers the checks and redirects everything else to HTTPS.
- Devices use `https://vpn.example.com:8443`.

If neither can work (HTTPS on another port, and no `-acme-http-listen`), `tc-control` refuses to start and says why, instead of failing to get a certificate later.

### At home behind your router

The same as above, with the ports forwarded on the router to the server's LAN address. Devices at home may not reach the public name through their own router; see [reaching the public name from inside](network-setups.md#the-one-catch-reaching-the-public-name-from-inside). The fix is a local DNS entry pointing the name at the server's LAN address. The certificate still works, because it's for the name.

## Try it first with the test service

Let's Encrypt limits how often it issues certificates, and failed attempts count too ([rate limits](#rate-limits)). If you're not sure the DNS and ports are right, try the **test service** first. It has generous limits, but its certificates aren't trusted, so devices won't connect while it's on.

```sh
TC_CONTROL_ARGS="-listen :443 -acme-domain vpn.example.com -acme-staging -domain home.internal"
```

```sh
sudo systemctl restart tc-control
curl -k https://vpn.example.com/key                     # -k: accept the untrusted test certificate
echo | openssl s_client -connect vpn.example.com:443 -servername vpn.example.com 2>/dev/null | openssl x509 -noout -issuer
# issuer=… (STAGING) …
```

When that works, switch to real certificates. **Delete the test certificate first:** certificates are stored by name, so the test one would otherwise keep being served.

```sh
sudo systemctl stop tc-control
sudo rm -r /var/lib/private/tc-control/acme             # the stored certificates (not your accounts or machines)
# remove -acme-staging from /etc/default/tc-control
sudo systemctl start tc-control
curl https://vpn.example.com/key                        # fetches the real certificate
```

## Check it

```sh
curl https://vpn.example.com/key
echo | openssl s_client -connect vpn.example.com:443 -servername vpn.example.com 2>/dev/null | openssl x509 -noout -issuer -dates
```

The issuer is Let's Encrypt, and `notAfter` is when the certificate expires (it's renewed well before). The log shows problems getting it:

```sh
journalctl -u tc-control | grep -i acme
```

## Move existing devices to HTTPS

Devices that joined over plain HTTP keep their identity: it's the same server, with the same key. Point each one at the new URL; no auth key is needed.

**Linux:**

```sh
sudo tc up --server https://vpn.example.com
tc status                                   # control: https://vpn.example.com
```

**Android:** in the app, tap Disconnect, change **Server** to `https://vpn.example.com`, and tap Connect.

New devices join with `--server https://vpn.example.com` from the start. Devices check certificates against the system's trusted authorities, which include Let's Encrypt on every current Linux distribution and Android version.

## The web portal

The portal uses the same certificate: it's at `https://vpn.example.com:7741` once TCP 7741 is open. See [Open the portal to other people](installation.md#open-the-portal-to-other-people) for letting others sign up.

## Standalone relays

A [standalone relay](usage.md#relays) gets its own certificate the same way, for its own name:

```sh
TC_RELAY_TOKEN=tc-relay-… tc-relay -control-url https://vpn.example.com \
    -listen :443 -acme-domain relay-eu.example.com -acme-dir /var/lib/tc-relay/acme
```

`-acme-dir` is where it keeps its certificates. It defaults to `acme` in the current directory, so give it a fixed place when running it as a service. In the relay map, use its HTTPS URL: `https://relay-eu.example.com/relay`.

## Renewals, storage and backups

- **Renewal is automatic** while the server runs: after two thirds of a certificate's lifetime, which is 30 days before expiry for today's 90-day certificates. It needs no restart. Port 443 (or 80 with `-acme-http-listen`) must still be reachable then, so don't close it after the first certificate.
- **Where certificates live:** in `acme/` next to the database. For the packaged server that's `/var/lib/tc-control/acme`, which is really `/var/lib/private/tc-control/acme`. It holds your Let's Encrypt account key and the certificates with their private keys, readable only by the service. Keep it private.
- **Backups** don't need it: if it's lost, new certificates are simply fetched. Restoring it avoids fetching again, which helps if you move servers often ([rate limits](#rate-limits)).
- **Moving the server** to new hardware: copy the database as in [Move the server](installation.md#move-the-server), and optionally the `acme` folder; point the DNS name at the new server.
- **Changing the name** means a new certificate; devices must use the new name (`sudo tc up --server https://new-name`).

## Rate limits

Let's Encrypt limits how many certificates it issues for a name each week, and how many failed checks it accepts per hour. A normal setup is nowhere near them: `tc-control` fetches one certificate, keeps it, and renews it once in a while. You can hit them by:
- getting certificates over and over while experimenting, for example by deleting the `acme` folder each time;
- leaving a broken setup retrying (DNS or port wrong).

Use the [test service](#try-it-first-with-the-test-service) while experimenting. The current limits are on [letsencrypt.org/docs/rate-limits](https://letsencrypt.org/docs/rate-limits/). If you hit one, wait it out: usually hours, at most a week for duplicate certificates. Meanwhile, devices already connected keep their tunnels; to let devices connect, you can run without `-acme-domain` (plain HTTP on 7740) until then.

## Troubleshooting

Problems getting a certificate show up in the log, and the first HTTPS request fails with a TLS error such as `tlsv1 alert internal error`:

```sh
journalctl -u tc-control --since -10min | grep -i -E "acme|tls"
```

| Message or symptom | Cause and fix |
|---|---|
| `tc-control: -acme-domain: the certificate authority can't verify the domain …` (at start) | HTTPS isn't on port 443 and there's no `-acme-http-listen`. Use `-listen :443`, or add `-acme-http-listen :80`. |
| `acme/autocert: missing server name` | Something connected by IP address (`https://203.0.113.5`). Use the name. |
| `acme/autocert: host "…" not configured in HostWhitelist` | The name used isn't in `-acme-domain`. Add it (comma-separated), or use the configured one. |
| `… Timeout during connect (likely firewall problem)` or `Connection refused` | Let's Encrypt can't reach port 443 (or 80). Check the firewall, the cloud security group, and the router's port forwarding. Test from outside your network: `curl -v https://vpn.example.com/key`. |
| `… DNS problem: NXDOMAIN` or `no valid A records` | The name doesn't resolve yet, or points elsewhere. Check `dig +short vpn.example.com`; new records can take a while to appear. |
| `… CAA record for … prevents issuance` | The domain has a CAA record that doesn't allow Let's Encrypt. Add one: `example.com. CAA 0 issue "letsencrypt.org"`. |
| `… too many certificates` or `too many failed authorizations` | A [rate limit](#rate-limits). Wait, and use `-acme-staging` while fixing the setup. |
| Works from outside, times out from home | Your router doesn't route its own public address from inside ([fix](network-setups.md#the-one-catch-reaching-the-public-name-from-inside)). |
| Devices say `x509: certificate signed by unknown authority` | `-acme-staging` is still on, or its certificate is still stored ([switch to real certificates](#try-it-first-with-the-test-service)). On a very old device, update its trusted certificates (`ca-certificates` package). |

### The IPv6 trap

If the name has an `AAAA` (IPv6) record, Let's Encrypt prefers it. If that IPv6 address doesn't reach the server on port 443, for example because of an old record or an IPv6 firewall, the check fails even though IPv4 works. Either make IPv6 work (open 443 for IPv6 as well; `tc-control` listens on both) or remove the `AAAA` record.

## Options

| Option | Default | Description |
|---|---|---|
| `-acme-domain` | none | Get certificates for this name, or several names separated by commas. Turns on HTTPS for the control and portal listeners. |
| `-acme-http-listen` | none | Also answer Let's Encrypt's checks on this address (`:80`), redirecting other requests to HTTPS. Needed when `-listen` isn't on port 443. |
| `-acme-email` | none | Contact address for the Let's Encrypt account (optional) |
| `-acme-staging` | `false` | Use the test service: generous limits, untrusted certificates |
| `-acme-dir` (`tc-relay` only) | `acme` | Where `tc-relay` keeps its certificates. `tc-control` always uses `acme/` next to its database. |

All other options are in the [configuration reference](configuration.md#tc-control-serve). To use a certificate you already have instead, see [Your own certificate](installation.md#your-own-certificate).
