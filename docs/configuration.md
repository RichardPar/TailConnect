# Configuration reference

Every option, file and port. For what to set and when, see [Installation](installation.md) and [Usage](usage.md).

- [Settings at a glance](#settings-at-a-glance)
- [tc-control serve](#tc-control-serve)
- [tc-control admin commands](#tc-control-admin-commands)
- [tcd](#tcd)
- [tc](#tc)
- [tc-relay](#tc-relay)
- [Helper scripts](#helper-scripts)
- [Settings files](#settings-files)
- [Environment variables](#environment-variables)
- [Relay map](#relay-map)
- [Ports](#ports)
- [Files and paths](#files-and-paths)
- [Addresses](#addresses)

---

## Settings at a glance

Every setting, and where to change it. *Server options* go in `/etc/default/tc-control` on the server (then `sudo systemctl restart tc-control`). *Portal* means the [web portal](portal.md). *CLI* means `sudo tc-control …` on the server.

**The server** (server options; details [below](#tc-control-serve)):

| Setting | Option | Default |
|---|---|---|
| MagicDNS domain | `-domain` | `tc.internal` |
| Domains accounts may choose for themselves | `-tenant-domain-suffixes` | `internal` |
| MagicDNS on or off | `-magic-dns` | on |
| Send all of the devices' DNS through MagicDNS | `-dns-nameservers 1.1.1.1,…` | off (devices keep their own DNS) |
| Control and relay address | `-listen` | `:7740` |
| Portal address | `-admin-listen` | `:7741` (every address) |
| URL shown for joining | `-public-url` | derived |
| HTTPS: automatic (Let's Encrypt) | `-acme-domain`, `-acme-http-listen`, `-acme-dns`, `-acme-email`, `-acme-staging` | off ([guide](lets-encrypt.md)) |
| HTTPS: your own certificate | `-tls-cert`, `-tls-key` | off |
| HTTPS: a self-signed certificate | `-tls-self-signed` (extra names: `-tls-names`) | off |
| Who may create accounts | `-signup off\|approval\|invite\|open` | `approval` |
| How long machines stay authorised | `-key-expiry 180d` or `never` | 180 days |
| Removing offline ephemeral machines | `-ephemeral-timeout` | 30 minutes |
| Built-in relay | `-relay` | on |
| More relay regions | `-relay-map FILE` | none |
| STUN server | `-stun-listen` | `:3478` |
| Metrics | `-metrics-listen` | off |
| JSON logs | `-log-json` | off |

**Accounts:**

| Setting | Portal | CLI |
|---|---|---|
| Create an account | Accounts → Add account | `users create NAME [-operator] [-password]` |
| Approve, suspend, reactivate | Accounts | `users approve\|suspend\|activate NAME` |
| Operator or tenant | Accounts → Make operator / Make tenant | `users role NAME operator\|tenant` |
| Password | My account (own), Accounts → Reset password | `users passwd NAME` |
| Require approval for new machines | My account | `users machine-approval NAME on\|off` |
| Account's own MagicDNS domain | My account (own), Accounts → Domain | `users domain NAME [DOMAIN\|default]` |
| Access rules | Access rules | `rules add -user NAME FROM TO [PORTS]`, `rules delete ID` |
| Invites (sign-up without approval) | Accounts → Invites | `invites create [-expiration 168h]`, `invites revoke ID` |
| Delete an account | Accounts → Delete | `users delete NAME` |

**Machines:**

| Setting | Portal | CLI |
|---|---|---|
| Name | Machines → Rename | `nodes rename ID NAME` |
| Tags | Machines → Tags | `nodes tag ID TAG[,TAG…]` |
| Key never expires, or normal lifetime | Machines → Never expire / Set expiry | `nodes expiry ID never\|DURATION` |
| Approve | Machines → Approve | `nodes approve ID` |
| Exit node (off by default; Linux only) | Machines → Exit node: off / on | `nodes exit-node ID on\|off` |
| Remove | Machines → Remove | `nodes delete ID` |
| Share with another account | Sharing | `shares create ID ACCOUNT`, `shares link ID`, `shares accept ID`, `shares revoke ID` |

**Joining:**

| Setting | Portal | CLI |
|---|---|---|
| Auth key: account, expiry, reusable, ephemeral, pre-approved | Auth keys | `keys create -user NAME [-expiration 24h] [-reusable] [-ephemeral] [-preapproved]` |
| Revoke a key | Auth keys → Revoke | `keys revoke ID` |
| Standalone relay token | (CLI only) | `relays create NAME`, `relays delete NAME` |
| Admin token (recovery, API) | (CLI only) | `admin-token` |

**Linux devices** (`/etc/default/tcd`, then `sudo systemctl restart tcd`; or `tc up` options; details in [tcd](#tcd) and [tc](#tc)):

| Setting | Where | Default |
|---|---|---|
| Server, auth key, name | `sudo tc up --server URL --authkey KEY --hostname NAME` | name: the OS hostname |
| Pin the server key | `tc up --server-key mkey:…` | fetched (trust on first use, or checked by HTTPS) |
| Trust a self-signed server certificate | `tc up --tls-fingerprint sha256:…` | only certificates from trusted authorities |
| Send internet traffic through an [exit node](usage.md#exit-nodes) | `sudo tc up --exit-node NAME`; `--exit-node ""` stops | none; remembered in `state.json` |
| DNS integration | `-dns auto\|systemd-resolved\|file\|off` | `auto` |
| WireGuard port | `-port` | `41641` |
| Interface name | `-tun` (or `userspace`) | `tc0` |
| Metrics | `-metrics-listen` | off |
| Disconnect, reconnect, leave | `tc down`, `tc up`, `tc logout` | |

**Android devices** (in the app; [details](android.md)): server, auth key and device name on the main screen; always-on VPN in Android's settings (VPN → TailConnect → Always-on VPN).

---

## tc-control serve

The coordination server: control API, built-in relay, STUN, web portal.

| Flag | Default | Description |
|---|---|---|
| `-db` | see [below](#tc-control-admin-commands) | SQLite database. The packaged unit uses `/var/lib/tc-control/control.db`. |
| `-listen` | `:7740` | Control API and built-in relay (TCP) |
| `-admin-listen` | `:7741` | Web portal and its API: `:7741` on every address, `127.0.0.1:7741` on the server only (reach it with an SSH tunnel), `""` turns them off. Without HTTPS, passwords cross the network unencrypted, and `tc-control` logs a warning. |
| `-key-expiry` | `180d` | How long machines stay authorised after joining or re-authenticating: days (`90d`), a Go duration (`720h`), or `never`. Machines set to never expire, and machines that joined before this existed, are unaffected. |
| `-ephemeral-timeout` | `30m` | Remove ephemeral machines that have been offline this long (`0` keeps them). |
| `-signup` | `approval` | Who may create accounts in the portal: `off`, `approval` (pending until an operator approves), `invite` (needs an invite code) or `open`. A valid invite skips approval in every mode except `off`. |
| `-stun-listen` | `:3478` | Built-in STUN server (UDP). `""` turns it off; devices then can't learn their public address, and NAT traversal suffers. |
| `-domain` | `tc.internal` | MagicDNS suffix: devices are `<name>.<domain>`. Needs two or more labels of lowercase letters, digits and `-`. |
| `-tenant-domain-suffixes` | `internal` | Comma-separated suffixes an account may choose its own MagicDNS domain under in the portal (`internal` allows `acme.internal`). `""` lets only operators set account domains, which may be anything. See [MagicDNS](usage.md#magicdns). |
| `-magic-dns` | `true` | Devices resolve MagicDNS names and point the OS at the resolver. `=false` turns it off. |
| `-dns-nameservers` | none | Comma-separated upstream resolvers. When set, devices send **all** DNS through MagicDNS, which forwards non-MagicDNS names to these. |
| `-relay` | `true` | Serve the built-in relay at `/relay` on the control listener (registered devices only) |
| `-relay-map` | none | JSON [relay map](#relay-map) to advertise instead of the built-in relay alone |
| `-public-url` | derived from `-listen` | URL shown in the portal for clients to use |
| `-acme-domain` | none | Get HTTPS certificates from Let's Encrypt for this DNS name (comma-separated for several), for both the control and portal listeners. The name must point at the server, and Let's Encrypt must reach port 443 (or `-acme-http-listen`). Certificates are kept in `acme/` next to the database and renewed automatically. ([How](installation.md#enable-https)) |
| `-acme-http-listen` | none | Also serve Let's Encrypt's checks on this address (`:80`), and redirect other requests there to HTTPS. Needed when `-listen` isn't on port 443. |
| `-acme-email` | none | Contact address for the Let's Encrypt account (optional) |
| `-acme-staging` | `false` | Use Let's Encrypt's test service (certificates clients won't trust) |
| `-acme-dns` | none | `duckdns`: Let's Encrypt checks a `NAME.duckdns.org` name through DuckDNS (a TXT record) instead of connecting in, so HTTPS can use any port and nothing has to be open for the check. Needs `TC_DUCKDNS_TOKEN`. Excludes `-acme-http-listen`. [Details](lets-encrypt.md#no-open-port-the-dns-check-duckdns). |
| `-tls-cert`, `-tls-key` | none | Your own PEM certificate (with chain) and key, instead of `-acme-domain`. Turns on HTTPS for both the control and portal listeners. |
| `-tls-self-signed` | off | HTTPS with a certificate `tc-control` makes itself, kept in `tls/` next to the database. It logs the certificate's fingerprint, and the portal shows it; clients trust it with `tc up --tls-fingerprint`. Excludes `-tls-cert` and `-acme-domain`. See [Self-signed certificate](installation.md#self-signed-certificate-no-dns-name-or-open-port-needed). |
| `-tls-names` | none | With `-tls-self-signed`: more comma-separated DNS names or addresses for the certificate, beyond the hostname, `hostname.local`, the machine's IPv4 addresses, `::1` and the `-public-url` host. |
| `-metrics-listen` | none | Serve [metrics](usage.md#monitoring) at `/metrics` on this address (plain HTTP, no login), e.g. `127.0.0.1:7743` |
| `-log-json` | `false` | Log in JSON instead of text |

## tc-control admin commands

```
tc-control users create NAME [-operator] [-password] | list | delete NAME
tc-control users passwd NAME | approve NAME | suspend NAME | activate NAME
tc-control users role NAME operator|tenant | machine-approval NAME on|off
tc-control users domain NAME [DOMAIN|default]
tc-control invites create [-expiration 168h] | list | revoke ID
tc-control keys create -user NAME [-reusable] [-ephemeral] [-preapproved] [-expiration 24h]
tc-control keys list [-user NAME] | revoke ID
tc-control nodes list [-user NAME] | delete ID | rename ID NEWNAME
tc-control nodes approve ID | expiry ID never|DURATION | tag ID TAG[,TAG...]
tc-control nodes exit-node ID on|off
tc-control rules list [-user NAME] | add -user NAME FROM TO [PORTS] | delete ID
tc-control relays create NAME | list | delete NAME
tc-control shares list [-user NAME] | create NODE_ID ACCOUNT | link NODE_ID [-expiration 168h]
tc-control shares accept ID | revoke ID
tc-control admin-token
tc-control version
```

| Flag | Applies to | Description |
|---|---|---|
| `-db PATH` | all | Database. Default: `$TC_CONTROL_DB`, else `/var/lib/tc-control/control.db` if it exists, else `./control.db` |
| `-json` | `list` commands | Machine-readable output |
| `-user NAME` | `keys create`, `rules add` (required), `keys list`, `nodes list`, `shares list`, `rules list` | Account to create the key or rule for, or to filter by |
| `-operator` | `users create` | Make the account an operator |
| `-password` | `users create` | Also set a password (prompted twice on a terminal, else one line from stdin), as `users passwd` does |
| `-reusable` | `keys create` | The key can register any number of devices until it expires |
| `-ephemeral` | `keys create` | Devices joining with it are ephemeral: removed once offline for `-ephemeral-timeout` |
| `-preapproved` | `keys create` | Devices joining with it skip the account's machine approval |
| `-expiration` | `keys create`, `invites create`, `shares link` | Lifetime as a Go duration (`30m`, `24h`, `720h`); default `24h` for keys, `168h` for invites and share links |

Account names are 1-32 lowercase letters, digits and inner `-` (they're part of machine names). Machine names for `rename` are a DNS label: lowercase letters, digits and `-`, up to 63 characters, unique within the account. Passwords are 10-256 characters.

## tcd

The client daemon. It runs as root, or with `CAP_NET_ADMIN`.

| Flag | Default | Description |
|---|---|---|
| `-state` | `/var/lib/tailconnect` | Directory for keys and registration (`state.json`, mode 0600) |
| `-socket` | `/run/tailconnect/tcd.sock` | Local API socket used by `tc` |
| `-tun` | `tc0` | TUN interface name, or `userspace` for an in-process network stack (no root, no OS changes) |
| `-port` | `41641` | WireGuard UDP port. `0` = random. If the port is busy, a random one is used. |
| `-dns` | `auto` | Host DNS integration: `auto`, `systemd-resolved`, `file` or `off` ([details](usage.md#magicdns)) |
| `-resolv-conf` | `/etc/resolv.conf` | File rewritten in `file` mode |
| `-metrics-listen` | none | Serve [metrics](usage.md#monitoring) at `/metrics` on this address, e.g. `127.0.0.1:7744` |
| `-verbose` | `false` | Log WireGuard internals |
| `-version` | | Print the version and exit |

## tc

| Command | Flags |
|---|---|
| `tc up` | `--server URL`, `--authkey KEY` (or `$TC_AUTHKEY`), `--hostname NAME`, `--server-key mkey:…`, `--tls-fingerprint sha256:…`, `--exit-node NAME` (`""` = none; omitted = unchanged) |
| `tc down` | |
| `tc status` | `--json` |
| `tc ip [PEER]` | `-4`, `-6` |
| `tc logout` | |
| `tc version` | |

Global: `--socket PATH` (or `$TC_SOCKET`; default `/run/tailconnect/tcd.sock`). See [Usage](usage.md#the-tc-client) for what each command does.

## tc-relay

A standalone relay and STUN server ([when to use one](usage.md#relays)).

| Flag | Default | Description |
|---|---|---|
| `-control-url` | none | The control server to check machines with ([how](usage.md#relays)). Required unless `-allow-any`. |
| `-token-file` | none | File with the relay's token from `tc-control relays create NAME`. Or set `TC_RELAY_TOKEN`. (Not a flag value, which other users could read in `ps`.) |
| `-allow-any` | `false` | Instead of `-control-url`: an open relay for any device that proves it owns its key |
| `-listen` | `:7742` | Relay listen address (TCP) |
| `-stun-listen` | `:3478` | STUN server (UDP). `""` turns it off. |
| `-key-file` | `relay.key` | Relay private key, created if missing |
| `-public-url` | derived | Relay URL, used only for the example relay map it prints |
| `-acme-domain`, `-acme-http-listen`, `-acme-email`, `-acme-staging` | none | Automatic HTTPS from Let's Encrypt, as for `tc-control` |
| `-acme-dir` | `acme` | Where `tc-relay` keeps its certificates |
| `-tls-cert`, `-tls-key` | none | Serve HTTPS with your own certificate |
| `-metrics-listen` | none | Serve [metrics](usage.md#monitoring) at `/metrics` on this address |
| `-log-json` | `false` | JSON logs |
| `-version` | | Print the version and exit |

`GET /` on the relay port shows its version, connected clients and packet counters.

---

## Helper scripts

In `packaging/linux/`, next to `install.sh`, for HTTPS on a server reachable from the internet. Run them as root on the server; devices need nothing.

| Script | What it does |
|---|---|
| `letsencrypt.sh NAME [--port N] [--public-port N] [--email ADDR] [--staging] [--no-dns] [--dry-run]` | Switches `tc-control` to a Let's Encrypt certificate for NAME: sets `-listen` and `-acme-domain`, removes other HTTPS options, keeps everything else. For a DuckDNS name it uses the DNS check (`-acme-dns duckdns`, no port needs to be open for Let's Encrypt) and stores the token from `duckdns.sh`; for other names, `-acme-http-listen :80` when the port isn't 443. `--public-port` sets `-public-url` when the router forwards another outside port. Backs up the settings first, clears a stored test certificate when leaving `--staging`, restarts and checks that the certificate arrives. `--restore` puts the previous settings back. |
| `duckdns.sh install NAME` | Keeps the DuckDNS name NAME pointing at this network's public address: an update script and a systemd timer, every 5 minutes. Asks for the token (or reads `DUCKDNS_TOKEN`). Also `status`, `update`, `uninstall`. |

Details and a walk-through: [HOWTO: DuckDNS and Let's Encrypt](duckdns.md).

## Settings files

The packaged systemd units read extra options from these files. The installer creates them with commented examples and never overwrites them.

| File | Variable | Used by |
|---|---|---|
| `/etc/default/tc-control` | `TC_CONTROL_ARGS="…"` | `tc-control.service`, appended to `tc-control serve -db /var/lib/tc-control/control.db` |
| `/etc/default/tcd` | `TCD_ARGS="…"` | `tcd.service`, appended to `tcd -state /var/lib/tailconnect -socket /run/tailconnect/tcd.sock` |

Restart the service after editing. Variables inside these files are **not** expanded. For other unit changes (certificates, capabilities), use `sudo systemctl edit tc-control` or `tcd`; see [Enable HTTPS](installation.md#enable-https).

## Environment variables

| Variable | Used by | Effect |
|---|---|---|
| `TC_CONTROL_DB` | `tc-control` | Default database path |
| `TC_SOCKET` | `tc` | Default `tcd` socket |
| `TC_AUTHKEY` | `tc up` | Auth key, if `--authkey` isn't given |
| `TC_DISCO_DEBUG=1` | `tcd` | Log every path-discovery message (for debugging NAT traversal) |
| `TC_DUCKDNS_TOKEN` | `tc-control` | DuckDNS token for `-acme-dns duckdns`. Set it in `/etc/default/tc-control` (mode 600), not on the command line. |

## Relay map

`tc-control -relay-map FILE` advertises these relay regions to every device:

```json
{
  "Regions": [
    {
      "ID": 1, "Code": "home", "Name": "tc-control (embedded)",
      "Nodes": [{"Name": "1a", "URL": "/relay", "STUNPort": 3478}]
    },
    {
      "ID": 2, "Code": "eu", "Name": "Frankfurt",
      "Nodes": [{"Name": "2a", "URL": "https://relay-eu.example.com/relay", "HostName": "relay-eu.example.com", "STUNPort": 3478}]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `ID` | Region number (shown as `relay N` in `tc status`); must be unique and non-zero |
| `Code`, `Name` | Short and display names |
| `Nodes[].URL` | Relay endpoint. A path without a host (`/relay`) is the relay built into the control server, reached at the control URL. |
| `Nodes[].STUNPort` | UDP port of the region's STUN server; `0` = none |
| `Nodes[].HostName` | STUN host, if different from the URL's host |

## Ports

| Port | Protocol | Where | Who connects |
|---|---|---|---|
| 7740 | TCP | control server | devices → control API and built-in relay |
| 3478 | UDP | control server, `tc-relay` | devices → STUN |
| 7741 | TCP | control server | operators and tenants → web portal and API |
| 7742 | TCP | `tc-relay` | devices → standalone relay |
| 443 | TCP | control server or `tc-relay`, with `-listen :443` | devices → HTTPS; Let's Encrypt → certificate checks (`-acme-domain`) |
| 80 | TCP | with `-acme-http-listen :80` | Let's Encrypt → certificate checks |
| 7743, 7744 | TCP | with `-metrics-listen` (suggested ports; loopback or private) | your monitoring → metrics |
| 41641 | UDP | every device | device ↔ device (WireGuard, path discovery) |
| 53 | UDP and TCP | `100.100.100.100`, inside each device | the device's own programs → MagicDNS (never leaves the device) |

## Files and paths

| Path | What |
|---|---|
| `/usr/local/bin/{tc-control,tcd,tc,tc-relay}` | Binaries (`install.sh`) |
| `/etc/systemd/system/{tc-control,tcd}.service` | Units |
| `/etc/default/{tc-control,tcd}` | [Settings files](#settings-files) |
| `/var/lib/tc-control/control.db` | Server database: accounts, machines, shares, password and key hashes, the server's private keys. Mode 0700 directory, owned by the service. [Back it up](installation.md#back-up-and-restore). |
| `/var/lib/tailconnect/state.json` | Device keys and registration |
| `/var/lib/tailconnect/resolv.conf.backup` | Original `resolv.conf`, kept while `-dns file` is active |
| `/run/tailconnect/tcd.sock` | `tc` ↔ `tcd` socket |
| `/usr/local/share/doc/tailconnect/` | This documentation |
| `/var/lib/tc-control/acme/` | Let's Encrypt account key and certificates (`-acme-domain`). Back it up with the database. |
| `/var/lib/tc-control/tls/` | The self-signed certificate and its key (`-tls-self-signed`). Back it up: devices pinned this key. |
| `/etc/default/tc-control.pre-letsencrypt-*` | Settings backups made by `letsencrypt.sh` (`--restore` puts the newest back) |
| `/etc/duckdns/duckdns.conf` | DuckDNS name and token, root only (`duckdns.sh`) |
| `/usr/local/sbin/duckdns-update`, `/etc/systemd/system/duckdns.{service,timer}` | The DuckDNS updater and its 5-minute timer (`duckdns.sh`) |

## Addresses

| Range | Use |
|---|---|
| `100.64.0.0/10` | Device IPv4 addresses (the shared CGNAT range) |
| `fd7c:7c0e:a1e0::/48` | Device IPv6 addresses. Each device's IPv6 address ends in its IPv4 address: `100.64.0.2` ↔ `fd7c:7c0e:a1e0::6440:2`. |
| Routing table `124`, rules `5270`-`5272`, firewall mark `0x7c0000/0xff0000` | Used by `tcd` while the machine uses an [exit node](how-it-works.md#exit-nodes) |
| nftables table `tailconnect-exit` (`ip` and `ip6`) | NAT and forwarding on an exit node |
| `100.100.100.0/24` | Reserved for in-tunnel services. `100.100.100.100` is MagicDNS (and `fd7c:7c0e:a1e0::6464:6464` over IPv6). |
