# Configuration reference

Every option, file and port. For what to set and when, see [Installation](installation.md) and [Usage](usage.md).

- [tc-control serve](#tc-control-serve)
- [tc-control admin commands](#tc-control-admin-commands)
- [tcd](#tcd)
- [tc](#tc)
- [tc-relay](#tc-relay)
- [Settings files](#settings-files)
- [Environment variables](#environment-variables)
- [Relay map](#relay-map)
- [Ports](#ports)
- [Files and paths](#files-and-paths)
- [Addresses](#addresses)

---

## tc-control serve

The coordination server: control API, built-in relay, STUN, web portal.

| Flag | Default | Description |
|---|---|---|
| `-db` | see [below](#tc-control-admin-commands) | SQLite database. The packaged unit uses `/var/lib/tc-control/control.db`. |
| `-listen` | `:7740` | Control API and built-in relay (TCP) |
| `-admin-listen` | `127.0.0.1:7741` | Web portal and its API. `""` turns them off. Keep it on loopback, or use TLS if other people sign in to it ([how](installation.md#open-the-portal-to-other-people)). |
| `-signup` | `approval` | Who may create accounts in the portal: `off`, `approval` (pending until an operator approves), `invite` (needs an invite code) or `open`. A valid invite skips approval in every mode except `off`. |
| `-stun-listen` | `:3478` | Built-in STUN server (UDP). `""` turns it off; devices then can't learn their public address, and NAT traversal suffers. |
| `-domain` | `tc.internal` | MagicDNS suffix: devices are `<name>.<domain>`. Needs two or more labels of lowercase letters, digits and `-`. |
| `-magic-dns` | `true` | Devices resolve MagicDNS names and point the OS at the resolver. `=false` turns it off. |
| `-dns-nameservers` | none | Comma-separated upstream resolvers. When set, devices send **all** DNS through MagicDNS, which forwards non-MagicDNS names to these. |
| `-relay` | `true` | Serve the built-in relay at `/relay` on the control listener (registered devices only) |
| `-relay-map` | none | JSON [relay map](#relay-map) to advertise instead of the built-in relay alone |
| `-public-url` | derived from `-listen` | URL shown in the portal for clients to use |
| `-tls-cert`, `-tls-key` | none | PEM certificate (with chain) and key. Turns on HTTPS for both the control and portal listeners. |
| `-log-json` | `false` | Log in JSON instead of text |

## tc-control admin commands

```
tc-control users create NAME [-operator] [-password] | list | delete NAME
tc-control users passwd NAME | approve NAME | suspend NAME | activate NAME
tc-control users role NAME operator|tenant
tc-control invites create [-expiration 168h] | list | revoke ID
tc-control keys create -user NAME [-reusable] [-ephemeral] [-expiration 24h]
tc-control keys list [-user NAME] | revoke ID
tc-control nodes list [-user NAME] | delete ID | rename ID NEWNAME
tc-control shares list [-user NAME] | create NODE_ID ACCOUNT | link NODE_ID [-expiration 168h]
tc-control shares accept ID | revoke ID
tc-control admin-token
tc-control version
```

| Flag | Applies to | Description |
|---|---|---|
| `-db PATH` | all | Database. Default: `$TC_CONTROL_DB`, else `/var/lib/tc-control/control.db` if it exists, else `./control.db` |
| `-json` | `list` commands | Machine-readable output |
| `-user NAME` | `keys create` (required), `keys list`, `nodes list`, `shares list` | Account to create the key for, or to filter by |
| `-operator` | `users create` | Make the account an operator |
| `-password` | `users create` | Also set a password (prompted twice on a terminal, else one line from stdin), as `users passwd` does |
| `-reusable` | `keys create` | The key can register any number of devices until it expires |
| `-ephemeral` | `keys create` | Devices joining with it are marked ephemeral |
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
| `-verbose` | `false` | Log WireGuard internals |
| `-version` | | Print the version and exit |

## tc

| Command | Flags |
|---|---|
| `tc up` | `--server URL`, `--authkey KEY` (or `$TC_AUTHKEY`), `--hostname NAME`, `--server-key mkey:…` |
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
| `-allow-any` | `false` | **Required.** Relay for any device that proves it owns its key. A standalone relay can't check registrations with the control server yet. |
| `-listen` | `:7742` | Relay listen address (TCP) |
| `-stun-listen` | `:3478` | STUN server (UDP). `""` turns it off. |
| `-key-file` | `relay.key` | Relay private key, created if missing |
| `-public-url` | derived | Relay URL, used only for the example relay map it prints |
| `-tls-cert`, `-tls-key` | none | Serve HTTPS |
| `-log-json` | `false` | JSON logs |
| `-version` | | Print the version and exit |

`GET /` on the relay port shows its version, connected clients and packet counters.

---

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
| 7741 | TCP | control server (loopback by default) | operators and tenants → web portal and API |
| 7742 | TCP | `tc-relay` | devices → standalone relay |
| 41641 | UDP | every device | device ↔ device (WireGuard, path discovery) |
| 53 | UDP | `100.100.100.100`, inside each device | the device's own programs → MagicDNS (never leaves the device) |

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

## Addresses

| Range | Use |
|---|---|
| `100.64.0.0/10` | Device IPv4 addresses (the shared CGNAT range) |
| `fd7c:7c0e:a1e0::/48` | Device IPv6 addresses. Each device's IPv6 address ends in its IPv4 address: `100.64.0.2` ↔ `fd7c:7c0e:a1e0::6440:2`. |
| `100.100.100.0/24` | Reserved for in-tunnel services. `100.100.100.100` is MagicDNS (and `fd7c:7c0e:a1e0::6464:6464` over IPv6). |
