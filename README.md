# TailConnect

A self-hosted mesh VPN built on WireGuard. A small coordination server hands out addresses and keys; devices then connect to each other directly over WireGuard, through NAT where possible and via a relay where not, and find each other by name. One server can host several separate networks (accounts), which can share individual machines with each other.

## Status

Supported platforms: Linux (server and client), Windows 10/11 and Android (clients).

Windows and Android machines can use an exit node, but only Linux machines can be one. See the [roadmap](#roadmap).

To get started, see the [quick start](QUICKSTART.md).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/portal-machines-dark.png">
  <img alt="Web portal, operator view: six machines online across two accounts, jellyfin an exit node, one waiting for approval" src="docs/images/portal-machines.png">
</picture>

<sub>The terminal images come from a real test network: a Raspberry Pi running the server and Linux machines on a home LAN, one of them behind NAT, across two accounts (`richard` and `alice`). The portal screenshots come from a demo network with the same accounts and machine names. The Android screenshot comes from a real tablet on the test network. Use your own addresses in place of `192.168.10.x`. Secrets are masked.</sub>

## Features

- `tc-control`, the coordination server: one static binary with an embedded SQLite database, web portal, admin CLI, relay and STUN server. Runs on a Raspberry Pi.
- Accounts: each account is an isolated network. Sign-up can be off, invite-only, operator-approved or open.
- One-way sharing: an account can share a single machine with another account. The other account's machines can connect to it; it can't connect back.
- Direct WireGuard paths found with STUN and hole punching. Without a direct path, traffic goes through a relay, still end-to-end encrypted. Failover between the two takes about 3 seconds.
- MagicDNS: machines resolve as `name.account.domain` or just `name`. An account can set its own domain. Split DNS through systemd-resolved, with a `resolv.conf` fallback, and through NRPT rules on Windows.
- Exit nodes: a Linux machine can route internet traffic for the other machines in its account. Linux, Windows and Android machines can use one (`tc up --exit-node NAME`, or the apps' Exit node menu). Off by default.
- Access rules within an account: tag machines and allow traffic from one tag to another on given ports.
- Machine lifecycle: key expiry (180 days by default, or never per machine), optional approval of new machines, removal of ephemeral machines.
- Pre-auth keys: single-use or reusable, ephemeral or pre-approved, with expiry and revocation.
- HTTPS without a web server or certbot: Let's Encrypt (HTTP-01, or DNS-01 through DuckDNS), or a self-signed certificate that clients pin by fingerprint.
- Windows client: a service with the Wintun driver and a tray app, with a one-click installer.
- Linux desktop app: a panel icon and status window (GTK 3, still built without cgo).
- Android app containing the same Go client.
- Standalone relays (`tc-relay`), authorised by the server; Prometheus metrics.
- Userspace mode for containers and machines without root.
- Security: Noise IK control channel, requests bound to the machine key, argon2id password hashes, other secrets stored only as hashes, relays see only encrypted traffic.

## Quick start

On the **server**, from a release tarball (or `make dist`):

```sh
sudo ./packaging/linux/install.sh server     # asks a few questions, creates your account, prints a join key
```

On **every device**:

```sh
sudo ./packaging/linux/install.sh client     # asks for the server URL and the key, then joins
tc status
```

No settings files need editing. [QUICKSTART.md](QUICKSTART.md) covers the full setup, including HTTPS, Android and the web portal.

## Documentation

| Guide | What's in it |
|---|---|
| [Quick start](QUICKSTART.md) | From nothing to two connected devices and the web portal, in ten minutes |
| [Installation](docs/installation.md) | Requirements, building, installing the server and clients, HTTPS (Let's Encrypt, self-signed or your own certificate), upgrading, uninstalling |
| [The web portal](docs/portal.md) | Every tab, column, button and setting of the portal, with screenshots |
| [Usage](docs/usage.md) | Accounts and sign-up, joining devices, sharing machines, the web portal, admin CLI and API, the `tc` client, MagicDNS, relays |
| [HTTPS with Let's Encrypt](docs/lets-encrypt.md) | Free certificates, obtained and renewed by the server itself: setup, testing, renewals, troubleshooting |
| [HOWTO: DuckDNS and Let's Encrypt](docs/duckdns.md) | A home server reachable from anywhere with a free DuckDNS name and a trusted certificate, step by step, with two scripts that do the work |
| [Windows](docs/windows.md) | The Windows client and tray app: package, install, join, use, upgrade, uninstall |
| [Linux desktop app](docs/linux-app.md) | The panel icon and window on a Linux desktop: install, use, who may connect, troubleshooting |
| [Android](docs/android.md) | The Android app: build, install over USB, join, use |
| [LAN and internet setups](docs/network-setups.md) | Where to put the server: LAN only, on the internet, or at home reachable from outside; settings, ports and pitfalls |
| [Configuration](docs/configuration.md) | Settings at a glance, then every flag, settings file, environment variable, port and file path |
| [How it works](docs/how-it-works.md) | Architecture, NAT traversal, MagicDNS, tenants and sharing, security model |
| [Troubleshooting](docs/troubleshooting.md) | Diagnosing joins, paths, DNS and services |
| [Performance](docs/performance.md) | Throughput, latency and server scale, with charts; how to measure it |
| [Development](docs/development.md) | Building, tests, end-to-end test scripts, code layout |

## Roadmap

Done:

- M1: Coordination server, pre-auth keys, admin CLI and web UI
- M2: Linux client (`tcd`/`tc`), Noise control channel, streaming network map, WireGuard mesh, userspace mode, systemd units
- M3: magicsock and relay fallback (built into `tc-control`, plus standalone `tc-relay`)
- M4: NAT traversal: STUN, authenticated disco pings, CallMeMaybe hole punching, latency-based home relay
- M5: MagicDNS: in-tunnel resolver, split DNS via systemd-resolved, `resolv.conf` fallback, reverse lookups, optional upstream forwarding
- M6: Multi-tenant accounts: passwords, sign-up modes, isolated networks, one-way sharing enforced by an in-tunnel packet filter
- M7: Windows client: Wintun, Windows service, named-pipe local API, NRPT for DNS, tray app, zip package with `tcd install`
- M8: Android app: the Go client behind a VpnService, built with the SDK tools only (no Gradle or NDK)
- M9: Hardening: key expiry, machine approval, ephemeral cleanup, tag-based access rules, batched UDP, delta map updates, relay authorisation, MagicDNS over TCP, built-in Let's Encrypt, metrics

Not done:

- Windows and Android: being an exit node
- UDP GSO/GRO for higher throughput
