# TailConnect

A self-hosted mesh VPN built on WireGuard, for Linux, Windows and Android. One small coordination server hands out addresses and keys. Devices then talk to each other directly over WireGuard, even when both are behind NAT, and reach each other by name. One server can host many separate networks (tenants), which can share individual machines with each other.

**Status:** the server, the Linux client and the Android app are complete:
- encrypted control channel, WireGuard mesh, and NAT traversal with relay fallback;
- MagicDNS;
- multi-tenant accounts with one-way sharing, and access rules;
- exit nodes;
- machine approval and key expiry;
- automatic HTTPS, and metrics.

Windows is next (see [Roadmap](#roadmap)).

**New here? Start with the [Quick start](QUICKSTART.md).**

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/portal-machines-dark.png">
  <img alt="Web portal, operator view: six machines online across two accounts, one waiting for approval" src="docs/images/portal-machines.png">
</picture>

<sub>The terminal images come from a real test network: a Raspberry Pi running the server and Linux machines on a home LAN, one of them behind NAT, across two accounts (`richard` and `alice`). The portal screenshots come from a demo network with the same accounts and machine names. The Android screenshot comes from a real tablet on the test network. Use your own addresses in place of `192.168.10.x`. Secrets are masked.</sub>

## Features

- **One coordination server** (`tc-control`): a single static binary with an embedded SQLite database, a web portal and CLI, a relay and a STUN server. It runs happily on a Raspberry Pi.
- **Accounts and tenants:** every account is its own private network. Sign-up can be off, by invite, with operator approval, or open. Accounts' machines never see each other.
- **One-way sharing:** an account can share a single machine with another account. The other account's machines can then connect to it, but it can't connect back.
- **Direct WireGuard paths** between devices, found by STUN and hole punching through NAT. When no direct path exists, traffic goes through the built-in relay, still end-to-end encrypted. Switching between the two takes about 3 seconds.
- **MagicDNS:** every machine is reachable as `name.account.your-domain`, or just `name`. Split DNS through systemd-resolved, with a `resolv.conf` fallback.
- **Exit nodes:** turn on a Linux machine as an exit node, and other machines in its account can send all their internet traffic through it (`tc up --exit-node NAME`). Off for every machine until turned on.
- **Access rules** within an account: tag machines, then allow *from → to on ports* (for example, laptops may reach the servers on SSH only).
- **Machine lifecycle:** keys that expire after 180 days (or never, per machine), optional approval of new machines, and automatic removal of ephemeral machines.
- **Pre-auth keys** for joining devices: single-use or reusable, ephemeral or pre-approved, with an expiry and revocation.
- **Automatic HTTPS** from Let's Encrypt, built in: no web server, proxy or certbot.
- **Android app** for phones and tablets, with the same client inside.
- **Standalone relays** near your machines, checked against the server; **metrics** for monitoring.
- **Userspace mode** for containers and machines without root.
- **Secure by default:** the control channel uses Noise IK, every request is tied to the device's machine key, passwords are hashed with argon2id, other secrets are stored only as hashes, and relays can't read traffic.

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

There are no settings files to edit. **[QUICKSTART.md](QUICKSTART.md)** walks through it all, including HTTPS, Android and the web portal, in about ten minutes.

## Documentation

| Guide | What's in it |
|---|---|
| [Quick start](QUICKSTART.md) | From nothing to two connected devices and the web portal, in ten minutes |
| [Installation](docs/installation.md) | Requirements, building, installing the server and clients, HTTPS, upgrading, uninstalling |
| [The web portal](docs/portal.md) | Every tab, column, button and setting of the portal, with screenshots |
| [Usage](docs/usage.md) | Accounts and sign-up, joining devices, sharing machines, the web portal, admin CLI and API, the `tc` client, MagicDNS, relays |
| [HTTPS with Let's Encrypt](docs/lets-encrypt.md) | Free certificates, obtained and renewed by the server itself: setup, testing, renewals, troubleshooting |
| [Android](docs/android.md) | The Android app: build, install over USB, join, use |
| [LAN and internet setups](docs/network-setups.md) | Where to put the server: LAN only, on the internet, or at home reachable from outside; settings, ports and pitfalls |
| [Configuration](docs/configuration.md) | Settings at a glance, then every flag, settings file, environment variable, port and file path |
| [How it works](docs/how-it-works.md) | Architecture, NAT traversal, MagicDNS, tenants and sharing, security model |
| [Troubleshooting](docs/troubleshooting.md) | Diagnosing joins, paths, DNS and services |
| [Performance](docs/performance.md) | Throughput, latency and server scale, with charts; how to measure it |
| [Development](docs/development.md) | Building, tests, end-to-end test scripts, code layout |

## Roadmap

1. ✅ Coordination server, pre-auth keys, admin CLI and admin web UI
2. ✅ Linux client (`tcd`/`tc`), Noise control channel, streaming network map, WireGuard mesh, userspace mode, systemd units
3. ✅ magicsock, relay fallback (built into `tc-control`, plus standalone `tc-relay`), ~3s failover
4. ✅ NAT traversal: STUN, authenticated disco pings, CallMeMaybe hole punching, latency-based home relay
5. ✅ MagicDNS: in-tunnel resolver, split DNS via systemd-resolved, resolv.conf fallback, reverse lookups, optional upstream forwarding
6. ✅ Multi-tenant: accounts with passwords, sign-up modes and approval, isolated networks per account, one-way machine sharing with an in-tunnel packet filter
7. Windows port (Wintun, Windows service, NRPT)
8. ✅ Android app: the Go client with a VpnService and a phone/tablet GUI, built with the SDK's own tools (no Gradle or NDK)
9. ✅ Hardening: key expiry, machine approval and ephemeral cleanup; access rules with tags; batched UDP and delta maps; standalone relays checked against the server; MagicDNS over TCP; built-in HTTPS from Let's Encrypt; metrics
