# TailConnect

A self-hosted mesh VPN built on WireGuard, for Linux, Windows and Android. One small coordination server hands out addresses and keys. Devices then talk to each other directly over WireGuard, even when both are behind NAT, and reach each other by name. One server can host many separate networks (tenants), which can share individual machines with each other.

**Status: milestone 6 of 9.** The Linux client and server are complete: encrypted control channel, WireGuard mesh, NAT traversal with relay fallback, MagicDNS, and multi-tenant accounts with one-way machine sharing. Windows and Android are next (see [Roadmap](#roadmap)).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/portal-machines-dark.png">
  <img alt="Web portal, operator view: four machines online across two accounts" src="docs/images/portal-machines.png">
</picture>

<sub>Every screenshot and terminal image in this documentation comes from a real test network: a Raspberry Pi running the server and three Linux machines on a home LAN, one of them behind NAT, across two accounts (`richard` and `alice`). Use your own addresses in place of `192.168.10.x`. Secrets are masked.</sub>

## Features

- **One coordination server** (`tc-control`): a single static binary with an embedded SQLite database, a web portal and CLI, a relay and a STUN server. It runs happily on a Raspberry Pi.
- **Accounts and tenants:** every account is its own private network. Sign-up can be off, by invite, with operator approval, or open. Accounts' machines never see each other.
- **One-way sharing:** an account can share a single machine with another account. The other account's machines can then connect to it, but it can't connect back.
- **Direct WireGuard paths** between devices, found by STUN and hole punching through NAT. When no direct path exists, traffic goes through the built-in relay, still end-to-end encrypted. Switching between the two takes about 3 seconds.
- **MagicDNS:** every machine is reachable as `name.account.your-domain`, or just `name`. Split DNS through systemd-resolved, with a `resolv.conf` fallback.
- **Pre-auth keys** for joining devices: single-use or reusable, with an expiry and revocation.
- **Userspace mode** for containers and machines without root.
- **Secure by default:** the control channel uses Noise IK, every request is tied to the device's machine key, passwords are hashed with argon2id, other secrets are stored only as hashes, and relays can't read traffic.

## Quick start

On the **server**, download a release tarball, or build one with `make dist` (see [Installation](docs/installation.md#get-the-software)):

```sh
tar xzf tailconnect-v0.5.1-linux-amd64.tar.gz && cd tailconnect-v0.5.1-linux-amd64
sudo ./packaging/linux/install.sh server
sudo tc-control users create alice -operator -password             # your account (prompts for a password)
sudo tc-control keys create -user alice -reusable -expiration 24h    # prints tc-auth-…
```

On **every device**, from the same tarball:

```sh
sudo ./packaging/linux/install.sh client
sudo tc up --server http://SERVER:7740 --authkey tc-auth-…
tc status
ping other-device
```

On the server, open **TCP 7740** and **UDP 3478**. On devices with a firewall, open **UDP 41641**. That's all you need to get started. The [installation guide](docs/installation.md) covers HTTPS, the web portal, sign-up for other people, running without systemd or without root, upgrades and removal.

![Setup in five steps: install the server, create a user and key, install tcd on each device, join, verify](docs/images/setup-flow.svg)

## Documentation

| Guide | What's in it |
|---|---|
| [Installation](docs/installation.md) | Requirements, building, installing the server and clients, HTTPS, upgrading, uninstalling |
| [Usage](docs/usage.md) | Accounts and sign-up, joining devices, sharing machines, the web portal, admin CLI and API, the `tc` client, MagicDNS, relays |
| [Android](docs/android.md) | The Android app: build, install over USB, join, use |
| [LAN and internet setups](docs/network-setups.md) | Where to put the server: LAN only, on the internet, or at home reachable from outside; settings, ports and pitfalls |
| [Configuration](docs/configuration.md) | Every flag, settings file, environment variable, port and file path |
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
