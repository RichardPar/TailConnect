# TailConnect

A self-hosted mesh VPN built on WireGuard, for Linux, Windows and Android. One small coordination server hands out addresses and keys. Every device then talks to every other device directly over WireGuard, even when both are behind NAT, and reaches the others by name.

**Status: milestone 5 of 8.** The Linux client and server are complete: encrypted control channel, WireGuard mesh, NAT traversal with relay fallback, and MagicDNS. Windows and Android are next (see [Roadmap](#roadmap)).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/admin-machines-dark.png">
  <img alt="Admin web UI showing three machines online" src="docs/images/admin-machines.png">
</picture>

<sub>Every screenshot and terminal image in this documentation comes from a real test network: two physical machines on a home LAN, one also hosting a node behind NAT. Use your own addresses in place of `192.168.10.x`. Secrets are masked.</sub>

## Features

- **One coordination server** (`tc-control`): a single static binary with an embedded SQLite database, an admin web UI and CLI, a relay and a STUN server.
- **Direct WireGuard paths** between devices, found by STUN and hole punching through NAT. When no direct path exists, traffic goes through the built-in relay, still end-to-end encrypted. Switching between the two takes about 3 seconds.
- **MagicDNS:** every device is reachable as `name.your-domain`, or just `name`. Split DNS through systemd-resolved, with a `resolv.conf` fallback.
- **Pre-auth keys** for joining devices: single-use or reusable, with an expiry and revocation.
- **Userspace mode** for containers and machines without root.
- **Secure by default:** the control channel uses Noise IK, every request is tied to the device's machine key, secrets are stored only as hashes, and relays can't read traffic.

## Quick start

On the **server**, download a release tarball, or build one with `make dist` (see [Installation](docs/installation.md#get-the-software)):

```sh
tar xzf tailconnect-v0.5.1-linux-amd64.tar.gz && cd tailconnect-v0.5.1-linux-amd64
sudo ./packaging/linux/install.sh server
sudo tc-control users create alice
sudo tc-control keys create -user alice -reusable -expiration 24h    # prints tc-auth-…
```

On **every device**, from the same tarball:

```sh
sudo ./packaging/linux/install.sh client
sudo tc up --server http://SERVER:7740 --authkey tc-auth-…
tc status
ping other-device
```

On the server, open **TCP 7740** and **UDP 3478**. On devices with a firewall, open **UDP 41641**. That's all you need to get started. The [installation guide](docs/installation.md) covers HTTPS, the admin UI, running without systemd or without root, upgrades and removal.

![Setup in five steps: install the server, create a user and key, install tcd on each device, join, verify](docs/images/setup-flow.svg)

## Documentation

| Guide | What's in it |
|---|---|
| [Installation](docs/installation.md) | Requirements, building, installing the server and clients, HTTPS, upgrading, uninstalling |
| [Usage](docs/usage.md) | Joining devices, the admin web UI, admin CLI and API, the `tc` client, MagicDNS, relays |
| [Configuration](docs/configuration.md) | Every flag, settings file, environment variable, port and file path |
| [How it works](docs/how-it-works.md) | Architecture, NAT traversal, MagicDNS, security model |
| [Troubleshooting](docs/troubleshooting.md) | Diagnosing joins, paths, DNS and services |
| [Development](docs/development.md) | Building, tests, end-to-end test scripts, code layout |

## Roadmap

1. ✅ Coordination server, pre-auth keys, admin CLI and admin web UI
2. ✅ Linux client (`tcd`/`tc`), Noise control channel, streaming network map, WireGuard mesh, userspace mode, systemd units
3. ✅ magicsock, relay fallback (built into `tc-control`, plus standalone `tc-relay`), ~3s failover
4. ✅ NAT traversal: STUN, authenticated disco pings, CallMeMaybe hole punching, latency-based home relay
5. ✅ MagicDNS: in-tunnel resolver, split DNS via systemd-resolved, resolv.conf fallback, reverse lookups, optional upstream forwarding
6. Windows port (Wintun, Windows service, NRPT)
7. Android port (gomobile, VpnService)
8. Hardening: ACLs, key expiry, node approval, ephemeral node cleanup, packaging
