# Development

## Build and test

Requires Go 1.26. `make` is optional: every target is a thin wrapper around `go`.

```sh
make build          # bin/tc-control, bin/tcd, bin/tc, bin/tc-relay (version from git describe)
make test           # go vet + go test -race ./...
make e2e            # network-namespace tests (below)
make cross          # compile checks for Windows and Android
make dist           # release tarballs in dist/
```

`go test -race ./...` includes in-process end-to-end tests. Real `tcd` daemons run on userspace network stacks against a real `tc-control`, with no root needed. They cover:
- joining, traffic and `down`/`up`;
- removal, logout and rejoining;
- relay fallback;
- MagicDNS lookups, reverse lookups and renames;
- moving the server to a new address;
- tenant isolation (no peers, names or traffic across accounts) and account suspension;
- one-way sharing: the recipient reaches the shared machine, the shared machine can't open connections back, revoking ends it.

Other packages test the pieces directly: accounts, invites and shares in `internal/db`; sign-up modes, tenant scoping, sessions and rate limits in `internal/admin`; map isolation, sharing and the relay policy in `internal/control`; the packet filter with crafted IPv4 and IPv6 packets in `internal/filter`.

## End-to-end scripts

These build the binaries, then run them in private network namespaces with real TUN devices, routes, nftables NAT and `ping`. They run without root if unprivileged user namespaces are enabled (the default on most distributions). Each prints `== PASS`, or the failing step plus the logs. Set `KEEP_LOGS=DIR` to keep the logs.

| Script | What it checks |
|---|---|
| `tests/e2e/lan.sh` | Two devices on a bridged LAN: join, ping, routes, relay failover and recovery (via blackhole routes), admin removal, logout |
| `tests/e2e/nat.sh` | Two devices behind separate NAT routers (OpenWrt-style firewalls): STUN, hole punching on the first packet, relay fallback when UDP is cut, recovery. Then MagicDNS through glibc (short names, reverse lookups, NXDOMAIN, forwarding to a fake upstream); a second account's machine on another network behind site b's router (isolation, then a one-way share and its revocation); and `resolv.conf` restored on stop. |

Debugging options for `nat.sh`:
- `TC_DISCO_DEBUG=1` logs disco messages;
- `TC_NAT_PCAP=1` records UDP on both routers' WAN side with `tests/e2e/udpsniff.py`.

## Performance

```sh
make bench          # Go benchmarks
make perf           # throughput and latency through real kernel TUN devices
make perf-budget    # fail if key operations exceed their budgets
```

What each measures, current figures with charts and the known limits are in [Performance](performance.md).

## Code layout

| Path | What |
|---|---|
| `cmd/tc-control` | Coordination server and admin CLI |
| `cmd/tcd` | Client daemon: TUN or userspace networking, wiring for OS integration |
| `cmd/tc` | Client CLI |
| `cmd/tc-relay` | Standalone relay and STUN server |
| `internal/control` | Control API: Noise upgrade, register, map streaming, logout; embedded relay setup |
| `internal/controlclient` | Client side of the control protocol |
| `internal/noise` | Noise IK handshake and encrypted framed stream |
| `internal/protocol` | Wire types shared by client and server |
| `internal/daemon` | `tcd` core: persisted state, map-stream loop, endpoint discovery |
| `internal/engine` | wireguard-go device, peer config applied as diffs, netlink router, DNS wiring |
| `internal/magicsock` | WireGuard transport: per-packet path choice, disco path discovery, STUN, home relay |
| `internal/disco` | Path-discovery messages (ping, pong, CallMeMaybe), sealed with NaCl box |
| `internal/stun` | STUN Binding client and server (RFC 5389) |
| `internal/relay` | Relay protocol, server and client |
| `internal/dns` | MagicDNS: resolver, TUN packet interception, OS configuration (systemd-resolved, resolv.conf) |
| `internal/filter` | In-tunnel stateful packet filter that makes sharing one-way |
| `internal/password` | Password hashing (argon2id) |
| `internal/localapi` | `tc` ↔ `tcd` API over a Unix socket (SO_PEERCRED) |
| `internal/admin` | Web portal: accounts, sign-up, sessions, sharing; JSON API and embedded UI (`ui/`) |
| `internal/db` | SQLite store (pure Go): accounts, machines, keys, invites, shares; a change counter kept by triggers |
| `internal/ipam`, `internal/key` | Address allocation, typed keys |
| `packaging/linux` | systemd units, settings files, `install.sh` |
| `tests/e2e` | Network-namespace test scripts and helpers |
| `tests/perf` | Throughput script and its measuring tool (`tput`) |

## Conventions

- No cgo. Every binary must cross-compile with `CGO_ENABLED=0`, and `make cross` checks Windows and Android.
- Platform code lives in `_linux.go` and `_other.go` files with build tags, behind small interfaces: `engine.Router`, `dns.OSConfigurator`.
- Peer changes are applied as diffs, never by tearing down the device.
- A failing OS integration (DNS, for instance) is reported in `tc status`. It doesn't take the tunnel down.
