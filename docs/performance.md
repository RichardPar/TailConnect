# Performance

How fast TailConnect moves traffic, how it scales on the server, and how to measure it yourself. All figures come from one machine (Intel i9-11950H laptop, 16 threads, Linux), so treat them as relative: your hardware and network will differ.

- [Throughput](#throughput)
- [Latency](#latency)
- [Server and packet paths](#server-and-packet-paths)
- [Known limits](#known-limits)
- [Measure it yourself](#measure-it-yourself)

---

## Throughput

![Tunnel throughput: kernel TUN 1,075 Mbit/s direct and 597 Mbit/s through the relay; userspace 386 and 369 Mbit/s](images/perf-throughput.svg)

| Path | Kernel TUN | Userspace (in-process) |
|---|---|---|
| Direct path | 1,075 Mbit/s | 386 Mbit/s |
| Through the relay | 597 Mbit/s | 369 Mbit/s |
| Bare network, no tunnel (reference) | 20,024 Mbit/s | |

- **Kernel TUN** is what a normal installation uses: `tests/perf/throughput.sh` runs two machines in network namespaces joined by a virtual Ethernet link, with real `tc0` interfaces and a single TCP stream.
- **Userspace** is `tcd -tun userspace` (gVisor's network stack inside the process), measured by `BenchmarkThroughput` between two daemons over loopback.
- The bare network is virtual Ethernet inside one host, so it's far faster than any real link; it shows the tunnel's own cost. The tunnel's direct-path limit here is about 1 Gbit/s, so on faster links the tunnel, not the network, sets the ceiling (see [Known limits](#known-limits)).

## Latency

![TCP round-trip time: bare network p50 31 µs, tunnel direct 175 µs, tunnel relay 279 µs; p99 58, 300 and 410 µs](images/perf-latency.svg)

| Path | p50 (median) | p99 |
|---|---|---|
| Bare network | 31 µs | 58 µs |
| Tunnel, direct | 175 µs | 300 µs |
| Tunnel, relay | 279 µs | 410 µs |

One-byte request and reply over TCP, 2,000 round trips, kernel TUN. The tunnel adds about 0.15 ms on a direct path and 0.25 ms through the relay; on a real network, the distance between the machines (and to the relay) dominates.

## Server and packet paths

From `make bench`:

| What | Cost | Why it matters |
|---|---|---|
| Packet filter, no shares | 7 ns per packet | the cost when sharing isn't used |
| Packet filter, shares exist, packet from a same-account machine | 58 ns, no allocations | every packet pays this once any share exists |
| Packet filter, reply from a shared machine | ~340 ns | only a shared machine's traffic pays this |
| MagicDNS interception, ordinary packet | 63 ns | every packet the host sends |
| MagicDNS local answer (1,000 machines) | ~2.5 µs | about 400,000 lookups a second per core |
| Network map for a machine in a 1,000-machine account, built and encoded | ~0.3 ms | per machine, per change it can see |
| One change fanned out to all 1,000 machines of an account | ~0.36 s of server CPU | e.g. a laptop roaming to a new address |
| What each machine is sent for that change | 0.4 KB (a delta), instead of a 343 KB full map | network traffic from the server per change |
| Relay policy check | ~165 ns per relayed packet | |
| Relay forwarding, one stream of 1,280-byte packets | ~130 MB/s | |
| Joining, with 2,000 machines in the account | ~3.4 ms per join | how fast a fleet can join |
| Password hash (argon2id) | ~55 ms | the portal runs four at once: about 70 sign-ins a second |

## Known limits

- **About 1 Gbit/s per stream through the tunnel.** magicsock reads and writes UDP in batches (`recvmmsg`/`sendmmsg`, up to 128 packets per system call) and the kernel TUN device uses offloads, but each UDP datagram is still one packet in the kernel: system calls are about 40% of CPU, encryption about 10%. UDP segmentation offload (GSO/GRO) is the next step to raise it.
- **Every change still costs the server a map per machine.** Machines are sent only what changed (a 0.4 KB delta instead of a 343 KB map in a 1,000-machine account), but the server still works out each machine's map, about 0.3 ms per machine per change.
- **The relay forwards ~130 MB/s per stream** in the benchmark, limited by per-packet work (a system call and a channel hand-off per packet).

## Measure it yourself

```sh
make bench          # Go benchmarks (a few minutes)
make perf           # throughput and latency through real kernel TUN devices
make perf-budget    # fail if key operations exceed their budgets
```

- **`make bench`** runs the Go benchmarks: the packet filter, MagicDNS, relay forwarding, map building and encoding at scale, the relay policy, the database, password hashing, and TCP throughput and round trips between two real daemons (direct and relayed). Run one area with, for example, `go test -run '^$' -bench . ./internal/control/`.
- **`make perf`** runs [tests/perf/throughput.sh](../tests/perf/throughput.sh): two machines in network namespaces (no root needed with unprivileged user namespaces), measured with a small tool, [tests/perf/tput](../tests/perf/tput/main.go), on the bare network, the tunnel's direct path and the relay. `DURATION=10s RTTS=5000` makes longer runs; `MIN_DIRECT_MBPS=500 MIN_RELAY_MBPS=300` makes it fail below a throughput budget.
- **`make perf-budget`** runs a few benchmarks and fails if they exceed limits set about 10× above the figures here. They catch regressions in complexity rather than noise.
- **The charts** on this page are drawn by [tests/perf/charts.py](../tests/perf/charts.py) from the figures at its top: update them from a new run and run `python3 tests/perf/charts.py`.
