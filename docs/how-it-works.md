# How it works

![Architecture: tc-control streams network maps to devbox, laptop and natbox over Noise; the devices talk to each other directly over WireGuard](images/architecture.svg)

TailConnect has a **control plane** and a **data plane**. The control server (`tc-control`) knows which accounts and machines exist and tells every machine about its peers. It never carries their traffic. Machines (`tcd`) carry traffic between themselves over WireGuard: directly when they can, and through a relay when they can't. One server hosts many accounts (tenants), each a separate network.

- [Keys](#keys)
- [Joining](#joining)
- [The network map](#the-network-map)
- [Tenants](#tenants)
- [Sharing and the packet filter](#sharing-and-the-packet-filter)
- [Data plane](#data-plane)
- [NAT traversal](#nat-traversal)
- [Relays](#relays)
- [MagicDNS](#magicdns)
- [Resilience](#resilience)
- [Security model](#security-model)

---

## Keys

Each device generates three key pairs, all Curve25519, and keeps them in `/var/lib/tailconnect/state.json`:

| Key | Prefix | Used for |
|---|---|---|
| Machine key | `mkey:` | Identifies the device to the control server (Noise channel) |
| Node key | `nodekey:` | The device's WireGuard key. Peers and relays know the device by it. |
| Disco key | `discokey:` | Seals path-discovery messages between peers |

The server has its own machine key, plus a relay key, stored in its database. Private keys never leave the machine that made them.

## Joining

1. `tc up --server URL --authkey KEY` asks the local `tcd` to register.
2. `tcd` fetches the server's public key from `GET /key` and pins it. Over HTTPS this is authenticated; over plain HTTP it's trust on first use, unless you pass `--server-key`.
3. `tcd` opens a **Noise IK** channel to the server, carried in an HTTP Upgrade on `POST /machine/noise`. The handshake proves the device holds its machine key and the server holds the pinned key. Everything after that runs inside the channel, as HTTP/2 requests.
4. The device sends its node key, disco key, hostname and the auth key. The server checks the auth key (and that its account is active), records the device in that account, picks a name unique within the account, and gives it the lowest free address in `100.64.0.0/10` (unique across the whole server), plus the matching IPv6 address.

A device can only act on its own registration: every request is tied to the machine key that made the Noise handshake. Knowing other devices' public keys gets an attacker nothing.

## The network map

After joining, `tcd` keeps one streaming request open. The server answers with a **network map**: this machine, its peers (name, addresses, node and disco keys, reported endpoints, home relay, and for other accounts' machines whether they may open connections), the DNS settings and the relay map. Whenever any of that changes, the server pushes a new map:
- a machine joins, leaves or is renamed;
- a machine reports new endpoints;
- a share is created, accepted or ended, or an account is suspended;
- anything is edited from the portal, the API or the CLI.

The server notices changes made by other processes, such as the CLI, through a change counter that database triggers keep up to date, which it checks every second. Keep-alives every 30 seconds keep the stream open through middleboxes.

## Tenants

Every account is a tenant: a separate network that happens to share the server. Isolation is enforced at three points:

- **Network maps.** A machine's map contains its own account's machines, plus machines involved in a share with its account ([below](#sharing-and-the-packet-filter)). Nothing else: other accounts' machines, addresses and endpoints never reach it, so it can't even address them. Without a peer entry, WireGuard drops anything they send.
- **Names.** Machines are named `machine.account.domain`, unique per account. Each machine's resolver answers only from its own map, so other accounts' names don't resolve.
- **Relay.** The built-in relay keeps a table of which account each node key belongs to, and which accounts each machine is shared with (rebuilt within a second of any change). It forwards a packet only between machines that may talk.

Accounts that are pending approval or suspended are cut off the same way: their machines drop out of everyone's map, the relay refuses them, and they get an empty map with a notice. Their keys stay valid, so reactivation restores everything at once.

Operators are tenants too, for networking: an operator's own machines are as isolated as anyone's. The operator role only grants management of the server.

## Sharing and the packet filter

A share lets one account's machines connect to one machine of another account. For a machine N, the server computes:

- **its peers:** its own account's machines, the machines shared with its account, and, if N itself is shared, the recipient accounts' machines (so their connections can be answered);
- **for each peer P from another account, whether P may open connections to N:** only if N is shared with P's account. Otherwise P is marked *no-initiate*.

Every `tcd` runs a small stateful **packet filter** between WireGuard and the TUN device. Packets this machine sends to a no-initiate peer create flow entries (TCP and UDP by address and ports, ping by identifier). Packets from a no-initiate peer are delivered only if they belong to one of those flows; ICMP errors pass too, for path-MTU discovery. Everything else from that peer, including a TCP SYN, a UDP packet to a fresh port or a ping, is dropped and counted (`FilterDropped` in `tc status --json`). Idle flows expire: TCP after 30 minutes (5 seconds after a reset), UDP after 2 minutes, ping after 30 seconds.

The filter sits on the **receiving** side, so the machines being protected enforce the rule themselves; a compromised shared machine can't turn it off. The source address of a tunnel packet can be trusted for this, because WireGuard only accepts packets from a peer with that peer's own tunnel addresses as the source. When a share is added or removed, restrictions are applied before the new peer is added and lifted only after the old one is removed, so no packet slips through in between.

If two accounts share machines with each other, each may open connections to the other's shared machine, which gives a two-way link between those two machines only.

## Data plane

`tcd` runs **wireguard-go** on a TUN device (`tc0`). Each network map is applied to WireGuard as a diff, so existing sessions survive updates. Every peer gets a /32 and a /128 route on `tc0` (tagged `proto 124`). Handshakes are started by traffic, so idle peers cost nothing, which matters on battery.

Underneath WireGuard sits **magicsock**, TailConnect's transport. WireGuard addresses each peer by its node key instead of an IP address, and magicsock picks the actual path for every packet:

- a **direct** UDP path, once one is confirmed;
- otherwise the peer's **relay**.

A direct path that stops answering for 3 seconds is dropped, and traffic moves to the relay. When the direct path comes back, traffic returns to it.

## NAT traversal

Most devices sit behind NAT, so they don't know the address others can reach them at. TailConnect finds direct paths like this:

1. **STUN.** Each device sends STUN requests from its WireGuard socket to the control server (UDP 3478) and to any other relay regions. The answer is the device's public address and port as seen from outside (its NAT mapping). It reports that to the control server, along with its local interface addresses. These are its **endpoints**, and they appear in every peer's network map.
2. **Disco pings.** When two devices start talking, each sends **disco** pings to all of the other's endpoints. Disco messages are sealed with NaCl box between the two devices' disco keys, so they can't be forged.
3. **CallMeMaybe.** At the same moment, each sends a *CallMeMaybe* message through the relay, asking the other side to ping back. Both sides now send at once, so each NAT sees outgoing traffic to the other's address and lets the replies in: a **hole is punched** in both NATs.
4. **Pong.** The first authenticated pong confirms the path and measures its latency, and traffic switches to it. Heartbeat pings every few seconds keep the path, and the NAT mapping, alive while the devices are active. The best path is re-evaluated as pongs come in.

**What works.** Ordinary home-router NATs keep the same public port for a socket and only let in replies to traffic sent out. These are punched on the first packet; `tests/e2e/nat.sh` checks this against routers configured like OpenWrt.

**What doesn't.** Some NATs can't be punched:
- NATs that pick a new public port for every destination ("symmetric" NAT, common on mobile carrier networks);
- Linux routers with no firewall on their WAN input, where stray packets create conntrack entries that make the NAT rewrite ports.

Peers behind these use the relay, which always works.

## Relays

A relay forwards WireGuard packets between devices that can't reach each other directly. Devices connect to their **home relay**: the region with the lowest STUN latency. They only switch to another region when it's at least 30% faster, to avoid flapping. A device sends packets for a peer to the peer's home relay, addressed by node key. The relay passes them on without being able to read them.

The connection is an HTTP Upgrade (`tailconnect-relay-v1`) on the relay's URL. The relay checks that the device owns its node key with a NaCl box challenge. The relay built into `tc-control` also refuses devices that aren't registered.

## MagicDNS

Each device runs a small DNS resolver at `100.100.100.100`, answering from the network map it already has:

- **A** and **AAAA** records for `<machine>.<account>.<domain>`, for every machine in its map;
- **PTR** records for tunnel addresses;
- **NXDOMAIN** for unknown names under the domain.

There's no socket: `tcd` catches UDP packets to `100.100.100.100:53` as they enter the TUN device, before WireGuard sees them, and writes the answer straight back. Two consequences:
- it works the same on every platform;
- only the device itself can query it, because peers' packets arrive on the other side of WireGuard.

Then the OS is pointed at the resolver:
- **systemd-resolved:** `tc0` gets `100.100.100.100` as its DNS server, with the account's domain and then the base domain as search domains, and routing domains for the reverse zones of `100.64.0.0/10` and the IPv6 range. resolved sends only those names there (split DNS). When the search domains change on a running link, `tcd` reconfigures the link from scratch, because only then does resolved rewrite the stub `resolv.conf` that glibc reads.
- **resolv.conf:** the resolver becomes the only nameserver. It forwards other names to the original nameservers, one after another, with a 2-second timeout each. Answers larger than the client accepts come back truncated.

With `-dns-nameservers` on the server, devices send everything to MagicDNS (resolved's `~.` routing domain), and it forwards non-MagicDNS names to those servers.

## Resilience

- **Control server down.** Tunnels keep running on the last network map, and `tcd` reconnects with backoff. Devices that change networks meanwhile can still find each other through the relay, as long as the relay is up. The built-in relay is part of the control server, so for that case run a [separate relay](usage.md#relays).
- **Device removed by its owner or an operator.** Its tunnel is torn down, it goes to the logged-out state, and it must join again with an auth key.
- **Account suspended.** Its machines are cut off within a second but keep their keys and their stream to the server, so reactivation restores the network without touching them.
- **Server moved.** `tc up --server NEW` keeps the registration when the new URL serves the same server key.

## Security model

- **Control channel.** Everything after `GET /key` runs inside Noise IK, and each request is tied to the client's machine key. Over plain HTTP, the server key is trusted on first use. Use HTTPS, or pin it with `--server-key`, to close that gap.
- **Secrets at rest.** Passwords are hashed with argon2id (19 MiB, 2 passes, per-password salt); auth keys, invites, share links and the admin token are stored only as SHA-256 hashes. The database also holds the server's private machine key and relay key, so protect it and its backups.
- **Tenant isolation.** See [Tenants](#tenants). In the portal and API, another account's machines, keys and shares look like they don't exist (404), and operator endpoints refuse tenants.
- **Web portal.**
  - HMAC-signed `SameSite=Strict` session cookies, valid for 12 hours. A password change, suspension or role change ends that account's sessions; replacing the admin token ends token sessions.
  - Sign-in and sign-up: 10 attempts per IP address, then one every 6 seconds; failed sign-ins take the same time whether or not the account exists; at most four password hashes are computed at once.
  - Writes are accepted only as JSON, and the request origin is checked. A strict Content Security Policy.
  - It listens on loopback by default; `tc-control` warns if it listens elsewhere without TLS.
- **Sharing.** One-way, enforced by the receiving machines' packet filter ([details](#sharing-and-the-packet-filter)).
- **Path discovery.** Disco messages are sealed with NaCl box between the peers' disco keys, which are published in the network map. Discovery can't be spoofed to divert traffic.
- **Data.** WireGuard traffic is encrypted end to end between devices. Neither the control server nor the relays can read it.
- **Relays.** A device must prove it owns its node key before the relay accepts packets for it, so nobody can claim another device's key to intercept its packets. The built-in relay serves only registered machines of active accounts, and only between machines that may talk; standalone `tc-relay` serves anyone who proves a key (`-allow-any`).
- **MagicDNS.** It answers only the local device and isn't reachable from peers, so it can't be used as an open resolver.
- **Local API.** `tc` talks to `tcd` over a Unix socket. The caller's UID (`SO_PEERCRED`) decides what it may do: status for anyone; up, down and logout for root.
- **Least privilege.** `tc-control` runs as an unprivileged dynamic user. `tcd` runs as root, limited to `CAP_NET_ADMIN` and `CAP_NET_RAW`, with a read-only system except `/etc/resolv.conf`.

Not yet: access rules within an account (every machine of an account can reach every other), device approval and key expiry. These are planned for milestone 9.
