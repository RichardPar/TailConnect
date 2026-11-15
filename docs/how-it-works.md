# How it works

![Architecture: tc-control streams network maps to devbox, laptop and natbox over Noise; the devices talk to each other directly over WireGuard](images/architecture.svg)

TailConnect has a **control plane** and a **data plane**. The control server (`tc-control`) knows which accounts and machines exist and tells every machine about its peers. It never carries their traffic. Machines (`tcd`) carry traffic between themselves over WireGuard: directly when they can, and through a relay when they can't. One server hosts many accounts (tenants), each a separate network.

- [Keys](#keys)
- [Joining](#joining)
- [The network map](#the-network-map)
- [Tenants](#tenants)
- [Sharing and the packet filter](#sharing-and-the-packet-filter)
- [Access rules and the packet filter](#access-rules-and-the-packet-filter)
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
2. `tcd` fetches the server's public key from `GET /key` and pins it. Over HTTPS this is authenticated, by a trusted certificate or one whose key fingerprint the device pinned (`--tls-fingerprint`); over plain HTTP it's trust on first use, unless you pass `--server-key`.
3. `tcd` opens a **Noise IK** channel to the server, carried in an HTTP Upgrade on `POST /machine/noise`. The handshake proves the device holds its machine key and the server holds the pinned key. Everything after that runs inside the channel, as HTTP/2 requests.
4. The device sends its node key, disco key, hostname and the auth key. The server checks the auth key (and that its account is active), records the device in that account, picks a name unique within the account, and gives it the lowest free address in `100.64.0.0/10` (unique across the whole server), plus the matching IPv6 address.

A device can only act on its own registration: every request is tied to the machine key that made the Noise handshake. Knowing other devices' public keys gets an attacker nothing.

## The network map

After joining, `tcd` keeps one streaming request open. The server answers with a **network map**: this machine, its peers (name, addresses, node and disco keys, reported endpoints, home relay, and for other accounts' machines whether they may open connections), the DNS settings and the relay map. Whenever any of that changes, the server pushes a new map:
- a machine joins, leaves or is renamed;
- a machine reports new endpoints;
- a share is created, accepted or ended, or an account is suspended;
- anything is edited from the portal, the API or the CLI.

After the first map on a stream, the server sends only what changed: the peers that were added or changed, and the ones that were removed. In a 1,000-machine account that's about 0.4 KB per change instead of a 340 KB map. A change to the machine itself, the DNS settings or the relays brings a full map again. The server builds every map from one consistent read of the database, so a machine never sees a half-applied edit (such as a new access rule without the tags it refers to). Clients older than protocol version 2 always get full maps.

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

## Access rules and the packet filter

An account's rules (*from → to on ports*, with selectors `*`, `tag:NAME` or a machine name) are compiled into a policy in the server's snapshot. For machine N and each peer P of the same account, the server computes what P may open on N (the union of matching rules) and what N may open on P:

- neither: P is left out of N's map (and N out of P's), and the relay won't carry packets between them;
- P may open everything: P is an ordinary peer;
- otherwise P is marked *no-initiate* with the list of allowed ports (`Inbound`).

N's packet filter treats such a peer like a shared machine, except that new connections to an allowed port (TCP or UDP by destination port, ping for `icmp`) pass too. Replies to N's own connections always pass. A client that doesn't understand port lists still sees *no-initiate* and blocks everything new from that peer: it fails closed. An account without rules has no policy, so maps and the filter work exactly as without access rules. A stored rule that fails to compile makes the account deny everything rather than allow it.

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

- **A** and **AAAA** records for `<machine>.<account>.<domain>` (or `<machine>.<account's own domain>`), for every machine in its map;
- **PTR** records for tunnel addresses;
- **NXDOMAIN** for unknown names under the domain.

The map lists every domain the device must answer (`DNS.Domains`): the base domain, plus the own domains of accounts whose machines are in the map. A device only ever answers, and routes to the resolver, domains of accounts it can see.

There's no socket: `tcd` catches UDP packets to `100.100.100.100:53` as they enter the TUN device, before WireGuard sees them, and writes the answer straight back. TCP queries (DNS clients retry over TCP when an answer is too big for UDP) go to a small TCP/IP stack inside `tcd` that owns only the resolver's addresses; it is started on the first TCP query. Two consequences:
- it works the same on every platform;
- only the device itself can query it, because peers' packets arrive on the other side of WireGuard.

Then the OS is pointed at the resolver:
- **systemd-resolved:** `tc0` gets `100.100.100.100` as its DNS server, with the account's domain and then the base domain as search domains, and routing domains for the reverse zones of `100.64.0.0/10` and the IPv6 range. resolved sends only those names there (split DNS). When the search domains change on a running link, `tcd` reconfigures the link from scratch, because only then does resolved rewrite the stub `resolv.conf` that glibc reads.
- **resolv.conf:** the resolver becomes the only nameserver. It forwards other names to the original nameservers, one after another, with a 2-second timeout each. Answers larger than the client accepts come back truncated.

With `-dns-nameservers` on the server, devices send everything to MagicDNS (resolved's `~.` routing domain), and it forwards non-MagicDNS names to those servers.
- **Android:** the VPN interface's DNS server is the resolver, and Android sends it every name. It forwards other names to the DNS servers of the network underneath (Wi-Fi or mobile data), which the app reports to `tcd` whenever that network changes. The resolver looks them up at each query, so a network change takes effect at once. A report without DNS servers (Android sends some while switching networks) keeps the previous ones.

## Exit nodes

A machine whose exit node role is on gets `ExitNode` in its own map entry, and in the map entries other machines of its account see, unless they may not send it everything (a share, or access rules). It then:
- turns on IP forwarding (IPv6 too where possible; interfaces that accept router advertisements are moved to `accept_ra=2` first, so the host keeps its own IPv6 addresses);
- adds an nftables table `tailconnect-exit` per family: masquerade traffic from `tc0` leaving by another interface, and accept it, with replies, in the forward hook.

A machine using an exit node adds `0.0.0.0/0` and `::/0` to that peer's WireGuard allowed IPs, and routes the default through `tc0` without touching the main routing table, as `wg-quick` does:

| Rule | Effect |
|---|---|
| `5270: fwmark 0x7c0000/0xff0000 lookup main` | `tcd`'s own sockets (WireGuard and disco UDP, relay and control connections), marked with `SO_MARK`, use the real network |
| `5271: lookup main suppress_prefixlength 0` | every route of the main table except its default: the LAN and the tunnel's peers |
| `5272: lookup 124` | table 124 holds the default routes into `tc0` |

Inbound packets from the exit node can come from any address. WireGuard still attributes a packet to the peer with the most specific allowed IP, so the exit node can't pose as another peer. Everything is removed when the exit node is turned off or `tcd` stops, and on start (after a crash).

## Resilience

- **Control server down.** Tunnels keep running on the last network map, and `tcd` reconnects with backoff. Devices that change networks meanwhile can still find each other through the relay, as long as the relay is up. The built-in relay is part of the control server, so for that case run a [separate relay](usage.md#relays).
- **Device removed by its owner or an operator.** Its tunnel is torn down, it goes to the logged-out state, and it must join again with an auth key.
- **Account suspended, machine unapproved, or key expired.** The machine is cut off within a second (an expiry takes effect at the moment it passes, though nothing in the database changes then: the server tracks the next expiry and rebuilds maps when it's reached). It keeps its keys and its stream to the server, so approval, reactivation or `tc up --authkey` restores it without anything else.
- **Ephemeral machines** that have been offline for `-ephemeral-timeout` are removed by the server; machines with an open map stream never are.
- **Server moved.** `tc up --server NEW` keeps the registration when the new URL serves the same server key.

## Security model

- **Control channel.** Everything after `GET /key` runs inside Noise IK, and each request is tied to the client's machine key. Over plain HTTP, the server key is trusted on first use. Use HTTPS (a public certificate, or a self-signed one pinned with `--tls-fingerprint`), or pin the key with `--server-key`, to close that gap.
- **Secrets at rest.** Passwords are hashed with argon2id (19 MiB, 2 passes, per-password salt); auth keys, invites, share links and the admin token are stored only as SHA-256 hashes. The database also holds the server's private machine key and relay key, so protect it and its backups.
- **Tenant isolation.** See [Tenants](#tenants). In the portal and API, another account's machines, keys and shares look like they don't exist (404), and operator endpoints refuse tenants.
- **Web portal.**
  - HMAC-signed `SameSite=Strict` session cookies, valid for 12 hours. A password change, suspension or role change ends that account's sessions; replacing the admin token ends token sessions.
  - Password guesses are limited. Sign-in, sign-up and checking the current password when changing it allow 10 attempts per client, then one every 6 seconds. A client is one IPv4 address or one IPv6 /64 network, because one subscriber usually gets a whole /64. On top of that, each account allows 20 wrong passwords from anywhere, then one a minute, so guessing from many addresses gets no further. Failed sign-ins take the same time whether or not the account exists. At most four password hashes are computed at once.
  - Writes are accepted only as JSON, and the request origin is checked. A strict Content Security Policy. Over HTTPS, browsers are told to use only HTTPS (HSTS, for a year).
  - The portal answers only to host names it knows: IP addresses, `localhost`, the machine's hostname, the certificate's names, the `-public-url` host and any listed in `-admin-hosts`. This stops other web pages from reaching it through a visitor's browser by pointing their own name at the server (DNS rebinding), even when it listens on the server only.
  - The UI builds pages from text only, never from HTML, so names and other data that machines report can't inject scripts.
  - It listens on port 7741 on every address by default (or only on the server, if you choose). Without TLS, `tc-control` warns that passwords cross the network unencrypted.
- **Sharing.** One-way, enforced by the receiving machines' packet filter ([details](#sharing-and-the-packet-filter)).
- **Path discovery.** Disco messages are sealed with NaCl box between the peers' disco keys, which are published in the network map. Discovery can't be spoofed to divert traffic.
- **Data.** WireGuard traffic is encrypted end to end between devices. Neither the control server nor the relays can read it.
- **Traffic reports.** For the portal's traffic view, every machine sends the server how many bytes it exchanged with each peer, over its control connection. Only counts: nothing about what the traffic is or where else it goes. The server keeps the latest report in memory, for operators and the machine's own account to see.
- **Relays.** A device must prove it owns its node key before the relay accepts packets for it, so nobody can claim another device's key to intercept its packets. Relays serve only registered machines of active accounts, and only between machines that may talk. The built-in relay knows this directly; a standalone `tc-relay` asks the control server, authenticated with its own revocable token, and caches the answers until the rules change (unless it is run as an open relay with `-allow-any`).
- **HTTPS.** `tc-control` and `tc-relay` serve HTTPS themselves, with certificates from Let's Encrypt (`-acme-domain`, renewed automatically) or your own files. Nothing needs to run in front of them.
- **Self-signed certificates.** With `-tls-self-signed`, `tc-control` makes an ECDSA P-256 key once and a certificate for its hostname and addresses, kept in `tls/` beside the database. Devices pin the SHA-256 of the certificate's public key (SubjectPublicKeyInfo), not the certificate itself, so the server can reissue the certificate for new addresses without breaking them. A device with a pin accepts a server whose certificate is valid as usual or whose key matches the pin, and uses the pin for the control connection, the first `GET /key` and the built-in relay. Without a pin, it refuses and reports the fingerprint it saw. A failed attempt leaves the device connected to its current server.
- **MagicDNS.** It answers only the local device and isn't reachable from peers, so it can't be used as an open resolver.
- **Local API.** `tc` talks to `tcd` over a Unix socket. The caller's UID (`SO_PEERCRED`) decides what it may do: status for anyone; up, down and logout for root.
- **Least privilege.** `tc-control` runs as an unprivileged dynamic user. `tcd` runs as root, limited to `CAP_NET_ADMIN` and `CAP_NET_RAW`, with a read-only system except `/etc/resolv.conf`.

- **Access rules** are enforced by the receiving machine's filter, like sharing, and by the relay; machines that may not talk aren't told about each other at all.
