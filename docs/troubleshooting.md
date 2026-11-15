# Troubleshooting

Start with these three commands. They answer most questions:

```sh
tc status                          # on the device: state, peers, paths, DNS
journalctl -u tcd -e               # device log
journalctl -u tc-control -e        # server log (on the server)
```

- [Error messages](#error-messages)
- [tcd won't start](#tcd-wont-start)
- [Stuck in "Starting"](#stuck-in-starting)
- [A peer is missing or unreachable](#a-peer-is-missing-or-unreachable)
- [Peers stay on relay](#peers-stay-on-relay)
- [Names don't resolve](#names-dont-resolve)
- [Sharing](#sharing)
- [Web portal and accounts](#web-portal-and-accounts)
- [Debug logging](#debug-logging)
- [Start over](#start-over)

---

## Error messages

| Message | Cause and fix |
|---|---|
| `cannot reach tcd at /run/tailconnect/tcd.sock (is it running?)` | `tcd` isn't running: `sudo systemctl start tcd`, and check `journalctl -u tcd`. For a userspace `tcd`, pass its socket: `tc --socket PATH`. |
| `permission denied: run as root (e.g. sudo tc ...)` | `up`, `down` and `logout` need root |
| `no control server configured: pass --server URL` | First `tc up` on this device: add `--server http://SERVER:7740` |
| `this machine is not registered: pass --authkey …` | The device hasn't joined yet, was removed, or is switching to a different server. Create an auth key (`sudo tc-control keys create -user NAME`) and pass `--authkey`. |
| `registration refused: control: 401 invalid, expired or already-used auth key` | The key is mistyped, expired, revoked, or single-use and already used. `sudo tc-control keys list` shows each key's status. Create a new one. |
| `fetch server key: … connection refused` | Nothing listens at that address and port. Check the URL (default port **7740**), that `tc-control` is running, and the server's firewall. |
| `fetch server key: … i/o timeout` | A firewall is dropping the connection, or the address is wrong |
| `tls: failed to verify certificate: x509: certificate signed by unknown authority` | The server's certificate isn't trusted. Use a public CA, or add your CA to the system trust store and restart `tcd` ([details](installation.md#enable-https)). |
| `register: control: 403 account is not active (pending approval or suspended)` | The auth key's account is waiting for approval or suspended. An operator approves or reactivates it (Accounts tab, or `tc-control users activate NAME`). |
| `Notice: this machine's account is suspended or awaiting approval` (status) | Same cause, for a machine that already joined: it has no peers until the account is active again, then recovers by itself. |
| `Notice: this machine is waiting for approval …` (status) | The account requires approval for new machines. The owner or an operator approves it (Machines → Approve, or `tc-control nodes approve ID`); it then connects by itself. |
| `Notice: this machine's key has expired …` (status) | Its authorisation ran out (`-key-expiry`, 180 days by default). Run `sudo tc up --authkey KEY` on it with a key of its account. To stop a server expiring, set it to never expire (Machines → Never expire, or `tc-control nodes expiry ID never`). |
| `tc-control: -acme-domain: the certificate authority can't verify the domain …` | Let's Encrypt only connects to ports 443 and 80. Use `-listen :443`, or add `-acme-http-listen :80` ([details](installation.md#enable-https)). |
| `acme/autocert: …` or `tls: … internal error` on the first HTTPS request | Getting the certificate failed. Check that the DNS name points at this server and that TCP 443 (or 80 with `-acme-http-listen`) is open from the internet. `journalctl -u tc-control` has Let's Encrypt's reason. Too many attempts hit its rate limits: test with `-acme-staging`. More in [HTTPS with Let's Encrypt](lets-encrypt.md#troubleshooting). |
| `tc-relay: cannot use the control server … control server rejected the relay token` | The token is mistyped or was deleted. Create a new one with `sudo tc-control relays create NAME` (`relays list` shows the existing ones). |
| `relay … not authorized: control server unavailable` (client log) | The standalone relay can't reach the control server (check `-control-url`, and the relay's log), or its token was revoked. Machines fall back to other relays and direct paths meanwhile. |
| An ephemeral machine disappeared | Ephemeral machines are removed after 30 minutes offline (`-ephemeral-timeout`). Join long-lived machines with a normal key. |
| `Logged out … Note: this machine was removed from the network` | The machine was removed (by its owner or an operator). Rejoin with `sudo tc up --authkey …`. |
| `Warning: control unreachable: …` (status, while running) | The device lost contact with the server and is retrying. Tunnels keep working on the last map. Fix the server or the network; the device reconnects by itself. |
| `create TUN tc0 (are you root?)` (tcd log) | See [tcd won't start](#tcd-wont-start) |

## tcd won't start

```sh
systemctl status tcd
journalctl -u tcd -n 50
```

- **`create TUN … operation not permitted` or `no such file or directory`.** The kernel has no TUN support, or you're in a container without `/dev/net/tun`. On a VM, `sudo modprobe tun`. For a container, pass the device through (`--device /dev/net/tun --cap-add NET_ADMIN` with Docker), or use [userspace mode](installation.md#without-root-userspace-mode).
- **`address already in use` on the port.** That's not fatal: `tcd` falls back to a random port and logs it. Set a fixed one with `-port` in `/etc/default/tcd` if a firewall needs it.
- **It started with a different interface name.** `-tun` in `/etc/default/tcd`.

## Stuck in "Starting"

`tc status` shows `State: Starting` with a `Warning:` line underneath. Typical causes:

- The server is down or unreachable. Test from the device with `curl http://SERVER:7740/key`.
- The server URL changed. Run `sudo tc up --server NEW-URL`; if it's the same server, the device keeps its registration ([details](installation.md#move-the-server)).
- The server's database was replaced, so its key no longer matches the one the device pinned. Run `sudo tc logout`, which forgets the old key, then rejoin with `sudo tc up --authkey …`.

## A peer is missing or unreachable

1. **Is it in `tc status`?** If not, check `sudo tc-control nodes list` on the server:
   - it isn't registered, or was removed;
   - it belongs to **another account**: accounts are separate networks. Join it to your account, or have its owner [share it](usage.md#sharing-a-machine) with you;
   - its account is pending or suspended (`tc-control users list`).
2. **Is it online?** The portal's Machines tab, or `LAST SEEN` in `nodes list`, shows when it last contacted the server.
3. **Ping by address first:** `ping 100.64.x.y`.
   - If that works but the name doesn't, see [Names don't resolve](#names-dont-resolve).
   - If neither works, check `tcd` on the other device.
4. **Local firewall.** Packets arrive on `tc0`. A host firewall with a default-drop input policy (ufw, firewalld) drops them unless you allow that interface. For example: `sudo ufw allow in on tc0`, or `sudo firewall-cmd --zone=trusted --add-interface=tc0 --permanent`.
5. **Routes.** `ip route show dev tc0` should list the peer's address. Another VPN or a policy route sending `100.64.0.0/10` elsewhere breaks this.

## Peers stay on relay

`tc status` shows `relay N` for a peer that's actively talking: no direct path was found. Traffic still works, just with more latency. Check these:

- **UDP 41641** must be allowed out on both devices, and in on at least one if it has a host firewall. The device's port is in the `tcd` log (`WireGuard on UDP port …`).
- **STUN must work**, so each device knows its public address. In `tc status --json`, `Self.Endpoints` should include a public address. If not:
  - check that UDP 3478 is open on the server;
  - check that `tc-control` isn't started with `-stun-listen ""`.
- **Hard NATs.** Mobile networks and some corporate networks use NATs that can't be punched ([why](how-it-works.md#nat-traversal)). If both peers are behind one, they stay on the relay. One peer with a public address or a port forward (UDP 41641 to that device) is enough to get a direct path.
- To see path discovery in detail, set `TC_DISCO_DEBUG=1` on both devices ([below](#debug-logging)).

## Names don't resolve

```sh
tc status | head -2                              # look at the MagicDNS: line
dig @100.100.100.100 peer.your-domain            # ask the resolver directly
```

- **`dig @100.100.100.100` works, but plain lookups don't.** The OS isn't using the resolver. The `MagicDNS:` line says how `tcd` configured the OS, and shows any error.
  - **systemd-resolved:** `resolvectl status tc0` should show `DNS Servers: 100.100.100.100` and your domain. If systemd-resolved was restarted, `sudo systemctl restart tcd` reapplies the settings.
  - **file:** `/etc/resolv.conf` should start with `nameserver 100.100.100.100`. If NetworkManager or dhclient rewrote it, restart `tcd`. Better still, use systemd-resolved, which supports split DNS.
  - **off:** the OS isn't configured: userspace mode, a network namespace, or `-dns off`.
- **`dig` fails too.**
  - Check the `MagicDNS:` line exists. If it's missing, MagicDNS is off on the server (`-magic-dns=false`).
  - Check `ip route get 100.100.100.100` goes via `tc0`.
- **Short names don't work but full names do.** The search domain is missing. With systemd-resolved, check `resolvectl domain tc0`. Some tools, such as `nslookup` and `dig`, ignore search domains; use `getent hosts NAME` to test what programs actually see.
- **A renamed device still resolves to its old name.** Answers are cached for up to 5 minutes. Run `resolvectl flush-caches`.
- **`laptop.home.internal` stopped working after upgrading to 0.6.** Names now include the account: `laptop.richard.home.internal`. Short names (`laptop`) still work.
- **Another account's machine doesn't resolve.** By design, unless it's shared with you: then it's `machine.owner` (for example `nas.alice`).

## Access rules

- **A machine can't reach another of the same account.** If the account has any rules, only what they allow works. Check `tc-control rules list -user NAME` (or the Access rules tab) and the machines' tags (`nodes list --json`, or the Machines tab). `tc status` on the receiving machine shows what each peer may open there.
- **A machine disappeared from `tc status` after adding a rule.** Machines that no rule lets talk in either direction aren't peers at all. Add a rule, or delete the last rule to allow everything again.
- **The connection works one way only.** Rules are one-way: `tag:a → tag:b` lets a open connections to b. Add the reverse rule if b must open connections to a too.

## Sharing

- **I accepted a share but can't reach the machine.**
  - `tc status` on your machine should list it as `shared with you`. If it doesn't, check the share's status in the portal (Sharing tab) or with `tc-control shares list`: it may still be pending, revoked, or the owner's account may be suspended.
  - If it's listed but unreachable, go through [A peer is missing or unreachable](#a-peer-is-missing-or-unreachable); the owner's host firewall must allow incoming traffic on `tc0`.
- **The shared machine can't reach my machines.** That's the design: sharing is one-way, and your machines' packet filter drops connections it opens (`FilterDropped` in `tc status --json` counts them). For a connection the other way, share one of your machines with its account too.
- **A share link says "invalid, expired or already-used".** Links work once and expire (7 days by default). Ask the owner for a new one. You can't redeem a link to your own machine.

## Web portal and accounts

- **Can't open it.** It listens on `127.0.0.1:7741` on the server only, unless you [opened it](installation.md#open-the-portal-to-other-people). Use `ssh -L 7741:127.0.0.1:7741 server` and open `http://localhost:7741`.
- **Nobody can sign in.** Create an operator account on the server: `sudo tc-control users create NAME -operator -password` (or give an existing account a password with `users passwd NAME` and `users role NAME operator`). The server logs a warning at start while no operator can sign in. The admin token (`sudo tc-control admin-token`) also signs in as operator.
- **"wrong name or password".** Names are lowercase. An account created without a password (`users create NAME` alone) can't sign in until it gets one. An operator can reset any password.
- **"your account is waiting for the operator's approval" / "this account is suspended".** An operator approves or reactivates it in the Accounts tab, or with `tc-control users approve NAME`.
- **"too many attempts".** 10 sign-in or sign-up attempts per IP address, then one every 6 seconds. Wait a minute.
- **No "Create an account" link.** Sign-up is off on this server (`-signup off`). Ask the operator for an account or an invite.
- **Signed out unexpectedly.** Sessions last 12 hours. Changing your password signs out your other sessions; an operator suspending your account or changing its role signs out all of them.

## Debug logging

| What | How |
|---|---|
| Path discovery (pings, pongs, CallMeMaybe) | `TC_DISCO_DEBUG=1`. Under systemd, run `sudo systemctl edit tcd` and add `[Service]` and `Environment=TC_DISCO_DEBUG=1`, then restart. |
| WireGuard internals | `-verbose` in `/etc/default/tcd` |
| Server logs as JSON | `-log-json` in `/etc/default/tc-control` |
| What the device knows | `tc status --json`: endpoints, current paths, latencies, DNS state |

## Start over

On a device, forget everything and rejoin:

```sh
sudo tc logout                         # removes the device on the server, too
sudo tc up --server URL --authkey …
```

If the server is gone, or has a new database, `tc logout` can't reach it. Remove the old entry on the server, if there is one (`tc-control nodes delete ID`), and rejoin with `--authkey`.
