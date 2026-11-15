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
- [Admin UI](#admin-ui)
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
| `Logged out … Note: this machine was removed from the network` | An admin removed the device. Rejoin with `sudo tc up --authkey …`. |
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

1. **Is it in `tc status`?** If not, it isn't registered or was removed: check `sudo tc-control nodes list` on the server.
2. **Is it online?** The admin UI's Machines tab, or `LAST SEEN` in `nodes list`, shows when it last contacted the server.
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

## Admin UI

- **Can't open it.** It listens on `127.0.0.1:7741` on the server only. Use `ssh -L 7741:127.0.0.1:7741 server` and open `http://localhost:7741`.
- **"no admin token configured".** Run `sudo tc-control admin-token` on the server.
- **Signed out unexpectedly.** Sessions last 12 hours, and creating a new admin token signs everyone out.

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
