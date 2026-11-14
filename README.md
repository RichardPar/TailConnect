# TailConnect

A self-hosted mesh VPN, built on WireGuard, for Linux, Windows and Android.

**Status: milestone 1 (coordination server skeleton).** No client yet.

## Components (so far)

| Path | What |
|---|---|
| `cmd/tc-control` | Coordination server and admin CLI |
| `internal/control` | Client-facing API: `GET /key`, `POST /machine/register`, `POST /machine/map` |
| `internal/admin` | Admin web server: JSON API at `/api/v1` and an embedded UI at `/` |
| `internal/db` | SQLite store (pure Go, no cgo): users, pre-auth keys, nodes, settings |
| `internal/ipam` | Address allocation: 100.64.0.0/10, plus a ULA IPv6 derived from each IPv4 |
| `internal/key` | Machine, node and disco Curve25519 key types |
| `internal/protocol` | Wire types shared by server and clients |

## Quick start

```sh
go build -o bin/tc-control ./cmd/tc-control
export TC_CONTROL_DB=$PWD/control.db

bin/tc-control users create alice
bin/tc-control keys create -user alice -reusable -expiration 24h   # prints tc-auth-…
bin/tc-control admin-token                                          # prints tc-admin-…
bin/tc-control serve            # control on 127.0.0.1:8080, admin UI on 127.0.0.1:8081
```

Open http://127.0.0.1:8081 and sign in with the admin token. Scripts can call
the admin API with `Authorization: Bearer tc-admin-…`.

The admin CLI reads and writes the database directly, so it works whether or not
`serve` is running. Running `admin-token` again replaces the token and signs out
every session.

## Security notes (milestone 1)

- `/machine/*` trusts the keys sent in the request body. Milestone 2 moves these
  endpoints onto a Noise IK channel authenticated by the machine key. Until then,
  keep the control listener on loopback or a trusted network. `serve` warns if you don't.
- Put the admin listener behind TLS (`-tls-cert/-tls-key`) if it is not on loopback.
- Auth keys and the admin token are stored only as SHA-256 hashes.

## Development

```sh
go test ./...
GOOS=windows go build ./... && GOOS=android GOARCH=arm64 go build ./...
```

`go.mod` requires Go 1.26. With `GOTOOLCHAIN=auto` (the default), an older Go
downloads the 1.26 toolchain automatically.

## Roadmap

1. ✅ Coordination server, pre-auth keys, admin CLI and admin web UI
2. Linux client (`tcd`/`tc`), Noise control channel, streaming netmap, static WireGuard mesh
3. magicsock and the relay server (`tc-relay`)
4. NAT traversal (STUN, disco, hole punching)
5. MagicDNS (`<name>.tc.internal`)
6. Windows port (Wintun, service, NRPT)
7. Android port (gomobile, VpnService)
8. Hardening: ACLs, key expiry, node approval, ephemeral cleanup, packaging
