# Installation

This guide sets up a TailConnect network: one **control server** (`tc-control`) and any number of **devices** running the client daemon (`tcd`) and CLI (`tc`). It covers Linux servers and clients. For Windows PCs, see [Windows](windows.md); for phones and tablets, see [Android](android.md).

**First decide where the server goes:** only on your LAN, on the internet, or at home but reachable from outside. [LAN and internet setups](network-setups.md) has the settings, ports and pitfalls for each.

- [Requirements](#requirements)
- [Get the software](#get-the-software)
- [Install the control server](#install-the-control-server)
- [Enable HTTPS](#enable-https)
- [Open the portal to other people](#open-the-portal-to-other-people)
- [Install clients](#install-clients)
- [Run without the installer](#run-without-the-installer)
- [Upgrade](#upgrade)
- [Move the server](#move-the-server)
- [Back up and restore](#back-up-and-restore)
- [Uninstall](#uninstall)

---

## Requirements

| | Control server | Devices |
|---|---|---|
| OS | Linux (any distribution) | Linux with `/dev/net/tun` (or [userspace mode](#without-root-userspace-mode)) |
| Service manager | systemd for the packaged unit; anything else [works by hand](#run-without-the-installer) | same |
| CPU | amd64 or arm64 tarballs; any architecture Go supports if you build it yourself | same |
| Resources | A few MB of RAM; a small VM or Raspberry Pi is plenty | same |
| Network | Reachable by every device on **TCP 7740** (control API and relay) and **UDP 3478** (STUN) | **UDP 41641** in and out for direct paths (optional: without it, traffic uses the relay) |
| DNS (optional) | | systemd-resolved, or a writable `/etc/resolv.conf`, for MagicDNS names |

To build from source you also need **Go 1.26** (an older Go with the default `GOTOOLCHAIN=auto` downloads it), and optionally `make`. All binaries are static (no cgo) and can be copied to other machines as they are.

## Get the software

**Release tarball.** Each tarball contains the four binaries, the systemd units, the installer, two helper scripts and these docs:

```
tailconnect-v0.5.1-linux-amd64/
├── bin/          tc-control  tcd  tc  tc-relay
├── packaging/linux/
│   ├── install.sh
│   ├── letsencrypt.sh       switch the server to a Let's Encrypt certificate
│   ├── duckdns.sh           keep a DuckDNS name pointing at your home address
│   ├── tc-control.service   tc-control.default
│   └── tcd.service          tcd.default
├── README.md
└── docs/
```

**Build from source:**

```sh
git clone <this repo> && cd TailConnect
make build              # → bin/tc-control, bin/tcd, bin/tc, bin/tc-relay
make dist               # → dist/tailconnect-VERSION-linux-{amd64,arm64}.tar.gz
```

`make` stamps the version from `git describe`. To set it explicitly, use `make dist VERSION=v0.5.1`. Without `make`, run `go build -o bin/ ./cmd/...`, which reports its version as `dev`. To build for another architecture, run `make dist ARCHES="arm"` or `GOARCH=riscv64 go build -o bin/ ./cmd/...`.

The installer works from a source checkout too: it takes binaries from `bin/`.

---

## Install the control server

Pick a machine every device can reach: a small VPS, a home server, or one of the devices itself ([which setup?](network-setups.md#which-setup)). Then, from the tarball or source directory:

```sh
sudo ./packaging/linux/install.sh server
```

On a first install it asks a few questions and does the rest itself. This is a real run, on a LAN:

```
== Server settings
Machines are named NAME.ACCOUNT.DOMAIN, e.g. laptop.alice.home.internal.
Pick the domain now: changing it later renames every machine.
MagicDNS domain [home.internal]:

Where will your devices reach this server?
  1) Only on this LAN: no public name needed (devices away from home can't connect)
  2) From anywhere, over HTTPS: needs a DNS name pointing here, and port 443 reachable
     from the internet (a free certificate comes from Let's Encrypt automatically)
Choose 1 or 2 [1]:
This server's address on the LAN (give it a fixed address on your router) [192.168.10.124]:

The web portal (port 7741) is where you manage accounts, machines and keys. Who may open it?
  1) Anyone who can reach this server; they still need to sign in (plain HTTP: passwords typed into it cross your network unencrypted)
  2) Only this machine: from your computer, through an SSH tunnel
Choose 1 or 2 [1]:
  saved in /etc/default/tc-control
tc-control is running (v0.6.0-dev).
  If this machine or your network has a firewall, open: 7740/tcp 3478/udp 7741/tcp

== Your account
You sign in to the web portal with it, and your devices join it. It's an operator
account: it can also manage the server and other people's accounts.
Account name [richard]: alice
Choose a password (at least 10 characters).
New password for alice:
Repeat it:
  created alice

== Ready
Join your devices with this key. It works for 24 hours, on any number of devices:

  tc-auth-fkbfs4lo••••••••••••••••••••••••

  Linux:    sudo ./packaging/linux/install.sh client     (asks for the server and the key)
  Android:  in the TailConnect app, Server: http://192.168.10.124:7740  and the key above
  Server URL for devices: http://192.168.10.124:7740

Web portal: http://192.168.10.124:7741   (sign in as alice)
```

With choice **2**, it asks for the server's DNS name, the HTTPS port (443, or another with port 80 for Let's Encrypt's checks) and an optional e-mail, and turns on [automatic HTTPS](lets-encrypt.md). The web portal is open to the network by default, on port 7741; choose **2** at that question to keep it on the server only. If `ufw` or `firewalld` is active, it offers to open the ports.

The installer:
- copies `tc-control` to `/usr/local/bin`;
- installs and starts the `tc-control` systemd unit. It runs as an unprivileged dynamic user, with its database in `/var/lib/tc-control/control.db`;
- writes your answers to `/etc/default/tc-control`, which is kept on upgrades;
- creates your account, an **operator**, which can run the server in the web portal. Other people's accounts are ordinary **tenants**, each with its own private network ([accounts and sign-up](usage.md#accounts-and-sign-up)). Nothing needs creating in the portal first: this is the first account;
- creates an auth key for joining devices. It's printed **once** and stored only as a hash.

**Later:**
- `sudo ./packaging/linux/install.sh server --reconfigure` asks the questions again; machines and accounts are kept.
- Running the installer again without it upgrades in place, without questions.
- `--no-setup` skips the questions, for scripts. Then set the options yourself (below), and create the account with `sudo tc-control users create NAME -operator -password` and a key with `sudo tc-control keys create -user NAME -reusable`.

`tc-control` on the server finds the installed database by itself, so these commands need no `-db` flag, and work whether or not the service is running.

### Other options

The installer covers the common settings. For the others, such as who may sign up, edit `/etc/default/tc-control` and restart:

```sh
# /etc/default/tc-control
TC_CONTROL_ARGS="-domain home.internal -public-url http://vpn.example.com:7740"
```

```sh
sudo systemctl restart tc-control
```

The options you're most likely to want:

| Option | Why |
|---|---|
| `-domain home.internal` | MagicDNS names become `laptop.alice.home.internal` (default `tc.internal`). Changing it later renames everything. |
| `-signup MODE` | Who may create accounts in the portal: `off`, `approval` (default), `invite` or `open`. See [accounts and sign-up](usage.md#accounts-and-sign-up). |
| `-public-url URL` | The URL shown in the portal for clients to use |
| `-acme-domain NAME` | Automatic HTTPS from Let's Encrypt; see [Enable HTTPS](#enable-https) |
| `-tls-self-signed` | HTTPS on a LAN with a certificate the server makes itself; devices pin its fingerprint. See [Self-signed certificate](#self-signed-certificate-no-dns-name-or-open-port-needed) |
| `-listen :PORT` | A different control port (default `:7740`) |

All options are listed in the [configuration reference](configuration.md#tc-control-serve).

### Open the firewall

| Port | Protocol | Purpose |
|---|---|---|
| 7740 | TCP | Control API and built-in relay (clients connect here) |
| 3478 | UDP | STUN: clients learn their public address, needed for NAT traversal |
| 7741 | TCP | Web portal (unless you chose to keep it on the server only) |

```sh
sudo ufw allow 7740/tcp && sudo ufw allow 3478/udp                     # Ubuntu/Debian with ufw
sudo firewall-cmd --permanent --add-port={7740/tcp,3478/udp} && sudo firewall-cmd --reload   # Fedora/RHEL
```

On a cloud VM, open the same ports in the provider's security group.

### Check it

```sh
systemctl status tc-control
curl http://localhost:7740/key        # {"Version":2,"MachineKey":"mkey:…"}
journalctl -u tc-control -f           # logs
```

The **web portal** is at `http://SERVER:7741` (`https://` with HTTPS). Sign in with your account. If you kept it on the server only, run `ssh -L 7741:127.0.0.1:7741 server` from your computer and open `http://localhost:7741`. See [the web portal](usage.md#the-web-portal).

---

## Enable HTTPS

Over plain HTTP, the control channel is still encrypted and authenticated with Noise. However, the first time a client connects, it trusts whatever server key it is given ("trust on first use"). HTTPS removes that gap and lets you serve on port 443. HTTPS covers both the control API and the web portal. `tc-control` does HTTPS itself: no web server or proxy in front of it.

### Automatic certificates (Let's Encrypt)

`tc-control` gets a free certificate from Let's Encrypt and renews it by itself. It's for the server only: devices need no certificate and no setup, and trust it like any website's. You need:
- a DNS name pointing at the server, such as `vpn.example.com`;
- TCP port 443 reachable from the internet, so Let's Encrypt can check that the name is yours.

The quickest way is the script, which sets the options, keeps your others, backs up the settings and checks that the certificate arrives:

```sh
sudo ./packaging/linux/letsencrypt.sh vpn.example.com --staging   # Let's Encrypt's test service first
sudo ./packaging/linux/letsencrypt.sh vpn.example.com             # then the real certificate
sudo ./packaging/linux/letsencrypt.sh --restore                   # undo: the previous settings back
```

Or by hand:

```sh
# /etc/default/tc-control
TC_CONTROL_ARGS="-listen :443 -acme-domain vpn.example.com"
```

```sh
sudo systemctl restart tc-control
curl https://vpn.example.com/key       # the first request fetches the certificate (a few seconds)
```

Clients then join with `--server https://vpn.example.com`. Open TCP 443 instead of 7740.

**A home server with a changing address?** A free DuckDNS name works: `sudo ./packaging/linux/duckdns.sh install NAME` keeps it pointing at your home. [HOWTO: DuckDNS and Let's Encrypt](duckdns.md) goes through it step by step, router included.

**[HTTPS with Let's Encrypt](lets-encrypt.md)** is the full guide:
- the DNS and port checklist;
- using a port other than 443;
- trying it first with the test service;
- moving existing devices to HTTPS;
- relays, renewals and rate limits;
- fixes for each error.

### Self-signed certificate (no DNS name or open port needed)

On a LAN, or anywhere Let's Encrypt can't reach the server, `tc-control` can make its own certificate:

```sh
# /etc/default/tc-control
TC_CONTROL_ARGS="-tls-self-signed -public-url https://192.168.1.10:7740"
```

```sh
sudo systemctl restart tc-control
sudo journalctl -u tc-control | grep fingerprint
# ... msg="HTTPS with a self-signed certificate: ..." fingerprint=sha256:Xq3…
```

Only the server has a certificate; devices need none. But no authority vouches for a self-signed certificate, so each device is told which one to trust, by its fingerprint, the way SSH remembers a host key:

```sh
sudo tc up --server https://192.168.1.10:7740 --tls-fingerprint sha256:Xq3… --authkey tc-auth-…
```

- **Where to find the fingerprint:** the server log, and the portal's **Auth keys** tab, whose join command already includes it. An auth key's QR code carries it too, so the Android app trusts the right certificate without typing.
- **If you leave it out**, `tc up` refuses and prints the fingerprint the server presented. Compare it with the log or portal, then run the command again with it. The Android app shows the same fingerprint and asks **Trust this server's certificate?**
- **The fingerprint names the key, not the certificate.** The key is made once and kept in `tls/` next to the database. The certificate covers the server's hostname, `hostname.local`, its IPv4 addresses and the `-public-url` host. When those change, `tc-control` reissues the certificate with the same key, so clients keep working. Add more names with `-tls-names vpn.lan,10.0.0.5`.
- **Check a fingerprint with standard tools:** `openssl s_client -connect SERVER:7740 </dev/null 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | basenc --base64url | tr -d =` prints the part after `sha256:`.
- **Browsers** warn about the portal's certificate. Accept it once; the warning comes back only when the certificate is reissued for new names.
- **IPv6:** the certificate covers the machine's IPv4 addresses and `::1`. Add IPv6 addresses you connect to by number with `-tls-names` (temporary addresses change daily, so they aren't added automatically).
- **Moving existing devices to HTTPS:** `sudo tc up --server https://… --tls-fingerprint sha256:…` on each one keeps its identity (the server key is the same). The built-in relay uses the same pin.
- **Back up `tls/`** with the database. A new key means a new fingerprint for every client.
- **Standalone relays** (`tc-relay`) don't have a self-signed option yet. Run them with Let's Encrypt, your own certificate, or plain HTTP: relayed packets are WireGuard either way.

### Your own certificate

If you already have a certificate (from your own CA, or one renewed by other tooling), give `tc-control` the files. The packaged unit runs as a dynamic user that can't read other users' files, such as those under `/etc/letsencrypt`. So hand the files to the service with systemd **credentials**, using a drop-in:

```sh
sudo systemctl edit tc-control
```

```ini
[Service]
LoadCredential=cert.pem:/etc/letsencrypt/live/vpn.example.com/fullchain.pem
LoadCredential=key.pem:/etc/letsencrypt/live/vpn.example.com/privkey.pem
```

Then point `tc-control` at the copies systemd makes:

```sh
# /etc/default/tc-control
TC_CONTROL_ARGS="-listen :443 -public-url https://vpn.example.com -tls-cert /run/credentials/tc-control.service/cert.pem -tls-key /run/credentials/tc-control.service/key.pem"
```

- **Renewals:** systemd copies the credentials when the service starts, so restart `tc-control` after each renewal. Connected clients reconnect by themselves, and their tunnels keep running during the restart.
- **Private CA certificates:** clients check the certificate against the system trust store. Add your CA there (`/usr/local/share/ca-certificates/` and `update-ca-certificates` on Debian/Ubuntu), then **restart `tcd`**, which reads the store at startup.
- **A self-signed certificate of your own?** Clients can pin it like the built-in one: `--tls-fingerprint`. The fingerprint is in the error `tc up` prints.
- **No certificate at all?** Pin the server key on each client instead: `sudo tc up --server http://… --server-key mkey:…`. The key is in the server log and in `curl http://SERVER:7740/key`.

---

## Open the portal to other people

The portal is reachable on port 7741 by default, so people on the network can already open it. For other people to sign up, add their own devices and share machines:

1. **Use HTTPS** ([how](#enable-https)): they type passwords into the portal. The portal uses the server's certificate.
2. **Choose who may sign up**, in `/etc/default/tc-control`, then restart:
   ```sh
   TC_CONTROL_ARGS="… -signup approval"
   ```
3. **Open TCP 7741** in the firewall (and on the router, for people outside), and send people `https://vpn.example.com:7741`.

With `-signup approval` (the default), new accounts wait in the Accounts tab until an operator approves them; `invite` needs a code you hand out; `off` hides sign-up. There's no e-mail on the server, so forgotten passwords are reset by an operator (Accounts → Reset password, or `tc-control users passwd NAME`).

To keep the portal private instead, run the installer with `--reconfigure` and choose "only this machine", or set `-admin-listen 127.0.0.1:7741`.

---

## Install clients

On every device, from the tarball or source directory:

```sh
sudo ./packaging/linux/install.sh client
```

It asks for the server URL, the auth key (hidden as you type) and a name for the device, and joins:

```
tcd is running (v0.6.0-dev).

== Join a network
The server URL and an auth key come from whoever runs the server
(sudo tc-control keys create -user NAME, or Auth keys in the web portal).
Server URL (e.g. http://192.168.1.10:7740 or https://vpn.example.com): http://192.168.10.124:7740
Auth key (tc-auth-…; input hidden):
Name for this device [laptop]:
Connected as laptop.alice.home.internal (100.64.0.2, fd7c:7c0e:a1e0::6440:2)
```

If joining fails (a mistyped key, say), it shows why and offers to try again. To join a different server later, run it with `--reconfigure`. Without a terminal, or with `--no-setup`, it only installs; then join with `sudo tc up --server URL --authkey KEY`.

The installer copies `tcd` and `tc` to `/usr/local/bin`, then installs and starts the `tcd` unit. That unit runs as root with only `CAP_NET_ADMIN` and `CAP_NET_RAW`, and keeps its keys in `/var/lib/tailconnect`. It also creates `/etc/default/tcd` for options.

`tc up`:
- registers the device in the auth key's account;
- gives it a `100.64.x.y` address and a matching IPv6 address;
- configures the `tc0` interface, routes and DNS.

Options:

- `--hostname NAME` sets the device's name; the default is the OS hostname. An administrator can rename it later.
- You need the auth key only once. After a reboot or `tc down`, the device reconnects with a plain `sudo tc up`, or by itself when `tcd` starts.
- `--server-key mkey:…` pins the server key over plain HTTP (see [Enable HTTPS](#enable-https)).
- `--tls-fingerprint sha256:…` trusts a server's self-signed certificate (see [Self-signed certificate](#self-signed-certificate-no-dns-name-or-open-port-needed)).
- To use the key without putting it in shell history, run `sudo TC_AUTHKEY=tc-auth-… tc up --server …`.

Check it worked:

```sh
tc status          # this device, its peers and how each is reached
ping laptop        # MagicDNS: other devices by name
```

What the output means is explained in [Usage](usage.md#check-the-mesh).

### Client options

Edit `/etc/default/tcd` and run `sudo systemctl restart tcd`:

```sh
# /etc/default/tcd
TCD_ARGS="-dns off"         # e.g. leave the host's DNS alone
```

| Option | Default | |
|---|---|---|
| `-dns` | `auto` | How MagicDNS is wired into the OS: `auto`, `systemd-resolved`, `file`, `off` ([details](usage.md#magicdns)) |
| `-port` | `41641` | WireGuard UDP port. Falls back to a random port if it's in use. |
| `-tun` | `tc0` | Interface name |

### Without root: userspace mode

In containers, on shared machines, or anywhere you can't create a TUN device, run `tcd` as a normal user with an in-process network stack:

```sh
tcd -tun userspace -state ~/.local/share/tailconnect -socket "$XDG_RUNTIME_DIR/tcd.sock" &
tc --socket "$XDG_RUNTIME_DIR/tcd.sock" up --server http://SERVER:7740 --authkey tc-auth-…
```

The device joins the network and answers ping on its address. Other devices can reach it, and it shows up everywhere like any other device. Its own programs, however, can't use the tunnel, because no interface or route is added to the OS. Use this mode for test nodes and services built on the Go library, not for a workstation.

---

## Run without the installer

On systems without systemd, or to try TailConnect out in a terminal, run the binaries directly. They log to stderr.

```sh
# Server (any user; creates ./control.db)
tc-control users create alice -operator -password
tc-control keys create -user alice -reusable
tc-control serve -domain home.internal

# Client (root, for the TUN device and routes)
sudo tcd &                       # state in /var/lib/tailconnect, socket /run/tailconnect/tcd.sock
sudo tc up --server http://SERVER:7740 --authkey tc-auth-…
```

For other init systems, run `tc-control serve -db /var/lib/tc-control/control.db` and `tcd` as long-running services, restart them on failure, and send SIGTERM to stop them. `tcd` restores DNS settings and removes its routes when it stops.

---

## Upgrade

Run the installer again from the new release. It replaces the binaries and units, keeps `/etc/default/*` and `/var/lib/*`, and restarts the service:

```sh
sudo ./packaging/linux/install.sh server      # on the server
sudo ./packaging/linux/install.sh client      # on each device
```

- **Server restarts** don't drop tunnels. Devices keep talking to each other with the network map they have, and reconnect to the control server within seconds.
- **Client restarts** interrupt that device's traffic for a second or two. It keeps its address, name and keys.

**From 0.5 to 0.6** (multi-tenant):

- Upgrade the server first, then the clients. The database is migrated automatically on start; back it up first.
- Existing users become active tenant accounts without passwords. Give yourself an account to sign in to the portal: `sudo tc-control users passwd NAME` and `sudo tc-control users role NAME operator`. The admin token keeps working.
- Machine names gain the account: `laptop.home.internal` becomes `laptop.richard.home.internal`. Short names (`ping laptop`) keep working once clients run 0.6.
- Users' machines no longer see each other's: each user is now a separate network. Share machines between them where needed ([sharing](usage.md#sharing-a-machine)).

## Move the server

To give the server a new address, port or HTTPS while keeping its database, run on each device:

```sh
sudo tc up --server https://new-address
```

The device fetches the server key from the new URL. If it's the same server (same key), the device keeps its registration, address and name, and no auth key is needed. For a server with a self-signed certificate, add `--tls-fingerprint sha256:…`; without it the device refuses, prints the fingerprint, and stays connected to the old address. If the key is different, it's a different server: the device starts with a fresh identity and needs an auth key for that server.

**To new hardware** (say, from a VM to a Raspberry Pi): install the server on the new machine, stop both servers, copy the database across, start the new one, then run `tc up --server` on each device as above:

```sh
# on the new server, after install.sh server
sudo systemctl stop tc-control
sudo cp control.db /var/lib/private/tc-control/control.db      # copied from the old server's /var/lib/tc-control/
sudo cp /etc/default/tc-control.old /etc/default/tc-control    # or set the options again (-domain, -public-url, ...)
sudo systemctl start tc-control
```

Because the database holds the server's key, the devices keep their accounts, addresses and names. (The unit hands files copied in as root to the service's user when it starts.)

## Back up and restore

Everything the server knows is in `/var/lib/tc-control/control.db`: accounts, machines, shares, password and key hashes, and the server's own private keys. **Keep backups private.** A consistent copy:

```sh
sudo systemctl stop tc-control
sudo cp /var/lib/tc-control/control.db /root/tc-control-$(date +%F).db
sudo cp -r /var/lib/tc-control/tls /root/tc-control-tls-$(date +%F)    # with -tls-self-signed
sudo systemctl start tc-control
```

With `-tls-self-signed`, back up the `tls/` folder beside the database too. Its key is what devices pinned: a server without it makes a new key, and every device then needs `tc up --tls-fingerprint` with the new fingerprint.

To restore, stop the service, copy the file back to the same path, and start it; the service takes ownership of the file when it starts. If the database is lost, the replacement server has a new key: on every device run `sudo tc logout` (which forgets the old key), then join again with `sudo tc up --server URL --authkey …`.

On a device, `/var/lib/tailconnect/state.json` holds its keys. If it's lost, the device simply joins again.

## Uninstall

```sh
sudo tc logout                                            # optional: remove the device from the network first
sudo ./packaging/linux/install.sh uninstall-client        # stops tcd, removes binaries and unit
sudo ./packaging/linux/install.sh uninstall-server        # on the server
```

Stopping `tcd` removes the interface and restores DNS. Keys, settings and the server database are kept, so a later install picks up where it left off. Add `--purge` to delete them as well (including `systemctl edit` drop-ins).
