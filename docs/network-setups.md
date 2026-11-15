# LAN and internet setups

Where you put the control server decides who can reach your network and from where. This page covers the three common setups: what to set, which ports to open, and what to watch out for. The commands for installing the server and the devices are in [Installation](installation.md).

- [Which setup?](#which-setup)
- [LAN only](#lan-only)
- [On the internet](#on-the-internet)
- [Home server reachable from outside](#home-server-reachable-from-outside)
- [Moving from one setup to another](#moving-from-one-setup-to-another)
- [Checking a setup](#checking-a-setup)

---

## Which setup?

| | LAN only | On the internet | Home server reachable from outside |
|---|---|---|---|
| Server runs on | A machine on your network (home server, Raspberry Pi) | A machine with a public address (cloud VM, rented server) | A machine on your home network |
| Devices can be | On that network | Anywhere | At home and away |
| You need | Nothing else | A DNS name for the server | A DNS name, and a router you can forward ports on |
| HTTPS | Optional: self-signed (devices pin its fingerprint), or pin the server key | Automatic (Let's Encrypt) | Automatic (Let's Encrypt) |
| Ports open to the internet | None | TCP 443, UDP 3478 | TCP 443, UDP 3478, forwarded to the server |

In every setup:
- **Devices on the same LAN talk to each other directly over the LAN.** Each device tells the server its local addresses, and its peers try those first, so traffic between two machines at home stays at home even when the server is on the internet.
- **Traffic between devices never passes through the server**, except through its relay when they can't reach each other directly. Relayed traffic is still encrypted end to end; the server can't read it.
- **If the server goes down, tunnels keep running** on the last network map. What stops working: joining, changes (new machines, shares, rules), and finding devices that have moved to another network.

---

## LAN only

A server on your home or office network, for devices on that network. It's the simplest setup and needs nothing from outside: no DNS name, no certificate, no open ports on the router.

**Use it when** every device stays on the network, for example a home lab, an office, or machines in one building. It doesn't help a laptop that leaves the network: away from home it can't reach the server or the relay, so it can't find the machines at home. For that, see [Home server reachable from outside](#home-server-reachable-from-outside).

### Server

Give the server a fixed address on the LAN (a DHCP reservation on your router, or a static address), say `192.168.1.10`. Then set:

```sh
# /etc/default/tc-control
TC_CONTROL_ARGS="-domain home.internal -public-url http://192.168.1.10:7740"
```

```sh
sudo systemctl restart tc-control
```

- `-domain home.internal`: machines are `laptop.alice.home.internal`. Names ending in `.internal` are reserved for private networks and never clash with real internet names.
- `-public-url`: what the web portal tells people to use. The server listens on all its addresses, port 7740.

### Firewall

Allow the ports from the LAN only:

```sh
sudo ufw allow from 192.168.1.0/24 to any port 7740 proto tcp     # control API and relay
sudo ufw allow from 192.168.1.0/24 to any port 3478 proto udp     # STUN
sudo ufw allow from 192.168.1.0/24 to any port 7741 proto tcp     # web portal
```

Don't forward anything on the router.

### Devices

Over plain HTTP the control channel is still encrypted (Noise). But the first time a device connects, it trusts whatever server key it's given ("trust on first use"). On a LAN you trust, that's usually fine. To rule out a fake server, there are two ways.

**HTTPS with a self-signed certificate** (recommended: it also encrypts the web portal, so passwords don't cross the LAN in the clear). Add `-tls-self-signed` to the server and switch the public URL to `https://`:

```sh
# /etc/default/tc-control
TC_CONTROL_ARGS="-domain home.internal -tls-self-signed -public-url https://192.168.1.10:7740"
```

After `sudo systemctl restart tc-control`, the log and the portal's Auth keys tab show the certificate's fingerprint. Devices join with it:

```sh
sudo tc up --server https://192.168.1.10:7740 --tls-fingerprint sha256:sfg_RIP4… --authkey tc-auth-…
```

The portal's join command and QR codes already include it. Details in [Self-signed certificate](installation.md#self-signed-certificate-no-dns-name-or-open-port-needed).

**Or pin the server key** and stay on plain HTTP. Read it once on the server:

```sh
curl http://192.168.1.10:7740/key           # {"Version":2,"MachineKey":"mkey:520ff7…"}
```

Then join each device with it:

```sh
sudo tc up --server http://192.168.1.10:7740 --server-key mkey:520ff7… --authkey tc-auth-…
```

### Good to know

- **Use the address, or a name your router's DNS knows.** `--server http://pi.lan:7740` works if every device resolves `pi.lan`. Don't use a name that only some devices know.
- **The web portal** is at `http://192.168.1.10:7741`. On plain HTTP, passwords typed into it cross the LAN unencrypted. If you don't trust everyone on the network, keep the portal on the server only (the installer offers this) and reach it with `ssh -L 7741:127.0.0.1:7741 192.168.1.10`.
- **Wi-Fi client isolation** (common on guest networks) stops devices from reaching each other directly. Traffic then goes through the relay on the server, which still works but is slower. `tc status` shows `relay 1` instead of `direct` for those peers.

---

## On the internet

A server with a public address, for devices anywhere: at home, at work, on mobile data, abroad. A small cloud VM is plenty.

**Use it when** devices move around, or are in different places.

### Server

1. **Give the server a DNS name.** At your DNS provider, add an `A` record (and `AAAA` for IPv6) such as `vpn.example.com` → the server's public address. Check it: `dig +short vpn.example.com`.
2. **Turn on automatic HTTPS:**
   ```sh
   # /etc/default/tc-control
   TC_CONTROL_ARGS="-listen :443 -acme-domain vpn.example.com -acme-email you@example.com -domain home.internal"
   ```
   ```sh
   sudo systemctl restart tc-control
   curl https://vpn.example.com/key            # the first request fetches the certificate (a few seconds)
   ```
   `tc-control` gets a certificate from Let's Encrypt and renews it by itself. [The full guide](lets-encrypt.md) has the checklist, options and fixes.

### Firewall

| Port | Protocol | Why |
|---|---|---|
| 443 | TCP | Control API and relay over HTTPS; Let's Encrypt's checks |
| 3478 | UDP | STUN: devices learn their public address, which they need to connect directly through NAT |

```sh
sudo ufw allow 443/tcp && sudo ufw allow 3478/udp
```

On a cloud VM, also open them in the provider's firewall ("security group"). Keep SSH open for yourself. Open TCP 7741 too, to use the web portal from your browser (over HTTPS, with the same certificate); or keep it closed and reach the portal through an SSH tunnel.

### Devices

```sh
sudo tc up --server https://vpn.example.com --authkey tc-auth-…
```

Devices need no open ports. They connect out to the server, and they find each other through NAT by themselves (hole punching). When that isn't possible, for example with strict firewalls or UDP blocked, traffic goes through the relay on port 443. It keeps working wherever HTTPS does.

### Good to know

- **Direct connections need outgoing UDP.** Most networks allow it. Where it's blocked, devices fall back to the relay. `tc status` shows which path each peer uses.
- **Two devices at home** still talk directly over your LAN, not through the server.
- **The portal** is at `https://vpn.example.com:7741` once TCP 7741 is open. On a server that's reachable from the internet, anyone can see the sign-in page. To keep it private, choose "only this machine" in the installer and use `ssh -L 7741:127.0.0.1:7741 vpn.example.com`.
- **Machines far from the server:** relayed traffic crosses to the server and back. If many of your machines are on another continent, add a [standalone relay](usage.md#relays) near them.
- **Watch it:** add `-metrics-listen 127.0.0.1:7743` and see [Monitoring](usage.md#monitoring).

---

## Home server reachable from outside

The server runs at home, and your router forwards the needed ports to it. Devices at home and away use the same address. Use it when you want everything at home with no rented server, and a laptop or phone that also works away from home.

### What you need

- **A public address at home.** Check it: if the WAN address shown on your router's status page differs from what `curl -4 ifconfig.me` reports, your provider puts you behind carrier-grade NAT, and port forwarding can't work. Ask your provider for a public address, or use the [internet setup](#on-the-internet) with a small VM.
- **A DNS name** for your home address. If your provider changes the address from time to time, use a dynamic DNS service; many routers have a built-in client for it. [HOWTO: DuckDNS and Let's Encrypt](duckdns.md) walks through this whole setup with a free DuckDNS name.
- **A fixed LAN address for the server** (a DHCP reservation), say `192.168.1.10`.

### Router

Forward these to `192.168.1.10`:

| Port | Protocol | Why |
|---|---|---|
| 443 | TCP | Control API and relay over HTTPS; Let's Encrypt's checks |
| 3478 | UDP | STUN |

If port 443 on your router is already used by something else, forward another outside port, such as 8443, to the server. Then forward TCP 80 too, for Let's Encrypt's checks (see below).

### Server

The same as [on the internet](#on-the-internet):

```sh
# /etc/default/tc-control
TC_CONTROL_ARGS="-listen :443 -acme-domain home.example.com -domain home.internal"
```

With another outside port (8443 forwarded to the server's 8443, and 80 to 80):

```sh
TC_CONTROL_ARGS="-listen :8443 -acme-http-listen :80 -acme-domain home.example.com -domain home.internal"
```

Devices then join with `--server https://home.example.com:8443`.

### The one catch: reaching the public name from inside

At home, `home.example.com` resolves to your router's public address. Devices on the LAN then connect to their own router from the inside. Many routers handle that ("NAT loopback" or "hairpin NAT"); some don't, and the connection just times out at home while working fine from outside.

If yours doesn't, make the name resolve to the server's LAN address at home. Add a local DNS entry on your router (often under "DNS", "hostnames" or "static DNS"), or in your local DNS server:

```
home.example.com → 192.168.1.10
```

The certificate is for the name, not the address, so HTTPS keeps working with the LAN address. Devices then reach the server directly at home and through the router when away, with the same `--server` URL.

### Good to know

- **The server's own upload speed limits relayed traffic** away from home. Direct connections don't go through it, and most connections are direct.
- **When the home connection is down**, devices away from home can't reach anything at home. That would be true of any setup.

---

## Moving from one setup to another

You can start on the LAN and move to the internet later without joining every device again. The server keeps its key, accounts, addresses and names:

1. Change the server's settings as above, and restart it.
2. On each device, point it at the new address. No auth key is needed, because it's the same server:
   ```sh
   sudo tc up --server https://vpn.example.com
   ```

To move the server to other hardware (from a Raspberry Pi to a VM, say), copy its database across: see [Move the server](installation.md#move-the-server).

---

## Checking a setup

On a device:

```sh
tc status
```

- **`State: Running`** and your peers listed: the device reaches the server.
- **`direct 192.168.1.20:41641`** on a peer: a direct path (here over the LAN). **`relay 1`**: through the relay. That works, but it's slower and usually means UDP is blocked somewhere.
- **`relay: 1`** in the header: connected to the relay, the fallback for when direct paths fail.

From outside your network (for example, a laptop connected to a phone's mobile hotspot), check the server is reachable:

```sh
curl https://vpn.example.com/key
```

When something doesn't work, see [Troubleshooting](troubleshooting.md).
