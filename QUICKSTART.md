# Quick start

From nothing to two connected devices and the web portal in about ten minutes, by answering a few questions: no settings files to edit. You need a Linux machine for the server (a small VM or a Raspberry Pi is plenty) and at least one device to join: Linux, or an [Android](docs/android.md) phone or tablet.

![Setup in five steps: install the server, create a user and key, install tcd on each device, join, verify](docs/images/setup-flow.svg)

**Decide where the server goes first.** It decides the address devices use and which ports to open:
- **only on your LAN:** devices use `http://192.168.1.10:7740`;
- **on the internet:** devices use `https://vpn.example.com`;
- **at home but reachable from outside.**

[LAN and internet setups](docs/network-setups.md) explains each. The steps below work for all three. `SERVER` means the address you picked.

---

## 1. Get the software

Download the tarball for your server's architecture (`amd64` or `arm64`) from the project's Releases page, or build it with `make dist` ([how](docs/installation.md#get-the-software)). Then unpack it:

```sh
tar xzf tailconnect-v0.6.0-dev-linux-amd64.tar.gz && cd tailconnect-v0.6.0-dev-linux-amd64
```

The same tarball has the server, the client, the installer and these docs.

## 2. Install the server

```sh
sudo ./packaging/linux/install.sh server
```

The installer asks a few questions, writes the settings, starts the server, and creates your account. There's no file to edit:

```
== Server settings
MagicDNS domain [home.internal]:
Where will your devices reach this server?
  1) Only on this LAN: no public name needed (devices away from home can't connect)
  2) From anywhere, over HTTPS: needs a DNS name pointing here, and port 443 reachable …
Choose 1 or 2 [1]:
This server's address on the LAN (give it a fixed address on your router) [192.168.1.10]:

The web portal (port 7741) is where you manage accounts, machines and keys. Who may open it?
  1) Anyone who can reach this server; they still need to sign in (plain HTTP: passwords …)
  2) Only this machine: from your computer, through an SSH tunnel
Choose 1 or 2 [1]:
  saved in /etc/default/tc-control
tc-control is running (v0.6.0-dev).
Open 7740/tcp 3478/udp 7741/tcp in the firewall (ufw)? (y/n) [y]:

== Your account
Account name [alice]:
New password for alice:
Repeat it:

== Ready
Join your devices with this key. It works for 24 hours, on any number of devices:

  tc-auth-…

  Linux:    sudo ./packaging/linux/install.sh client     (asks for the server and the key)
  Android:  in the TailConnect app, Server: http://192.168.1.10:7740  and the key above

Web portal: http://192.168.1.10:7741   (sign in as alice)
```

| Question | What to answer |
|---|---|
| MagicDNS domain | The end of your machines' names: `laptop.alice.home.internal`. Pick it now: changing it later renames every machine. |
| Where devices reach the server | **1** for a server only on your LAN. **2** for one reachable from anywhere: you give its DNS name, and it gets a free HTTPS certificate from Let's Encrypt by itself ([what that needs](docs/lets-encrypt.md#what-you-need)). |
| Address, or DNS name and port | What devices connect to. On a LAN, give the server a fixed address on your router. |
| Web portal | **1** (the default): anyone who can reach the server can open the sign-in page, on port 7741. Over plain HTTP (a LAN server), passwords cross your network unencrypted; with HTTPS, the portal uses the same certificate. **2**: only the server itself; you reach it through an SSH tunnel. |
| Firewall | Asked only if `ufw` or `firewalld` is active. Otherwise, open the ports it lists, and on a router or cloud VM also forward or allow them there. |
| Account and password | Your account, an operator: you sign in to the web portal with it, and your devices join it. You don't create anything in the portal first: this is the first account. |

Changed your mind later? Run `sudo ./packaging/linux/install.sh server --reconfigure` to answer the questions again. Your machines and accounts are kept.

## 3. Join your devices

**Linux**, from the same tarball:

```sh
sudo ./packaging/linux/install.sh client
```

It asks for the server URL (from the end of step 2), the auth key (hidden as you type), and a name for the device, then joins:

```
== Join a network
Server URL (e.g. http://192.168.1.10:7740 or https://vpn.example.com): http://192.168.1.10:7740
Auth key (tc-auth-…; input hidden):
Name for this device [laptop]:
Connected as laptop.alice.home.internal (100.64.0.2, fd7c:7c0e:a1e0::6440:2)
```

**Android:** build and install the app ([how](docs/android.md#build-the-app)). Then, in the web portal, create an auth key and point the device's camera at its QR code: the app opens with the server and key filled in ([how](docs/android.md#join-with-a-qr-code)). Or type them in. Tap Connect.

<img alt="The Android app connected: this device's name and addresses, and four other devices reached directly" src="docs/images/android-phone.png" width="300">

The auth key is needed only to join. Afterwards, devices reconnect by themselves. Need another key later? Use Auth keys in the web portal, or `sudo tc-control keys create -user alice`.

## 4. Check it

On a Linux device:

```sh
tc status            # this device, its peers, and how each is reached
ping laptop          # other devices by name
```

![Terminal: tc status with peers reached directly, then ping by name](docs/images/term-client-verify.png)

`direct` means the devices talk to each other directly; `relay 1` means through the server's relay. Both work; direct is faster. If something's off, see [Troubleshooting](docs/troubleshooting.md).

## 5. Open the web portal

Open **http://SERVER:7741** (or **https://vpn.example.com:7741** with HTTPS) in a browser and sign in as alice. The installer printed the exact address.

If you chose to keep the portal on the server only, tunnel to it from your computer instead: `ssh -L 7741:127.0.0.1:7741 you@SERVER`, then open http://localhost:7741.

![Web portal, Machines tab: six machines in two accounts, jellyfin an exit node, one waiting for approval](docs/images/portal-machines.png)

Here you manage machines, auth keys, access rules, sharing and accounts. [The web portal](docs/portal.md) explains every tab and setting.

---

## Next steps

| To… | See |
|---|---|
| Let other people sign up and run their own networks on your server | [Accounts and sign-up](docs/usage.md#accounts-and-sign-up), [Open the portal to other people](docs/installation.md#open-the-portal-to-other-people) |
| Share one machine (a media server, a printer) with another account | [Sharing a machine](docs/usage.md#sharing-a-machine) |
| Limit which machines can reach which | [Access rules](docs/usage.md#access-rules) |
| Approve new machines before they join | [My account](docs/portal.md#my-account) |
| Move from a LAN server to an internet one without re-joining | [Moving from one setup to another](docs/network-setups.md#moving-from-one-setup-to-another) |
| Monitor the server and devices | [Monitoring](docs/usage.md#monitoring) |
| Change any setting | [Settings at a glance](docs/configuration.md#settings-at-a-glance) |
