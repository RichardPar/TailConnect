# Windows

The Windows client puts a PC on your network like any other device: it gets a `100.64.x.y` address and a name, reaches your machines directly or through the relay, and resolves MagicDNS names in every program. It runs as a Windows service (`tcd`), controlled from the **TailConnect app** in the notification area or with the `tc` command.

- [Requirements](#requirements)
- [Get the package](#get-the-package)
- [Install and join](#install-and-join)
- [The TailConnect app](#the-tailconnect-app)
- [Using it](#using-it)
- [Upgrade](#upgrade)
- [Uninstall](#uninstall)
- [Service options](#service-options)
- [How it works](#how-it-works)
- [Troubleshooting](#troubleshooting)

---

## Requirements

- Windows 10 version 2004 or later, or Windows 11, 64-bit (Intel/AMD `amd64`, or Arm `arm64`).
- An Administrator account, to install, and to log in or out (connecting and disconnecting are open to every signed-in user).
- A TailConnect server the PC can reach, and an auth key for the account it joins (`sudo tc-control keys create -user NAME`, or **Auth keys → Generate key** in the portal).

Not yet on Windows: using or being an [exit node](usage.md#exit-nodes).

## Get the package

Each release has, for `amd64` (most PCs) and `arm64` (Arm PCs such as the Surface Pro X):

- `tailconnect-VERSION-windows-ARCH-setup.exe`: the **one-click installer**.
- `tailconnect-VERSION-windows-ARCH.zip`: the same programs as a zip, for installing from the command line or a script.

Or build them on any machine with Go (no Windows needed):

```bash
make dist-windows                 # zips and installers for amd64 and arm64, in dist/
make dist-windows ARCHES=amd64    # just one
```

Both contain `tcd.exe`, `tc.exe`, `TailConnect.exe` (the app), `wintun.dll` (the [Wintun](https://www.wintun.net) network driver by WireGuard LLC, with its license), a `README.txt` and these docs. The installer is the app with the zip embedded (`go build -tags setup ./cmd/tc-gui`). The first build downloads Wintun from wintun.net once, checks it against a pinned SHA-256 hash, and keeps it in `dist/.cache/`.

The programs are not code-signed. When you open the installer, Windows SmartScreen may say **Windows protected your PC**: choose **More info**, then **Run anyway**.

## Install and join

**With the installer**: double-click `tailconnect-VERSION-windows-amd64-setup.exe` and accept the Windows prompt (**Do you want to allow this app to make changes?**). It installs everything, starts the service and the app, and opens the login window: enter the server address (e.g. `https://tailconnect.example.com:8443`) and an auth key, then **Log in**. If the account requires approval of new machines, approve the PC in the portal (**Machines**) or with `sudo tc-control nodes approve ID`.

Running a newer installer upgrades in place and keeps the PC logged in. TailConnect appears in **Settings → Apps → Installed apps**, from where it can be uninstalled.

**From the zip** (or for scripted installs):

1. Copy the zip to the PC and unzip it (right-click → **Extract All**).
2. Open a **Command Prompt as Administrator**: Start, type `cmd`, right-click **Command Prompt**, **Run as administrator**.
3. Install from the unzipped folder:

   ```bat
   cd %USERPROFILE%\Downloads\tailconnect-v1.0.0-windows-amd64
   tcd install
   ```

   This copies the programs to `C:\Program Files\TailConnect`, adds that folder to the system PATH, installs and starts the **TailConnect** service, and adds the TailConnect app to the Start menu, to every user's sign-in, and to **Settings → Apps**. The service starts with Windows and restarts by itself if it fails.

4. Join: in the TailConnect app (its icon is in the notification area by the clock; if not, start it from the Start menu), choose **Log in…**, confirm the Windows prompt, and enter the server address and auth key. Or, in a **new** Administrator Command Prompt (so it sees the new PATH):

   ```bat
   tc up --server https://tailconnect.example.com:8443 --authkey tc-auth-...
   ```

   For a server with a self-signed certificate, add `--tls-fingerprint sha256:...` ([details](installation.md#self-signed-certificate-no-dns-name-or-open-port-needed)), or fill in **Certificate** in the login window.

```text
C:\> tc status
State: Running   control: https://tailconnect.duckdns.org:8443   relay: 1
MagicDNS: richard.home.internal (nrpt, only .home.internal names)
100.64.0.8   surfacebook   richard   windows   (this machine)
100.64.0.1   devbox        richard   linux     active; direct 192.168.10.205:41641 (5.4ms)
100.64.0.5   jellyfin      richard   linux     active; direct 192.168.10.112:41641 (12.0ms)
```

## The TailConnect app

The app runs for each signed-in user and shows the connection by the clock: a teal icon when connected, grey when disconnected or not logged in, amber when something needs attention (the machine awaits approval, its key expired, the service isn't running), with a notification when that starts.

- **Click** the icon for the TailConnect window: the state, this PC's name and address, the server and MagicDNS domain, **Connect**/**Disconnect**, **Log in…** (or **Change server or account…**), **Log out…**, and the network's machines with their address, OS, account and connection (direct with latency, or via relay). Double-click a machine to copy its address; right-click to copy its IPv4 or IPv6 address or name. Closing the window keeps the app running.
- **Right-click** the icon for a menu: the state, this PC's address (click to copy), Connect or Disconnect, **Copy address of** each machine (ticked when active), the window, logging in and out, and **Exit** (closes the app, not the connection).
- **Connect** and **Disconnect** work for every signed-in user. **Log in…** and **Log out…** change this PC's network, so they ask for an Administrator (the Windows UAC prompt) and then open in an elevated copy of the app. Logging in asks for the server address, an auth key, the PC's name, and the certificate fingerprint for a server with a self-signed certificate; already logged in, leave the key empty to change only the name, or give a key to re-register.

## Using it

`tc` works as on Linux ([reference](usage.md#the-tc-client)), from any Command Prompt or PowerShell window:

| Command | Who can run it |
|---|---|
| `tc status`, `tc status --json`, `tc ip PEER`, `tc version` | Any user |
| `tc up` (reconnect, no options), `tc down` | Any user signed in at the PC (or over Remote Desktop), as in the app |
| `tc up --server/--authkey/--hostname/...`, `tc logout` | An Administrator prompt only; others get `permission denied: this needs an Administrator: run tc from an Administrator command prompt` |

- **Names**: `ping laptop`, `ssh user@jellyfin`, `\\nas.richard.home.internal\share`, and so on, in any program. Only MagicDNS names (and reverse lookups of tunnel addresses) go to MagicDNS; every other name uses your normal DNS.
- **Reaching this PC**: other machines on your network can reach services on it (Remote Desktop, file sharing, SSH, a web server) at its tunnel address or name, subject to your account's [access rules](usage.md#access-rules). tcd adds a firewall rule allowing traffic to the tunnel addresses; the program itself may still need to be allowed through Windows Firewall, as for any LAN connection.
- **Network type**: Windows lists the tunnel as a network named *TailConnect*, usually as **Public**. TailConnect's firewall rules apply to every network type, so that doesn't matter for TailConnect; you can still change it under **Settings → Network & internet**.

## Upgrade

Run the new version's installer, or unzip the new version and run `tcd install` from it in an Administrator Command Prompt. Either way it closes the app, stops the service, replaces the files in Program Files, keeps the service's options, and starts both again. The machine stays logged in.

## Uninstall

In **Settings → Apps → Installed apps**, find **TailConnect**, choose **Uninstall**, and accept the prompts. Or, in an Administrator Command Prompt:

```bat
tcd uninstall
```

Either way, this closes the app and stops and removes the service, the adapter, the firewall and DNS rules, the PATH entry, the Start menu, sign-in and Apps entries, and the files in `C:\Program Files\TailConnect` (`tcd.exe` itself, which is running the uninstall, goes at the next restart). The machine's keys and settings stay in `C:\ProgramData\TailConnect`, so a later install rejoins as the same machine. Delete that folder to make the PC forget the network; to remove the machine from the network as well, run `tc logout` before uninstalling, or delete it in the portal.

## Service options

`tcd install` passes any flags after it to the service:

```bat
tcd install -port 41642 -dns off
```

Running `tcd install` again without flags keeps the current ones; with flags, it replaces them. The flags that matter on Windows:

| Flag | Default | What it does |
|---|---|---|
| `-port N` | `41641` | WireGuard UDP port (`0` = random). Forward this port on your router for direct connections from the internet. |
| `-dns MODE` | `auto` | `auto` (or `nrpt`) points Windows at MagicDNS for MagicDNS names; `off` leaves Windows' DNS alone (names then only resolve when asking `100.100.100.100` directly). |
| `-tun NAME` | `TailConnect` | The network adapter's name, or `userspace` for in-process networking without an adapter (other machines can only ping this one). |
| `-state DIR` | `C:\ProgramData\TailConnect` | Keys, registration and the log. |
| `-metrics-listen ADDR` | off | Prometheus metrics, e.g. `127.0.0.1:7744`. |
| `-verbose` | off | WireGuard debug logging. |

`tcd -h` lists them all.

## How it works

| Part | On Windows |
|---|---|
| Network adapter | A [Wintun](https://www.wintun.net) adapter named *TailConnect*, created when the tunnel comes up (`tc up`) and removed when it goes down. It always has the same identity, so Windows keeps one network entry for it. |
| Addresses and routes | Set through the IP Helper API: the node's `/32` and `/128` addresses, a route per peer, MTU 1280, interface metric 5. tcd only removes routes it added. |
| DNS | [Name Resolution Policy Table](https://learn.microsoft.com/windows-server/networking/dns/deploy/nrpt/nrpt-top) rules in the registry send the account's domains and the tunnel's reverse zones to `100.100.100.100`; the adapter gets the account's domain as its DNS suffix and search list, so short names work. If the server sets upstream DNS servers, one rule for `.` sends all names to MagicDNS. |
| Firewall | Two rules, both for all network types: *TailConnect (WireGuard)* allows inbound UDP to `tcd.exe` (direct connections); *TailConnect (tunnel)* allows inbound traffic to the node's tunnel addresses. Windows' strong host model drops packets for those addresses that arrive on other adapters, and tcd's packet filter applies the account's access rules. |
| Local API | `tc` and the app talk to the service over the named pipe `\\.\pipe\tailconnect`, which other computers can't open. Any user can read the status; a process of a user signed in at the PC (interactive logon) can also connect and disconnect; logging in, changing settings and logging out need a caller running as SYSTEM, as an elevated Administrator, or as the service's own user. `tc` and the app only trust a pipe created by SYSTEM or Administrators, so another user's program can't pose as the service to collect an auth key. |
| App | `TailConnect.exe`, started at sign-in (`HKLM\...\Run`), one per user. Win32 directly, no other runtime; `TailConnect.exe -login` and `-logout` are what it runs elevated. |
| Files | Programs in `C:\Program Files\TailConnect`. Keys, registration and `tcd.log` (rotated at 10 MB to `tcd.log.1`) in `C:\ProgramData\TailConnect`, readable only by SYSTEM and Administrators. |

DNS and firewall rules left behind by a crash are removed when the service starts again.

## Troubleshooting

| Symptom | What to check |
|---|---|
| `tc` is not recognised | Open a new Command Prompt after installing (the PATH change only reaches new windows), or run `"C:\Program Files\TailConnect\tc.exe"`. |
| The app's icon is amber with "service not running", or `cannot reach tcd at \\.\pipe\tailconnect` | The service isn't running: `sc query TailConnect`, then the log. Start it with `sc start TailConnect` or in `services.msc`. |
| `permission denied` on `tc up --authkey ...` or `tc logout` | Use a Command Prompt started with **Run as administrator**. In the app, accept the Windows prompt. |
| No TailConnect icon by the clock | Start **TailConnect** from the Start menu. Windows may hide it under the **^** arrow; drag it out to keep it visible. |
| `refusing to use \\.\pipe\tailconnect: it was not created by the TailConnect service` | Another program holds the pipe name. Stop it (or restart Windows) and start the service. |
| Service won't start; log says `wintun.dll` missing or `create TUN` failed | Reinstall with `tcd install` from the unzipped folder, which contains `wintun.dll`. |
| Peers show `relay` instead of `direct` | Another firewall or security suite may be blocking UDP to `tcd.exe` (port 41641). Windows Firewall is handled by tcd's rule (`netsh advfirewall firewall show rule name="TailConnect (WireGuard)"`). |
| Names don't resolve, but `tc status` shows peers | `tc status` should say `nrpt`. Check the rules with `Get-DnsClientNrptPolicy` in PowerShell, and `Resolve-DnsName laptop.ACCOUNT.home.internal`. On PCs managed by Group Policy, the domain's NRPT rules replace local ones (the log says so); use `-dns off` and full names via `100.100.100.100`, or have the rule added to the policy. `nslookup` ignores NRPT, so test with `Resolve-DnsName` or `ping` instead. |
| Other machines can't reach a service on this PC | `ping` it first (the tunnel rule allows that). Then allow the program in Windows Firewall, and check the account's access rules. |

Log: `C:\ProgramData\TailConnect\tcd.log`, from an Administrator PowerShell: `Get-Content C:\ProgramData\TailConnect\tcd.log -Tail 50 -Wait`. See also the general [troubleshooting guide](troubleshooting.md).
