# Windows

The Windows client puts a PC on your network like any other device: it gets a `100.64.x.y` address and a name, reaches your machines directly or through the relay, and resolves MagicDNS names in every program. It runs as a Windows service (`tcd`), controlled with the `tc` command.

- [Requirements](#requirements)
- [Get the package](#get-the-package)
- [Install and join](#install-and-join)
- [Using it](#using-it)
- [Upgrade](#upgrade)
- [Uninstall](#uninstall)
- [Service options](#service-options)
- [How it works](#how-it-works)
- [Troubleshooting](#troubleshooting)

---

## Requirements

- Windows 10 version 2004 or later, or Windows 11, 64-bit (Intel/AMD `amd64`, or Arm `arm64`).
- An Administrator account, to install the service and to run `tc up`, `tc down` and `tc logout`.
- A TailConnect server the PC can reach, and an auth key for the account it joins (`sudo tc-control keys create -user NAME`, or **Auth keys → Generate key** in the portal).

Not yet on Windows: using or being an [exit node](usage.md#exit-nodes), and a graphical app.

## Get the package

Build the zip on any machine with Go (no Windows needed):

```bash
make dist-windows                 # dist/tailconnect-VERSION-windows-amd64.zip and -arm64.zip
make dist-windows ARCHES=amd64    # just one
```

The zip contains `tcd.exe`, `tc.exe`, `wintun.dll` (the [Wintun](https://www.wintun.net) network driver by WireGuard LLC, with its license), a `README.txt` and these docs. The first build downloads Wintun from wintun.net once, checks it against a pinned SHA-256 hash, and keeps it in `dist/.cache/`.

The programs are not code-signed, so Windows may warn about them when started from Explorer. Installing from a command prompt, as below, avoids that.

## Install and join

1. Copy the zip to the PC and unzip it (right-click → **Extract All**).
2. Open a **Command Prompt as Administrator**: Start, type `cmd`, right-click **Command Prompt**, **Run as administrator**.
3. Install from the unzipped folder:

   ```bat
   cd %USERPROFILE%\Downloads\tailconnect-v1.0.0-windows-amd64
   tcd install
   ```

   This copies `tcd.exe`, `tc.exe` and `wintun.dll` to `C:\Program Files\TailConnect`, adds that folder to the system PATH, and installs and starts the **TailConnect** service. The service starts with Windows and restarts by itself if it fails.

4. Open a **new** Administrator Command Prompt (so it sees the new PATH) and join:

   ```bat
   tc up --server https://tailconnect.example.com:8443 --authkey tc-auth-...
   ```

   For a server with a self-signed certificate, add `--tls-fingerprint sha256:...` ([details](installation.md#self-signed-certificate-no-dns-name-or-open-port-needed)). If the account requires approval of new machines, approve it in the portal (**Machines**) or with `sudo tc-control nodes approve ID`.

```text
C:\> tc status
State: Running   control: https://tailconnect.duckdns.org:8443   relay: 1
MagicDNS: richard.home.internal (nrpt, only .home.internal names)
100.64.0.8   surfacebook   richard   windows   (this machine)
100.64.0.1   devbox        richard   linux     active; direct 192.168.10.205:41641 (5.4ms)
100.64.0.5   jellyfin      richard   linux     active; direct 192.168.10.112:41641 (12.0ms)
```

## Using it

`tc` works as on Linux ([reference](usage.md#the-tc-client)), from any Command Prompt or PowerShell window:

| Command | Who can run it |
|---|---|
| `tc status`, `tc status --json`, `tc ip PEER`, `tc version` | Any user |
| `tc up ...`, `tc down`, `tc logout` | An Administrator prompt only; others get `permission denied: run tc from an Administrator command prompt` |

- **Names**: `ping laptop`, `ssh user@jellyfin`, `\\nas.richard.home.internal\share`, and so on, in any program. Only MagicDNS names (and reverse lookups of tunnel addresses) go to MagicDNS; every other name uses your normal DNS.
- **Reaching this PC**: other machines on your network can reach services on it (Remote Desktop, file sharing, SSH, a web server) at its tunnel address or name, subject to your account's [access rules](usage.md#access-rules). tcd adds a firewall rule allowing traffic to the tunnel addresses; the program itself may still need to be allowed through Windows Firewall, as for any LAN connection.
- **Network type**: Windows lists the tunnel as a network named *TailConnect*, usually as **Public**. TailConnect's firewall rules apply to every network type, so that doesn't matter for TailConnect; you can still change it under **Settings → Network & internet**.

## Upgrade

Unzip the new version and run `tcd install` from it in an Administrator Command Prompt. It stops the service, replaces the files in Program Files, keeps the service's options, and starts it again. The machine stays logged in.

## Uninstall

In an Administrator Command Prompt:

```bat
tcd uninstall
```

This stops and removes the service, the adapter, the firewall and DNS rules, the PATH entry, and the files in `C:\Program Files\TailConnect` (`tcd.exe` itself, which is running the uninstall, goes at the next restart). The machine's keys and settings stay in `C:\ProgramData\TailConnect`, so a later install rejoins as the same machine. Delete that folder to make the PC forget the network; to remove the machine from the network as well, run `tc logout` before uninstalling, or delete it in the portal.

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
| Local API | `tc` talks to the service over the named pipe `\\.\pipe\tailconnect`. Any signed-in user can connect; changes need a caller running as SYSTEM, as an elevated Administrator, or as the service's own user. `tc` only trusts a pipe created by SYSTEM or Administrators, so another user's program can't pose as the service to collect an auth key. |
| Files | Programs in `C:\Program Files\TailConnect`. Keys, registration and `tcd.log` (rotated at 10 MB to `tcd.log.1`) in `C:\ProgramData\TailConnect`, readable only by SYSTEM and Administrators. |

DNS and firewall rules left behind by a crash are removed when the service starts again.

## Troubleshooting

| Symptom | What to check |
|---|---|
| `tc` is not recognised | Open a new Command Prompt after installing (the PATH change only reaches new windows), or run `"C:\Program Files\TailConnect\tc.exe"`. |
| `cannot reach tcd at \\.\pipe\tailconnect` | The service isn't running: `sc query TailConnect`, then the log. Start it with `sc start TailConnect` or in `services.msc`. |
| `permission denied` on `tc up`/`down`/`logout` | Use a Command Prompt started with **Run as administrator**. |
| `refusing to use \\.\pipe\tailconnect: it was not created by the TailConnect service` | Another program holds the pipe name. Stop it (or restart Windows) and start the service. |
| Service won't start; log says `wintun.dll` missing or `create TUN` failed | Reinstall with `tcd install` from the unzipped folder, which contains `wintun.dll`. |
| Peers show `relay` instead of `direct` | Another firewall or security suite may be blocking UDP to `tcd.exe` (port 41641). Windows Firewall is handled by tcd's rule (`netsh advfirewall firewall show rule name="TailConnect (WireGuard)"`). |
| Names don't resolve, but `tc status` shows peers | `tc status` should say `nrpt`. Check the rules with `Get-DnsClientNrptPolicy` in PowerShell, and `Resolve-DnsName laptop.ACCOUNT.home.internal`. On PCs managed by Group Policy, the domain's NRPT rules replace local ones (the log says so); use `-dns off` and full names via `100.100.100.100`, or have the rule added to the policy. `nslookup` ignores NRPT, so test with `Resolve-DnsName` or `ping` instead. |
| Other machines can't reach a service on this PC | `ping` it first (the tunnel rule allows that). Then allow the program in Windows Firewall, and check the account's access rules. |

Log: `C:\ProgramData\TailConnect\tcd.log`, from an Administrator PowerShell: `Get-Content C:\ProgramData\TailConnect\tcd.log -Tail 50 -Wait`. See also the general [troubleshooting guide](troubleshooting.md).
