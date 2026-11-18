# The Linux desktop app

On a Linux desktop, the **TailConnect app** (`tc-gui`) puts an icon in the panel and opens a status window, like the [Windows app](windows.md#the-tailconnect-app). It controls the same `tcd` service as `tc`, so both can be used side by side.

- [Requirements](#requirements)
- [Install](#install)
- [Using it](#using-it)
- [Who may do what](#who-may-do-what)
- [Uninstall](#uninstall)
- [How it works](#how-it-works)
- [Troubleshooting](#troubleshooting)

---

## Requirements

- A desktop with GTK 3 (Cinnamon, GNOME, KDE Plasma, MATE, XFCE, …). The app loads GTK when it starts; nothing needs installing at build time.
- For the panel icon: a panel that shows app indicators (Cinnamon, KDE, MATE, XFCE and Ubuntu's GNOME do; plain GNOME needs the *AppIndicator and KStatusNotifierItem Support* extension). Without `libayatana-appindicator3`, it uses the older system tray instead.
- polkit (`pkexec`) with a password agent, which every desktop has, for logging in and out.

## Install

The app comes with the client in the Linux tarball. The usual client install sets it up whenever GTK 3 is present:

```sh
sudo ./packaging/linux/install.sh client
```

It also:

- installs `/usr/local/bin/tc-gui`, the **TailConnect** entry in the applications menu, and its icon;
- starts the app at every login (`/etc/xdg/autostart/tailconnect.desktop`), with only the panel icon showing;
- creates the `tailconnect` group and adds the user who ran `sudo` to it;
- installs a polkit action (`org.tailconnect.gui.helper`) for the password prompt.

Open it the first time from the applications menu (**TailConnect**), or with `tc-gui`.

## Using it

**The panel icon** is teal when connected, grey when disconnected or logged out, and amber with a "!" when something needs attention (the service isn't running, the server sent a notice, a connection error). A notification appears when a problem starts.

**Its menu** (click the icon) has:

- the state, and this computer's name and address (click to copy the address);
- **Connect** or **Disconnect**;
- **Copy address of** → each machine on the network;
- **Exit node: None** (or the one in use) → **None** or one of the account's [exit nodes](usage.md#exit-nodes), to send all internet traffic through it. Shown while connected, when the account has an exit node. Users outside the `tailconnect` group are asked for a password;
- **Open TailConnect**, **Log in…** (or **Change server or account…**), **Log out…**, **Quit**.

**The window** shows the state, this computer's name and address, the server and the MagicDNS domain, the Connect/Disconnect, login and logout buttons, an **Exit node** button (when the account has one), and every machine with its address, OS, account and connection (`direct, 5 ms`, `via relay`, `idle`, `shared with you`, …). Double-click a machine to copy its address; right-click to copy its IPv4 or IPv6 address or its name. Closing the window keeps the app running in the panel; **Quit** in the menu ends it.

**Log in…** asks for the server address, an auth key, this computer's name and, only for a server with a self-signed certificate, its fingerprint (`sha256:…`). When already logged in, leave the key empty to change only the name.

Starting `tc-gui` again opens the running app's window instead of a second app. `tc-gui -login` opens its login window.

## Who may do what

| Action | Who |
|---|---|
| See the status | everyone |
| Connect, disconnect | members of the `tailconnect` group; anyone else is asked for an administrator's password |
| Log in, change server or name, log out | an administrator (the app asks for the password) |

To let someone else connect and disconnect: `sudo usermod -aG tailconnect NAME`. It takes effect at once (`tcd` reads `/etc/group` on each request); they don't need to log in again. The same applies to `tc up` (with no options) and `tc down` in a terminal.

## Uninstall

`sudo ./packaging/linux/install.sh uninstall-client` removes the app with the client; `--purge` also removes the `tailconnect` group.

## How it works

- `tc-gui` is a Go program that calls GTK 3 through [purego](https://github.com/ebitengine/purego), so it's built without cgo like the other binaries (amd64 and arm64 from any machine). The panel icon is an AppIndicator (StatusNotifierItem over D-Bus), or a GtkStatusIcon where that library is missing.
- It reads the status from `tcd`'s socket every 2 seconds. Connect and disconnect go to the socket directly; `tcd` checks the caller's user with `SO_PEERCRED` and allows members of `tailconnect`.
- For logging in and out, it runs `pkexec tc-gui -helper` and passes the request (with the auth key) on standard input, never on the command line. The helper, running as root, sends it to `tcd` and prints the result.
- One app per user: a socket in `$XDG_RUNTIME_DIR` passes a later start's request to the running app. The state icons are written to `$XDG_RUNTIME_DIR/tailconnect-icons`.

## Troubleshooting

- **No icon in the panel.** The panel shows no app indicators: on GNOME, install the AppIndicator extension; elsewhere, add the panel's system-tray or status-notifier applet. The window still works (open it from the applications menu).
- **"TailConnect service not running".** Start it with `sudo systemctl start tcd`; `journalctl -u tcd` shows why it stopped.
- **Connect asks for a password.** You aren't in the `tailconnect` group: `sudo usermod -aG tailconnect $USER`.
- **`tc-gui: GTK 3 is needed`.** Install `libgtk-3-0` (Debian, Ubuntu, Mint) or `gtk3` (Fedora, Arch).
- **`cannot open the display`.** It was started outside a desktop session (e.g. over SSH). Use `tc` there.
