TailConnect for Windows
=======================

Needs Windows 10 version 2004 or later, or Windows 11 (64-bit Intel/AMD or Arm).

Install or upgrade
------------------
1. Unzip this folder anywhere (for example, Downloads).
2. Open a Command Prompt as Administrator: Start, type "cmd",
   right-click Command Prompt, "Run as administrator".
3. Go to the unzipped folder and install:

     cd %USERPROFILE%\Downloads\tailconnect-...-windows-amd64
     tcd install

   This copies the programs to C:\Program Files\TailConnect, adds that
   folder to PATH, starts the TailConnect service (it starts again with
   Windows), and adds the TailConnect app to the Start menu and sign-in.
   Running "tcd install" from a newer version upgrades in place and keeps
   this machine's login.

4. Join your network: click the TailConnect icon by the clock (or start
   TailConnect from the Start menu), choose "Log in...", accept the Windows
   prompt, and enter the server address and auth key.
   Or, in a NEW Administrator Command Prompt (so it sees the new PATH):

     tc up --server https://YOUR-SERVER:8443 --authkey tc-auth-...

   For a server with a self-signed certificate, add
   --tls-fingerprint sha256:... (the server's log shows it).

Use
---
The TailConnect app (icon by the clock) shows the connection and the
network's machines, and connects or disconnects. Or with the command line:

  tc status          peers, paths and MagicDNS
  tc ip PEER         a peer's tunnel address
  tc down / tc up    disconnect / reconnect   (any signed-in user)
  tc logout          leave the network        (Administrator prompt)

Names like "laptop" and "laptop.you.home.internal" work in any program;
other names still use your normal DNS.

Uninstall
---------
In an Administrator Command Prompt:

  tcd uninstall

This removes the service, firewall rules, DNS rules and the files in
Program Files. This machine's keys stay in C:\ProgramData\TailConnect, so a
later install comes back as the same machine; delete that folder to forget it.

Troubleshooting
---------------
  Log:       C:\ProgramData\TailConnect\tcd.log
  Service:   services.msc, "TailConnect"
  More help: docs\windows.md and docs\troubleshooting.md in this folder.

wintun.dll is the Wintun network driver by WireGuard LLC, included under the
license in LICENSE-wintun.txt.
