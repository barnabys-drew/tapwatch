# Helping someone install tapwatch

For the person helping an owner who is new to all of this. The owner follows
[office-unifi.md](office-unifi.md); this page is what to sort out around it.

## Before you send them the guide

Ask them, and get answers to each:

1. **Who owns the network?** If it isn't them, they need the owner's written OK first, and the people who use
   the network should be told it's monitored for security. tapwatch sees every device's traffic metadata.
2. **Is there a UniFi switch (USW) behind the gateway?** The gateway's own ports can't mirror. If there's only a
   gateway, they need a managed switch first.
3. **A second network port on the PC?** A USB-to-Ethernet adapter is fine. Without one, only that PC is watched.
4. **Which Windows?** Windows 11 gets everything. Windows 10 works, but the router's logs can't reach WSL there.
5. **Does the PC stay on** overnight and at weekends? tapwatch only watches while it's on.
6. **Which UniFi gateway, switch, and UniFi Network version?** Menu names differ between versions.
7. **Where do alerts go?** The ntfy app is simplest. The alerts and the ntfy address are theirs: you don't see
   them unless they also add a channel you share.
8. **AI keys:** have them skip both at install. Don't lend them your own keys: they bill to you and would send
   their network's case descriptions under your account. They can add their own later in `~/tapwatch/.env`.

## Send them

- The guide: [docs/setup/office-unifi.md](office-unifi.md) (link to the `main` branch on GitHub).
- How to download: the [latest release](https://github.com/barnabys-drew/tapwatch/releases/latest), the
  `tapwatch-v….zip` under **Assets**. A release install is what `tapwatch update` moves forward; a ZIP of `main`
  from the green **Code** button installs `main` instead.
- What to send back if it stops: `%LOCALAPPDATA%\tapwatch\install.log` (it holds no passwords or keys) and a
  photo of the screen.

## After the install

- **First check:** have them open Ubuntu and run `cd ~/tapwatch; .venv/bin/tapwatch doctor`, then send you the
  output. Each problem comes with its fix.
- **Right after installing,** "just started" notes for the capture and the router are normal. Run the check again
  after 15 minutes.
- **The first 3 days are quiet by design** (the learning period). Tell them, so they don't think it's broken.
- **Their cases stay on their PC.** To help with one, have them read it from the case desk
  (http://127.0.0.1:8765 on that PC) or send a screenshot. Nothing reaches you automatically.
- **Updates:** have them double-click `update-windows.cmd` in the folder they extracted. It shows what changed,
  asks first, and rolls back to the old version if the new one fails its checks. Their daily digest says when a
  new release is out. A fresh ZIP and running the installer again also works and keeps their settings.
- **On Windows 11 26H2 and later** the installer may end with "Restart this PC once to finish": Windows'
  built-in Sysmon only starts its log at boot. Until they restart, program starts and DNS lookups aren't recorded.
- **Moving to another PC:** `deploy/export-state.sh` on the old one, and the file next to `install-windows.cmd`
  on the new one ([windows.md](windows.md#moving-tapwatch-to-another-pc)).

## What to feed back

Anything they got stuck on goes into the guide or the installer, as a
[GitHub issue](https://github.com/barnabys-drew/tapwatch/issues). Keep their name and details out of the issue.
