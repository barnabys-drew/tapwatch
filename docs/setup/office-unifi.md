# Setting up tapwatch in an office with UniFi

For someone who hasn't done this before. Allow about an hour, most of it waiting for downloads.
You need a Windows 11 PC that stays on, and the UniFi network's admin login.

tapwatch watches a copy of the office's internet traffic and the router's own logs, and sends an alert
to your phone when something looks wrong: a computer calling out to a known bad server, a new device
logging in to the router, a program setting itself up to run at every start. It never blocks
anything, and nothing it sees leaves the PC except the alerts (and, only if you add the optional
keys, short descriptions for the AI).

## Before you start

Tick these off first; each one is explained below.

- [ ] **Permission:** the network's owner has said yes in writing, and the people who use it will be told (step 0).
- [ ] **A UniFi switch** (a USW model) sits between the UniFi router and the rest of the network. The router's own
      ports can't copy traffic; without a switch, buy one first.
- [ ] **A second network port** on the PC: a USB-to-Ethernet adapter (about $15) is fine.
- [ ] **A Windows 11 PC** that stays on all the time, with 8 GB of memory and 20 GB free.
- [ ] **The UniFi admin login**, to set up the copy port and the router's logs.
- [ ] **The ntfy app** on your phone (or a Discord channel for alerts).
- [ ] **About an hour**, with the PC free to restart once.

The installer is new. If it stops, it says why and where its log is: send that file to whoever is helping you.

Helping someone else set it up? Start with [helping-an-install.md](helping-an-install.md).

## 0. Permission first

tapwatch sees every device's traffic on the network: who talks to what, and when (not the contents of
encrypted pages or messages). Only set it up on a network you own or are responsible for, with the
owner's written OK, and tell the people who use it that the network is monitored for security.

## 1. What you need

| | Why | Notes |
|---|---|---|
| A **Windows 11 PC** that's on all the time | it runs tapwatch | 8 GB of memory or more, 20 GB free disk. Windows 10 works, but without the router's logs |
| A **UniFi switch** (a USW model) between the UniFi router and the rest of the network | it copies the traffic to the PC | The UniFi router's own ports can't make a copy. Most UniFi offices already have one |
| A **second network port** on the PC | one port is the PC's normal connection, the other only listens | A USB-to-Ethernet adapter (about $15) is fine. Without it, tapwatch only sees this one PC |
| A **network cable** | from the switch's copy port to the PC's second port | |
| A **phone** with the free **ntfy** app (App Store / Google Play) | where alerts arrive | Or a Discord channel |

## 2. Plug it in

1. Plug the USB-to-Ethernet adapter into the PC.
2. Pick a free port on the UniFi switch. Write down its number: this is the **copy port**.
3. Run a cable from the copy port to the adapter.
4. Find the switch port the **UniFi router** plugs into (in UniFi: **UniFi Devices**, click the switch,
   **Ports**; the router shows as the port's connected device). Write down its number: this is the
   **router port**.

## 3. Make the switch copy the router's traffic

In UniFi Network (in a browser, or the UniFi app):

1. **UniFi Devices** → click the switch → **Ports** → click the **copy port**.
2. Set its **Operation** (on some versions "Port Profile") to **Mirroring**.
3. Set the port to mirror to the **router port**, then **Apply**.

The copy port stops acting as a normal network port; that's expected. Screens differ a little between
UniFi versions; if you can't find Mirroring, search the settings for "mirror".

## 4. Run the installer

1. On the PC, open https://github.com/barnabys-drew/tapwatch, click the green **Code** button, then
   **Download ZIP**.
2. Open your Downloads folder, right-click the ZIP, **Extract All**, **Extract**.
3. In the extracted folder, double-click **install-windows.cmd**. If Windows says "Windows protected your
   PC", click **More info**, then **Run anyway**. Click **Yes** when it asks for admin rights.
4. Answer its questions. Enter takes the suggestion shown in [brackets].
   - **Which network port:** the installer lists this PC's ports and suggests the one that isn't your
     internet connection, which is the adapter from step 2.
   - **Where alerts go:** pick the ntfy phone app unless you already use Discord.
   - **AI keys:** press Enter to skip both. tapwatch works without them, and you can add them later.
5. It restarts the PC once. Sign back in and the installer window comes back by itself and carries on.
6. One installer you click through yourself: **Npcap**. Click **I Agree**, leave the ticked options,
   **Install**, then **Finish**.
7. At the end it checks everything, sends a test alert, and shows the ntfy address to subscribe to.

If it stops with an error, it says what went wrong and where its log file is. Send that file to
whoever is helping you: it has no passwords or keys in it.

## 5. Get alerts on your phone

1. Open the ntfy app and tap **+**.
2. Type the address the installer showed (it starts with `https://ntfy.sh/tapwatch-`), then **Subscribe**.
3. The test alert should arrive within a minute.

Treat that address like a password: anyone who has it can read your alerts.

## 6. Send the router's logs to tapwatch

This shows tapwatch what the router itself sees: attacks it blocked, and every admin login.

1. In UniFi Network: **CyberSecure** → **Traffic Logging** → **Activity Logging (Syslog)** →
   **SIEM Server**. (Older versions: Settings → Control Plane → Integrations → Activity Logging. Search
   the settings for "SIEM" if neither is there.)
2. **Server Address:** this PC's address. The installer showed it at the start ("This PC's address"); in
   Windows it's also in Settings → Network & internet → Ethernet → IPv4 address.
3. **Port:** `5514`.
4. **Contents:** tick Admin Activity, Security Detections, Critical, Devices, Updates, VPN, Triggers and
   Clients. Leave **Firewall Default Policy** off (it floods the log with harmless lines).
5. **Apply.**

## 7. Check it

Open **Ubuntu** from the Start menu and type:

```
cd ~/tapwatch; .venv/bin/tapwatch doctor
```

Every line should say `[ok]`. Anything else says what to do. Right after installing, "just started"
notes are normal; check again after 15 minutes.

## What a normal first week looks like

- **Days 1–3 are a learning period.** tapwatch is learning what's normal for this office, so it holds back
  most alerts and puts them in a daily summary instead. Only the clearest problems interrupt you.
- **After that**, an alert means something new or unusual happened. Each one says which device, what it
  did, and why that can matter. Many turn out to be normal (a new app updating itself). On the PC, the
  **case desk** (open http://127.0.0.1:8765 in a browser) lists every case, and you can mark one
  "expected" so it stops alerting.
- **Some alerts come through even during the learning period:** a port opened to the internet, a new
  login to the router, a strange device handing out network addresses. Look at those the same day.

## If something's wrong later

- **No alerts for days:** run the check in step 7. tapwatch also sends an alert when its own capture
  stops.
- **The PC was off or restarted:** tapwatch starts again by itself, even before anyone signs in.
- **To update tapwatch:** run install-windows.cmd again from a fresh ZIP. It keeps your settings.
