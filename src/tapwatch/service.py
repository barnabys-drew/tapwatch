"""`tapwatch service install`: run tapwatch unattended as systemd *user* services (no root).

For a Linux host (deploy/omarchy/install.sh) and for the Windows path, where everything but Npcap runs
inside WSL (which has systemd). In both, the capture is dumpcap on the mirror NIC streaming into Zeek in
Docker (eval/capture_mirror.sh). deploy/docker-compose.yml is the all-containers alternative.

The units run the same Python and the same tapwatch code as the command that installed them,
from a working directory holding config.yaml, .env and the database. That suits a repo
checkout, and a split layout where the code lives in a separate deploy directory.

Services stop when you log out unless lingering is on:  loginctl enable-linger $USER
"""

from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path

import tapwatch

UNIT_DIR = Path.home() / ".config/systemd/user"
CODE = Path(tapwatch.__file__).resolve().parent.parent          # .../src
REPO = CODE.parent                                                # repo root (eval/, deploy/)


def _unit(description: str, exec_start: str, home: str, restart: str = "on-failure", extra: str = "") -> str:
    return f"""[Unit]
Description={description}
After=network-online.target

[Service]
Type=simple
WorkingDirectory={home}
Environment=PYTHONPATH={CODE}
Environment=PYTHONUNBUFFERED=1
ExecStart={exec_start}
{extra}Restart={restart}
RestartSec=15
TimeoutStopSec=30

[Install]
WantedBy=default.target
"""


def units(home: str, zeek_dir: str, capture_iface: str | None = None, syslog: bool = False,
          python: str = sys.executable) -> dict[str, str]:
    home, zeek_dir = str(Path(home).resolve()), str(Path(zeek_dir).resolve())
    tw = f"{shlex.quote(python)} -m tapwatch.cli -c config.yaml"
    out = {
        "tapwatch-alerter.service": _unit("tapwatch alerter (detectors, triage, alerts)",
                                          f"{tw} run --zeek-dir {shlex.quote(zeek_dir)}", home),
        "tapwatch-ui.service": _unit("tapwatch case desk", f"{tw} ui --zeek-dir {shlex.quote(zeek_dir)}", home),
        "tapwatch-watchdog.service": _unit(
            "tapwatch watchdog (emails when capture or the alerter stops)",
            f"/bin/bash {REPO}/eval/watchdog.sh {shlex.quote(zeek_dir)} 300", home, restart="always",
            extra=f"Environment=TAPWATCH_HOME={home}\nEnvironment=\"TAPWATCH_CMD={python} -m tapwatch.cli\"\n"),
    }
    if capture_iface:  # dumpcap on the mirror NIC (Npcap's on Windows, the distro's on Linux) into Zeek in Docker
        out["tapwatch-capture.service"] = _unit(
            "tapwatch capture (mirror NIC -> Zeek)",
            f"{REPO}/eval/capture_mirror.sh {shlex.quote(zeek_dir)} 87600 {shlex.quote(capture_iface)}", home,
            restart="always",
            extra="ExecStartPre=-/usr/bin/docker rm -f tapwatch-mirror\nExecStopPost=-/usr/bin/docker rm -f tapwatch-mirror\n")
    if syslog:
        out["tapwatch-syslog.service"] = _unit("tapwatch router syslog listener",
                                               f"{tw} syslog --out {shlex.quote(zeek_dir)}", home)
    return out


def install(unit_texts: dict[str, str], run=subprocess.run, unit_dir: Path = UNIT_DIR) -> list[str]:
    unit_dir.mkdir(parents=True, exist_ok=True)
    for name, text in unit_texts.items():
        (unit_dir / name).write_text(text)
    run(["systemctl", "--user", "daemon-reload"], check=True)
    run(["systemctl", "--user", "enable", "--now", *unit_texts], check=True)
    return [str(unit_dir / n) for n in unit_texts]


def uninstall(run=subprocess.run, unit_dir: Path = UNIT_DIR) -> list[str]:
    names = sorted(p.name for p in unit_dir.glob("tapwatch-*.service"))
    if names:
        run(["systemctl", "--user", "disable", "--now", *names], check=False)
        for n in names:
            (unit_dir / n).unlink()
        run(["systemctl", "--user", "daemon-reload"], check=False)
    return names
