"""`tapwatch update`: move an install to the newest release (or main), and back again if anything fails.

Every install method clones the repo (the Windows installer inside Ubuntu, Omarchy, the plain Linux steps), so an
update is git: fetch, check the new version out, install its dependencies into the venv, run the self-check,
restart the services the change needs, and run doctor. If any step fails, the previous version is checked out
again, reinstalled and restarted, and the update says what failed.

Two lines (config `update.channel`): `releases` (default) follows the newest `vX.Y.Z` tag, `main` follows the main
branch (a dev install). Nothing updates by itself: the daily digest only says a newer release exists (`notice`),
because an install that updated on its own would turn one bad push into every install's problem.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from . import doctor

ROOT = Path(__file__).resolve().parents[2]   # src/tapwatch/update.py -> the checkout
TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
CHECK_EVERY = 86400   # the digest asks the remote at most once a day
SETTLE = 20           # seconds for restarted services to come up before doctor looks


class UpdateError(RuntimeError):
    pass


def _run(cmd: list[str], cwd: Path = ROOT, timeout: float = 600) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=False, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def git(*args: str, run=_run) -> str:
    p = run(["git", *args])
    if p.returncode != 0:
        raise UpdateError(f"git {' '.join(args)}: {(p.stderr or p.stdout).strip()[:300]}")
    return p.stdout.strip()


def channel(cfg: dict) -> str:
    c = str((cfg.get("update") or {}).get("channel") or "releases")
    if c not in ("releases", "main"):
        raise UpdateError(f"update.channel is {c!r}: releases or main")
    return c


def newest(tags) -> str | None:
    """The highest vX.Y.Z among `tags`, by number (v0.10.0 > v0.9.0)."""
    ok = [t for t in tags if TAG.match(t)]
    return max(ok, key=lambda t: tuple(int(x) for x in TAG.match(t).groups())) if ok else None


def current(run=_run) -> str:
    """The release this checkout is on, or branch@commit."""
    p = run(["git", "describe", "--tags", "--exact-match", "HEAD"])
    if p.returncode == 0 and TAG.match(p.stdout.strip()):
        return p.stdout.strip()
    branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip() or "HEAD"
    return f"{branch}@{git('rev-parse', '--short', 'HEAD', run=run)}"


@dataclass
class Plan:
    channel: str
    current: str
    target: str            # a tag, or origin/main
    target_commit: str
    head_commit: str
    changes: list[str]     # one line per commit, newest first
    ahead: bool = False    # this checkout already contains the target (a main install past the newest release)

    @property
    def needed(self) -> bool:
        return self.target_commit != self.head_commit and not self.ahead


def plan(cfg: dict, run=_run) -> Plan:
    ch = channel(cfg)
    git("fetch", "--quiet", "--tags", "origin", run=run)
    if ch == "main":
        target = "origin/main"
    else:
        target = newest(git("tag", "-l", "v*", run=run).split())
        if not target:
            raise UpdateError("no release tags yet (vX.Y.Z); set update.channel: main to follow main")
    head, tc = git("rev-parse", "HEAD", run=run), git("rev-parse", f"{target}^{{commit}}", run=run)
    changes = git("log", "--no-merges", "--format=%s", f"{head}..{tc}", run=run).splitlines() if head != tc else []
    # already past it (main installed after the newest release was cut): "updating" would be a downgrade
    ahead = head != tc and run(["git", "merge-base", "--is-ancestor", tc, head]).returncode == 0
    return Plan(ch, current(run), target, tc, head, changes, ahead)


def _dirty(run=_run) -> list[str]:
    """Tracked files changed in the checkout: an update would overwrite someone's edits, so it stops."""
    return [line for line in git("status", "--porcelain", "--untracked-files=no", run=run).splitlines() if line]


def _install(run=_run) -> None:
    p = run([sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "-e", str(ROOT)])
    if p.returncode != 0:
        raise UpdateError(f"installing dependencies failed: {(p.stderr or p.stdout).strip()[-400:]}")


def _checkout(ref: str, ch: str, run=_run) -> None:
    if ch == "main" and ref == "origin/main":
        git("checkout", "--quiet", "main", run=run)
        git("merge", "--quiet", "--ff-only", "origin/main", run=run)
    else:
        git("checkout", "--quiet", "--detach", ref, run=run)


def _units_to_restart(prev: str, new: str, units: list[str], run=_run) -> list[str]:
    """Every installed Python service; capture only when its own files (deploy/) changed."""
    changed = git("diff", "--name-only", prev, new, run=run).splitlines() if prev != new else []
    capture = any(f.startswith("deploy/") for f in changed)
    return [u for u in units if u != "tapwatch-capture" or capture]


def _restart(units: list[str], run=_run) -> None:
    if not units:
        return
    p = run(["systemctl", "--user", "restart", *[f"{u}.service" for u in units]], timeout=120)
    if p.returncode != 0:
        raise UpdateError(f"restarting {', '.join(units)} failed: {(p.stderr or p.stdout).strip()[:300]}")


def _selfcheck(cfg_path: str, run=_run) -> None:
    p = run([sys.executable, "-m", "tapwatch.cli", "-c", cfg_path, "selfcheck"], timeout=900)
    if p.returncode != 0:
        raise UpdateError("the new version's self-check failed:\n" + "\n".join(p.stdout.splitlines()[-8:]))


def _doctor(cfg_path: str, run=_run) -> None:
    p = run([sys.executable, "-m", "tapwatch.cli", "-c", cfg_path, "doctor"], timeout=300)
    if p.returncode != 0:
        fails = [line for line in p.stdout.splitlines() if line.startswith("[FAIL]")]
        raise UpdateError("doctor found a problem after the update:\n" + "\n".join(fails[:8] or p.stdout.splitlines()[-8:]))


def apply(cfg: dict, cfg_path: str, p: Plan, units: list[str] | None = None, run=_run, sleep=time.sleep,
          say=print) -> bool:
    """Carry out `p`. True when updated; on failure, roll back to where it was and raise UpdateError."""
    if not p.needed:
        say(f"tapwatch {p.current} is " + (f"ahead of {p.target}" if p.ahead else "up to date") + f" ({p.channel})")
        return False
    dirty = _dirty(run)
    if dirty:
        raise UpdateError("the checkout has local changes, which an update would overwrite:\n  " + "\n  ".join(dirty[:8]))
    units = doctor.installed_units() if units is None else units
    restart = _units_to_restart(p.head_commit, p.target_commit, units, run)
    on_main = git("rev-parse", "--abbrev-ref", "HEAD", run=run) == "main"   # a rollback puts the branch back too
    say(f"updating {p.current} -> {p.target} ({len(p.changes)} change(s))")
    try:
        _checkout(p.target, p.channel, run)
        _install(run)
        _selfcheck(cfg_path, run)
        _restart(restart, run)
        if restart:
            sleep(SETTLE)
            _doctor(cfg_path, run)
    except (UpdateError, subprocess.TimeoutExpired) as e:
        say(f"update failed: {e}\nrolling back to {p.current}")
        try:
            if on_main:
                git("checkout", "--quiet", "main", run=run)
                git("reset", "--quiet", "--keep", p.head_commit, run=run)
            else:
                git("checkout", "--quiet", "--detach", p.head_commit, run=run)
            _install(run)
            _restart(restart, run)
        except (UpdateError, subprocess.TimeoutExpired) as e2:
            raise UpdateError(f"{e}\nand the rollback failed too: {e2}\nrun `git checkout {p.head_commit}` in "
                              f"{ROOT}, then `tapwatch doctor`") from e
        raise UpdateError(f"{e}\nrolled back to {p.current}") from e
    say(f"updated to {p.target}" + (f"; restarted {', '.join(restart)}; doctor all good" if restart else ""))
    return True


# ---------------------------------------------------------------- the digest's notice

def notice(cfg: dict, state_path: Path, now: float | None = None, run=_run) -> str:
    """"tapwatch vX.Y.Z is available ..." once there's a newer release (releases channel), else "". Asks the remote
    at most once a day (cached in `state_path`); any failure is "" (an offline sensor shouldn't spam the digest)."""
    if (cfg.get("update") or {}).get("notify", True) is False:
        return ""
    now = time.time() if now is None else now
    try:
        if channel(cfg) != "releases":
            return ""
        cached = json.loads(state_path.read_text()) if state_path.exists() else {}
        if now - cached.get("checked", 0) > CHECK_EVERY:
            out = git("ls-remote", "--tags", "--refs", "origin", "v*", run=run)
            tags = [line.rsplit("/", 1)[-1] for line in out.splitlines()]
            cached = {"checked": now, "latest": newest(tags)}
            state_path.write_text(json.dumps(cached))
        latest, cur = cached.get("latest"), current(run)
    except (UpdateError, OSError, ValueError, subprocess.TimeoutExpired):
        return ""
    if not latest or latest == cur:
        return ""
    if TAG.match(cur) and tuple(map(int, TAG.match(cur).groups())) >= tuple(map(int, TAG.match(latest).groups())):
        return ""
    return f"tapwatch {latest} is available (this install runs {cur}): run `tapwatch update`"
