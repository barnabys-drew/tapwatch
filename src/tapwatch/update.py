"""`tapwatch update`: move an install to the newest release (or main), and back again if anything fails.

Every install method clones the repo (the Windows installer inside Ubuntu, Omarchy, the plain Linux steps), so an
update is git: fetch, check the new version out, install its dependencies into the venv, run the self-check,
restart the services the change needs, and check them. If any step fails, or the update is interrupted, the
previous version is checked out again (on the branch it was on), reinstalled and restarted, and the update says
what failed.

"Check them" is two things. The restarted services must stay up: their systemd restart counters must not move
across a wait longer than the units' RestartSec, so a version that crash-loops can't pass by being caught between
restarts. And doctor must find nothing *new* to fail: it runs before the update too, and only failures that weren't
there before count, so an agent PC that's off or a router that stopped sending logs doesn't roll every update back.

Two lines (config `update.channel`): `releases` (default) follows the newest `vX.Y.Z` tag, `main` follows the main
branch (a dev install). A checkout already past the newest release (main installed after it was cut) is never moved
back to it. Nothing updates by itself: the daily digest only says a newer release exists (`notice`), because an
install that updated on its own would turn one bad push into every install's problem.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from . import doctor

ROOT = Path(__file__).resolve().parents[2]   # src/tapwatch/update.py -> the checkout
TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
CHECK_EVERY = 86400   # the digest asks the remote at most once a day
SETTLE = 45           # seconds the restarted services must stay up: longer than the units' RestartSec (15) + start
NOTICE_TIMEOUT = 15   # the digest's version check never holds the alerter longer than this
CAPTURE_FILES = ("deploy/", "eval/capture_mirror.sh")   # what the capture unit runs
GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}    # never wait on a credential prompt


class UpdateError(RuntimeError):
    pass


def _run(cmd: list[str], cwd: Path = ROOT, timeout: float = 600) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=False, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=GIT_ENV)


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


def _ver(t: str) -> tuple:
    return tuple(int(x) for x in TAG.match(t).groups())


def newest(tags) -> str | None:
    """The highest vX.Y.Z among `tags`, by number (v0.10.0 > v0.9.0)."""
    ok = [t for t in tags if TAG.match(t)]
    return max(ok, key=_ver) if ok else None


def current(run=_run) -> str:
    """The release this checkout is on, or branch@commit."""
    p = run(["git", "describe", "--tags", "--exact-match", "HEAD"])
    if p.returncode == 0 and TAG.match(p.stdout.strip()):
        return p.stdout.strip()
    branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"]).stdout.strip() or "HEAD"
    return f"{branch}@{git('rev-parse', '--short', 'HEAD', run=run)}"


def contains(commit: str, run=_run) -> bool | None:
    """Whether HEAD already includes `commit`: True, False, or None when git can't tell (a shallow clone)."""
    if run(["git", "cat-file", "-e", f"{commit}^{{commit}}"]).returncode != 0:
        return False   # not even in the repository, so not in HEAD's history
    p = run(["git", "merge-base", "--is-ancestor", commit, "HEAD"])
    if p.returncode in (0, 1):
        return p.returncode == 0
    return None


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
    if git("rev-parse", "--is-shallow-repository", run=run) == "true":
        git("fetch", "--quiet", "--unshallow", "origin", run=run)   # history is needed to tell newer from older
    git("fetch", "--quiet", "--tags", "--force", "origin", run=run)  # --force: a tag moved upstream must not stop it
    if ch == "main":
        target = "origin/main"
    else:
        target = newest(git("tag", "-l", "v*", run=run).split())
        if not target:
            raise UpdateError("no release tags yet (vX.Y.Z); set update.channel: main to follow main")
    head, tc = git("rev-parse", "HEAD", run=run), git("rev-parse", f"{target}^{{commit}}", run=run)
    ahead = False
    if head != tc:
        inside = contains(tc, run)
        if inside is None:
            raise UpdateError(f"can't tell whether this checkout is older or newer than {target}")
        ahead = inside
    changes = git("log", "--no-merges", "--format=%s", f"{head}..{tc}", run=run).splitlines() \
        if head != tc and not ahead else []
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


def _changed(prev: str, new: str, run=_run) -> list[str]:
    return git("diff", "--name-only", prev, new, run=run).splitlines() if prev != new else []


def _units_to_restart(changed: list[str], units: list[str]) -> list[str]:
    """Every installed Python service; capture only when the files it runs changed."""
    capture = any(f.startswith(CAPTURE_FILES) for f in changed)
    return [u for u in units if u != "tapwatch-capture" or capture]


def _restart(units: list[str], run=_run) -> None:
    if not units:
        return
    p = run(["systemctl", "--user", "restart", *[f"{u}.service" for u in units]], timeout=120)
    if p.returncode != 0:
        raise UpdateError(f"restarting {', '.join(units)} failed: {(p.stderr or p.stdout).strip()[:300]}")


def _health(units: list[str], run=_run) -> dict[str, tuple[str, str]]:
    """unit -> (ActiveState, NRestarts)."""
    out = {}
    for u in units:
        p = run(["systemctl", "--user", "show", f"{u}.service", "-p", "ActiveState", "-p", "NRestarts"], timeout=30)
        kv = dict(line.split("=", 1) for line in p.stdout.splitlines() if "=" in line)
        out[u] = (kv.get("ActiveState", ""), kv.get("NRestarts", ""))
    return out


def _stayed_up(units: list[str], run=_run, sleep=time.sleep) -> None:
    """The restarted services are active now and still active, with no restart in between, SETTLE seconds later."""
    if not units:
        return
    sleep(5)
    before = _health(units, run)
    sleep(SETTLE)
    after = _health(units, run)
    bad = [u for u in units if after[u][0] != "active" or before[u][1] != after[u][1] or before[u][0] != "active"]
    if bad:
        raise UpdateError(f"{', '.join(bad)} didn't stay up after the restart (crashed or restarting): "
                          f"journalctl --user -u {bad[0]}")


def _selfcheck(cfg_path: str, run=_run) -> None:
    p = run([sys.executable, "-m", "tapwatch.cli", "-c", cfg_path, "selfcheck"], timeout=900)
    if p.returncode != 0:
        raise UpdateError("the new version's self-check failed:\n" + "\n".join(p.stdout.splitlines()[-8:]))


def _doctor_fails(cfg_path: str, run=_run) -> set[str]:
    """doctor's FAIL lines, by the part and what it says (so a FAIL that was already there before isn't new)."""
    p = run([sys.executable, "-m", "tapwatch.cli", "-c", cfg_path, "doctor"], timeout=300)
    return {" ".join(line.split()) for line in p.stdout.splitlines() if line.startswith("[FAIL]")}


def apply(cfg: dict, cfg_path: str, p: Plan, units: list[str] | None = None, run=_run, sleep=time.sleep,
          say=print) -> bool:
    """Carry out `p`. True when updated; on failure or interruption, roll back to where it was and raise."""
    if not p.needed:
        say(f"tapwatch {p.current} is " + (f"ahead of {p.target}" if p.ahead else "up to date") + f" ({p.channel})")
        return False
    dirty = _dirty(run)
    if dirty:
        raise UpdateError("the checkout has local changes, which an update would overwrite:\n  " + "\n  ".join(dirty[:8]))
    cfg_path = str(Path(cfg_path).resolve())
    units = doctor.installed_units() if units is None else units
    changed = _changed(p.head_commit, p.target_commit, run)
    restart = _units_to_restart(changed, units)
    branch = run(["git", "symbolic-ref", "-q", "--short", "HEAD"]).stdout.strip()   # "" when detached
    known = _doctor_fails(cfg_path, run) if restart else set()   # what already fails, before touching anything
    say(f"updating {p.current} -> {p.target} ({len(p.changes)} change(s))")
    try:
        _checkout(p.target, p.channel, run)
        _install(run)
        _selfcheck(cfg_path, run)
        _restart(restart, run)
        _stayed_up(restart, run, sleep)
        if restart:
            new = _doctor_fails(cfg_path, run) - known
            if "tapwatch-capture" in restart:   # Zeek rotates on shutdown: give capture its own minutes
                new = {f for f in new if " Capture " not in f"{f} "}
            if new:
                raise UpdateError("doctor found new problems after the update:\n" + "\n".join(sorted(new)[:8]))
    except BaseException as e:   # an interrupted update rolls back too (Ctrl-C mid-install, an OSError)
        old = signal.signal(signal.SIGINT, signal.SIG_IGN)   # a second Ctrl-C must not stop the rollback
        try:
            say(f"update failed: {e or type(e).__name__}\nrolling back to {p.current}")
            problems = _rollback(p, branch, restart, run)
        finally:
            signal.signal(signal.SIGINT, old)
        if problems:
            raise UpdateError(f"{e}\nand the rollback hit problems: {'; '.join(problems)}\nto finish it by hand, in "
                              f"{ROOT}: git checkout {branch or p.head_commit}"
                              + (f" && git reset --keep {p.head_commit}" if branch else "")
                              + " && .venv/bin/pip install -e . && systemctl --user restart "
                              + " ".join(f"{u}.service" for u in restart) + " && .venv/bin/tapwatch doctor") from e
        if isinstance(e, (KeyboardInterrupt, SystemExit)):
            raise UpdateError(f"interrupted; rolled back to {p.current}") from e
        raise UpdateError(f"{e}\nrolled back to {p.current}") from e
    if any(f == "src/tapwatch/service.py" for f in changed):
        say("the service definitions changed in this version: run `tapwatch service install` with your usual options")
    say(f"updated to {p.target}" + (f"; restarted {', '.join(restart)}; they stayed up and doctor found nothing new"
                                    if restart else ""))
    return True


def _rollback(p: Plan, branch: str, restart: list[str], run=_run) -> list[str]:
    """Back to the commit (and branch) it was on, reinstalled, services restarted. Each step is tried even if one
    before it failed: old files with new modules in memory is the state to avoid. Returns what went wrong."""
    problems = []
    try:
        if branch:
            git("checkout", "--quiet", branch, run=run)
            git("reset", "--quiet", "--keep", p.head_commit, run=run)
        else:
            git("checkout", "--quiet", "--detach", p.head_commit, run=run)
    except (UpdateError, OSError, subprocess.TimeoutExpired) as e:
        problems.append(f"checkout: {e}")
    for step in (lambda: _install(run), lambda: _restart(restart, run)):
        try:
            step()
        except (UpdateError, OSError, subprocess.TimeoutExpired) as e:
            problems.append(str(e))
    return problems


# ---------------------------------------------------------------- the digest's notice

def notice(cfg: dict, state_path: Path, now: float | None = None, run=_run) -> str:
    """"tapwatch vX.Y.Z is available ..." once there's a release this checkout doesn't contain (releases channel),
    else "". Asks the remote at most once a day, failures included (cached in `state_path`), with a short timeout:
    it runs in the alerter's loop. Any failure is "", so an offline sensor doesn't spam the digest."""
    if (cfg.get("update") or {}).get("notify", True) is False:
        return ""
    now = time.time() if now is None else now
    try:
        if channel(cfg) != "releases":
            return ""
        cached = json.loads(state_path.read_text()) if state_path.exists() else {}
        if "checked" not in cached or now - cached["checked"] > CHECK_EVERY:
            cached = {"checked": now, "latest": None, "commit": None}
            try:
                p = run(["git", "-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=10", "ls-remote", "--tags",
                         "origin", "v*"], timeout=NOTICE_TIMEOUT)
                peeled: dict[str, str] = {}
                for line in p.stdout.splitlines() if p.returncode == 0 else ():
                    sha, ref = line.split("\t", 1)
                    name = ref.rsplit("/", 1)[-1]
                    if name.endswith("^{}"):
                        peeled[name.removesuffix("^{}")] = sha   # an annotated tag's commit wins over the tag object
                    else:
                        peeled.setdefault(name, sha)
                latest = newest(peeled)
                cached.update(latest=latest, commit=peeled.get(latest) if latest else None)
            finally:
                state_path.write_text(json.dumps(cached))
        latest, commit = cached.get("latest"), cached.get("commit")
        if not latest or not commit or contains(commit, run) is not False:
            return ""   # nothing released, this checkout already has it, or git can't tell
        return f"tapwatch {latest} is available (this install runs {current(run)}): run `tapwatch update`"
    except (UpdateError, OSError, ValueError, subprocess.TimeoutExpired):
        return ""
