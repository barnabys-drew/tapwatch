"""`tapwatch update` (#304) against real git repos in a temp folder; pip, the self-check, systemd and doctor are faked."""
import subprocess

import pytest

from tapwatch import update


def sh(cwd, *cmd):
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)


def commit(repo, name, tag=None):
    (repo / name).write_text(name)
    sh(repo, "git", "add", name)
    sh(repo, "git", "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", f"add {name}")
    if tag:
        sh(repo, "git", "tag", tag)


@pytest.fixture
def repos(tmp_path):
    origin = tmp_path / "origin"
    origin.mkdir()
    sh(origin, "git", "init", "-q", "-b", "main")
    commit(origin, "a", "v0.3.0")
    clone = tmp_path / "clone"
    sh(tmp_path, "git", "clone", "-q", str(origin), str(clone))
    sh(clone, "git", "checkout", "-q", "--detach", "v0.3.0")
    return origin, clone


class Runner:
    """Real git in the clone; pip, self-check, systemctl and doctor are scripted.

    fail: a step that fails ("pip", "selfcheck", "restart"); raise_in: a step that raises (an interrupt);
    doctor: FAIL lines before and after the update; restarts: NRestarts per `show` call, in order."""

    def __init__(self, clone, fail=None, raise_in=None, doctor=((), ()), restarts=("0", "0"), fail_once=False):
        self.clone, self.fail, self.raise_in, self.calls, self.fail_once = clone, fail, raise_in, [], fail_once
        self.doctor, self.restarts, self.shows, self.doctors = doctor, restarts, 0, 0

    def __call__(self, cmd, cwd=None, timeout=600):
        if cmd[0] == "git":
            return subprocess.run(cmd, check=False, cwd=self.clone, capture_output=True, text=True)
        if cmd[0] == "systemctl":
            step = "show" if cmd[2] == "show" else "restart"
        else:
            step = "pip" if "pip" in cmd else cmd[-1]
        self.calls.append(step)
        if step == self.raise_in:
            raise KeyboardInterrupt
        out = ""
        if step == "show":
            out = f"ActiveState=active\nNRestarts={self.restarts[min(self.shows, len(self.restarts) - 1)]}\n"
            self.shows += 1
        elif step == "doctor":
            out = "\n".join(self.doctor[min(self.doctors, 1)])
            self.doctors += 1
        failed = step == self.fail
        if failed and self.fail_once:
            self.fail = None   # the rollback's own attempt at the same step works
        return subprocess.CompletedProcess(cmd, 1 if failed else 0, stdout=out, stderr="")


def head(clone):
    return subprocess.run(["git", "describe", "--tags", "--always"], check=False, cwd=clone, capture_output=True,
                          text=True).stdout.strip()


def branch(clone):
    return subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], check=False, cwd=clone, capture_output=True,
                          text=True).stdout.strip()


def apply(run, p, units=("tapwatch-alerter",)):
    return update.apply({}, "config.yaml", p, units=list(units), run=run, sleep=lambda s: None, say=lambda m: None)


def test_newest_release_is_by_number_not_by_text():
    assert update.newest(["v0.9.0", "v0.10.0", "v0.3.1", "latest", "v1.0"]) == "v0.10.0"
    assert update.newest(["nightly"]) is None


def test_up_to_date_then_a_new_release_is_planned_with_its_changes(repos):
    origin, clone = repos
    run = Runner(clone)
    p = update.plan({}, run=run)
    assert (p.current, p.target, p.needed) == ("v0.3.0", "v0.3.0", False)
    commit(origin, "b")
    commit(origin, "c", "v0.3.1")
    p = update.plan({}, run=run)
    assert p.target == "v0.3.1" and p.needed and p.changes == ["add c", "add b"]


def test_update_installs_selfchecks_restarts_waits_and_runs_doctor(repos):
    origin, clone = repos
    commit(origin, "b", "v0.3.1")
    run = Runner(clone)
    assert apply(run, update.plan({}, run=run), units=["tapwatch-alerter", "tapwatch-capture"])
    assert head(clone) == "v0.3.1"
    assert run.calls == ["doctor", "pip", "selfcheck", "restart", "show", "show", "doctor"]   # capture untouched


def test_a_failure_doctor_already_had_doesnt_roll_back_but_a_new_one_does(repos):
    origin, clone = repos
    commit(origin, "b", "v0.3.1")
    agent_off = "[FAIL] PC agent   hasn't changed for 9 h"
    run = Runner(clone, doctor=([agent_off], [agent_off]))
    assert apply(run, update.plan({}, run=run)) and head(clone) == "v0.3.1"
    sh(clone, "git", "checkout", "-q", "--detach", "v0.3.0")
    run = Runner(clone, doctor=([agent_off], [agent_off, "[FAIL] Services   tapwatch-alerter failed"]))
    with pytest.raises(update.UpdateError, match="new problems") as e:
        apply(run, update.plan({}, run=run))
    assert "rolled back to v0.3.0" in str(e.value) and "hasn't changed" not in str(e.value) and head(clone) == "v0.3.0"


@pytest.mark.parametrize("fail", ["selfcheck", "restart"])
def test_a_failing_step_rolls_back_reinstalls_and_restarts(repos, fail):
    origin, clone = repos
    commit(origin, "b", "v0.3.1")
    run = Runner(clone, fail=fail, fail_once=True)
    with pytest.raises(update.UpdateError, match="rolled back to v0.3.0"):
        apply(run, update.plan({}, run=run))
    assert head(clone) == "v0.3.0" and run.calls[-2:] == ["pip", "restart"]


def test_a_service_that_crash_loops_between_checks_rolls_back(repos):
    origin, clone = repos
    commit(origin, "b", "v0.3.1")
    run = Runner(clone, restarts=("0", "2"))                 # active both times, but restarted in between
    with pytest.raises(update.UpdateError, match="didn't stay up"):
        apply(run, update.plan({}, run=run))
    assert head(clone) == "v0.3.0"


def test_ctrl_c_mid_install_still_rolls_back(repos):
    origin, clone = repos
    commit(origin, "b", "v0.3.1")
    run = Runner(clone, raise_in="selfcheck")
    with pytest.raises(update.UpdateError, match="interrupted; rolled back"):
        apply(run, update.plan({}, run=run))
    assert head(clone) == "v0.3.0"


def test_a_rollback_whose_reinstall_fails_still_restarts_and_says_how_to_finish(repos):
    origin, clone = repos
    commit(origin, "b", "v0.3.1")
    run = Runner(clone, fail="selfcheck")

    def pip_fails_on_the_way_back(cmd, cwd=None, timeout=600):
        if "pip" in cmd and "selfcheck" in run.calls:
            run.calls.append("pip")
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="no network")
        return run(cmd, cwd, timeout)
    with pytest.raises(update.UpdateError, match="finish it by hand") as e:
        apply(pip_fails_on_the_way_back, update.plan({}, run=run))
    assert run.calls[-1] == "restart" and "pip install -e ." in str(e.value)


def test_local_edits_stop_the_update(repos):
    origin, clone = repos
    commit(origin, "b", "v0.3.1")
    (clone / "a").write_text("edited")
    run = Runner(clone)
    with pytest.raises(update.UpdateError, match="local changes"):
        apply(run, update.plan({}, run=run))
    assert head(clone) == "v0.3.0"


def test_a_checkout_past_the_newest_release_is_not_downgraded(repos):
    _, clone = repos
    sh(clone, "git", "checkout", "-q", "main")
    commit(clone, "local-newer")                            # main moved on after v0.3.0 was cut
    p = update.plan({}, run=Runner(clone))
    assert p.ahead and not p.needed and p.target == "v0.3.0"


def test_the_main_channel_follows_main_and_a_rollback_keeps_the_branch(repos):
    origin, clone = repos
    sh(clone, "git", "checkout", "-q", "main")
    commit(origin, "b")
    run = Runner(clone)
    p = update.plan({"update": {"channel": "main"}}, run=run)
    assert p.target == "origin/main" and p.changes == ["add b"]
    assert apply(run, p, units=[])
    assert (clone / "b").exists()
    commit(origin, "c")                                     # a broken main: rolled back, and still on the branch
    run = Runner(clone, fail="selfcheck")
    with pytest.raises(update.UpdateError, match="rolled back"):
        apply(run, update.plan({"update": {"channel": "main"}}, run=run), units=[])
    assert branch(clone) == "main" and not (clone / "c").exists()


def test_a_rollback_returns_to_another_branch_too(repos):
    origin, clone = repos
    sh(clone, "git", "checkout", "-q", "-b", "dev")         # an install from a dev ZIP
    commit(origin, "b", "v0.3.1")
    run = Runner(clone, fail="selfcheck")
    with pytest.raises(update.UpdateError, match="rolled back"):
        apply(run, update.plan({}, run=run))
    assert branch(clone) == "dev"


def test_the_digest_notice_once_a_day_quiet_when_current_or_offline(repos, tmp_path):
    origin, clone = repos
    state = tmp_path / "check.json"
    run = Runner(clone)
    assert update.notice({}, state, now=1000, run=run) == ""                       # on the newest release
    commit(origin, "b", "v0.3.1")
    assert update.notice({}, state, now=2000, run=run) == ""                       # cached for a day
    text = update.notice({}, state, now=1000 + update.CHECK_EVERY + 1, run=run)
    assert "v0.3.1 is available" in text and "v0.3.0" in text
    assert update.notice({"update": {"notify": False}}, state, run=run) == ""
    assert update.notice({"update": {"channel": "main"}}, state, run=run) == ""

    def offline(cmd, cwd=None, timeout=600):
        if "ls-remote" in cmd:
            assert timeout <= update.NOTICE_TIMEOUT                           # never holds the alerter for long
        return subprocess.CompletedProcess(cmd, 128, stdout="", stderr="could not resolve host")
    other = tmp_path / "other.json"
    assert update.notice({}, other, now=5000, run=offline) == "" and other.exists()   # failures cached too


def test_no_notice_for_a_main_install_already_past_the_newest_release(repos, tmp_path):
    """Review of #312: every install is on main; a release it already contains isn't an update."""
    origin, clone = repos
    sh(clone, "git", "checkout", "-q", "main")
    commit(origin, "b")
    sh(clone, "git", "pull", "-q", "--ff-only")
    assert update.notice({}, tmp_path / "c.json", now=1, run=Runner(clone)) == ""


def test_the_digest_carries_the_notice_even_with_nothing_else_to_review(tmp_path):
    from tapwatch.pipeline import Pipeline
    from tapwatch.store import Store
    from tapwatch.summarizer import Assets

    sent = []

    class Notifier:
        def send(self, title, items):
            sent.append((title, items))

    p = Pipeline([], Assets(), Store(str(tmp_path / "t.db")), notifier=Notifier(),
                 update_notice=lambda: "tapwatch v0.3.1 is available (this install runs v0.3.0): run `tapwatch update`")
    assert p.send_digest() == 1
    title, items = sent[0]
    assert "update available" in title and "v0.3.1" in items[0]["facts"]["What"]
    def broken():
        raise RuntimeError("no network")
    sent.clear()
    assert Pipeline([], Assets(), Store(str(tmp_path / "u.db")), notifier=Notifier(), update_notice=broken).send_digest() == 0
