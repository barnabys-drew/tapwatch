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
    """Real git in the clone; everything else answers from `fail` (a step name that should fail)."""

    def __init__(self, clone, fail=None):
        self.clone, self.fail, self.calls = clone, fail, []

    def __call__(self, cmd, cwd=None, timeout=600):
        if cmd[0] == "git":
            return subprocess.run(cmd, check=False, cwd=self.clone, capture_output=True, text=True)
        step = "systemctl" if cmd[0] == "systemctl" else "pip" if "pip" in cmd else cmd[-1]
        self.calls.append(step)
        ok = step != self.fail
        return subprocess.CompletedProcess(cmd, 0 if ok else 1, stdout="" if ok else "[FAIL] x  broken", stderr="")


def head(clone):
    return subprocess.run(["git", "describe", "--tags", "--always"], check=False, cwd=clone, capture_output=True, text=True).stdout.strip()


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


def test_update_checks_out_installs_selfchecks_restarts_and_runs_doctor(repos):
    origin, clone = repos
    commit(origin, "b", "v0.3.1")
    run = Runner(clone)
    p = update.plan({}, run=run)
    assert update.apply({}, "config.yaml", p, units=["tapwatch-alerter", "tapwatch-capture"], run=run,
                        sleep=lambda s: None, say=lambda m: None)
    assert head(clone) == "v0.3.1"
    assert run.calls == ["pip", "selfcheck", "systemctl", "doctor"]     # capture untouched: no deploy/ change


def test_a_failing_new_version_rolls_back(repos):
    origin, clone = repos
    commit(origin, "b", "v0.3.1")
    for step in ("selfcheck", "doctor"):
        sh(clone, "git", "checkout", "-q", "--detach", "v0.3.0")
        run = Runner(clone, fail=step)
        p = update.plan({}, run=run)
        with pytest.raises(update.UpdateError, match="rolled back to v0.3.0"):
            update.apply({}, "config.yaml", p, units=["tapwatch-alerter"], run=run, sleep=lambda s: None,
                         say=lambda m: None)
        assert head(clone) == "v0.3.0" and run.calls[-2:] == ["pip", "systemctl"]   # reinstalled, restarted


def test_a_checkout_past_the_newest_release_is_not_downgraded(repos):
    _, clone = repos
    sh(clone, "git", "checkout", "-q", "main")
    commit(clone, "local-newer")                            # main moved on after v0.3.0 was cut
    p = update.plan({}, run=Runner(clone))
    assert p.ahead and not p.needed and p.target == "v0.3.0"


def test_local_edits_stop_the_update(repos):
    origin, clone = repos
    commit(origin, "b", "v0.3.1")
    (clone / "a").write_text("edited")
    run = Runner(clone)
    with pytest.raises(update.UpdateError, match="local changes"):
        update.apply({}, "config.yaml", update.plan({}, run=run), units=[], run=run, say=lambda m: None)
    assert head(clone) == "v0.3.0"


def test_the_main_channel_follows_main(repos):
    origin, clone = repos
    sh(clone, "git", "checkout", "-q", "main")
    commit(origin, "b")
    run = Runner(clone)
    p = update.plan({"update": {"channel": "main"}}, run=run)
    assert p.target == "origin/main" and p.changes == ["add b"]
    assert update.apply({}, "c.yaml", p, units=[], run=run, say=lambda m: None)
    assert (clone / "b").exists()
    commit(origin, "c")                                     # a broken main: rolled back, and still on the branch
    run = Runner(clone, fail="selfcheck")
    with pytest.raises(update.UpdateError, match="rolled back"):
        update.apply({}, "c.yaml", update.plan({"update": {"channel": "main"}}, run=run), units=[], run=run,
                     say=lambda m: None)
    branch = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], check=False, cwd=clone, capture_output=True, text=True)
    assert branch.stdout.strip() == "main" and not (clone / "c").exists()


def test_the_digest_notice_once_a_day_and_quiet_when_current_or_offline(repos, tmp_path):
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
        return subprocess.CompletedProcess(cmd, 128, stdout="", stderr="could not resolve host")
    assert update.notice({}, tmp_path / "other.json", run=offline) == ""


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
