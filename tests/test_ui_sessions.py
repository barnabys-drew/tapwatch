from tapwatch.summarizer import Assets
from tapwatch.ui import App

TOKEN = "abcde-fghij-klmno-pqrst"


def app(tmp_path, token=TOKEN):
    return App(str(tmp_path / "t.db"), Assets(), host="0.0.0.0", token=token)


def test_login_survives_a_ui_restart(tmp_path):
    sid = app(tmp_path).new_session()
    assert app(tmp_path).session_ok(sid)  # a fresh App with the same token still accepts it


def test_forged_or_unsigned_sessions_are_rejected(tmp_path):
    a = app(tmp_path)
    nonce = a.new_session().split(".")[0]
    assert not a.session_ok(nonce)                   # no signature
    assert not a.session_ok(nonce + ".AAAAAAAAAAAA")  # wrong signature
    assert not a.session_ok(None)


def test_changing_the_token_logs_everyone_out(tmp_path):
    sid = app(tmp_path).new_session()
    assert not app(tmp_path, token="zzzzz-yyyyy-xxxxx-wwwww").session_ok(sid)


def test_logout_revokes(tmp_path):
    a = app(tmp_path)
    sid = a.new_session()
    a.revoked.add(sid)
    assert not a.session_ok(sid)
