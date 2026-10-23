"""`tapwatch import-state`: take over another computer's tapwatch, and nothing else from the archive."""

import io
import tarfile

import pytest

from tapwatch import migrate

CONFIG = "db_path: data/tw.db\nassets_file: assets.yaml\nhost_context: {host: 192.168.50.20}\nui: {host: 192.168.50.20}\n"


def archive(path, files):
    with tarfile.open(path, "w:gz") as tar:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return path


def export(tmp_path, **extra):
    return archive(tmp_path / "state.tar.gz", {"./config.yaml": CONFIG, "./.env": "X=1\n",
                                                "./data/tw.db": "db", "./assets.yaml": "{}", **extra})


def test_an_export_is_taken_over_and_the_old_computers_settings_listed(tmp_path):
    dest = tmp_path / "new"
    dest.mkdir()
    listed = migrate.import_state(export(tmp_path), dest)
    assert sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file()) == \
        [".env", "assets.yaml", "config.yaml", "data/tw.db"]
    assert (dest / ".env").stat().st_mode & 0o777 == 0o600
    assert listed == ["host_context.host: 192.168.50.20", "ui.host: 192.168.50.20"]


def test_anything_else_in_the_archive_refuses_it(tmp_path):
    dest = tmp_path / "new"
    dest.mkdir()
    with pytest.raises(migrate.ImportRefused, match="eval/capture_mirror.sh"):
        migrate.import_state(export(tmp_path, **{"./eval/capture_mirror.sh": "pwn"}), dest)
    assert list(dest.iterdir()) == []
    with pytest.raises(migrate.ImportRefused, match="not a path inside"):
        migrate.import_state(export(tmp_path, **{"../outside": "x"}), dest)


def test_an_existing_install_is_never_overwritten(tmp_path):
    (tmp_path / "config.yaml").write_text("mine: true\n")
    with pytest.raises(migrate.ImportRefused, match="already has a config.yaml"):
        migrate.import_state(export(tmp_path), tmp_path)
    assert (tmp_path / "config.yaml").read_text() == "mine: true\n"
