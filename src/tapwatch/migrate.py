"""`tapwatch import-state <file>`: take over another computer's tapwatch (deploy/export-state.sh made the file).

The archive carries config.yaml, .env, the database (cases, notes, suppressions, every detector's learned
baselines) and the assets file and own IOC list. Only those are taken, at the paths that config.yaml names, inside
this folder: any other member refuses the whole archive, so a file can't replace code that runs as this account.
Python's "data" tar filter also refuses links, devices and absolute or `..` paths. A path that already exists here
is refused too: in a fresh install nothing at the database or assets path exists yet, so anything that does is code
or the owner's own data. Everything is unpacked into a folder of its own first and moved into place only when all of
it arrived, config.yaml last, so a failed import leaves nothing that looks like a finished install. The settings that
named the old computer are listed for the owner to point at this one, not rewritten: config.yaml carries the owner's
comments.
"""

from __future__ import annotations

import os
import shutil
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

import yaml

# Settings that usually name the computer they were written on.
MACHINE_SETTINGS = (("host_context", "host"), ("ui", "host"), ("ui", "base_url"), ("ui", "zeek_dirs"),
                    ("ui", "home_url"), (None, "feeds_dir"), (None, "smtp"), ("fleet", "results_log"))


class ImportRefused(ValueError):
    pass


def _norm(name) -> str:
    if not isinstance(name, str) or not name:
        raise ImportRefused(f"refusing the archive: {name!r} is not a file path")
    p = PurePosixPath(name)
    parts = [x for x in p.parts if x != "."]
    if p.is_absolute() or ".." in parts or not parts:
        raise ImportRefused(f"refusing {name!r}: not a path inside the tapwatch folder")
    return "/".join(parts)


def import_state(archive: str | Path, dest: str | Path = ".") -> list[str]:
    """Unpack `archive` into `dest`. Returns "key: value" lines for the settings to point at this computer."""
    dest = Path(dest)
    if (dest / "config.yaml").exists():
        raise ImportRefused("this folder already has a config.yaml: move it (and the database) aside to import")
    try:
        with tarfile.open(archive) as tar:
            members = {_norm(m.name): m for m in tar.getmembers() if m.isfile()}
            if "config.yaml" not in members or ".env" not in members:
                raise ImportRefused("not a tapwatch export: it has no config.yaml or .env "
                                    "(make one with deploy/export-state.sh)")
            cfg = yaml.safe_load(tar.extractfile(members["config.yaml"])) or {}
            if not isinstance(cfg, dict):
                raise ImportRefused("refusing the archive: its config.yaml is not a tapwatch config")
            db = _norm(cfg.get("db_path") or "tapwatch.db")
            if db not in members:
                raise ImportRefused(f"not a full export: it has no database ({db}); make it again with deploy/export-state.sh")
            allowed = {"config.yaml", ".env", db} | {_norm(cfg[k]) for k in ("assets_file", "ioc_file") if cfg.get(k)}
            extra = sorted(set(members) - allowed)
            if extra:
                raise ImportRefused(f"refusing the archive: it holds files a tapwatch export doesn't: {', '.join(extra[:5])}")
            there = sorted(n for n in members if (dest / n).exists() or (dest / n).is_symlink())
            if there:
                raise ImportRefused(f"refusing to overwrite {', '.join(there)}: move it aside first")
            staging = Path(tempfile.mkdtemp(prefix=".import-", dir=dest))
            try:
                tar.extractall(staging, members=list(members.values()), filter="data")
                os.chmod(staging / ".env", 0o600)   # before it moves into place: it holds the alert addresses and keys
                for name in sorted(members, key=lambda n: n == "config.yaml"):   # config.yaml last: it marks the install
                    (dest / name).parent.mkdir(parents=True, exist_ok=True)
                    os.replace(staging / name, dest / name)
            finally:
                shutil.rmtree(staging, ignore_errors=True)
    except (tarfile.TarError, yaml.YAMLError) as e:
        raise ImportRefused(f"can't read the export: {e}") from e
    return review(cfg)


def review(cfg: dict) -> list[str]:
    out = []
    for section, key in MACHINE_SETTINGS:
        part = cfg.get(section) if section else cfg
        val = part.get(key) if isinstance(part, dict) else None
        if val:
            out.append(f"{section + '.' if section else ''}{key}: {'(set)' if key == 'smtp' else val}")
    return out
