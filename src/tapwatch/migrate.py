"""`tapwatch import-state <file>`: take over another computer's tapwatch (deploy/export-state.sh made the file).

The archive carries config.yaml, .env, the database (cases, notes, suppressions, every detector's learned
baselines) and the assets file and own IOC list. Only those are taken, at the paths that config.yaml names, inside
this folder: any other member refuses the whole archive, so a file can't replace code that runs as this account.
Python's "data" tar filter also refuses links, devices and absolute or `..` paths. The settings that named the old
computer are listed for the owner to point at this one, not rewritten: config.yaml carries the owner's comments.
"""

from __future__ import annotations

import os
import tarfile
from pathlib import Path, PurePosixPath

import yaml

# Settings that usually name the computer they were written on.
MACHINE_SETTINGS = (("host_context", "host"), ("ui", "host"), ("ui", "base_url"), ("ui", "zeek_dirs"),
                    (None, "feeds_dir"), (None, "smtp"), ("fleet", "results_log"))


class ImportRefused(ValueError):
    pass


def _norm(name: str) -> str:
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
    with tarfile.open(archive) as tar:
        members = {_norm(m.name): m for m in tar.getmembers() if m.isfile()}
        if "config.yaml" not in members or ".env" not in members:
            raise ImportRefused("not a tapwatch export: it has no config.yaml or .env (make one with deploy/export-state.sh)")
        cfg = yaml.safe_load(tar.extractfile(members["config.yaml"])) or {}
        allowed = {"config.yaml", ".env", _norm(cfg.get("db_path") or "tapwatch.db")}
        allowed |= {_norm(cfg[k]) for k in ("assets_file", "ioc_file") if cfg.get(k)}
        extra = sorted(set(members) - allowed)
        if extra:
            raise ImportRefused(f"refusing the archive: it holds files a tapwatch export doesn't: {', '.join(extra[:5])}")
        tar.extractall(dest, members=list(members.values()), filter="data")
    os.chmod(dest / ".env", 0o600)
    return review(cfg)


def review(cfg: dict) -> list[str]:
    out = []
    for section, key in MACHINE_SETTINGS:
        val = (cfg.get(section) or {}).get(key) if section else cfg.get(key)
        if val:
            out.append(f"{section + '.' if section else ''}{key}: {'(set)' if key == 'smtp' else val}")
    return out
