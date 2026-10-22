#!/usr/bin/env bash
# Pack up a tapwatch install to move it to another computer (deploy/omarchy/install.sh --import <file>):
# config.yaml, .env, the assets file, your own IOC list (ioc_file) and the database, which holds the cases, their
# notes and suppressions, and every detector's learned baselines, so the new sensor doesn't start a new learning
# period. The public lists aren't packed: the new computer downloads them.
#
#   deploy/export-state.sh [tapwatch folder (default: this checkout)] [out file (default: ./tapwatch-state.tar.gz)]
#
# The database is copied with SQLite's online backup, so the alerter can keep running; cases it adds after this
# stay on the old computer. Stop the old sensor once the new one runs (systemctl --user disable --now 'tapwatch-*'),
# or both alert on everything. The file holds .env, with the alert addresses and API keys: it is made readable by
# you only. Move it directly (scp, a USB stick) and delete it afterwards.
set -euo pipefail
home=$(realpath "${1:-$(dirname "$0")/..}")
out=$(realpath -m "${2:-tapwatch-state.tar.gz}")
cd "$home"
for f in config.yaml .env; do
  [ -f "$f" ] || { echo "no $f in $home" >&2; exit 1; }
done
py=$([ -x .venv/bin/python ] && echo .venv/bin/python || echo python3)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# The database, assets file and IOC list where config.yaml says they are (db_path, assets_file, ioc_file), packed
# under those names. The assets file and IOC list are optional, as they are to tapwatch.
"$py" - "$tmp" <<'PY'
import shutil
import sqlite3
import sys
from pathlib import Path

import yaml

out = Path(sys.argv[1])
cfg = yaml.safe_load(open("config.yaml")) or {}
db = cfg.get("db_path", "tapwatch.db")
optional = [cfg[k] for k in ("assets_file", "ioc_file") if cfg.get(k)]
for name in (db, *optional):
    if Path(name).is_absolute() or ".." in Path(name).parts:
        sys.exit(f"{name}: only files inside the tapwatch folder can be moved this way; copy it by hand")
if not Path(db).is_file():
    sys.exit(f"no database at {db}")
for name in ("config.yaml", ".env", *(o for o in optional if Path(o).is_file())):
    (out / name).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(name, out / name)
(out / db).parent.mkdir(parents=True, exist_ok=True)
src, dst = sqlite3.connect(f"file:{db}?mode=ro", uri=True), sqlite3.connect(out / db)
src.backup(dst)  # consistent while the alerter keeps writing
dst.close()
PY
(umask 077 && tar -czf "$out" -C "$tmp" .)
echo "wrote $out ($(du -h "$out" | cut -f1)); on the new computer: deploy/omarchy/install.sh --import $(basename "$out")"
