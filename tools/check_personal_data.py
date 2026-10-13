"""Fail if tracked files contain personal data. Run before every public push; CI runs it too.

    python3 tools/check_personal_data.py            # tracked files (git ls-files)
    python3 tools/check_personal_data.py FILE ...   # specific files

Two layers:
  * generic patterns, safe to publish: email addresses, home-directory and Windows user paths,
    MAC addresses outside documentation and test ranges
  * .personal-denylist (gitignored, never committed): one regular expression per line for your
    own specifics: hostnames, device addresses and MACs, names, employer and project names.
    CI doesn't have it; run this locally before publishing.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ALLOWED_EMAILS = re.compile(r"(noreply|no-reply)@|@(example\.(com|org|net)|users\.noreply\.github\.com|anthropic\.com)$"
                            r"|\.example$", re.IGNORECASE)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
USER_PATH = re.compile(r"((?<![\w/.])/home/(?!user\b|you\b|<)[a-z][a-z0-9_-]+|/mnt/c/Users/(?!<)[^/\s]+|"
                       r"C:\\\\?Users\\\\?(?!<|Public\b|%)[^\\\s]+)", re.IGNORECASE)
MAC = re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.IGNORECASE)
# Documentation (RFC 7042 00:00:5e:00:53), broadcast/multicast, and the test-only values tapwatch uses.
ALLOWED_MAC = re.compile(r"^(00:00:5e:00:53|00:00:00:00:00:00|ff:ff:ff:ff:ff:ff|33:33:|01:00:5e|02:00:00|aa:bb:cc|11:22:33|"
                         r"da:|08:00:27)",
                         re.IGNORECASE)
SKIP_SUFFIXES = (".pcap", ".png", ".jpg", ".gif", ".ico", ".db", ".gz", ".zip")


SELF = "tools/check_personal_data.py"  # its own patterns would match themselves


def tracked() -> list[str]:
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout
    return [f for f in out.splitlines() if not f.endswith(SKIP_SUFFIXES) and f != SELF]


def denylist(path: str = ".personal-denylist") -> list[re.Pattern]:
    p = Path(path)
    if not p.exists():
        return []
    return [re.compile(line.strip(), re.IGNORECASE) for line in p.read_text().splitlines()
            if line.strip() and not line.startswith("#")]


def scan(files: list[str], deny: list[re.Pattern]) -> list[str]:
    findings = []
    for f in files:
        try:
            text = Path(f).read_text(errors="replace")
        except (OSError, IsADirectoryError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            hits = [m.group(0) for m in EMAIL.finditer(line) if not ALLOWED_EMAILS.search(m.group(0))]
            hits += [m.group(0) for m in USER_PATH.finditer(line)]
            hits += [m.group(0) for m in MAC.finditer(line) if not ALLOWED_MAC.match(m.group(0))]
            hits += [m.group(0) for d in deny for m in d.finditer(line)]
            findings += [f"{f}:{n}: {h}" for h in hits]
    return findings


def main(argv: list[str]) -> int:
    deny = denylist()
    found = scan(argv or tracked(), deny)
    for line in found:
        print(line)
    print(f"{len(found)} finding(s); personal denylist: {len(deny)} pattern(s)"
          + ("" if deny else " (none: generic checks only)"))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
