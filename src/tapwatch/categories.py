"""Domain categories from an offline list (the UT1 blacklists, fetched by `tapwatch update-feeds`).

A case that names a destination gets a `category` fact (advertising, remote_control, file_hosting,
vpn, media, ...) so Jev reads "an advertising domain" as a fact instead of guessing from the name,
and triage can see at a glance what kind of site a first contact or an odd TLS session went to.
Measured 2026-10-16: the day's false alarms were ad-tech hosts behind a phone's news page (#362,
#363), a security vendor (#373) and a video call (#371), none of which the hand lists named.

The list is a feed file (`categories.tsv`: domain, tab, category), loaded whole at startup; nothing
is looked up online. Matching is by suffix, longest first, so a listed base domain covers its hosts.
"""

from __future__ import annotations

from pathlib import Path

CATEGORIES: dict[str, str] = {}  # domain -> category; module state like detectors.LOCAL_NETS


def set_categories(table: dict[str, str]) -> None:
    CATEGORIES.clear()
    CATEGORIES.update(table)


def load(path: str | Path | None) -> int:
    """Load `categories.tsv` into the module table; returns the number of domains (0 when there is no file)."""
    table: dict[str, str] = {}
    if path and Path(path).exists():
        for line in Path(path).read_text(errors="replace").splitlines():
            if not line or line.startswith("#"):
                continue
            dom, _, cat = line.partition("\t")
            if dom and cat:
                table[dom.strip().lower()] = cat.strip()
    set_categories(table)
    return len(table)


def category(name: str | None) -> str:
    """The category of `name` or any parent domain it sits under; "" when unlisted."""
    if not name:
        return ""
    labels = name.lower().rstrip(".").split(".")
    for i in range(len(labels) - 1):
        hit = CATEGORIES.get(".".join(labels[i:]))
        if hit:
            return hit
    return ""
