# Contributing

Thanks for helping. tapwatch is small on purpose: plain Python, few dependencies, rules you can read.

## Set up

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
make test lint
python3 tools/check_personal_data.py     # no personal data in tracked files
```

Changes go to the `dev` branch by pull request; `dev` is merged into `main` when its checks
(tests, lint, Semgrep, Trivy, the personal-data check) are green.

## Never share real traffic

Logs from a real network reveal what people do at home. **Don't paste Zeek logs, pcaps, internal
addresses, MAC addresses or hostnames into issues or pull requests.** Describe the pattern
instead ("a TV connects to one host every 300 s over TLS"), or reproduce it with
`eval/make_synthetic_pcap.py`. Tests use documentation addresses (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`, `00:00:5e:00:53:xx`) or `192.168.50.0/24` for "inside".

`tools/check_personal_data.py` also reads an optional, gitignored `.personal-denylist` (one regex
per line) with your own hostnames, addresses and names. Run it before every push.

## Adding or changing a detector

1. Write the threat, the fields it reads, the logic, the baseline, the expected false positives
   and how to test safely at home. `docs/detections/DESIGN.md` has the format.
2. Implement it in `src/tapwatch/detectors.py`: a `Detector` with `feed()` returning `Case`s. Put
   counting, timing and thresholds in code. If it learns something, list it in `PERSIST`.
3. Decide routing: always-alert (`must_alert`), code-only (`router.CODE_ONLY`), or AI-assisted.
   Don't ask Jev whether a domain or address is normal.
4. Add tests, including the false positives you expect.
5. Show it on data: `tapwatch eval` on a public capture or a synthetic pcap, and the noise on
   benign traffic. Share numbers, not logs.

## Style

Match the surrounding code. Comments explain *why* (often with the measurement that motivated a
threshold). `ruff check src tests` must pass.
