# Live capture: the shared policy plus hourly rotation, so logs never fill the disk.
# Rotated files are named conn.2026-10-13-14-00-00.log (UTC open time); tapwatch reads them
# for case evidence and deletes them after zeek_retention_days (default 30).
@load ./tapwatch.zeek

redef Log::default_rotation_interval = 1 hr;
