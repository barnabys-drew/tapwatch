-- R09 Upload drift (all devices) and camera upload stop
-- Measured 2026-10-12: cloud camera ~340 MB/h up, steady; next device 23 MB/h; most ~0.
-- Route: Jev (Q-cat, Q-routine, Q-wake) for spikes; camera stop -> DIGEST, code-only.
.read docs/detections/rules/_common.sql

WITH hourly AS (
    SELECT "id.orig_h" AS host, (ts // 3600)::BIGINT AS hr,
           dayofweek(to_timestamp(ts)) * 24 + hour(to_timestamp(ts)) AS how,   -- hour of week
           sum(coalesce(orig_bytes, 0)) AS up
    FROM conn WHERE is_internal("id.orig_h") AND NOT is_internal("id.resp_h") GROUP BY ALL
),
cur AS (SELECT * FROM hourly WHERE hr = (SELECT max(hr) - 1 FROM hourly)),          -- last complete hour
prof AS (
    SELECT h.host, h.how, median(h.up) AS med, count(*) AS weeks
    FROM hourly h WHERE h.hr < (SELECT max(hr) - 1 FROM hourly) GROUP BY ALL
)
SELECT c.host, c.up / 1e6 AS up_mb, p.med / 1e6 AS normal_mb, c.up / nullif(p.med, 0) AS times_normal,
       coalesce(a.role, 'unknown') AS role,
       CASE WHEN a.role = 'camera' AND c.up < 0.05 * p.med THEN 'camera_stop' ELSE 'spike' END AS kind,
       'upload|' || c.host || '|' || c.hr AS dedupe
FROM cur c JOIN prof p USING (host, how) LEFT JOIN assets a ON a.ip = c.host
WHERE p.weeks >= 2
  AND ((c.up > 10 * greatest(p.med, 1) AND c.up > 500e6)
       OR (a.role = 'camera' AND c.up < 0.05 * p.med));
-- Camera "new destination" clause (> 50 MB/h to a base domain outside its 14-day set) runs in R02's state.
