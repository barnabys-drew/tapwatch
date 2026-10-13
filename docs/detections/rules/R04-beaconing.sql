-- R04 Beaconing, home-tuned (hunt version of detectors.Beaconing: CV <= 0.15, >= 10 hits, >= 10 min)
-- Route: Jev (Q-cat, Q-sev, Q-routine, Q-wake, Q-role-fit). Code adds sni_popular, shared_by, role.
.read docs/detections/rules/_common.sql
CREATE OR REPLACE VIEW tranco AS SELECT lower(column1) AS dom FROM read_csv(getvariable('tranco'), header=false);

WITH c AS (
    SELECT "id.orig_h" AS host, "id.resp_h" AS dst, "id.resp_p" AS port, ts,
           ts - lag(ts) OVER (PARTITION BY "id.orig_h", "id.resp_h", "id.resp_p" ORDER BY ts) AS gap,
           coalesce(orig_bytes, 0) AS up
    FROM conn WHERE is_internal("id.orig_h") AND NOT is_internal("id.resp_h")
),
pairs AS (
    SELECT host, dst, port, count(*) AS hits, max(ts) - min(ts) AS span_s,
           avg(gap) AS mean_gap, stddev_pop(gap) / nullif(avg(gap), 0) AS cv, avg(up) AS bytes_per_hit
    FROM c GROUP BY ALL
    HAVING count(*) >= 10 AND max(ts) - min(ts) >= 600 AND avg(gap) >= 5
),
sni AS (SELECT "id.resp_h" AS dst, any_value(server_name) AS sni FROM ssl WHERE server_name IS NOT NULL GROUP BY 1),
shared AS (  -- how many household devices talk to the same base domain
    SELECT base_domain(server_name) AS dom, count(DISTINCT "id.orig_h") AS n FROM ssl
    WHERE server_name IS NOT NULL GROUP BY 1
)
SELECT p.*, s.sni, base_domain(s.sni) IN (SELECT dom FROM tranco) AS sni_popular,
       coalesce(sh.n, 0) - 1 AS shared_by_other_devices,
       'beaconing|' || p.host || '|' || p.dst || ':' || p.port AS dedupe
FROM pairs p LEFT JOIN sni s USING (dst) LEFT JOIN shared sh ON sh.dom = base_domain(s.sni)
WHERE p.cv <= 0.15
  -- home suppression: popular AND shared heartbeat (push, NTP, vendor cloud) -> leave to LOG
  AND NOT (base_domain(s.sni) IN (SELECT dom FROM tranco) AND coalesce(sh.n, 0) >= 2)
ORDER BY cv;
