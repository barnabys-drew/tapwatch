-- R08 Newly registered or rare-in-household domain. CODE-ONLY: Jev is measured weak at
-- "is this new domain normal" (called herdr.dev, bleepingcomputer.com C2 at 0.5-0.95).
-- Measured 2026-10-12: ~150 first-seen (device, base domain) pairs/h after warmup on an active
-- evening; 160 of 167 base domains were in Tranco top-100k; 124 used by only one device.
-- Route: NRD on fixed-function -> ALERT; NRD on other -> DIGEST; random-looking -> DIGEST; else LOG.
.read docs/detections/rules/_common.sql
CREATE OR REPLACE VIEW tranco AS SELECT lower(column1) AS dom FROM read_csv(getvariable('tranco'), header=false);
CREATE OR REPLACE VIEW nrd    AS SELECT lower(column0) AS dom FROM read_csv(getvariable('nrd_30d'), header=false);
SET VARIABLE detect_from = (SELECT max(ts) - 3600 FROM conn);

WITH names AS (
    SELECT ts, "id.orig_h" AS host, query AS name FROM dns
    WHERE "id.resp_p" = 53 AND rcode_name = 'NOERROR' AND query LIKE '%.%'
    UNION ALL
    SELECT ts, "id.orig_h", server_name FROM ssl WHERE server_name LIKE '%.%'
),
clean AS (
    SELECT ts, host, name, base_domain(name) AS dom FROM names
    WHERE is_internal(host) AND NOT regexp_matches(name, '\.(local|arpa|localdomain|lan|home)\.?$')
),
firsts AS (SELECT host, dom, min(ts) AS first_ts, any_value(name) AS example FROM clean GROUP BY ALL),
users AS (SELECT dom, count(DISTINCT host) AS n FROM firsts GROUP BY dom)
SELECT f.host, f.dom, f.example, f.first_ts,
       f.dom IN (SELECT dom FROM nrd) AS newly_registered,
       -- looks_random() from detectors.py: label >= 10 chars and (>= 3 digits or vowel ratio < 0.2 or consonant run >= 6)
       regexp_matches(split_part(f.example, '.', 1), '^.{10,}$')
         AND (length(regexp_replace(split_part(f.example, '.', 1), '[^0-9]', '', 'g')) >= 3
              OR regexp_matches(split_part(f.example, '.', 1), '[b-df-hj-np-tv-z]{6}')) AS random_looking,
       coalesce(a.fixed_function, false) AS fixed_function,
       'new_domain|' || f.host || '|' || f.dom AS dedupe
FROM firsts f JOIN users u USING (dom) LEFT JOIN assets a ON a.ip = f.host
WHERE f.first_ts >= getvariable('detect_from')
  AND u.n = 1
  AND f.dom NOT IN (SELECT dom FROM tranco)
  AND f.dom NOT IN (SELECT dom FROM read_csv(getvariable('domain_allow'), header=false, columns={'dom': 'VARCHAR'}));  -- work suffixes live in config, not git
