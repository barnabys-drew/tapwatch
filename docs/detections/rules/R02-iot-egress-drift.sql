-- R02 Fixed-function device egress drift (camera, TV, hub, printer, network gear, audio)
-- Route: new port or country -> DIGEST (Jev may raise to ALERT); ASN-only drift -> LOG.
-- Jev: Q-role-fit, Q-cat, Q-wake on a summary that already says "new for this device".
--      Never ask Jev whether the ASN/country is normal.
-- Needs: offline ASN/country table (iptoasn.com TSV loaded as ip2asn(range_start, range_end, asn, country)).
.read docs/detections/rules/_common.sql
SET VARIABLE detect_from = (SELECT max(ts) - 3600 FROM conn);       -- last hour
SET VARIABLE learn_from  = getvariable('detect_from') - 14 * 86400;  -- 14 days before it

WITH ff AS (SELECT ip FROM assets WHERE fixed_function),
out AS (
    SELECT c.ts, c."id.orig_h" AS host, c.proto, c."id.resp_p" AS port, c."id.resp_h" AS dst,
           a.asn, a.country
    FROM conn c
    JOIN ff ON c."id.orig_h" = ff.ip
    LEFT JOIN ip2asn a ON inet_aton(c."id.resp_h") BETWEEN a.range_start AND a.range_end  -- IPv4 only; tapwatch uses a radix lookup
    WHERE NOT is_internal(c."id.resp_h") AND c.ts >= getvariable('learn_from')
),
base AS (SELECT * FROM out WHERE ts < getvariable('detect_from')),
cur  AS (SELECT * FROM out WHERE ts >= getvariable('detect_from')),
new_port AS (
    SELECT host, 'port' AS dim, proto || '/' || port AS value, count(*) AS conns FROM cur
    WHERE (host, proto, port) NOT IN (SELECT (host, proto, port) FROM base) GROUP BY ALL
),
new_country AS (
    SELECT host, 'country' AS dim, country AS value, count(*) AS conns FROM cur
    WHERE country IS NOT NULL AND (host, country) NOT IN (SELECT (host, country) FROM base) GROUP BY ALL
),
new_asn AS (
    SELECT host, 'asn' AS dim, string_agg(DISTINCT asn::VARCHAR, ',') AS value, count(*) AS conns FROM cur
    WHERE (host, asn) NOT IN (SELECT (host, asn) FROM base) GROUP BY host
    HAVING count(DISTINCT asn) >= 3
)
SELECT *, 'iot_drift|' || host || '|' || dim || '|' || value AS dedupe,
       CASE dim WHEN 'asn' THEN 'log' ELSE 'digest' END AS floor_route
FROM (SELECT * FROM new_port UNION ALL SELECT * FROM new_country UNION ALL SELECT * FROM new_asn)
-- Learning guard: devices with < 7 days of history stay silent.
WHERE host IN (SELECT host FROM base GROUP BY host HAVING max(ts) - min(ts) >= 7 * 86400);
