-- R01 Internet-exposed service appears
-- Threat: port forward / UPnP / NAT-PMP mapping, or a compromised device listening for the internet.
-- Route: ALERT, code-only (router.CODE_ONLY). Dedupe: exposure|host|proto/port.
-- Measured 2026-10-12 (0.8 h): 0 established inbound services; 3 unanswered P2P probes.
.read docs/detections/rules/_common.sql

WITH inbound AS (
    SELECT "id.resp_h" AS host, proto, "id.resp_p" AS port, min(ts) AS first_ts,
           count(*) AS conns, count(DISTINCT "id.orig_h") AS outside_peers
    FROM conn
    WHERE NOT is_internal("id.orig_h") AND is_internal("id.resp_h")
      AND conn_state IN ('SF', 'S1', 'S2', 'S3', 'RSTO', 'RSTR')
      AND coalesce(resp_bytes, 0) > 0
    GROUP BY ALL
),
stun AS (  -- P2P apps punch holes after STUN; suppress UDP on ephemeral ports for those hosts
    SELECT DISTINCT "id.orig_h" AS host FROM conn WHERE proto = 'udp' AND "id.resp_p" = 3478
),
mapping_req AS (  -- NAT-PMP/PCP (udp/5351) or UPnP SSDP/SOAP to the gateway in the last 24 h
    SELECT "id.orig_h" AS host, max(ts) AS last_req FROM conn
    WHERE is_internal("id.resp_h") AND "id.resp_p" IN (5351, 1900, 5000) GROUP BY ALL
),
known AS (  -- exposures already acknowledged: the same query over the previous 30 days, saved by tapwatch
    SELECT host, proto, port FROM read_csv_auto(getvariable('exposure_baseline'))
)
SELECT i.*, m.last_req IS NOT NULL AND i.first_ts - m.last_req < 86400 AS after_mapping_request,
       'exposure|' || i.host || '|' || i.proto || '/' || i.port AS dedupe
FROM inbound i
LEFT JOIN mapping_req m USING (host)
WHERE (i.host, i.proto, i.port) NOT IN (SELECT (host, proto, port) FROM known)
  AND NOT (i.proto = 'udp' AND i.port >= 49152 AND i.host IN (SELECT host FROM stun))
ORDER BY first_ts;
