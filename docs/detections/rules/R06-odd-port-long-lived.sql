-- R06 Odd-port or long-lived outbound
-- Measured 2026-10-12: 14 proto/port pairs house-wide; p99 duration 610 s; 0 connections > 1 h.
-- Route: Jev (Q-cat, Q-human, Q-wake); floor DIGEST for service-unknown on fixed-function devices.
.read docs/detections/rules/_common.sql
SET VARIABLE detect_from = (SELECT max(ts) - 3600 FROM conn);
SET VARIABLE learn_from  = getvariable('detect_from') - 14 * 86400;

WITH out AS (
    SELECT ts, "id.orig_h" AS host, "id.resp_h" AS dst, proto, "id.resp_p" AS port, service,
           coalesce(duration, 0) AS dur, coalesce(orig_bytes, 0) AS up, coalesce(resp_bytes, 0) AS down
    FROM conn
    WHERE is_internal("id.orig_h") AND NOT is_internal("id.resp_h") AND proto IN ('tcp', 'udp')
      AND conn_state NOT IN ('S0', 'REJ', 'OTH') AND ts >= getvariable('learn_from')
),
house_ports AS (SELECT DISTINCT proto, port FROM out WHERE ts < getvariable('detect_from')),
dev_ports   AS (SELECT DISTINCT host, proto, port FROM out WHERE ts < getvariable('detect_from')),
cur AS (SELECT * FROM out WHERE ts >= getvariable('detect_from'))
SELECT c.host, c.proto, c.port, any_value(c.service) AS service, count(*) AS conns,
       max(c.dur) AS longest_s, sum(c.up) AS up_bytes, sum(c.down) AS down_bytes,
       (c.proto, c.port) NOT IN (SELECT (proto, port) FROM house_ports) AS new_for_house,
       (c.host, c.proto, c.port) NOT IN (SELECT (host, proto, port) FROM dev_ports) AS new_for_device,
       'odd_port|' || c.host || '|' || c.proto || '/' || c.port AS dedupe
FROM cur c LEFT JOIN assets a ON a.ip = c.host
GROUP BY c.host, c.proto, c.port, a.fixed_function
HAVING new_for_house
    OR (coalesce(a.fixed_function, false) AND new_for_device)
    OR max(c.dur) > 4 * 3600
    OR (c.port <> 443 AND sum(c.dur) > 2 * 3600);
-- UDP on ephemeral ports from a host that did STUN in the same minute: drop (games/voice).
