-- R10 TLS weak-signal stack: score established outbound TLS, raise at >= 3.
-- Measured 2026-10-12: 22% of TLS rows lack SNI but only 43 established; 0.7% of established outbound
-- TCP went to an IP no DNS answer explains; 49 'unable to get local issuer' rows = Zeek missing
-- intermediates on Windows CDN traffic (never scored on its own).
-- Route: 3 -> DIGEST; >= 4 -> Jev (Q-cat, Q-wake). JA4 clause needs the FoxIO ja4 Zeek package.
.read docs/detections/rules/_common.sql
CREATE OR REPLACE VIEW x509 AS SELECT * FROM read_json_auto(zeek('x509'), format='newline_delimited', ignore_errors=true);

WITH answered AS (SELECT DISTINCT unnest(answers) AS ip FROM dns WHERE answers IS NOT NULL),
selfsigned AS (SELECT DISTINCT fingerprint FROM x509 WHERE "certificate.subject" = "certificate.issuer"),
s AS (
    SELECT ts, "id.orig_h" AS host, "id.resp_h" AS dst, "id.resp_p" AS port, server_name,
           (server_name IS NULL)::INT AS no_sni,
           ("id.resp_h" NOT IN (SELECT ip FROM answered))::INT AS bare_ip,
           (validation_status IN ('self signed certificate', 'self signed certificate in certificate chain',
                                  'certificate has expired'))::INT AS bad_cert,
           ("id.resp_p" <> 443)::INT AS odd_port
           -- + (ja4 NOT IN household_ja4_7d)::INT AS rare_ja4   -- enable once ja4 is logged
    FROM ssl
    WHERE established AND is_internal("id.orig_h") AND NOT is_internal("id.resp_h")
)
SELECT host, dst, port, any_value(server_name) AS sni, count(*) AS sessions,
       max(no_sni + bare_ip + bad_cert + odd_port) AS score,
       'tls_odd|' || host || '|' || dst AS dedupe
FROM s GROUP BY host, dst, port
HAVING max(no_sni + bare_ip + bad_cert + odd_port) >= 3
ORDER BY score DESC;
