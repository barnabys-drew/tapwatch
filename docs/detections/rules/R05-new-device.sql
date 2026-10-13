-- R05 New device joins (keyed on MAC from DHCP; extend with UDM Wi-Fi connect events)
-- Route: DIGEST; ALERT if wired, 01:00-06:00, or Q-role in (computer, unknown) with a global (non-random) MAC.
-- Jev: Q-role (seeds assets.yaml), Q-human, Q-wake. Hostname is untrusted data.
.read docs/detections/rules/_common.sql
SET VARIABLE learn_until = (SELECT min(ts) FROM dhcp) + 7 * 86400;

WITH firsts AS (
    SELECT mac, min(ts) AS first_ts, any_value(host_name) AS host_name, any_value(assigned_addr) AS ip
    FROM dhcp WHERE mac IS NOT NULL GROUP BY mac
)
SELECT mac, first_ts, host_name, ip,
       -- locally administered bit (2nd hex digit in {2,6,a,e}) = randomized/private MAC
       substr(mac, 2, 1) IN ('2', '6', 'a', 'e') AS randomized_mac,
       upper(replace(substr(mac, 1, 8), ':', '')) AS oui,   -- join to the OUI vendor table in tapwatch
       hour(to_timestamp(first_ts)) BETWEEN 1 AND 5 AS night,
       'new_device|' || mac AS dedupe
FROM firsts
WHERE first_ts > getvariable('learn_until')
  AND mac NOT IN (SELECT mac FROM assets WHERE mac IS NOT NULL);
-- tapwatch then waits 10 min and attaches: services contacted, user-agent families, SSID/wired (UDM syslog).
