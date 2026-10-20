# Zeek for tapwatch: the upstream LTS image with its Debian packages brought up to date.
#
# Upstream publishes each Zeek release once and does not rebuild it when Debian ships fixes, so the image ages:
# on 2026-10-20 zeek/zeek:7.0.0 carried 30 critical and 312 high CVEs (trivy), 35 of its packages with a
# fix available, and the newest 8.0.10 and 8.2.2 images 21 / 224. Zeek parses hostile network traffic all day,
# so its libraries matter. Rebuild with `docker build --pull --no-cache` to pick up later fixes.
#
# 9.0 is the current LTS line (the `lts` tag). Measured 2026-10-20 against 7.0.0 on the eval capture and Zeek's own
# DHCP/FTP/HTTP/TLS test traces: the same records in conn, dns, ssl, http, dhcp and ftp, every shared field equal
# (only the random uids differ), and only new fields added (conn `ip_proto`, dns `opcode`/`opcode_name`).
FROM zeek/zeek:9.0.0
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade \
 && apt-get clean && rm -rf /var/lib/apt/lists/*
