# tapwatch site policy, shared by every capture path (live, Windows mirror, pcap replay).
@load local
# Source and destination MACs in conn.log: device identity survives DHCP changes (rule R05).
@load policy/protocols/conn/mac-logging

redef LogAscii::use_json = T;
