# EVE JSON investigation queries

Set LOG to your EVE JSON file. These queries are based on the commands used in the lab.

```bash
LOG=/var/log/suricata/eve.json
sudo jq -r '.event_type' "$LOG" | sort | uniq -c | sort -nr
sudo jq -c 'select(.event_type == "http") | {timestamp,src_ip,dest_ip,dest_port,http}' "$LOG"
sudo jq -c 'select(.event_type == "dns")' "$LOG"
sudo jq -r 'select(.event_type == "dns") | .dns.type' "$LOG" | sort | uniq -c
sudo jq -c 'select(.event_type == "alert") | {timestamp,src_ip,dest_ip,dest_port,alert}' "$LOG"
sudo jq -r 'select(.event_type == "alert") | .alert.signature' "$LOG" | sort | uniq -c
sudo jq -c 'select(.event_type == "flow" and .proto == "TCP")' "$LOG" | wc -l
sudo jq -c 'select(.flow_id == 730716910331567)' "$LOG"
```

For the offline alert, filter Wireshark with `frame.number == 583` and compare the timestamp and TCP fields. Flow IDs are scoped to the relevant sensor/capture context.
