#!/usr/bin/env python3
"""Parse an airodump-ng CSV and show, for every 'Alexander the Great' mesh node,
its channel and which client STATIONs are associated to it. No sudo needed.
    python3 find_client.py /tmp/scan-01.csv
"""
import sys
TARGET_ESSID = "Alexander the Great"
path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/scan-01.csv"
lines = open(path, encoding="utf-8", errors="ignore").read().splitlines()

aps = {}            # bssid -> (channel, essid)
mode = "ap"
clients = []        # (station, bssid, power, packets)
for line in lines:
    if line.startswith("Station MAC"):
        mode = "sta"; continue
    if line.startswith("BSSID") or not line.strip():
        continue
    c = [x.strip() for x in line.split(",")]
    if mode == "ap" and len(c) >= 14:
        aps[c[0]] = (c[3], c[13])
    elif mode == "sta" and len(c) >= 6:
        clients.append((c[0], c[5], c[3], c[4]))

alex = {b: (ch, e) for b, (ch, e) in aps.items() if e == TARGET_ESSID}
print(f"\n=== '{TARGET_ESSID}' nodes seen ===")
for b, (ch, e) in sorted(alex.items()):
    print(f"  node {b}  channel {ch}")

print("\n=== clients attached to a node (this is what you want) ===")
found = False
for sta, bssid, pwr, pkts in clients:
    if bssid in alex:
        ch = alex[bssid][0]
        print(f"  CLIENT {sta}  ->  node {bssid}  CHANNEL {ch}  pwr {pwr}  pkts {pkts}")
        found = True
if not found:
    print("  (none yet — generate traffic on the phone and re-scan; "
          "if the AP shows but never a client, it's the card's uplink-capture issue)")
