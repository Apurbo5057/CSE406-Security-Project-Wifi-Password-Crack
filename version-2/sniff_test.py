#!/usr/bin/env python3
from scapy.all import sniff, Dot11, Dot11Beacon, EAPOL

counts = {"total_dot11": 0, "redmi_beacons": 0, "eapol": 0}

def show(pkt):
    if not pkt.haslayer(Dot11):
        return
    counts["total_dot11"] += 1
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt.info.decode(errors="ignore") if pkt.info else ""
        if ssid == "Redmi Note 11":
            counts["redmi_beacons"] += 1
    if pkt.haslayer(EAPOL):
        counts["eapol"] += 1
        print(">>> EAPOL seen!", pkt.summary())

print("[*] Listening for 15 seconds...")
sniff(iface="mon0", prn=show, timeout=15)
print(counts)
