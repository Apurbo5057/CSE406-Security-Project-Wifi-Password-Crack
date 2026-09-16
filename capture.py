#!/usr/bin/env python3
"""
capture.py  --  CSE 406 Project (Topic 20)

Replaces airodump-ng: sniff 802.11, detect the WPA2 4-way handshake, save it.

EAPOL detection walks the raw 802.11 bytes exactly like aircrack-ng
(aircrack-ng.c ~L1480): compute the 802.11 header length (24, +6 for a
4-address WDS frame, +2 for QoS-Data), skip LLC/SNAP, check EtherType 0x888E.
This does NOT rely on scapy dissecting an EAPOL layer -- which it fails to do
on QoS-Data / FCS-tailed frames, the reason a naive haslayer(EAPOL) capture
sees zero handshake frames even while thousands of frames flow.

Usage:
    sudo python3 capture.py <iface> <AP_BSSID> [outfile.cap]
    sudo python3 capture.py wlan0mon 5C:62:8B:BA:FD:3E my_capture.cap
"""

import sys, time
from scapy.all import sniff, wrpcap, Dot11, Dot11Beacon

IFACE = AP_MAC = OUTFILE = None
collected, kept, msg1_rc, msg2_rc, clients = [], [], {}, {}, set()
total = 0; heard_beacon = False; last_status = 0.0
ANY = False


def eapol_from_dot11(h):
    """Return the EAPOL-Key bytes (truncated like aircrack) or None."""
    if len(h) < 24:
        return None
    fc0, fc1 = h[0], h[1]
    if (fc0 & 0x0C) != 0x08:                     # must be a Data frame
        return None
    z = 30 if (fc1 & 0x03) == 0x03 else 24       # 4-address WDS -> 30
    if fc0 & 0x80:                               # QoS Data -> header +2
        z += 2
        if fc1 & 0x80:                           # Order bit -> +4 HT Control
            z += 4
    if h[z:z + 6] != b"\xaa\xaa\x03\x00\x00\x00":   # LLC/SNAP
        return None
    if h[z + 6:z + 8] != b"\x88\x8e":            # EtherType == EAPOL
        return None
    eapol = h[z + 8:]
    if len(eapol) < 4:
        return None
    size = ((eapol[2] << 8) | eapol[3]) + 4      # EAPOL body len + 4-byte hdr
    if not (0 < size <= len(eapol)):
        return None
    return eapol[:size]


def classify(e):
    ki = (e[5] << 8) | e[6]
    rc = e[9:17]
    ack, mic, secure = ki & 0x0080, ki & 0x0100, ki & 0x0200
    if ack and not mic:                return 1, rc
    if mic and not ack and not secure: return 2, rc
    if mic and ack:                    return 3, rc
    if mic and secure and not ack:     return 4, rc
    return 0, rc


def is_mcast(mac):
    try:    return bool(int(mac.split(":")[0], 16) & 0x01)
    except: return True

def same_oui(mac):
    return mac.lower()[:8] == AP_MAC.lower()[:8]


def note_client(pkt):
    ap = AP_MAC.lower()
    for a, b in ((pkt.addr1, pkt.addr2), (pkt.addr2, pkt.addr3)):
        if a and b and ap in (str(a).lower(), str(b).lower()):
            other = str(b).lower() if str(a).lower() == ap else str(a).lower()
            if not other or other == ap or is_mcast(other) or same_oui(other):
                continue
            if other not in clients:
                clients.add(other)
                print(f"[client] {other}  <-- real station (deauth THIS)")


def process(pkt):
    global total, heard_beacon, last_status
    total += 1
    now = time.time()
    if now - last_status > 5:
        last_status = now
        print(f"    ... {total} frames | beacon:{'YES' if heard_beacon else 'no'} "
              f"| clients:{len(clients)} | msg1:{len(msg1_rc)} msg2:{len(msg2_rc)}")

    if not pkt.haslayer(Dot11):
        return
    if pkt.haslayer(Dot11Beacon) and str(pkt.addr3).lower() == AP_MAC.lower() \
            and not heard_beacon:
        heard_beacon = True
        print(f"[ok] hearing beacons from {AP_MAC} -- channel & range good")

    if ANY or AP_MAC.lower() in (str(pkt.addr1).lower(), str(pkt.addr2).lower(),
                                 str(pkt.addr3).lower()):
        if not ANY:
            note_client(pkt)

    # buffer AP-related frames (skip beacons) for Wireshark inspection
    if not pkt.haslayer(Dot11Beacon) and len(kept) < 300000:
        if ANY or AP_MAC.lower() in (str(pkt.addr1).lower(),
                str(pkt.addr2).lower(), str(pkt.addr3).lower()):
            kept.append(pkt)

    # --- aircrack-style EAPOL extraction from raw MAC bytes ---
    h = bytes(pkt[Dot11])
    e = eapol_from_dot11(h)
    if e is None:
        return
    if not ANY and AP_MAC.lower() not in (str(pkt.addr1).lower(),
                              str(pkt.addr2).lower(), str(pkt.addr3).lower()):
        return

    msg, rc = classify(e)
    if not msg:
        return
    collected.append(pkt)
    if msg == 1: msg1_rc[rc] = True
    elif msg == 2: msg2_rc[rc] = True
    tag = "  <-- note the AP here!" if ANY else ""
    print(f"[+] EAPOL msg{msg}  rc={rc.hex()}  a1={pkt.addr1} a2={pkt.addr2}{tag}")

    paired = set(msg1_rc) & set(msg2_rc)
    if paired and not ANY:
        print(f"[+] Matched msg1+msg2 (rc={next(iter(paired)).hex()}). Saving.")
        wrpcap(OUTFILE, collected)
        print(f"[+] Wrote {len(collected)} frames to {OUTFILE}")
        sys.exit(0)


def main():
    global IFACE, AP_MAC, OUTFILE
    if not (3 <= len(sys.argv) <= 4):
        sys.exit(f"usage: sudo python3 {sys.argv[0]} <iface> <AP_BSSID> [outfile.cap]")
    IFACE, AP_MAC = sys.argv[1], sys.argv[2]
    global ANY
    ANY = (AP_MAC.lower() == "any")
    OUTFILE = sys.argv[3] if len(sys.argv) == 4 else "my_capture.cap"
    print(f"[*] Sniffing on {IFACE} for a handshake with {AP_MAC}")
    print("[*] Keep this running; deauth a [client] MAC from a SECOND terminal.")
    try:
        sniff(iface=IFACE, prn=process, store=False)
    except KeyboardInterrupt:
        if collected:
            wrpcap(OUTFILE, collected)
            print(f"\n[+] Wrote {len(collected)} EAPOL frames to {OUTFILE}")
        elif kept:
            wrpcap(OUTFILE, kept)
            print(f"\n[!] No EAPOL detected. Wrote {len(kept)} other AP frames "
                  f"to {OUTFILE} so you can inspect in Wireshark.")
            print("    In Wireshark, apply display filter:  eapol")
            print("    - if EAPOL frames ARE there, the parser missed them (tell me)")
            print("    - if there are NONE, no handshake reached this channel/BSSID")
        else:
            print("\n[!] Captured nothing at all -- interface/channel problem.")


if __name__ == "__main__":
    main()
