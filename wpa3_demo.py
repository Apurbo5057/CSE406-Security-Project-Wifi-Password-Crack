#!/usr/bin/env python3
"""
wpa3_demo.py  --  CSE 406 Project (Topic 20), DEFENSE demonstration

Standalone companion to crack.py. It exists to answer one question rigorously:

    "Our offline dictionary attack (capture.py + crack.py) recovers a
     WPA2-PSK password. Does WPA3-Personal (SAE) actually stop it, or did
     crack.py just fail because it doesn't implement the newer MIC?"

crack.py raises `key_descriptor_version=0 (AES-128-CMAC / WPA3-style) is not
implemented` on a WPA3 handshake. That alone is a weak claim -- a reviewer can
say "you just didn't code CMAC". So this script deliberately CLOSES that gap:

    * It IMPLEMENTS the AES-128-CMAC MIC that WPA3-SAE uses (via the
      `cryptography` library, already pulled in by scapy), so "not implemented"
      is no longer the reason anything fails.
    * It then runs the EXACT same WPA2-PSK offline attack as crack.py --
      PMK = PBKDF2-HMAC-SHA1(passphrase, ssid), PTK via PRF-512, KCK, MIC --
      reusing crack.py's own derive_pmk / derive_ptk / derive_kck functions.

The result on a WPA3-SAE capture: NO password matches -- not even the CORRECT
one. That is the real proof. In WPA3-SAE the PMK is NOT PBKDF2(passphrase);
it is the output of the SAE (Dragonfly) elliptic-curve exchange, which can
only be produced by a live handshake WITH the AP (one online attempt per
guess, rate-limited by anti-clogging tokens + mandatory PMF). There is no
offline function from passphrase -> captured MIC, so the dictionary attack has
no valid target. Implementing CMAC does not help; the vulnerability is gone at
the root.

Nothing in this file modifies capture.py, crack.py, handshake.py, or config.py.

Usage (mirrors crack.py; same config.py defaults for capture/ssid/bssid):
    python3 wpa3_demo.py info
    python3 wpa3_demo.py single "<the real password>"   # the key demo: still NO MATCH on SAE
    python3 wpa3_demo.py wordlist [--wordlist PATH]
"""
import argparse
import sys
from pathlib import Path

import config
from handshake import extract_handshakes, mac_bytes_to_str, mac_str_to_bytes

# Reuse crack.py's WPA2-PSK derivation verbatim -- we are proving that this
# exact, correct WPA2 attack chain does not transfer to SAE, so we must use
# the identical functions rather than a re-implementation.
from crack import derive_pmk, derive_ptk, derive_kck

try:
    from cryptography.hazmat.primitives import cmac
    from cryptography.hazmat.primitives.ciphers import algorithms
    _HAVE_CMAC = True
except Exception:  # pragma: no cover - cryptography ships with scapy here
    _HAVE_CMAC = False


# =============================================================================
# The piece crack.py leaves out: the AES-128-CMAC MIC (WPA3 / SHA256 AKMs)
# =============================================================================
def compute_mic(kck: bytes, eapol_frame_mic_zeroed: bytes, key_descriptor_version: int) -> bytes:
    """Like crack.py's compute_mic, but ALSO handles the AES-128-CMAC case
    (key descriptor version 0 or 3) that WPA3-SAE / PMF negotiate. Always
    returns the 16-byte MIC that would sit in the Key MIC field."""
    import hashlib
    import hmac

    if key_descriptor_version == 1:            # WPA / TKIP  (HMAC-MD5)
        return hmac.new(kck, eapol_frame_mic_zeroed, hashlib.md5).digest()
    if key_descriptor_version == 2:            # WPA2 / CCMP (HMAC-SHA1-128)
        return hmac.new(kck, eapol_frame_mic_zeroed, hashlib.sha1).digest()[:16]
    if key_descriptor_version in (0, 3):       # WPA3-SAE / PMF (AES-128-CMAC)
        if not _HAVE_CMAC:
            raise RuntimeError(
                "AES-128-CMAC needs the 'cryptography' package (normally installed "
                "with scapy). Install it: pip install cryptography"
            )
        c = cmac.CMAC(algorithms.AES(kck))     # KCK is the 128-bit CMAC key
        c.update(eapol_frame_mic_zeroed)
        return c.finalize()[:16]
    raise ValueError(f"unexpected key_descriptor_version={key_descriptor_version}")


def wpa2_attack_matches(handshake, ssid: str, password: str) -> bool:
    """The WPA2-PSK offline test, now with a working MIC for every version.
    Returns True iff this password reproduces the captured MIC via the
    WPA2 derivation chain."""
    pmk = derive_pmk(password, ssid)  # <-- PBKDF2(passphrase): correct for PSK, WRONG for SAE
    ptk = derive_ptk(pmk, handshake.ap_mac, handshake.sta_mac, handshake.anonce, handshake.snonce)
    kck = derive_kck(ptk)
    mic = compute_mic(kck, handshake.eapol_frame_mic_zeroed, handshake.key_descriptor_version)
    return mic == handshake.mic


# =============================================================================
# Reporting helpers
# =============================================================================
_SAE_VERSIONS = (0, 3)


def _mode_label(version: int) -> str:
    return {
        1: "WPA/TKIP (HMAC-MD5 MIC)",
        2: "WPA2-PSK (HMAC-SHA1 MIC) -- crackable by crack.py",
        0: "WPA3-SAE / PMF (AES-128-CMAC MIC) -- PMK is NOT PBKDF2(passphrase)",
        3: "SHA256 AKM / PMF (AES-128-CMAC MIC)",
    }.get(version, f"unknown (version {version})")


def _resolve(args):
    capture_file = Path(args.capture) if args.capture else config.CAPTURE_FILE
    bssid = mac_str_to_bytes(args.bssid if args.bssid else config.BSSID)
    handshakes = extract_handshakes(capture_file, bssid)
    if not handshakes:
        print(f"[-] No handshake found for BSSID {mac_bytes_to_str(bssid)} in {capture_file}")
        sys.exit(2)
    return capture_file, handshakes


def _explain_sae():
    print()
    print("    Why even the CORRECT password fails here:")
    print("      * WPA2-PSK: PMK = PBKDF2-HMAC-SHA1(passphrase, ssid). The passphrase")
    print("        fully determines the MIC, so it can be guessed OFFLINE from a capture.")
    print("      * WPA3-SAE: the PMK is the output of the SAE (Dragonfly) exchange, not")
    print("        of the passphrase. Reproducing it needs a LIVE handshake with the AP")
    print("        (one online, rate-limited attempt per guess; PMF blocks deauth too).")
    print("      * So no offline function maps passphrase -> captured MIC. Implementing")
    print("        AES-128-CMAC (done above) removes the 'not implemented' excuse and the")
    print("        attack STILL fails -- the vulnerability is gone at the root.")


# =============================================================================
# Commands
# =============================================================================
def cmd_info(args) -> int:
    capture_file, handshakes = _resolve(args)
    hs = handshakes[0]
    ssid = args.ssid or config.SSID
    print(f"[+] Capture file        : {capture_file}")
    print(f"[+] SSID (PBKDF2 salt)  : {ssid}")
    print(f"[+] BSSID / AP MAC      : {mac_bytes_to_str(hs.ap_mac)}")
    print(f"[+] Client / STA MAC    : {mac_bytes_to_str(hs.sta_mac)}")
    print(f"[+] Key descriptor ver  : {hs.key_descriptor_version}  ->  {_mode_label(hs.key_descriptor_version)}")
    print(f"[+] Captured MIC        : {hs.mic.hex()}")
    print(f"[+] AES-128-CMAC ready  : {_HAVE_CMAC}")
    if hs.key_descriptor_version in _SAE_VERSIONS:
        print("[!] This is a WPA3-SAE-style handshake: the offline dictionary attack cannot succeed.")
        _explain_sae()
    elif hs.key_descriptor_version == 2:
        print("[*] This is a WPA2-PSK handshake: the offline dictionary attack (crack.py) applies.")
    return 0


def cmd_single(args) -> int:
    _, handshakes = _resolve(args)
    ssid = args.ssid or config.SSID
    version = handshakes[0].key_descriptor_version
    print(f"[*] Handshake type      : version {version} -> {_mode_label(version)}")
    print(f"[*] Trying password {args.password!r} with the WPA2-PSK attack (CMAC MIC implemented)...")

    matched = any(wpa2_attack_matches(hs, ssid, args.password) for hs in handshakes)
    if matched:
        print(f"[+] MATCH   -> password is: {args.password}")
        if version == 2:
            print("    (Expected: WPA2-PSK is vulnerable to this offline attack.)")
        return 0

    print(f"[-] NO MATCH -> {args.password!r} does not reproduce the captured MIC")
    if version in _SAE_VERSIONS:
        print("    >>> DEFENSE CONFIRMED: this was run with the AES-128-CMAC MIC fully")
        print("    >>> implemented, and even the correct password fails to match.")
        _explain_sae()
    return 1


def cmd_wordlist(args) -> int:
    _, handshakes = _resolve(args)
    ssid = args.ssid or config.SSID
    wordlist_path = Path(args.wordlist) if args.wordlist else config.WORDLIST_FILE
    if not wordlist_path.exists():
        print(f"[-] Wordlist not found: {wordlist_path}")
        sys.exit(2)
    version = handshakes[0].key_descriptor_version
    print(f"[*] Handshake type      : version {version} -> {_mode_label(version)}")
    print(f"[*] Running WPA2-PSK attack (CMAC MIC implemented) over {wordlist_path}")

    tried = 0
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            pw = line.rstrip("\r\n")
            if not (config.MIN_PASSWORD_LEN <= len(pw) <= config.MAX_PASSWORD_LEN):
                continue
            tried += 1
            if any(wpa2_attack_matches(hs, ssid, pw) for hs in handshakes):
                print(f"\n[+] KEY FOUND! -> {pw}   (after {tried} candidates)")
                return 0
    print(f"\n[-] No match in {tried} candidates.")
    if version in _SAE_VERSIONS:
        print("    >>> DEFENSE CONFIRMED: the whole wordlist fails against WPA3-SAE,")
        print("    >>> with the CMAC MIC implemented -- the offline attack has no target.")
        _explain_sae()
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wpa3_demo.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="mode", required=True)

    def add_common(p):
        p.add_argument("--capture", help=f"capture file (default: {config.CAPTURE_FILE})")
        p.add_argument("--ssid", help=f"network SSID / PBKDF2 salt (default: {config.SSID})")
        p.add_argument("--bssid", help=f"target AP BSSID (default: {config.BSSID})")

    p_info = sub.add_parser("info", help="classify the captured handshake (WPA2 vs WPA3-SAE)")
    add_common(p_info)
    p_info.set_defaults(func=cmd_info)

    p_single = sub.add_parser("single", help="attack one password (shows NO MATCH on SAE)")
    p_single.add_argument("password")
    add_common(p_single)
    p_single.set_defaults(func=cmd_single)

    p_word = sub.add_parser("wordlist", help="attack a whole wordlist (0 matches on SAE)")
    p_word.add_argument("--wordlist", help=f"wordlist file (default: {config.WORDLIST_FILE})")
    add_common(p_word)
    p_word.set_defaults(func=cmd_wordlist)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
