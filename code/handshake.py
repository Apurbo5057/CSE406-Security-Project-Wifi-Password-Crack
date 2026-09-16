"""
Our own parser for: pcap container -> 802.11 frames -> EAPOL-Key frames ->
grouped/paired WPA2 4-way handshake(s). No scapy, no third-party libraries —
everything below is hand-decoded from the raw bytes per the pcap, 802.11, and
802.11i (EAPOL-Key) specs.
"""
import struct
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

DLT_IEEE802_11 = 105          # linktype for plain 802.11 frames, no radiotap prefix
DLT_IEEE802_11_RADIOTAP = 127  # linktype for 802.11 frames prefixed with a Radiotap header

# --- Key Information field bit masks (802.11i, bit0 = LSB) -----------------
KI_INSTALL = 0x0040
KI_ACK = 0x0080
KI_MIC = 0x0100
KI_SECURE = 0x0200
KI_DESCRIPTOR_VERSION_MASK = 0x0007


# =============================================================================
# 1. pcap container
# =============================================================================
def iter_pcap_frames(path: Path) -> Iterator[bytes]:
    """Yield each captured 802.11 frame's raw bytes from a classic pcap file."""
    with open(path, "rb") as f:
        global_header = f.read(24)
        if len(global_header) < 24:
            raise ValueError(f"{path}: not a valid pcap file (truncated global header)")

        magic = global_header[0:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            fmt = "<"  # magic stored little-endian -> file is little-endian
        elif magic == b"\xa1\xb2\xc3\xd4":
            fmt = ">"  # magic stored big-endian -> file is big-endian
        else:
            raise ValueError(f"{path}: not a classic pcap file (bad magic {magic.hex()})")

        linktype = struct.unpack(fmt + "I", global_header[20:24])[0]
        if linktype not in (DLT_IEEE802_11, DLT_IEEE802_11_RADIOTAP):
            raise ValueError(
                f"{path}: unsupported linktype {linktype} (expected {DLT_IEEE802_11} = "
                f"DLT_IEEE802_11, or {DLT_IEEE802_11_RADIOTAP} = DLT_IEEE802_11_RADIOTAP). "
                "This parser only handles plain 802.11 frames, optionally prefixed with a "
                "Radiotap header."
            )
        has_radiotap = linktype == DLT_IEEE802_11_RADIOTAP

        while True:
            record_header = f.read(16)
            if len(record_header) < 16:
                break  # clean EOF
            _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(fmt + "IIII", record_header)
            frame = f.read(incl_len)
            if len(frame) < incl_len:
                break  # truncated capture, stop rather than yield a short frame
            if has_radiotap:
                frame = strip_radiotap(frame)
                if frame is None:
                    continue  # malformed Radiotap header on this frame, skip it
            yield frame


def strip_radiotap(frame: bytes) -> Optional[bytes]:
    """Remove a Radiotap header and return the 802.11 frame after it, or None
    if `frame` doesn't start with a well-formed Radiotap header.

    Radiotap header layout (always little-endian, regardless of pcap byte
    order): it_version(1) it_pad(1) it_len(2, LE -- total header length,
    including these 4 bytes) it_present(4+ -- a bitmask, ignored here since
    we only need to know where the header ends, not what's in it)."""
    if len(frame) < 4 or frame[0] != 0:  # it_version must be 0
        return None
    it_len = struct.unpack("<H", frame[2:4])[0]
    if it_len < 4 or it_len > len(frame):
        return None
    return frame[it_len:]


# =============================================================================
# 2. 802.11 header
# =============================================================================
def parse_80211_header(frame: bytes) -> Optional[dict]:
    """Return header info for a Data frame, or None for anything else / too short."""
    if len(frame) < 24:
        return None

    fc0, fc1 = frame[0], frame[1]
    frame_type = (fc0 >> 2) & 0b11
    subtype = (fc0 >> 4) & 0b1111
    if frame_type != 2:  # only Data frames carry EAPOL
        return None

    to_ds = bool(fc1 & 0x01)
    from_ds = bool(fc1 & 0x02)
    addr1 = frame[4:10]
    addr2 = frame[10:16]
    addr3 = frame[16:22]

    is_qos = bool(subtype & 0x08)
    has_addr4 = to_ds and from_ds
    # Note: HT Control field (+4 bytes, present when the Order bit is set on a
    # QoS frame from an 802.11n+ device) is not handled — not needed for this
    # capture's EAPOL frames, which are all non-QoS.
    header_len = 24 + (6 if has_addr4 else 0) + (2 if is_qos else 0)
    if len(frame) < header_len:
        return None

    if to_ds and not from_ds:  # STA -> AP
        ap_mac, sta_mac = addr1, addr2
    elif from_ds and not to_ds:  # AP -> STA
        ap_mac, sta_mac = addr2, addr1
    else:
        return None  # WDS or ad-hoc traffic, not a normal infrastructure BSS frame

    return {
        "to_ds": to_ds,
        "from_ds": from_ds,
        "ap_mac": ap_mac,
        "sta_mac": sta_mac,
        "header_len": header_len,
    }


# =============================================================================
# 3. LLC/SNAP + EAPOL extraction
# =============================================================================
def extract_eapol(frame: bytes, header_len: int) -> Optional[bytes]:
    """Return the exact-length raw EAPOL frame bytes, or None if not EAPOL."""
    llc = frame[header_len : header_len + 8]
    if len(llc) != 8:
        return None
    if llc[0:3] != b"\xaa\xaa\x03" or llc[6:8] != b"\x88\x8e":
        return None  # not DSAP/SSAP/Control=AA/AA/03 + ethertype EAPOL

    eapol_start = header_len + 8
    if len(frame) < eapol_start + 4:
        return None

    eapol_length = struct.unpack(">H", frame[eapol_start + 2 : eapol_start + 4])[0]
    total_len = 4 + eapol_length
    eapol = frame[eapol_start : eapol_start + total_len]
    if len(eapol) != total_len:
        return None  # truncated frame
    return eapol


# =============================================================================
# 4. EAPOL-Key field decode
# =============================================================================
def parse_eapol_key(eapol: bytes) -> Optional[dict]:
    """Decode the fixed EAPOL-Key fields. Offsets are from the `version` byte."""
    if len(eapol) < 99:
        return None
    if eapol[1] != 3:  # type: must be EAPOL-Key
        return None

    key_info = struct.unpack(">H", eapol[5:7])[0]
    key_data_length = struct.unpack(">H", eapol[97:99])[0]

    return {
        "version": eapol[0],
        "descriptor_type": eapol[4],
        "key_info": key_info,
        "key_descriptor_version": key_info & KI_DESCRIPTOR_VERSION_MASK,
        "install": bool(key_info & KI_INSTALL),
        "ack": bool(key_info & KI_ACK),
        "mic_present": bool(key_info & KI_MIC),
        "secure": bool(key_info & KI_SECURE),
        "replay_counter": int.from_bytes(eapol[9:17], "big"),
        "nonce": eapol[17:49],
        "mic": eapol[81:97],
        "key_data_length": key_data_length,
    }


def classify_message(key_info: int) -> int:
    """Return 1/2/3/4 for a canonical 4-way-handshake message, else 0."""
    ack = bool(key_info & KI_ACK)
    mic = bool(key_info & KI_MIC)
    secure = bool(key_info & KI_SECURE)
    install = bool(key_info & KI_INSTALL)
    if ack and not mic:
        return 1
    if mic and not ack and not secure:
        return 2
    if ack and mic and secure and install:
        return 3
    if mic and secure and not ack and not install:
        return 4
    return 0


def zero_mic(eapol: bytes) -> bytes:
    """Return a copy of the EAPOL frame with the 16-byte Key MIC field zeroed."""
    return eapol[:81] + (b"\x00" * 16) + eapol[97:]


# =============================================================================
# 5. Handshake grouping / selection
# =============================================================================
@dataclass
class Handshake:
    ap_mac: bytes
    sta_mac: bytes
    anonce: bytes
    snonce: bytes
    mic: bytes
    eapol_frame_mic_zeroed: bytes
    key_descriptor_version: int
    replay_counter: int
    is_complete_4way: bool


def extract_handshakes(cap_path: Path, target_bssid: bytes) -> list:
    """
    Parse cap_path and return every crackable Handshake candidate for
    target_bssid, most likely first.

    Frames belonging to other BSSIDs are dropped before any further processing.

    A real AP under load can retransmit Msg1 with a FRESH ANonce each time
    instead of resending the original bytes (observed directly in
    capture-01.cap), and the sniffer can miss the one Msg1 a station actually
    used. Since Msg3 carries the same ANonce as the Msg1 it confirms, it's a
    second source of candidate ANonces — sometimes the only one a lossy
    capture still has. Rather than guess which single ANonce is "the" right
    one (that can't be known until a password is actually tried), every
    ANonce ever sent to a station (from its Msg1s and Msg3s) is paired with
    every one of that station's Msg2 responses, and the caller (crack.py)
    tests a candidate password against *all* resulting Handshake objects.
    """
    anonce_candidates: dict = defaultdict(set)  # sta_mac -> {anonce, ...}
    msg2_records = []
    seen_msg2 = set()  # (sta_mac, snonce, mic) - dedupe retransmitted Msg2s
    msg4_seen = set()  # (sta_mac, replay_counter) - for the is_complete_4way hint

    for frame in iter_pcap_frames(cap_path):
        hdr = parse_80211_header(frame)
        if hdr is None or hdr["ap_mac"] != target_bssid:
            continue

        eapol = extract_eapol(frame, hdr["header_len"])
        if eapol is None:
            continue

        parsed = parse_eapol_key(eapol)
        if parsed is None:
            continue

        msg_type = classify_message(parsed["key_info"])
        if msg_type in (1, 3):  # both carry ANonce
            anonce_candidates[hdr["sta_mac"]].add(parsed["nonce"])
        elif msg_type == 2:
            key = (hdr["sta_mac"], parsed["nonce"], parsed["mic"])
            if key in seen_msg2:
                continue
            seen_msg2.add(key)
            msg2_records.append(
                {
                    "ap_mac": hdr["ap_mac"],
                    "sta_mac": hdr["sta_mac"],
                    "snonce": parsed["nonce"],
                    "mic": parsed["mic"],
                    "eapol_frame_mic_zeroed": zero_mic(eapol),
                    "key_descriptor_version": parsed["key_descriptor_version"],
                    "replay_counter": parsed["replay_counter"],
                }
            )
        elif msg_type == 4:
            msg4_seen.add((hdr["sta_mac"], parsed["replay_counter"]))

    handshakes = []
    for m2 in msg2_records:
        candidates = anonce_candidates.get(m2["sta_mac"], set())
        # Msg1+Msg2 share one replay counter; a successful exchange continues
        # with Msg3+Msg4 carrying the NEXT counter value, not the same one.
        confirmed = (m2["sta_mac"], m2["replay_counter"] + 1) in msg4_seen
        for anonce in candidates:
            handshakes.append(
                Handshake(
                    ap_mac=m2["ap_mac"],
                    sta_mac=m2["sta_mac"],
                    anonce=anonce,
                    snonce=m2["snonce"],
                    mic=m2["mic"],
                    eapol_frame_mic_zeroed=m2["eapol_frame_mic_zeroed"],
                    key_descriptor_version=m2["key_descriptor_version"],
                    replay_counter=m2["replay_counter"],
                    is_complete_4way=confirmed,
                )
            )

    handshakes.sort(key=lambda h: not h.is_complete_4way)
    return handshakes


# =============================================================================
# 6. Small helpers
# =============================================================================
def mac_str_to_bytes(mac: str) -> bytes:
    return bytes(int(b, 16) for b in mac.split(":"))


def mac_bytes_to_str(mac: bytes) -> str:
    return mac.hex(":")
