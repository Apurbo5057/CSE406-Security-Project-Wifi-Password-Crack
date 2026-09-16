#!/usr/bin/env python3
"""
Test suite for the WPA2 handshake parser and cracker. Runs against the real
capture-01.cap referenced in config.py. Stdlib unittest only.

    python3 test_crack.py -v
"""
import struct
import tempfile
import unittest
from pathlib import Path

import config
import crack
import handshake


class TestHandshakeParsing(unittest.TestCase):
    """General parsing smoke tests against whatever capture is currently
    configured as CAPTURE_FILE -- this can be the plain-802.11 (linktype 105)
    capture-01.cap provided with the assignment, or a fresh linktype-127
    Radiotap capture made with capture.py; both must parse without error."""

    @classmethod
    def setUpClass(cls):
        cls.bssid = handshake.mac_str_to_bytes(config.BSSID)
        cls.handshakes = handshake.extract_handshakes(config.CAPTURE_FILE, cls.bssid)

    def test_pcap_parses_without_exception(self):
        self.assertIsInstance(self.handshakes, list)

    def test_handshake_found(self):
        self.assertGreater(
            len(self.handshakes), 0, f"no crackable handshake extracted from {config.CAPTURE_FILE}"
        )

    def test_field_lengths(self):
        hs = self.handshakes[0]
        self.assertEqual(len(hs.ap_mac), 6)
        self.assertEqual(len(hs.sta_mac), 6)
        self.assertEqual(len(hs.anonce), 32)
        self.assertEqual(len(hs.snonce), 32)
        self.assertEqual(len(hs.mic), 16)
        self.assertIn(hs.key_descriptor_version, (1, 2, 3))
        self.assertGreaterEqual(len(hs.eapol_frame_mic_zeroed), 99)

    def test_bssid_matches_config(self):
        self.assertEqual(self.handshakes[0].ap_mac, self.bssid)

    def test_classify_message(self):
        self.assertEqual(handshake.classify_message(0x0080), 1)  # ack, no mic
        self.assertEqual(handshake.classify_message(0x0100), 2)  # mic, no ack/secure
        self.assertEqual(handshake.classify_message(0x03c0), 3)  # ack+mic+secure+install
        self.assertEqual(handshake.classify_message(0x0300), 4)  # mic+secure, no ack/install
        self.assertEqual(handshake.classify_message(0x0000), 0)  # none of the above


class TestRadiotapParsing(unittest.TestCase):
    """capture.py (live scapy sniffing) writes linktype 127 (Radiotap-wrapped
    802.11), while airodump-ng-produced captures like the original
    capture-01.cap use linktype 105 (plain 802.11, no Radiotap). Both must
    yield identical 802.11 frame bytes once unwrapped."""

    def test_strip_radiotap_basic(self):
        radiotap_header = bytes([0, 0]) + (8).to_bytes(2, "little") + b"\x00" * 4  # it_len=8
        frame_body = b"\xaa" * 20
        self.assertEqual(handshake.strip_radiotap(radiotap_header + frame_body), frame_body)

    def test_strip_radiotap_rejects_bad_version(self):
        bad = bytes([1, 0]) + (8).to_bytes(2, "little") + b"\x00" * 4
        self.assertIsNone(handshake.strip_radiotap(bad))

    def test_strip_radiotap_rejects_length_beyond_frame(self):
        bad = bytes([0, 0]) + (999).to_bytes(2, "little") + b"\x00" * 4
        self.assertIsNone(handshake.strip_radiotap(bad))

    def test_iter_pcap_frames_handles_radiotap_linktype(self):
        radiotap = bytes([0, 0]) + (8).to_bytes(2, "little") + b"\x00" * 4  # it_len=8
        fake_80211_frame = b"\x08\x02" + b"\x00" * 22
        record_data = radiotap + fake_80211_frame
        global_header = struct.pack(
            "<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, handshake.DLT_IEEE802_11_RADIOTAP
        )
        record_header = struct.pack("<IIII", 0, 0, len(record_data), len(record_data))

        with tempfile.NamedTemporaryFile(suffix=".cap", delete=False) as f:
            f.write(global_header + record_header + record_data)
            tmp_path = Path(f.name)
        try:
            frames = list(handshake.iter_pcap_frames(tmp_path))
            self.assertEqual(frames, [fake_80211_frame])
        finally:
            tmp_path.unlink()


class TestCrypto(unittest.TestCase):
    def test_pmk_length_type_determinism(self):
        pmk1 = crack.derive_pmk("some_password", "some_ssid")
        pmk2 = crack.derive_pmk("some_password", "some_ssid")
        self.assertEqual(pmk1, pmk2)
        self.assertIsInstance(pmk1, bytes)
        self.assertEqual(len(pmk1), 32)

    def test_ptk_is_64_bytes(self):
        pmk = b"\x11" * 32
        ptk = crack.derive_ptk(pmk, b"\x01" * 6, b"\x02" * 6, b"\xaa" * 32, b"\xbb" * 32)
        self.assertEqual(len(ptk), 64)

    def test_mic_always_16_bytes(self):
        kck = b"\x00" * 16
        frame = b"\x01\x03\x00\x5f" + b"\x00" * 95
        self.assertEqual(len(crack.compute_mic(kck, frame, 1)), 16)
        self.assertEqual(len(crack.compute_mic(kck, frame, 2)), 16)

    def test_unsupported_descriptor_version_raises(self):
        with self.assertRaises(ValueError):
            crack.compute_mic(b"\x00" * 16, b"\x00" * 99, 3)


class TestAgainstKnownGoodCapture(unittest.TestCase):
    """Regression tests pinned to a specific saved capture (not whatever
    config.CAPTURE_FILE currently points at, which changes every time someone
    runs capture.py) so they can't silently stop testing anything useful just
    because a fresh capture replaced capture-01.cap. Skipped if that backup
    isn't present (e.g. a friend's checkout that never had it)."""

    KNOWN_GOOD_CAPTURE = config.BASE_DIR / "capture-01.cap.original-backup"

    @classmethod
    def setUpClass(cls):
        if not cls.KNOWN_GOOD_CAPTURE.exists():
            raise unittest.SkipTest(f"{cls.KNOWN_GOOD_CAPTURE} not present")
        cls.bssid = handshake.mac_str_to_bytes(config.BSSID)
        cls.handshakes = handshake.extract_handshakes(cls.KNOWN_GOOD_CAPTURE, cls.bssid)

    def test_best_handshake_is_complete_4way(self):
        # This specific capture's replay_counter=2 group has all 4 messages.
        self.assertTrue(self.handshakes[0].is_complete_4way)

    def test_wrong_password_is_rejected(self):
        self.assertFalse(
            crack.test_password(self.handshakes, config.SSID, "definitely-wrong-password-xyz")
        )

    def test_known_correct_password_is_accepted(self):
        # Cross-checked against aircrack-ng on this exact capture+wordlist
        # (`aircrack-ng -w testlist.txt -b <BSSID> capture-01.cap` -> KEY FOUND!
        # [ 27111998 ]) — this is a real regression test: it only passes if
        # extract_handshakes() considers every ANonce a station's Msg1s *and*
        # Msg3s carried, since the Msg1 that this particular password's
        # handshake actually used was never captured (only its Msg3 was).
        self.assertTrue(crack.test_password(self.handshakes, config.SSID, "27111998"))

    def test_wordlist_mode_completes_without_exception(self):
        result = crack.test_wordlist(
            self.handshakes, config.SSID, config.WORDLIST_FILE, progress=False
        )
        self.assertTrue(result is None or isinstance(result, str))


if __name__ == "__main__":
    unittest.main(verbosity=2)
