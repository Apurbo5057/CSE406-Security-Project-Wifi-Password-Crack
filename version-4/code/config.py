"""
Single source of truth for every changeable/user-specific setting used by this tool.
Nothing else in code/ should hardcode a path, SSID, BSSID, or filename — edit only here.
"""
from pathlib import Path

# --- Wireless target -------------------------------------------------------
# Used by capture.py (INTERFACE, BSSID) and deauth.py (INTERFACE, BSSID,
# CLIENT_MAC). CHANNEL isn't read by any script directly — it's just what you
# pass to `iw ... set channel` when putting the NIC in monitor mode — but it's
# kept here too so every setting for the pipeline lives in one file.
INTERFACE = "wlan0"
MONITOR_INTERFACE = "wlan0mon"
SSID = "Redmi Note 11"
BSSID = "B6:1E:02:85:2A:AE"
CHANNEL = 2
CLIENT_MAC = "56:71:42:3C:65:F4"    # deauth.py: leave empty to broadcast-deauth ALL clients; set one MAC to target just that device

# --- File locations ---------------------------------------------------------
# code/ lives one directory below the repo root, which is where capture-01.cap
# and testlist.txt actually are. Resolving relative to this file (not the
# caller's cwd) means the tool works no matter where it's invoked from.
BASE_DIR = Path(__file__).resolve().parent.parent
CAPTURE_FILE = BASE_DIR / "capture-01.cap"
WORDLIST_FILE = BASE_DIR / "testlist.txt"

# --- Cracking tunables -------------------------------------------------------
WORDLIST_CHUNK_SIZE = 2000   # passwords handed to a worker process at a time
MIN_PASSWORD_LEN = 8         # WPA2-PSK spec minimum
MAX_PASSWORD_LEN = 63        # WPA2-PSK spec maximum
