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

# mobile hotspot
SSID = "Redmi Note 11"
BSSID = "36:94:5e:43:f9:4d"
CHANNEL = 11
# FREQUENCY = 2.4 

#5c:62:8b:ba:fc:87
#3c:52:a1:c5:2a:85
# SSID = "Alexander the Great"
# BSSID = "5c:62:8b:ba:fc:87"
# CHANNEL = 153


CLIENT_MAC = ""
MONITOR_INTERFACE = "wlan0mon"
CAPTURE_FILE = "capture-01.cap"
WORDLIST_FILE = "testlist.txt"



#76:FE:CE:2E:ED:5E  --> 5



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
