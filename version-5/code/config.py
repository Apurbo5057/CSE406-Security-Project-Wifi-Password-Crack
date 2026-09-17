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

SSID = "Rezan"
BSSID ="6c:4c:bc:4f:94:2a"
CHANNEL = 4


# mobile hotspot
# SSID = "Apurbo phone"
# BSSID = "0a:6c:09:34:56:8b"
# CHANNEL = 11
# FREQUENCY = 2.4 

#5c:62:8b:ba:fc:87
#3c:52:a1:c5:2a:85
#5c:62:8b:ba:fd:3f
#76:fe:ce:2e:ed:5e
# SSID = "Alexander the Great"
# BSSID = "76:fe:ce:2e:ed:5e"
# CHANNEL = 2


CLIENT_MAC = ""
MONITOR_INTERFACE = "wlan0mon"
CAPTURE_FILE = "capture-01.cap"
WORDLIST_FILE = "rockyou.txt"



#client mac
#8e:d3:23:10:86:a6
#b6:47:5c:ec:f9:3f --> shirin phone
#5e:33:8c:67:33:fe --> amma phone



# --- File locations ---------------------------------------------------------
# code/ lives one directory below the repo root, which is where capture-01.cap
# and testlist.txt actually are. Resolving relative to this file (not the
# caller's cwd) means the tool works no matter where it's invoked from.
BASE_DIR = Path(__file__).resolve().parent.parent
CAPTURE_FILE = BASE_DIR / "capture-01.cap"
WORDLIST_FILE = BASE_DIR / "rockyou.txt"

# --- Cracking tunables -------------------------------------------------------
WORDLIST_CHUNK_SIZE = 2000   # passwords handed to a worker process at a time
MIN_PASSWORD_LEN = 8         # WPA2-PSK spec minimum
MAX_PASSWORD_LEN = 63        # WPA2-PSK spec maximum
