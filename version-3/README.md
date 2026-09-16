# WPA2 Handshake Cracker

CSE406 (Security Sessional) Topic 20 — Wi-Fi password cracking attack.

A from-scratch attack against WPA2-PSK: capture a handshake, crack it offline. Everything lives in
this one folder. The **cracking** math — EAPOL parsing, PMK/PTK/KCK derivation, MIC verification,
wordlist testing (`handshake.py`, `crack.py`) — is entirely our own implementation, **zero
third-party dependencies, no aircrack-ng/hashcat/pyrit/hcxtools/scapy used or invoked**. `capture.py`
(and, optionally, `deauth.py`) handle getting a handshake in the first place, and craft/parse their
own raw 802.11 frames with `scapy` (not `aireplay-ng`/`airodump-ng`) — see §1 for that one extra
dependency.

## Files

| File | What it does |
|---|---|
| `config.py` | **The only file you need to edit.** All target/network/file settings for every script below. |
| `capture.py` | **Passively** sniffs monitor-mode traffic for the target BSSID, recognizes EAPOL handshake messages per-client, and saves a `.cap` file once it has a usable handshake. Never sends deauth frames itself. Needs `scapy`. |
| `deauth.py` | Optional: forges 802.11 deauth frames to force a client to reconnect, so `capture.py` doesn't have to wait for a natural reconnect. Needs `scapy`. |
| `handshake.py` | Parses the `.cap` file: pcap container → 802.11 frames → EAPOL-Key frames → candidate 4-way handshakes. Handles both plain 802.11 captures (linktype 105, e.g. from `airodump-ng`) and Radiotap-wrapped ones (linktype 127, what `capture.py`'s live `scapy` sniffing produces). Pure stdlib. |
| `crack.py` | PMK/PTK/MIC crypto + the command-line tool (`info` / `single` / `wordlist` modes). Pure stdlib. |
| `test_crack.py` | Automated test suite, runs against the real capture file. Pure stdlib. |

## 0. Don't have a capture yet? Capture one first

Everything from §2 onward assumes `capture-01.cap` already exists. If it doesn't, run `capture.py`
— it reads its target settings from `config.py`, same as the cracker. All commands below are run
from the repository root (the folder containing `code/`, `capture-01.cap`, `testlist.txt`,
`CLAUDE.md`).

**`capture.py` is purely passive** — it never sends deauth/disassociation frames. It watches the
target BSSID and waits for *any* client to (re)associate on its own, which naturally triggers a
fresh 4-way handshake. That can take a while if nobody's device happens to reconnect. `deauth.py` is
an optional accelerator you can run in a second terminal to force a reconnect immediately — `capture.py`
doesn't need it and doesn't call it.

1. In `config.py`, make sure `INTERFACE`, `MONITOR_INTERFACE`, `BSSID`, and `CHANNEL` match your
   target. `CLIENT_MAC` is optional for `capture.py` — leave it blank to capture the first client
   that completes a handshake, or set it to only track/save one specific client's exchange
   (visible via `airodump-ng` recon or the STATION list — see `aircrack-ng-workflow.md` for an
   example of finding this). If you also plan to run `deauth.py`, it *does* require `CLIENT_MAC` to
   be set (it needs to know who to knock offline) and refuses to run otherwise.

2. Create the monitor-mode interface (needs root). `MONITOR_INTERFACE` in `config.py`
   (`wlp0s20f3mon`) is a **separate** virtual interface from `INTERFACE` (`wlp0s20f3`) — plain
   `iw <iface> set monitor control` switches an interface in place and does *not* create this
   second one, so use `airmon-ng` instead, which does:
   ```bash
   sudo airmon-ng check kill                # stops NetworkManager/wpa_supplicant fighting for the card
   sudo airmon-ng start wlp0s20f3 11        # your INTERFACE and CHANNEL from config.py
   iw dev                                    # confirm wlp0s20f3mon now exists, type monitor
   ```
   `airmon-ng check kill` will drop your normal Wi-Fi connection — expected, restored in step 4.
   (`capture.py` also tries to set the channel itself on startup from `config.CHANNEL`, as a
   best-effort double-check — you'll see `[*] wlp0s20f3mon set to channel 11` or a warning if that
   fails, in which case set it manually as shown above.)

3. Start the capture (needs root) — it prints `[+] Msg{1-4}/4 from {client MAC} ...` as it sees
   handshake messages from any client, and once one client has completed Msg1+Msg2 it waits up to
   5 more seconds for a confirming Msg3+Msg4 before saving `CAPTURE_FILE` (from `config.py`) and
   exiting on its own:
   ```bash
   sudo python3 code/capture.py
   ```
   Optionally, in a second terminal, speed things up by forcing the target client to reconnect:
   ```bash
   sudo python3 code/deauth.py
   ```
   Otherwise just wait for a real device on the network to reconnect naturally (turning its Wi-Fi
   off/on, or walking out of and back into range, works too).

4. Once `capture.py` exits, your `.cap` file is already exactly where `config.py`'s `CAPTURE_FILE`
   expects it. Continue with §1 onward below. Afterwards, restore normal networking:
   ```bash
   sudo airmon-ng stop wlp0s20f3mon
   sudo systemctl restart NetworkManager
   ping -c 3 google.com                      # confirm you're back online
   ```

**Troubleshooting:**

- **`capture.py` overwrites `CAPTURE_FILE` if it already exists** — it calls `wrpcap()` on exit,
  which replaces the file at that path with no confirmation prompt. If you already have a capture
  you care about (like the provided `capture-01.cap`), back it up or point `CAPTURE_FILE` at a
  different name before running `capture.py` again. A copy of the original provided capture is kept
  at `capture-01.cap.original-backup` (repo root) in case you need to restore it.
- **`OSError: [Errno 19] No such device`** when running `capture.py`/`deauth.py` — `wlp0s20f3mon`
  doesn't exist yet. Run step 2's `airmon-ng` commands and confirm with `iw dev` before retrying.
- **`ModuleNotFoundError: No module named 'scapy'` even after `pip install scapy`** — you likely
  installed it for your normal user, but `sudo python3` runs as root with a different environment.
  Install it system-wide instead: `sudo apt install python3-scapy`.
- **Dual-band networks (e.g. `Niloy` 2.4GHz vs `Niloy-5G`):** these are usually two different BSSIDs
  on two different channels, even though they share a base name. Before capturing, re-confirm the
  BSSID/channel for the band you actually want with a quick recon scan (matches
  `aircrack-ng-workflow.md`'s step 2):
  ```bash
  sudo airodump-ng wlp0s20f3mon
  ```
  and update `BSSID`/`CHANNEL` in `config.py` if they don't match what you see there.
- **`ValueError: unsupported linktype 127`** — this was a real gap, now fixed: `capture.py`'s live
  `scapy` sniffing writes Radiotap-wrapped frames (linktype 127), which `handshake.py` now handles
  directly alongside plain-802.11 captures (linktype 105, e.g. from `airodump-ng`). If you still see
  this, you're running an older `handshake.py` — `git pull`/re-copy the file, or check
  `handshake.DLT_IEEE802_11_RADIOTAP` exists.
- **`wordlist`/`single` says "not found" even though you're sure the password is right** — a capture
  that only got Msg1+Msg2 (no Msg3/Msg4, i.e. `info` shows `Complete 4-way: False`) with just one or
  two ANonce samples has a real chance of not containing the *specific* ANonce the client actually
  used (this AP has been observed generating a fresh ANonce on retries — see `handshake.py`'s
  `extract_handshakes` docstring). This isn't a bug; it means the capture window was too short or
  too quiet. Recapture with `capture.py` and `deauth.py` running **at the same time**, in two
  terminals (not one after the other) — forcing a reconnect *while* actively listening gives the
  best chance of catching a complete, confirmed (Msg3/Msg4) exchange.

## 1. Requirements

For **cracking** (`crack.py`, `handshake.py`, `test_crack.py`): just Python 3 (3.9+), nothing to
install — pure standard library.

```bash
python3 --version
```

For **capturing** (`capture.py`, `deauth.py`, only needed if you're doing §0): those two also need
`scapy`, since that's what they use to sniff and forge raw 802.11 frames. They must run as root
(`sudo python3 code/capture.py`), so install it system-wide rather than with a plain `pip install`
(which only installs for your normal user — invisible to `sudo`'s Python):

```bash
sudo apt install python3-scapy
```

## 2. Configure `config.py`

Open `config.py`. These are the only values you should ever need to change:

```python
INTERFACE = "wlp0s20f3"           # your wireless NIC name (used by capture.py/deauth.py)
MONITOR_INTERFACE = "wlp0s20f3mon"  # monitor-mode interface name (used by capture.py/deauth.py)
SSID = "Niloy"                    # target network's exact name (PBKDF2 salt — must match exactly)
BSSID = "3C:84:6A:34:20:7C"       # target AP's MAC address
CHANNEL = 11                      # target AP's channel (for your own `iw ... set channel`, not read by any script)
CLIENT_MAC = ""                   # a client's MAC to deauth (only needed for deauth.py, see §0)
CAPTURE_FILE = "capture-01.cap"   # your .cap file's name
WORDLIST_FILE = "testlist.txt"    # your wordlist's name
```

- `SSID` and `BSSID` **must** match the network in your `.cap` file exactly, or parsing/cracking
  will fail (SSID is used as the cryptographic salt; BSSID is used to filter which frames belong to
  the target AP).
- `CAPTURE_FILE` / `WORDLIST_FILE` are just filenames — put your `.cap` file and your wordlist file
  in the **repository root** (the folder one level above `code/`, i.e. next to `CLAUDE.md`), and the
  tool finds them automatically no matter where you run it from. You don't need to write a path.
- `INTERFACE` / `MONITOR_INTERFACE` / `CLIENT_MAC` are only needed if you're also running
  `capture.py`/`deauth.py` (§0) — the cracker itself (§3 onward) doesn't touch them.

## 3. Run the tests

From the repository root (one level above `code/`):

```bash
cd "path/to/Security"          # the folder containing code/, capture-01.cap, testlist.txt
python3 code/test_crack.py -v
```

Expect all tests to print `ok` and finish with `OK`. This checks: the `.cap` file parses correctly,
a complete handshake is found for your configured SSID/BSSID, all extracted fields have the right
lengths, the crypto functions are deterministic and produce correctly-sized output, and a
deliberately wrong password is correctly rejected.

If a test fails here, fix `config.py` (wrong SSID/BSSID, or `CAPTURE_FILE` doesn't exist) before
moving on — the other modes will fail the same way.

## 4. Inspect the handshake (`info` mode)

```bash
python3 code/crack.py info
```

Parses `CAPTURE_FILE`, filters to `BSSID`, and prints what it found: how many candidate handshakes
exist, and details of the best one (client MAC, which handshake messages were captured, the raw
ANonce/SNonce/MIC). Use this to sanity-check that your capture actually contains a usable handshake
before trying to crack it.

**Why "candidate handshakes" and not just one:** a real Wi-Fi capture is messy — a busy AP can retry
Msg1 with a *fresh* ANonce each time instead of resending the original one, and the sniffer can miss
the one Msg1 a client actually used before it replied. Since Msg3 carries the same ANonce as the
Msg1 it confirms, `handshake.py` treats both Msg1 *and* Msg3 as ANonce sources, and pairs every
ANonce ever sent to a station with every one of that station's Msg2 responses — because there's no
way to know which pairing is the real one until a password is actually tried against it. `single`
and `wordlist` modes test each candidate password against *every* candidate handshake, so this is
handled automatically; you'll just see a (usually large) "Candidate handshakes" count in `info`
mode, which is expected and not an error.

- **`Complete 4-way: True`** — this specific candidate's Msg2 was followed by a real Msg3+Msg4, i.e.
  the AP itself confirmed this exchange succeeded. Strong signal, but not required for cracking.
- **`Complete 4-way: False`** — no confirming Msg3/Msg4 seen for this candidate. Still fully
  crackable (Msg1/Msg3-ANonce + Msg2 is all the math needs), just less independently confirmed.
- If it errors with "No crackable handshake found" — your capture doesn't contain any ANonce+Msg2
  pair for the configured BSSID. Recheck `BSSID` in `config.py`, or recapture (see §0).

## 5. Test one password (`single` mode)

```bash
python3 code/crack.py single "some_candidate_password"
```

Prints `MATCH` or `NO MATCH`. Exit code `0` = correct password, `1` = wrong password. Good for
quickly checking one guess without running the whole wordlist.

## 6. Run a wordlist attack (`wordlist` mode)

```bash
python3 code/crack.py wordlist
```

Streams every line of `WORDLIST_FILE` (default `testlist.txt`) and tests it, spread across all CPU
cores. Stops immediately and prints the password as soon as it finds a match. Prints progress every
~20,000 candidates.

To point it at a different/bigger wordlist without editing `config.py`:

```bash
python3 code/crack.py wordlist --wordlist "CSE406_ WiFi Password Crack/RockYou Password List/rockyou.txt"
```

Other useful flags (all optional, all subcommands accept them):

```bash
python3 code/crack.py wordlist --processes 4       # use fewer CPU cores
python3 code/crack.py wordlist --chunk-size 5000    # passwords per batch handed to a worker
python3 code/crack.py <mode> --capture other.cap --ssid OtherSSID --bssid AA:BB:CC:DD:EE:FF
```

**Note on `testlist.txt`:** it has a leftover placeholder line, `your_actual_router_password`
(never replaced with a real password) — that specific line will never match. But `testlist.txt` as
shipped does contain the real `Niloy` password among its other entries, so `wordlist` mode is
expected to print `KEY FOUND!` against it as-is (cross-checked against `aircrack-ng -w testlist.txt
-b 3C:84:6A:34:20:7C capture-01.cap`, which agrees). If you repoint `WORDLIST_FILE` at a different
list that doesn't contain the real password, "not found" is the correct result, not a bug.

## Quick start, start to finish

```bash
cd "path/to/Security"                    # repo root
# 0. no capture-01.cap yet? see "0. Don't have a capture yet?" above first.
$EDITOR code/config.py                   # set SSID / BSSID to match your capture (skip if using the defaults)
python3 code/test_crack.py -v            # 1. sanity-check everything parses and computes correctly
python3 code/crack.py info               # 2. confirm a handshake was found
python3 code/crack.py single "guess"     # 3. (optional) try one password
python3 code/crack.py wordlist           # 4. run the full dictionary attack
```