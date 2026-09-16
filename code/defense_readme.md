# Defense Demonstration — WPA3-Personal (SAE) defeats the offline attack

This project's attack (`capture.py` → `crack.py`) recovers a **WPA2-PSK**
password from a captured 4-way handshake. This document shows that switching
the network to **WPA3-Personal (SAE)** defeats that attack — and proves *why*,
using `code/wpa3_demo.py`.

`wpa3_demo.py` is standalone: it imports `crack.py`, `handshake.py`, and
`config.py` read-only and changes none of them.

---

## How to run the demo

### 1. Baseline — the attack works on WPA2-PSK
Set the AP to **WPA2-Personal**, capture, and crack as usual:
```
sudo python3 code/capture.py
python3 code/crack.py wordlist          # -> [+] KEY FOUND!
```
`crack.py info` will show **Key descriptor ver : 2** (WPA2, HMAC-SHA1 MIC).

### 2. Switch the AP to WPA3-Personal (SAE) and re-capture
On the hotspot/router, set security to **WPA3-Personal only** (not the mixed
"WPA2/WPA3 transition" mode — see the note at the bottom). Update
`code/config.py` (`SSID`, `BSSID`, `CHANNEL`) to the WPA3 network, then:
```
sudo python3 code/capture.py           # still grabs a 4-way handshake
```

### 3. Show the attack fails — even with the correct password
```
python3 code/wpa3_demo.py info                     # classifies the handshake
python3 code/wpa3_demo.py single "<real password>" # -> [-] NO MATCH
python3 code/wpa3_demo.py wordlist                 # -> no match in N candidates
```
`info` reports **Key descriptor ver : 0 → WPA3-SAE (AES-128-CMAC MIC)**, and
both `single` and `wordlist` return **NO MATCH** — including for the correct
password.

(For comparison, `crack.py` itself stops earlier on a WPA3 capture with
`key_descriptor_version=0 ... is not implemented`. `wpa3_demo.py` deliberately
implements that missing MIC so the failure can't be blamed on missing code.)

---

## How it works

`wpa3_demo.py` runs the **exact same WPA2-PSK offline attack** as `crack.py`,
reusing its `derive_pmk` / `derive_ptk` / `derive_kck` functions:

```
PMK  = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32)
PTK  = PRF-512(PMK, AP_MAC, STA_MAC, ANonce, SNonce)
KCK  = PTK[0:16]
MIC  = <keyed hash>(KCK, EAPOL-frame-with-MIC-zeroed)
guess is correct  <=>  computed MIC == captured MIC
```

The one thing `crack.py` leaves out is the MIC algorithm WPA3 uses.
`wpa3_demo.py` adds it in `compute_mic()`:

| Key descriptor version | Security | MIC algorithm |
|---|---|---|
| 2 | WPA2-PSK | HMAC-SHA1-128 |
| 0 / 3 | WPA3-SAE / PMF | **AES-128-CMAC** (implemented here via `cryptography`) |

So on a WPA3 capture the tool can now compute a real, valid MIC — there is no
"not implemented" gap left. It then tries the password(s) and reports whether
the computed MIC equals the captured one.

---

## Why it works (the actual reason WPA3 wins)

The result: **no password reproduces the captured MIC — not even the correct
one.** That is the proof, and the reason is structural:

- **WPA2-PSK:** `PMK = PBKDF2(passphrase, ssid)`. The passphrase *alone*
  determines every key and therefore the MIC. An attacker who captures the
  handshake can test unlimited guesses **offline**, at full CPU/GPU speed.
  This is the vulnerability the project exploits.

- **WPA3-SAE (Dragonfly):** the PMK is **not** derived from the passphrase by
  PBKDF2. It is the output of the **SAE elliptic-curve exchange** between
  client and AP. To reproduce the PMK for a guessed password you must run a
  **live** SAE handshake *with the AP* — one **online** attempt per guess,
  rate-limited by SAE anti-clogging tokens. There is no offline function that
  maps a guessed passphrase to the captured MIC.

Therefore the captured 4-way handshake contains **nothing to brute-force
offline**. Implementing AES-128-CMAC (as this demo does) removes the only
"we just didn't code it" objection, and the dictionary attack *still* fails —
the vulnerability is gone at the root, not merely unimplemented.

As a bonus, WPA3 makes **PMF (Protected Management Frames) mandatory**, so the
spoofed deauthentication frames from `deauth.py` are ignored — the attacker
can no longer force a client to re-handshake either.

---

## Important: use WPA3-*only*, not transition mode

WPA3 "transition" (mixed WPA2/WPA3) mode keeps advertising WPA2 so old devices
can still join. An attacker can then **downgrade** a client onto the WPA2 path
and crack it exactly as before. For the defense to hold, configure the AP as
**WPA3-Personal only**. (This is itself a good finding to mention in the
report.)
