# Wi-Fi Security From First Principles — A Complete Guide

**Scope.** This guide takes you from "I ran aircrack-ng and it worked but I don't
know why" to "I can look at raw wireless bytes, explain every field, understand
the cryptography, read the tools' source, and build my own." It is written for an
isolated lab, your own equipment, and academic/research use.

**A deliberate choice:** the physical-radio layer (Level 1) is compressed to the
minimum you need to reason about captures. The depth is spent where it pays off
for understanding and tooling — frames, parsing, crypto, the 4-way handshake, and
implementation.

---

## How to read this guide (dependency map)

```
        ┌─────────────────────────────────────────────┐
        │ Part 0  Mental models & layer separation     │
        └───────────────────┬─────────────────────────┘
                            │
   ┌────────────────────────┼────────────────────────┐
   ▼                        ▼                         ▼
Part 1 (brief)          Part 2                    Part 3
Physical/RF        Hardware + driver/OS       802.11 architecture
(just enough)      monitor mode, radiotap     terminology, channels
   │                        │                         │
   └────────────┬───────────┴────────────┬────────────┘
                ▼                         ▼
           Part 4                    Part 5
      Frame structure &         Connection lifecycle
      raw-byte parsing          (discovery→association)
                │                         │
                └────────────┬────────────┘
                             ▼
                        Part 6
              WPA/WPA2/WPA3 + RSN + crypto foundations
                             │
                             ▼
                        Part 7
              EAPOL + the 4-way handshake (byte level)
                             │
                             ▼
                        Part 8
              What is actually being "cracked"
                             │
                             ▼
                        Part 9
              pcap → crackable representation
                             │
                             ▼
                        Part 10
              Tool internals (airmon/airodump/aireplay/aircrack)
                             │
                             ▼
                        Part 11
              Build your own tools (8 staged milestones)
                             │
                             ▼
                        Part 12
              Return to deauth → capture → crack, analyzed
```

Read top to bottom the first time. Later, jump straight to Parts 4, 7, 9, and 11 —
those are the load-bearing chapters for building a parser and a cracker.

Each major topic uses the same rhythm: **big picture → why it exists → how it
works → what it looks like on the wire → how software parses it → how you'd
implement it → security angle → lab → self-test.** Not every section needs all
ten, but that's the spine.

---

## Part 0 — Mental models: keep the layers separate

The single biggest source of confusion is collapsing distinct things into one.
Burn these separations into your head now; every later section leans on them.

**The encapsulation stack (what physically wraps what):**

```
Radio signal          ← analog RF energy in the air
  └ PHY frame         ← preamble + PHY header + payload (PPDU)
      └ 802.11 frame  ← MAC header + frame body + FCS (this is our main object)
          └ LLC/SNAP  ← 8-byte shim that says "the next thing is EtherType X"
              └ IP packet
                  └ TCP/UDP segment
                      └ application data
```

A monitor-mode capture normally gives you the **802.11 frame** (often with a
**radiotap** header bolted on the front by the driver, describing the radio
conditions). It does *not* give you the analog signal, and it usually cannot give
you the PHY preamble. Everything above LLC/SNAP is only visible if the frame
isn't encrypted.

**Identity separations:**

```
SSID     = the human network name ("Alexander the Great")   — a label
BSSID    = MAC of one AP radio's BSS ("5C:62:8B:BA:FD:3E")  — an interface
MAC addr = 48-bit hardware/interface address                — layer 2 identity
IP addr  = layer 3 identity, assigned after you join         — routing identity
```

One SSID can have many BSSIDs (mesh, dual-band, multiple APs). A BSSID *is* a MAC
address, but not every MAC address is a BSSID.

**Security-term separations (people mix these constantly):**

```
802.1X = a framework for port-based network access control
EAP    = the authentication protocol that runs inside 802.1X
EAPOL  = "EAP over LAN" — the L2 transport that also carries the 4-way handshake
WPA    = Wi-Fi Alliance branding for TKIP-era security
WPA2   = RSN with CCMP/AES (what you're almost certainly attacking)
WPA3   = RSN with SAE (kills offline dictionary attacks)
RSN    = "Robust Security Network" — the actual 802.11 spec term WPA2/3 implement
```

Whenever a later section risks blurring two of these, it will stop and point it
out.

---

## Part 1 — Physical/RF reality (the compressed version)

You asked to de-emphasize this, so here is only what changes your decisions when
capturing.

**A channel is a frequency band, and your radio can only be on one at a time.**
2.4 GHz channels 1–13 are ~5 MHz apart but ~20 MHz wide, so they overlap; only
1/6/11 are non-overlapping. 5 GHz has many more, wider, non-overlapping channels.
6 GHz (Wi-Fi 6E, which your MT7921 supports) adds even more.

**Consequences you must respect:**

- A monitor interface parked on channel 4 hears **nothing** on channel 36 (5 GHz).
  If a device roams to 5 GHz, its whole handshake is invisible to you. This alone
  explains most "I see traffic but no EAPOL" situations.
- Wider channels (40/80/160 MHz) mean the AP's energy spans multiple 20 MHz
  channel numbers; capture on the AP's *primary* channel.
- **Signal strength decides behavior.** Clients roam to the strongest AP. A
  sibling BSSID at −37 dBm will win over one at −57 dBm, so the client may not be
  where you expect. Weak frames (−90 dBm) arrive corrupted (bad FCS) and get
  dropped before you ever see them.
- Channel *hopping* (what `airodump-ng` does when you don't pin `-c`) means you
  only hear each channel a fraction of the time — you can miss the brief handshake.
  Pin the channel when you want a specific handshake.

That's the RF you need. Everything else (modulation, symbols, ADC/DAC) is real but
doesn't change how you capture or parse, so we move on.

**Self-test:** Your card is on channel 4 and you see thousands of data frames from
the AP but zero EAPOL after a reconnect. Name two RF-level explanations before
suspecting your code. *(Answer: the client reassociated on 5 GHz / a different
primary channel; or the client's frames arrive too weak and are dropped as bad-FCS.)*

---

## Part 2 — Hardware, driver, OS, and how a packet is captured

### 2.1 What the NIC vs. the CPU actually does

A Wi-Fi NIC is two machines welded together:

- **PHY**: turns RF into bits and back. Handles modulation, timing, the preamble.
- **MAC hardware + firmware**: handles the tight-timing 802.11 rules the CPU is
  too slow for — ACKs (a data frame must be ACKed within microseconds),
  retransmission, CTS/RTS, hardware crypto (CCMP encrypt/decrypt), and **frame
  filtering** (in normal mode it drops frames not addressed to you *before the CPU
  ever sees them*).

The CPU/driver/OS handle everything that isn't time-critical: association logic,
key management, handing frames to user space.

### 2.2 Monitor mode vs. managed mode (precise definitions)

- **Managed mode**: the NIC is a client. Its MAC filter accepts only frames to its
  own address or broadcast/multicast, and the driver hands you *decrypted*
  Ethernet-looking frames. You never see 802.11 management frames or other
  stations' traffic.
- **Monitor mode**: the MAC filter is opened up. The NIC delivers **every 802.11
  frame it can decode on the current channel** — management, control, data, from
  any BSS — as raw 802.11 frames, *without* decrypting (you don't have the keys),
  usually with a radiotap header prepended.

Monitor mode is **not** the same as promiscuous mode. Promiscuous mode is a wired
concept ("accept all frames on my LAN segment") and still gives you Ethernet
frames. Monitor mode gives you raw radio-layer 802.11 frames.

**What monitor mode does NOT do:** it doesn't let you hear other channels
simultaneously, doesn't decrypt protected data, and doesn't guarantee you receive
every frame (weak/corrupt frames are dropped by the PHY/MAC before delivery).

### 2.3 The capture path, stage by stage

```
Air → Antenna → RF front-end → PHY (demodulate, check FCS)
    → MAC/firmware (filter per mode, add RX metadata)
    → driver (mac80211) → builds a radiotap header
    → kernel packet socket (AF_PACKET) on the monitor netdev
    → libpcap → your program (scapy / tshark / Wireshark)
```

Key facts that explain real bugs:

- The **radiotap header** is *added by the driver*, not transmitted. It carries
  RX channel, signal (dBm), rate, and flags such as "FCS present" or "bad FCS."
  Its length is in its own bytes 2–3 (little-endian). To get to the 802.11 frame
  you skip radiotap first.
- Frames with **bad FCS** may be delivered with a flag or dropped — driver
  dependent. This is why a weak client's msg2 can simply never appear.
- Some information (exact PHY preamble, precise timing) **cannot be
  reconstructed** from a capture because it was never delivered to software.

### 2.4 Injection

Injection = the driver/firmware transmits a frame you crafted, bypassing the
normal association state machine. Not all chips/drivers allow it. `aireplay-ng
--test` (or crafting a frame with scapy `sendp`) verifies it. Your MT7921 supports
both monitor and injection, which is why the aircrack path worked.

**Lab 2:** Put your card in monitor mode, run `iw dev <mon> info` to confirm
`type monitor` and the channel. Capture 10 seconds with `tshark -I -i <mon>` and
note that you see beacons from *many* networks — proof the MAC filter is open.

**Self-test:** Why can a monitor capture show you a neighbor's beacon but not the
web page they're loading? *(The beacon is an unencrypted management frame on your
channel; their HTTP is inside CCMP-encrypted data frames you have no key for — and
possibly on another channel.)*

---

## Part 3 — IEEE 802.11 architecture, terminology, and channels

### 3.1 The cast of characters and how they relate

```
        ESS  (one logical network, one SSID, possibly many APs)
      ┌──────────────┴───────────────┐
    BSS                             BSS
 (AP radio =                    (AP radio =
  one BSSID)                     another BSSID)
   ├── STA (client)               ├── STA
   └── STA                        └── STA
```

- **SSID / ESSID**: the network name. (ESSID = "extended" SSID; in practice people
  use them interchangeably.)
- **BSS**: one AP radio and its associated stations. Identified by the **BSSID**
  (that radio's MAC).
- **ESS**: several BSSs sharing one SSID, glued by a **distribution system** (the
  wired/mesh backbone) so a client can roam between them.
- **STA (station)**: any 802.11 device; loosely, "client" = a non-AP STA.
- **IBSS**: ad-hoc mode (no AP). Rare today; mostly ignore it.
- **Infrastructure mode**: the normal STA↔AP model.

Relationship chain to memorize:

```
SSID names the network → BSSID names one AP radio in it → STA associates to a BSSID
→ RSN/WPA defines how they secure the link → EAPOL carries the key handshake
```

### 3.2 Channels, revisited technically

Channel number ↔ center frequency is a fixed table (ch1 = 2412 MHz, ch6 = 2437,
ch11 = 2462; 5 GHz ch36 = 5180, etc.). "Channel width" is how much spectrum around
that center the transmission occupies. The AP advertises its primary channel in
beacons (the **DS Parameter Set** IE, or HT/VHT IEs for width). A capture tool
must tune to that primary channel to hear the BSS reliably.

**Self-test:** Two BSSIDs share the SSID "HomeNet," one on channel 6 and one on
channel 36. You capture on channel 6 and see only half the handshakes you expect.
Why? *(Clients on the 5 GHz BSSID are invisible to a 2.4 GHz capture.)*

---

## Part 4 — 802.11 frames and byte-level parsing

This is the chapter you'll reread. Everything about capture and cracking depends on
locating fields in raw bytes.

### 4.1 The general 802.11 frame

```
+----+----------+------+------+------+------+------+------+---------+-----+
| FC | Duration | Addr1| Addr2| Addr3| Seq  |Addr4 | QoS  | Body    | FCS |
| 2  |    2     |  6   |  6   |  6   |  2   |(6)*  |(2)*  | var     |  4  |
+----+----------+------+------+------+------+------+------+---------+-----+
* present only in certain frames (see below)
```

- **Frame Control (2 bytes)** — the most important 2 bytes in Wi-Fi. Layout of the
  first octet (`fc[0]`):

  ```
  bits 0-1: Protocol Version (00)
  bits 2-3: Type      (00=Management, 01=Control, 10=Data, 11=Extension)
  bits 4-7: Subtype   (e.g. Data:0=Data, 8=QoS Data; Mgmt:8=Beacon, 4=Probe Req,
                       5=Probe Resp, 11=Auth, 0=Assoc Req, 1=Assoc Resp, 12=Deauth)
  ```

  Second octet (`fc[1]`) is flags:

  ```
  0x01 ToDS      0x02 FromDS   0x04 MoreFrag  0x08 Retry
  0x10 PwrMgmt   0x20 MoreData 0x40 Protected 0x80 Order(+HTC)
  ```

- **Duration/ID (2)**: NAV time for medium reservation. Rarely relevant to us.
- **Address 1/2/3**: roles depend on ToDS/FromDS (Part 4.3).
- **Sequence Control (2)**: fragment number (4 bits) + sequence number (12 bits).
- **Address 4 (6)**: present only when **both** ToDS and FromDS are set (WDS/mesh).
- **QoS Control (2)**: present only for QoS subtypes (subtype bit `0x08` set on a
  data frame, i.e. `fc[0] & 0x80`). **This 2-byte field is the #1 reason naive
  parsers miss EAPOL** — it shifts everything after the header by 2 bytes.
- **HT Control (4)**: present only when the Order bit (`fc[1] & 0x80`) is set on a
  QoS data frame. Shifts by a further 4 bytes.
- **Frame Body**: the payload (for data frames, starts with LLC/SNAP).
- **FCS (4)**: CRC-32 over the frame. May or may not be handed to software.

**Computing the MAC header length** (this is exactly what aircrack does):

```
z = 24                       # base: FC+Dur+A1+A2+A3+Seq
if (fc[1] & 0x03) == 0x03:   # ToDS AND FromDS -> Addr4 present
    z += 6
if (fc[0] & 0x80):           # QoS data subtype
    z += 2
    if (fc[1] & 0x80):       # Order bit -> HT Control present
        z += 4
```

### 4.2 A real beacon, dissected

Beacon = management (type 0), subtype 8. After the 24-byte MAC header comes a
fixed part then a list of **Information Elements (IEs)**.

```
802.11 MAC header (24 bytes):
  fc      = 80 00           type=0 subtype=8 (Beacon), no flags
  dur     = 00 00
  addr1   = ff ff ff ff ff ff   (broadcast — beacons go to everyone)
  addr2   = 5c 62 8b ba fd 3e   (transmitter = the AP/BSSID)
  addr3   = 5c 62 8b ba fd 3e   (BSSID)
  seqctl  = a0 3c

Beacon fixed body (12 bytes):
  timestamp        = 8 bytes  (AP's 64-bit microsecond clock)
  beacon interval  = 2 bytes  (e.g. 64 00 = 100 TU ≈ 102.4 ms)
  capability info  = 2 bytes  (Privacy bit tells you it's encrypted, etc.)

Information Elements (Type-Length-Value):
  id=00 len=12 "Alexander the Great"    ← SSID IE (id 0)
  id=01 len=08 ...                       ← Supported Rates
  id=03 len=01 04                        ← DS Parameter Set: channel = 4
  id=30 len=14 ...                       ← RSN IE (id 48): this is WPA2!
  ...
```

**IE parsing logic — the pattern behind every "list of options" in 802.11:**

```
i = start_of_IEs
while i < len(body):
    ie_id  = body[i]
    ie_len = body[i+1]
    ie_val = body[i+2 : i+2+ie_len]
    handle(ie_id, ie_val)
    i += 2 + ie_len
```

The **RSN IE (id 48)** is where you read the security config: which cipher (CCMP
vs TKIP), which AKM (PSK vs SAE vs 802.1X), and whether **PMF/802.11w** (management
frame protection) is required — that last flag predicts whether your deauth will
even work.

**Endianness note:** 802.11 fixed fields are little-endian (beacon interval `64 00`
= 0x0064 = 100). But EAPOL, which rides on top, is **big-endian** (network order).
Getting this backwards silently corrupts everything.

### 4.3 The four-address problem

An Ethernet frame needs two addresses (src, dst). Why does 802.11 need up to four?
Because a wireless frame may traverse the air *and* a distribution system, so it
must track both the immediate radio hop and the ultimate endpoints.

The ToDS/FromDS bits select the meaning of each address:

```
ToDS FromDS  Addr1(RX)  Addr2(TX)  Addr3      Addr4   scenario
 0    0      DA         SA         BSSID      –       IBSS / mgmt
 0    1      DA         BSSID      SA         –       AP → client (FromDS)
 1    0      BSSID      SA         DA         –       client → AP (ToDS)
 1    1      RA         TA         DA         SA      WDS / mesh (4-addr)
```

- **RA/TA** = receiver/transmitter address (the immediate radio hop).
- **DA/SA** = final destination/source.
- **BSSID** = which BSS the frame belongs to.

Concrete example. AP `5C:62:8B:BA:FD:3E`, client `8A:29:12:5A:6E:D9`:

- Client sends data to the AP (ToDS=1): `addr1=BSSID(AP)`, `addr2=client`,
  `addr3=final dst`.
- AP sends data to the client (FromDS=1): `addr1=client`, `addr2=BSSID(AP)`,
  `addr3=original src`.

This is why, when you extract EAPOL, "who is the AP and who is the client" depends
on the direction bits — and why a robust parser identifies the BSSID by role, not
by "whichever address is first."

**Self-test:** You capture a data frame with `fc[1]=0x01`. Which address is the
BSSID? *(ToDS set, FromDS clear → addr1 is the BSSID.)*

---

## Part 5 — The lifecycle of a normal connection

Before attacking, understand what "normal" looks like. Every attack is a
perturbation of this sequence.

```
AP  ── Beacon ───────────────▶ (broadcast, ~10/sec: "I exist, here's my SSID/RSN/channel")
STA ── Probe Request ────────▶ (optional: "anyone named HomeNet?")
AP  ── Probe Response ───────▶ (unicast: same info as beacon, directed)
STA ── Authentication ───────▶ (Open System: basically a formality in WPA2-PSK)
AP  ── Authentication ───────▶
STA ── Association Request ──▶ (client's chosen RSN params, capabilities)
AP  ── Association Response ─▶ (accepted, assigns an Association ID)
        ── now "associated" but NOT yet allowed to pass data ──
        ── 4-WAY HANDSHAKE (EAPOL) proves both know the PSK, derives keys ──
        ── encrypted data flows ──
```

For each stage, ask the seven questions the master prompt lists: who sends it, who
receives it, why, what fields, what's learned, what state changes, what happens
next. Two that matter most for attacks:

- **Authentication (802.11 "Open System")** in WPA2-PSK is *not* where the password
  is checked. It's a legacy two-message formality. The real proof-of-password is
  the later 4-way handshake. (This trips everyone up.)
- **Association** negotiates the RSN parameters (cipher/AKM) but still transfers no
  user data — the "controlled port" stays blocked until the handshake completes.

**Missing/malformed messages:** if the handshake never completes, the client is
associated but sandboxed (no data). If a deauth arrives, the client tears down and
restarts from Authentication — which is exactly why deauth triggers a fresh
handshake you can capture.

---

## Part 6 — WPA/WPA2/WPA3, RSN, and just-enough cryptography

### 6.1 The evolution and why each step happened

```
WEP  : RC4 + broken IV scheme. Keys recoverable in minutes. Dead.
 ↓
WPA  : TKIP — a patch to run on WEP-era hardware. Added per-packet keys + MIC
       (Michael). Transitional; also deprecated.
 ↓
WPA2 : RSN with CCMP (AES-CCM). The 4-way handshake as we know it. Still the
       dominant target; vulnerable to OFFLINE dictionary attack on the handshake.
 ↓
WPA3 : RSN with SAE ("Dragonfly"). A password-authenticated key exchange that is
       zero-knowledge — capturing the handshake yields NOTHING to brute-force
       offline. This is the fix for the attack you're studying.
```

Terms kept distinct:

- **WPA2-Personal (PSK)**: everyone shares one passphrase → PMK. *Your target.*
- **WPA2-Enterprise (802.1X/EAP)**: each user authenticates to a RADIUS server;
  the PMK comes from EAP, not a shared passphrase.
- **RSN**: the spec-level name; the RSN IE in beacons is where this is advertised.
- **SAE**: WPA3's handshake, resistant to offline guessing.

### 6.2 The crypto primitives you must understand

- **Hash (SHA-1/SHA-256)**: one-way digest. Fixed-size output, infeasible to
  reverse.
- **HMAC**: keyed hash — proves a message was produced by someone holding the key.
  `HMAC(key, message)`. Used for the handshake **MIC**.
- **Nonce**: "number used once" — fresh random value per session. Prevents replay:
  even with the same password, every handshake produces different keys because the
  nonces differ.
- **PBKDF2**: deliberately *slow* password hashing. Repeats HMAC thousands of times
  so each password guess is expensive — this is what makes cracking cost real time.
- **Key hierarchy**: derive many purpose-specific keys from one root, so a leak of
  one doesn't expose others.

### 6.3 The WPA2 key hierarchy (map primitives → Wi-Fi)

```
Passphrase (+ SSID as salt)
        │  PBKDF2-HMAC-SHA1, 4096 iterations, 32-byte output
        ▼
PMK  (Pairwise Master Key, 256-bit)          ← same every session (fixed by pw+SSID)
        │  PRF-512 over: PMK, "Pairwise key expansion",
        │  min(APmac,STAmac)‖max(...)‖min(ANonce,SNonce)‖max(...)
        ▼
PTK  (Pairwise Transient Key, 512-bit)       ← fresh each session (nonces differ)
        ├─ KCK  = PTK[0:16]   Key Confirmation Key  (computes the handshake MIC)
        ├─ KEK  = PTK[16:32]  Key Encryption Key    (encrypts the GTK in msg3)
        └─ TK   = PTK[32:48]  Temporal Key          (encrypts actual data frames)

GTK (Group Temporal Key) — for broadcast/multicast — delivered encrypted in msg3.
```

Exact formulas (these are what your cracker recomputes):

```python
PMK = PBKDF2_HMAC_SHA1(passphrase, ssid, iterations=4096, dklen=32)

def PRF512(pmk, A, B):           # A = b"Pairwise key expansion"
    r = b""; i = 0
    while len(r) < 64:
        r += HMAC_SHA1(pmk, A + b"\x00" + B + bytes([i]))
        i += 1
    return r[:64]

B   = min(ap,sta)+max(ap,sta)+min(anonce,snonce)+max(anonce,snonce)
PTK = PRF512(PMK, b"Pairwise key expansion", B)
KCK = PTK[:16]
```

**Why sort the MACs and nonces (`min`/`max`)?** So both sides compute the identical
PTK without agreeing on an order first — order-independence by construction.

**Self-test:** Two networks share the passphrase `hunter2` but have different
SSIDs. Do they have the same PMK? *(No — the SSID is the PBKDF2 salt, so the PMK
differs. This is why the SSID must be exactly right when cracking.)*

---

## Part 7 — EAPOL and the 4-way handshake, to the byte

### 7.1 Why the handshake exists

After association, both sides *claim* to know the PSK, but nobody has proven it and
no session keys exist yet. The 4-way handshake:

1. proves each side holds the same PMK **without sending it**,
2. mixes in fresh nonces so session keys are unique,
3. installs the PTK/GTK,
4. is itself integrity-protected (from msg2 on) by a MIC computed with the derived
   key — a chicken-and-egg solved by deriving the PTK from values exchanged in
   msg1/msg2.

### 7.2 The message flow and what each carries

```
AP (Authenticator)                         STA (Supplicant)
   knows PMK, picks ANonce                    knows PMK
   │
   │──── Msg1: ANonce, replay=r ───────────▶  now has ANonce → can compute PTK
   │        (no MIC — nothing to key it yet)   picks SNonce, computes PTK, KCK
   │
   │◀─── Msg2: SNonce, MIC, replay=r ───────  proves STA has PTK (MIC valid)
   │     AP now has SNonce → computes PTK,     
   │     verifies MIC with KCK
   │
   │──── Msg3: MIC, encrypted GTK, replay=r+1 ▶ AP proves it too; sends group key
   │
   │◀─── Msg4: MIC, replay=r+1 ─────────────  ack; both install keys
   │
   ═══ controlled port opens; encrypted data flows ═══
```

Public vs. secret — the crux of crackability:

- **Public (in the capture):** both MACs, ANonce, SNonce, the MIC, the EAPOL
  frames, the SSID (from beacons).
- **Secret:** the passphrase → PMK → PTK/KCK.

The attacker has everything to *recompute* the MIC for a guessed passphrase and
compare. **Msg1 + Msg2 is sufficient** (ANonce from msg1, SNonce+MIC from msg2).

### 7.3 The EAPOL-Key frame, field by field

EAPOL sits inside the data frame's body, after LLC/SNAP. LLC/SNAP is 8 bytes and
ends with the EtherType `88 8E` (EAPOL). The EAPOL-Key structure (offsets relative
to the start of the EAPOL header):

```
Offset Len Field
  0     1  Protocol Version
  1     1  Packet Type (3 = EAPOL-Key)
  2     2  Packet Body Length (big-endian)
  4     1  Descriptor Type (2 = RSN/WPA2, 254 = WPA)
  5     2  Key Information (BIG-ENDIAN bitfield — see below)
  7     2  Key Length
  9     8  Key Replay Counter        ← pairs msg1↔msg2 (same value)
 17    32  Key Nonce                 ← ANonce (msg1) or SNonce (msg2)
 49    16  Key IV
 65     8  Key RSC
 73     8  Reserved
 81    16  Key MIC                   ← the value you compare against
 97     2  Key Data Length
 99   var  Key Data (e.g. RSN IE, or encrypted GTK in msg3)
```

**Key Information bits** (the 16-bit field at offset 5–6, big-endian, so bit 8+
live in byte 5 and bits 0–7 in byte 6):

```
0x0008 Key Type (1=Pairwise)
0x0040 Install
0x0080 Key ACK       ← set by AP (msg1, msg3)
0x0100 Key MIC       ← set once a MIC is present (msg2, msg3, msg4)
0x0200 Secure        ← set later in the handshake (msg3, msg4)
0x0007 Descriptor Version (2 = HMAC-SHA1-128 MIC for CCMP)
```

Classifying which message you're holding:

```
msg1: ACK=1, MIC=0
msg2: MIC=1, ACK=0, Secure=0
msg3: MIC=1, ACK=1
msg4: MIC=1, ACK=0, Secure=1     (distinguish from msg2 by the Secure bit!)
```

### 7.4 Computing/verifying the MIC (the heart of it)

```python
# after locating the EAPOL bytes `e` for msg2:
key_info = (e[5] << 8) | e[6]
mic      = e[81:97]
# zero the MIC field, then keep EXACTLY the real EAPOL length:
eapol_no_mic = e[:81] + b"\x00"*16 + e[97:]
size = ((e[2] << 8) | e[3]) + 4          # body length + 4-byte header
eapol_no_mic = eapol_no_mic[:size]        # trailing padding/FCS must be excluded

kck = PTK[:16]
desc_ver = key_info & 0x0007
if desc_ver == 1:                         # WPA/TKIP
    computed = HMAC_MD5(kck, eapol_no_mic)
elif desc_ver == 2:                       # WPA2/CCMP  ← your case
    computed = HMAC_SHA1(kck, eapol_no_mic)[:16]
else:                                     # desc_ver 3
    computed = AES_CMAC(kck, eapol_no_mic)

if computed == mic:  # guessed passphrase is correct
```

Two subtleties that cause silent failure: (1) using the *whole* scapy EAPOL layer
instead of truncating to `size` includes padding and breaks the MIC; (2) descriptor
version 3 uses AES-CMAC, not HMAC-SHA1 — if a modern AP negotiates it, a
SHA1-only cracker will never match.

### 7.5 Locating EAPOL in raw bytes (do not trust a dissector)

Because of the QoS/HT-Control shifts, the robust method (this is aircrack's
approach) walks the header manually:

```python
def eapol_from_dot11(h):        # h = 802.11 MAC frame (radiotap already stripped)
    if len(h) < 24: return None
    fc0, fc1 = h[0], h[1]
    if (fc0 & 0x0C) != 0x08: return None        # must be a Data frame
    z = 30 if (fc1 & 0x03) == 0x03 else 24      # 4-address?
    if fc0 & 0x80:                              # QoS data
        z += 2
        if fc1 & 0x80: z += 4                   # + HT Control
    if h[z:z+6] != b"\xaa\xaa\x03\x00\x00\x00": return None   # LLC/SNAP
    if h[z+6:z+8] != b"\x88\x8e": return None   # EtherType EAPOL
    eapol = h[z+8:]
    size = ((eapol[2] << 8) | eapol[3]) + 4
    return eapol[:size] if 0 < size <= len(eapol) else None
```

**Self-test:** Why does `msg2` verification zero out bytes 81–96 before computing
the MIC? *(The sender computed the MIC over the frame with the MIC field zeroed;
to reproduce it you must recreate that exact input.)*

---

## Part 8 — What is actually being "cracked"

Say it precisely: you are **not** decrypting the password and you are **not**
breaking AES. You are running an **offline guessing** loop:

```
for each candidate password:
    PMK = PBKDF2(candidate, SSID)          # slow on purpose
    PTK = PRF512(PMK, macs, nonces)        # from captured public values
    if HMAC(PTK[:16], eapol_msg2_zeroed) == captured_MIC:
        return candidate                    # the guess reproduced the MIC
```

Why this shape:

- **Offline** = no interaction with the AP after capture; you can try billions of
  guesses at your own pace. That's why capturing one handshake is dangerous for
  weak passwords and why WPA3/SAE (which prevents offline guessing) matters.
- **Password strength is everything.** The MIC comparison is cheap; PBKDF2's 4096
  iterations dominate cost (~thousands of guesses/sec/core). A random 12+ char
  password is infeasible; `g0dspeedy0u` in a wordlist falls instantly.
- **You only confirm, never invert.** Each guess is a full forward computation; a
  match means "this password reproduces the observed MIC," which (barring
  astronomically unlikely collisions) means it's the real one.

**Self-test:** Why can't the attacker precompute one table for all networks?
*(The PMK depends on the SSID salt, and the PTK depends on per-session nonces, so
work isn't reusable across networks/sessions — except SSID-specific PMK tables like
hashcat's, which still cost the PBKDF2 up front.)*

---

## Part 9 — From pcap to a crackable representation

### 9.1 pcap/pcapng structure

- **pcap**: 24-byte global header (magic, version, **link-layer type**) then a
  series of records, each with a 16-byte record header (timestamp,
  `caplen`, `origlen`) followed by the captured bytes.
- **pcapng**: block-structured (Section Header, Interface Description, Enhanced
  Packet Blocks). More metadata; same idea.
- **Link-layer type** matters: `105 = IEEE802_11` (bare 802.11) vs `127 =
  IEEE802_11_RADIOTAP` (radiotap + 802.11). Your first parsing step depends on
  which one it is — for 127 you must skip the radiotap header (its length is in its
  own bytes 2–3, little-endian).
- **caplen vs origlen**: if the capture was snapped short, `caplen < origlen` and
  the frame is truncated — a real cause of "missing" fields.

### 9.2 The extraction pipeline

```
pcap bytes
  → per-record: read caplen, slice frame
  → if linktype 127: strip radiotap (skip rt_len bytes)
  → parse 802.11 header (Part 4.1); compute z
  → is it Data with LLC/SNAP EtherType 0x888E? → EAPOL
  → classify msg1/2/3/4 by Key Information bits
  → group by (BSSID, client, replay counter) into handshake attempts
  → pair msg1(ANonce) with msg2(SNonce+MIC) sharing a replay counter
  → emit {ssid, ap, sta, anonce, snonce, mic, eapol_msg2_zeroed, desc_ver}
```

The pairing step is where correctness lives: a capture usually holds *several*
handshake attempts; if you mix an ANonce from attempt A with an SNonce/MIC from
attempt B, the MIC will never verify even with the right password. Pair by the
**Key Replay Counter** (msg1 and msg2 of the same exchange share it).

**Self-test:** A capture has `caplen=98` for what should be a 150-byte EAPOL data
frame. What went wrong and what's the effect? *(The capture snaplen truncated the
frame; the MIC/Key-Data are cut off, so the handshake is unusable — recapture with
full snaplen.)*

---

## Part 10 — Tool internals

For each tool: what problem, what it consumes, what it produces, and the
NIC/driver/OS role. Don't memorize flags — understand the data flow.

- **airmon-ng** — *problem:* put the card in monitor mode without NetworkManager
  fighting it. *Does:* kills interfering processes, asks the driver (via `iw`/nl80211)
  to create a monitor virtual interface. *Produces:* a `mon` netdev delivering raw
  802.11 + radiotap.

- **airodump-ng** — *problem:* discover BSSIDs/stations and capture handshakes.
  *Consumes:* the monitor interface's frame stream. *Does:* parses beacons/probes
  to build the AP table, parses data frames' addresses to infer the station table,
  detects EAPOL to flag "WPA handshake," and writes a pcap. *Channel hops* unless
  pinned with `-c`.

- **aireplay-ng** — *problem:* force events (e.g. reconnection). *Does:* crafts
  802.11 management frames (e.g. deauth) and **injects** them via the driver.
  Depends entirely on injection support. `--deauth` with `-c` targets one station;
  without `-c` it broadcasts.

- **aircrack-ng** — *problem:* recover the PSK offline. *Consumes:* the pcap +
  wordlist + BSSID. *Does:* the Part 9 extraction, then the Part 8 guess loop
  (PBKDF2→PTK→MIC compare), heavily optimized in C/SIMD. *Produces:* `KEY FOUND!`
  plus the Master Key (PMK), Transient Key (PTK), and EAPOL HMAC (the MIC) — each of
  which maps directly to a value your own tool computes.

- **Wireshark/tshark** — *problem:* general dissection. *Does:* the same
  radiotap→802.11→LLC/SNAP→EAPOL walk you're learning, then renders every field.
  Your parser's ground-truth oracle: whatever you extract, compare against tshark.

General trace to hold in mind:

```
frame → NIC/driver → capture iface → tool → frame decoder → 802.11 parser
      → protocol parser → field extraction → analysis/attack logic
```

**Lab 10:** capture a handshake, open it in Wireshark, apply display filter
`eapol`, and manually verify: which frame is msg1 vs msg2 (Key Information bits),
the ANonce/SNonce, and the MIC. This makes Parts 7–9 concrete.

---

## Part 11 — Build your own tools, staged

Build incrementally; at each stage, explain protocol → show bytes → parse →
implement → **compare with tshark** → explain discrepancies. Coding rule: don't
hide the concept behind a library call. If you use `scapy`'s `rdpcap`, still know
that it's iterating pcap records and slicing frames.

**Stage 1 — Raw pcap reader.** Open a pcap, iterate records, print
`timestamp, caplen, origlen`. Goal: understand the container. (Use raw file I/O
first; then note what `rdpcap` does for you.)

**Stage 2 — 802.11 header parser.** For each frame: strip radiotap, decode Frame
Control (type/subtype/flags), compute `z`, print addresses by role, sequence
number, retry bit. Validate types against tshark's "Type/Subtype" column.

**Stage 3 — Management frame parser.** Decode beacon/probe/assoc fixed fields
(timestamp, interval, capability).

**Stage 4 — Information Element parser.** Walk the TLV list; decode SSID (id 0), DS
Parameter (id 3, → channel), and the RSN IE (id 48, → cipher/AKM/PMF). Now you can
print a network's security config yourself.

**Stage 5 — EAPOL parser.** Use `eapol_from_dot11` (Part 7.5); decode Key
Information, replay counter, nonce, MIC. Print which message each is.

**Stage 6 — Handshake analyzer.** Group by (BSSID, station, replay counter); report
whether a capture contains a pairable msg1+msg2 — i.e., "is this crackable?"

**Stage 7 — Session/protocol analyzer.** Reconstruct higher-level views: AP table,
station table, per-session state — your own mini-airodump for offline pcaps.

**Stage 8 — Research tooling.** Only now, with the protocol understood, assemble the
project's security-testing functionality (the offline PMK→PTK→MIC verifier over a
wordlist), validating it reproduces aircrack's result on the same capture.

Each stage is a checkpoint: if your output diverges from tshark, you've found a gap
in understanding — chase it before moving on.

---

## Part 12 — Now return to deauth → capture → crack

With the foundation built, your existing three-script workflow stops being magic.
Analyze it against everything above:

- **deauth** — crafts a management frame (type 0, subtype 12) with the direction
  bits clear, `addr1=target`, `addr2=addr3=BSSID`, a reason code, and injects it.
  *Understand:* why it forces the client back to the Authentication stage (Part 5),
  why PMF/802.11w (Part 4.2 RSN IE) can make it silently fail, and why targeting a
  real associated station beats broadcasting.

- **capture** — a monitor-mode sniffer that must be on the client's **actual
  channel/band** (Part 1), extracts EAPOL by walking raw bytes (Part 7.5, not a
  dissector), and pairs msg1+msg2 by replay counter (Part 9).

- **crack** — the offline verifier: SSID+passphrase→PMK, +nonces+MACs→PTK, MIC
  compare (Parts 6–8), truncating the EAPOL to its real length and matching the
  descriptor version.

For each line of each script you should now be able to answer the master-prompt
questions: what command/OS interface it invokes, what the NIC does, which frame is
transmitted, what it contains, why the target responds, how the response is
captured, how the parser recognizes it, and where the data flows next.

And you can answer the diagnostic questions from real experience: *"I see thousands
of frames but zero EAPOL"* is no longer a mystery — it's Part 1 (wrong band), Part
4 (QoS offset), or Part 9 (no reconnection/no pairable pair), and you know how to
tell which.

---

## Appendix A — Consolidated self-test

1. Distinguish SSID, BSSID, MAC, IP in one sentence each.
2. Given `fc[0]=0x88, fc[1]=0x41`, what is the frame type/subtype, is QoS present,
   is it protected, and how long is the MAC header?
3. Why is the SSID part of the PMK computation?
4. Which handshake messages are strictly necessary to crack, and why?
5. Why does zeroing the MIC field matter before recomputing it?
6. Why can WPA3 not be attacked with the offline method in Part 8?
7. Name three reasons a valid handshake might be absent from a capture.

*(Answers are throughout Parts 3, 4, 6, 7, and 8 — write yours, then check.)*

## Appendix B — Primary sources and how to read them

- **IEEE 802.11 standard** (esp. clauses on frame formats and RSNA/4-way
  handshake): the ground truth for every field. Read it by section, not linearly;
  use it to confirm offsets. Supports Parts 4, 7.
- **aircrack-ng source** (`aircrack-ng.c`, crypto engine): see the exact `z`
  computation and MIC logic. Read it *after* Part 7 so it's familiar, not cryptic.
  Supports Parts 7, 9, 10.
- **Wireshark source** (802.11 dissector `packet-ieee80211.c`): the most complete
  parser in existence; use it to resolve "what is this field?" Supports Part 4.
- **libpcap / pcap-savefile docs**: the file formats in Part 9.
- **scapy docs**: understand what `Dot11`/`EAPOL` layers do — and where they fall
  short (QoS/HTC), which motivated the manual parser.
- **Linux `iw` / nl80211 / mac80211 docs**: what "monitor mode" and "set channel"
  actually ask the kernel to do. Supports Part 2.

Read specs by: (1) find the figure/table for the structure, (2) map each field to
bytes, (3) confirm against a real capture in Wireshark, (4) only then read the
prose. Specs describe; captures prove.
```
