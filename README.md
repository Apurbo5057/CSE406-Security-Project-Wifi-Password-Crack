# CSE406 — WPA2 Wi-Fi Security Project

Coursework project on WPA2/802.11 security: capturing the 4-way handshake, deauthentication,
and offline dictionary cracking, plus a defensive write-up and WPA3 demo.

> **For authorized lab / educational use only.** Only run these tools against networks you own
> or have explicit written permission to test.

## Repository layout

Each `version-*` folder is a snapshot of the project as it evolved. Commit history is ordered
`version-0 → version-5`, so the git log reads as the project's progression.

| Version | Contents |
|---------|----------|
| `version-0` | Planning & research: project spec, research strategy, Wi-Fi deep-dive guide, aircrack-ng workflow |
| `version-1` | Initial capture/crack/deauth scripts (developed on an Azure VM) |
| `version-2` | Local capture toolset + sniff test + WPA2 study guide |
| `version-3` | Modular refactor: `config`, `handshake`, `crack`, with tests |
| `version-4` | Runs against real field captures; client discovery + workflow docs |
| `version-5` | **Latest** — defense demo, WPA3 demo, and the LaTeX design report |

The current, most complete code lives in [`version-5/code`](version-5/code).

## Not tracked in git

The following are intentionally excluded (see `.gitignore`) and must be provided locally:

- **`rockyou.txt`** — the ~133 MB public wordlist. Download it separately and place it where each version expects.
- `__pycache__/` and `*.pyc` — Python bytecode.
- `*.cap`, `*.csv`, `*.netxml`, `*.kismet.*` — captured/generated packet artifacts.
- LaTeX build artifacts.
