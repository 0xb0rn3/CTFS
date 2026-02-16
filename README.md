# CTFS — CTF Automation Scripts

> **Author:** 0xb0rn3 | 0xbv1 · IG: theehiv3 · X: @0xbv1  
> Automated exploitation scripts for completed CTF rooms and challenges.

A growing collection of purpose-built automation tools that capture the full exploitation chain for specific CTF rooms — from initial recon to root flag. Each script is a standalone autopwn for a single room, documented with the technique it demonstrates.

---

## Repository Structure

```
CTFS/
├── THM/                          # TryHackMe rooms
│   ├── rootmeCTF/
│   │   ├── rootmeautopwn         # RootMe full autopwn
│   │   └── README.md
│   └── ...
├── HTB/                          # Hack The Box machines (coming)
│   └── ...
└── README.md
```

---

## Scripts

### TryHackMe

| Room | Script | Techniques | Difficulty |
|------|--------|------------|------------|
| [RootMe](THM/rootmeCTF/) | `rootmeautopwn` | File upload filter bypass · SUID privesc · Webshell | Easy |

---

## How These Scripts Work

Each script automates a specific room's exploitation chain. They are not general-purpose tools — they encode the exact sequence of steps the room requires, so they run fast and hands-free once the VPN is connected.

Typical chain:

```
Recon → Enumeration → Initial Access → Post-Exploitation → Flag(s)
```

All output (scan results, flags, payloads) is saved to a timestamped directory so runs are fully auditable.

---

## Usage

```bash
git clone https://github.com/0xb0rn3/CTFS.git
cd CTFS/<platform>/<room>/
chmod +x <script>
./<script>
```

Most scripts auto-detect your VPN IP from `tun0` and prompt for the target IP. Connect to the platform VPN first.

---

## Requirements

| Tool | Used by |
|------|---------|
| `nmap` | All recon scripts |
| `gobuster` | Web enumeration scripts |
| `curl` | HTTP interaction |
| `nc` | Reverse shell listeners |
| `gcc` / `python3` | Exploit compilation scripts |

Scripts auto-install missing dependencies on Arch Linux and Debian/Ubuntu systems.

---

## Platforms

| Badge | Platform |
|-------|---------|
| 🟢 | TryHackMe — active |
| 🔵 | Hack The Box — coming |

---

## Disclaimer

All scripts target intentionally vulnerable CTF environments. For authorized use on platforms you are subscribed to only. Do not run against systems you do not own or have explicit written permission to test.
