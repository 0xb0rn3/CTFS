# W1seGuy — CTF Writeup

**Author:** 0xb0rn3
**Target IP:** 10.49.149.93
**Port:** 1337 (TCP)

---

## Overview

W1seGuy is a cryptography challenge centered on a weak XOR encryption scheme. The server encrypts a flag with a randomly generated 5-character alphanumeric key and sends the result as a hex-encoded ciphertext. You must recover the key to obtain a second flag. The vulnerability lies in the fact that the flag format (`THM{...}`) is known — enabling a classic **known-plaintext XOR attack**.

---

## Reconnaissance

Connecting to the server reveals:

```
This XOR encoded text has flag 1: 1007234d32752e02583601371a7736307b0d5d2105211c05232803175e17363b170637363721443f
What is the encryption key?
```

The server:
1. Generates a random 5-character key from `[a-zA-Z0-9]`
2. XOR-encrypts the flag with that key (cycling every 5 bytes)
3. Sends the ciphertext as a hex string (this is flag 1 — encoded)
4. Prompts for the key; if correct, reveals flag 2

---

## Source Code Analysis

```python
def setup(server, key):
    flag = open('flag.txt', 'r').read().strip()
    xored = ""
    for i in range(0, len(flag)):
        xored += chr(ord(flag[i]) ^ ord(key[i % len(key)]))
    hex_encoded = xored.encode().hex()
    return hex_encoded
```

Key observations:
- The key is only **5 characters** long
- XOR is **symmetric**: `flag ^ key = ct`, so `ct ^ flag = key`, and `ct ^ key = flag`
- The flag format `THM{...}` is **public knowledge** — 4 of the 5 key bytes are trivially recoverable

---

## Attack: Known-Plaintext XOR

XOR encryption satisfies:

```
ciphertext[i] = flag[i] ^ key[i % 5]
key[i % 5]    = flag[i] ^ ciphertext[i]
```

Since all TryHackMe flags begin with `THM{` and end with `}`, we have 5 known plaintext bytes:

| Position | Known plaintext | Operation          | Recovers |
|----------|-----------------|--------------------|----------|
| 0        | `T` (0x54)      | `0x54 ^ ct[0]`     | key[0]   |
| 1        | `H` (0x48)      | `0x48 ^ ct[1]`     | key[1]   |
| 2        | `M` (0x4d)      | `0x4d ^ ct[2]`     | key[2]   |
| 3        | `{` (0x7b)      | `0x7b ^ ct[3]`     | key[3]   |
| n-1      | `}` (0x7d)      | `0x7d ^ ct[n-1]`   | key[(n-1)%5] |

For a 40-byte flag, `(40-1) % 5 = 4`, so `ct[39]` recovers `key[4]`. All five key bytes are recovered with no brute-force needed.

### Step-by-step

```python
hex_ct = "1007234d32752e02583601371a7736307b0d5d2105211c05232803175e17363b170637363721443f"
ct = bytes.fromhex(hex_ct)

key = [None] * 5
for i, ch in enumerate(b"THM{"):
    key[i] = chr(ch ^ ct[i])
key[(len(ct) - 1) % 5] = chr(ord('}') ^ ct[-1])

key_str = ''.join(key)   # e.g. "DOn6B"
flag1 = ''.join(chr(ct[i] ^ ord(key_str[i % 5])) for i in range(len(ct)))
```

Sending `key_str` back to the server triggers the flag 2 response.

---

## Flags

| Flag | Value |
|------|-------|
| **Flag 1** | `THM{p1alntExtAtt4ckcAnr3alLyhUrty0urxOr}` |
| **Flag 2** | `THM{BrUt3_ForC1nG_XOR_cAn_B3_FuN_nO?}` |

---

## Automated Exploit

`solve.py` handles the full chain automatically — connect, attack, submit key, print both flags.

```
python3 solve.py <ip> <port>
python3 solve.py 10.49.149.93 1337
```

**Sample output:**
```
[*] Connecting to 10.49.149.93:1337
[*] Server: This XOR encoded text has flag 1: 2d3b002a...

[+] Recovered key  : ysMQN
[+] Flag 1         : THM{p1alntExtAtt4ckcAnr3alLyhUrty0urxOr}

[*] Server: What is the encryption key?
[*] Server: Congrats! That is the correct key! Here is flag 2: THM{BrUt3_ForC1nG_XOR_cAn_B3_FuN_nO?}

[+] Flag 2         : THM{BrUt3_ForC1nG_XOR_cAn_B3_FuN_nO?}
```

---

## Why This Works

XOR with a short, repeating key is fundamentally broken against known-plaintext. Once you know even a few bytes of the plaintext, the key is directly computable — no brute-force, no exhaustive search. The predictable `THM{...}` flag format makes this trivial: four prefix bytes cover key positions 0–3, and the closing `}` covers position 4.

**Lesson:** Never use XOR with a short key for confidentiality, especially when the plaintext format is partially known. Use authenticated encryption (AES-GCM, ChaCha20-Poly1305) with cryptographically random keys.
