#!/usr/bin/env python3
"""
W1seGuy CTF — Automated Solver
Author: 0xb0rn3

Usage:
    python3 solve.py <ip> <port>
    python3 solve.py 10.49.149.93 1337
"""

import socket
import sys
import string


def recover_key(ct: bytes) -> str:
    """
    Known-plaintext XOR attack.
    THM flags always start with 'THM{' and end with '}'.
    That gives us 5 key bytes (positions 0-3 from prefix, position 4 from suffix).
    """
    key = ['?'] * 5

    # Recover key[0..3] from known prefix "THM{"
    known_prefix = b"THM{"
    for i, ch in enumerate(known_prefix):
        key[i % 5] = chr(ch ^ ct[i])

    # Recover key[(n-1)%5] from known suffix "}"
    last_idx = len(ct) - 1
    key[last_idx % 5] = chr(ord('}') ^ ct[last_idx])

    # If any key byte is still unknown (edge-case lengths), brute-force it
    charset = string.ascii_letters + string.digits
    for idx in range(5):
        if key[idx] == '?':
            for candidate in charset:
                test_key = key[:]
                test_key[idx] = candidate
                decrypted = xor_decrypt(ct, ''.join(test_key))
                if decrypted.startswith("THM{") and decrypted.endswith("}"):
                    key[idx] = candidate
                    break

    return ''.join(key)


def xor_decrypt(ct: bytes, key: str) -> str:
    return ''.join(chr(ct[i] ^ ord(key[i % len(key)])) for i in range(len(ct)))


def solve(ip: str, port: int):
    print(f"[*] Connecting to {ip}:{port}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((ip, port))

    # --- Flag 1 ---
    data = s.recv(4096).decode().strip()
    print(f"[*] Server: {data}")

    hex_ct = data.split(": ")[1].strip()
    ct = bytes.fromhex(hex_ct)

    key = recover_key(ct)
    flag1 = xor_decrypt(ct, key)

    print(f"\n[+] Recovered key  : {key}")
    print(f"[+] Flag 1         : {flag1}")

    # Consume the key prompt
    prompt = s.recv(4096).decode().strip()
    print(f"\n[*] Server: {prompt}")

    # --- Flag 2 ---
    s.send((key + "\n").encode())
    response = s.recv(4096).decode().strip()
    print(f"[*] Server: {response}")

    if "flag 2" in response.lower() or "THM{" in response:
        flag2 = response.split(": ")[-1].strip()
        print(f"\n[+] Flag 2         : {flag2}")
    else:
        print("\n[-] Key was rejected — something went wrong.")

    s.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <ip> <port>")
        sys.exit(1)

    solve(sys.argv[1], int(sys.argv[2]))
