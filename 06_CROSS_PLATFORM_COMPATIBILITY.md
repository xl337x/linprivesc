# APEX — Cross-Platform Compatibility
## Every Environment, Every Distro, Every Constraint

---

## 1. Linux Distribution Matrix

### 1.1 Debian/Ubuntu Family
```
Package manager:  dpkg/apt
Integrity check:  debsums -c
Init system:      systemd (modern) / upstart (old) / sysvinit (very old)
Cron:             /etc/crontab, /etc/cron.d/, /var/spool/cron/crontabs/
Shadow:           /etc/shadow (shadow group)
Sudoers:          /etc/sudoers, /etc/sudoers.d/
Special tools:    update-rc.d, service
Notes:            Most HTB/PG machines — well-supported
```

### 1.2 RHEL/CentOS/Fedora Family
```
Package manager:  rpm/yum/dnf
Integrity check:  rpm -Va
Init system:      systemd (modern) / sysvinit (old)
Cron:             /etc/crontab, /etc/cron.d/, /var/spool/cron/
Shadow:           /etc/shadow
Sudoers:          /etc/sudoers, /etc/sudoers.d/
Special notes:    SELinux ENABLED BY DEFAULT — major impact on detection
                  /etc/selinux/config for policy
```

### 1.3 Alpine Linux
```
Package manager:  apk
Integrity check:  NONE (apk has no verify command)
Init system:      OpenRC
Cron:             /etc/periodic/ (not /etc/cron.d/)
                  /etc/crontabs/ (user crontabs)
Shell:            ash (busybox), NOT bash
Special:          musl libc — ldd works differently
                  Most binaries are busybox symlinks
                  Very common in Docker containers
Detection:        Must use busybox fallbacks for almost everything
```

### 1.4 Arch Linux
```
Package manager:  pacman
Integrity check:  pacman -Qk (check package files)
Init system:      systemd
Cron:             cronie package — /etc/cron.d/, /var/spool/cron/
Notes:            Rolling release — always latest packages
```

### 1.5 OpenBSD/FreeBSD (Rare in CTF but possible)
```
Shell:            sh/ksh (NOT bash by default)
Package manager:  pkg_add (OpenBSD) / pkg (FreeBSD)
Init:             rc.d scripts
Key difference:   Many bash-isms won't work — use POSIX sh
find:             Different flags than GNU find
stat:             Different format flags (-f not -c)
```

### 1.6 Very Old Systems (Ubuntu 10.04, CentOS 5, etc.)
```
Kernel:           Old (2.6.x) — more kernel CVEs available
Init:             sysvinit or upstart
systemctl:        NOT AVAILABLE
timeout:          May not exist
getcap:           May not exist
ss:               Not available — use netstat
Notes:            More permissive defaults, more CVEs
                  DirtyCow very likely to work on these
```

---

## 2. Compatibility Wrapper: Every Command

These wrappers ensure every command works regardless of environment.
Always call the wrapper, NEVER call the binary directly.

### 2.1 stat wrapper
```bash
apex_stat() {
    local file="$1"
    local field="$2"
    
    case "$field" in
        owner)
            # GNU stat (Linux):
            stat -c "%U" "$file" 2>/dev/null || \
            # BSD stat (FreeBSD/macOS):
            stat -f "%Su" "$file" 2>/dev/null || \
            # Last resort: ls parsing
            ls -la "$file" 2>/dev/null | awk '{print $3}'
            ;;
        group)
            stat -c "%G" "$file" 2>/dev/null || \
            stat -f "%Sg" "$file" 2>/dev/null || \
            ls -la "$file" 2>/dev/null | awk '{print $4}'
            ;;
        perms_octal)
            stat -c "%a" "$file" 2>/dev/null || \
            stat -f "%Lp" "$file" 2>/dev/null || \
            # From ls output: -rwsr-xr-x → 4755
            python3 -c "import os,stat; print(oct(os.stat('$file').st_mode)[-4:])" 2>/dev/null
            ;;
        size)
            stat -c "%s" "$file" 2>/dev/null || \
            stat -f "%z" "$file" 2>/dev/null || \
            wc -c < "$file" 2>/dev/null
            ;;
        mtime_epoch)
            stat -c "%Y" "$file" 2>/dev/null || \
            stat -f "%m" "$file" 2>/dev/null
            ;;
    esac
}
```

### 2.2 find wrapper
```bash
apex_find() {
    local type_arg=""
    local perm_arg=""
    local args_extra="$@"
    
    # Test if GNU find or BusyBox find
    if [[ $FIND_HAS_WRITABLE -eq 1 ]]; then
        # GNU find — use -writable flag
        find / -writable $FIND_MAXDEPTH \
            -not -path "*/proc/*" -not -path "*/sys/*" \
            -not -path "*/dev/*" "$args_extra" 2>/dev/null | head -500
    else
        # BusyBox find — use permission bits instead
        # -writable in BusyBox = files writable by anyone
        # We need files writable by current user (group or other)
        find / \( -perm -o+w -o \( -perm -g+w -group "$(id -gn)" \) \) \
            $FIND_MAXDEPTH \
            -not -path "*/proc/*" -not -path "*/sys/*" \
            -not -path "*/dev/*" "$args_extra" 2>/dev/null | head -500
    fi
}

apex_find_suid() {
    find / -perm -4000 $FIND_MAXDEPTH \
        -not -path "*/proc/*" -not -path "*/sys/*" 2>/dev/null
}

apex_find_sgid() {
    find / -perm -2000 $FIND_MAXDEPTH \
        -not -path "*/proc/*" -not -path "*/sys/*" 2>/dev/null
}
```

### 2.3 getcap wrapper
```bash
apex_get_caps() {
    if [[ $HAS_GETCAP -eq 1 ]]; then
        safe_run "getcap -r / 2>/dev/null" 15
        return
    fi
    
    # Fallback 1: /proc/*/status CapEff field
    echo "[INFO] getcap not available — using /proc/*/status fallback"
    for status_file in /proc/[0-9]*/status; do
        local pid=$(echo "$status_file" | grep -oE '[0-9]+')
        local cap_eff=$(grep "^CapEff:" "$status_file" 2>/dev/null | awk '{print $2}')
        local name=$(grep "^Name:" "$status_file" 2>/dev/null | awk '{print $2}')
        local exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
        
        # Skip zero capabilities
        [[ -z "$cap_eff" || "$cap_eff" == "0000000000000000" ]] && continue
        
        echo "$exe = $(decode_capabilities $cap_eff)"
    done
}

decode_capabilities() {
    local cap_hex="$1"
    local cap_int=$((16#$cap_hex))
    local cap_names=""
    
    # Decode important capability bits
    [[ $((cap_int & (1<<7)))  -ne 0 ]] && cap_names+="cap_setuid+"
    [[ $((cap_int & (1<<6)))  -ne 0 ]] && cap_names+="cap_setgid+"
    [[ $((cap_int & (1<<1)))  -ne 0 ]] && cap_names+="cap_dac_override+"
    [[ $((cap_int & (1<<21))) -ne 0 ]] && cap_names+="cap_sys_admin+"
    [[ $((cap_int & (1<<13))) -ne 0 ]] && cap_names+="cap_net_admin+"
    
    echo "${cap_names:-other(0x$cap_hex)}"
}
```

### 2.4 Init system wrapper
```bash
apex_list_scheduled_tasks() {
    case "$INIT" in
        systemd)
            safe_run "systemctl list-timers --all --no-pager" 10
            safe_run "systemctl list-units --type=service --all --no-pager" 10
            safe_run "systemctl list-sockets --all --no-pager" 10
            ;;
        sysvinit)
            safe_run "ls -la /etc/init.d/" 5
            safe_run "find /etc/rc*.d -type l" 5
            # Cron still works
            ;;
        openrc)
            safe_run "rc-status --all" 5
            safe_run "rc-update show" 5
            ;;
        runit)
            safe_run "ls /etc/service/" 5
            safe_run "ls /var/service/" 5
            ;;
        *)
            echo "[WARN] Unknown init system — using fallback"
            # Try everything
            safe_run "ls /etc/init.d/ 2>/dev/null" 5
            safe_run "crontab -l 2>/dev/null" 5
            ;;
    esac
    
    # Cron is universal — check regardless of init system
    apex_read_all_cron
}
```

### 2.5 Package integrity wrapper
```bash
apex_integrity_check() {
    case "$PKG" in
        dpkg)
            safe_run "debsums -c 2>/dev/null" 60 | grep -v "^$" | while IFS= read -r line; do
                echo "[INTEGRITY_FAIL] $line"
            done
            ;;
        rpm)
            safe_run "rpm -Va 2>/dev/null" 60 | grep "^..5" | while IFS= read -r line; do
                echo "[INTEGRITY_FAIL] Hash mismatch: $line"
            done
            ;;
        apk)
            # Alpine: no verify command
            # Use timeline + strings analysis instead
            echo "[INFO] Alpine detected — no package integrity tool"
            echo "[INFO] Using timeline and strings analysis"
            apex_timeline_check
            ;;
        pacman)
            safe_run "pacman -Qk 2>/dev/null" 60 | grep "warning\|error" | while IFS= read -r line; do
                echo "[INTEGRITY_FAIL] $line"
            done
            ;;
        none)
            echo "[WARN] No package manager found — integrity check limited to timeline"
            apex_timeline_check
            ;;
    esac
}
```

### 2.6 Network tool wrapper
```bash
apex_open_ports() {
    case "$NET_TOOL" in
        ss)
            safe_run "ss -tlnp" 5
            safe_run "ss -ulnp" 5
            safe_run "ss -xlnp" 5  # unix sockets
            ;;
        netstat)
            safe_run "netstat -tlnp 2>/dev/null" 5
            safe_run "netstat -ulnp 2>/dev/null" 5
            safe_run "netstat -xlnp 2>/dev/null" 5
            ;;
        none)
            # No network tool — use /proc
            echo "[INFO] No ss/netstat — reading /proc/net directly"
            cat /proc/net/tcp 2>/dev/null
            cat /proc/net/tcp6 2>/dev/null
            cat /proc/net/udp 2>/dev/null
            cat /proc/net/unix 2>/dev/null
            ;;
    esac
}
```

### 2.7 Strings wrapper
```bash
apex_strings() {
    local binary="$1"
    local min_length="${2:-4}"
    
    if [[ $HAS_STRINGS -eq 1 ]]; then
        strings -n "$min_length" "$binary" 2>/dev/null
    elif command -v objdump >/dev/null 2>&1; then
        # objdump fallback
        objdump -s "$binary" 2>/dev/null | \
            grep -oP '(?<=  )[\x20-\x7e]{4,}' 2>/dev/null
    elif [[ $HAS_PYTHON3 -eq 1 ]]; then
        # Python fallback
        python3 -c "
import sys
with open('$binary', 'rb') as f:
    data = f.read()
import re
for m in re.finditer(b'[\\x20-\\x7e]{$min_length,}', data):
    print(m.group().decode('ascii', errors='ignore'))
" 2>/dev/null
    else
        # Last resort: tr to remove non-printable
        cat "$binary" 2>/dev/null | tr -dc '[:print:]' | \
            grep -oE '.{4,}' 2>/dev/null
    fi
}
```

---

## 3. Shell Compatibility

### 3.1 Bash-Only Features That Must Have Fallbacks

```bash
# Bash 4+ associative arrays:
declare -A my_dict   # bash 4+ only
# Fallback for bash 3 (macOS default) or sh:
# Use flat arrays with naming convention

# Bash [[ ]] with regex:
[[ "$string" =~ ^pattern$ ]]  # bash only
# Fallback:
echo "$string" | grep -qE "^pattern$"

# Bash process substitution:
diff <(cmd1) <(cmd2)  # bash/zsh only
# Fallback:
cmd1 > /tmp/a; cmd2 > /tmp/b; diff /tmp/a /tmp/b; rm /tmp/a /tmp/b

# Bash printf %q (quote for reuse):
printf '%q' "$var"   # bash only
# Fallback:
echo "$var" | sed "s/'/'\\\\''/g; s/^/'/; s/$/'/"
```

### 3.2 Restricted Shell Detection and Escape

```bash
detect_restricted_shell() {
    # Check if we're in rbash, rksh, etc.
    local shell_name=$(ps -p $$ -o comm= 2>/dev/null | tr -d '-')
    echo $SHELL 2>/dev/null | grep -q "rbash\|rksh\|rsh" && IS_RESTRICTED=1
    
    # Test actual restrictions
    (cd /tmp 2>/dev/null) || IS_RESTRICTED=1
    (PATH=/tmp:$PATH 2>/dev/null) || IS_RESTRICTED=1
    
    if [[ $IS_RESTRICTED -eq 1 ]]; then
        echo "[RESTRICTED_SHELL] Detected restricted shell"
        echo "  Current shell: $SHELL (PID $$: $shell_name)"
        echo ""
        echo "  ESCAPE METHODS TO TRY:"
        echo "  vi → :set shell=/bin/bash → :shell"
        echo "  vim → :!bash"
        echo "  man → !/bin/bash"
        echo "  less → !/bin/bash"
        echo "  awk → awk 'BEGIN{system(\"/bin/bash\")}'"
        echo "  find → find / -exec /bin/bash \\; -quit"
        echo "  python3 → python3 -c 'import os;os.execl(\"/bin/bash\",\"bash\",\"-p\")'"
        echo "  perl → perl -e 'exec \"/bin/bash\"'"
        echo "  env → env /bin/bash"
        echo "  tee → tee </dev/null | bash"
        echo ""
        echo "  If above fail, check what binaries ARE accessible:"
        compgen -c 2>/dev/null | sort | head -50
    fi
}
```

---

## 4. Container Environment Handling

### 4.1 Docker Container Checks

```bash
handle_docker_container() {
    echo "[CONTAINER] Docker container detected"
    
    # Check escape vectors
    # 1. Privileged flag
    if cat /proc/self/status | grep -q "CapEff:.*[^0]"; then
        local caps=$(cat /proc/self/status | grep "CapEff:")
        echo "[CONTAINER_CAPS] $caps"
        # Full capabilities = privileged container = likely escape possible
        # 0000003fffffffff or similar = ALL caps = privileged
    fi
    
    # 2. Docker socket mounted
    [[ -S /var/run/docker.sock ]] && {
        echo "[DOCKER_SOCKET] /var/run/docker.sock accessible"
        echo "  → Full host access via docker commands"
        echo "  Exploit: docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
    }
    
    # 3. Host filesystem mounts
    mount | grep -v "^overlay\|^proc\|^tmpfs\|^devpts\|^sysfs\|^cgroup\|^mqueue\|^hugetlbfs" | \
        grep -E "^/dev/|host" && echo "  [HOST_MOUNT] Host filesystem mounted"
    
    # 4. Kubernetes service account
    [[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]] && {
        echo "[K8S_TOKEN] Kubernetes service account token found"
        echo "  Check RBAC permissions for this service account"
    }
    
    # 5. Network namespace (can we reach other containers?)
    safe_run "ip route" 5
    
    # 6. Writable cgroup
    [[ -w /sys/fs/cgroup ]] && echo "[CGROUP_WRITABLE] /sys/fs/cgroup writable — possible escape"
    
    # 7. nsenter available
    command -v nsenter >/dev/null 2>&1 && echo "[NSENTER] Available — may allow namespace escape"
}
```

---

## 5. Architecture Variants

```bash
detect_architecture() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64)
            echo "[ARCH] x86_64 — most exploits available"
            ;;
        aarch64|arm64)
            echo "[ARCH] ARM64 — limited pre-compiled exploit availability"
            echo "  Need: cross-compile or find ARM64 binaries"
            ;;
        armv7*|armhf)
            echo "[ARCH] ARM32 — Raspberry Pi territory"
            echo "  Need: ARM32 compiled exploits"
            ;;
        i[3-6]86|i686)
            echo "[ARCH] x86 32-bit — old system"
            echo "  More kernel exploits available"
            ;;
        mips*)
            echo "[ARCH] MIPS — embedded/router territory"
            echo "  Very limited tool availability"
            ;;
    esac
    
    echo "[KERNEL] $(uname -r)"
    echo "[ARCH] Cross-compile target for attacker: $ARCH"
    echo "[CMD] gcc -march=$ARCH exploit.c -o exploit"
}
```

---

## 6. When Nothing Is Available

**Absolute minimum environment:** Only `/bin/sh`, `/bin/cat`, `/bin/ls`, `/proc`.

```bash
# APEX minimum mode — works with POSIX sh only
minimal_enum() {
    echo "=== MINIMAL ENUMERATION MODE ==="
    
    # Identity
    id 2>/dev/null || cat /proc/self/status | grep -E "^Uid:|^Gid:|^Groups:"
    
    # SUID (posix find)
    find / -perm -4000 2>/dev/null
    
    # Sudo (if available)
    sudo -n -l 2>/dev/null
    
    # Cron
    cat /etc/crontab 2>/dev/null
    ls /etc/cron* 2>/dev/null
    
    # Running processes (via /proc)
    for pid in /proc/[0-9]*/; do
        uid=$(cat "$pid/status" 2>/dev/null | grep "^Uid:" | awk '{print $2}')
        cmd=$(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ')
        echo "UID=$uid CMD=$cmd"
    done
    
    # Writable files (POSIX)
    find / -perm -o+w -not -path "*/proc/*" -not -path "*/sys/*" 2>/dev/null
    
    # Capabilities via /proc
    cat /proc/self/status 2>/dev/null | grep "^Cap"
    
    # Groups
    cat /etc/group 2>/dev/null | grep "$(id -u)"
}
```
