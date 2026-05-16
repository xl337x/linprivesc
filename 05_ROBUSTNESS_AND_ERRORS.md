# APEX — Robustness and Error Handling
## Every Technical Failure Mode and Exact Solution

---

## 1. The Three-Layer Protection (Applied To Every Command)

Every single command APEX runs must be wrapped in all three layers.
Missing even ONE layer causes a failure mode.

```bash
safe_run() {
    local cmd="$1"
    local timeout_sec="${2:-10}"
    
    # LAYER 1: stdin from /dev/null
    #   Kills ANY password prompt immediately.
    #   sudo, mysql, ssh, su, gpg — all hang waiting for input.
    #   /dev/null gives EOF immediately → command sees no input → exits.
    
    # LAYER 2: timeout
    #   Even /dev/null won't stop some commands (NFS hangs, FUSE hangs,
    #   commands that sleep in a loop, commands that poll).
    #   timeout sends SIGTERM after N seconds.
    #   Without timeout: one hanging command = script frozen forever.
    
    # LAYER 3: subshell + always return 0
    #   Script crash in subshell stays in subshell.
    #   Parent always sees return code 0.
    #   Without this: syntax error in one function = entire script dies.
    
    local result
    case "$TIMEOUT_CMD" in
        timeout)
            result=$(timeout "$timeout_sec" bash -c "$cmd" </dev/null 2>/dev/null)
            ;;
        "busybox timeout")
            result=$(busybox timeout "$timeout_sec" bash -c "$cmd" </dev/null 2>/dev/null)
            ;;
        none)
            # No timeout binary — background process with kill watchdog
            local tmpfile=$(mktemp /dev/shm/.apex_XXXXXX 2>/dev/null || mktemp)
            bash -c "$cmd" </dev/null >"$tmpfile" 2>/dev/null &
            local bg_pid=$!
            ( sleep "$timeout_sec"; kill $bg_pid 2>/dev/null ) &
            local killer=$!
            wait $bg_pid 2>/dev/null
            kill $killer 2>/dev/null
            result=$(cat "$tmpfile" 2>/dev/null)
            rm -f "$tmpfile" 2>/dev/null
            ;;
    esac
    
    local exit_code=$?
    [[ $exit_code -eq 124 ]] && \
        echo "TIMEOUT[$((timeout_sec))s]: $cmd" >> "${APEX_TMP}/debug.log" 2>/dev/null
    [[ $exit_code -ne 0 && $exit_code -ne 124 ]] && \
        echo "FAILED[$exit_code]: $cmd" >> "${APEX_TMP}/debug.log" 2>/dev/null
    
    echo "$result"
    return 0  # ALWAYS
}
```

---

## 2. Every Known Hang Scenario and Solution

### 2.1 sudo -l Hangs Waiting for Password

**Problem:** `sudo -l` without `-n` flag → prompts for password → hangs forever.

**Solution:** Always use `sudo -n -l` (non-interactive mode).
If password required: returns exit code 1 immediately. No hang.

```bash
# WRONG:
sudo -l

# CORRECT:
safe_run "sudo -n -l" 5
# If exit code 1 + stderr "sudo: a password is required":
#   → sudo exists but requires password
#   → note it: "sudo requires password — credential testing needed"
```

### 2.2 find / Hangs on NFS/FUSE/Proc Mounts

**Problem:** `find /` hits an NFS mount that's unresponsive, or a FUSE filesystem
that hangs, or /proc entries that block on read. Can hang for minutes.

**Solution:**
```bash
# Always exclude known hang-prone filesystems
safe_find() {
    local args="$@"
    
    # Get list of non-standard filesystem mounts to exclude
    local excludes=""
    while IFS= read -r mount_line; do
        local fs_type=$(echo "$mount_line" | awk '{print $3}')
        local mount_point=$(echo "$mount_line" | awk '{print $2}')
        case "$fs_type" in
            nfs|nfs4|cifs|smbfs|fuse|fusectl|sysfs|proc|devpts|tmpfs|devtmpfs|securityfs|cgroup*|pstore|bpf|tracefs|hugetlbfs|mqueue|debugfs|configfs|ramfs)
                excludes="$excludes -not -path \"${mount_point}/*\""
                ;;
        esac
    done < <(cat /proc/mounts 2>/dev/null)
    
    # Always exclude problematic paths
    local standard_excludes="-not -path '*/proc/*' -not -path '*/sys/*' -not -path '*/dev/*' -not -path '/run/*'"
    
    eval "timeout 30 find / $standard_excludes $excludes $args 2>/dev/null | head -1000"
}
```

### 2.3 su Command Hangs

**Problem:** `su root -c 'id'` → always prompts for password → hangs.

**Solution:** Use `timeout + /dev/null` combination. The /dev/null stdin gives EOF
to the password prompt, causing immediate failure. No hang.

```bash
# With /dev/null stdin: su gets EOF instead of password → exits immediately
echo "" | timeout 3 su root -c 'id' </dev/null 2>/dev/null
```

### 2.4 SSH Commands Hang

**Problem:** `ssh user@host 'id'` → host key verification prompt or password prompt.

**Solution:**
```bash
safe_run "ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 user@host 'id'" 5
# BatchMode=yes: disables all interactive prompts
# ConnectTimeout=3: 3 second connection timeout
```

### 2.5 mysql/psql Hangs

**Problem:** `mysql -u root` → prompts for password.

**Solution:**
```bash
# MySQL: -e flag with empty password attempt
safe_run "mysql -u root -e 'select user()' 2>/dev/null" 5
safe_run "mysql -u root --password='' -e 'select user()' 2>/dev/null" 5

# PostgreSQL: -w flag (no password prompt)
safe_run "psql -U postgres -w -c 'select current_user' 2>/dev/null" 5
```

### 2.6 getcap Hangs or Returns Slowly

**Problem:** `getcap -r /` traverses entire filesystem → can hang on NFS/FUSE.

**Solution:**
```bash
safe_run "getcap -r / 2>/dev/null" 15  # 15 second timeout
# If getcap not available: use /proc/*/status CapEff fallback
```

### 2.7 debsums Hangs on Package Verification

**Problem:** `debsums -c` checks every file in every package → very slow on large systems.

**Solution:**
```bash
# Add timeout, limit to most important packages
safe_run "debsums -c 2>/dev/null | head -50" 60  # 1 minute max
# Prioritize: only check SUID binaries and execution graph items
debsums_check_specific() {
    local binary="$1"
    local package=$(dpkg -S "$binary" 2>/dev/null | cut -d: -f1)
    [[ -n "$package" ]] && safe_run "debsums -c $package" 10
}
```

### 2.8 pspy Needs to Be Transferred

**Problem:** pspy is not installed by default. Needs to be downloaded/transferred.

**Solution:** APEX includes inline pspy-equivalent:
```bash
# Built-in process monitor (no pspy binary needed)
monitor_processes_inline() {
    local duration="${1:-180}"  # 3 minutes default
    local seen_pids=""
    local end_time=$(($(date +%s) + duration))
    
    echo "[APEX-PSPY] Monitoring processes for ${duration}s..."
    
    while [[ $(date +%s) -lt $end_time ]]; do
        while IFS= read -r pid_dir; do
            local pid=$(basename "$pid_dir")
            
            # Skip already-seen PIDs
            [[ "$seen_pids" == *":$pid:"* ]] && continue
            seen_pids="${seen_pids}:${pid}:"
            
            local uid=$(awk '/^Uid:/{print $2}' "$pid_dir/status" 2>/dev/null)
            local cmd=$(cat "$pid_dir/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 200)
            local exe=$(readlink "$pid_dir/exe" 2>/dev/null)
            local ts=$(date "+%H:%M:%S")
            
            [[ -z "$cmd" ]] && continue
            
            echo "[$ts] UID=$uid PID=$pid CMD=$cmd"
            
        done < <(ls -d /proc/[0-9]*/ 2>/dev/null)
        sleep 0.5
    done
}
```

---

## 3. Command Injection Prevention in Our Own Code

**Problem:** Filenames on CTF machines may contain shell special characters.
If we interpolate filenames directly into commands, we get code injection in our OWN tool.

```bash
# DANGEROUS:
cat $filename                    # filename = "; rm -rf /"
find $directory -name "*.conf"   # directory = "/ -exec rm {} ;"
eval "ls $user_input"            # ANY user input

# SAFE:
cat "$filename"                  # always double-quote
find "$directory" -name "*.conf" # always double-quote
# NEVER eval user-controlled input
```

**Null-safe file iteration (handles ALL special characters in filenames):**
```bash
# WRONG (breaks on spaces, newlines, special chars):
for f in $(find / -name "*.sh"); do
    process "$f"
done

# CORRECT (null-terminated, handles all characters):
while IFS= read -r -d '' f; do
    process "$f"
done < <(find / -name "*.sh" -print0 2>/dev/null)
```

---

## 4. Output Parsing Robustness

### 4.1 ANSI Color Code Stripping

**Problem:** Many commands output ANSI color codes when they detect a terminal.
Inside `$()` capture, codes may or may not be included depending on terminal state.
These codes corrupt our regex parsing.

**Solution:** Strip ANSI from ALL captured output before parsing:
```bash
strip_ansi() {
    sed 's/\x1b\[[0-9;]*[mGKHFJsurABCDSTfnhiI]//g; s/\x1b[()][AB012]//g'
}

# Usage:
sudo_output=$(safe_run "sudo -n -l" 5 | strip_ansi)
```

### 4.2 Regex Not Position-Based Parsing

**Problem:** Output formats change between versions. Positional awk parsing breaks.

```bash
# FRAGILE — breaks when output format changes:
awk '{print $3}' /etc/passwd          # assumes field 3 is always home dir
sudo -n -l | awk '{print $3}'          # assumes command is always field 3

# ROBUST — regex-based, version-independent:
grep "^NOPASSWD:" | grep -oE '/[^ ,]+'
grep "^CapEff:" | awk '{print $2}'
```

### 4.3 sudo -l Multi-Format Parsing

```bash
# sudo -l output varies by version:
# Old: (ALL) NOPASSWD: /bin/bash
# New: (ALL : ALL) NOPASSWD: /bin/bash
# With defaults: Defaults env_reset
#                Defaults env_keep += LD_PRELOAD
#                (ALL) NOPASSWD: /usr/bin/python3

parse_sudo_output() {
    local output="$1"
    
    # Parse NOPASSWD commands (handles both old and new format)
    echo "$output" | grep -E "NOPASSWD" | grep -oE '/[^ ,;]+' | sort -u
    
    # Parse ALL/wildcard permissions
    echo "$output" | grep -E "\(ALL\)|\(ALL : ALL\)" | while IFS= read -r line; do
        echo "$line" | grep -v "NOPASSWD" && echo "  → requires password but has broad scope"
    done
    
    # Parse env_keep (CRITICAL — students always miss this)
    echo "$output" | grep -iE "env_keep|env_check" | while IFS= read -r line; do
        echo "[SUDO_ENV_KEEP] $line"
        echo "$line" | grep -iE "LD_PRELOAD|LD_LIBRARY|PYTHONPATH|PERL5LIB|NODE_PATH|RUBY" && \
            echo "  [CRITICAL] Library injection via env_keep possible"
    done
}
```

---

## 5. Resource Exhaustion Protection

### 5.1 Memory Protection

```bash
# find / with large filesystem can use GB of memory
# Pipe through head to cap output
safe_find() {
    eval "find / ... 2>/dev/null" | head -500  # never more than 500 results
}

# Check available memory before large operations
check_memory_before_find() {
    local mem_kb=$(awk '/MemAvailable/{print $2}' /proc/meminfo 2>/dev/null)
    if [[ -n "$mem_kb" && $mem_kb -lt 51200 ]]; then  # < 50MB
        FIND_MAXDEPTH="-maxdepth 4"
        echo "[APEX-WARN] Low memory — limiting search depth"
    fi
}
```

### 5.2 CPU Protection

```bash
# Throttle our own CPU usage to avoid detection
nice_run() {
    nice -n 19 "$@"  # lowest priority — won't impact system
}

# Use ionice too if available
ionice_run() {
    command -v ionice >/dev/null 2>&1 && ionice -c 3 "$@" || "$@"
}
```

### 5.3 Inode/Disk Space Protection

```bash
# Can't create temp files if filesystem is full
# Check before trying
safe_mktemp() {
    local dir="$1"
    local inodes=$(df -i "$dir" 2>/dev/null | tail -1 | awk '{print $4}')
    [[ -z "$inodes" || "$inodes" -lt 10 ]] && {
        echo ""  # no temp file available
        return 1
    }
    mktemp "$dir/apex_XXXXXX" 2>/dev/null
}
```

---

## 6. Race Conditions in APEX Itself

### 6.1 TOCTOU in File Checks

```bash
# PROBLEM: file exists when we check, deleted before we read
if [[ -r "$file" ]]; then       # check
    content=$(cat "$file")      # use — file may be gone
fi

# SOLUTION: Read directly, handle failure gracefully
content=$(cat "$file" 2>/dev/null)
[[ -z "$content" && ! -e "$file" ]] && echo "File disappeared during analysis"
```

### 6.2 Symlink Race in find Output

```bash
# find reports /opt/script.sh
# Between find reporting it and us reading it: symlink changed to /etc/passwd
# We read sensitive file we didn't intend to
# SOLUTION: Use O_NOFOLLOW equivalent — verify path before reading
verify_and_read() {
    local path="$1"
    # Verify it's a regular file (not symlink leading somewhere unexpected)
    [[ -L "$path" ]] && {
        local target=$(readlink -f "$path" 2>/dev/null)
        echo "[SYMLINK] $path → $target"
        path="$target"  # follow to real target
    }
    cat "$path" 2>/dev/null
}
```

---

## 7. Detection Evasion (Being Stealthy)

### 7.1 Avoid Triggering IDS/Auditd

```bash
# Problem: IDS may alert on rapid file access patterns
# Our find / generates thousands of file opens in seconds

# Solution: Rate limiting for stealth mode
STEALTH_MODE=0  # default off (CTF usually fine)

rate_limited_find() {
    if [[ $STEALTH_MODE -eq 1 ]]; then
        # Slow down to avoid IDS signatures
        find "$@" 2>/dev/null | while IFS= read -r line; do
            echo "$line"
            sleep 0.01  # 10ms delay between results
        done
    else
        find "$@" 2>/dev/null  # full speed
    fi
}
```

### 7.2 Write to Memory, Not Disk

```bash
# All temp files go to /dev/shm (RAM) by default
# Never to /tmp if /dev/shm available — stays off disk
# Smaller forensic footprint
```

### 7.3 Cleanup on Exit

```bash
cleanup_apex() {
    # Kill all background jobs
    kill $(jobs -p) 2>/dev/null
    wait 2>/dev/null
    
    # Remove temp files
    [[ -n "$APEX_TMP" && -d "$APEX_TMP" ]] && rm -rf "$APEX_TMP"
    
    # Remove test files we may have created
    rm -f /tmp/.apex_test_* /dev/shm/.apex_test_* 2>/dev/null
}

trap cleanup_apex INT TERM EXIT
```

---

## 8. The "Partial Results" Problem

**Problem:** If APEX is killed mid-run, partial results could mislead.
"Layer 1 found nothing" might mean "layer 1 was killed, not that layer 1 is clean."

**Solution:** Atomic output + clear status markers:
```bash
# Write results only when COMPLETE — not incrementally
# Each layer writes to temp, final output written atomically at end

finalize_output() {
    local final_file="/dev/shm/apex_results_$(date +%s).txt"
    
    {
        echo "APEX RESULTS — $(date)"
        echo "Layers completed: ${COMPLETED_LAYERS[*]}"
        echo "Layers pending: ${PENDING_LAYERS[*]}"
        echo "---"
        cat "$APEX_TMP/confirmed_chains"
        echo "---"
        echo "STATUS: COMPLETE — all requested layers finished"
    } > "$final_file"
    
    echo "[APEX] Results written to: $final_file"
    cat "$final_file"
}

# If killed before finalize_output: no output file = user knows it was incomplete
# If completed: output file with explicit "STATUS: COMPLETE" marker
```

---

## 9. Error Messages Reference

| Error | Cause | Solution |
|-------|-------|---------|
| `sudo: a password is required` | sudo needs password | Note and move on, try credential DNA |
| `find: '/proc/...': Permission denied` | Expected — normal | Use `2>/dev/null` (already in safe_find) |
| `getcap: not found` | Not installed | Use /proc/*/status CapEff fallback |
| `timeout: command not found` | Old system/BusyBox | Use background+kill fallback |
| `stat: illegal option -- c` | BSD stat | Use fallback format |
| `systemctl: command not found` | Not systemd | Use sysvinit/cron fallback |
| `debsums: command not found` | Not Debian | Use rpm -Va or timeline fallback |
| `No space left on device` | Full filesystem | Use memory-only mode |
| `bash: /dev/shm: Read-only file system` | Restricted /dev/shm | Use /tmp fallback |
| `ulimit: fork: resource temporarily unavailable` | Fork limit hit | Disable parallel mode |
