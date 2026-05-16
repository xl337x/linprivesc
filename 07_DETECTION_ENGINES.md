# APEX — Detection Engines Deep Design
## Engine 1: Mapper | Engine 2: Reader | Engine 3: Reasoner

---

## Engine 1: The Mapper — Complete Data Collection

The Mapper collects ALL data needed for analysis. No analysis happens here.
Pure data collection, maximally parallel, all isolated, all with timeouts.

### Complete Data Collection Checklist

```
IDENTITY AND CONTEXT:
  [✓] id — current user, groups (ALL groups including non-standard ones)
  [✓] whoami
  [✓] hostname
  [✓] uname -a (OS, kernel, arch)
  [✓] cat /etc/os-release
  [✓] cat /proc/version
  [✓] uptime (how long running — affects what processes are present)

SUDO:
  [✓] sudo -n -l (non-interactive — NEVER without -n)
  [✓] Parse: commands, env_keep, env_check, env_reset, requiretty
  [✓] sudo version: sudo --version (Baron Samedit CVE check)
  [✓] cat /etc/sudoers (if readable)
  [✓] cat /etc/sudoers.d/* (if readable)

SUID/SGID/CAPABILITIES:
  [✓] find / -perm -4000 (SUID)
  [✓] find / -perm -2000 (SGID) — students always forget this
  [✓] getcap -r / (capabilities — students always forget this)
  [✓] /proc/*/status CapEff fallback if getcap missing

CRON:
  [✓] cat /etc/crontab — ESPECIALLY the PATH= line at top
  [✓] ls -la /etc/cron.d/ && cat /etc/cron.d/*
  [✓] cat /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*
  [✓] cat /var/spool/cron/crontabs/* (all user crontabs)
  [✓] crontab -l (current user)
  [✓] for each user in /etc/passwd: crontab -l -u $user

SYSTEMD:
  [✓] systemctl list-timers --all (timers = hidden crons)
  [✓] systemctl list-units --type=service --all
  [✓] systemctl list-sockets --all (socket activation)
  [✓] For each service: systemctl cat $service (read unit file)
  [✓] Find writable unit files: find /etc/systemd /usr/lib/systemd -writable

SERVICES/PROCESSES:
  [✓] ps aux (static snapshot)
  [✓] /proc/*/status + /proc/*/cmdline + /proc/*/exe (comprehensive)
  [✓] Inline pspy (3 minutes dynamic monitoring in parallel)
  [✓] /etc/init.d/* (if sysvinit)
  [✓] ls /etc/service/ /var/service/ (if runit)

WRITE MAP:
  [✓] find / -writable (all writable files)
  [✓] find / -writable -type d (writable directories → can replace files inside)
  [✓] cat /etc/ld.so.preload (CRITICAL — writable = instant root for all binaries)
  [✓] find / -name "*.pth" (Python path injection)
  [✓] find / -name "site-packages" -type d (Python site-packages writable?)
  [✓] Python sys.path from python3 -c "import sys; print(sys.path)"
  [✓] Perl @INC: perl -e 'print join("\n", @INC)'
  [✓] Node.js NODE_PATH from env
  [✓] cat /etc/ld.so.conf.d/* (library load paths)
  [✓] find / -name "*.so" -writable (writable shared libraries)

GROUPS (ALL GROUPS — NOT JUST KNOWN ONES):
  [✓] id (all groups)
  [✓] For EACH group: find / -group $group -writable 2>/dev/null
  [✓] Known high-value groups: docker, lxd, lxc, disk, shadow, adm, audio, video, tape, kmem, wheel
  [✓] Unknown groups: check if group has access to any running service socket or special file
  [✓] groups in /etc/group: check who else is in each group (shared group with root process)

NFS:
  [✓] cat /etc/exports
  [✓] showmount -e localhost
  [✓] mount | grep nfs

NETWORK (for internal services, application layer):
  [✓] ss -tlnp (listening TCP)
  [✓] ss -ulnp (listening UDP)
  [✓] ss -xlnp (Unix sockets)
  [✓] ip route / route (routing table)
  [✓] cat /etc/hosts (internal hostnames)

CREDENTIALS:
  # Full implementation spec: 13_CREDENTIAL_AND_SECRET_DETECTION.md

  SSH ARTIFACTS:
  [✓] find all home dirs + /root for .ssh/ directory
  [✓] SSH private keys: id_rsa, id_ed25519, id_ecdsa, id_dsa, id_xmss — check if encrypted
  [✓] find / -name "id_*" -not -name "*.pub" — all private keys system-wide
  [✓] find / -name "*.pem" -o "*.key" → grep "PRIVATE KEY" header
  [✓] authorized_keys WRITABLE → register 95% finding + generate inject exploit
  [✓] .ssh/ dir writable (no authorized_keys) → can CREATE it → 90% finding
  [✓] home dir writable → can create .ssh/authorized_keys → 85% finding
  [✓] ROOT authorized_keys writable → 99% CRITICAL
  [✓] known_hosts → extract hostnames/IPs as pivot map
  [✓] .ssh/config → extract Host, HostName, IdentityFile, ProxyJump entries
  [✓] SSH agent sockets: find /tmp /run/user -name "agent.*" -type s → accessible?
  [✓] SSH_AUTH_SOCK hijack: if we can r/w another user's agent socket → use their keys
  [✓] SSH host keys /etc/ssh/ssh_host_*_key readable → server impersonation signal

  HISTORY FILE CONTENT ANALYSIS (grep, not just dump):
  [✓] ALL history files: bash/zsh/sh/ash/fish/mysql/psql/python/node/irb/sqlite
  [✓] All home dirs + /root history files
  [✓] grep -E "mysql.*-p|sshpass.*-p|curl.*-u|PASSW|passw|KEY=|TOKEN=|BEARER=|chpasswd"
  [✓] Extract inline passwords from matched commands
  [✓] Log files: /var/log/auth.log for credential patterns

  PROCESS ENVIRONMENTS (300+ variable name patterns):
  [✓] /proc/*/environ for ALL processes
  [✓] Pattern: PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|AUTH|CREDENTIAL|DB_PASS|
               DATABASE_URL|PRIVATE_KEY|ACCESS_KEY|AWS_|GCP_|AZURE_|
               GITHUB_TOKEN|GITLAB_TOKEN|SLACK_TOKEN|STRIPE_|TWILIO_|HEROKU_API
  [✓] Note UID of owning process — root process env vars highest value

  CLOUD CREDENTIALS:
  [✓] AWS: ~/.aws/credentials, ~/.aws/config, env AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY
  [✓] AWS IMDS: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
  [✓] GCP: find *.json → grep '"type": "service_account"'
  [✓] GCP IMDS: curl -H "Metadata-Flavor: Google" http://metadata.google.internal/...
  [✓] Azure: ~/.azure/azureProfile.json, ~/.azure/msal_token_cache.bin
  [✓] Azure IMDS: curl -H "Metadata:true" http://169.254.169.254/metadata/instance
  [✓] Terraform: find *.tfstate → extract password fields; find *.tfvars → grep creds
  [✓] HashiCorp Vault: ~/.vault-token

  CONTAINER CREDENTIALS:
  [✓] Docker: ~/.docker/config.json → base64-decode "auth" field
  [✓] Kubernetes: ~/.kube/config → extract tokens and certs
  [✓] K8s ServiceAccount: /var/run/secrets/kubernetes.io/serviceaccount/token
  [✓] Container env vars: grep all running container environments for cred patterns

  DATABASE CREDENTIALS:
  [✓] MySQL: ~/.my.cnf, /root/.my.cnf, /etc/mysql/my.cnf, /etc/mysql/debian.cnf
  [✓] PostgreSQL: ~/.pgpass, /root/.pgpass, pg_hba.conf trust entries
  [✓] MongoDB: test unauthenticated connection to 127.0.0.1:27017
  [✓] Redis: test PING to 127.0.0.1:6379 — no-auth = CONFIG SET = file write as redis
  [✓] SQLite: find *.db *.sqlite → open and extract password/hash columns

  GIT REPOSITORY MINING:
  [✓] find all .git directories accessible to us
  [✓] git remote -v → grep for https://user:pass@... in remote URLs
  [✓] git log --all --full-history → commits with password|secret|token in message
  [✓] git show $hash → extract actual credential lines from matching commits
  [✓] git stash show -p → grep stash content for credentials
  [✓] .git/config → check remote URL for embedded credentials

  PASSWORD MANAGERS:
  [✓] find *.kdbx *.kdb (KeePass databases)
  [✓] detect running KeePass/KeePassXC process → flag /proc/PID/mem dump path
  [✓] ~/.password-store/*.gpg (pass/gopass entries)
  [✓] ~/.vault-token (HashiCorp Vault)
  [✓] ~/.config/op/config (1Password CLI)

  NETWORK AND APPLICATION CREDENTIALS:
  [✓] ~/.netrc, /root/.netrc (FTP/HTTP basic auth — machine/login/password)
  [✓] ~/.pgpass (PostgreSQL password file)
  [✓] ~/.curlrc (may contain -u user:pass or --header Authorization:)
  [✓] ~/.wgetrc (http_user/http_password)
  [✓] /etc/NetworkManager/system-connections/ → grep psk= password= (WiFi passwords)
  [✓] /etc/fstab → grep credentials= → read referenced SMB credential files
  [✓] Web app configs: wp-config.php, configuration.php, config.php, database.php,
      .env, .env.local, .env.production, settings.py, database.yml, database.yaml,
      config/secrets.yml, config/application.yml, application.properties,
      config/parameters.yml, hibernate.cfg.xml
  [✓] Jenkins: find credentials.xml → extract <secret> <password> <apiToken>
  [✓] Ansible: find *.vault, vault.yml → flag as encrypted secrets
  [✓] Ansible inventory: grep ansible_ssh_pass, ansible_become_pass, ansible_password
  [✓] PHP files in /var/www /srv /opt → grep $password = "..." patterns
  [✓] Rails: find secrets.yml, master.key

  SSL/TLS PRIVATE KEYS:
  [✓] find *.pem *.key *.p12 *.pfx *.jks *.ovpn — check for PRIVATE KEY header
  [✓] .ovpn: grep auth-user-pass, username, password entries
  [✓] Java keystores (.jks .p12): flag for manual extraction

  HOT FILES LIST (check in every home dir + /root):
  [✓] .aws/credentials, .kube/config, .docker/config.json, .vault-token
  [✓] .netrc, .pgpass, .git-credentials, .gitconfig (credential.helper)
  [✓] .pypirc, .npmrc, .wgetrc, .curlrc
  [✓] .kdbx, .htpasswd, .erlang.cookie, .google_authenticator
  [✓] .gnupg/, .ssh/, .ovpn, .pem files
  [✓] .azure/, .bluemix/, .cloudflared/
  [✓] .roadtools_auth, .msmtprc, .ftpconfig

  PASSWORD FILES:
  [✓] /etc/passwd — readable (user enumeration + hash check for old systems)
  [✓] /etc/passwd — WRITABLE → 99% CRITICAL (add root user, instant root)
  [✓] /etc/shadow — readable → crack root hash
  [✓] /etc/shadow — WRITABLE → 99% CRITICAL (replace root hash)
  [✓] /etc/master.passwd (BSD shadow variant)
  [✓] Backup files: *.bak *.old *.orig *~ *.backup

  CREDENTIAL DNA PROPAGATION (after any credential found):
  [✓] Generate mutations: original, Capitalized, UPPER, lower, +1, +123, +!, leet, stripped
  [✓] Test each mutation: su - root (via expect), su - found_user (via expect)
  [✓] Test each mutation: SSH localhost (via sshpass if available)
  [✓] Test each mutation: MySQL root (mysql -u root -p$mutation)
  [✓] Test each mutation: PostgreSQL (psql -U postgres)
  [✓] Register 99% finding for any valid root credential found

SCREEN/TMUX SESSION DETECTION:
  [✓] screen -ls (list screen sessions)
  [✓] tmux list-sessions (list tmux sessions)
  [✓] find /tmp -name ".screen*" -o -name "tmux-*" (socket files)
  [✓] Check if sessions owned by root or other privileged users
  [✓] Check if we can attach to those sessions

INTEGRITY:
  [✓] debsums -c (Debian — verify all package files)
  [✓] rpm -Va (RHEL — verify all package files)
  [✓] find / -newer /proc/1/exe (files newer than PID 1 = added after boot)
  [✓] find /usr/local/bin /usr/local/sbin -type f -executable (custom binaries)
  [✓] strings on suspicious binaries

KERNEL AND VERSION:
  [✓] uname -r (kernel version)
  [✓] cat /proc/version_signature
  [✓] sudo --version (Baron Samedit check)
  [✓] pkexec --version (PwnKit check)
  [✓] dpkg -l | grep -i sudo (sudo package version)
  [✓] dmesg | grep -i "security\|CVE" (security patches in kernel log)

CONTAINER/NAMESPACE:
  [✓] cat /.dockerenv (Docker)
  [✓] cat /proc/1/cgroup (container cgroup hierarchy)
  [✓] cat /proc/self/status | grep Seccomp
  [✓] cat /proc/self/status | grep CapBnd (bounding set)
  [✓] ls -la /var/run/docker.sock (Docker socket)
  [✓] mount | grep overlay (Docker overlay filesystem)
  [✓] ls /var/run/secrets/kubernetes.io/ (Kubernetes)
  [✓] nsenter --help (namespace escape tool available?)
  [✓] Compare /proc/self/mounts vs /proc/1/mounts (namespace divergence)

MAC POLICY:
  [✓] getenforce (SELinux status)
  [✓] aa-status (AppArmor status)
  [✓] cat /proc/self/attr/current (SELinux context)
  [✓] cat /sys/kernel/security/apparmor/profiles (AppArmor profiles)

D-BUS / INOTIFY:
  [✓] busctl list (D-Bus services including activatable)
  [✓] find /proc/*/fd -lname "inotify" (processes using inotify)
  [✓] find /usr/share/dbus-1 /etc/dbus-1 -name "*.service" (D-Bus service files)
```

---

## Engine 2: The Deep Reader — Content Analysis

The Reader takes items from Engine 1's execution graph and reads their CONTENT.
This is what no other tool does. This is where multi-hop chains are discovered.

### Reading Priority Queue

Items are read in priority order:
1. Scripts directly called by root cron (highest priority)
2. Scripts called by root systemd services
3. Scripts called by SUID binaries
4. Configs sourced by any of the above
5. Libraries loaded by any of the above
6. Anything called from any of the above (recursive)

### Shell Script Analysis

For each shell script in execution graph:
```
PATTERN: source/dot commands     → WHAT_SOURCED is writable?
PATTERN: commands without /      → PATH hijack (check each PATH dir for writability)
PATTERN: eval/exec of variable   → What controls that variable?
PATTERN: $() command substitution used as command → What does that output?
PATTERN: output redirect >>/>    → Is that destination writable?
PATTERN: VARNAME=value; $VARNAME → Is the setter (config file) writable?
PATTERN: import/require/source   → Language-specific module injection
PATTERN: PATH= set in script     → Does the custom PATH have writable dirs?
PATTERN: LD_PRELOAD= set         → Library injection
PATTERN: Python -c or -m         → Arbitrary code possible if script arg controlled
```

### Python Script Analysis

```
PATTERN: import module            → Is module path writable? .pth file inject?
PATTERN: from X import Y          → Same
PATTERN: open(filename)           → Is filename writable? Does filename come from config?
PATTERN: subprocess/os.system     → Is command PATH-relative? Args injectable?
PATTERN: exec()/eval()            → What feeds this? Writable source?
PATTERN: yaml.load()/pickle.load() → Deserialization sink — what's the data source?
PATTERN: __import__()             → Dynamic import — source injectable?
PATTERN: sys.path.insert/append   → PATH manipulation — where is it inserting from?
```

### Compiled Binary Analysis (via strings)

```
PATTERN: /absolute/path           → Check if writable
PATTERN: relative_command         → PATH hijack check
PATTERN: lib*.so                  → Check if that library is writable
PATTERN: /etc/*.conf              → Check if that config is writable
PATTERN: system("cmd")            → Is cmd PATH-relative?
PATTERN: execvp("cmd")            → Is cmd PATH-relative? (yes for execvp)
PATTERN: execve("/path", ...)     → Is /path writable?
PATTERN: dlopen("lib")            → Library injection if relative path
```

### Systemd Unit File Analysis

```
PATTERN: ExecStart=/path          → Read /path deeply
PATTERN: ExecStartPre=/path       → Read /path deeply
PATTERN: ExecStartPost=/path      → Read /path deeply
PATTERN: EnvironmentFile=/path    → Is /path writable? Can we inject LD_PRELOAD?
PATTERN: Environment=VAR=val      → Is VAR LD_PRELOAD, PYTHONPATH, etc.?
PATTERN: WorkingDirectory=/path   → Is /path writable? Library in CWD loaded?
PATTERN: User=username            → What user does this run as?
PATTERN: Group=groupname          → What group?
PATTERN: CapabilityBoundingSet=   → What capabilities are granted?
PATTERN: AmbientCapabilities=     → What ambient capabilities?
```

### Cron File Analysis (Critical Patterns)

```
PATTERN: PATH=/usr/local/bin:...  → Check EACH dir in PATH for writability
                                    If writable: ANY command without full path = hijackable
PATTERN: command (no leading /)   → PATH-relative: check all PATH dirs
PATTERN: /path/script args        → Read script, check if writable
PATTERN: bash -c "cmd"            → What is cmd? Writable source?
PATTERN: * * * * * user cmd       → Who is 'user'? What can they access?
PATTERN: MAILTO=                  → Where do errors go? (usually ignore)
PATTERN: @reboot                  → Runs on reboot — timing dependency
```

---

## Engine 3: The Reasoner — Chain Confirmation and Ranking

The Reasoner takes all findings from Engines 1 and 2 and builds CONFIRMED CHAINS.

### Confidence Scoring Formula

```
base_confidence = vector_base_score (see table below)
+15 if confirmed by package integrity check (debsums/rpm)
+10 if confirmed by timeline analysis (newer than /proc/1/exe)
+20 if deep reader confirms relationship (content analysis)
+15 if multiple independent lenses agree
-20 if single-lens only (may be false positive)
-15 if MAC is active and path may be blocked
-10 if requires waiting (cron/timer — timing dependent)

cap at 99 maximum
```

### Vector Base Scores

| Vector | Base Score | Reasoning |
|--------|-----------|-----------|
| sudo NOPASSWD on shell | 95 | Direct, reliable, immediate |
| sudo NOPASSWD on interpreter | 93 | Direct, reliable |
| /etc/ld.so.preload writable | 99 | Affects ALL binaries |
| SUID shell (bash, sh, dash) | 99 | Direct root |
| docker group + docker running | 98 | Well-established escape |
| lxd/lxc group | 95 | Reliable container escape |
| disk group | 90 | Raw disk access |
| Capabilities cap_setuid | 93 | Direct root equivalent |
| Writable file in cron chain | 85 | Timing dependent |
| Writable cron PATH dir | 88 | PATH hijack reliable |
| NFS no_root_squash | 92 | Well-established |
| sudo env_keep LD_PRELOAD | 90 | Library injection |
| Writable EnvironmentFile | 87 | Service restart needed |
| SUID non-standard binary | 70 | Needs investigation |
| Multi-hop writable chain | 75 | Complex, verify first |
| Kernel CVE | 60 | Version ≠ patch status |

### Trap Warning Database

```
VECTOR: sudo NOPASSWD on /usr/bin/python3
TRAP:   Check env_reset vs env_keep first
        If env_reset: -E flag may not work
        If env_keep += PYTHONPATH: use PYTHONPATH instead
VERIFY: sudo -n -l | grep -E "env_reset|env_keep|PYTHONPATH"
GREEN:  env_keep += PYTHONPATH → easiest path

VECTOR: SUID vim/nano/editor
TRAP:   May be patched version without shell escape
        May be vim-tiny (no Python/Perl support)
        Student spends time → patched → wasted
VERIFY: vim --version | grep +python, or: /usr/bin/vim -c ':q' 2>&1
GREEN:  vim --version shows "+python3" → Python escape works

VECTOR: /etc/crontab with non-standard PATH
TRAP:   Students read the script (line 7) and miss PATH (line 3)
        PATH dir may be writable but command may have full path
VERIFY: grep "^PATH=" /etc/crontab && check each dir
GREEN:  /usr/local/bin writable AND some command in cron lacks full path

VECTOR: Writable EnvironmentFile in systemd unit
TRAP:   Service may not restart automatically
        Restart interval may be long (hours)
        Requires manual restart (if you can: systemctl restart)
VERIFY: systemctl show $service | grep -i "restart\|restart-sec"
GREEN:  Service restarts on failure OR has short restart timer

VECTOR: docker group
TRAP:   Docker daemon may not be running
        Correct: docker group + docker daemon running
VERIFY: docker info >/dev/null 2>&1 && echo "running"
GREEN:  docker info works AND /var/run/docker.sock accessible

VECTOR: NFS no_root_squash
TRAP:   Attacker machine may not have NFS client installed
        May need specific subnet to be allowed
VERIFY: showmount -e TARGET && check /etc/exports IP restriction
GREEN:  No IP restriction OR our IP is in allowed range

VECTOR: Kernel CVE (e.g., DirtyCow)
TRAP:   Version shows vulnerable but patch applied silently
        Exploit compiles but segfaults on patched kernel
        gcc not available to compile
VERIFY: dmesg | grep -i "dirty\|cow\|CVE" (patches logged)
        cat /proc/version_signature (may show patch info)
GREEN:  No patch indication AND kernel is old AND gcc available
```

### Output Generation

```
For each confirmed chain, output:
1. Header: [PATH N] CONFIDENCE: X% — COMPLEXITY: low/medium/high
2. Vector type and description
3. Full chain: what we write → what reads it → who executes → root
4. Trap warning: what maker likely did to waste time
5. Verify command: quick check before spending time
6. Exact exploit command (adapted to available primitives)
7. Time estimate to exploit
```

### Never-Says-Clean Logic

```
if confirmed_chains is empty:
    if layer_1_complete:
        print("Layer 1 (DAC graph) exhausted. No filesystem-based paths found.")
        activate_layer_2()  # Deep credential hunt
    
    if layer_2_complete and no_credentials_found:
        print("Layer 2 (credentials) exhausted. No usable credentials found.")
        activate_layer_3()  # Integrity check
    
    if layer_3_complete:
        print("Layer 3 (integrity) complete.")
        if modified_binaries_found:
            print("Modified binaries detected! These are your target.")
        else:
            activate_layer_4()  # pspy dynamic
    
    [... continues through all 10 layers ...]
    
    if ALL_layers_complete and still_empty:
        print("All automated layers exhausted.")
        print("MANUAL INVESTIGATION REQUIRED:")
        print_open_services()
        print("Check application logic on each service above.")
        print("Also verify: pspy ran for full 3+ minutes? debsums ran clean? getcap ran?")
```
