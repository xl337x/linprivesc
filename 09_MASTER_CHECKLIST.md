# APEX — Master Pre-Build Checklist
## Everything That Must Work Before Code Is Written

---

## SECTION 1: Pre-Flight Checks (Must All Pass Before Detection Begins)

```
ENVIRONMENT DETECTION:
  □ OS and distro identified (os-release, uname)
  □ Kernel version captured
  □ Architecture identified (x86_64, arm64, i686, etc.)
  □ Init system identified (systemd/sysvinit/openrc/runit/unknown)
  □ Package manager identified (dpkg/rpm/apk/pacman/none)
  □ Shell type identified (bash/sh/dash/ash/restricted)
  □ Are we in restricted shell? (test cd, PATH change, /redirect)

SECURITY LAYER DETECTION:
  □ SELinux status (enforcing/permissive/disabled)
  □ AppArmor status (enabled/disabled)
  □ Seccomp status (/proc/self/status Seccomp field)
  □ Grsecurity/PaX check (uname -r grep)

CONTAINER DETECTION:
  □ /.dockerenv exists? → Docker
  □ /proc/1/cgroup contains docker/lxc/containerd?
  □ Kubernetes service account token present?
  □ Are we PID 1 namespace? (/proc/1/sched)
  □ Mount namespace same as PID 1?

RESOURCE CHECKS:
  □ Available memory (< 50MB = limit depth)
  □ Fork limit (ulimit -u)
  □ Writable temp location found (/dev/shm → /tmp → /var/tmp → $HOME)
  □ Disk space for results

BINARY AVAILABILITY CHECK:
  □ timeout (or busybox timeout or manual fallback)
  □ getcap (or /proc/*/status fallback)
  □ strings (or python3/objdump fallback)
  □ ldd (or scanelf fallback)
  □ debsums (or rpm -Va or timeline fallback)
  □ systemctl (or sysvinit fallback)
  □ ss (or netstat or /proc/net fallback)
  □ find -writable (or -perm -o+w fallback)
  □ stat -c (or BSD stat or ls fallback)
  □ python3 / python2 / perl / awk (execution primitives)
  □ base64 (transfer method — POSIX, always present)

EXECUTION PRIMITIVE TEST:
  □ Test direct execution in /tmp (place binary, chmod +x, run)
  □ Test direct execution in /dev/shm
  □ Test interpreter execution (python3/perl/awk)
  □ Test memfd_create via python3
  □ Test /dev/tcp connectivity
  □ Record ALL working primitives for exploit generation
```

---

## SECTION 2: Engine 1 Mapper Checklist

```
IDENTITY:
  □ id (all groups — not just primary)
  □ whoami
  □ All /etc/passwd entries (user list for crontab checks)
  □ /etc/group (group memberships)

SUDO:
  □ sudo -n -l (NON-INTERACTIVE — NEVER WITHOUT -n)
  □ Parse commands (NOPASSWD)
  □ Parse env_keep lines (CRITICAL — often missed)
  □ Parse env_check lines
  □ Check sudo version (Baron Samedit)
  □ Check /etc/sudoers if readable
  □ Check /etc/sudoers.d/* if readable

SUID/SGID:
  □ find / -perm -4000 (SUID) with proper exclusions
  □ find / -perm -2000 (SGID) — students forget this
  □ getcap -r / OR /proc/*/status CapEff fallback
  □ Check capabilities on running processes too

CRON (ALL SOURCES):
  □ /etc/crontab — READ THE FULL FILE INCLUDING PATH LINE AT TOP
  □ /etc/cron.d/* — all files
  □ /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*
  □ /var/spool/cron/crontabs/* (ALL users, not just current)
  □ crontab -l (current user)
  □ For each user in /etc/passwd: attempt crontab -l -u $user
  □ Crontab-UI files if present (/etc/crontab-ui)

SYSTEMD:
  □ systemctl list-timers --all (HIDDEN CRONS)
  □ systemctl list-units --type=service --all
  □ systemctl list-sockets --all
  □ For each service: systemctl cat → read EnvironmentFile, ExecStart
  □ find /etc/systemd /usr/lib/systemd -writable -type f
  □ Check /etc/systemd/system/*.service for custom services

PROCESSES (STATIC + DYNAMIC):
  □ ps aux OR /proc/*/cmdline enumeration
  □ Root processes specifically: uid=0 in /proc/*/status
  □ Inline pspy: monitor /proc for 3 minutes (background)
  □ Save ALL new processes seen during monitoring

WRITE MAP:
  □ All writable files (find -writable or fallback)
  □ All writable directories
  □ /etc/ld.so.preload — existence + permissions (CRITICAL)
  □ /etc/ld.so.conf.d/* — all library path configs
  □ All .pth files (find / -name "*.pth")
  □ Python site-packages directories
  □ Python sys.path directories
  □ Perl @INC directories
  □ Node.js NODE_PATH directories
  □ All writable .so files

GROUPS (ALL — NOT JUST KNOWN):
  □ High-value known: docker, lxd, lxc, disk, shadow, adm, kmem, tape, video
  □ ALL other non-standard groups: find writable files owned by that group
  □ Screen/tmux group access
  □ Any group that owns a service socket
  □ Shared group membership with root processes

NFS:
  □ /etc/exports readable?
  □ showmount -e localhost
  □ Any no_root_squash entries?
  □ mount | grep nfs

SCREEN/TMUX SESSIONS:
  □ screen -ls (list sessions)
  □ tmux list-sessions
  □ find /tmp -name ".screen*" -o -name "tmux-*" type socket
  □ Who owns those sessions? Can we attach?

INTEGRITY:
  □ debsums -c (Debian) OR rpm -Va (RHEL)
  □ find -newer /proc/1/exe (timeline — adds after boot)
  □ find /usr/local/bin /usr/local/sbin -type f -executable (custom binaries)
  □ Check size anomaly on suspicious binaries

NETWORK/SERVICES:
  □ ss -tlnp / netstat -tlnp (listening ports)
  □ ss -xlnp (unix sockets)
  □ Any internal services accessible that aren't in external scan?

KERNEL/VERSION:
  □ uname -r
  □ sudo --version
  □ pkexec --version
  □ dpkg -l sudo | grep version
  □ dmesg | grep -i "CVE\|security\|patch"

CREDENTIALS:
  # Full implementation: 13_CREDENTIAL_AND_SECRET_DETECTION.md

  SSH:
  □ All private keys (id_rsa, id_ed25519, id_ecdsa, *.pem) — encrypted or cleartext?
  □ find / -name "id_*" -not -name "*.pub" — keys in non-standard locations
  □ authorized_keys WRITABLE → inject our pubkey → 95% confidence path
  □ .ssh/ dir writable (no authorized_keys) → create it → 90%
  □ Home dir writable → create .ssh/authorized_keys → 85%
  □ ROOT authorized_keys writable → 99% CRITICAL — generate exploit immediately
  □ known_hosts → extract all hosts as pivot map
  □ .ssh/config → extract HostName, IdentityFile, ProxyJump
  □ SSH agent sockets in /tmp /run/user → accessible? → hijack another user's keys
  □ /etc/ssh/ssh_host_*_key readable → server impersonation possible

  HISTORY (content analysis, not just dump):
  □ ALL history: bash/zsh/sh/fish/mysql/psql/python/node/irb for current user + all homes
  □ grep -E "mysql.*-p|sshpass.*-p|curl.*-u|PASSW|passw|KEY=|TOKEN=|chpasswd"
  □ Extract actual password values from matched commands

  PROCESS ENVIRONMENTS (300+ patterns):
  □ /proc/*/environ → tr '\0' '\n' → grep PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|
    AUTH|CREDENTIAL|DB_PASS|DATABASE_URL|PRIVATE_KEY|ACCESS_KEY|
    AWS_|GCP_|AZURE_|GITHUB_TOKEN|GITLAB_TOKEN|SLACK_TOKEN|STRIPE_|TWILIO_

  CLOUD:
  □ AWS: ~/.aws/credentials + ~/.aws/config + env AWS_ACCESS_KEY_*
  □ AWS IMDS: curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
  □ GCP: find *.json → grep "service_account" + IMDS metadata.google.internal
  □ Azure: ~/.azure/azureProfile.json + IMDS http://169.254.169.254/metadata/
  □ Terraform: find *.tfstate → extract password fields; *.tfvars → grep creds
  □ HashiCorp Vault: ~/.vault-token

  CONTAINERS:
  □ Docker: ~/.docker/config.json → base64-decode auth field
  □ Kubernetes: ~/.kube/config + /var/run/secrets/kubernetes.io/serviceaccount/token

  DATABASES:
  □ MySQL: ~/.my.cnf, /etc/mysql/debian.cnf (often has root password)
  □ PostgreSQL: ~/.pgpass
  □ MongoDB: test unauthenticated connection 127.0.0.1:27017
  □ Redis: PING 127.0.0.1:6379 — no auth = CONFIG SET = write files as redis user
  □ SQLite: find *.db *.sqlite → extract password/hash columns

  GIT:
  □ find all .git dirs → git remote -v (embedded creds in URL?)
  □ git log --all --full-history → commits with password|secret|token
  □ git show $hash → actual credential content from matching commits
  □ git stash show -p → uncommitted work with credentials

  PASSWORD MANAGERS:
  □ find *.kdbx *.kdb (KeePass) — also detect running KeePass process
  □ ~/.password-store/*.gpg (pass/gopass)
  □ ~/.vault-token

  NETWORK/APP CREDENTIALS:
  □ ~/.netrc, ~/.pgpass, ~/.curlrc, ~/.wgetrc
  □ /etc/NetworkManager/system-connections/ → grep psk= password=
  □ /etc/fstab → credentials= references → read SMB credential files
  □ Web configs: wp-config.php, .env, .env.local, settings.py, database.yml,
    config.php, configuration.php, database.php, config/secrets.yml,
    application.properties, config/parameters.yml, hibernate.cfg.xml
  □ Jenkins: find credentials.xml → extract secrets
  □ Ansible: *.vault files, inventory with ansible_password
  □ PHP files /var/www: grep $password = "..."

  SSL/TLS:
  □ find *.pem *.key *.p12 *.pfx *.jks *.ovpn → check PRIVATE KEY header
  □ .ovpn: grep auth-user-pass, embedded credentials

  HOT FILES (check every home dir + /root):
  □ .aws/credentials, .kube/config, .docker/config.json, .vault-token
  □ .netrc, .pgpass, .git-credentials, .pypirc, .npmrc
  □ .kdbx, .htpasswd, .erlang.cookie, .google_authenticator
  □ .azure/, .gnupg/, .ssh/, .ovpn

  PASSWORD FILES:
  □ /etc/passwd READABLE (user list, old hash in field 2)
  □ /etc/passwd WRITABLE → 99% CRITICAL (add root user instantly)
  □ /etc/shadow READABLE → crack root hash
  □ /etc/shadow WRITABLE → 99% CRITICAL (replace root hash)
  □ Backup files: *.bak *.old *.orig *~ *.backup

  CREDENTIAL DNA (run after every found credential):
  □ Generate mutations: original, Capitalized, UPPER, lower, +1, +123, +!, leet
  □ Test via su - root (expect), su - user (expect)
  □ Test via SSH localhost (sshpass)
  □ Test MySQL root, PostgreSQL postgres
  □ Register 99% finding for any valid root credential
```

---

## SECTION 3: Engine 2 Deep Reader Checklist

```
FOR EACH ITEM IN EXECUTION GRAPH:
  □ Can we read it? (if NOT readable → HIGH SIGNAL, log it)
  □ Is it itself writable? (direct exploit)
  □ Is its PARENT DIRECTORY writable? (can replace it)
  □ Shell scripts:
    □ source/dot commands → check if target writable
    □ commands without / → PATH hijack check
    □ eval statements → trace variable source
    □ output redirects → check if destination writable
    □ config file reads → check if config writable
    □ variable-as-command patterns
  □ Python scripts:
    □ all import statements → module path writable?
    □ all .pth files in sys.path → writable?
    □ subprocess/os.system calls → PATH-relative?
    □ exec()/eval() → source injectable?
    □ yaml.load/pickle.load → deserialization sinks
  □ Compiled binaries:
    □ strings → absolute paths writable?
    □ strings → relative commands (PATH hijack)?
    □ ldd → libraries writable?
    □ library DIRECTORIES writable?
  □ Systemd units:
    □ ExecStart binary/script readable?
    □ EnvironmentFile writable?
    □ WorkingDirectory writable?
    □ User= field (who runs this?)
  □ Cron files:
    □ PATH= line at top → check each dir
    □ Commands without full path → PATH hijack
    □ Called scripts → read them (recursive)
  □ CHAIN DEPTH: follow up to 5 hops, never infinite
  □ ALREADY_READ tracker: don't re-read same file
```

---

## SECTION 4: Engine 3 Reasoner Checklist

```
CHAIN BUILDING:
  □ All findings from Engines 1+2 collected
  □ Each finding has: type, path, chain_description, base_confidence
  □ Multi-lens bonus applied (+15 for each additional confirming lens)
  □ MAC active penalty applied if applicable (-15)
  □ Timing dependency penalty applied if applicable (-10)
  □ Sorted by confidence descending

FOR EACH CONFIRMED CHAIN:
  □ Trap warning assigned from trap database
  □ Verify command generated (quick pre-exploit check)
  □ Exploit command generated (adapted to available exec primitives)
  □ Complexity rating assigned
  □ Time estimate included
  □ Fallback command if primary fails

OUTPUT:
  □ Header block (environment summary)
  □ Confirmed paths in confidence order (max 5 shown)
  □ Trap warnings per path
  □ Layer status (what ran, what's pending)
  □ Pivot guidance if all paths fail
  □ Never outputs "nothing found" — always outputs next layer advice
```

---

## SECTION 5: Robustness Checklist

```
EVERY COMMAND:
  □ stdin redirected from /dev/null (no password prompts)
  □ stderr redirected to /dev/null or log file (no noise)
  □ Wrapped in timeout (no hanging — ever)
  □ Running in subshell (failures isolated)
  □ Returns 0 to parent (script never dies from command failure)
  □ Output capped with head -N (no memory explosion)
  □ All filenames double-quoted (no injection)
  □ All iterations use null-terminated form (-print0 + read -d '')

PARALLELISM:
  □ Independent scans run in parallel (&)
  □ Global watchdog per phase (kills stragglers)
  □ Results written to temp files (not accumulated in memory)
  □ All parallel jobs cleaned up on exit (trap cleanup INT TERM EXIT)

TEMP FILES:
  □ Prefer /dev/shm (RAM, no disk write)
  □ Fall back to /tmp if /dev/shm unavailable
  □ All temp files cleaned up on exit
  □ Results written atomically at end (not incrementally)
  □ Partial results never shown (killed mid-run = no output)
```

---

## SECTION 6: Machine Coverage Validation Checklist

Verified against all 84 machines in the HTML database.

```
SUDO VECTORS (40% of machines):
  □ NOPASSWD command → COVERED (sudo -n -l parse)
  □ env_keep LD_PRELOAD → COVERED (env_keep parser)
  □ Wildcard * injection → COVERED (wildcard detector)
  □ Script calling PATH-relative binary → COVERED (deep reader)
  □ sudo /usr/bin/env bypass → COVERED (env binary detection)
  □ Exception bypass (!/bin/bash) → COVERED (exception pattern)
  □ Bash comparison glob (Codify) → COVERED (script deep read flags)

SUID/CAPABILITY VECTORS (15%):
  □ Standard GTFOBins SUID → COVERED
  □ Custom SUID binary → COVERED (strings analysis + PATH check)
  □ Capabilities (cap_setuid) → COVERED (getcap + /proc fallback)
  □ SUID with PATH hijack → COVERED (strings finds relative calls)
  □ SGID escalation → COVERED (find -perm -2000)

CRON VECTORS (12%):
  □ Writable cron script → COVERED
  □ Cron PATH variable hijack → COVERED (first check in cron parser)
  □ Wildcard injection in cron → COVERED
  □ Systemd timer instead of cron → COVERED (list-timers)
  □ Script in chain writable → COVERED (deep reader)

CONTAINER/GROUP VECTORS (8%):
  □ docker group → COVERED
  □ lxd group (Tabby) → COVERED
  □ disk group (Extplorer) → COVERED
  □ shadow group → COVERED
  □ adm group → COVERED
  □ Non-standard groups → COVERED (check ALL groups)

CREDENTIAL VECTORS (10%):
  □ Config file password → COVERED (credential hunt)
  □ History file password → COVERED
  □ Process environment password → COVERED (/proc/*/environ)
  □ Database file credential → COVERED
  □ Credential reuse (Credential DNA) → COVERED

WRITABLE FILE VECTORS (10%):
  □ Direct writable script in cron/service → COVERED
  □ Writable config sourced by root → COVERED (deep reader)
  □ Writable library in load path → COVERED
  □ /etc/ld.so.preload writable → COVERED (critical priority)
  □ Python .pth file writable → COVERED
  □ EnvironmentFile writable → COVERED (unit deep reader)
  □ Parent directory writable (can replace file) → COVERED

APPLICATION-SPECIFIC VECTORS (5%):
  □ KeePass memory dump (Keeper) → Layer 10 flags KeePass process
  □ Redis CONFIG SET (Readys) → Layer 10 flags Redis port 6379
  □ Jenkins credential (Builder) → Layer 10 flags Jenkins
  □ Screen/tmux session hijack (BankSmarter) → COVERED (session detection)
  □ Git log credentials (Editorial) → COVERED (credential hunt)
  □ Internal service command injection (Sea) → Layer 10 flags port 8080
  □ Grav/CMS scheduler (Astronaut) → Layer 10 flags CMS ports

KERNEL CVE VECTORS:
  □ DirtyCow check → COVERED (kernel version + CVE database)
  □ Dirty Pipe check → COVERED
  □ PwnKit (pkexec) check → COVERED
  □ Baron Samedit (sudo heap) → COVERED (sudo version check)

SPECIAL CASES:
  □ BankSmarter tmux bankers group → COVERED (ALL groups checked)
  □ Nibbles sudo writable script → COVERED
  □ Sunday /etc/shadow readable → COVERED (credential hunt)
  □ Poison VNC → Layer 10 flags VNC port
  □ Irked SUID viewuser calling /tmp/update → COVERED (strings)
  □ Broker sudo nginx config write → COVERED (sudo parser + nginx binary)
  □ Tartar sauce multi-hop (tar→systemctl→service write) → COVERED (deep reader chain)
```

---

## SECTION 7: Final Build Gate

**ALL items below must be TRUE before first release:**

```
□ Pre-flight runs in < 5 seconds
□ Layer 1-3 complete in < 90 seconds on standard system
□ No command can hang the script (all have timeout + /dev/null stdin)
□ Script handles SIGINT cleanly (temp files removed)
□ Script handles crash in any function (always continues)
□ Script works on bash 3.x AND bash 4.x AND sh (POSIX)
□ Script works on Debian/Ubuntu AND RHEL/CentOS AND Alpine
□ Script works with AND without: getcap, debsums, systemctl, strings
□ Output is always actionable (never "nothing found" without next steps)
□ No password prompts ever occur (all stdin from /dev/null)
□ All temp files go to /dev/shm by default, /tmp fallback
□ All temp files cleaned up on any exit condition
□ Tool tested against 5+ different machine types
□ Confidence scores validated against known machine solutions
□ Trap warnings match real failure modes from actual CTF experience
```
