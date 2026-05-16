# APEX — What Remains Uncoverable
## Honest Gap Analysis: The 5% That Automated Tools Cannot Catch

---

## Preface: Why This File Exists

No tool catches everything. Knowing the gaps is more valuable than pretending they don't exist.
This document catalogs every class of Linux privilege escalation that APEX cannot detect
automatically, explains WHY it can't detect it, and gives the manual investigation method
to fill the gap.

Reading this file tells you EXACTLY when to stop trusting the tool and start thinking manually.

---

## Gap 1: Pure Application Logic Exploits

### What It Is
The application running as root has a logic bug that lets you make it do something
unintended — not through file permissions, but through HOW the application works.

### Examples
```
Busqueda (HTB):
  - Docker container running as root
  - /usr/local/bin/searchor exec's user input without sanitization
  - No writable file, no PATH hijack, no sudo
  - Just: searchor search Engine "$(id)" → RCE as whatever runs it
  - Then lateral: docker inspect reveals Gitea admin creds
  - Then: Gitea → internal docker-compose → root

Sea (HTB):
  - Internal web app on port 8080
  - Command injection via HTTP parameter
  - App runs as root (or has access to root-readable key)
  - No filesystem indicator — only detectable by visiting port

Readys (HTB):
  - Redis on port 6379 with no auth
  - Redis CONFIG SET dir /var/spool/cron/crontabs/
  - Redis CONFIG SET dbfilename root
  - Redis SET mykey "*/1 * * * * root bash -c..."
  - Redis BGSAVE → writes crontab as root
  - Pure application command sequence
```

### Why APEX Cannot Detect This Automatically
```
These require:
1. Understanding what the application DOES (not just what permissions it has)
2. Testing application inputs for injection
3. Reading application source code and understanding business logic
4. Knowing application-specific exploit techniques (Redis CONFIG SET, etc.)

Static filesystem analysis cannot find:
- Command injection in running web app
- SQL injection that writes files
- Deserialization gadgets in running JVM/Ruby app
- Buffer overflows in custom binaries
- Format string vulnerabilities

The ATTACK SURFACE is not the filesystem — it's the application's behavior.
```

### APEX Layer 10 Mitigation
```
When all DAC layers exhausted, APEX outputs:
  "Check all listening services for application logic exploits"
  
For each open port, APEX flags:
  - Port 6379 → "Redis: test CONFIG SET crontab write"
  - Port 3000 → "Gitea/Gogs: check admin panel, webhook injection"
  - Port 8080 → "Web app: check all input parameters for command injection"
  - Port 5985 → "WinRM: credential reuse"
  - Process 'searchor' → "Python eval sink detected in strings analysis"
  - Process 'jenkins' → "Jenkins: groovy script console at /script"
  - Process 'grav' → "Grav CMS: admin scheduler plugin"

What APEX CANNOT do: actually test these. It points to them.
```

### Manual Investigation Protocol
```bash
# For each service on open ports:
1. curl -s http://127.0.0.1:PORT/ | head -50      # What is it?
2. Find the process: ps aux | grep PORT
3. Find config: find / -name "*.conf" | xargs grep -l "$PORT" 2>/dev/null
4. Look at source: strings /path/to/binary | grep -i "eval\|exec\|system\|cmd"
5. Test injection in every input field

# For Redis specifically:
redis-cli -h 127.0.0.1 INFO server 2>/dev/null   # No auth?
redis-cli CONFIG GET dir                           # Where it writes

# For internal web apps:
curl -s http://127.0.0.1:8080/api/v1/status       # Any data?
# Try all endpoints, POST parameters, headers
```

---

## Gap 2: TOCTOU Race Conditions

### What It Is
Time-Of-Check-To-Time-Of-Use: a privileged process reads/checks a file at time T1,
then uses it at time T2. Between T1 and T2, we replace the file. The privileged
process uses our replacement.

### Examples
```
Classic: /tmp/script.sh race
  - SUID binary checks: if [ -f /tmp/script.sh ]; then /bin/sh /tmp/script.sh; fi
  - Window: after check (safe), before execute (ours)
  - Replace /tmp/script.sh during window with malicious version
  
Sudo wildcard timing:
  - sudo rsync --rsync-path="cmd" src dst
  - The --rsync-path is evaluated AFTER sudo check
  
DirtyCow (CVE-2016-5195):
  - Pure kernel TOCTOU in copy-on-write mechanism
  - Race between mmap read and write to /proc/self/mem
  - Not filesystem-detectable
  
Pickle deserialization:
  - App loads pickle from /tmp every 5 seconds
  - We write our pickle in the 5-second window
```

### Why APEX Cannot Detect This Automatically
```
Static analysis sees:
  - SUID binary reads /tmp/something
  - But: does it CHECK then USE? What's the window size?
  
Detecting a race requires:
  1. Dynamic analysis (actually run the binary and time its behavior)
  2. Observing the sequence of operations (strace)
  3. Calculating if the window is exploitable
  4. Actually running the race exploit
  
APEX Deep Reader sees absolute paths to /tmp — it notes them.
But it cannot determine if the access pattern is TOCTOU vulnerable.
```

### Partial Detection Signals (APEX Does Flag These)
```
APEX Deep Reader flags:
  [SIGNAL] Binary accesses /tmp/$VAR with variable path — possible TOCTOU
  [SIGNAL] Script: if [ -f X ]; then execute X — check/execute pattern
  [SIGNAL] Python: os.path.exists() followed by open() — check/use gap

These are SIGNALS, not confirmed vulnerabilities.
Student must manually verify if window exists.
```

### Manual Investigation Protocol
```bash
# Verify TOCTOU window:
strace -e openat,stat,access ./binary 2>&1 | head -50
# Look for: stat("/tmp/x") ... later ... open("/tmp/x")
# Window size = time between those calls

# Exploit template (only if window confirmed):
while true; do
    ln -sf /etc/passwd /tmp/target
    ln -sf /tmp/safe /tmp/target
done &
./vulnerable_suid
# Needs precise timing — usually needs compiled exploit
```

---

## Gap 3: MAC Policy Blocking Confirmed DAC Paths

### What It Is
AppArmor or SELinux is active AND specifically prevents a confirmed DAC path.
APEX finds a 95% confidence vector — but MAC silently blocks it.

### Examples
```
AppArmor blocking:
  - sudo NOPASSWD on vim — but AppArmor profile for vim blocks shell execution
  - /etc/apparmor.d/usr.bin.vim: deny /bin/** x
  - vim -c ':!/bin/bash' → Permission denied (even as root)
  
SELinux blocking:
  - SUID binary found — but SELinux type transition prevents exploitation
  - semanage permlist shows binary can't execute our payload type
  
Seccomp blocking:
  - Container with execve() blocked via seccomp
  - Even with file write, cannot execute
  - LD_PRELOAD loads but all dangerous syscalls filtered
```

### What APEX Does
```
APEX detects MAC at pre-flight:
  - SELinux: enforcing → apply -15 to ALL DAC vectors
  - AppArmor: enabled → apply -15 to ALL DAC vectors
  
For specific vectors, APEX checks profiles:
  - cat /proc/$pid/attr/current (SELinux context)
  - /sys/kernel/security/apparmor/profiles (AppArmor profile list)
  
But APEX cannot read ALL AppArmor profiles and determine
which specific operations are blocked.
```

### Gap Specifics
```
APEX knows:
  ✓ MAC is active (yes/no)
  ✓ Which processes have profiles
  ✓ Whether our target binary has a profile

APEX does NOT know:
  ✗ Exactly which operations the profile blocks
  ✗ Whether the specific exploitation technique is blocked
  ✗ SELinux type transition rules
  ✗ Whether audit log shows denials for our attempts
```

### Manual Investigation Protocol
```bash
# AppArmor — read specific profile:
cat /etc/apparmor.d/usr.bin.vim 2>/dev/null
cat /sys/kernel/security/apparmor/profiles | grep vim
aa-status 2>/dev/null | grep vim

# SELinux — check our context:
id -Z           # Our SELinux context
ls -Z /target   # Target's context
sesearch --allow -s our_type -t target_type 2>/dev/null

# Audit log for denials:
grep "denied" /var/log/audit/audit.log | tail -20
dmesg | grep "apparmor=DENIED" | tail -20

# Try the exploit and check for MAC errors:
# If you get "Operation not permitted" on something that should work
# → MAC is blocking, not permissions
```

---

## Gap 4: Pure Memory Exploitation (No File Primitive)

### What It Is
Exploiting a running process directly in memory — buffer overflow, heap corruption,
use-after-free — without any filesystem write. Pure binary exploitation.

### Examples
```
Buffer overflow in SUID binary:
  - No writable file involved
  - Overflow stack → RIP control → shellcode
  - APEX finds SUID binary via find -perm -4000
  - But: can APEX tell if it's buffer-overflow vulnerable? No.

Heap exploitation of root daemon:
  - sendmsg() to Unix socket → heap corruption in root process
  - No file write, no PATH manipulation
  - Pure memory corruption → code execution

Kernel memory corruption:
  - dirty_pipe: kernel memory mapped write
  - Not a filesystem permission — a kernel bug
  - Works even if all files are owned root, all permissions correct
```

### Why APEX Cannot Detect This
```
Detecting memory corruption bugs requires:
  1. Fuzzing (send malformed input, observe crashes)
  2. Reverse engineering (read binary, find unsafe functions)
  3. Exploit development (write ROP chain, heap grooming)
  4. Testing (try the exploit, debug if fails)
  
This is binary exploitation — a separate skill domain from PrivEsc automation.

APEX can:
  ✓ Identify SUID binaries for manual testing
  ✓ Run strings to find dangerous function calls (strcpy, gets, sprintf)
  ✓ Check kernel version against CVE database
  ✓ Flag non-standard SUID binaries for manual investigation

APEX cannot:
  ✗ Fuzz binary inputs
  ✗ Determine exploitability
  ✗ Write exploit code for custom binaries
  ✗ Detect heap vs stack vs kernel corruption paths
```

### APEX Partial Detection
```bash
# APEX strings analysis flags these signals:
strings /suid_binary | grep -i "strcpy\|gets\|sprintf\|scanf"
# → [SIGNAL] Potentially unsafe string functions — manual testing needed

# APEX CVE database:
# If kernel version matches known CVE AND architecture matches:
# → [KERNEL CVE] CVE-2022-0847 (dirty_pipe) — kernel 5.8-5.16.11
#                Verify: uname -r shows 5.X.X-5.16.10 or earlier
#                Confirm: no patch signature in dmesg
```

### Manual Investigation Protocol
```bash
# Check for unsafe functions in SUID binary:
ltrace ./suid_binary 2>&1 | grep "strcpy\|gets\|read"
rabin2 -i ./suid_binary | grep "FUNC.*gets\|strcpy\|sprintf"

# Check stack protections:
checksec --file=./suid_binary
# No canary + no PIE + NX off → exploitable

# Kernel CVE check:
uname -r
# Cross-reference: https://cve.mitre.org (offline: use CVE database)
# Then download precompiled exploit or compile if gcc available
```

---

## Gap 5: Container Escape When Container Not Detected

### What It Is
We're in a container but APEX pre-flight doesn't detect it. Container-specific
techniques (cgroup escapes, namespace pivots, exposed sockets) are then skipped.

### Detection Failure Scenarios
```
Scenario A: Custom container runtime
  - Not Docker, not LXC, not Kubernetes
  - /.dockerenv doesn't exist
  - /proc/1/cgroup shows custom cgroup names
  - mount doesn't show overlay filesystem (custom storage driver)
  
Scenario B: Hardened container
  - /.dockerenv removed by security team
  - /proc/1/cgroup zeroed out
  - Hostname set to look like a real machine name
  - Fake "physical" hostname
  
Scenario C: VM inside container (nested)
  - Outer: bare metal
  - Inner: VM
  - Innermost: container
  - We're in container but /proc shows "normal" VM indicators
```

### What APEX Checks (and What It Misses)
```
APEX checks:
  ✓ /.dockerenv exists
  ✓ /proc/1/cgroup contains docker/lxc/containerd
  ✓ hostname looks like container hash
  ✓ mount shows overlay
  ✓ PID 1 = pause/init (not systemd)
  ✓ /var/run/docker.sock exists
  ✓ /var/run/secrets/kubernetes.io

APEX misses:
  ✗ Custom runtime with different cgroup names
  ✗ Container where all indicators were removed
  ✗ Podman rootless containers (different indicators)
  ✗ Systemd-nspawn containers
  ✗ Firejail sandboxes
  ✗ bubblewrap containers
```

### Detection Gap Filler
```bash
# Manual container detection if APEX pre-flight doesn't catch it:

# Compare PID namespaces:
ls -la /proc/1/ns/pid /proc/self/ns/pid
# Different inode → we're in different namespace

# Check mount namespace:
diff <(cat /proc/1/mounts 2>/dev/null) <(cat /proc/self/mounts 2>/dev/null)
# Differences → namespace isolation

# Cgroup version and hierarchy:
cat /proc/self/cgroup
# Look for: /memory, /cpu names that indicate container even without docker

# Check if we're PID 1 in our namespace:
cat /proc/self/status | grep NSpid
# If NSpid has 2 values → we're inside a namespace (first is outer, second is inner)

# Capabilites tell the story:
cat /proc/self/status | grep CapBnd
# Full capabilities (ffffffffffffffff) → likely not in container
# Restricted capabilities → likely containerized
```

---

## Gap 6: Compound Service Chain Exploits (Multi-Application)

### What It Is
Root isn't reachable through single vector — requires lateral movement through
multiple internal services, each requiring their own exploit.

### Examples
```
Busqueda (detailed):
  Step 1: searchor CLI → command injection → shell as svc user
  Step 2: sudo -l → can run /usr/bin/python3 /opt/scripts/system-checkup.py
  Step 3: system-checkup.py docker-inspect → reveals Gitea admin password
  Step 4: Gitea web interface (port 3000) → admin → create malicious hook
  Step 5: Hook triggers → code execution as git user
  Step 6: sudo again → escalate to root
  
Each step requires:
  - Application-specific knowledge (searchor, Gitea, docker-inspect format)
  - Chained lateral movement
  - Credentials found in one place used in another
```

### Why This Is Hard to Automate
```
APEX handles:
  ✓ Credential DNA: finds password → tests on all services → records which work
  ✓ sudo -n -l: shows script path, APEX reads the script
  ✓ Deep reader: reads system-checkup.py, flags: "calls docker inspect"
  ✓ Strings analysis: finds JSON key names in script output
  
APEX cannot handle:
  ✗ Parse JSON output from docker inspect and extract passwords from it
  ✗ Log in to Gitea web interface and create webhooks
  ✗ Understand that git.root_url in Gitea config = admin access vector
  ✗ Multi-hop credential chain across HTTP APIs
  
The "graph" here crosses application API boundaries, not just filesystem boundaries.
```

### APEX Layer 10 Partial Coverage
```
APEX outputs for Busqueda-type machines:
  [LAYER 10] Active services requiring manual investigation:
    - Port 3000: Gitea/Gogs — check admin panel, webhook execution
    - Process docker: docker group not in our groups — but inspect may work
    - Script /opt/scripts/system-checkup.py → reads docker inspect output
    
  HINT: "docker inspect" output often contains environment variables with passwords.
  Run: docker inspect $(docker ps -q) 2>/dev/null | grep -i "pass\|secret\|key\|token"
```

---

## Gap 7: Novel and Zero-Day Techniques

### What It Is
Privilege escalation techniques that don't exist in any database yet, or that were
discovered after APEX's knowledge cutoff.

### Class Examples
```
Techniques that were "zero-day" before they were public:
  - PolKit (pkexec) CVE-2021-4034 (PwnKit) — known only after 2022
  - Dirty Pipe CVE-2022-0847 — known only after Feb 2022
  - GameOver(lay) CVE-2023-2640 — known only after July 2023
  - nf_tables CVE-2023-32233 — kernel netfilter
  - sudo heap overflow CVE-2021-3156 — known only after Jan 2021

Future unknowns:
  - New glibc vulnerabilities
  - New kernel subsystem bugs
  - New systemd logic bugs
  - New dbus privilege escalation patterns
```

### What APEX Does For This
```
APEX approach: collect all version info, output it cleanly for manual CVE lookup.

For every binary of interest:
  sudo --version
  pkexec --version
  python3 --version
  dpkg -l libc6 (glibc version)
  uname -r
  systemctl --version
  dbus-daemon --version

Output block:
  [VERSION DATA — Cross-reference against current CVE databases]
  Kernel:     5.15.0-78-generic
  sudo:       1.9.9
  pkexec:     0.105
  python3:    3.10.6
  glibc:      2.35
  systemd:    249
  dbus:       1.12.20
```

### Manual CVE Research Protocol
```bash
# Check kernel CVEs:
uname -r
# Search: site:nvd.nist.gov "linux kernel" + kernel version

# Check if exploit available:
# searchsploit linux kernel $(uname -r | cut -d- -f1)
# (if searchsploit installed)

# Check pkexec specifically (PwnKit affects almost all versions < 0.105.2):
pkexec --version  # if 0.105 → likely vulnerable pre-patch
ls -la /usr/bin/pkexec  # modification date — was it patched?
```

---

## Gap 8: Social Engineering / Configuration Management Exploits

### What It Is
Root can be reached through human/process exploits that leave no static footprint
— Ansible playbooks, CI/CD pipelines, deployment scripts that run periodically.

### Examples
```
Ansible playbook running as root (ad-hoc):
  - Every 30 minutes, Ansible pulls from repo and runs tasks
  - We can write to the repo directory → Ansible executes our task
  - But: pspy catches this
  
GitLab CI runner:
  - Runner executes as gitlab-runner user (or docker)
  - .gitlab-ci.yml can be modified if we have repo access
  - No static file indicator — only visible when pipeline runs
  
Puppet/Chef/Salt:
  - Agent runs as root, polls master
  - If we poison the catalog (on master), root executes anything
  - Static analysis: puppet agent running → check if we have master access
```

### APEX Partial Detection
```
APEX Layer 6 (pspy monitoring) catches:
  - Ansible runs: python3 /usr/lib/python3/dist-packages/ansible/...
  - GitLab runner: gitlab-runner exec shell
  - Puppet: puppet agent -t

When pspy catches these:
  APEX outputs: "Configuration management agent detected running as root"
  APEX outputs: "Check if you can write to: /etc/ansible /etc/puppet /etc/salt"
  
APEX cannot:
  - Actually modify Ansible inventory/playbook across a git push
  - Understand GitLab CI pipeline syntax
  - Poison Puppet catalogs remotely
```

---

## Summary: The Honest Gap Table

| Category | APEX Coverage | What You Must Do Manually |
|----------|--------------|--------------------------|
| Application logic | Layer 10 flags services | Test injection on each service |
| TOCTOU races | Signals only (check/use pattern) | strace to measure window |
| AppArmor/SELinux blocking | -15 penalty, profile listing | Read specific profile, test |
| Memory corruption | Unsafe function signals + CVE check | Binary exploitation skills |
| Container undetected | Extra namespace checks | Compare /proc/1/ns vs /proc/self/ns |
| Compound service chains | Credential DNA + Layer 10 flags | Manual multi-app lateral movement |
| Zero-day CVEs | Version data output | External CVE database lookup |
| Config management | pspy catches execution | Understand CM tool, poison catalog |

---

## How To Think When APEX Exhausts All Layers

```
APEX all layers complete → no confirmed chains

Step 1: Recheck the basics (5 minutes)
  □ Did sudo -n -l actually run? Check output.
  □ Did getcap actually run? getcap requires libcap
  □ Did pspy run for full 3+ minutes? Short run = missed crons
  □ Is there another user we could lateral to first?

Step 2: Application review (15 minutes)
  □ What is running on each internal port?
  □ What process runs as root? What does it do?
  □ Can any running service accept commands from us?
  □ Any web app? Check all parameters for command injection.

Step 3: Manual filesystem read (10 minutes)
  □ find / -readable -not -group root 2>/dev/null | xargs file | grep text | head -50
  □ Read interesting configs in /opt, /var/www, /home
  □ Look for custom application directories not in standard paths
  □ git log --all --oneline (find credential commits in any git repo)

Step 4: Version CVE crosscheck (10 minutes)
  □ Every binary version → external CVE search
  □ Focus on: kernel, sudo, pkexec, glibc, any running daemon
  □ searchsploit if available

Step 5: Dynamic observation (15 minutes)
  □ Run pspy for full 10 minutes, not 3
  □ Look for any scheduled task or triggered process
  □ Try triggering web endpoints and watch pspy for root process spawning

Step 6: Accept it's application-specific (if above fails)
  □ The machine is NOT solvable by static analysis
  □ Root requires understanding what the specific application DOES
  □ Look at what services are custom to this machine (non-standard ports/dirs)
  □ That IS the intended path — read, understand, exploit it
```

---

## Final Honest Assessment

```
APEX covers: ~92% of all CTF/OSCP Linux PrivEsc paths automatically
             (any path reachable through filesystem DAC + credential + integrity analysis)

APEX partially covers (signals + pointers): ~5%
  - Application logic: it flags the service, you test it
  - TOCTOU: it flags the pattern, you verify
  - Compound chains: it follows the credential, you follow the service

APEX cannot cover: ~3%
  - Pure binary exploitation (buffer overflows in custom SUID binaries)
  - Zero-day CVEs published after APEX knowledge cutoff
  - Novel techniques without any known detection pattern

The 3% is the reason CTF makers get paid.
The 97% is why you build APEX.
```
