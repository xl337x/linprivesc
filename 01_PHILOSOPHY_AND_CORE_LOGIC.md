# APEX — Philosophy and Core Logic
## The Foundation That Makes Everything Else Work

---

## 1. Why Every Existing Tool Fails

### 1.1 The Pattern Matching Problem

Every existing tool (LinPEAS, unix-privesc-check, BeRoot, Seatbelt) operates on
the same broken foundation: **pattern matching against known bad configurations**.

```
Tool logic:  "Does this match a known vulnerable pattern?"
Maker logic: "Make the path not match any known pattern."
```

This is a losing arms race. The tool adds a pattern. The maker avoids that pattern.
The tool adds another. The maker learns it. Students in the middle get destroyed.

LinPEAS returns 400 lines because it has 400 patterns. Most are noise on any given
machine. Students don't know which 3 out of 400 actually matter. Anxiety. Rabbit
holes. Exam failure.

### 1.2 The Real Problem Is Cognitive Load

Students don't fail OSCP because they lack knowledge of techniques.
Students fail because they:
- Don't know what to try FIRST
- Don't know when to STOP and pivot
- Can't distinguish signal from noise in massive tool output
- Fall into rabbit holes that look real but aren't
- Run out of time doing deep dives on wrong vectors

The tool must solve the cognitive load problem, not just the enumeration problem.

### 1.3 Why More Enumeration Is Not The Answer

Adding more checks to LinPEAS doesn't fix it. You get 500 lines instead of 400.
More noise. More anxiety. More rabbit holes. The problem is architectural.

---

## 2. The Three Primitives — Mathematical Foundation

**Every Linux privilege escalation without exception requires ONE of:**

```
PRIMITIVE 1: WRITE something you shouldn't be able to write
             → that gets executed with elevated privilege

PRIMITIVE 2: EXECUTE something directly with elevated privilege
             (SUID, sudo, capabilities, etc.)

PRIMITIVE 3: READ something sensitive you shouldn't read
             → credential, key, hash → leads to elevated execution
```

**There is no fourth primitive.** This is not a heuristic. This is the Linux security
model. DAC (Discretionary Access Control) controls read, write, execute. Every privesc
path uses one or more of these three operations at some point.

### 2.1 Why This Matters

A CTF maker MUST give you a path. That path MUST use at least one primitive.
Therefore:

- Map everything that executes with elevated privilege (PRIMITIVE 2 surface)
- Map everything you can write (PRIMITIVE 1 surface)
- Map everything sensitive you can read (PRIMITIVE 3 surface)
- Find intersections and chains

**If these maps are complete, you find every path. No exceptions.**

### 2.2 Where This Breaks Down (Honest Assessment)

The three primitives cover DAC-based privilege escalation. They do NOT cover:

- **Memory corruption (kernel exploits):** No file write needed. Pure syscall → ring0.
- **Application logic flaws:** SQLi that writes to /etc/passwd. Invisible to filesystem.
- **MAC bypass (SELinux/AppArmor):** DAC says writable. MAC says blocked. Different layer.
- **Race conditions (TOCTOU):** Static analysis cannot detect timing windows.
- **Container escapes:** You're root inside container. Need different primitive set.

These cases are handled by separate modules (Layers 5-10 in adaptive architecture).
See `02_ARCHITECTURE.md` for the full adaptive layer system.

---

## 3. The Graph Intersection Approach

### 3.1 Two Graphs, One Intersection

```
GRAPH A: Execution Graph
         Everything that runs with elevated privilege on this machine
         
GRAPH B: Influence Graph  
         Everything the current user can affect (write, replace, inject)

INTERSECTION = Your exact attack surface
```

If the intersection is empty, there is no DAC-based privesc path.
This cannot happen on a CTF machine (the machine would be unsolvable).
Therefore: always non-empty. Always produces a path.

### 3.2 Graph A — Execution Graph (Complete)

```
Direct execution mechanisms:
├── SUID binaries (find -perm -4000)
├── SGID binaries (find -perm -2000)
├── Capabilities (getcap -r /)
├── Sudo rules (sudo -n -l)
│   ├── Commands
│   ├── env_keep variables (LD_PRELOAD, PYTHONPATH, etc.)
│   └── Wildcard rules
├── Cron jobs
│   ├── /etc/crontab (including PATH line at top — students miss this)
│   ├── /etc/cron.d/*
│   ├── /var/spool/cron/crontabs/*
│   ├── /etc/cron.hourly|daily|weekly|monthly/*
│   └── User crontabs for all users
├── Systemd timers (systemctl list-timers --all)
├── Systemd services (ExecStart, ExecStartPre, ExecStartPost)
│   └── EnvironmentFile paths
├── Socket-activated services (systemctl list-sockets)
├── D-Bus activated services (busctl list)
├── Init.d scripts (if sysvinit)
├── Running root processes (ps aux / /proc/*/status UID=0)
└── pspy dynamic monitoring (processes not visible at scan time)
```

### 3.3 Graph B — Influence Graph (Complete)

```
Direct write:
├── Writable files (find -writable)
├── Writable directories → can REPLACE any file inside
│   (file locked ≠ parent directory locked — students miss this)
├── Writable files via group membership
└── World-writable files

Indirect write (influence without direct write):
├── Writable libraries in load paths (/etc/ld.so.conf.d/*)
├── Writable /etc/ld.so.preload (MOST POWERFUL — loads into ALL binaries)
├── Writable Python .pth files (auto-import on any python3 call)
├── Writable Python site-packages directory
├── Writable Perl modules (@INC directories)
├── Writable Ruby gems
├── Writable Node.js modules (NODE_PATH directories)
├── Writable environment files (EnvironmentFile= in systemd units)
├── Writable config files that root sources/reads
└── Writable intermediate scripts in multi-hop trust chains

Execution output influence:
├── Root reads our binary output and eval's it
├── Root reads our binary output and pipes to sh
├── Root reads our binary output and writes to privileged file
└── Root checks our exit code and makes decisions based on it
```

### 3.4 Chain Following (Multi-hop)

The intersection check must be RECURSIVE, not just single-hop.

```
Example 3-hop chain (students give up after hop 1):

/etc/crontab calls /usr/local/bin/backup   [hop 1 — student looks here]
/usr/local/bin/backup sources /etc/app/config [hop 2 — student stops here]  
/etc/app/config is writable by current user   [hop 3 — THE PATH]

Simple intersection check: "nothing writable called by cron" → WRONG
Deep chain following:      "cron → script → sources config → CONFIG WRITABLE" → CORRECT
```

Maximum chain depth: 5 hops (covers all known real-world cases, prevents infinite loops).

---

## 4. The Deep Reader — What No Tool Does

### 4.1 The Fundamental Gap In All Existing Tools

LinPEAS finds `/opt/backup.sh` runs as root. **Stops there.**

It does not read `/opt/backup.sh`.
It does not check what `/opt/backup.sh` calls.
It does not check what those calls reference.
It does not check if any referenced file is writable.

APEX **reads the content** of everything in the execution graph and follows
all references recursively. This is Engine 2 (the Reader).

### 4.2 What To Read In Each File Type

**Shell scripts:**
- All `source` and `.` commands → writable source target = inject commands
- All commands called without full path → PATH hijack candidates
- All `eval` statements → variable content injection
- All output redirections → writable output target = content injection
- All config file reads → writable config = inject settings
- All variable assignments from external sources → trace variable origin

**Python scripts:**
- All `import` statements → check each module path for writability
- All `open()` calls → check those files for writability
- All `subprocess`/`os.system`/`os.popen` calls → check called commands
- All `exec()`/`eval()` calls → trace input source
- `.pth` files in any python path → auto-execute on any python import

**Compiled binaries:**
- `strings` output → extract all path references
- `ldd` output → check all linked libraries for writability
- Calls without full path in strings → PATH hijack candidates
- Strings like `chmod`, `setuid`, `system` → behavior hints

**Systemd unit files:**
- `ExecStart`, `ExecStartPre`, `ExecStartPost` → read those binaries/scripts
- `EnvironmentFile` → check if writable
- `WorkingDirectory` → check if writable
- `Environment=LD_PRELOAD=` → immediate escalation if we can influence it

**Cron files:**
- `PATH=` line at top (STUDENTS ALWAYS MISS THIS)
- Every command called without full path → check PATH directories
- Every script called → read that script recursively

---

## 5. The Cognitive Load Solution

### 5.1 Output Philosophy

```
LinPEAS: "Here are 400 things that might matter. Good luck."
APEX:    "Here are 3 confirmed paths. Try them in this order. Here is the exact command."
```

APEX only outputs CONFIRMED chains. Not possibilities. Not maybes. Confirmed paths
where the write map and execution graph intersect with multi-hop chain verification.

### 5.2 Confidence Ranking

Every output item has a confidence score (0-100%) based on how many independent
detection methods confirm it. A finding confirmed by 3 lenses = high confidence.
A finding from 1 lens = low confidence, needs manual verification.

### 5.3 Trap Warnings

Every confirmed finding comes with the trap the CTF maker likely set:
- What students typically do wrong here
- What to verify before spending time on this path
- The green flags that confirm this is the real path

### 5.4 The Never-Says-Clean Rule

APEX never outputs "nothing found" and stops.

If no DAC-based paths found → Layer 4 (credentials)
If no credentials found → Layer 5 (integrity check)
If integrity clean → Layer 6 (kernel CVE)
If no kernel CVE → Layer 7 (pspy dynamic monitoring)
If pspy nothing → Layer 8 (container escape)
If not in container → Layer 9 (MAC policy analysis)
If MAC clean → Layer 10 ("Manual analysis required — application logic on ports: X")

The tool tells you EXACTLY what it has and hasn't checked, and what to do next.

---

## 6. The Exam Anxiety Elimination Protocol

### 6.1 Why Students Fail OSCP (Real Reasons)

Not lack of technique knowledge. These are the real killers:
1. Spending 8 hours on machine 1 instead of 1.5h on each of 5
2. Going deep on a rabbit hole that looks real
3. Not having a systematic order to try things
4. Output overload causing paralysis
5. Not knowing when to stop and pivot

### 6.2 How APEX Solves Each

| Problem | APEX Solution |
|---------|--------------|
| Time overinvestment | Confidence % tells you how long to try each path |
| Rabbit holes | Trap warnings per finding, confirmed-only output |
| No systematic order | Ranked output, try in order, done |
| Output overload | Only confirmed chains shown, zero noise |
| Pivot timing | Empty layer = explicit "pivot to next layer" message |

### 6.3 The 3-Minute Triage Rule

APEX output guides: "Try Path 1 first (estimated 30 seconds). If fails, try Path 2
(estimated 2 minutes). If both fail, run: apex --layer 4" 

No guessing. No anxiety. Just the next action.
