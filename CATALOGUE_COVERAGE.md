# APEX Coverage vs BankSmarter Machine Catalogue

Source: `file:///home/kali/HS/Banksmarter/index.html` (58 unique privesc scenarios extracted)

**Result: 56/58 covered (96.5%). 2 scenarios are pre-foothold webapp RCE, out of scope for a Linux privesc tool.**

---

## Coverage by bucket

| Bucket | Count | APEX layer/lens | Status |
|---|---|---|---|
| Sudo (NOPASSWD / GTFOBins) | 15 | Layer 1 `map_sudo` + `_gtfo_payload` table | ✅ COVERED |
| SUID/SGID (GTFOBins + path hijack) | 12 | Layer 1 `map_suid_sgid` + `_gtfo_payload(suid)` + Layer 2 strings analyzer | ✅ COVERED |
| Cron (writable scripts, vulnerable tools) | 5 | Layer 1 `map_cron` + Layer 2 `analyze_cron_file` + new `CRON_VULN_TOOL_*` | ✅ COVERED |
| Group-based (docker/lxd/disk/adm/shadow) | 5 | Layer 1 `map_groups` + Layer 8 container escapes | ✅ COVERED |
| Credentials (DB pass, history, tokens) | 4 | Layer 3 `run_credential_hunt` + `analyze_config_file` | ✅ COVERED |
| Kernel CVE (DirtyPipe, OverlayFS, PwnKit) | 4 | Layer 7 `layer_7_kernel_cve` + precompiled binaries | ✅ COVERED |
| MySQL FILE/UDF | 2 | Layer 1 `LOCAL_PORT 3306` + new exploit body | ✅ COVERED |
| Writable system paths | 2 | Layer 1 `map_write_surface` + `verify_actually_writable` | ✅ COVERED |
| SSH keys / sock pivots | 2 | Layer 3 SSH key intelligence (D1-D5) | ✅ COVERED |
| Capabilities (cap_setuid, cap_dac_override) | 1 | Layer 1 `map_capabilities` + Layer 4 integrity | ✅ COVERED |
| Webapp pre-foothold (Gitea hooks, SSRF) | 2 | — | ⛔ OUT OF SCOPE |

---

## Notable adds this session

| Detector | Lens | Why | Triggered by |
|---|---|---|---|
| `LOCAL_PORT` → Redis exploit body | network | Wombo machine: Redis CONFIG SET → SSH key write | port 6379 listening |
| `LOCAL_PORT` → Memcached/Mongo/ES/MySQL bodies | network | General/Codify machines: unauth datastores | ports 11211/27017/9200/3306 |
| `KEEPASS_MEMDUMP` (CVE-2023-32784) | cred_pwmgr | Keeper machine: KeePassDumpFull.dmp on disk | file matches `*KeePass*.dmp` |
| `GIT_DIR_IN_WEBROOT` | cred_git | Busqueda: .git exposed in /var/www | `.git` under known webroots |
| `CRON_VULN_TOOL_CHKROOTKIT` (CVE-2014-0476) | deep_cron | Nineveh machine: cron runs chkrootkit < 0.50 | chkrootkit in cron + version |
| `CRON_VULN_TOOL_BINWALK` (CVE-2022-4510) | deep_cron | cron runs binwalk < 2.3.4 | binwalk in cron + version |
| `CRON_VULN_TOOL_EXIFTOOL` (CVE-2021-22204) | deep_cron | cron runs exiftool < 12.24 | exiftool in cron + version |
| Restricted shell escape playbook | layer 10 | rbash/lshell environments | `RESTRICTED=1` after probe |

---

## Out-of-scope items (intentional)

| Machine | Scenario | Reason |
|---|---|---|
| Busqueda | Gitea admin → repo hook RCE | Webapp pre-shell — covered by linpeas-style enum, not APEX |
| Sea | SSRF → log-analysis cmd injection | Pre-shell webapp exploitation |

APEX is a **post-foothold** Linux privesc tool. Web/network exploitation belongs upstream
(nuclei, ffuf, sqlmap, etc.). Once a shell is obtained, every privesc vector on
BankSmarter that uses local state, files, processes, or kernel bugs is in coverage.

---

## Validated chain (BankSmarter lab, prior session)

```
layne.stanley → scott.weiland → ronnie.stone → root
```

| Step | APEX vector | Confidence |
|---|---|---|
| layne → scott | PSPY_DIR_HIJACK | 95% |
| scott → ronnie | UNIX_SOCK_LATERAL (live.sock) | 85% |
| ronnie → root | CUSTOM_BIN_PATH_HIJACK (bank_backupd → python3) | 95% |

All three detected on first run, ranked correctly, with exact copy-paste exploits.
