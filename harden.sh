#!/usr/bin/env bash
#
# harden.sh - Interactive Debian/Ubuntu (incl. Raspberry Pi OS) hardening
#             and automated cleanup/update setup.
#
# Usage: sudo bash harden.sh
#
set -uo pipefail
# Note: deliberately NOT using `set -e` — most steps must be allowed to fail
# individually (missing packages, already-applied changes, etc.) without
# aborting the whole run. Critical steps check their own exit codes.

# Prevent apt/dpkg and the `needrestart` hook (default on Ubuntu 22.04+)
# from popping up interactive dialogs during upgrades/installs — those are
# distinct from our own prompts below and would otherwise hang the script
# waiting on a whiptail dialog nobody's watching for.
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

# ------------------------------------------------------------------------
# Colour (auto-disabled when not on a terminal, NO_COLOR is set, or the
# terminal doesn't support it — everything still works with plain text)
# ------------------------------------------------------------------------
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]] && command -v tput &>/dev/null && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
    C_RESET=$(tput sgr0);   C_BOLD=$(tput bold);    C_DIM=$(tput dim)
    C_RED=$(tput setaf 1);  C_GREEN=$(tput setaf 2); C_YELLOW=$(tput setaf 3)
    C_BLUE=$(tput setaf 4); C_MAGENTA=$(tput setaf 5); C_CYAN=$(tput setaf 6)
else
    C_RESET=""; C_BOLD=""; C_DIM=""
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_MAGENTA=""; C_CYAN=""
fi

# ------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------
LOG_TAG="${C_CYAN}${C_BOLD}[harden]${C_RESET}"
LOG_PREFIX="$LOG_TAG"
DRY_RUN=0
NONINTERACTIVE=0
CONFIG_FILE=""

print_config_template() {
    cat <<'TEMPLATE'
# harden.sh config file — KEY=VALUE, one per line, quoting anything with
# spaces. Values are taken literally (nothing is expanded or executed),
# so a password hash containing $ is safe to use quoted or unquoted.
# Booleans accept y/n (yes/true/1 also work).
# Run with: sudo bash harden.sh --config harden.conf
#
# Anything left unset falls back to the same default shown here, so you
# only need to include the values you want to change from default.

## Account & Access
NEW_USER=""                    # new sudo user to create, blank to skip
EXISTING_USER=""                # used instead of NEW_USER if that's blank and SSH_PUBKEY is set
SSH_PUBKEY=""                   # public key to install for NEW_USER/EXISTING_USER, blank to skip
NEW_USER_PASSWORD=""            # plaintext, or a crypt hash (starting with $) from mkpasswd -m sha-512
LOCK_ROOT="y"
SHELL_TIMEOUT="y"
SHELL_TIMEOUT_SECS="900"

## System
TIMEZONE="UTC"
ENABLE_TIMESYNC="y"
UU_CHECK_INTERVAL="1"
UU_LEVEL="security"             # security | all | none
UU_INSTALL_TIME="03:00"
UU_AUTO_REBOOT="n"
UU_REBOOT_TIME="03:30"
UU_NTFY_URL=""                  # separate ntfy topic for the update summary

## SSH
SSH_PORT="22"
ENV_TYPE="internal"             # internal | external
SSHAUDIT_HARDEN="y"
REGEN_HOSTKEYS="n"              # only asked/applied when ENV_TYPE=external
SSH_BANNER="y"
BANNER_TEXT="Authorized access only. All activity may be monitored and reported."
SSH_EXTRA_LIMITS="y"
SSH_MAX_AUTH_TRIES="3"
SSH_LOGIN_GRACE_TIME="30"
SSH_CLIENT_ALIVE_INTERVAL="300"
SSH_CLIENT_ALIVE_COUNT_MAX="2"

## Firewall
LAN_CIDRS="192.168.1.0/24"      # only used when ENV_TYPE=internal; comma-separate for multiple ranges, e.g. "192.168.1.0/24,10.0.0.0/8"
UFW_LOGGING="y"

## Intrusion Prevention
ENABLE_NTFY="n"
NTFY_URL=""                     # ntfy topic for SSH-login + fail2ban-ban alerts
F2B_IGNOREIP=""                 # only used when ENV_TYPE=internal

## Kernel & Resource Limits
SYSCTL_HARDEN="y"
STRICT_SYSCTL="y"
DISABLE_COREDUMPS="y"
BLACKLIST_PROTOCOLS="y"

## Auditing & Compliance
ENABLE_AUDITD="y"
CHECK_APPARMOR="y"
PASSWORD_POLICY="y"
PW_MINLEN="12"
JOURNALD_PERSIST="y"
ENABLE_ROOTKIT="y"
ENABLE_ACCOUNTING="y"

# Applied automatically, no separate toggle: any NOPASSWD sudoers entry
# found on the box gets fixed the same way every time.
FIX_NOPASSWD_SUDOERS="y"

# Fixes locked/passwordless accounts that already have sudo access
# (e.g. a cloud image's default user). One "username:secret" per line —
# secret can be plaintext or a crypt hash (starting with $). Any flagged
# account with no matching entry here is left alone and just warned
# about, never silently broken.
SUDO_USER_PASSWORDS=""

## Cleanup
TMPREAPER_TIME="7d"
TMPREAPER_EXTRA=""
LOGROTATE_WEEKS="4"

## Verification
RUN_DEBSUMS="y"
RUN_SSHAUDIT="y"
RUN_LYNIS="y"
TEMPLATE
}

usage() {
    cat <<'USAGE'
harden.sh - interactive Debian/Ubuntu hardening and auto-cleanup setup.

Usage: sudo bash harden.sh [options]

  --dry-run, -n          Report exactly what would change without modifying
                          anything or installing packages.
  --config, -c <file>    Read all answers from <file> instead of prompting —
                          runs completely non-interactively.
  --config-b64 <string>  Same as --config, but the file content is passed
                          base64-encoded — handy for a one-line snippet in
                          an SSH client, where you can't easily attach a
                          separate file. Falls back to the HARDEN_CONFIG_B64
                          environment variable if this flag isn't given.
  --print-config          Print a fully-commented template config file to
                          stdout and exit (redirect it to a file to start
                          from it: sudo bash harden.sh --print-config > harden.conf).
  --help, -h              Show this message.
USAGE
}

CONFIG_B64=""

args=("$@")
i=0
while (( i < ${#args[@]} )); do
    arg="${args[$i]}"
    case "$arg" in
        --dry-run|-n)
            DRY_RUN=1
            LOG_TAG="${C_MAGENTA}${C_BOLD}[harden][dry-run]${C_RESET}"
            LOG_PREFIX="$LOG_TAG"
            ;;
        --config|-c)
            i=$((i+1))
            CONFIG_FILE="${args[$i]:-}"
            NONINTERACTIVE=1
            ;;
        --config=*)
            CONFIG_FILE="${arg#--config=}"
            NONINTERACTIVE=1
            ;;
        --config-b64)
            i=$((i+1))
            CONFIG_B64="${args[$i]:-}"
            NONINTERACTIVE=1
            ;;
        --config-b64=*)
            CONFIG_B64="${arg#--config-b64=}"
            NONINTERACTIVE=1
            ;;
        --print-config)
            print_config_template
            exit 0
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            usage
            exit 1
            ;;
    esac
    i=$((i+1))
done

# Fall back to the HARDEN_CONFIG_B64 env var if no --config/--config-b64 flag
# was given — handy for an SSH-client snippet where you'd rather not paste
# a long base64 blob as a literal command-line argument.
if [[ -z "$CONFIG_FILE" && -z "$CONFIG_B64" && -n "${HARDEN_CONFIG_B64:-}" ]]; then
    CONFIG_B64="$HARDEN_CONFIG_B64"
    NONINTERACTIVE=1
fi

if [[ -n "$CONFIG_B64" ]]; then
    TMP_CONFIG=$(mktemp /tmp/harden-config.XXXXXX)
    chmod 600 "$TMP_CONFIG"
    trap 'command rm -f "$TMP_CONFIG"' EXIT
    if ! echo "$CONFIG_B64" | base64 -d > "$TMP_CONFIG" 2>/dev/null; then
        echo "[harden] ERROR: --config-b64/HARDEN_CONFIG_B64 is not valid base64." >&2
        exit 1
    fi
    CONFIG_FILE="$TMP_CONFIG"
fi

info()  { echo -e "${LOG_PREFIX} $*"; }
warn()  { echo -e "${LOG_PREFIX} ${C_YELLOW}${C_BOLD}WARNING:${C_RESET} $*" >&2; }
err()   { echo -e "${LOG_PREFIX} ${C_RED}${C_BOLD}ERROR:${C_RESET} $*" >&2; }
ok()    { echo -e "${LOG_PREFIX} ${C_GREEN}[OK]${C_RESET} $*"; }

# normalize_bool <value> <default> — accepts y/yes/true/1 (case-insensitive)
# as "y", everything else (including unset/empty) as "n". Used so config
# file values and interactive answers both end up in the same y/n form.
normalize_bool() {
    local v="${1:-$2}"
    case "${v,,}" in
        y|yes|true|1) echo "y" ;;
        *) echo "n" ;;
    esac
}

# set_user_password <user> <secret> — secret can be plaintext or a crypt
# hash (auto-detected by a leading $, e.g. from `mkpasswd -m sha-512`).
set_user_password() {
    local user="$1" secret="$2"
    [[ -z "$secret" ]] && return 1
    if [[ "$secret" == \$* ]]; then
        echo "${user}:${secret}" | chpasswd -e
    else
        echo "${user}:${secret}" | chpasswd
    fi
}

# lookup_sudo_password <user> — searches SUDO_USER_PASSWORDS (one
# "user:secret" per line) for a matching entry.
lookup_sudo_password() {
    local target="$1" line lu lp
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        lu="${line%%:*}"
        lp="${line#*:}"
        if [[ "$lu" == "$target" ]]; then
            echo "$lp"
            return 0
        fi
    done <<< "${SUDO_USER_PASSWORDS:-}"
    return 1
}

# load_config_file <path> — reads KEY="value" / KEY='value' / KEY=value
# lines and assigns them as plain literal strings, with no shell
# expansion or execution of the value's content at all. Deliberately NOT
# `source`d as shell: password hashes (yescrypt/bcrypt/SHA-512 all use $
# as a field separator) would otherwise be parsed as variable references
# — "$y$j9T$..." un-quoted-safely would either crash under `set -u` or,
# worse, silently corrupt the hash — and arbitrary shell in a value
# (e.g. a stray $(...)) would otherwise just execute as root.
load_config_file() {
    local file="$1" line line_num=0 key value first_char
    while IFS= read -r line || [[ -n "$line" ]]; do
        line_num=$((line_num+1))
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
            key="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"
            first_char="${value:0:1}"
            if [[ "$first_char" == '"' ]]; then
                value="${value#\"}"
                value="${value%%\"*}"
            elif [[ "$first_char" == "'" ]]; then
                value="${value#\'}"
                value="${value%%\'*}"
            else
                value="${value%%#*}"
                value="${value%"${value##*[![:space:]]}"}"
            fi
            printf -v "$key" '%s' "$value"
        else
            warn "Ignoring unrecognised line $line_num in config: $line"
        fi
    done < "$file"
}

# section <title> — visual divider between the major phases of a run.
section() {
    local title=" $* " width cols rule
    cols=$(tput cols 2>/dev/null || echo 60)
    [[ "$cols" =~ ^[0-9]+$ ]] || cols=60
    width=$(( cols < 40 ? 40 : (cols > 60 ? 60 : cols) ))
    rule=$(printf '%*s' "$width" '' | tr ' ' '=')
    echo
    echo -e "${C_BLUE}${C_BOLD}${rule}${C_RESET}"
    echo -e "${C_BLUE}${C_BOLD}${title}${C_RESET}"
    echo -e "${C_BLUE}${C_BOLD}${rule}${C_RESET}"
}

# subsection <title> — lightweight heading used to group related prompts
# within gather_config(), matching the names of the section() dividers
# those answers get applied under later in the run.
subsection() {
    local title="$*" underline
    underline=$(printf '%*s' "${#title}" '' | tr ' ' '-')
    echo
    echo -e "${C_BOLD}${title}${C_RESET}"
    echo -e "${C_DIM}${underline}${C_RESET}"
}

# run <description> -- <command...>
# Executes the command normally, or just reports it under --dry-run.
run() {
    local desc="$1"; shift
    [[ "${1:-}" == "--" ]] && shift
    if (( DRY_RUN )); then
        echo "${LOG_PREFIX} would: ${desc}"
        return 0
    fi
    "$@"
}

# write_file <path> — reads content from stdin. Reports under --dry-run.
write_file() {
    local path="$1"
    if (( DRY_RUN )); then
        echo "${LOG_PREFIX} would write: ${path}"
        cat > /dev/null
        return 0
    fi
    cat > "$path"
}

# Under --dry-run, shadow every mutating command with a stub that reports
# what it would have done and succeeds. Read-only invocations that the
# script depends on for its logic (systemctl list-unit-files, ufw status,
# passwd -S, crontab -l, apt-get update) are passed through to the real
# binary so the dry run still follows the same code paths as a real one.
if (( DRY_RUN )); then
    _report() { echo "${LOG_PREFIX} would run: $*"; }

    systemctl() {
        case "${1:-}" in
            list-unit-files|status|show|is-active|is-enabled) command systemctl "$@" ;;
            *) _report "systemctl $*" ;;
        esac
    }
    ufw() {
        case "${1:-}" in
            status) command ufw "$@" ;;
            *) _report "ufw $*" ;;
        esac
    }
    passwd() {
        case "${1:-}" in
            -S) command passwd "$@" ;;
            *) _report "passwd $*" ;;
        esac
    }
    crontab() {
        if [[ "${1:-}" == "-l" ]]; then command crontab "$@"; else _report "crontab $*"; cat > /dev/null; fi
    }
    apt-get() {
        case "${1:-}" in
            update) command apt-get "$@" ;;
            *) _report "apt-get $*" ;;
        esac
    }
    sed() {
        # Only -i (in-place) mutates; everything else is a normal filter.
        if [[ "${1:-}" == "-i" ]]; then _report "sed $*"; else command sed "$@"; fi
    }
    timedatectl() {
        case "${1:-}" in
            set-timezone) _report "timedatectl $*" ;;
            *) command timedatectl "$@" ;;
        esac
    }
    cp()         { _report "cp $*"; }
    mv()         { _report "mv $*"; }
    rm()         { _report "rm $*"; }
    mkdir()      { _report "mkdir $*"; }
    chmod()      { _report "chmod $*"; }
    chown()      { _report "chown $*"; }
    touch()      { _report "touch $*"; }
    adduser()    { _report "adduser $*"; }
    usermod()    { _report "usermod $*"; }
    ssh-keygen() { _report "ssh-keygen $*"; }
    augenrules() { _report "augenrules $*"; }
    sysctl()     { if [[ "${1:-}" == "--system" ]]; then _report "sysctl $*"; else command sysctl "$@"; fi; }
    chpasswd()   { _report "chpasswd $*"; cat > /dev/null; }
fi

ask() {
    # ask "Prompt text" "default" -> echoes the answer
    # Reads from /dev/tty, not stdin — so this still works when the script
    # itself is being piped in via `curl ... | bash` (stdin is the pipe in
    # that case, not the keyboard).
    local prompt="$1" default="${2:-}" reply=""
    if [[ -n "$default" ]]; then
        read -rp "${C_BOLD}${prompt}${C_RESET} ${C_DIM}[${default}]${C_RESET}: " reply < /dev/tty
        echo "${reply:-$default}"
    else
        read -rp "${C_BOLD}${prompt}${C_RESET}: " reply < /dev/tty
        echo "${reply}"
    fi
}

confirm() {
    # confirm "Prompt text" "y|n" -> return 0 for yes, 1 for no
    local prompt="$1" default="${2:-n}" reply=""
    local hint="y/N"
    [[ "$default" == "y" ]] && hint="Y/n"
    read -rp "${C_BOLD}${prompt}${C_RESET} ${C_DIM}[${hint}]${C_RESET}: " reply < /dev/tty
    reply="${reply:-$default}"
    [[ "$reply" =~ ^[Yy] ]]
}

backup_file() {
    local f="$1"
    if [[ -f "$f" && ! -f "${f}.harden-bak" ]]; then
        if (( DRY_RUN )); then
            echo "${LOG_PREFIX} would back up: $f -> ${f}.harden-bak"
            return 0
        fi
        cp -a "$f" "${f}.harden-bak"
        info "Backed up $f -> ${f}.harden-bak"
    fi
}

pkg_install() {
    # pkg_install pkg1 pkg2 ... — installs each independently, warns (does
    # not abort) on failure so one broken/missing package can't kill the run.
    local pkg ok=0 fail=0
    for pkg in "$@"; do
        if dpkg -s "$pkg" &>/dev/null; then
            info "Package already installed: $pkg"
            ok=$((ok+1))
            continue
        fi
        if (( DRY_RUN )); then
            echo "${LOG_PREFIX} would install: $pkg"
            ok=$((ok+1))
            continue
        fi
        info "Installing $pkg ..."
        if DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" &>/tmp/harden-apt-"$pkg".log; then
            ok=$((ok+1))
        else
            fail=$((fail+1))
            warn "Failed to install $pkg — see /tmp/harden-apt-${pkg}.log. Continuing."
        fi
    done
    return $fail
}

service_exists() { systemctl list-unit-files "$1" &>/dev/null && systemctl list-unit-files "$1" | grep -q "$1"; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root (sudo bash harden.sh)."
        exit 1
    fi
}

detect_os() {
    if [[ ! -f /etc/os-release ]]; then
        err "/etc/os-release not found — cannot confirm this is a Debian-based system."
        exit 1
    fi
    # shellcheck disable=SC1091
    source /etc/os-release
    local like="${ID_LIKE:-} ${ID:-}"
    if [[ "$like" != *debian* ]]; then
        warn "This doesn't look like a Debian-based system (ID=${ID:-unknown}, ID_LIKE=${ID_LIKE:-unknown})."
        confirm "Continue anyway?" "n" || exit 1
    else
        info "Detected: ${PRETTY_NAME:-$ID}"
    fi
}

# ------------------------------------------------------------------------
# 1. Preflight
# ------------------------------------------------------------------------
preflight() {
    require_root
    detect_os
    section "Preflight"
    if (( DRY_RUN )); then
        info "${C_MAGENTA}${C_BOLD}DRY RUN${C_RESET} — no changes will be made. Every action is reported instead."
    fi
    info "Running apt update && upgrade first..."
    apt-get update -y || warn "apt-get update failed — check network/sources.list."
    apt-get upgrade -y || warn "apt-get upgrade failed — continuing anyway."
    pkg_install curl || warn "curl failed to install — ntfy notifications will not work without it."
    pkg_install cron || warn "cron failed to install — scheduled cleanup and the fail2ban ntfy summary will not run without it."
}

# ------------------------------------------------------------------------
# 2. Gather configuration
# ------------------------------------------------------------------------
gather_config() {
    if (( NONINTERACTIVE )); then
        info "Non-interactive mode — using values from ${CONFIG_FILE}."
    else
        section "Configuration"
    fi

    (( NONINTERACTIVE )) || subsection "Account & Access"
    NEW_USER="${NEW_USER:-}"
    (( NONINTERACTIVE )) || NEW_USER=$(ask "New sudo user to create (blank to skip)" "$NEW_USER")

    EXISTING_USER="${EXISTING_USER:-}"
    SSH_PUBKEY="${SSH_PUBKEY:-}"
    NEW_USER_PASSWORD="${NEW_USER_PASSWORD:-}"
    if (( ! NONINTERACTIVE )); then
        if [[ -n "$NEW_USER" ]] || confirm "Add an SSH public key to an existing user's authorized_keys?" "$( [[ -n "$SSH_PUBKEY" ]] && echo y || echo n )"; then
            [[ -z "$NEW_USER" ]] && EXISTING_USER=$(ask "Which existing username?" "${EXISTING_USER:-${SUDO_USER:-}}")
            SSH_PUBKEY=$(ask "Paste the SSH public key (blank to skip)" "$SSH_PUBKEY")
        fi
    fi

    LOCK_ROOT=$(normalize_bool "${LOCK_ROOT:-}" "y")
    (( NONINTERACTIVE )) || { confirm "Lock the root account password (on top of disabling root SSH login)?" "$LOCK_ROOT" && LOCK_ROOT="y" || LOCK_ROOT="n"; }

    SHELL_TIMEOUT=$(normalize_bool "${SHELL_TIMEOUT:-}" "y")
    SHELL_TIMEOUT_SECS="${SHELL_TIMEOUT_SECS:-900}"
    if (( ! NONINTERACTIVE )); then
        if confirm "Auto-logout idle interactive shells after 15 minutes?" "$SHELL_TIMEOUT"; then
            SHELL_TIMEOUT="y"
            SHELL_TIMEOUT_SECS=$(ask "Idle timeout in seconds" "$SHELL_TIMEOUT_SECS")
        else
            SHELL_TIMEOUT="n"
        fi
    fi

    (( NONINTERACTIVE )) || subsection "System"
    CURRENT_TZ=$(timedatectl show -p Timezone --value 2>/dev/null || echo "UTC")
    TIMEZONE="${TIMEZONE:-$CURRENT_TZ}"
    (( NONINTERACTIVE )) || TIMEZONE=$(ask "Timezone" "$TIMEZONE")

    ENABLE_TIMESYNC=$(normalize_bool "${ENABLE_TIMESYNC:-}" "y")
    (( NONINTERACTIVE )) || { confirm "Explicitly enable systemd-timesyncd for NTP (skipped if chrony/ntpd already active)?" "$ENABLE_TIMESYNC" && ENABLE_TIMESYNC="y" || ENABLE_TIMESYNC="n"; }

    UU_CHECK_INTERVAL="${UU_CHECK_INTERVAL:-1}"
    (( NONINTERACTIVE )) || UU_CHECK_INTERVAL=$(ask "How often to check for updates (days)" "$UU_CHECK_INTERVAL")

    UU_LEVEL="${UU_LEVEL:-security}"
    (( NONINTERACTIVE )) || UU_LEVEL=$(ask "Install automatically: security / all / none" "$UU_LEVEL")
    case "$UU_LEVEL" in
        security|all|none) : ;;
        *) warn "Unrecognised value '$UU_LEVEL' — defaulting to 'security'."; UU_LEVEL="security" ;;
    esac

    UU_INSTALL_TIME="${UU_INSTALL_TIME:-03:00}"
    UU_AUTO_REBOOT=$(normalize_bool "${UU_AUTO_REBOOT:-}" "n")
    UU_REBOOT_TIME="${UU_REBOOT_TIME:-03:30}"
    UU_NTFY_URL="${UU_NTFY_URL:-}"
    if [[ "$UU_LEVEL" != "none" ]]; then
        if (( ! NONINTERACTIVE )); then
            UU_INSTALL_TIME=$(ask "Time to run the daily update/install (24h HH:MM)" "$UU_INSTALL_TIME")
        fi
        [[ "$UU_INSTALL_TIME" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || { warn "Invalid time '$UU_INSTALL_TIME' — defaulting to 03:00."; UU_INSTALL_TIME="03:00"; }

        if (( ! NONINTERACTIVE )); then
            if confirm "Allow an automatic reboot if one is required after updates?" "$UU_AUTO_REBOOT"; then
                UU_AUTO_REBOOT="y"
                UU_REBOOT_TIME=$(ask "Automatic reboot time (24h HH:MM)" "$UU_REBOOT_TIME")
            else
                UU_AUTO_REBOOT="n"
            fi
        fi
        if [[ "$UU_AUTO_REBOOT" == "y" ]]; then
            [[ "$UU_REBOOT_TIME" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || { warn "Invalid time '$UU_REBOOT_TIME' — defaulting to 03:30."; UU_REBOOT_TIME="03:30"; }
        fi

        if (( ! NONINTERACTIVE )); then
            if confirm "Send an ntfy summary after each run (packages available/patched, reboot status)? Uses its own topic, separate from SSH-login/fail2ban alerts." "$( [[ -n "$UU_NTFY_URL" ]] && echo y || echo n )"; then
                UU_NTFY_URL=$(ask "Full ntfy topic URL (e.g. https://ntfy.example.com/mytopic)" "$UU_NTFY_URL")
            fi
        fi
    fi

    (( NONINTERACTIVE )) || subsection "SSH"
    SSH_PORT="${SSH_PORT:-22}"
    (( NONINTERACTIVE )) || SSH_PORT=$(ask "SSH port to use" "$SSH_PORT")

    ENV_TYPE="${ENV_TYPE:-internal}"
    if (( ! NONINTERACTIVE )); then
        echo "Environment type:"
        echo "  1) internal (LAN only, trusted network)"
        echo "  2) external (internet-facing)"
        local envchoice
        envchoice=$(ask "Choose 1 or 2" "$( [[ "$ENV_TYPE" == "external" ]] && echo 2 || echo 1 )")
        [[ "$envchoice" == "2" ]] && ENV_TYPE="external" || ENV_TYPE="internal"
    fi
    case "$ENV_TYPE" in
        internal|external) : ;;
        *) warn "Unrecognised ENV_TYPE '$ENV_TYPE' — defaulting to 'internal'."; ENV_TYPE="internal" ;;
    esac
    info "Environment set to: $ENV_TYPE"

    SSHAUDIT_HARDEN=$(normalize_bool "${SSHAUDIT_HARDEN:-}" "y")
    (( NONINTERACTIVE )) || { confirm "Apply strict ssh-audit cipher/KEX/MAC hardening? (safe, recommended)" "$SSHAUDIT_HARDEN" && SSHAUDIT_HARDEN="y" || SSHAUDIT_HARDEN="n"; }

    REGEN_HOSTKEYS=$(normalize_bool "${REGEN_HOSTKEYS:-}" "n")
    if [[ "$ENV_TYPE" == "external" ]]; then
        (( NONINTERACTIVE )) || { confirm "Regenerate SSH host keys? (invasive — invalidates known_hosts on all existing clients)" "$REGEN_HOSTKEYS" && REGEN_HOSTKEYS="y" || REGEN_HOSTKEYS="n"; }
    else
        REGEN_HOSTKEYS="n"
    fi

    SSH_BANNER=$(normalize_bool "${SSH_BANNER:-}" "y")
    BANNER_TEXT="${BANNER_TEXT:-Authorized access only. All activity may be monitored and reported.}"
    if (( ! NONINTERACTIVE )); then
        if confirm "Add an SSH pre-login banner?" "$SSH_BANNER"; then
            SSH_BANNER="y"
            BANNER_TEXT=$(ask "Banner text" "$BANNER_TEXT")
        else
            SSH_BANNER="n"
        fi
    fi

    SSH_EXTRA_LIMITS=$(normalize_bool "${SSH_EXTRA_LIMITS:-}" "y")
    SSH_MAX_AUTH_TRIES="${SSH_MAX_AUTH_TRIES:-3}"
    SSH_LOGIN_GRACE_TIME="${SSH_LOGIN_GRACE_TIME:-30}"
    SSH_CLIENT_ALIVE_INTERVAL="${SSH_CLIENT_ALIVE_INTERVAL:-300}"
    SSH_CLIENT_ALIVE_COUNT_MAX="${SSH_CLIENT_ALIVE_COUNT_MAX:-2}"
    if (( ! NONINTERACTIVE )); then
        if confirm "Apply extra SSH limits (MaxAuthTries=${SSH_MAX_AUTH_TRIES}, LoginGraceTime=${SSH_LOGIN_GRACE_TIME}s, ClientAliveInterval=${SSH_CLIENT_ALIVE_INTERVAL}s, ClientAliveCountMax=${SSH_CLIENT_ALIVE_COUNT_MAX}, X11Forwarding=no)?" "$SSH_EXTRA_LIMITS"; then
            SSH_EXTRA_LIMITS="y"
            if confirm "Use those defaults?" "y"; then
                :
            else
                SSH_MAX_AUTH_TRIES=$(ask "MaxAuthTries (failed login attempts before disconnect)" "$SSH_MAX_AUTH_TRIES")
                SSH_LOGIN_GRACE_TIME=$(ask "LoginGraceTime in seconds (time allowed to authenticate)" "$SSH_LOGIN_GRACE_TIME")
                SSH_CLIENT_ALIVE_INTERVAL=$(ask "ClientAliveInterval in seconds (idle keepalive check)" "$SSH_CLIENT_ALIVE_INTERVAL")
                SSH_CLIENT_ALIVE_COUNT_MAX=$(ask "ClientAliveCountMax (missed keepalives before disconnect)" "$SSH_CLIENT_ALIVE_COUNT_MAX")
            fi
        else
            SSH_EXTRA_LIMITS="n"
        fi
    fi

    (( NONINTERACTIVE )) || subsection "Firewall"
    LAN_CIDRS="${LAN_CIDRS:-192.168.1.0/24}"
    if [[ "$ENV_TYPE" == "internal" ]]; then
        (( NONINTERACTIVE )) || LAN_CIDRS=$(ask "Comma-separated CIDR ranges allowed to reach SSH (e.g. 192.168.1.0/24,192.168.2.0/24)" "$LAN_CIDRS")
    else
        LAN_CIDRS=""
    fi

    UFW_LOGGING=$(normalize_bool "${UFW_LOGGING:-}" "y")
    (( NONINTERACTIVE )) || { confirm "Enable UFW firewall logging?" "$UFW_LOGGING" && UFW_LOGGING="y" || UFW_LOGGING="n"; }

    (( NONINTERACTIVE )) || subsection "Intrusion Prevention"
    ENABLE_NTFY=$(normalize_bool "${ENABLE_NTFY:-}" "n")
    NTFY_URL="${NTFY_URL:-}"
    if (( ! NONINTERACTIVE )); then
        if confirm "Enable ntfy notifications (SSH logins + fail2ban bans)?" "$ENABLE_NTFY"; then
            ENABLE_NTFY="y"
            NTFY_URL=$(ask "Full ntfy topic URL (e.g. https://ntfy.example.com/mytopic)" "$NTFY_URL")
        else
            ENABLE_NTFY="n"
        fi
    fi
    if [[ "$ENABLE_NTFY" == "y" && -z "$NTFY_URL" ]]; then
        warn "ENABLE_NTFY is on but NTFY_URL is blank — disabling ntfy."
        ENABLE_NTFY="n"
    fi

    F2B_IGNOREIP="${F2B_IGNOREIP:-}"
    if [[ "$ENV_TYPE" == "internal" ]]; then
        (( NONINTERACTIVE )) || F2B_IGNOREIP=$(ask "IP(s) fail2ban should never ban (space-separated, e.g. your admin workstation)" "$F2B_IGNOREIP")
    else
        F2B_IGNOREIP=""
    fi

    (( NONINTERACTIVE )) || subsection "Kernel & Resource Limits"
    local sysctl_default="n"; [[ "$ENV_TYPE" == "external" ]] && sysctl_default="y"
    SYSCTL_HARDEN=$(normalize_bool "${SYSCTL_HARDEN:-}" "$sysctl_default")
    (( NONINTERACTIVE )) || { confirm "Apply sysctl network hardening (anti-spoofing, disable redirects)?" "$SYSCTL_HARDEN" && SYSCTL_HARDEN="y" || SYSCTL_HARDEN="n"; }

    STRICT_SYSCTL=$(normalize_bool "${STRICT_SYSCTL:-}" "y")
    (( NONINTERACTIVE )) || { confirm "Apply stricter kernel sysctls (ASLR, dmesg/kptr restrict, TCP syncookies, disable sysrq, ICMP hardening)?" "$STRICT_SYSCTL" && STRICT_SYSCTL="y" || STRICT_SYSCTL="n"; }

    DISABLE_COREDUMPS=$(normalize_bool "${DISABLE_COREDUMPS:-}" "y")
    (( NONINTERACTIVE )) || { confirm "Disable core dumps?" "$DISABLE_COREDUMPS" && DISABLE_COREDUMPS="y" || DISABLE_COREDUMPS="n"; }

    BLACKLIST_PROTOCOLS=$(normalize_bool "${BLACKLIST_PROTOCOLS:-}" "y")
    (( NONINTERACTIVE )) || { confirm "Blacklist rarely-used network protocols (dccp, sctp, rds, tipc)?" "$BLACKLIST_PROTOCOLS" && BLACKLIST_PROTOCOLS="y" || BLACKLIST_PROTOCOLS="n"; }

    (( NONINTERACTIVE )) || subsection "Auditing & Compliance"
    ENABLE_AUDITD=$(normalize_bool "${ENABLE_AUDITD:-}" "y")
    (( NONINTERACTIVE )) || { confirm "Enable auditd (logs changes to key files like passwd/shadow/sudoers)?" "$ENABLE_AUDITD" && ENABLE_AUDITD="y" || ENABLE_AUDITD="n"; }

    CHECK_APPARMOR=$(normalize_bool "${CHECK_APPARMOR:-}" "y")
    (( NONINTERACTIVE )) || { confirm "Check AppArmor status and report any unenforced profiles?" "$CHECK_APPARMOR" && CHECK_APPARMOR="y" || CHECK_APPARMOR="n"; }

    PASSWORD_POLICY=$(normalize_bool "${PASSWORD_POLICY:-}" "y")
    PW_MINLEN="${PW_MINLEN:-12}"
    if (( ! NONINTERACTIVE )); then
        if confirm "Apply a password quality policy (applies to future password changes only, won't lock out current sessions)?" "$PASSWORD_POLICY"; then
            PASSWORD_POLICY="y"
            PW_MINLEN=$(ask "Minimum password length" "$PW_MINLEN")
        else
            PASSWORD_POLICY="n"
        fi
    fi

    JOURNALD_PERSIST=$(normalize_bool "${JOURNALD_PERSIST:-}" "y")
    (( NONINTERACTIVE )) || { confirm "Make systemd journal logs persistent across reboots?" "$JOURNALD_PERSIST" && JOURNALD_PERSIST="y" || JOURNALD_PERSIST="n"; }

    ENABLE_ROOTKIT=$(normalize_bool "${ENABLE_ROOTKIT:-}" "y")
    (( NONINTERACTIVE )) || { confirm "Install rkhunter + chkrootkit with a weekly scan?" "$ENABLE_ROOTKIT" && ENABLE_ROOTKIT="y" || ENABLE_ROOTKIT="n"; }

    ENABLE_ACCOUNTING=$(normalize_bool "${ENABLE_ACCOUNTING:-}" "y")
    (( NONINTERACTIVE )) || { confirm "Enable process accounting and sysstat (acct + sysstat)?" "$ENABLE_ACCOUNTING" && ENABLE_ACCOUNTING="y" || ENABLE_ACCOUNTING="n"; }

    FIX_NOPASSWD_SUDOERS=$(normalize_bool "${FIX_NOPASSWD_SUDOERS:-}" "y")
    SUDO_USER_PASSWORDS="${SUDO_USER_PASSWORDS:-}"

    (( NONINTERACTIVE )) || subsection "Cleanup"
    TMPREAPER_TIME="${TMPREAPER_TIME:-7d}"
    (( NONINTERACTIVE )) || TMPREAPER_TIME=$(ask "Max age for tmpreaper to clear files in /tmp and /var/tmp" "$TMPREAPER_TIME")

    TMPREAPER_EXTRA="${TMPREAPER_EXTRA:-}"
    (( NONINTERACTIVE )) || TMPREAPER_EXTRA=$(ask "Extra directories for tmpreaper to clean (space-separated, blank for none)" "$TMPREAPER_EXTRA")

    LOGROTATE_WEEKS="${LOGROTATE_WEEKS:-4}"
    (( NONINTERACTIVE )) || LOGROTATE_WEEKS=$(ask "How many weekly log rotations to keep in /var/log/*.log" "$LOGROTATE_WEEKS")

    (( NONINTERACTIVE )) || subsection "Verification"
    RUN_DEBSUMS=$(normalize_bool "${RUN_DEBSUMS:-}" "y")
    (( NONINTERACTIVE )) || { confirm "Verify installed package files against their checksums (debsums)?" "$RUN_DEBSUMS" && RUN_DEBSUMS="y" || RUN_DEBSUMS="n"; }

    RUN_SSHAUDIT=$(normalize_bool "${RUN_SSHAUDIT:-}" "y")
    (( NONINTERACTIVE )) || { confirm "Run ssh-audit against localhost after hardening to verify the config?" "$RUN_SSHAUDIT" && RUN_SSHAUDIT="y" || RUN_SSHAUDIT="n"; }

    RUN_LYNIS=$(normalize_bool "${RUN_LYNIS:-}" "y")
    (( NONINTERACTIVE )) || { confirm "Run Lynis before and after hardening to compare the hardening index and summarize findings?" "$RUN_LYNIS" && RUN_LYNIS="y" || RUN_LYNIS="n"; }

    echo
    info "Configuration collected. Proceeding — review each section's warnings as it runs."
}

# ------------------------------------------------------------------------
# 3. User + SSH key
# ------------------------------------------------------------------------
setup_user() {
    local target_user=""
    if [[ -n "$NEW_USER" ]]; then
        if id "$NEW_USER" &>/dev/null; then
            info "User $NEW_USER already exists — skipping creation."
        elif (( NONINTERACTIVE )); then
            info "Creating user $NEW_USER (non-interactive)..."
            adduser --disabled-password --gecos "" "$NEW_USER" || { err "Failed to create user $NEW_USER."; return 1; }
            if [[ -n "${NEW_USER_PASSWORD:-}" ]]; then
                set_user_password "$NEW_USER" "$NEW_USER_PASSWORD" \
                    && info "Password set for $NEW_USER." \
                    || warn "Could not set password for $NEW_USER."
            else
                warn "No NEW_USER_PASSWORD supplied — '$NEW_USER' has NO password. Sudo will not work for this account until one is set with 'sudo passwd $NEW_USER'."
            fi
        else
            info "Creating user $NEW_USER (you'll be prompted to set a password)..."
            adduser "$NEW_USER" || { err "Failed to create user $NEW_USER."; return 1; }
        fi
        usermod -aG sudo "$NEW_USER"
        target_user="$NEW_USER"
    elif [[ -n "${EXISTING_USER:-}" ]]; then
        if ! id "$EXISTING_USER" &>/dev/null; then
            warn "User $EXISTING_USER does not exist — skipping key setup."
            return 0
        fi
        target_user="$EXISTING_USER"
    fi

    [[ -z "$target_user" ]] && return 0
    [[ -z "$SSH_PUBKEY" ]] && return 0

    local home_dir; home_dir=$(getent passwd "$target_user" | cut -d: -f6)
    if [[ -z "$home_dir" || "$home_dir" == "/" ]]; then
        if (( DRY_RUN )); then
            echo "${LOG_PREFIX} would add the public key to ${target_user}'s authorized_keys (user doesn't exist yet in this dry run)"
        else
            warn "Could not determine a home directory for '${target_user}' — skipping SSH key setup."
        fi
        return 0
    fi
    mkdir -p "${home_dir}/.ssh"
    touch "${home_dir}/.ssh/authorized_keys"
    if ! grep -qF "$SSH_PUBKEY" "${home_dir}/.ssh/authorized_keys" 2>/dev/null; then
        if (( DRY_RUN )); then
            echo "${LOG_PREFIX} would append public key to ${home_dir}/.ssh/authorized_keys"
        else
            echo "$SSH_PUBKEY" >> "${home_dir}/.ssh/authorized_keys"
        fi
        info "Added public key to ${home_dir}/.ssh/authorized_keys"
    else
        info "Public key already present — skipping."
    fi
    chown -R "${target_user}:${target_user}" "${home_dir}/.ssh"
    chmod 700 "${home_dir}/.ssh"
    chmod 600 "${home_dir}/.ssh/authorized_keys"
}

# ------------------------------------------------------------------------
# 4. Sudo access audit — any NOPASSWD grant, and any sudo-group account
#    without a usable password
# ------------------------------------------------------------------------
audit_sudo_access() {
    local files
    files=$(grep -rl "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '\.harden-bak$' || true)
    for f in $files; do
        [[ -f "$f" ]] || continue
        local do_fix="n"
        if (( NONINTERACTIVE )); then
            do_fix="${FIX_NOPASSWD_SUDOERS:-y}"
        else
            confirm "Found NOPASSWD entries in $f — require a password there too?" "y" && do_fix="y"
        fi
        if [[ "$do_fix" == "y" ]]; then
            backup_file "$f"
            sed -i 's/NOPASSWD:/PASSWD:/' "$f"
            info "Updated $f to require a password for sudo."
        fi
    done

    local sudo_members
    sudo_members=$(getent group sudo 2>/dev/null | awk -F: '{print $4}' | tr ',' ' ')
    for u in $sudo_members; do
        [[ -z "$u" ]] && continue
        local status; status=$(passwd -S "$u" 2>/dev/null | awk '{print $2}')
        case "$status" in
            L)
                if (( NONINTERACTIVE )); then
                    local secret; secret=$(lookup_sudo_password "$u")
                    if [[ -n "$secret" ]]; then
                        set_user_password "$u" "$secret" \
                            && info "Password set for '$u' (was locked/unset)." \
                            || warn "Could not set password for '$u'."
                    else
                        warn "User '$u' has sudo access but their password is locked/unset — no matching entry in SUDO_USER_PASSWORDS, leaving as-is. Sudo will not work for this account until a password is set manually."
                    fi
                else
                    if confirm "User '$u' has sudo access but their password is locked/unset — set a real password now? (this replaces the lock with a working password)" "y"; then
                        passwd "$u" || warn "Could not set a password for '$u'."
                    fi
                fi
                ;;
            P)
                info "User '$u' (sudo access) already has a usable password." ;;
            *)
                warn "Could not determine password status for '$u'." ;;
        esac
    done
}

# ------------------------------------------------------------------------
# 5. Timezone
# ------------------------------------------------------------------------
setup_timezone() {
    if timedatectl list-timezones 2>/dev/null | grep -qx "$TIMEZONE"; then
        timedatectl set-timezone "$TIMEZONE" && info "Timezone set to $TIMEZONE."
    else
        warn "'$TIMEZONE' is not a recognised timezone — skipping."
    fi
}

setup_timesync() {
    [[ "$ENABLE_TIMESYNC" == "y" ]] || return 0
    if systemctl is-active chrony &>/dev/null || systemctl is-active ntp &>/dev/null || systemctl is-active ntpd &>/dev/null; then
        info "A time-sync daemon (chrony/ntpd) is already active — leaving it as-is."
        return 0
    fi
    (( DRY_RUN )) && echo "${LOG_PREFIX} would run: systemctl enable --now systemd-timesyncd"
    if systemctl enable --now systemd-timesyncd &>/dev/null; then
        info "systemd-timesyncd enabled for NTP."
    else
        warn "Could not enable systemd-timesyncd — check 'systemctl status systemd-timesyncd'."
    fi
}

# ------------------------------------------------------------------------
# 6. Unattended upgrades
# ------------------------------------------------------------------------
setup_unattended_upgrades() {
    if [[ "$UU_LEVEL" == "none" ]]; then
        info "Automatic upgrades set to 'none' — skipping unattended-upgrades setup."
        return 0
    fi

    pkg_install unattended-upgrades apt-listchanges

    write_file /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "${UU_CHECK_INTERVAL}";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    {
        echo "// Managed by harden.sh"
        echo "#clear Unattended-Upgrade::Allowed-Origins;"
        echo "Unattended-Upgrade::Allowed-Origins {"
        echo '    "${distro_id}:${distro_codename}-security";'
        echo '    "${distro_id}ESMApps:${distro_codename}-apps-security";'
        echo '    "${distro_id}ESMApps:${distro_codename}-infra-security";'
        if [[ "$UU_LEVEL" == "all" ]]; then
            echo '    "${distro_id}:${distro_codename}";'
            echo '    "${distro_id}:${distro_codename}-updates";'
        fi
        echo "};"
        echo
        if [[ "$UU_AUTO_REBOOT" == "y" ]]; then
            echo 'Unattended-Upgrade::Automatic-Reboot "true";'
            echo "Unattended-Upgrade::Automatic-Reboot-Time \"${UU_REBOOT_TIME}\";"
        else
            echo 'Unattended-Upgrade::Automatic-Reboot "false";'
        fi
    } | write_file /etc/apt/apt.conf.d/51harden-unattended-upgrades
    info "Wrote update level (${UU_LEVEL}) and reboot policy to /etc/apt/apt.conf.d/51harden-unattended-upgrades."

    # Pin the actual daily upgrade run to the chosen time — the stock
    # systemd timer runs in a randomized morning/evening window otherwise.
    mkdir -p /etc/systemd/system/apt-daily-upgrade.timer.d
    write_file /etc/systemd/system/apt-daily-upgrade.timer.d/override.conf <<EOF
[Timer]
OnCalendar=
OnCalendar=*-*-* ${UU_INSTALL_TIME}:00
RandomizedDelaySec=0
Persistent=true
EOF
    systemctl daemon-reload
    if systemctl restart apt-daily-upgrade.timer 2>/dev/null; then
        info "Daily upgrade run scheduled for ${UU_INSTALL_TIME}."
    else
        warn "Could not restart apt-daily-upgrade.timer — check 'systemctl status apt-daily-upgrade.timer'."
    fi

    (( DRY_RUN )) && echo "${LOG_PREFIX} would run: systemctl enable --now unattended-upgrades"
    if systemctl enable --now unattended-upgrades &>/dev/null; then
        ok "unattended-upgrades enabled (level=${UU_LEVEL}, checks every ${UU_CHECK_INTERVAL}d)."
    else
        warn "Could not enable unattended-upgrades service — check 'systemctl status unattended-upgrades'."
    fi

    if [[ -n "$UU_NTFY_URL" ]]; then
        mkdir -p /usr/bin/scripts
        write_file /usr/bin/scripts/uu-ntfy-summary.sh <<EOF
#!/bin/bash
LOG=/var/log/unattended-upgrades/unattended-upgrades.log
TODAY=\$(date +%Y-%m-%d)
PATCHED=0
if [[ -f "\$LOG" ]]; then
    PATCHED=\$(grep "\$TODAY" "\$LOG" | grep "Packages that will be upgraded:" | tail -n1 | sed 's/.*upgraded: //' | wc -w)
fi
AVAILABLE=\$(apt list --upgradable 2>/dev/null | grep -c upgradable)
REBOOT="no"
[[ -f /var/run/reboot-required ]] && REBOOT="yes"
curl -s -H p:3 -H title:"Unattended Upgrades" \\
    -d "\$(hostname): \${PATCHED} patched, \${AVAILABLE} still upgradable, reboot required: \${REBOOT}" \\
    "${UU_NTFY_URL}"
EOF
        chmod +x /usr/bin/scripts/uu-ntfy-summary.sh

        # Schedule the summary 15 minutes after the install time.
        local ih im
        IFS=: read -r ih im <<< "$UU_INSTALL_TIME"
        im=$((10#$im + 15)); ih=$((10#$ih))
        if (( im >= 60 )); then im=$((im - 60)); ih=$((ih + 1)); fi
        if (( ih >= 24 )); then ih=$((ih - 24)); fi
        local summary_time; printf -v summary_time "%02d:%02d" "$ih" "$im"

        ( crontab -l 2>/dev/null | grep -v 'uu-ntfy-summary.sh' ; echo "${im} ${ih} * * * /usr/bin/scripts/uu-ntfy-summary.sh" ) | crontab -
        info "Scheduled unattended-upgrades ntfy summary for ${summary_time}."
    fi
}

# ------------------------------------------------------------------------
# 7. SSH hardening (drop-in config, not editing sshd_config directly)
# ------------------------------------------------------------------------
setup_ssh() {
    local dropin_dir="/etc/ssh/sshd_config.d"
    local dropin="${dropin_dir}/99-harden.conf"
    mkdir -p "$dropin_dir"

    if ! grep -q "^Include ${dropin_dir}/\*.conf" /etc/ssh/sshd_config 2>/dev/null; then
        backup_file /etc/ssh/sshd_config
        # Include must be near the top to take effect on older OpenSSH.
        sed -i "1i Include ${dropin_dir}/*.conf" /etc/ssh/sshd_config
        info "Added Include directive for sshd_config.d to sshd_config."
    fi

    {
        echo "# Managed by harden.sh — do not edit by hand"
        echo "Port ${SSH_PORT}"
        echo "AddressFamily inet"
        echo "PubkeyAuthentication yes"
        echo "PasswordAuthentication no"
        echo "PermitRootLogin no"
        echo "PermitEmptyPasswords no"
        echo "IgnoreRhosts yes"
        if [[ "$SSH_EXTRA_LIMITS" == "y" ]]; then
            echo "MaxAuthTries ${SSH_MAX_AUTH_TRIES}"
            echo "LoginGraceTime ${SSH_LOGIN_GRACE_TIME}"
            echo "ClientAliveInterval ${SSH_CLIENT_ALIVE_INTERVAL}"
            echo "ClientAliveCountMax ${SSH_CLIENT_ALIVE_COUNT_MAX}"
            echo "X11Forwarding no"
        fi
        if [[ "$SSH_BANNER" == "y" ]]; then
            if (( DRY_RUN )); then
                echo "${LOG_PREFIX} would write banner to /etc/issue.net, /etc/issue, /etc/motd" >&2
            else
                echo "$BANNER_TEXT" > /etc/issue.net
                echo "$BANNER_TEXT" > /etc/issue
                echo "$BANNER_TEXT" > /etc/motd
            fi
            echo "Banner /etc/issue.net"
        fi
        if [[ "$SSHAUDIT_HARDEN" == "y" ]]; then
            echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256"
            echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
            echo "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com"
            echo "HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com"
        fi
    } | write_file "$dropin"
    info "Wrote SSH hardening drop-in: $dropin"

    if [[ "$SSHAUDIT_HARDEN" == "y" ]]; then
        if [[ -f /etc/ssh/moduli ]]; then
            if (( DRY_RUN )); then
                echo "${LOG_PREFIX} would filter weak DH moduli in /etc/ssh/moduli"
            else
            awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe 2>/dev/null \
                && mv -f /etc/ssh/moduli.safe /etc/ssh/moduli \
                && info "Removed weak Diffie-Hellman moduli." \
                || warn "Could not filter /etc/ssh/moduli — skipping."
            fi
        fi
    fi

    if [[ "$REGEN_HOSTKEYS" == "y" ]]; then
        mkdir -p /etc/ssh/host-key-backup
        if [[ -z "$(ls -A /etc/ssh/host-key-backup 2>/dev/null)" ]]; then
            cp -a /etc/ssh/ssh_host_* /etc/ssh/host-key-backup/ 2>/dev/null
        else
            info "host-key-backup already has the original keys — leaving it as-is."
        fi
        rm -f /etc/ssh/ssh_host_*
        ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" &>/dev/null
        ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" &>/dev/null
        info "Regenerated host keys (old ones backed up to /etc/ssh/host-key-backup)."
    fi

    # Validate before restarting — never restart on a config that fails to parse.
    if (( DRY_RUN )); then
        echo "${LOG_PREFIX} would validate with 'sshd -t' and restart SSH on port ${SSH_PORT}"
    elif sshd -t 2>/tmp/harden-sshd-test.log; then
        info "sshd config validated OK."
        local restart_ok=0
        if systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null; then
            restart_ok=1
        fi
        # On Ubuntu 22.10+/24.04+, SSH is socket-activated: ssh.socket owns
        # the listening port. Relying on the auto-generated socket config
        # to pick up Port from sshd_config turns out to be unreliable (a
        # known systemd/Ubuntu quirk — the generator doesn't consistently
        # honor it) — so an explicit ListenStream override is written
        # directly instead, which is the documented-reliable method.
        # Skipped entirely on systems without socket activation.
        if systemctl list-unit-files ssh.socket &>/dev/null && systemctl is-enabled ssh.socket &>/dev/null; then
            mkdir -p /etc/systemd/system/ssh.socket.d
            {
                echo "[Socket]"
                echo "ListenStream="
                echo "ListenStream=0.0.0.0:${SSH_PORT}"
            } | write_file /etc/systemd/system/ssh.socket.d/override.conf
            systemctl daemon-reload
            if systemctl restart ssh.socket 2>/dev/null; then
                info "Applied explicit ssh.socket override for port ${SSH_PORT}."
            else
                warn "Could not restart ssh.socket — the port change may not have taken effect. Check 'systemctl status ssh.socket'."
                restart_ok=0
            fi
        fi
        if (( restart_ok )); then
            sleep 1
            if command -v ss &>/dev/null && ! ss -ltn 2>/dev/null | grep -q ":${SSH_PORT} "; then
                warn "SSH restarted, but nothing appears to be listening on port ${SSH_PORT} yet — check 'ss -ltn' and 'systemctl status ssh.socket ssh.service' before disconnecting."
            else
                ok "SSH restarted on port ${SSH_PORT}."
            fi
            warn "TEST a NEW SSH session on port ${SSH_PORT} now, before closing this one."
        else
            err "SSH service restart failed — check 'systemctl status ssh'."
        fi
    else
        err "sshd -t validation FAILED — leaving service untouched. Details:"
        cat /tmp/harden-sshd-test.log >&2
        rm -f "$dropin"
        warn "Removed the bad drop-in ($dropin) so the existing SSH session stays safe."
    fi

    if [[ "$ENABLE_NTFY" == "y" ]]; then
        write_file /usr/bin/ntfy-ssh-login.sh <<EOF
#!/bin/bash
if [ "\${PAM_TYPE}" = "open_session" ]; then
  curl -s \\
    -H p:4 \\
    -H tags:information_source \\
    -H title:"SSH Login" \\
    -d "\${PAM_USER}@\${HOSTNAME} from \${PAM_RHOST}" \\
    -L "${NTFY_URL}"
fi
EOF
        chmod +x /usr/bin/ntfy-ssh-login.sh
        if ! grep -q "ntfy-ssh-login.sh" /etc/pam.d/sshd 2>/dev/null; then
            {
                echo "# Ntfy notification on login (added by harden.sh)"
                echo "session optional pam_exec.so /usr/bin/ntfy-ssh-login.sh"
            } | { if (( DRY_RUN )); then echo "${LOG_PREFIX} would append ntfy PAM hook to /etc/pam.d/sshd"; cat > /dev/null; else cat >> /etc/pam.d/sshd; fi; }
            info "Added ntfy SSH login alert to PAM."
        fi
    fi
}

# ------------------------------------------------------------------------
# 8. UFW firewall
# ------------------------------------------------------------------------
setup_ufw() {
    pkg_install ufw net-tools || true

    if [[ -f /etc/default/ufw ]]; then
        sed -i 's/IPV6=yes/IPV6=no/' /etc/default/ufw
    fi

    ufw default deny incoming
    ufw default allow outgoing

    # Drop any SSH rule this script added on a previous run before adding
    # the current one — otherwise a changed port, CIDR or environment type
    # leaves the old rule open alongside the new one. All rules we add
    # carry the [harden.sh] marker so they can be found regardless of what
    # the port or source was on the previous run.
    ufw_remove_tagged() {
        local tag="$1" num
        while true; do
            num=$(ufw status numbered 2>/dev/null | grep -F "$tag" | tail -n1 | grep -oE '^\[ *[0-9]+\]' | tr -d '[] ')
            [[ -z "$num" ]] && break
            ufw --force delete "$num" &>/dev/null
        done
    }
    ufw_remove_tagged "[harden.sh]"
    # Legacy markers from earlier versions of this script.
    ufw_remove_tagged "SSH (LAN)"
    ufw_remove_tagged "SSH (rate-limited)"

    if [[ "$ENV_TYPE" == "internal" ]]; then
        IFS=',' read -ra cidrs <<< "$LAN_CIDRS"
        for cidr in "${cidrs[@]}"; do
            cidr=$(echo "$cidr" | xargs)
            [[ -z "$cidr" ]] && continue
            ufw limit from "$cidr" to any port "$SSH_PORT" comment "[harden.sh] SSH (LAN)"
        done
    else
        ufw limit "${SSH_PORT}/tcp" comment "[harden.sh] SSH (rate-limited)"
    fi

    if [[ "$UFW_LOGGING" == "y" ]]; then
        ufw logging low
        info "UFW logging enabled (low)."
    fi

    ufw --force enable
    ufw reload
    ok "UFW enabled — default deny incoming, SSH allowed on port ${SSH_PORT}."
}

# ------------------------------------------------------------------------
# 9. Fail2ban
# ------------------------------------------------------------------------
setup_fail2ban() {
    pkg_install fail2ban rsyslog

    if [[ -f /etc/fail2ban/fail2ban.conf ]]; then
        cp -f /etc/fail2ban/fail2ban.conf /etc/fail2ban/fail2ban.local
        sed -i 's/loglevel = INFO/loglevel = NOTICE/' /etc/fail2ban/fail2ban.local
    fi

    local banaction="iptables" bantime="87000" ignoreip_line=""
    if [[ "$ENV_TYPE" == "internal" ]]; then
        bantime="300"
        [[ "$ENABLE_NTFY" == "y" ]] && banaction="ntfy"
        # Always keep localhost in the list — setting ignoreip at all
        # overrides fail2ban's built-in default of 127.0.0.1/8 ::1.
        ignoreip_line="ignoreip = 127.0.0.1/8 ::1${F2B_IGNOREIP:+ ${F2B_IGNOREIP}}"
    else
        banaction="iptables[type=allports]"
    fi

    if [[ "$banaction" == "ntfy" ]]; then
        write_file /etc/fail2ban/action.d/ntfy.local <<EOF
[Definition]
actionban = iptables -I f2b-<name> 1 -s <ip> -j <blocktype>
            curl -s -H p:4 -H tags:warning -H title:Fail2Ban -d "Blocked: <ip> on <fq-hostname>" "${NTFY_URL}"
actionunban = iptables -D f2b-<name> -s <ip> -j <blocktype>
EOF
    fi

    mkdir -p /etc/fail2ban/jail.local.d 2>/dev/null || true
    {
        echo "# Managed by harden.sh"
        if [[ -n "$ignoreip_line" ]]; then
            echo "[DEFAULT]"
            echo "$ignoreip_line"
            echo
        fi
        echo "[sshd]"
        echo "enabled = true"
        echo "port = ${SSH_PORT}"
        echo "backend = %(sshd_backend)s"
        echo "bantime = ${bantime}"
        echo "maxretry = 3"
        echo "findtime = 1800"
        echo "banaction = ${banaction}"
        echo "filter = sshd"
    } | write_file /etc/fail2ban/jail.local
    info "Wrote /etc/fail2ban/jail.local (bantime=${bantime}s, banaction=${banaction})."

    (( DRY_RUN )) && echo "${LOG_PREFIX} would run: systemctl enable --now fail2ban"
    if systemctl enable --now fail2ban &>/dev/null; then
        ok "fail2ban enabled and started."
    else
        warn "Could not start fail2ban — check 'systemctl status fail2ban'."
    fi

    if [[ "$ENV_TYPE" == "external" && "$ENABLE_NTFY" == "y" ]]; then
        mkdir -p /usr/bin/scripts
        write_file /usr/bin/scripts/f2b-ntfy.sh <<EOF
#!/bin/bash
export PATH=\$PATH:/usr/local/bin:/usr/bin:/bin
banned=\$(fail2ban-client status sshd 2>/dev/null | grep "Banned IP list:" | sed -E 's/^[^A-Za-z]*Banned IP list:[[:space:]]*//')
if [[ -n "\$banned" ]]; then
  curl -s "${NTFY_URL}" -H ta:no_entry -H p:2 -H title:Fail2Ban -d "\$(hostname) banned IPs: \${banned}"
fi
EOF
        chmod +x /usr/bin/scripts/f2b-ntfy.sh
        ( crontab -l 2>/dev/null | grep -v 'f2b-ntfy.sh' ; echo "0 5 * * * /usr/bin/scripts/f2b-ntfy.sh" ) | crontab -
        info "Daily fail2ban ntfy summary scheduled for 05:00."
    fi
}

# ------------------------------------------------------------------------
# 10. Sysctl hardening
# ------------------------------------------------------------------------
setup_sysctl() {
    if [[ "$SYSCTL_HARDEN" != "y" && "$STRICT_SYSCTL" != "y" && "$DISABLE_COREDUMPS" != "y" ]]; then
        return 0
    fi
    {
        echo "# Managed by harden.sh"
        if [[ "$SYSCTL_HARDEN" == "y" ]]; then
            cat <<'EOF'
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF
        fi
        if [[ "$STRICT_SYSCTL" == "y" ]]; then
            cat <<'EOF'

kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF
        fi
        if [[ "$DISABLE_COREDUMPS" == "y" ]]; then
            echo
            echo "fs.suid_dumpable = 0"
        fi
    } | write_file /etc/sysctl.d/99-harden.conf
    if sysctl --system &>/tmp/harden-sysctl.log; then
        info "sysctl hardening applied."
    else
        warn "sysctl --system reported issues — see /tmp/harden-sysctl.log."
    fi
}

# ------------------------------------------------------------------------
# 10b. Root lockdown, core dumps, secure /tmp+/dev/shm, auditd, AppArmor,
#      password policy — all optional add-ons, each independently gated
# ------------------------------------------------------------------------
setup_root_lock() {
    [[ "$LOCK_ROOT" == "y" ]] || return 0
    if passwd -S root 2>/dev/null | awk '{print $2}' | grep -q '^L'; then
        info "Root account already locked."
    else
        passwd -l root && info "Root account password locked." || warn "Could not lock root account."
    fi
}

setup_shell_timeout() {
    [[ "$SHELL_TIMEOUT" == "y" ]] || return 0
    write_file /etc/profile.d/99-harden-tmout.sh <<EOF
# Managed by harden.sh — auto-logout idle interactive login shells.
TMOUT=${SHELL_TIMEOUT_SECS}
export TMOUT
EOF
    info "Idle shell timeout set to ${SHELL_TIMEOUT_SECS}s (interactive login shells only)."
}

setup_coredumps_limits() {
    [[ "$DISABLE_COREDUMPS" == "y" ]] || return 0
    write_file /etc/security/limits.d/99-harden-nocore.conf <<'EOF'
# Managed by harden.sh
* hard core 0
EOF
    info "Core dumps disabled via limits.d (and fs.suid_dumpable via sysctl)."
}

setup_blacklist_protocols() {
    [[ "$BLACKLIST_PROTOCOLS" == "y" ]] || return 0
    write_file /etc/modprobe.d/harden-blacklist-protocols.conf <<'EOF'
# Managed by harden.sh — prevent rarely-used network protocols from
# being auto-loaded. Does not unload modules already in use.
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF
    info "Blacklisted dccp/sctp/rds/tipc from auto-loading."
}

setup_auditd() {
    [[ "$ENABLE_AUDITD" == "y" ]] || return 0
    if pkg_install auditd audispd-plugins; then
        mkdir -p /etc/audit/rules.d
        write_file /etc/audit/rules.d/harden.rules <<'EOF'
# Managed by harden.sh — watch key security-relevant files
-w /etc/passwd -p wa -k harden-identity
-w /etc/shadow -p wa -k harden-identity
-w /etc/sudoers -p wa -k harden-identity
-w /etc/sudoers.d/ -p wa -k harden-identity
-w /etc/ssh/sshd_config -p wa -k harden-sshd
EOF
        augenrules --load &>/tmp/harden-auditd.log || warn "augenrules --load reported issues — see /tmp/harden-auditd.log."
        (( DRY_RUN )) && echo "${LOG_PREFIX} would run: systemctl enable --now auditd"
        if systemctl enable --now auditd &>/dev/null; then
            info "auditd enabled with basic identity/SSH watch rules."
        else
            warn "Could not start auditd — check 'systemctl status auditd'."
        fi
    fi
}

setup_apparmor_check() {
    [[ "$CHECK_APPARMOR" == "y" ]] || return 0
    if ! command -v aa-status &>/dev/null; then
        pkg_install apparmor apparmor-utils
    fi
    if command -v aa-status &>/dev/null; then
        if aa-status --enabled 2>/dev/null; then
            local summary; summary=$(aa-status 2>/dev/null | head -n 3)
            info "AppArmor is enabled. Status:"
            echo "$summary"
        else
            warn "AppArmor is installed but not enabled — this usually needs a kernel/bootloader check and reboot to fix, so it's left as-is."
        fi
    else
        warn "AppArmor tools unavailable — skipping check."
    fi
}

setup_password_policy() {
    [[ "$PASSWORD_POLICY" == "y" ]] || return 0
    if pkg_install libpam-pwquality; then
        backup_file /etc/security/pwquality.conf
        if grep -q '^minlen' /etc/security/pwquality.conf 2>/dev/null; then
            sed -i "s/^minlen.*/minlen = ${PW_MINLEN}/" /etc/security/pwquality.conf
        else
            echo "minlen = ${PW_MINLEN}" >> /etc/security/pwquality.conf
        fi
    fi
    backup_file /etc/login.defs
    sed -i -E 's/^(PASS_MAX_DAYS\s+).*/\1365/' /etc/login.defs
    sed -i -E 's/^(PASS_MIN_DAYS\s+).*/\11/' /etc/login.defs
    sed -i -E 's/^(PASS_WARN_AGE\s+).*/\114/' /etc/login.defs
    info "Password policy set (minlen=${PW_MINLEN}, max/min/warn age in login.defs). Applies to future password changes and new accounts only — existing sessions are unaffected."
}

# ------------------------------------------------------------------------
# 11. Auto-cleanup: ncdu, tmpreaper, logrotate
# ------------------------------------------------------------------------
# ------------------------------------------------------------------------
# 11b. Persistent journald, rootkit scanning, and post-hardening audits
# ------------------------------------------------------------------------
setup_journald_persistent() {
    [[ "$JOURNALD_PERSIST" == "y" ]] || return 0
    mkdir -p /etc/systemd/journald.conf.d
    write_file /etc/systemd/journald.conf.d/99-harden.conf <<'EOF'
# Managed by harden.sh
[Journal]
Storage=persistent
SystemMaxUse=500M
SystemMaxFileSize=50M
MaxRetentionSec=1month
EOF
    if systemctl restart systemd-journald 2>/dev/null; then
        info "Journald logs are now persistent (capped at 500M / 1 month)."
    else
        warn "Could not restart systemd-journald — check 'systemctl status systemd-journald'."
    fi
}

setup_rootkit_scanners() {
    [[ "$ENABLE_ROOTKIT" == "y" ]] || return 0
    pkg_install rkhunter chkrootkit || true

    # Tune rkhunter to suppress known, well-documented false positives:
    # - WEB_CMD default is a relative path on some installs, which rkhunter
    #   itself flags as invalid at every run.
    # - /etc/.updated and /etc/.resolv.conf.systemd-resolved.bak are normal
    #   systemd/package-manager artifacts, not hidden-file rootkit signs.
    if [[ -f /etc/rkhunter.conf ]]; then
        backup_file /etc/rkhunter.conf
        if (( DRY_RUN )); then
            echo "${LOG_PREFIX} would append false-positive suppressions to /etc/rkhunter.conf"
        else
            {
                echo ""
                echo "# Managed by harden.sh — suppress known false positives"
                echo 'WEB_CMD=""'
                echo "ALLOWHIDDENFILE=/etc/.updated"
                echo "ALLOWHIDDENFILE=/etc/.resolv.conf.systemd-resolved.bak"
            } >> /etc/rkhunter.conf
        fi
        info "Tuned rkhunter config to suppress known false positives (WEB_CMD, known hidden files)."
    elif (( DRY_RUN )); then
        echo "${LOG_PREFIX} would append false-positive suppressions to /etc/rkhunter.conf (after install)"
    fi

    if command -v rkhunter &>/dev/null; then
        run "rkhunter --propupd (baseline file properties)" -- rkhunter --propupd &>/dev/null
    fi

    write_file /usr/bin/scripts/rootkit-scan.sh <<EOF
#!/bin/bash
# Managed by harden.sh — weekly rootkit scan, alerts only on findings.
#
# Self-baselining: the first run on a fresh box captures whatever
# rkhunter/chkrootkit report at that point as the accepted baseline for
# THIS server (a new-user-added warning for a mail package the OS itself
# installed isn't a threat — an unexplained one three months later is).
# Every run after that only alerts on lines that weren't in the baseline.
# To accept new findings as normal going forward (e.g. after intentionally
# installing a new service), delete the relevant file under
# /var/lib/harden-rootkit-scan/ and the next run re-baselines it.
LOG=/var/log/harden-rootkit-scan.log
NTFY_URL="${NTFY_URL}"
BASELINE_DIR=/var/lib/harden-rootkit-scan
mkdir -p "\$BASELINE_DIR"
{
  echo "=== \$(date) ==="
  FINDINGS=0

  if command -v rkhunter &>/dev/null; then
      rkhunter --update --quiet 2>/dev/null
      rkhunter --check --skip-keypress --report-warnings-only 2>&1 | tee /tmp/rkhunter.out
      # Known rkhunter bug: it only greps the literal sshd_config file and
      # doesn't resolve Include'd drop-ins, so it always reports
      # PermitRootLogin as unset even though harden.sh's drop-in sets it
      # (verified separately by the ssh-audit check) — filtered out
      # entirely rather than baselined, since it's not a real signal.
      grep -vi "SSH configuration option 'PermitRootLogin'" /tmp/rkhunter.out \\
          | grep -i "warning" | sort -u > /tmp/rkhunter.current
      if [[ ! -f "\$BASELINE_DIR/rkhunter.baseline" ]]; then
          cp /tmp/rkhunter.current "\$BASELINE_DIR/rkhunter.baseline"
          echo "rkhunter: first run — baseline established with \$(wc -l < /tmp/rkhunter.current) item(s), not alerting."
      else
          new_items=\$(comm -13 "\$BASELINE_DIR/rkhunter.baseline" /tmp/rkhunter.current)
          if [[ -n "\$new_items" ]]; then
              echo "rkhunter: new warnings since baseline:"
              echo "\$new_items"
              FINDINGS=\$((FINDINGS+1))
          fi
      fi
  fi

  if command -v chkrootkit &>/dev/null; then
      # chkrootkit's own convention: clean results say "not infected"
      # (lowercase), an actual finding says "INFECTED" (uppercase) — must
      # be case-sensitive here, or every clean line matches too.
      chkrootkit 2>&1 | tee /tmp/chkrootkit-full.out | grep "INFECTED" | sort -u > /tmp/chkrootkit.current
      if [[ ! -f "\$BASELINE_DIR/chkrootkit.baseline" ]]; then
          cp /tmp/chkrootkit.current "\$BASELINE_DIR/chkrootkit.baseline"
          [[ -s /tmp/chkrootkit.current ]] && echo "chkrootkit: first run — baseline established with \$(wc -l < /tmp/chkrootkit.current) item(s), not alerting."
      else
          new_items=\$(comm -13 "\$BASELINE_DIR/chkrootkit.baseline" /tmp/chkrootkit.current)
          if [[ -n "\$new_items" ]]; then
              echo "chkrootkit: new findings since baseline:"
              echo "\$new_items"
              FINDINGS=\$((FINDINGS+1))
          fi
      fi
  fi

  if [[ \$FINDINGS -gt 0 && -n "\$NTFY_URL" ]]; then
      curl -s -H p:5 -H tags:rotating_light -H title:"Rootkit Scan ALERT" \\
        -d "\$(hostname): rootkit scan reported findings — check \$LOG" "\$NTFY_URL"
  fi
  echo "Findings: \$FINDINGS"
} >> "\$LOG" 2>&1
EOF
    chmod +x /usr/bin/scripts/rootkit-scan.sh

    if (( DRY_RUN )); then
        echo "${LOG_PREFIX} would schedule weekly rootkit scan (Sundays 04:00)"
        echo "${LOG_PREFIX} would run: /usr/bin/scripts/rootkit-scan.sh (establish baseline immediately)"
    else
        ( crontab -l 2>/dev/null | grep -v 'rootkit-scan.sh' ; echo "0 4 * * 0 /usr/bin/scripts/rootkit-scan.sh" ) | crontab -
        info "Weekly rootkit scan scheduled (Sundays 04:00), alerts on findings only."
        info "Running the first scan now to establish this server's baseline (a couple of minutes)..."
        /usr/bin/scripts/rootkit-scan.sh
        info "Baseline established — see /var/log/harden-rootkit-scan.log."
    fi
}

setup_accounting() {
    [[ "$ENABLE_ACCOUNTING" == "y" ]] || return 0
    pkg_install acct sysstat || true

    if [[ -f /etc/default/sysstat ]]; then
        sed -i 's/ENABLED="false"/ENABLED="true"/' /etc/default/sysstat
    fi
    systemctl enable --now sysstat &>/dev/null || warn "Could not enable sysstat — check 'systemctl status sysstat'."
    systemctl enable --now acct 2>/dev/null || service acct start 2>/dev/null || true
    info "Process accounting (acct) and sysstat enabled."
}

run_debsums_check() {
    [[ "$RUN_DEBSUMS" == "y" ]] || return 0
    pkg_install debsums || return 0
    command -v debsums &>/dev/null || return 0

    if (( DRY_RUN )); then
        echo "${LOG_PREFIX} would run: debsums -s (package file integrity check)"
        return 0
    fi
    info "Verifying package file integrity (this can take a minute)..."
    local out; out=$(debsums -s 2>&1 | head -n 20)
    if [[ -z "$out" ]]; then
        info "debsums: all checked package files match their checksums."
    else
        warn "debsums reported modified/missing files:"
        echo "$out"
        warn "Config files are often modified legitimately — review before acting."
    fi
}

run_ssh_audit() {
    [[ "$RUN_SSHAUDIT" == "y" ]] || return 0
    pkg_install ssh-audit || return 0
    command -v ssh-audit &>/dev/null || { warn "ssh-audit not available — skipping verification."; return 0; }

    if (( DRY_RUN )); then
        echo "${LOG_PREFIX} would run: ssh-audit 127.0.0.1:${SSH_PORT}"
        return 0
    fi

    info "Running ssh-audit against 127.0.0.1:${SSH_PORT}..."
    local tries=0 ok_run=0
    while (( tries < 3 )); do
        if ssh-audit -p "${SSH_PORT}" 127.0.0.1 &>/tmp/harden-sshaudit.log; then
            ok_run=1
            break
        fi
        tries=$((tries+1))
        sleep 2
    done

    if (( ok_run )); then
        tail -n 25 /tmp/harden-sshaudit.log
    elif [[ "$SSH_PORT" != "22" ]]; then
        warn "Could not reach SSH on port ${SSH_PORT} after a few tries:"
        tail -n 5 /tmp/harden-sshaudit.log
        warn "Falling back to port 22 (in case the port change hasn't fully applied) just to verify the cipher config."
        if ssh-audit -p 22 127.0.0.1 &>/tmp/harden-sshaudit-22.log; then
            tail -n 25 /tmp/harden-sshaudit-22.log
            warn "That check ran against port 22, not ${SSH_PORT} — confirm SSH is actually listening on ${SSH_PORT} with 'ss -ltn'."
        else
            warn "ssh-audit could not connect on port 22 either:"
            tail -n 5 /tmp/harden-sshaudit-22.log
        fi
    else
        warn "ssh-audit could not connect — verify SSH is listening on ${SSH_PORT} with 'ss -ltn':"
        tail -n 5 /tmp/harden-sshaudit.log
    fi
}

LYNIS_BEFORE=""
LYNIS_AFTER=""

run_lynis_baseline() {
    [[ "$RUN_LYNIS" == "y" ]] || return 0
    pkg_install lynis || return 0
    command -v lynis &>/dev/null || { warn "lynis not available — skipping baseline audit."; return 0; }

    if (( DRY_RUN )); then
        echo "${LOG_PREFIX} would run: lynis audit system --quick (baseline, before hardening)"
        return 0
    fi
    info "Running baseline Lynis audit (before hardening — this takes a couple of minutes)..."
    lynis audit system --quick --quiet --report-file /var/log/harden-lynis-before.dat &>/var/log/harden-lynis-before.log
    LYNIS_BEFORE=$(grep -oE '^hardening_index=[0-9]+' /var/log/harden-lynis-before.dat 2>/dev/null | grep -oE '[0-9]+')
    if [[ -n "$LYNIS_BEFORE" ]]; then
        info "Baseline Lynis hardening index: ${LYNIS_BEFORE}"
    else
        info "Baseline Lynis audit complete."
    fi
}

run_lynis_audit() {
    [[ "$RUN_LYNIS" == "y" ]] || return 0
    pkg_install lynis || return 0
    command -v lynis &>/dev/null || { warn "lynis not available — skipping audit."; return 0; }

    if (( DRY_RUN )); then
        echo "${LOG_PREFIX} would run: lynis audit system --quick (final, after hardening)"
        return 0
    fi
    info "Running final Lynis audit (this takes a couple of minutes)..."
    lynis audit system --quick --quiet --report-file /var/log/harden-lynis-after.dat &>/var/log/harden-lynis-after.log
    LYNIS_AFTER=$(grep -oE '^hardening_index=[0-9]+' /var/log/harden-lynis-after.dat 2>/dev/null | grep -oE '[0-9]+')

    if [[ -n "$LYNIS_BEFORE" && -n "$LYNIS_AFTER" ]]; then
        local delta=$((LYNIS_AFTER - LYNIS_BEFORE)) sign="+"
        (( delta < 0 )) && sign=""
        info "Lynis hardening index: ${LYNIS_BEFORE} -> ${LYNIS_AFTER} (${sign}${delta})"
    elif [[ -n "$LYNIS_AFTER" ]]; then
        info "Lynis hardening index: ${LYNIS_AFTER}"
    else
        info "Lynis audit complete."
    fi
    info "Full report: /var/log/harden-lynis-after.dat"
}

setup_cleanup() {
    pkg_install ncdu logrotate || true

    if pkg_install tmpreaper; then
        local dirs="/tmp/. /var/tmp/."
        [[ -n "$TMPREAPER_EXTRA" ]] && dirs="${dirs} ${TMPREAPER_EXTRA}"
        write_file /etc/tmpreaper.conf <<EOF
# Managed by harden.sh
TMPREAPER_TIME='${TMPREAPER_TIME}'
TMPREAPER_PROTECT_EXTRA=''
TMPREAPER_DIRS='${dirs}'
TMPREAPER_DELAY='256'
TMPREAPER_ADDITIONALOPTIONS=''
EOF
        info "tmpreaper configured (age=${TMPREAPER_TIME}, dirs='${dirs}')."
    fi

    write_file /etc/logrotate.d/harden-varlog <<EOF
/var/log/*.log {
    weekly
    missingok
    rotate ${LOGROTATE_WEEKS}
    compress
    delaycompress
    notifempty
    create 0640 root root
}

# UFW logging is high-volume on an internet-facing host — rotate it
# harder than the general policy above.
/var/log/ufw.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        [ -x /usr/lib/rsyslog/rsyslog-rotate ] && /usr/lib/rsyslog/rsyslog-rotate || true
    endscript
}

/var/log/harden-rootkit-scan.log {
    monthly
    missingok
    rotate 6
    compress
    delaycompress
    notifempty
    create 0640 root root
}

/var/log/unattended-upgrades/*.log {
    weekly
    missingok
    rotate ${LOGROTATE_WEEKS}
    compress
    delaycompress
    notifempty
    create 0640 root root
}

/var/log/lynis.log /var/log/lynis-report.dat /var/log/harden-lynis-before.log /var/log/harden-lynis-before.dat /var/log/harden-lynis-after.log /var/log/harden-lynis-after.dat {
    monthly
    missingok
    rotate 3
    compress
    delaycompress
    notifempty
    create 0640 root root
}
EOF
    info "logrotate policy written (rotate=${LOGROTATE_WEEKS} weeks, plus ufw/rootkit/unattended-upgrades/lynis logs)."

    systemctl enable --now cron 2>/dev/null || warn "Could not enable/start cron — check 'systemctl status cron'."
}

# ------------------------------------------------------------------------
# 12. Summary
# ------------------------------------------------------------------------
print_summary() {
    if (( DRY_RUN )); then
        section "Summary (DRY RUN — nothing was changed)"
    else
        section "Summary"
    fi

    sumline() {
        local label="$1" value="$2" padded
        padded=$(printf "%-23s" "$label")
        echo -e "  ${C_BOLD}${padded}${C_RESET} ${value}"
    }
    # Colorizes a leading y/n token within a larger string, leaving the
    # rest of the text (e.g. "y (locked)") untouched.
    cyn() {
        local s="$1"
        if [[ "$s" == y* ]]; then echo -e "${C_GREEN}y${C_RESET}${s:1}"
        elif [[ "$s" == n* ]]; then echo -e "${C_DIM}n${C_RESET}${s:1}"
        else echo "$s"; fi
    }

    sumline "Environment:"        "${ENV_TYPE}"
    sumline "SSH port:"           "${SSH_PORT} ${C_DIM}(PasswordAuth disabled, PermitRootLogin disabled)${C_RESET}"
    sumline "UFW:"                "${C_GREEN}enabled${C_RESET}, default deny incoming"
    sumline "Fail2ban:"           "${C_GREEN}enabled${C_RESET} on sshd jail"
    if [[ "$UU_LEVEL" == "none" ]]; then
        sumline "Unattended upgrades:" "${C_DIM}disabled${C_RESET}"
    else
        sumline "Unattended upgrades:" "${UU_LEVEL}, checks every ${UU_CHECK_INTERVAL}d, installs at ${UU_INSTALL_TIME}, auto-reboot=$(cyn "$UU_AUTO_REBOOT"), ntfy summary=$(cyn "$( [[ -n "$UU_NTFY_URL" ]] && echo y || echo n )")"
    fi
    sumline "Sysctl hardening:"   "network=$(cyn "$SYSCTL_HARDEN") / kernel=$(cyn "$STRICT_SYSCTL")"
    sumline "Ntfy notifications:" "$(cyn "$ENABLE_NTFY")"
    sumline "Root account:"      "$(cyn "${LOCK_ROOT} (locked)")"
    sumline "Core dumps:"        "$(cyn "${DISABLE_COREDUMPS} (disabled)")"
    sumline "auditd:"            "$(cyn "$ENABLE_AUDITD")"
    sumline "Persistent journal:" "$(cyn "$JOURNALD_PERSIST")"
    sumline "UFW logging:"       "$(cyn "$UFW_LOGGING")"
    if [[ "$SSH_EXTRA_LIMITS" == "y" ]]; then
        sumline "Extra SSH limits:" "$(cyn "y")  MaxAuthTries=${SSH_MAX_AUTH_TRIES}, LoginGraceTime=${SSH_LOGIN_GRACE_TIME}s, ClientAliveInterval=${SSH_CLIENT_ALIVE_INTERVAL}s, ClientAliveCountMax=${SSH_CLIENT_ALIVE_COUNT_MAX}"
    else
        sumline "Extra SSH limits:" "$(cyn "n")"
    fi
    sumline "Rootkit scanners:"  "$(cyn "${ENABLE_ROOTKIT} (weekly, Sundays 04:00)")"
    sumline "Shell idle timeout:" "$(cyn "${SHELL_TIMEOUT}")$( [[ "$SHELL_TIMEOUT" == y ]] && echo " (${SHELL_TIMEOUT_SECS}s)" )"
    sumline "Time sync:"          "$(cyn "$ENABLE_TIMESYNC")"
    sumline "Blacklisted protocols:" "$(cyn "$BLACKLIST_PROTOCOLS")"
    sumline "Process accounting:" "$(cyn "$ENABLE_ACCOUNTING")"
    sumline "Password policy:"   "$(cyn "$PASSWORD_POLICY")"
    sumline "Cleanup:"           "${C_GREEN}configured${C_RESET} (tmpreaper + logrotate)"
    if [[ -n "$LYNIS_BEFORE" || -n "$LYNIS_AFTER" ]]; then
        if [[ -n "$LYNIS_BEFORE" && -n "$LYNIS_AFTER" ]]; then
            local delta=$((LYNIS_AFTER - LYNIS_BEFORE)) sign="+"
            (( delta < 0 )) && sign=""
            sumline "Lynis index:" "${LYNIS_BEFORE} -> ${LYNIS_AFTER} (${sign}${delta})"
        else
            sumline "Lynis index:" "${LYNIS_AFTER:-$LYNIS_BEFORE}"
        fi
    fi
    echo

    warn "Do NOT close this SSH session until you've confirmed a NEW connection works on port ${SSH_PORT}."
    [[ "$REGEN_HOSTKEYS" == "y" ]] && warn "Host keys were regenerated — clients must clear old known_hosts entries."
    echo -e "${C_DIM}Backups of any files this script modified in place were saved as <file>.harden-bak.${C_RESET}"
    echo
    echo -e "${C_BOLD}Reminder:${C_RESET} UFW only allows SSH right now. Add a rule for any other"
    echo "service this host needs to expose, e.g.:"
    echo -e "  ${C_CYAN}sudo ufw allow https${C_RESET}        # or: sudo ufw allow 443/tcp"
    echo -e "  ${C_CYAN}sudo ufw allow http${C_RESET}         # or: sudo ufw allow 80/tcp"
    echo "Check current rules with: sudo ufw status verbose"
}

# ------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------
main() {
    if (( NONINTERACTIVE )); then
        if [[ -z "$CONFIG_FILE" ]]; then
            err "--config/-c requires a file path."
            exit 1
        fi
        if [[ ! -f "$CONFIG_FILE" ]]; then
            err "Config file not found: $CONFIG_FILE"
            exit 1
        fi
        load_config_file "$CONFIG_FILE"
        info "Loaded config from $CONFIG_FILE — running non-interactively, no prompts."
    else
        # If stdin isn't already a terminal (e.g. this script is being piped
        # in via `curl ... | bash`), re-point it at /dev/tty so every prompt
        # below — ours and any external command's, like adduser's password
        # prompt — reads from the keyboard instead of the exhausted pipe.
        if [[ ! -t 0 ]]; then
            if [[ -r /dev/tty ]]; then
                exec < /dev/tty
            else
                err "No terminal available for interactive prompts (running non-interactively with no /dev/tty?)."
                exit 1
            fi
        fi
    fi

    preflight
    gather_config

    if [[ "$RUN_LYNIS" == "y" ]]; then
        section "Baseline Audit"
        run_lynis_baseline
    fi

    section "Account & Access"
    setup_user
    audit_sudo_access
    setup_root_lock
    setup_shell_timeout

    section "System"
    setup_timezone
    setup_timesync
    setup_unattended_upgrades

    section "SSH"
    setup_ssh

    section "Firewall"
    setup_ufw

    section "Intrusion Prevention"
    setup_fail2ban

    section "Kernel & Resource Limits"
    setup_sysctl
    setup_coredumps_limits
    setup_blacklist_protocols

    section "Auditing & Compliance"
    setup_auditd
    setup_apparmor_check
    setup_password_policy
    setup_journald_persistent
    setup_rootkit_scanners
    setup_accounting

    section "Cleanup"
    setup_cleanup

    section "Verification"
    run_debsums_check
    run_ssh_audit
    run_lynis_audit

    print_summary
}

main "$@"
