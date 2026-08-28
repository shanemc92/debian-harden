#!/usr/bin/env bash
#
# harden-undo.sh - Selectively reverse changes made by harden.sh.
#
# Asks about each change independently — answer 'n' to leave anything
# you're happy with untouched. Only checks for and offers to reverse
# things that are actually present on this system.
#
# Usage: sudo bash harden-undo.sh
#
set -uo pipefail

# ------------------------------------------------------------------------
# Helpers (same conventions as harden.sh)
# ------------------------------------------------------------------------
LOG_PREFIX="[undo]"
info()  { echo "${LOG_PREFIX} $*"; }
warn()  { echo "${LOG_PREFIX} WARNING: $*" >&2; }
err()   { echo "${LOG_PREFIX} ERROR: $*" >&2; }

confirm() {
    local prompt="$1" default="${2:-n}" reply
    local hint="y/N"
    [[ "$default" == "y" ]] && hint="Y/n"
    read -rp "${prompt} [${hint}]: " reply < /dev/tty
    reply="${reply:-$default}"
    [[ "$reply" =~ ^[Yy] ]]
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root (sudo bash harden-undo.sh)."
        exit 1
    fi
}

restore_backup() {
    # restore_backup /path/to/file -> 0 if a .harden-bak existed and was restored
    local file="$1"
    if [[ -f "${file}.harden-bak" ]]; then
        cp -a "${file}.harden-bak" "$file"
        info "Restored ${file} from ${file}.harden-bak."
        return 0
    fi
    return 1
}

remove_sysctl_keys() {
    local file="/etc/sysctl.d/99-harden.conf"
    [[ -f "$file" ]] || return 0
    for key in "$@"; do
        sed -i "/^${key} /d" "$file"
    done
    # drop the file entirely if nothing but comments/blank lines remain
    if ! grep -qE '^[a-zA-Z]' "$file"; then
        rm -f "$file"
    fi
    sysctl --system &>/tmp/harden-undo-sysctl.log \
        || warn "sysctl --system reported issues after revert — see /tmp/harden-undo-sysctl.log. A reboot fully clears any leftover runtime values."
}

CHANGED=0
note_change() { CHANGED=$((CHANGED+1)); }

# ------------------------------------------------------------------------
# 1. SSH hardening drop-in (port, password auth, root login, ciphers, banner)
# ------------------------------------------------------------------------
revert_ssh() {
    local dropin="/etc/ssh/sshd_config.d/99-harden.conf"
    [[ -f "$dropin" ]] || { info "SSH hardening drop-in not found — skipping."; return 0; }

    echo
    if confirm "Revert SSH hardening? This restores port 22, re-enables password authentication and root login, and removes the banner/cipher restrictions. Only do this if SSH access is currently broken." "n"; then
        rm -f "$dropin"
        restore_backup /etc/ssh/sshd_config || true
        if sshd -t 2>/tmp/harden-undo-sshd.log; then
            if systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null; then
                info "SSH hardening reverted and service restarted on the default port (22)."
                warn "If UFW only allows your custom SSH port, add a rule for port 22 too (or whatever port you're now using) before you disconnect."
            else
                err "Reverted config but SSH service restart failed — check 'systemctl status ssh'."
            fi
        else
            err "sshd -t validation failed after revert — see /tmp/harden-undo-sshd.log. Left the service untouched."
        fi
        note_change
    fi
}

# ------------------------------------------------------------------------
# 2. Regenerated SSH host keys
# ------------------------------------------------------------------------
revert_hostkeys() {
    local backup_dir="/etc/ssh/host-key-backup"
    [[ -d "$backup_dir" ]] && [[ -n "$(ls -A "$backup_dir" 2>/dev/null)" ]] || return 0

    echo
    if confirm "Restore the original SSH host keys (from before regeneration)? Clients won't need to clear known_hosts again." "n"; then
        mkdir -p /etc/ssh/host-key-regen-backup
        cp -a /etc/ssh/ssh_host_* /etc/ssh/host-key-regen-backup/ 2>/dev/null
        cp -a "${backup_dir}"/ssh_host_* /etc/ssh/ 2>/dev/null
        if sshd -t 2>/tmp/harden-undo-hostkeys.log; then
            systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
            info "Original host keys restored (regenerated ones saved to /etc/ssh/host-key-regen-backup)."
        else
            err "sshd -t validation failed after restoring host keys — see /tmp/harden-undo-hostkeys.log."
        fi
        note_change
    fi
}

# ------------------------------------------------------------------------
# 3. UFW firewall
# ------------------------------------------------------------------------
revert_ufw() {
    command -v ufw &>/dev/null || return 0
    ufw status 2>/dev/null | grep -q "Status: active" || { info "UFW is not active — skipping."; return 0; }

    echo
    if confirm "Disable UFW entirely? This removes ALL firewall protection, not just what harden.sh added." "n"; then
        ufw --force disable
        info "UFW disabled."
        note_change
    fi
}

# ------------------------------------------------------------------------
# 4. fail2ban
# ------------------------------------------------------------------------
revert_fail2ban() {
    [[ -f /etc/fail2ban/jail.local ]] || { info "No fail2ban jail.local found — skipping."; return 0; }

    echo
    if confirm "Disable fail2ban and remove its custom config (jail.local, ntfy action, alert cron job)?" "n"; then
        systemctl disable --now fail2ban &>/dev/null
        rm -f /etc/fail2ban/jail.local /etc/fail2ban/action.d/ntfy.local
        restore_backup /etc/fail2ban/fail2ban.conf || rm -f /etc/fail2ban/fail2ban.local
        rm -f /usr/bin/scripts/f2b-ntfy.sh
        crontab -l 2>/dev/null | grep -v 'f2b-ntfy.sh' | crontab - 2>/dev/null || true
        info "fail2ban disabled and custom config removed."
        note_change
    fi
}

# ------------------------------------------------------------------------
# 5. Unattended upgrades
# ------------------------------------------------------------------------
revert_unattended_upgrades() {
    [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]] || return 0

    echo
    if confirm "Disable automatic unattended upgrades?" "n"; then
        systemctl disable --now unattended-upgrades &>/dev/null
        rm -f /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/51harden-unattended-upgrades
        rm -rf /etc/systemd/system/apt-daily-upgrade.timer.d
        systemctl daemon-reload
        systemctl restart apt-daily-upgrade.timer 2>/dev/null || true
        rm -f /usr/bin/scripts/uu-ntfy-summary.sh
        crontab -l 2>/dev/null | grep -v 'uu-ntfy-summary.sh' | crontab - 2>/dev/null || true
        info "Unattended upgrades disabled and custom config/timer/cron removed."
        note_change
    fi
}

# ------------------------------------------------------------------------
# 6. Root account lock
# ------------------------------------------------------------------------
revert_root_lock() {
    command -v passwd &>/dev/null || return 0
    passwd -S root 2>/dev/null | awk '{print $2}' | grep -q '^L' || return 0

    echo
    if confirm "Unlock the root account password?" "n"; then
        passwd -u root && info "Root account unlocked." || warn "Could not unlock root account."
        note_change
    fi
}

# ------------------------------------------------------------------------
# 7. Core dumps
# ------------------------------------------------------------------------
revert_coredumps() {
    [[ -f /etc/security/limits.d/99-harden-nocore.conf ]] || return 0

    echo
    if confirm "Re-enable core dumps?" "n"; then
        rm -f /etc/security/limits.d/99-harden-nocore.conf
        remove_sysctl_keys "fs.suid_dumpable"
        info "Core dumps re-enabled."
        note_change
    fi
}

# ------------------------------------------------------------------------
# 8. Sysctl hardening (network + strict kernel), asked separately
# ------------------------------------------------------------------------
revert_sysctl_network() {
    grep -qE '^net\.ipv[46]\.conf\.all\.accept_redirects' /etc/sysctl.d/99-harden.conf 2>/dev/null || return 0

    echo
    if confirm "Revert network sysctl hardening (redirects/source-route/rp_filter)?" "n"; then
        remove_sysctl_keys \
            "net.ipv4.conf.all.accept_redirects" "net.ipv6.conf.all.accept_redirects" \
            "net.ipv4.conf.default.accept_redirects" "net.ipv6.conf.default.accept_redirects" \
            "net.ipv4.conf.all.accept_source_route" "net.ipv6.conf.all.accept_source_route" \
            "net.ipv4.conf.default.accept_source_route" "net.ipv6.conf.default.accept_source_route" \
            "net.ipv4.conf.all.rp_filter" "net.ipv4.conf.default.rp_filter"
        info "Network sysctl hardening reverted."
        note_change
    fi
}

revert_sysctl_strict() {
    grep -qE '^kernel\.randomize_va_space' /etc/sysctl.d/99-harden.conf 2>/dev/null || return 0

    echo
    if confirm "Revert strict kernel sysctls (ASLR/kptr/dmesg restrict, TCP syncookies)?" "n"; then
        remove_sysctl_keys "kernel.randomize_va_space" "kernel.kptr_restrict" "kernel.dmesg_restrict" "net.ipv4.tcp_syncookies"
        info "Strict kernel sysctls reverted."
        note_change
    fi
}

# ------------------------------------------------------------------------
# 9. auditd
# ------------------------------------------------------------------------
revert_auditd() {
    [[ -f /etc/audit/rules.d/harden.rules ]] || return 0

    echo
    if confirm "Disable auditd and remove its watch rules?" "n"; then
        rm -f /etc/audit/rules.d/harden.rules
        command -v augenrules &>/dev/null && augenrules --load &>/dev/null
        systemctl disable --now auditd &>/dev/null
        info "auditd disabled and watch rules removed."
        note_change
    fi
}

# ------------------------------------------------------------------------
# 10. Password policy
# ------------------------------------------------------------------------
revert_password_policy() {
    [[ -f /etc/security/pwquality.conf || -f /etc/login.defs ]] || return 0
    grep -q '^minlen' /etc/security/pwquality.conf 2>/dev/null || \
        grep -qE '^PASS_MAX_DAYS\s+365' /etc/login.defs 2>/dev/null || return 0

    echo
    if confirm "Revert password policy (pwquality minlen + login.defs aging)?" "n"; then
        restore_backup /etc/security/pwquality.conf || sed -i '/^minlen/d' /etc/security/pwquality.conf 2>/dev/null
        if ! restore_backup /etc/login.defs; then
            sed -i -E 's/^(PASS_MAX_DAYS\s+).*/\199999/' /etc/login.defs
            sed -i -E 's/^(PASS_MIN_DAYS\s+).*/\10/' /etc/login.defs
            sed -i -E 's/^(PASS_WARN_AGE\s+).*/\17/' /etc/login.defs
        fi
        info "Password policy reverted."
        note_change
    fi
}

# ------------------------------------------------------------------------
# 11. Raspberry Pi passwordless sudo
# ------------------------------------------------------------------------
revert_sudoers_nopasswd() {
    local files f
    files=$(find /etc/sudoers /etc/sudoers.d/ -maxdepth 1 -name '*.harden-bak' 2>/dev/null)
    [[ -n "$files" ]] || return 0

    for bak in $files; do
        f="${bak%.harden-bak}"
        echo
        if confirm "Restore passwordless sudo from ${f} (undo the password requirement harden.sh added)? This lowers security." "n"; then
            restore_backup "$f"
            info "Restored NOPASSWD sudo access from ${f}."
            note_change
        fi
    done
}

# ------------------------------------------------------------------------
# 12. ntfy SSH login hook
# ------------------------------------------------------------------------
revert_ntfy_hook() {
    grep -q "ntfy-ssh-login.sh" /etc/pam.d/sshd 2>/dev/null || return 0

    echo
    if confirm "Remove the ntfy SSH-login notification hook?" "n"; then
        sed -i '/ntfy-ssh-login\.sh/d' /etc/pam.d/sshd
        sed -i '/^# Ntfy notification on login/d' /etc/pam.d/sshd
        rm -f /usr/bin/ntfy-ssh-login.sh
        info "ntfy SSH-login hook removed."
        note_change
    fi
}

# ------------------------------------------------------------------------
# 13. Cleanup config (tmpreaper, logrotate)
# ------------------------------------------------------------------------
revert_cleanup() {
    [[ -f /etc/tmpreaper.conf || -f /etc/logrotate.d/harden-varlog ]] || return 0

    echo
    if confirm "Remove the tmpreaper/logrotate cleanup config added by harden.sh?" "n"; then
        rm -f /etc/tmpreaper.conf /etc/logrotate.d/harden-varlog
        info "Cleanup config removed."
        note_change
    fi
}

# ------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------
main() {
    require_root
    if [[ ! -t 0 ]]; then
        if [[ -r /dev/tty ]]; then
            exec < /dev/tty
        else
            err "No terminal available for interactive prompts."
            exit 1
        fi
    fi

    info "Checking what's present and asking about each — 'n' or Enter leaves it as-is."

    revert_ssh
    revert_hostkeys
    revert_ufw
    revert_fail2ban
    revert_unattended_upgrades
    revert_root_lock
    revert_coredumps
    revert_sysctl_network
    revert_sysctl_strict
    revert_auditd
    revert_password_policy
    revert_sudoers_nopasswd
    revert_ntfy_hook
    revert_cleanup

    echo
    if [[ $CHANGED -eq 0 ]]; then
        info "Nothing was changed."
    else
        info "Done — ${CHANGED} change(s) reverted."
        warn "If you reverted SSH hardening, test a new connection before closing this session."
    fi
}

main "$@"
