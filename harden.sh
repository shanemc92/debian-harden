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
# Helpers
# ------------------------------------------------------------------------
LOG_PREFIX="[harden]"
info()  { echo "${LOG_PREFIX} $*"; }
warn()  { echo "${LOG_PREFIX} WARNING: $*" >&2; }
err()   { echo "${LOG_PREFIX} ERROR: $*" >&2; }

ask() {
    # ask "Prompt text" "default" -> echoes the answer
    # Reads from /dev/tty, not stdin — so this still works when the script
    # itself is being piped in via `curl ... | bash` (stdin is the pipe in
    # that case, not the keyboard).
    local prompt="$1" default="${2:-}" reply
    if [[ -n "$default" ]]; then
        read -rp "${prompt} [${default}]: " reply < /dev/tty
        echo "${reply:-$default}"
    else
        read -rp "${prompt}: " reply < /dev/tty
        echo "${reply}"
    fi
}

confirm() {
    # confirm "Prompt text" "y|n" -> return 0 for yes, 1 for no
    local prompt="$1" default="${2:-n}" reply
    local hint="y/N"
    [[ "$default" == "y" ]] && hint="Y/n"
    read -rp "${prompt} [${hint}]: " reply < /dev/tty
    reply="${reply:-$default}"
    [[ "$reply" =~ ^[Yy] ]]
}

backup_file() {
    local f="$1"
    if [[ -f "$f" && ! -f "${f}.harden-bak" ]]; then
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
    echo
    info "=== Configuration ==="

    NEW_USER=$(ask "New sudo user to create (blank to skip)" "")

    SSH_PUBKEY=""
    if [[ -n "$NEW_USER" ]] || confirm "Add an SSH public key to an existing user's authorized_keys?" "y"; then
        [[ -z "$NEW_USER" ]] && EXISTING_USER=$(ask "Which existing username?" "${SUDO_USER:-}")
        SSH_PUBKEY=$(ask "Paste the SSH public key (blank to skip)" "")
    fi

    SSH_PORT=$(ask "SSH port to use" "22")

    echo "Environment type:"
    echo "  1) internal (LAN only, trusted network)"
    echo "  2) external (internet-facing)"
    local envchoice
    envchoice=$(ask "Choose 1 or 2" "1")
    if [[ "$envchoice" == "2" ]]; then ENV_TYPE="external"; else ENV_TYPE="internal"; fi
    info "Environment set to: $ENV_TYPE"

    LAN_CIDRS=""
    if [[ "$ENV_TYPE" == "internal" ]]; then
        LAN_CIDRS=$(ask "Comma-separated CIDR ranges allowed to reach SSH (e.g. 192.168.1.0/24,192.168.2.0/24)" "192.168.1.0/24")
    fi

    CURRENT_TZ=$(timedatectl show -p Timezone --value 2>/dev/null || echo "UTC")
    TIMEZONE=$(ask "Timezone" "$CURRENT_TZ")

    ENABLE_NTFY="n"
    NTFY_URL=""
    if confirm "Enable ntfy notifications (SSH logins + fail2ban bans)?" "n"; then
        ENABLE_NTFY="y"
        NTFY_URL=$(ask "Full ntfy topic URL (e.g. https://ntfy.example.com/mytopic)" "")
        [[ -z "$NTFY_URL" ]] && { warn "No URL given — disabling ntfy."; ENABLE_NTFY="n"; }
    fi

    SSHAUDIT_HARDEN="n"
    confirm "Apply strict ssh-audit cipher/KEX/MAC hardening? (safe, recommended)" "y" && SSHAUDIT_HARDEN="y"

    REGEN_HOSTKEYS="n"
    if [[ "$ENV_TYPE" == "external" ]]; then
        confirm "Regenerate SSH host keys? (invasive — invalidates known_hosts on all existing clients)" "n" && REGEN_HOSTKEYS="y"
    fi

    SYSCTL_HARDEN="n"
    local sysctl_default="n"; [[ "$ENV_TYPE" == "external" ]] && sysctl_default="y"
    confirm "Apply sysctl network hardening (anti-spoofing, disable redirects)?" "$sysctl_default" && SYSCTL_HARDEN="y"

    STRICT_SYSCTL="n"
    confirm "Apply stricter kernel sysctls (ASLR, dmesg/kptr restrict, TCP syncookies)?" "y" && STRICT_SYSCTL="y"

    DISABLE_COREDUMPS="n"
    confirm "Disable core dumps?" "y" && DISABLE_COREDUMPS="y"

    LOCK_ROOT="n"
    confirm "Lock the root account password (on top of disabling root SSH login)?" "y" && LOCK_ROOT="y"

    ENABLE_AUDITD="n"
    confirm "Enable auditd (logs changes to key files like passwd/shadow/sudoers)?" "y" && ENABLE_AUDITD="y"

    CHECK_APPARMOR="n"
    confirm "Check AppArmor status and report any unenforced profiles?" "y" && CHECK_APPARMOR="y"

    PASSWORD_POLICY="n"
    PW_MINLEN="12"
    if confirm "Apply a password quality policy (applies to future password changes only, won't lock out current sessions)?" "y"; then
        PASSWORD_POLICY="y"
        PW_MINLEN=$(ask "Minimum password length" "12")
    fi

    SSH_BANNER="n"
    BANNER_TEXT="Authorized access only. All activity may be monitored and reported."
    if confirm "Add an SSH pre-login banner?" "y"; then
        SSH_BANNER="y"
        BANNER_TEXT=$(ask "Banner text" "$BANNER_TEXT")
    fi

    TMPREAPER_TIME=$(ask "Max age for tmpreaper to clear files in /tmp and /var/tmp" "7d")
    TMPREAPER_EXTRA=$(ask "Extra directories for tmpreaper to clean (space-separated, blank for none)" "")

    LOGROTATE_WEEKS=$(ask "How many weekly log rotations to keep in /var/log/*.log" "4")

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
    mkdir -p "${home_dir}/.ssh"
    touch "${home_dir}/.ssh/authorized_keys"
    if ! grep -qF "$SSH_PUBKEY" "${home_dir}/.ssh/authorized_keys" 2>/dev/null; then
        echo "$SSH_PUBKEY" >> "${home_dir}/.ssh/authorized_keys"
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
    files=$(grep -rl "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true)
    for f in $files; do
        [[ -f "$f" ]] || continue
        if confirm "Found NOPASSWD entries in $f — require a password there too?" "y"; then
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
                if confirm "User '$u' has sudo access but their password is locked/unset — set a real password now? (this replaces the lock with a working password)" "y"; then
                    passwd "$u" || warn "Could not set a password for '$u'."
                fi
                ;;
            NP)
                if confirm "User '$u' has sudo access but NO password is set — set one now?" "y"; then
                    passwd "$u"
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

# ------------------------------------------------------------------------
# 6. Unattended upgrades
# ------------------------------------------------------------------------
setup_unattended_upgrades() {
    pkg_install unattended-upgrades apt-listchanges
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    if systemctl enable --now unattended-upgrades &>/dev/null; then
        info "unattended-upgrades enabled."
    else
        warn "Could not enable unattended-upgrades service — check 'systemctl status unattended-upgrades'."
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
        if [[ "$SSH_BANNER" == "y" ]]; then
            echo "$BANNER_TEXT" > /etc/issue.net
            echo "Banner /etc/issue.net"
        fi
        if [[ "$SSHAUDIT_HARDEN" == "y" ]]; then
            echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256"
            echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
            echo "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com"
            echo "HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com"
        fi
    } > "$dropin"
    info "Wrote SSH hardening drop-in: $dropin"

    if [[ "$SSHAUDIT_HARDEN" == "y" ]]; then
        if [[ -f /etc/ssh/moduli ]]; then
            awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe 2>/dev/null \
                && mv -f /etc/ssh/moduli.safe /etc/ssh/moduli \
                && info "Removed weak Diffie-Hellman moduli." \
                || warn "Could not filter /etc/ssh/moduli — skipping."
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
    if sshd -t 2>/tmp/harden-sshd-test.log; then
        info "sshd config validated OK."
        if systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null; then
            info "SSH restarted on port ${SSH_PORT}."
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
        cat > /usr/bin/ntfy-ssh-login.sh <<EOF
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
            } >> /etc/pam.d/sshd
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
    # the current one — otherwise a changed port/CIDR leaves the old one
    # open alongside the new one.
    ufw_remove_tagged() {
        local tag="$1" num
        while true; do
            num=$(ufw status numbered 2>/dev/null | grep -F "$tag" | tail -n1 | grep -oE '^\[ *[0-9]+\]' | tr -d '[] ')
            [[ -z "$num" ]] && break
            ufw --force delete "$num" &>/dev/null
        done
    }
    ufw_remove_tagged "SSH (LAN)"
    ufw_remove_tagged "SSH (rate-limited)"

    if [[ "$ENV_TYPE" == "internal" ]]; then
        IFS=',' read -ra cidrs <<< "$LAN_CIDRS"
        for cidr in "${cidrs[@]}"; do
            cidr=$(echo "$cidr" | xargs)
            [[ -z "$cidr" ]] && continue
            ufw limit from "$cidr" to any port "$SSH_PORT" comment "SSH (LAN)"
        done
    else
        ufw limit "${SSH_PORT}/tcp" comment "SSH (rate-limited)"
    fi

    ufw --force enable
    ufw reload
    info "UFW enabled — default deny incoming, SSH allowed on port ${SSH_PORT}."
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
        local ignoreip
        ignoreip=$(ask "IP(s) to always allow (space-separated, e.g. your admin workstation)" "")
        [[ -n "$ignoreip" ]] && ignoreip_line="ignoreip = ${ignoreip}"
    else
        banaction="iptables[type=allports]"
    fi

    if [[ "$banaction" == "ntfy" ]]; then
        cat > /etc/fail2ban/action.d/ntfy.local <<EOF
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
    } > /etc/fail2ban/jail.local
    info "Wrote /etc/fail2ban/jail.local (bantime=${bantime}s, banaction=${banaction})."

    if systemctl enable --now fail2ban &>/dev/null; then
        info "fail2ban enabled and started."
    else
        warn "Could not start fail2ban — check 'systemctl status fail2ban'."
    fi

    if [[ "$ENV_TYPE" == "external" && "$ENABLE_NTFY" == "y" ]]; then
        mkdir -p /usr/bin/scripts
        cat > /usr/bin/scripts/f2b-ntfy.sh <<EOF
#!/bin/bash
export PATH=\$PATH:/usr/local/bin:/usr/bin:/bin
banned=\$(fail2ban-client status sshd 2>/dev/null | grep "Banned IP list:")
if [[ -n "\$banned" ]]; then
  curl -s "${NTFY_URL}" -H ta:no_entry -H p:2 -H title:Fail2Ban -d "\$(hostname) \${banned}"
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
net.ipv4.tcp_syncookies = 1
EOF
        fi
        if [[ "$DISABLE_COREDUMPS" == "y" ]]; then
            echo
            echo "fs.suid_dumpable = 0"
        fi
    } > /etc/sysctl.d/99-harden.conf
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

setup_coredumps_limits() {
    [[ "$DISABLE_COREDUMPS" == "y" ]] || return 0
    cat > /etc/security/limits.d/99-harden-nocore.conf <<'EOF'
# Managed by harden.sh
* hard core 0
EOF
    info "Core dumps disabled via limits.d (and fs.suid_dumpable via sysctl)."
}

setup_auditd() {
    [[ "$ENABLE_AUDITD" == "y" ]] || return 0
    if pkg_install auditd audispd-plugins; then
        mkdir -p /etc/audit/rules.d
        cat > /etc/audit/rules.d/harden.rules <<'EOF'
# Managed by harden.sh — watch key security-relevant files
-w /etc/passwd -p wa -k harden-identity
-w /etc/shadow -p wa -k harden-identity
-w /etc/sudoers -p wa -k harden-identity
-w /etc/sudoers.d/ -p wa -k harden-identity
-w /etc/ssh/sshd_config -p wa -k harden-sshd
EOF
        augenrules --load &>/tmp/harden-auditd.log || warn "augenrules --load reported issues — see /tmp/harden-auditd.log."
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
setup_cleanup() {
    pkg_install ncdu logrotate || true

    if pkg_install tmpreaper; then
        local dirs="/tmp/. /var/tmp/."
        [[ -n "$TMPREAPER_EXTRA" ]] && dirs="${dirs} ${TMPREAPER_EXTRA}"
        cat > /etc/tmpreaper.conf <<EOF
# Managed by harden.sh
TMPREAPER_TIME='${TMPREAPER_TIME}'
TMPREAPER_PROTECT_EXTRA=''
TMPREAPER_DIRS='${dirs}'
TMPREAPER_DELAY='256'
TMPREAPER_ADDITIONALOPTIONS=''
EOF
        info "tmpreaper configured (age=${TMPREAPER_TIME}, dirs='${dirs}')."
    fi

    cat > /etc/logrotate.d/harden-varlog <<EOF
/var/log/*.log {
    weekly
    missingok
    rotate ${LOGROTATE_WEEKS}
    compress
    delaycompress
    notifempty
    create 0640 root root
}
EOF
    info "logrotate policy written (rotate=${LOGROTATE_WEEKS} weeks)."

    systemctl enable --now cron 2>/dev/null || warn "Could not enable/start cron — check 'systemctl status cron'."
}

# ------------------------------------------------------------------------
# 12. Summary
# ------------------------------------------------------------------------
print_summary() {
    echo
    info "=== Summary ==="
    echo "  Environment:        ${ENV_TYPE}"
    echo "  SSH port:           ${SSH_PORT}  (PasswordAuth disabled, PermitRootLogin disabled)"
    echo "  UFW:                enabled, default deny incoming"
    echo "  Fail2ban:           enabled on sshd jail"
    echo "  Unattended upgrades: enabled"
    echo "  Sysctl hardening:   ${SYSCTL_HARDEN} (network) / ${STRICT_SYSCTL} (kernel)"
    echo "  Ntfy notifications: ${ENABLE_NTFY}"
    echo "  Root account:       ${LOCK_ROOT} (locked)"
    echo "  Core dumps:         ${DISABLE_COREDUMPS} (disabled)"
    echo "  auditd:             ${ENABLE_AUDITD}"
    echo "  Password policy:    ${PASSWORD_POLICY}"
    echo "  Cleanup:            tmpreaper + logrotate configured"
    echo
    warn "Do NOT close this SSH session until you've confirmed a NEW connection works on port ${SSH_PORT}."
    [[ "$REGEN_HOSTKEYS" == "y" ]] && warn "Host keys were regenerated — clients must clear old known_hosts entries."
    echo "Backups of any files this script modified in place were saved as <file>.harden-bak."
    echo
    echo "Reminder: UFW only allows SSH right now. Add a rule for any other"
    echo "service this host needs to expose, e.g.:"
    echo "  sudo ufw allow https        # or: sudo ufw allow 443/tcp"
    echo "  sudo ufw allow http         # or: sudo ufw allow 80/tcp"
    echo "Check current rules with: sudo ufw status verbose"
}

# ------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------
main() {
    # If stdin isn't already a terminal (e.g. this script is being piped in
    # via `curl ... | bash`), re-point it at /dev/tty so every prompt below
    # — ours and any external command's, like adduser's password prompt —
    # reads from the keyboard instead of the exhausted pipe.
    if [[ ! -t 0 ]]; then
        if [[ -r /dev/tty ]]; then
            exec < /dev/tty
        else
            err "No terminal available for interactive prompts (running non-interactively with no /dev/tty?)."
            exit 1
        fi
    fi

    preflight
    gather_config
    setup_user
    audit_sudo_access
    setup_root_lock
    setup_timezone
    setup_unattended_upgrades
    setup_ssh
    setup_ufw
    setup_fail2ban
    setup_sysctl
    setup_coredumps_limits
    setup_auditd
    setup_apparmor_check
    setup_password_policy
    setup_cleanup
    print_summary
}

main "$@"
