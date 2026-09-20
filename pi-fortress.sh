#!/bin/bash

################################################################################
# Pi Fortress - Raspberry Pi Security Hardening Script                         #
#                                                                              #
# Comprehensive automated security configuration for fresh Raspberry Pi        #
# installations. Implements SSH hardening, firewall setup, Fail2Ban intrusion  #
# prevention, automatic updates, rootkit detection, and industry-standard      #
# security best practices.                                                     #
#                                                                              #
# Author: Sharon Hazan (https://github.com/Sharonhazan)                        #
# Repository: https://github.com/Sharonhazan/pi-fortress                       #
# License: MIT                                                                 #
#                                                                              #
# Usage: sudo bash pi-fortress.sh                                              #
################################################################################

set -Eeuo pipefail

# Never let a package prompt block an unattended run
export DEBIAN_FRONTEND=noninteractive

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log file
LOGFILE="/var/log/pi_security_hardening.log"
LOG_READY=0

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_DIR="/etc/ssh/sshd_config.d"
SSHD_HARDENING="$SSHD_CONFIG_DIR/hardening.conf"

# Results of each step, reported in the summary at the end
STEPS_OK=()
STEPS_FAILED=()
STEPS_SKIPPED=()

# Exit code a step uses to report "nothing to do here"
readonly STEP_SKIPPED=2

# Functions to print colored output
log_line() {
    if [ "$LOG_READY" -eq 1 ]; then
        printf '%s\n' "$1" >> "$LOGFILE"
    fi
}

print_status() {
    echo -e "${GREEN}[+]${NC} $1"
    log_line "[+] $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    log_line "[!] $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1" >&2
    log_line "[-] $1"
}

# Report where a step died instead of leaving the failure unexplained. The trap
# is inherited by each step's subshell, where it can fire both for the failing
# command and again for the function returning non-zero, so only the first
# report is kept.
ERR_REPORTED=0

report_failure() {
    local rc="$1"
    local line="$2"

    if [ "$rc" -eq "$STEP_SKIPPED" ] || [ "$ERR_REPORTED" -eq 1 ]; then
        return 0
    fi
    ERR_REPORTED=1
    print_error "Unexpected failure at line $line (exit $rc)"
}

trap 'report_failure "$?" "$LINENO"' ERR

# Check if running as root before anything tries to write to the log file
if [ "$EUID" -ne 0 ]; then
    print_error "Please run as root (use sudo)"
    exit 1
fi

touch "$LOGFILE"
LOG_READY=1

# Optional prompts are skipped when there is no terminal to answer them
if [ -t 0 ]; then
    INTERACTIVE=1
else
    INTERACTIVE=0
fi

# Raspberry Pi boot config path (Bookworm uses /boot/firmware, older uses /boot)
BOOT_CONFIG="/boot/firmware/config.txt"
if [ ! -f "$BOOT_CONFIG" ]; then
    BOOT_CONFIG="/boot/config.txt"
fi

SSHD_BIN="$(command -v sshd || echo /usr/sbin/sshd)"

NOLOGIN_SHELL="/usr/sbin/nologin"
[ -x "$NOLOGIN_SHELL" ] || NOLOGIN_SHELL="/sbin/nologin"

###############################################################################
# HELPERS
###############################################################################

# Run one hardening step in a subshell so that a failure is reported and the
# remaining steps still run, instead of aborting the whole script halfway.
run_step() {
    local name="$1"
    local func="$2"
    local rc=0

    echo ""
    print_status "$name..."

    # The subshell must stay a standalone command: inside a || list bash would
    # disable errexit for it, and the step would carry on past its own failure.
    # Pre-marking the failure as reported stops the ERR trap from repeating the
    # message here, since the subshell already printed the real failing line.
    ERR_REPORTED=1
    set +e
    ( set -Ee; ERR_REPORTED=0; "$func" )
    rc=$?
    set -e
    ERR_REPORTED=0

    case "$rc" in
        0)
            STEPS_OK+=("$name")
            ;;
        "$STEP_SKIPPED")
            STEPS_SKIPPED+=("$name")
            ;;
        *)
            print_error "Step failed: $name - continuing with the remaining steps"
            STEPS_FAILED+=("$name")
            ;;
    esac
}

is_yes() {
    case "${1,,}" in
        y|yes) return 0 ;;
        *) return 1 ;;
    esac
}

# The systemd unit for OpenSSH is "ssh" on Debian and "sshd" elsewhere
ssh_service_unit() {
    local unit
    for unit in ssh sshd; do
        if systemctl cat "$unit.service" > /dev/null 2>&1; then
            echo "$unit"
            return 0
        fi
    done
    echo "ssh"
}

# Ports sshd actually listens on, so the firewall rules match the SSH config
sshd_ports() {
    local ports=""
    ports="$("$SSHD_BIN" -T 2>/dev/null | awk '$1 == "port" { print $2 }')" || ports=""
    if [ -z "$ports" ]; then
        ports="22"
    fi
    echo "$ports"
}

# Is the default route leaving over a wireless interface? Disabling WiFi on such
# a machine would cut the connection this script is most likely running over.
default_route_is_wireless() {
    local iface
    for iface in $(ip -o route show default 2>/dev/null |
        awk '{ for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1) }'); do
        if [ -d "/sys/class/net/$iface/wireless" ] || [ -e "/sys/class/net/$iface/phy80211" ]; then
            echo "$iface"
            return 0
        fi
    done
    return 1
}

# Append a line to config.txt at most once, and make sure it lands in an [all]
# section so it applies to every model rather than the last filtered section.
add_boot_config_line() {
    local line="$1"
    local last_section

    if [ ! -f "$BOOT_CONFIG" ]; then
        print_warning "No Raspberry Pi boot config found - cannot add '$line'"
        return 1
    fi

    if grep -qxF "$line" "$BOOT_CONFIG"; then
        print_status "'$line' is already present in $BOOT_CONFIG"
        return 0
    fi

    last_section="$(grep -o '^\[[^]]*\]' "$BOOT_CONFIG" | tail -n 1 || true)"
    if [ "$last_section" != "[all]" ]; then
        printf '\n[all]\n' >> "$BOOT_CONFIG"
    fi
    printf '%s\n' "$line" >> "$BOOT_CONFIG"
    print_status "Added '$line' to $BOOT_CONFIG"
}

###############################################################################
# 1. UPDATE SYSTEM
###############################################################################
step_update_system() {
    apt-get update
    apt-get upgrade -y
    apt-get dist-upgrade -y
    apt-get autoremove -y
    apt-get autoclean -y
}

###############################################################################
# 2. SSH HARDENING
###############################################################################
step_ssh_hardening() {
    local backup unit mode
    backup="${SSHD_CONFIG}.backup.$(date +%Y%m%d-%H%M%S)"

    # Backup original SSH config (timestamped to preserve previous backups on re-runs)
    cp "$SSHD_CONFIG" "$backup"
    print_status "Current SSH config backed up to $backup"

    mkdir -p "$SSHD_CONFIG_DIR"

    # sshd only reads the drop-in directory when the main config includes it.
    # Without this check the hardening below can be silently ignored.
    if ! grep -Eqi "^[[:space:]]*Include[[:space:]]+${SSHD_CONFIG_DIR}/\*\.conf" "$SSHD_CONFIG"; then
        print_warning "$SSHD_CONFIG does not include $SSHD_CONFIG_DIR - adding the Include directive"
        mode="$(stat -c '%a' "$SSHD_CONFIG")"
        printf 'Include %s/*.conf\n' "$SSHD_CONFIG_DIR" > "${SSHD_CONFIG}.tmp"
        cat "$SSHD_CONFIG" >> "${SSHD_CONFIG}.tmp"
        mv "${SSHD_CONFIG}.tmp" "$SSHD_CONFIG"
        chmod "$mode" "$SSHD_CONFIG"
    fi

    # SSH Configuration
    cat > "$SSHD_HARDENING" << 'EOF'
# Disable root login
PermitRootLogin no

# Disable password authentication (use key-based only)
# COMMENTED OUT - Enable after setting up SSH keys
#PasswordAuthentication no

# Enable public key authentication
PubkeyAuthentication yes

# Disable empty passwords
PermitEmptyPasswords no

# Disable X11 forwarding
X11Forwarding no

# Set login grace time
LoginGraceTime 60

# Maximum authentication attempts
MaxAuthTries 3

# Maximum sessions
MaxSessions 2

# Use only strong ciphers
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# Use only strong MACs
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

# Use only strong Key Exchange algorithms
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Disable agent forwarding
AllowAgentForwarding no

# Disable TCP forwarding
AllowTcpForwarding no

# Set client alive interval (detect dead connections)
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

    # Validate before restarting: an invalid config would leave sshd refusing to
    # start, locking out every remote user.
    if ! "$SSHD_BIN" -t; then
        print_error "The new SSH configuration is invalid - rolling back"
        rm -f "$SSHD_HARDENING"
        cp "$backup" "$SSHD_CONFIG"
        return 1
    fi
    print_status "New SSH configuration validated"

    unit="$(ssh_service_unit)"
    if ! systemctl restart "$unit"; then
        print_error "$unit failed to restart - rolling back the hardening config"
        rm -f "$SSHD_HARDENING"
        cp "$backup" "$SSHD_CONFIG"
        systemctl restart "$unit" ||
            print_error "$unit is still down - restore SSH access before disconnecting!"
        return 1
    fi
    print_status "SSH service ($unit) restarted"

    # Confirm the drop-in is in effect rather than quietly ignored
    if "$SSHD_BIN" -T 2>/dev/null | grep -qix "permitrootlogin no"; then
        print_status "SSH hardened. Root login disabled."
    else
        print_warning "Could not confirm that $SSHD_HARDENING is in effect - check it manually"
    fi
    print_warning "Password authentication still enabled. Disable after setting up SSH keys!"
}

###############################################################################
# 3. SETUP SSH KEY AUTHENTICATION HELPER
###############################################################################
step_ssh_key_helper() {
    cat > /root/setup_ssh_keys.sh << 'EOF'
#!/bin/bash
echo "SSH Key Setup Helper"
echo "===================="
echo "1. On your LOCAL machine, generate SSH key (if you haven't):"
echo "   ssh-keygen -t ed25519 -C 'your_email@example.com'"
echo ""
echo "2. Copy the key to this Pi:"
echo "   ssh-copy-id username@$(hostname -I | awk '{print $1}')"
echo ""
echo "3. Test the connection from your local machine"
echo ""
echo "4. Once working, disable password authentication:"
echo "   Edit /etc/ssh/sshd_config.d/hardening.conf"
echo "   Uncomment: PasswordAuthentication no"
echo "   Then: sudo systemctl restart ssh"
EOF
    chmod +x /root/setup_ssh_keys.sh
    print_status "SSH key setup helper created: /root/setup_ssh_keys.sh"
}

###############################################################################
# 4. INSTALL AND CONFIGURE FAIL2BAN
###############################################################################
step_fail2ban() {
    local backend logpath

    apt-get install -y fail2ban

    # The sshd jail needs a log source. Images without rsyslog have no
    # /var/log/auth.log, and pointing the jail at a missing file stops
    # Fail2Ban from starting at all - read the journal instead.
    if [ -f /var/log/auth.log ]; then
        backend="auto"
        logpath="logpath = /var/log/auth.log"
    else
        backend="systemd"
        logpath="# no /var/log/auth.log on this system, the journal is used instead"
        print_warning "/var/log/auth.log not found - using the systemd journal as the Fail2Ban backend"
    fi

    # Create local configuration
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = $backend
# destemail and sendername commented out because no mail server is installed by default
# destemail = root@localhost
# sendername = Fail2Ban
action = %(action_)s

[sshd]
enabled = true
port = ssh
filter = sshd
$logpath
maxretry = 3
bantime = 7200
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban

    # Confirm it survived the config change instead of assuming it did
    sleep 2
    if ! systemctl is-active --quiet fail2ban; then
        print_error "Fail2Ban is not running - check: journalctl -u fail2ban"
        return 1
    fi
    print_status "Fail2Ban installed and configured"
}

###############################################################################
# 5. CONFIGURE FIREWALL (UFW)
###############################################################################
step_firewall() {
    local port

    apt-get install -y ufw

    # Default policies
    ufw default deny incoming
    ufw default allow outgoing

    # Allow SSH on whichever port(s) sshd listens on, rate limited against
    # brute force attempts
    for port in $(sshd_ports); do
        ufw limit "$port/tcp"
        print_status "Firewall allows SSH on port $port (rate limited)"
    done

    # Enable firewall
    ufw --force enable

    systemctl enable ufw
    print_status "Firewall configured and enabled"
}

###############################################################################
# 6. DISABLE UNNECESSARY SERVICES
###############################################################################
step_optional_disables() {
    local answer wireless_iface

    if [ "$INTERACTIVE" -ne 1 ]; then
        print_warning "No terminal attached - skipping the optional Bluetooth and WiFi questions"
        return "$STEP_SKIPPED"
    fi

    # Disable Bluetooth if not needed
    read -r -p "Disable Bluetooth? (y/n): " answer || answer=""
    if is_yes "$answer"; then
        systemctl disable bluetooth || print_warning "Could not disable the bluetooth service"
        systemctl stop bluetooth || print_warning "Could not stop the bluetooth service"
        add_boot_config_line "dtoverlay=disable-bt"
        print_status "Bluetooth disabled"
    fi

    # Disable WiFi if using ethernet only
    read -r -p "Disable WiFi (only if using Ethernet)? (y/n): " answer || answer=""
    if is_yes "$answer"; then
        if wireless_iface="$(default_route_is_wireless)"; then
            print_warning "This machine reaches the network over WiFi ($wireless_iface) - refusing to disable it"
        else
            add_boot_config_line "dtoverlay=disable-wifi"
            print_status "WiFi disabled (takes effect after reboot)"
        fi
    fi
}

###############################################################################
# 7. AUTOMATIC SECURITY UPDATES
###############################################################################
step_auto_updates() {
    apt-get install -y unattended-upgrades

    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=Raspbian,codename=${distro_codename}";
    "origin=Raspberry Pi Foundation,codename=${distro_codename}";
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    print_status "Automatic security updates enabled"
}

###############################################################################
# 8. SECURE SHARED MEMORY
###############################################################################
step_shared_memory() {
    # /run/shm is only a symlink to /dev/shm on current Raspberry Pi OS, so the
    # mount options have to be applied to /dev/shm to have any effect.
    if grep -q '^[[:space:]]*tmpfs[[:space:]]\+/run/shm[[:space:]]' /etc/fstab; then
        sed -i '\#^[[:space:]]*tmpfs[[:space:]]\+/run/shm[[:space:]]#d' /etc/fstab
        print_status "Removed the ineffective /run/shm entry left by an earlier run"
    fi

    if grep -q '^[^#]*[[:space:]]/dev/shm[[:space:]]' /etc/fstab; then
        print_status "/dev/shm already has an /etc/fstab entry - leaving it unchanged"
        return 0
    fi

    echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    print_status "Shared memory secured (takes effect after reboot)"
}

###############################################################################
# 9. INSTALL SECURITY TOOLS
###############################################################################
step_security_tools() {
    apt-get install -y \
        rkhunter \
        chkrootkit \
        logwatch \
        auditd

    # Update rkhunter file properties database to prevent initial false positives
    rkhunter --propupd || print_warning "rkhunter baseline update had warnings (safe to ignore on first run)"

    print_status "Security tools installed"
}

###############################################################################
# 10. CONFIGURE SYSTEM LIMITS
###############################################################################
step_system_limits() {
    # A drop-in file is rewritten in place, so re-running the script cannot
    # stack duplicate limits the way appending to limits.conf does.
    cat > /etc/security/limits.d/99-pi-fortress.conf << 'EOF'
# Managed by pi-fortress
* hard core 0
* soft nproc 512
* hard nproc 1024
EOF

    if grep -q '^# Security limits$' /etc/security/limits.conf; then
        print_warning "Earlier runs appended limits to /etc/security/limits.conf - remove those duplicates by hand"
    fi

    print_status "System security limits configured"
}

###############################################################################
# 11. NETWORK SECURITY
###############################################################################
step_network_security() {
    cat > /etc/sysctl.d/99-security.conf << 'EOF'
# IP Forwarding (disable if not routing)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable source packet routing
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable ICMP redirect acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Enable IP spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_all = 0

# Ignore broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable IPv6 if not needed
#net.ipv6.conf.all.disable_ipv6 = 1
#net.ipv6.conf.default.disable_ipv6 = 1

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Protect against SYN flood attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
EOF

    # -e ignores keys this kernel does not expose, for example the IPv6 keys on
    # a system booted with ipv6.disable=1
    if sysctl -e -p /etc/sysctl.d/99-security.conf > /dev/null; then
        print_status "Network security settings applied"
    else
        print_warning "Some sysctl settings could not be applied now; they are retried on boot"
    fi
}

###############################################################################
# 12. SET PROPER PERMISSIONS
###############################################################################
step_permissions() {
    local home

    chmod 700 /root

    for home in /home/*; do
        [ -d "$home" ] || continue
        chmod 700 "$home"
    done

    print_status "Home directory permissions set to 700"
}

###############################################################################
# 13. DISABLE UNUSED ACCOUNTS
###############################################################################
step_lock_accounts() {
    local user shell

    for user in games news uucp proxy www-data backup list irc gnats; do
        id "$user" > /dev/null 2>&1 || continue

        if ! usermod -L "$user"; then
            print_warning "Could not lock the password for $user"
            continue
        fi

        # A locked password still leaves a usable login shell behind
        shell="$(getent passwd "$user" | cut -d: -f7)"
        case "$shell" in
            */nologin | */false) ;;
            *)
                usermod -s "$NOLOGIN_SHELL" "$user" ||
                    print_warning "Could not set a nologin shell for $user"
                ;;
        esac
    done

    print_status "Unused system accounts locked"
}

###############################################################################
# 14. CREATE SECURITY CHECK SCRIPT
###############################################################################
step_security_check_script() {
    cat > /usr/local/bin/security-check.sh << 'EOF'
#!/bin/bash
echo "==================================="
echo "Raspberry Pi Security Check"
echo "==================================="
echo ""

echo "SSH Failed Login Attempts:"
if [ -f /var/log/auth.log ]; then
    grep "Failed password" /var/log/auth.log | tail -10
else
    journalctl --no-pager -u ssh -u sshd 2>/dev/null | grep "Failed password" | tail -10
fi
echo ""

echo "Fail2Ban Status:"
if command -v fail2ban-client > /dev/null 2>&1; then
    fail2ban-client status sshd
else
    echo "fail2ban is not installed"
fi
echo ""

echo "Active Firewall Rules:"
if command -v ufw > /dev/null 2>&1; then
    ufw status numbered
else
    echo "ufw is not installed"
fi
echo ""

echo "Last 10 Logins:"
last -10
echo ""

echo "Currently Logged In Users:"
w
echo ""

echo "Listening Ports:"
ss -tulpn
echo ""

echo "Running Security Scan (rkhunter)..."
if command -v rkhunter > /dev/null 2>&1; then
    rkhunter --check --skip-keypress --report-warnings-only
else
    echo "rkhunter is not installed"
fi
EOF

    chmod +x /usr/local/bin/security-check.sh
    print_status "Security check script created: /usr/local/bin/security-check.sh"
}

###############################################################################
# RUN ALL STEPS
###############################################################################
print_status "Starting Raspberry Pi Security Hardening - $(date)"

run_step "Updating system packages" step_update_system
run_step "Hardening SSH configuration" step_ssh_hardening
run_step "Creating SSH key setup helper" step_ssh_key_helper
run_step "Installing and configuring Fail2Ban" step_fail2ban
run_step "Setting up firewall (UFW)" step_firewall
run_step "Disabling unnecessary services" step_optional_disables
run_step "Setting up automatic security updates" step_auto_updates
run_step "Securing shared memory" step_shared_memory
run_step "Installing security tools" step_security_tools
run_step "Configuring system security limits" step_system_limits
run_step "Applying network security settings" step_network_security
run_step "Setting proper file permissions" step_permissions
run_step "Locking unused system accounts" step_lock_accounts
run_step "Creating security check script" step_security_check_script

###############################################################################
# 15. SUMMARY AND RECOMMENDATIONS
###############################################################################
echo ""
echo "==========================================="
if [ "${#STEPS_FAILED[@]}" -eq 0 ]; then
    print_status "Security Hardening Complete!"
else
    print_warning "Security Hardening Finished With Errors"
fi
echo "==========================================="
echo ""

echo "Completed steps: ${#STEPS_OK[@]}"
if [ "${#STEPS_SKIPPED[@]}" -gt 0 ]; then
    echo ""
    print_warning "SKIPPED:"
    for step in "${STEPS_SKIPPED[@]}"; do
        echo "   - $step"
    done
fi
if [ "${#STEPS_FAILED[@]}" -gt 0 ]; then
    echo ""
    print_error "FAILED (these changes were NOT applied):"
    for step in "${STEPS_FAILED[@]}"; do
        echo "   - $step"
    done
    echo ""
    echo "   Review $LOGFILE, fix the cause, then run this script again."
fi

echo ""
print_warning "IMPORTANT NEXT STEPS:"
echo ""
echo "1. SET UP SSH KEY AUTHENTICATION"
echo "   Run: /root/setup_ssh_keys.sh for instructions"
echo "   After setup, disable password authentication"
echo ""
echo "2. REBOOT to apply all changes"
echo "   Run: reboot"
echo ""
echo "3. REGULAR MAINTENANCE:"
echo "   - Run security check: sudo security-check.sh"
echo "   - Check fail2ban logs: sudo fail2ban-client status sshd"
echo "   - Review system logs: sudo journalctl -xe"
echo "   - Run rootkit scanner: sudo rkhunter --check"
echo ""
echo "4. ADDITIONAL SECURITY (OPTIONAL):"
echo "   - Set up VPN (WireGuard or OpenVPN)"
echo "   - Enable SELinux or AppArmor"
echo "   - Configure intrusion detection (Snort/Suricata)"
echo "   - Set up centralized logging"
echo ""
echo "5. FIREWALL RULES:"
echo "   Add rules as needed: sudo ufw allow <port>"
echo "   Example for web server: sudo ufw allow 80/tcp"
echo ""
print_warning "Your Pi is significantly more secure, but security is an ongoing process!"
echo ""
echo "Log file saved to: $LOGFILE"
echo "==========================================="

if [ "${#STEPS_FAILED[@]}" -gt 0 ]; then
    exit 1
fi
