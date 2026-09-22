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
# Usage: sudo bash pi-fortress.sh [--yes] [--no] [--help]                      #
################################################################################

# -E so the ERR trap also fires inside functions
set -Eeuo pipefail

VERSION="1.1.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log file
LOGFILE="/var/log/pi_security_hardening.log"

# Answer mode for optional prompts: ask | yes | no
ANSWER_MODE="ask"

usage() {
    cat << USAGE
Pi Fortress ${VERSION} - Raspberry Pi security hardening

Usage: sudo bash pi-fortress.sh [options]

Options:
  -y, --yes    Answer "yes" to every optional prompt (disables Bluetooth and WiFi)
  -n, --no     Answer "no" to every optional prompt (unattended run, keeps radios on)
  -h, --help   Show this help and exit

With no options the script prompts interactively for the optional steps.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        -y|--yes) ANSWER_MODE="yes" ;;
        -n|--no|--non-interactive) ANSWER_MODE="no" ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

# Check if running as root before touching anything, including the log file
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[-]${NC} Please run as root (use sudo)" >&2
    exit 1
fi

# Fall back to a writable location if /var/log is not available (e.g. read-only rootfs)
if ! touch "$LOGFILE" 2>/dev/null; then
    LOGFILE="/tmp/pi_security_hardening.log"
    touch "$LOGFILE"
fi
chmod 600 "$LOGFILE"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOGFILE"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOGFILE"
}

print_error() {
    echo -e "${RED}[-]${NC} $1" | tee -a "$LOGFILE" >&2
}

# Report where an aborted run stopped instead of dying silently halfway through
on_error() {
    print_error "Aborted at line $1. The system may be partially hardened."
    print_error "Review $LOGFILE, fix the cause, then re-run this script (it is safe to re-run)."
}
trap 'on_error $LINENO' ERR

# Ask a yes/no question, honouring --yes/--no and surviving `curl | bash` (no stdin)
confirm() {
    local prompt="$1" reply

    case "$ANSWER_MODE" in
        yes) print_status "$prompt -> yes (--yes)"; return 0 ;;
        no)  print_status "$prompt -> no (--no)"; return 1 ;;
    esac

    if [ ! -r /dev/tty ]; then
        print_warning "$prompt -> no (no terminal available)"
        return 1
    fi

    read -r -p "$prompt (y/n): " reply < /dev/tty || reply="n"
    [[ "$reply" =~ ^[Yy]$ ]]
}

# Append a line only if it is not already present, so re-runs do not duplicate config
append_once() {
    local line="$1" file="$2"
    grep -qxF "$line" "$file" 2>/dev/null && return 0
    echo "$line" >> "$file"
}

if ! command -v apt-get > /dev/null 2>&1; then
    print_error "apt-get not found. This script targets Raspberry Pi OS / Debian."
    exit 1
fi

# Keep apt from stopping on interactive config-file prompts mid-run
export DEBIAN_FRONTEND=noninteractive
APT_INSTALL=(apt-get install -y -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef)

print_status "Starting Raspberry Pi Security Hardening (v${VERSION}) - $(date)"

###############################################################################
# 1. UPDATE SYSTEM
###############################################################################
print_status "Updating system packages..."
apt-get update
apt-get dist-upgrade -y -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef
apt-get autoremove -y
apt-get autoclean

###############################################################################
# 2. SSH HARDENING
###############################################################################
print_status "Hardening SSH configuration..."

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_DIR="/etc/ssh/sshd_config.d"
HARDENING_CONF="${SSHD_CONFIG_DIR}/hardening.conf"

if [ ! -f "$SSHD_CONFIG" ]; then
    print_status "OpenSSH server not installed. Installing..."
    "${APT_INSTALL[@]}" openssh-server
fi

# Backup original SSH config (timestamped to preserve previous backups on re-runs)
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup.$(date +%Y%m%d-%H%M%S)"

# The drop-in directory is only read if sshd_config includes it. Older images
# (and hand-edited configs) lack the Include line, which would silently discard
# every setting below.
mkdir -p "$SSHD_CONFIG_DIR"
chmod 755 "$SSHD_CONFIG_DIR"
if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_CONFIG"; then
    print_warning "sshd_config has no Include for sshd_config.d - adding it"
    # sshd uses the first value it sees for most keywords, so the Include must be first
    printf 'Include /etc/ssh/sshd_config.d/*.conf\n\n' | cat - "$SSHD_CONFIG" > "${SSHD_CONFIG}.new"
    mv "${SSHD_CONFIG}.new" "$SSHD_CONFIG"
    chmod 644 "$SSHD_CONFIG"
fi

# Read the port actually in use so the firewall and Fail2Ban match reality
SSHD_BIN="$(command -v sshd || echo /usr/sbin/sshd)"
SSH_PORT="$("$SSHD_BIN" -T 2>/dev/null | awk '/^port /{print $2; exit}' || true)"
[ -n "$SSH_PORT" ] || SSH_PORT=22
print_status "Detected SSH port: ${SSH_PORT}"

# SSH Configuration
cat > "$HARDENING_CONF" << 'EOF'
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
chmod 644 "$HARDENING_CONF"

# Never restart sshd on a config it would reject - that is how you lose remote access
if ! "$SSHD_BIN" -t 2> /tmp/pi-fortress-sshd-test.err; then
    print_error "sshd rejected the hardened configuration. Reverting it and stopping:"
    cat /tmp/pi-fortress-sshd-test.err | tee -a "$LOGFILE" >&2
    rm -f "$HARDENING_CONF"
    exit 1
fi

print_status "SSH hardened. Root login disabled."
print_warning "Password authentication still enabled. Disable after setting up SSH keys!"

# The unit is ssh on Debian/Raspberry Pi OS and sshd elsewhere
SSH_SERVICE="ssh"
systemctl list-unit-files 2>/dev/null | grep -q '^ssh\.service' || SSH_SERVICE="sshd"
systemctl restart "$SSH_SERVICE"
# Socket activation (Bookworm) hands off new connections, so it needs the restart too
if systemctl is-active --quiet ssh.socket 2>/dev/null; then
    systemctl restart ssh.socket
fi
print_status "SSH service restarted (${SSH_SERVICE})"

###############################################################################
# 3. SETUP SSH KEY AUTHENTICATION HELPER
###############################################################################
cat > /root/setup_ssh_keys.sh << 'EOF'
#!/bin/bash
PI_IP="$(hostname -I | awk '{print $1}')"
echo "SSH Key Setup Helper"
echo "===================="
echo "1. On your LOCAL machine, generate SSH key (if you haven't):"
echo "   ssh-keygen -t ed25519 -C 'your_email@example.com'"
echo ""
echo "2. Copy the key to this Pi:"
echo "   ssh-copy-id username@${PI_IP}"
echo ""
echo "3. Test the connection from your local machine"
echo ""
echo "4. Once working, disable password authentication:"
echo "   Edit /etc/ssh/sshd_config.d/hardening.conf"
echo "   Uncomment: PasswordAuthentication no"
echo "   Then: sudo systemctl restart ssh"
EOF
chmod 700 /root/setup_ssh_keys.sh
print_status "SSH key setup helper created: /root/setup_ssh_keys.sh"

###############################################################################
# 4. INSTALL AND CONFIGURE FAIL2BAN
###############################################################################
print_status "Installing and configuring Fail2Ban..."
"${APT_INSTALL[@]}" fail2ban

# Debian 12 ships without rsyslog, so /var/log/auth.log may not exist and the
# default file backend would leave the sshd jail dead on arrival.
if [ -f /var/log/auth.log ]; then
    F2B_BACKEND_LINES="backend = auto
logpath = /var/log/auth.log"
    print_status "Fail2Ban will read /var/log/auth.log"
else
    F2B_BACKEND_LINES="backend = systemd"
    print_status "No /var/log/auth.log found - Fail2Ban will read the systemd journal"
fi

# Create local configuration
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
# destemail and sendername commented out because no mail server is installed by default
# destemail = root@localhost
# sendername = Fail2Ban
action = %(action_)s

[sshd]
enabled = true
port = ${SSH_PORT}
filter = sshd
${F2B_BACKEND_LINES}
maxretry = 3
bantime = 7200
EOF

systemctl enable fail2ban
# Report a failed start rather than aborting the whole run on it
systemctl restart fail2ban || true
if systemctl is-active --quiet fail2ban; then
    print_status "Fail2Ban installed and configured"
else
    print_warning "Fail2Ban is not running. Check: journalctl -u fail2ban -n 50"
fi

###############################################################################
# 5. CONFIGURE FIREWALL (UFW)
###############################################################################
print_status "Setting up firewall (UFW)..."
"${APT_INSTALL[@]}" ufw

# Default policies
ufw default deny incoming
ufw default allow outgoing

# Allow the port SSH is really listening on, rate-limited against brute force
ufw limit "${SSH_PORT}/tcp" comment 'SSH (rate limited)' || ufw limit "${SSH_PORT}/tcp"
ufw logging low

# Enable firewall
ufw --force enable

systemctl enable ufw
print_status "Firewall configured and enabled (SSH port ${SSH_PORT} allowed)"

###############################################################################
# 6. DISABLE UNNECESSARY SERVICES
###############################################################################
print_status "Disabling unnecessary services..."

# Determine Raspberry Pi boot config path (Bookworm uses /boot/firmware, older uses /boot)
CONFIG_FILE="/boot/firmware/config.txt"
if [ ! -f "$CONFIG_FILE" ]; then
    CONFIG_FILE="/boot/config.txt"
fi

if [ ! -f "$CONFIG_FILE" ]; then
    print_warning "No Raspberry Pi config.txt found - skipping Bluetooth/WiFi options"
else
    # Disable Bluetooth if not needed
    if confirm "Disable Bluetooth?"; then
        systemctl disable --now bluetooth 2>/dev/null || true
        systemctl disable --now hciuart 2>/dev/null || true
        append_once "dtoverlay=disable-bt" "$CONFIG_FILE"
        print_status "Bluetooth disabled (fully removed after reboot)"
    fi

    # Disable WiFi if using ethernet only
    if confirm "Disable WiFi (only if using Ethernet)?"; then
        append_once "dtoverlay=disable-wifi" "$CONFIG_FILE"
        print_status "WiFi disabled (takes effect after reboot)"
    fi
fi

###############################################################################
# 7. AUTOMATIC SECURITY UPDATES
###############################################################################
print_status "Setting up automatic security updates..."
"${APT_INSTALL[@]}" unattended-upgrades

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
Unattended-Upgrade::SyslogEnable "true";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

systemctl enable --now unattended-upgrades 2>/dev/null || true
print_status "Automatic security updates enabled"

###############################################################################
# 8. SECURE SHARED MEMORY
###############################################################################
print_status "Securing shared memory..."
if grep -qE '^[^#]*[[:space:]]/dev/shm[[:space:]]' /etc/fstab; then
    print_status "Shared memory already has an fstab entry - leaving it alone"
else
    append_once "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" /etc/fstab
    mount -o remount,noexec,nosuid,nodev /dev/shm 2>/dev/null || true
    print_status "Shared memory secured"
fi

###############################################################################
# 9. INSTALL SECURITY TOOLS
###############################################################################
print_status "Installing security tools..."
"${APT_INSTALL[@]}" \
    rkhunter \
    chkrootkit \
    logwatch \
    auditd

systemctl enable --now auditd 2>/dev/null || print_warning "Could not enable auditd"

print_status "Security tools installed"

###############################################################################
# 10. CONFIGURE SYSTEM LIMITS
###############################################################################
print_status "Configuring system security limits..."
# A drop-in file instead of appending to limits.conf, which would stack up on re-runs
cat > /etc/security/limits.d/99-pi-fortress.conf << 'EOF'
# Security limits (managed by pi-fortress)
* hard core 0
* soft nproc 512
* hard nproc 1024
EOF

###############################################################################
# 11. NETWORK SECURITY
###############################################################################
print_status "Applying network security settings..."
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

# Do not accept ICMP redirects even from listed gateways
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Enable IP spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_all = 0

# Ignore broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

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

# Harden kernel pointer and dmesg exposure
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
EOF

# -e keeps an unknown key (e.g. net.ipv6.* on an IPv6-less kernel) from aborting the run
sysctl -e -p /etc/sysctl.d/99-security.conf > /dev/null
print_status "Network security settings applied"

###############################################################################
# 12. SET PROPER PERMISSIONS
###############################################################################
print_status "Setting proper file permissions..."
chmod 700 /root
for home_dir in /home/*/; do
    if [ -d "$home_dir" ]; then
        chmod 700 "$home_dir"
    fi
done

###############################################################################
# 13. DISABLE UNUSED ACCOUNTS
###############################################################################
print_status "Locking unused system accounts..."
for user in games news uucp proxy www-data backup list irc gnats; do
    if id "$user" > /dev/null 2>&1; then
        usermod -L "$user" 2>/dev/null || print_warning "Could not lock account: $user"
    fi
done

###############################################################################
# 14. CREATE SECURITY CHECK SCRIPT
###############################################################################
print_status "Creating security check script..."
cat > /usr/local/bin/security-check.sh << 'EOF'
#!/bin/bash
echo "==================================="
echo "Raspberry Pi Security Check"
echo "==================================="
echo ""

echo "SSH Failed Login Attempts:"
if [ -r /var/log/auth.log ]; then
    grep "Failed password" /var/log/auth.log | tail -10
else
    journalctl -u ssh -u sshd --no-pager 2>/dev/null | grep "Failed password" | tail -10
fi
echo ""

echo "Fail2Ban Status:"
fail2ban-client status sshd 2>/dev/null || echo "  Fail2Ban sshd jail unavailable"
echo ""

echo "Active Firewall Rules:"
ufw status numbered
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

echo "Pending Security Updates:"
apt-get -s upgrade 2>/dev/null | grep -ci '^Inst.*security' || true
echo ""

echo "Running Security Scan (rkhunter)..."
rkhunter --check --skip-keypress --report-warnings-only
EOF

chmod 755 /usr/local/bin/security-check.sh
print_status "Security check script created: /usr/local/bin/security-check.sh"

###############################################################################
# 15. ROOTKIT BASELINE
###############################################################################
# Run last so the baseline reflects the permission and config changes above,
# otherwise the first rkhunter --check reports everything this script touched.
print_status "Recording rkhunter baseline..."
rkhunter --propupd > /dev/null 2>&1 || print_warning "rkhunter baseline update had warnings (safe to ignore on first run)"

###############################################################################
# 16. SUMMARY AND RECOMMENDATIONS
###############################################################################
echo ""
echo "==========================================="
print_status "Security Hardening Complete!"
echo "==========================================="
echo ""
print_warning "IMPORTANT NEXT STEPS:"
echo ""
echo "1. SET UP SSH KEY AUTHENTICATION"
echo "   Run: /root/setup_ssh_keys.sh for instructions"
echo "   After setup, disable password authentication"
echo ""
echo "2. TEST SSH IN A NEW TERMINAL before closing this session"
echo "   ssh -p ${SSH_PORT} username@$(hostname -I | awk '{print $1}')"
echo ""
echo "3. REBOOT to apply all changes"
echo "   Run: reboot"
echo ""
echo "4. REGULAR MAINTENANCE:"
echo "   - Run security check: sudo security-check.sh"
echo "   - Check fail2ban logs: sudo fail2ban-client status sshd"
echo "   - Review system logs: sudo journalctl -xe"
echo "   - Run rootkit scanner: sudo rkhunter --check"
echo ""
echo "5. ADDITIONAL SECURITY (OPTIONAL):"
echo "   - Set up VPN (WireGuard or OpenVPN)"
echo "   - Enable SELinux or AppArmor"
echo "   - Configure intrusion detection (Snort/Suricata)"
echo "   - Set up centralized logging"
echo ""
echo "6. FIREWALL RULES:"
echo "   Add rules as needed: sudo ufw allow <port>"
echo "   Example for web server: sudo ufw allow 80/tcp"
echo ""
print_warning "Your Pi is significantly more secure, but security is an ongoing process!"
echo ""
echo "Log file saved to: $LOGFILE"
echo "==========================================="
