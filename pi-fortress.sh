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
# Usage: sudo bash pi_fortress.sh                                              #
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Log file
LOGFILE="/var/log/pi_security_hardening.log"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOGFILE"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOGFILE"
}

print_error() {
    echo -e "${RED}[-]${NC} $1" | tee -a "$LOGFILE"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    print_error "Please run as root (use sudo)"
    exit 1
fi

print_status "Starting Raspberry Pi Security Hardening - $(date)"

###############################################################################
# 1. UPDATE SYSTEM
###############################################################################
print_status "Updating system packages..."
apt update && apt upgrade -y
apt dist-upgrade -y
apt autoremove -y
apt autoclean

###############################################################################
# 2. SSH HARDENING
###############################################################################
print_status "Hardening SSH configuration..."

# Backup original SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# SSH Configuration
cat > /etc/ssh/sshd_config.d/hardening.conf << 'EOF'
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

print_status "SSH hardened. Root login disabled."
print_warning "Password authentication still enabled. Disable after setting up SSH keys!"

# Restart SSH
systemctl restart ssh
print_status "SSH service restarted"

###############################################################################
# 5. SETUP SSH KEY AUTHENTICATION HELPER
###############################################################################
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

###############################################################################
# 6. INSTALL AND CONFIGURE FAIL2BAN
###############################################################################
print_status "Installing and configuring Fail2Ban..."
apt install -y fail2ban

# Create local configuration
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = root@localhost
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200
EOF

systemctl enable fail2ban
systemctl start fail2ban
print_status "Fail2Ban installed and configured"

###############################################################################
# 7. CONFIGURE FIREWALL (UFW)
###############################################################################
print_status "Setting up firewall (UFW)..."
apt install -y ufw

# Default policies
ufw default deny incoming
ufw default allow outgoing

# Allow SSH
ufw allow ssh

# Enable firewall
echo "y" | ufw enable

systemctl enable ufw
print_status "Firewall configured and enabled (SSH allowed)"

###############################################################################
# 8. DISABLE UNNECESSARY SERVICES
###############################################################################
print_status "Disabling unnecessary services..."

# Disable Bluetooth if not needed
read -p "Disable Bluetooth? (y/n): " disable_bt
if [ "$disable_bt" = "y" ]; then
    systemctl disable bluetooth
    systemctl stop bluetooth
    echo "dtoverlay=disable-bt" >> /boot/firmware/config.txt
    print_status "Bluetooth disabled"
fi

# Disable WiFi if using ethernet only
read -p "Disable WiFi (only if using Ethernet)? (y/n): " disable_wifi
if [ "$disable_wifi" = "y" ]; then
    echo "dtoverlay=disable-wifi" >> /boot/firmware/config.txt
    print_status "WiFi disabled (takes effect after reboot)"
fi

###############################################################################
# 9. AUTOMATIC SECURITY UPDATES
###############################################################################
print_status "Setting up automatic security updates..."
apt install -y unattended-upgrades

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
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

###############################################################################
# 10. SECURE SHARED MEMORY
###############################################################################
print_status "Securing shared memory..."
if ! grep -q "tmpfs /run/shm tmpfs" /etc/fstab; then
    echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    print_status "Shared memory secured"
fi

###############################################################################
# 11. INSTALL SECURITY TOOLS
###############################################################################
print_status "Installing security tools..."
apt install -y \
    rkhunter \
    chkrootkit \
    aide \
    logwatch \
    auditd

# Initialize AIDE database
print_status "Initializing AIDE database (this may take a while)..."
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

print_status "Security tools installed"

###############################################################################
# 12. CONFIGURE SYSTEM LIMITS
###############################################################################
print_status "Configuring system security limits..."
cat >> /etc/security/limits.conf << 'EOF'

# Security limits
* hard core 0
* soft nproc 512
* hard nproc 1024
EOF

###############################################################################
# 13. NETWORK SECURITY
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

sysctl -p /etc/sysctl.d/99-security.conf
print_status "Network security settings applied"

###############################################################################
# 14. SET PROPER PERMISSIONS
###############################################################################
print_status "Setting proper file permissions..."
chmod 700 /root
chmod 700 /home/*

###############################################################################
# 15. DISABLE UNUSED ACCOUNTS
###############################################################################
print_status "Locking unused system accounts..."
for user in games news uucp proxy www-data backup list irc gnats; do
    if id "$user" &>/dev/null; then
        usermod -L "$user"
    fi
done

###############################################################################
# 16. CREATE SECURITY CHECK SCRIPT
###############################################################################
print_status "Creating security check script..."
cat > /usr/local/bin/security-check.sh << 'EOF'
#!/bin/bash
echo "==================================="
echo "Raspberry Pi Security Check"
echo "==================================="
echo ""

echo "SSH Failed Login Attempts:"
grep "Failed password" /var/log/auth.log | tail -10
echo ""

echo "Fail2Ban Status:"
fail2ban-client status sshd
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

echo "Running Security Scan (rkhunter)..."
rkhunter --check --skip-keypress --report-warnings-only
EOF

chmod +x /usr/local/bin/security-check.sh
print_status "Security check script created: /usr/local/bin/security-check.sh"

###############################################################################
# 17. SUMMARY AND RECOMMENDATIONS
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
