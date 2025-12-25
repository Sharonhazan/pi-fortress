# 🏰 Pi Fortress

Comprehensive automated security hardening for Raspberry Pi. One script to transform your Pi into a fortress.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%20OS-red.svg)
![Shell](https://img.shields.io/badge/shell-bash-green.svg)
![Maintained](https://img.shields.io/badge/maintained-yes-brightgreen.svg)

## 🎯 What Does This Do?

This script transforms a fresh Raspberry Pi installation from default configuration to a hardened, secure system. It automates hours of manual security configuration into a single command.

**Perfect for:**
- Home servers and NAS systems
- IoT projects exposed to the internet
- Development environments
- Learning security best practices
- Any Pi that needs protection

## ✨ Features

### 🛡️ Core Security
- Automatic system updates with unattended security patches
- Strong password enforcement
- Secure file permissions and system limits
- Unused account lockdown

### 🔐 SSH Hardening
- Root login disabled
- Strong encryption (ChaCha20-Poly1305, AES-256-GCM)
- Key-based authentication support
- Maximum 3 login attempts
- Connection timeouts and session limits

### 🔥 Network Protection
- UFW firewall (default deny incoming)
- Fail2Ban intrusion prevention
- SYN flood protection
- IP spoofing protection
- Suspicious packet logging

### 🔍 Monitoring & Detection
- Rootkit detection (rkhunter, chkrootkit)
- File integrity monitoring (AIDE)
- System audit logging
- Custom security check script

### ⚙️ Optional Features
- Disable Bluetooth (if not needed)
- Disable WiFi (for Ethernet-only setups)
- Create new admin user
- Secure shared memory

## 🚀 Quick Start

### Installation

```bash
# Download the script
wget https://raw.githubusercontent.com/Sharonhazan/pi-fortress/main/pi_fortress.sh

# Make it executable
chmod +x pi_fortress.sh

# Run as root
sudo ./pi_fortress.sh
```

### What to Expect

The script will:
1. ✅ Update all system packages
2. ✅ Prompt you to change default password
3. ✅ Ask if you want to create a new admin user
4. ✅ Configure SSH security settings
5. ✅ Install and configure Fail2Ban
6. ✅ Set up UFW firewall
7. ✅ Install security monitoring tools
8. ✅ Apply network hardening
9. ✅ Create security check script

**Total time:** ~5-10 minutes (depending on your internet speed)

## 📋 What Gets Installed

| Package | Purpose |
|---------|---------|
| `fail2ban` | Blocks IPs after failed login attempts |
| `ufw` | Simple, effective firewall |
| `unattended-upgrades` | Automatic security updates |
| `rkhunter` | Rootkit detection |
| `chkrootkit` | Additional rootkit scanner |
| `aide` | File integrity monitoring |
| `logwatch` | Log analysis |
| `auditd` | System auditing |

## 🔧 Post-Installation Steps

### 1. Set Up SSH Keys (Important!)

The script keeps password authentication enabled initially. After setting up SSH keys, you should disable it.

**On your local machine:**
```bash
# Generate SSH key (if you don't have one)
ssh-keygen -t ed25519 -C "your_email@example.com"

# Copy to your Pi
ssh-copy-id username@your-pi-ip

# Test it works
ssh username@your-pi-ip
```

**Once working, disable password authentication:**
```bash
# On your Pi
sudo nano /etc/ssh/sshd_config.d/hardening.conf

# Uncomment this line:
PasswordAuthentication no

# Restart SSH
sudo systemctl restart ssh
```

### 2. Reboot Your Pi

```bash
sudo reboot
```

### 3. Run Security Check

```bash
sudo security-check.sh
```

This shows:
- Failed login attempts
- Fail2Ban status
- Firewall rules
- Recent logins
- Open ports
- Rootkit scan

## 🛡️ Security Features Explained

### SSH Configuration

```
✓ Root login: DISABLED
✓ Password auth: Enabled initially (disable after key setup)
✓ Max auth tries: 3
✓ Login timeout: 60 seconds
✓ Idle timeout: 5 minutes
✓ Strong ciphers only
```

### Fail2Ban Settings

```
✓ Ban after: 3 failed attempts
✓ Ban duration: 2 hours
✓ Find time: 10 minutes
✓ Email alerts: Configurable
```

### Firewall Rules

```
✓ Default incoming: DENY
✓ Default outgoing: ALLOW
✓ SSH port 22: ALLOW
✓ Custom ports: Easy to add
```

## 🔓 Common Tasks

### Add Firewall Rules

```bash
# Web server
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Custom application
sudo ufw allow 8080/tcp

# Check status
sudo ufw status numbered
```

### Check Fail2Ban

```bash
# View status
sudo fail2ban-client status sshd

# See banned IPs
sudo fail2ban-client status sshd | grep "Banned IP"

# Unban an IP
sudo fail2ban-client set sshd unbanip 192.168.1.100
```

### Manual Security Scans

```bash
# Rootkit scan
sudo rkhunter --check

# File integrity check
sudo aide --check

# View auth log
sudo tail -f /var/log/auth.log
```

## ⚠️ Important Warnings

### Before Running

- ✅ This is for **fresh installations** - test on existing systems carefully
- ✅ Have **physical access** available in case of lockout
- ✅ Know your **current IP address** for SSH access

### After Running

- 🔑 Set up SSH keys **before** disabling password authentication
- 🧪 Test SSH access in a **new terminal** before closing your current one
- 📝 Document any **custom ports** you open in the firewall
- 🔄 Reboot to apply all changes

### Common Mistakes

❌ **Disabling password auth without SSH keys** → Lockout  
❌ **Not allowing custom ports in UFW** → Services won't work  
❌ **Forgetting to reboot** → Some changes won't apply

## 🆘 Troubleshooting

### Locked Out of SSH

**Option 1: Physical Access**
```bash
# Connect keyboard/monitor
# Login locally
# Re-enable password auth
sudo nano /etc/ssh/sshd_config.d/hardening.conf
# Set: PasswordAuthentication yes
sudo systemctl restart ssh
```

**Option 2: SD Card Method**
1. Remove SD card from Pi
2. Mount on another computer
3. Edit `/etc/ssh/sshd_config.d/hardening.conf`
4. Enable `PasswordAuthentication yes`
5. Reinsert and boot

### My IP Got Banned

```bash
# From another IP or local access
sudo fail2ban-client set sshd unbanip YOUR_IP
```

### Port Not Working

```bash
# Check firewall
sudo ufw status

# Allow the port
sudo ufw allow PORT_NUMBER/tcp
```

## 🎯 Advanced Configuration

### Change SSH Port

```bash
sudo nano /etc/ssh/sshd_config.d/hardening.conf
# Add: Port 2222

sudo ufw allow 2222/tcp
sudo ufw delete allow 22/tcp
sudo systemctl restart ssh
```

### Enable Email Alerts

```bash
sudo apt install mailutils
sudo nano /etc/fail2ban/jail.local
# Set: destemail = your@email.com
sudo systemctl restart fail2ban
```

### Disable IPv6

```bash
sudo nano /etc/sysctl.d/99-security.conf
# Uncomment IPv6 disable lines
sudo sysctl -p
```

## 📚 Resources

- [Raspberry Pi Security Documentation](https://www.raspberrypi.com/documentation/computers/configuration.html#securing-your-raspberry-pi)
- [SSH Hardening Guide](https://www.ssh.com/academy/ssh/config)
- [UFW Documentation](https://help.ubuntu.com/community/UFW)
- [Fail2Ban Manual](https://www.fail2ban.org/)

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -m 'Add improvement'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Open a Pull Request

### Ideas for Contributions
- Support for other Linux distributions
- Additional security checks
- Automated testing
- Documentation improvements
- Translations

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This script implements security best practices but no system is 100% secure. Use at your own risk. Always:
- Test in a safe environment first
- Keep backups of important data
- Monitor your logs regularly
- Stay updated on security threats

**The author is not responsible for any damage, data loss, or security breaches.**

## 👤 Author

**Sharon Hazan**

- GitHub: [@Sharonhazan](https://github.com/Sharonhazan)
- Repository: [pi-fortress](https://github.com/Sharonhazan/pi-fortress)

## 💬 Support

- **Issues**: [Report bugs or request features](https://github.com/Sharonhazan/pi-fortress/issues)
- **Discussions**: [Ask questions or share ideas](https://github.com/Sharonhazan/pi-fortress/discussions)
- **Security Issues**: Report privately via GitHub Security Advisories

---

**⭐ If Pi Fortress helped secure your Raspberry Pi, please star the repository!**

Made with ❤️ for the Raspberry Pi community