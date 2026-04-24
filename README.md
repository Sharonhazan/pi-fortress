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
- System audit logging
- Custom security check script

### ⚙️ Optional Features
- Disable Bluetooth (if not needed)
- Disable WiFi (for Ethernet-only setups)
- Create new admin user
- Secure shared memory

## 🚀 Quick Start

### Prerequisites

**Important:** This script is designed for Raspberry Pi OS installations configured with the Raspberry Pi Imager. Make sure you've set up your username, password, and SSH settings during the imaging process.

**Compatibility:** Tested on Raspberry Pi OS Bookworm (current) and Bullseye. The script automatically detects the correct boot config path.

### Installation

**Download the script:**
```bash
wget https://raw.githubusercontent.com/Sharonhazan/pi-fortress/main/pi-fortress.sh
```

**Make it executable:**
```bash
chmod +x pi-fortress.sh
```

**Run as root:**
```bash
sudo ./pi-fortress.sh
```

### What to Expect

The script will:
1. ✅ Update all system packages
2. ✅ Configure SSH security settings
3. ✅ Install and configure Fail2Ban
4. ✅ Set up UFW firewall
5. ✅ Install security monitoring tools
6. ✅ Apply network hardening
7. ✅ Set proper permissions
8. ✅ Disable unused accounts
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
| `logwatch` | Log analysis |
| `auditd` | System auditing |

## 🔧 Post-Installation Steps

### 1. Set Up SSH Keys (Important!)

The script keeps password authentication enabled initially. After setting up SSH keys, you should disable it.

**On your local machine:**
**Generate SSH key (if you don't have one):**
```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
```

**Copy to your Pi:**
```bash
ssh-copy-id username@your-pi-ip
```

**Test it works:**
```bash
ssh username@your-pi-ip
```

**Once working, disable password authentication:**
**Edit SSH configuration:**
```bash
sudo nano /etc/ssh/sshd_config.d/hardening.conf
```

**Uncomment this line:**
```
PasswordAuthentication no
```

**Restart SSH:**
```bash
sudo systemctl restart ssh
```

### 2. Reboot Your Pi

**Reboot your Pi:**
```bash
sudo reboot
```

### 3. Run Security Check

**Run the security check:**
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

**Allow HTTP:**
```bash
sudo ufw allow 80/tcp
```

**Allow HTTPS:**
```bash
sudo ufw allow 443/tcp
```

**Allow custom application:**
```bash
sudo ufw allow 8080/tcp
```

**Check firewall status:**
```bash
sudo ufw status numbered
```

### Check Fail2Ban

**View Fail2Ban status:**
```bash
sudo fail2ban-client status sshd
```

**See banned IPs:**
```bash
sudo fail2ban-client status sshd | grep "Banned IP"
```

**Unban an IP:**
```bash
sudo fail2ban-client set sshd unbanip 192.168.1.100
```

### Manual Security Scans

**Run rootkit scan:**
```bash
sudo rkhunter --check
```

**View auth log:**
```bash
sudo tail -f /var/log/auth.log
```

## ⚠️ Important Warnings

### Before Running

- ✅ Configure your Pi with **Raspberry Pi Imager** (set username, password, and enable SSH)
- ✅ This script is for **fresh installations** - test on existing systems carefully
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
**Connect with keyboard and monitor, then:**
```bash
sudo nano /etc/ssh/sshd_config.d/hardening.conf
```

**Set this line:**
```
PasswordAuthentication yes
```

**Restart SSH:**
```bash
sudo systemctl restart ssh
```

**Option 2: SD Card Method**
1. Remove SD card from Pi
2. Mount on another computer
3. Edit `/etc/ssh/sshd_config.d/hardening.conf`
4. Enable `PasswordAuthentication yes`
5. Reinsert and boot

### My IP Got Banned

**From another IP or local access:**
```bash
sudo fail2ban-client set sshd unbanip YOUR_IP
```

### Port Not Working

**Check firewall status:**
```bash
sudo ufw status
```

**Allow the port:**
```bash
sudo ufw allow PORT_NUMBER/tcp
```

## 🎯 Advanced Configuration

### Change SSH Port

**Edit SSH config:**
```bash
sudo nano /etc/ssh/sshd_config.d/hardening.conf
```

**Add this line:**
```
Port 2222
```

**Update firewall:**
```bash
sudo ufw allow 2222/tcp
sudo ufw delete allow 22/tcp
```

**Restart SSH:**
```bash
sudo systemctl restart ssh
```

### Enable Email Alerts

**Note:** By default, email alerts in Fail2Ban are disabled because they require a mail server.

**Install mail utilities:**
```bash
sudo apt install mailutils
```

**Edit Fail2Ban config:**
```bash
sudo nano /etc/fail2ban/jail.local
```

**Set your email and action:**
```ini
destemail = your@email.com
sendername = Fail2Ban
action = %(action_mwl)s
```

**Restart Fail2Ban:**
```bash
sudo systemctl restart fail2ban
```

### Disable IPv6

**Edit sysctl config:**
```bash
sudo nano /etc/sysctl.d/99-security.conf
```

**Uncomment these lines:**
```
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
```

**Apply changes:**
```bash
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
