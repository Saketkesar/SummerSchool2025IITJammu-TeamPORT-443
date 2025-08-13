# 🎯 ShadowSnare - Advanced MITM Framework

[![Hackatime Badge](https://hackatime-badge.hackclub.com/U092A7ANS91/SummerSchool2025IITJammu)](https://hackatime.hackclub.com/)

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/Platform-Linux-green.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/Status-Educational-red.svg" alt="Status">
</div>

<div align="center">
  <h3>🎓 Cybersecurity Summer School 2025 - IIT Jammu</h3>
  <p><em>Educational MITM Framework for Understanding Network Security Vulnerabilities</em></p>
</div>

---

## 📋 Table of Contents

- [🎯 About](#-about)
- [👥 Team Members](#-team-members)
- [✨ Features](#-features)
- [🛠️ Installation](#️-installation)
- [🚀 Quick Start](#-quick-start)
- [📖 Usage Guide](#-usage-guide)
- [🔧 Components](#-components)
- [⚠️ Important Notes](#️-important-notes)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## 🎯 About

**ShadowSnare** is an advanced Man-in-the-Middle (MITM) framework developed for educational purposes during the Cybersecurity Summer School 2025 at IIT Jammu. This tool helps students and researchers understand network security vulnerabilities, DNS spoofing techniques, and defensive measures.

### 🎯 Project Objectives
- **Educational Focus**: Learn about network security vulnerabilities
- **Ethical Framework**: No pre-built phishing templates to prevent misuse
- **Hands-on Learning**: Users must create their own test pages
- **Real-world Understanding**: Comprehensive DNS spoofing and traffic interception

---

## 👥 Team Members

<div align="center">

| Team Member | Role | GitHub |
|-------------|------|--------|
| **Saket Kesar** | Lead Developer & Project Coordinator | [![GitHub](https://img.shields.io/badge/GitHub-Profile-blue)](https://github.com/Saketkesar) |
| **Dhruv Verma** | Security Researcher & Testing | [![GitHub](https://img.shields.io/badge/GitHub-Profile-blue)](#) |
| **Atharav Gaonker** | Network Analysis & Documentation | [![GitHub](https://img.shields.io/badge/GitHub-Profile-blue)](#) |

**Team PORT:443** - *Summer School 2025, IIT Jammu*

</div>

---

## ✨ Features

### 🛡️ Core Capabilities
- **🌐 Advanced DNS Spoofing**: Complete domain redirection with DoH/DoT blocking
- **🔄 ARP Spoofing**: Network-wide traffic interception
- **📡 Traffic Monitoring**: Real-time victim activity tracking
- **🔐 Credential Capture**: Educational credential monitoring system
- **🎯 GUI Interface**: User-friendly PyQt5 interface

### 🔧 Technical Features
- **Aggressive DNS Control**: Blocks external DNS servers (8.8.8.8, 1.1.1.1, etc.)
- **DoH/DoT Blocking**: Prevents DNS over HTTPS/TLS bypass
- **Multi-domain SSL**: Prevents "connection not private" errors
- **Real-time Verification**: Built-in DNS spoofing verification
- **Clean Framework**: No hardcoded phishing templates

### 🎨 Interface Tabs
- **🔵 Dashboard**: Attack controls and status monitoring
- **🛠️ MITM Engine**: Core attack configuration
- **🧪 Fake Pages**: Manual page management (ethical)
- **🧑‍💻 Victims**: Target discovery and monitoring
- **🔐 Credentials**: Captured data analysis
- **📜 Logs**: Real-time activity logging
- **⚙️ Settings**: Tool configuration

---

## 🛠️ Installation

### Prerequisites
- **Operating System**: Linux (Ubuntu/Debian recommended)
- **Python**: 3.8 or higher
- **Root Access**: Required for network operations
- **Network Interface**: Wireless adapter (wlan0) or Ethernet

### 📦 Dependencies Installation

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Python and pip
sudo apt install python3 python3-pip -y

# Install system dependencies
sudo apt install apache2 dnsmasq bettercap nmap arp-scan -y

# Install Python dependencies
pip3 install -r requirements.txt
```

### 🔧 Quick Setup

```bash
# Clone the repository
git clone https://github.com/Saketkesar/SummerSchool2025IITJammu-TeamPORT-443.git
cd SummerSchool2025IITJammu-TeamPORT-443

# Install Python requirements
pip3 install -r requirements.txt

# Make scripts executable
chmod +x *.sh

# Run the application
sudo python3 shadowsnare.py
```

<<<<<<< HEAD
=======
### 2. Configure Network
1. Select your network interface from the dropdown
2. Configure IP range for target discovery
3. Run network scan to discover potential targets

### 3. Setup Attack
1. Enable desired attack modules (ARP/DNS spoofing)
2. Configure spoofing domains and targets
3. Deploy credential capture system
4. Start MITM engine

### 4. Monitor Results
- View real-time logs in the Logs tab
- Monitor captured credentials in Credentials tab
- Track victim activity in Victims tab
- Export results for analysis

## 🌐 Creating Test Pages

> **⚠️ IMPORTANT**: ShadowSnare does **NOT** provide pre-built phishing templates for ethical reasons.

### Why No Templates?
- **Prevents Misuse**: Avoids enabling malicious activities
- **Encourages Learning**: Forces users to understand web development
- **Maintains Ethics**: Upholds responsible cybersecurity practices
- **Legal Protection**: Reduces liability for misuse

### You Must Create Your Own Test Pages

1. **Design Your HTML Page**
   ```html
   <!DOCTYPE html>
   <html lang="en">
   <head>
       <meta charset="UTF-8">
       <meta name="viewport" content="width=device-width, initial-scale=1.0">
       <title>Your Test Page</title>
       <style>
           body { font-family: Arial, sans-serif; margin: 50px; }
           .form-container { max-width: 400px; margin: auto; }
           input { width: 100%; padding: 10px; margin: 10px 0; }
           button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; }
       </style>
   </head>
   <body>
       <div class="form-container">
           <h2>Educational Test Login</h2>
           <form action="credentials.php" method="POST">
               <input type="text" name="username" placeholder="Username" required>
               <input type="password" name="password" placeholder="Password" required>
               <input type="hidden" name="service" value="educational-test">
               <button type="submit">Login</button>
           </form>
       </div>
   </body>
   </html>
   ```

2. **Deploy Your Page**
   ```bash
   # Place your HTML file in Apache directory
   sudo cp your-page.html /var/www/html/index.html
   
   # Ensure Apache is running
   sudo systemctl start apache2
   sudo systemctl enable apache2
   ```

3. **Test Capture System**
   - Visit `http://localhost/` to test your page
   - Submit test credentials
   - Check capture in ShadowSnare Credentials tab

### Credential Capture Requirements
- Form must POST to `credentials.php`
- Use input names: `username`, `password`
- Include service identifier: `<input type="hidden" name="service" value="your-service">`
- The capture system will automatically log submitted credentials

### File Locations
- **HTML Files**: `/var/www/html/`
- **Captured Credentials**: `/var/www/html/credentials.txt` and `/var/www/html/credentials.json`
- **Apache Logs**: `/var/log/apache2/`

## 🛡️ Ethical Guidelines

### ✅ Authorized Use
- **Educational Environments**: Classroom demonstrations and labs
- **Personal Networks**: Your own equipment and infrastructure
- **Authorized Testing**: Penetration tests with written permission
- **Security Research**: Responsible disclosure of vulnerabilities

### ❌ Prohibited Use
- **Unauthorized Networks**: Any network you don't own or have permission to test
- **Malicious Activities**: Stealing credentials or causing harm
- **Commercial Espionage**: Corporate or competitive intelligence gathering
- **Privacy Violations**: Intercepting personal communications without consent

### 📜 Legal Compliance
- Ensure you have **written authorization** before testing any network
- Comply with **local laws and regulations** regarding cybersecurity testing
- Follow **responsible disclosure** practices for any vulnerabilities discovered
- Respect **privacy and data protection** laws

## 🤝 Contributing

We welcome contributions from the cybersecurity community!

### How to Contribute
1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Contribution Guidelines
- Follow Python PEP 8 style guidelines
- Add comprehensive documentation for new features
- Include unit tests for new functionality
- Ensure backward compatibility
- Maintain ethical standards in all contributions

### Areas for Contribution
- **Protocol Support**: Additional network protocols
- **GUI Improvements**: Enhanced user interface features
- **Documentation**: Tutorials and educational content
- **Security Enhancements**: Improved safety mechanisms
- **Cross-platform Support**: Windows and macOS compatibility

## 👥 Team

**Cybersecurity Summer School 2025**

### Development Team
- **Atharv Gaonker** 
- **Saket Kesar**  
- **Dhruv Verma** 

### Project Details
- **Program**: Cybersecurity Summer School 2025
- **Institution**: IIT Jammu
- **Focus**: Educational Cybersecurity Tools
- **Duration**: Summer 2025

### Contact
For educational inquiries or collaboration opportunities:
- GitHub Issues for technical questions
- Educational institutions for partnership opportunities
- Security researchers for responsible disclosure

## 📁 Project Structure

```
shadowsnare/
├── shadowsnare.py          # Main application file
├── requirements.txt        # Python dependencies
├── setup.sh               # Installation script
├── run_shadowsnare.sh     # Launch script
├── FEATURES.md            # Detailed features list
├── shadowsnare_logs.txt   # Application logs
└── README.md              # This file
```

## 🔧 Technical Details

### Dependencies
- **PyQt5**: GUI framework
- **bettercap**: MITM engine
- **Apache2**: Web server
- **iptables**: Traffic redirection
- **nmap**: Network scanning

### Network Requirements
- Root/sudo privileges for network operations
- Network interface with monitor mode capability
- Access to target network (authorized only)

### Supported Protocols
- **HTTP/HTTPS**: Web traffic interception
- **DNS**: Domain name resolution spoofing
- **ARP**: Address resolution protocol manipulation

## 📄 License

This project is licensed under the **Educational Use License**.

### License Summary
- ✅ Educational and research use permitted
- ✅ Modification and distribution for educational purposes
- ❌ Commercial use prohibited without permission
- ❌ Malicious use strictly forbidden
- ⚠️ Users responsible for compliance with local laws

## ⚠️ Disclaimer

### Important Legal Notice

**ShadowSnare is developed exclusively for educational and authorized testing purposes.**

- **No Warranty**: This software is provided "as is" without any warranties
- **User Responsibility**: Users are solely responsible for ensuring legal compliance
- **Educational Purpose**: This tool is designed for learning cybersecurity concepts
- **Prohibited Misuse**: Any illegal or unauthorized use is strictly prohibited
- **Legal Compliance**: Users must comply with all applicable local and international laws

### Developer Responsibility

The developers of ShadowSnare:
- Do not condone or support illegal activities
- Are not responsible for misuse of this software
- Encourage responsible and ethical security research
- Support educational cybersecurity initiatives

### Reporting Issues

If you discover any security vulnerabilities:
1. **DO NOT** open public issues for security vulnerabilities
2. Contact the team through responsible disclosure channels
3. Provide detailed information about the issue
4. Allow reasonable time for response and remediation

>>>>>>> b5fc8e466b7fc7910bf36f2305a94dc8ba927b8a
---

## 🚀 Quick Start

### 1. **Launch ShadowSnare**
```bash
sudo python3 shadowsnare.py
```

### 2. **Network Setup**
- Select your network interface (usually `wlan0`)
- Scan for potential targets
- Choose target IP address

### 3. **DNS Spoofing Attack**
- Configure domains to spoof (e.g., `linkedin.com,facebook.com`)
- Start MITM attack
- Use "🔍 Verify DNS Spoofing" to confirm effectiveness

### 4. **Monitor Results**
- Check **Victims** tab for discovered targets
- Monitor **Logs** tab for real-time activity
- View **Credentials** tab for captured data

---

## 📖 Usage Guide

### 🎯 DNS Spoofing Workflow

1. **Network Discovery**
   ```bash
   # Automatic scan
   IP Range: 192.168.1.1 - 192.168.1.254
   ```

2. **Attack Configuration**
   ```bash
   # Target Selection
   Target IP: 192.168.1.XXX
   Domains: linkedin.com,*.linkedin.com,facebook.com
   ```

3. **Attack Execution**
   - ARP spoofing redirects victim traffic
   - DNS queries resolve to attacker IP
   - HTTP/HTTPS traffic intercepted

### 🧪 Manual Testing Scripts

#### Enhanced DNS Test
```bash
sudo bash dns_spoofing_test.sh
```

#### Working DNS Attack
```bash
sudo bash working_dns_attack.sh
```

### 🔍 Verification Commands
```bash
# Test DNS spoofing
nslookup linkedin.com 192.168.1.14

# Check iptables rules
sudo iptables -t nat -L PREROUTING

# Monitor dnsmasq logs
sudo tail -f /tmp/dnsmasq.log
```

---

## 🔧 Components

### 📁 Project Structure
```
ShadowSnare/
├── shadowsnare.py          # Main application
├── dns_server.py           # Custom DNS server
├── dns_spoofing_test.sh    # Enhanced testing script
├── working_dns_attack.sh   # Manual attack script
├── dnsmasq.conf           # DNS configuration
├── requirements.txt        # Python dependencies
├── DNS_SPOOFING_FIXES.md  # Technical documentation
└── README.md              # This file
```

### 🛠️ Core Components

#### 1. **ShadowSnare GUI** (`shadowsnare.py`)
- Main PyQt5 application
- Complete MITM framework
- Real-time monitoring and control

#### 2. **DNS Server** (`dns_server.py`)
- Custom DNS spoofing server
- Responds to all queries with attacker IP
- Real-time logging and monitoring

#### 3. **Test Scripts**
- **`dns_spoofing_test.sh`**: Comprehensive testing
- **`working_dns_attack.sh`**: Manual attack execution

#### 4. **Configuration Files**
- **`dnsmasq.conf`**: DNS spoofing configuration
- **`requirements.txt`**: Python dependencies

---

## ⚠️ Important Notes

### 🛡️ Ethical Guidelines

> **⚠️ EDUCATIONAL USE ONLY**
> 
> This tool is designed exclusively for educational purposes and authorized security testing. 

#### ✅ Permitted Uses
- **Educational Learning**: Understanding network security
- **Authorized Testing**: Testing on your own networks
- **Research Projects**: Academic cybersecurity research
- **Penetration Testing**: With explicit written permission

#### ❌ Prohibited Uses
- **Malicious Attacks**: Any unauthorized network attacks
- **Data Theft**: Stealing credentials or personal information
- **Privacy Violation**: Unauthorized monitoring of others
- **Commercial Exploitation**: Using for illegal profit

### 🔒 Technical Limitations
- **No Phishing Templates**: Users must create own test pages
- **Linux Only**: Designed for Linux environments
- **Root Required**: Needs administrative privileges
- **Educational Framework**: Not for production attacks

### 🛡️ Legal Disclaimer
- Users are responsible for compliance with local laws
- Only use on networks you own or have explicit permission
- Authors not liable for misuse or legal consequences
- Tool provided "as-is" for educational purposes only

---

## 🤝 Contributing

We welcome contributions from the cybersecurity community!

### 🐛 Bug Reports
- Use GitHub Issues for bug reports
- Include detailed reproduction steps
- Provide system information and logs

### 💡 Feature Requests
- Suggest new educational features
- Propose security improvements
- Share testing methodologies

### 🔧 Development
```bash
# Fork the repository
git fork https://github.com/Saketkesar/SummerSchool2025IITJammu-TeamPORT-443

# Create feature branch
git checkout -b feature/new-feature

# Make changes and commit
git commit -m "Add new educational feature"

# Push and create Pull Request
git push origin feature/new-feature
```

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

### 📋 License Summary
- ✅ **Use**: Educational and research purposes
- ✅ **Modify**: Adapt for learning needs
- ✅ **Distribute**: Share with attribution
- ❌ **Commercial**: No commercial exploitation
- ❌ **Liability**: Authors not responsible for misuse

---

<div align="center">

### 🎓 Cybersecurity Summer School 2025
**Indian Institute of Technology (IIT) Jammu**

*Building the next generation of cybersecurity professionals*

---

**Team PORT:443** | **Educational Framework** | **Ethical Security Research**

[![Hackatime Badge](https://hackatime-badge.hackclub.com/U092A7ANS91/SummerSchool2025IITJammu)](https://hackatime.hackclub.com/)

*Total coding time tracked on this repository*

</div>

---

<div align="center">
  <p>Made with ❤️ by Team PORT:443</p>
  <p><em>For educational purposes and ethical security research</em></p>
</div>
