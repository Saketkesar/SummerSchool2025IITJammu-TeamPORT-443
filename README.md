# ShadowSnare 🕷️

**Advanced Ethical MITM Framework for Cybersecurity Education**

![ShadowSnare](https://img.shields.io/badge/ShadowSnare-v2.0-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-Educational-orange.svg)

> **⚠️ EDUCATIONAL PURPOSE ONLY**  
> This tool is developed for cybersecurity education and authorized penetration testing only. Misuse of this tool for illegal activities is strictly prohibited.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Educational Purpose](#educational-purpose)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Creating Test Pages](#creating-test-pages)
- [Ethical Guidelines](#ethical-guidelines)
- [Contributing](#contributing)
- [Team](#team)
- [License](#license)
- [Disclaimer](#disclaimer)

## 🎯 Overview

ShadowSnare is an advanced Man-in-the-Middle (MITM) framework designed specifically for cybersecurity education and authorized penetration testing. It provides a comprehensive GUI-based platform for understanding network security vulnerabilities and attack vectors.

### Key Capabilities
- **ARP Spoofing**: Intercept network traffic through ARP table manipulation
- **DNS Spoofing**: Redirect domain queries to controlled servers
- **SSL Stripping**: Downgrade HTTPS connections to capture credentials
- **Real-time Monitoring**: Live traffic analysis and credential capture
- **Educational Interface**: User-friendly GUI for learning purposes

## ✨ Features

### 🛠️ Core Features
- **Multi-threaded MITM Engine** powered by bettercap
- **Professional PyQt5 GUI** with dark theme
- **Real-time Network Scanning** and victim discovery
- **Live Traffic Monitoring** with detailed logs
- **Credential Capture System** with multiple export formats
- **SSL/TLS Interception** capabilities
- **Comprehensive Logging** system

### 🎨 User Interface
- **Dashboard**: Real-time attack status and controls
- **MITM Engine**: Network configuration and attack settings
- **Fake Pages**: Manual page deployment guidance (**NO TEMPLATES PROVIDED**)
- **Victims**: Discovered hosts and target management
- **Credentials**: Live credential capture monitoring
- **Logs**: Detailed attack logs and system events
- **Settings**: Tool configuration and team information

### 🔧 Technical Features
- **Multi-protocol Support**: HTTP/HTTPS/DNS traffic interception
- **Advanced Proxy Scripts**: Custom JavaScript-based traffic manipulation
- **Flexible Network Configuration**: Support for multiple interfaces
- **Export Capabilities**: CSV, TXT, and JSON export formats
- **Real-time Updates**: Live status monitoring and notifications

## 🎓 Educational Purpose

ShadowSnare is developed as part of the **Cybersecurity Summer School 2025** program to:

- **Demonstrate MITM Attack Vectors**: Show how network attacks work in controlled environments
- **Teach Network Security**: Help students understand vulnerability assessment
- **Promote Ethical Hacking**: Encourage responsible security research
- **Develop Technical Skills**: Hands-on experience with security tools

### Learning Objectives
1. Understanding network protocol vulnerabilities
2. Learning about ARP and DNS spoofing techniques
3. Exploring SSL/TLS security mechanisms
4. Practicing ethical penetration testing methodologies
5. Developing incident response skills

## 📋 Prerequisites

### System Requirements
- **Operating System**: Linux (Ubuntu 20.04+ recommended)
- **Python**: 3.8 or higher
- **Memory**: Minimum 2GB RAM
- **Network**: Wireless adapter with monitor mode support
- **Privileges**: Root/sudo access required

### Required Tools
- **bettercap**: Modern MITM framework
- **Apache2**: Web server for hosting capture pages
- **nmap**: Network scanning utility
- **iptables**: Traffic redirection and filtering

## 🚀 Installation

### 1. Clone Repository
```bash
git clone https://github.com/your-username/shadowsnare.git
cd shadowsnare
```

### 2. Run Setup Script
```bash
chmod +x setup.sh
sudo ./setup.sh
```

### 3. Install Python Dependencies
```bash
pip3 install -r requirements.txt
```

### 4. Verify Installation
```bash
# Check if all tools are installed
which bettercap nmap apache2
```

## 💻 Usage

### 1. Launch ShadowSnare
```bash
# Method 1: Direct execution
sudo python3 shadowsnare.py

# Method 2: Using launcher script
chmod +x run_shadowsnare.sh
./run_shadowsnare.sh
```

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
- **Atharv Gaonker** - Core Development & Network Security
- **Saket Kesar** - GUI Design & System Integration  
- **Dhruv Verma** - Testing & Quality Assurance

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

---

## 🚀 Quick Start

```bash
# Clone and setup
git clone https://github.com/your-username/shadowsnare.git
cd shadowsnare
chmod +x setup.sh
sudo ./setup.sh

# Install dependencies
pip3 install -r requirements.txt

# Run ShadowSnare
sudo python3 shadowsnare.py
```

---

**Remember: With great power comes great responsibility. Use ShadowSnare ethically and legally.** 🕷️

---

*Developed with ❤️ for cybersecurity education by Team PORT:443*

*Summer School 2025 | IIT Jammu*
