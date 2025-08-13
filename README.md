# ShadowSnare

> Advanced MITM GUI Tool for Educational Cybersecurity Research

<div align="center">

[![Hackatime Badge](https://hackatime-badge.hackclub.com/U092A7ANS91/SummerSchool2025IITJammu)](https://hackatime.hackclub.com/)

**Total coding time tracked using Hackatime**

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-green.svg)
![GUI](https://img.shields.io/badge/GUI-PyQt5-orange.svg)
![Status](https://img.shields.io/badge/Status-Complete-success.svg)

</div>

## Overview

ShadowSnare is a comprehensive GUI-based Man-in-the-Middle attack tool developed for cybersecurity education during Summer School 2025 at IIT Jammu. It provides a complete framework for understanding network vulnerabilities through an intuitive PyQt5 interface.

### Key Capabilities
- Real-time network reconnaissance and target discovery
- Advanced ARP and DNS spoofing techniques
- Traffic interception and analysis
- Phishing infrastructure deployment
- Comprehensive logging and monitoring

```
Target → ShadowSnare → Internet
         ↓
    Attack Dashboard
```

## Features

### Core Attack Modules
- **Network Scanner** - Automated target discovery using nmap integration
- **ARP Spoofing** - Traffic redirection through ARP table manipulation  
- **DNS Spoofing** - Domain hijacking with DoH/DoT blocking capabilities
- **GUI Interface** - Multi-tabbed PyQt5 dashboard with real-time updates
- **Phishing Framework** - Customizable phishing page deployment
- **Traffic Monitor** - Live packet analysis and credential capture
- **Session Management** - Multi-target attack coordination

### Technical Features
- Bettercap integration for advanced network attacks
- Apache web server with SSL/TLS support via Cloudflare tunnels
- Real-time DNS verification and monitoring
- Comprehensive logging system
- Cross-platform compatibility (Linux focus)

## Installation

```bash
# Clone repository
git clone https://github.com/Saketkesar/SummerSchool2025IITJammu-TeamPORT-443.git
cd SummerSchool2025IITJammu-TeamPORT-443

# Setup dependencies
sudo ./setup.sh
pip3 install -r requirements.txt

# Launch application
sudo python3 shadowsnare.py
```

## How It Works

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     Victim      │────│   ShadowSnare   │────│   Real Server   │
│   192.168.1.16  │    │   192.168.1.14  │    │   target.com    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Code Example

```python
# Start attack
def start_attack(target_ip, domain):
    commands = [
        f"set arp.spoof.targets {target_ip}",
        "arp.spoof on",
        f"set dns.spoof.domains {domain}",
        "dns.spoof on"
    ]
    execute_bettercap(commands)
```

## Team

**Team PORT:443**  
Dhruv Verma • Saket Kesar • Atharv Gaonker  
*Summer School 2025 - IIT Jammu*



## Contributing

We welcome contributions to improve ShadowSnare for educational purposes:

### How to Contribute
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Make your changes with proper documentation
4. Test thoroughly in isolated environments
5. Submit a pull request with detailed description

### Contribution Guidelines
- Follow ethical hacking principles
- Maintain educational focus
- Include proper error handling
- Add comprehensive comments
- Update documentation accordingly
- Test all network attack modules

### Areas for Contribution
- Additional attack vectors and modules
- GUI improvements and user experience
- Performance optimizations
- Cross-platform compatibility
- Documentation and tutorials
- Security enhancements

## Requirements

### System Requirements
- **Operating System**: Linux (Ubuntu 20.04+ recommended)
- **Python**: 3.8 or higher
- **Memory**: 2GB RAM minimum
- **Storage**: 1GB free space
- **Network**: Wireless adapter or Ethernet interface

### Dependencies
- **PyQt5** - GUI framework
- **Bettercap** - Network attack engine
- **Apache2** - Web server
- **nmap** - Network discovery
- **iptables** - Traffic control

### Optional Tools
- **Cloudflared** - HTTPS tunnel support
- **Wireshark** - Advanced packet analysis
- **Metasploit** - Extended attack capabilities

## Project Structure

```
ShadowSnare/
├── shadowsnare.py                    # Main GUI application
├── dns_server.py                     # DNS spoofing module  
├── setup.sh                         # Automated installation script
├── requirements.txt                 # Python dependencies
├── README.md                        # Project documentation
├── ShadowSnare_Internship_Annexure.txt  # Technical documentation
└── LICENSE                          # MIT license
```

### Module Breakdown
- **GUI Components**: PyQt5-based interface with multiple tabs
- **Network Engine**: Bettercap integration for attack execution
- **Web Framework**: Apache server with PHP backend
- **Logging System**: Comprehensive activity and credential logging
- **Configuration**: JSON-based settings and target management

## Educational Use Only

**Important Notice**: This tool is developed strictly for educational and authorized testing purposes.

### Permitted Uses
- Cybersecurity education and training
- Authorized penetration testing
- Network security research
- Vulnerability demonstration in controlled environments

### Prohibited Uses
- Unauthorized network attacks
- Malicious credential harvesting
- Privacy violations
- Any illegal activities

### Legal Compliance
Users must ensure compliance with local laws and regulations. The developers are not responsible for misuse of this educational tool.
