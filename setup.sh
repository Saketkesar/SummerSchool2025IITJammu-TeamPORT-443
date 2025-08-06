#!/bin/bash

echo "🚀 ShadowSnare Setup Script"
echo "Developed by Team PORT:443"
echo "================================"

# Update system
echo "📦 Updating system packages..."
sudo apt-get update -qq

# Install Python dependencies
echo "🐍 Installing Python dependencies..."
sudo apt-get install -y python3 python3-pip python3-venv

# Install PyQt5
echo "🖥️ Installing PyQt5..."
sudo apt-get install -y python3-pyqt5 python3-pyqt5.qtwidgets

# Install network tools
echo "🌐 Installing network tools..."
sudo apt-get install -y nmap bettercap apache2 php

# Install additional tools
echo "🔧 Installing additional tools..."
sudo apt-get install -y iptables-persistent dnsutils

# Enable Apache
echo "🌐 Configuring Apache..."
sudo systemctl enable apache2
sudo systemctl start apache2

# Create web directory
sudo mkdir -p /var/www/html
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html

# Install Python requirements
echo "📋 Installing Python requirements..."
pip3 install -r requirements.txt

# Set permissions
chmod +x shadowsnare.py

echo "✅ Setup complete!"
echo ""
echo "🚀 To run ShadowSnare:"
echo "   sudo python3 shadowsnare.py"
echo ""
echo "⚠️  Remember: For Educational Purposes Only!"