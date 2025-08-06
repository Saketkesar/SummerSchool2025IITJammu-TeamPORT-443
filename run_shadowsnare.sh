#!/bin/bash
# ShadowSnare Launcher Script
# Developed by Team PORT:443

echo "🚀 ShadowSnare Launcher"
echo "========================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Root privileges required!"
    echo "🔧 Starting ShadowSnare with sudo..."
    echo ""
    sudo python3 shadowsnare.py
else
    echo "✅ Root privileges detected"
    echo "🚀 Starting ShadowSnare..."
    echo ""
    python3 shadowsnare.py
fi
