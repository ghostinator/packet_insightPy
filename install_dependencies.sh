#!/bin/bash
# Packet Insight Dependency Installer

# Check Python installation
if ! command -v python3 &> /dev/null; then
    echo "Python not found. Installing Python..."
    # macOS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install python
    # Linux (Debian/Ubuntu)
    elif [[ -f /etc/debian_version ]]; then
        sudo apt update
        sudo apt install -y python3 python3-pip
    # Linux (RHEL/CentOS)
    elif [[ -f /etc/redhat-release ]]; then
        sudo yum install -y python3 python3-pip
    # Windows (via WSL)
    elif [[ "$OSTYPE" == "msys" ]]; then
        echo "Please install Python from https://python.org"
        exit 1
    fi
fi

# Check for tshark/Wireshark installation
if ! command -v tshark &> /dev/null; then
    echo "tshark not found. Installing Wireshark/tshark..."
    # macOS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install wireshark
    # Linux (Debian/Ubuntu)
    elif [[ -f /etc/debian_version ]]; then
        sudo apt update
        sudo apt install -y tshark
    # Linux (RHEL/CentOS)
    elif [[ -f /etc/redhat-release ]]; then
        sudo yum install -y wireshark
    # Windows (via WSL)
    elif [[ "$OSTYPE" == "msys" ]]; then
        echo "Please install Wireshark from https://www.wireshark.org/download.html"
    fi
fi

# Install PyInstaller and dependencies
pip3 install pyinstaller pyshark tqdm netifaces pyyaml

echo "Dependencies installed successfully!"
