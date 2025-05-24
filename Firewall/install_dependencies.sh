#!/bin/bash

# Exit on any error
set -e

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect package manager
detect_package_manager() {
    if command_exists dnf; then
        echo "dnf"
    elif command_exists yum; then
        echo "yum"
    elif command_exists apt-get; then
        echo "apt-get"
    else
        echo "none"
    fi
}

# Install package using appropriate package manager
install_package() {
    local package=$1
    case $PACKAGE_MANAGER in
        dnf|yum)
            sudo $PACKAGE_MANAGER install -y "$package"
            ;;
        apt-get)
            sudo apt-get update
            sudo apt-get install -y "$package"
            ;;
        *)
            echo "Error: Unsupported package manager. Please install $package manually."
            exit 1
            ;;
    esac
}

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

# Detect package manager
PACKAGE_MANAGER=$(detect_package_manager)
if [ "$PACKAGE_MANAGER" = "none" ]; then
    echo "Error: No supported package manager found (dnf, yum, or apt-get required)"
    exit 1
fi
echo "Using package manager: $PACKAGE_MANAGER"

# Install Python 3 and pip
echo "Installing Python 3 and pip..."
install_package python3
install_package python3-pip

# Install system dependencies
echo "Installing system dependencies..."
case $PACKAGE_MANAGER in
    dnf|yum)
        install_package python3-devel
        install_package gcc
        install_package make
        install_package libpcap-devel
        install_package nmap
        install_package iptables
        install_package nftables
        install_package net-tools
        install_package iproute
        install_package bridge-utils
        ;;
    apt-get)
        install_package python3-dev
        install_package gcc
        install_package make
        install_package libpcap-dev
        install_package nmap
        install_package iptables
        install_package nftables
        install_package net-tools
        install_package iproute2
        install_package bridge-utils
        ;;
esac

# Install Python packages
echo "Installing Python packages..."
pip3 install --upgrade pip
pip3 install flask
pip3 install psutil
pip3 install python-nmap
pip3 install scapy
pip3 install netfilterqueue
pip3 install netifaces
pip3 install ipaddress

# Install nftables Python bindings
echo "Installing nftables Python bindings..."
pip3 install libnftables

# Configure nftables
echo "Configuring nftables..."
systemctl enable nftables
systemctl start nftables

# Disable firewalld if present
if command_exists systemctl && systemctl list-units --full -all | grep -q firewalld; then
    echo "Disabling firewalld..."
    systemctl stop firewalld
    systemctl disable firewalld
fi

# Enable IP forwarding
echo "Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
# Make IP forwarding persistent
if [ -f /etc/sysctl.conf ]; then
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
fi

# Create web directory for JSON files
echo "Creating web directory..."
mkdir -p web
chmod 755 web

# Verify installations
echo "Verifying installations..."
for cmd in python3 pip3 nmap nft iptables ip; do
    if command_exists "$cmd"; then
        echo "$cmd is installed"
    else
        echo "Error: $cmd is not installed"
        exit 1
    fi
done

# Verify Python packages
for pkg in flask psutil python-nmap scapy netfilterqueue netifaces ipaddress libnftables; do
    if pip3 show "$pkg" >/dev/null 2>&1; then
        echo "Python package $pkg is installed"
    else
        echo "Error: Python package $pkg is not installed"
        exit 1
    fi
done

echo "All dependencies installed successfully!"
echo "You can now run the firewall script."
echo "Note: Ensure port 5000 is free before running the Flask application."