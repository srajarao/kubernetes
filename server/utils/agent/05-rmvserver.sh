#!/bin/bash

# Script to remove k3s server from Tower (local execution)
# This script performs a clean removal of the k3s server installation

set -e

echo "Starting k3s server removal on Tower..."

# Stop the k3s service if running
if systemctl is-active --quiet k3s.service; then
    echo "Stopping k3s service..."
    sudo systemctl stop k3s.service
    sudo systemctl disable k3s.service
fi

# Remove the k3s systemd service file
if [ -f /etc/systemd/system/k3s.service ]; then
    echo "Removing k3s systemd service file..."
    sudo rm -f /etc/systemd/system/k3s.service
    sudo systemctl daemon-reload
fi

# Remove k3s binary and related files
if [ -x /usr/local/bin/k3s ]; then
    echo "Removing k3s binary..."
    sudo rm -f /usr/local/bin/k3s
fi

# Remove k3s data directory
if [ -d /var/lib/rancher/k3s ]; then
    echo "Removing k3s data directory..."
    sudo rm -rf /var/lib/rancher/k3s
fi

# Remove k3s configuration files
if [ -d /etc/rancher/k3s ]; then
    echo "Removing k3s configuration directory..."
    sudo rm -rf /etc/rancher/k3s
fi

# Remove k3s uninstall script if present
if [ -f /usr/local/bin/k3s-uninstall.sh ]; then
    echo "Removing k3s uninstall script..."
    sudo rm -f /usr/local/bin/k3s-uninstall.sh
fi

# Clean up any remaining k3s processes
echo "Checking for any remaining k3s processes..."
if pgrep -f k3s > /dev/null; then
    echo "Terminating remaining k3s processes..."
    sudo pkill -f k3s || true
fi

# Remove k3s user if it exists
if id -u k3s > /dev/null 2>&1; then
    echo "Removing k3s user..."
    sudo userdel k3s || true
fi

# Remove k3s group if it exists
if getent group k3s > /dev/null 2>&1; then
    echo "Removing k3s group..."
    sudo groupdel k3s || true
fi

echo "k3s server removal completed successfully on Tower."
echo "Note: You may need to manually clean up any remaining configuration files or data."