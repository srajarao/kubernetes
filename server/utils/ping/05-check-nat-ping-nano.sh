#!/bin/bash

# 05-check-nat-ping-nano.sh
# Network connectivity check script for Nano (run from Tower via SSH)
# Checks ping to all cluster nodes, default gateway, and DNS resolution from Nano

NANO_IP="192.168.1.181"
SSH_USER="sanjay"
SSH_KEY="$HOME/.ssh/id_ed25519"
SSH_OPTS="-o StrictHostKeyChecking=no -o LogLevel=ERROR -i $SSH_KEY"

echo "=== Network Connectivity Check from Nano ==="
echo "Date: $(date)"
echo "Running checks on Nano ($NANO_IP) via SSH"
echo

# Function to run command on Nano via SSH
run_on_nano() {
    ssh $SSH_OPTS $SSH_USER@$NANO_IP "$1"
}

# Function to check ping from Nano
check_ping_from_nano() {
    local host=$1
    local ip=$2
    echo -n "Pinging $host ($ip) from Nano... "
    if run_on_nano "ping -c 3 -W 2 $ip > /dev/null 2>&1"; then
        echo "✓ SUCCESS"
        return 0
    else
        echo "✗ FAILED"
        return 1
    fi
}

# Check connectivity from Nano to cluster nodes
echo "=== Checking connectivity from Nano to cluster nodes ==="
FAILED_NODES=""

# Tower
if ! check_ping_from_nano "tower" "192.168.1.150"; then
    FAILED_NODES="$FAILED_NODES tower"
fi

# Spark1
if ! check_ping_from_nano "spark1" "192.168.1.201"; then
    FAILED_NODES="$FAILED_NODES spark1"
fi

# Spark2
if ! check_ping_from_nano "spark2" "192.168.1.202"; then
    FAILED_NODES="$FAILED_NODES spark2"
fi

# AGX
if ! check_ping_from_nano "agx" "192.168.1.244"; then
    FAILED_NODES="$FAILED_NODES agx"
fi

echo

# Check default gateway on Nano
echo "=== Checking default gateway on Nano ==="
GATEWAYS=$(run_on_nano "ip route show default | awk '{print \$3}' | tr '\n' ' '")
if echo "$GATEWAYS" | grep -q "192.168.1.1"; then
    echo "✓ Default gateway includes 192.168.1.1 (ER605 router)"
    echo "  All gateways: $GATEWAYS"
else
    echo "✗ Default gateway does not include 192.168.1.1. Got: $GATEWAYS"
fi

echo

# Check DNS resolution from Nano
echo "=== Checking DNS resolution from Nano ==="
echo -n "Resolving google.com from Nano... "
if run_on_nano "nslookup google.com > /dev/null 2>&1 || host google.com > /dev/null 2>&1"; then
    echo "✓ SUCCESS"
else
    echo "✗ FAILED"
fi

echo

# Check Nano's local network configuration
echo "=== Nano Network Configuration ==="
echo "Nano IP addresses:"
run_on_nano "ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print \"  \" \$2}'"

echo
echo "Nano routing table (default routes):"
run_on_nano "ip route show | grep '^default' | sed 's/^/  /'"

echo

# Summary
echo "=== Summary ==="
if [ -n "$FAILED_NODES" ]; then
    echo "✗ Failed to ping nodes from Nano:$FAILED_NODES"
    exit 1
else
    echo "✓ All nodes are reachable from Nano"
fi

echo "✓ Network configuration check from Nano completed"