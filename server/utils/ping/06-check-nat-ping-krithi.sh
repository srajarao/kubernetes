#!/bin/bash

# 06-check-nat-ping-krithi.sh
# Network connectivity check script for Krithi (run from Tower via SSH)
# Checks ping to all cluster nodes, default gateway, and DNS resolution from Krithi

KRITHI_IP="192.168.1.100"
SSH_USER="sanjay"
SSH_KEY="$HOME/.ssh/id_ed25519"
SSH_OPTS="-o StrictHostKeyChecking=no -o LogLevel=ERROR -i $SSH_KEY"

echo "=== Network Connectivity Check from Krithi ==="
echo "Date: $(date)"
echo "Running checks on Krithi ($KRITHI_IP) via SSH"
echo

# Function to run command on Krithi via SSH
run_on_krithi() {
    ssh $SSH_OPTS $SSH_USER@$KRITHI_IP "$1"
}

# Function to check ping from Krithi
check_ping_from_krithi() {
    local host=$1
    local ip=$2
    echo -n "Pinging $host ($ip) from Krithi... "
    if run_on_krithi "ping -c 3 -W 2 $ip > /dev/null 2>&1"; then
        echo "✓ SUCCESS"
        return 0
    else
        echo "✗ FAILED"
        return 1
    fi
}

# Check connectivity from Krithi to cluster nodes
echo "=== Checking connectivity from Krithi to cluster nodes ==="
FAILED_NODES=""

# Tower
if ! check_ping_from_krithi "tower" "192.168.1.150"; then
    FAILED_NODES="$FAILED_NODES tower"
fi

# Spark1
if ! check_ping_from_krithi "spark1" "192.168.1.201"; then
    FAILED_NODES="$FAILED_NODES spark1"
fi

# Spark2
if ! check_ping_from_krithi "spark2" "192.168.1.202"; then
    FAILED_NODES="$FAILED_NODES spark2"
fi

# AGX
if ! check_ping_from_krithi "agx" "192.168.1.244"; then
    FAILED_NODES="$FAILED_NODES agx"
fi

# Nano
if ! check_ping_from_krithi "nano" "192.168.1.181"; then
    FAILED_NODES="$FAILED_NODES nano"
fi

echo

# Check default gateway on Krithi
echo "=== Checking default gateway on Krithi ==="
GATEWAYS=$(run_on_krithi "ip route show default | awk '{print \$3}' | tr '\n' ' '")
if echo "$GATEWAYS" | grep -q "192.168.1.1"; then
    echo "✓ Default gateway includes 192.168.1.1 (ER605 router)"
    echo "  All gateways: $GATEWAYS"
else
    echo "✗ Default gateway does not include 192.168.1.1. Got: $GATEWAYS"
fi

echo

# Check DNS resolution from Krithi
echo "=== Checking DNS resolution from Krithi ==="
echo -n "Resolving google.com from Krithi... "
if run_on_krithi "nslookup google.com > /dev/null 2>&1 || host google.com > /dev/null 2>&1"; then
    echo "✓ SUCCESS"
else
    echo "✗ FAILED"
fi

echo

# Check Krithi's local network configuration
echo "=== Krithi Network Configuration ==="
echo "Krithi IP addresses:"
run_on_krithi "ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print \"  \" \$2}'"

echo
echo "Krithi routing table (default routes):"
run_on_krithi "ip route show | grep '^default' | sed 's/^/  /'"

echo

# Summary
echo "=== Summary ==="
if [ -n "$FAILED_NODES" ]; then
    echo "✗ Failed to ping nodes from Krithi:$FAILED_NODES"
    exit 1
else
    echo "✓ All nodes are reachable from Krithi"
fi

echo "✓ Network configuration check from Krithi completed"