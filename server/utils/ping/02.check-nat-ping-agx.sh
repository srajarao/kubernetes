#!/bin/bash

# 02.check-nat-ping-agx.sh
# Network connectivity check script for AGX (run from Tower via SSH)
# Checks ping to all cluster nodes, default gateway, and DNS resolution from AGX

AGX_IP="192.168.1.244"
SSH_USER="sanjay"
SSH_KEY="$HOME/.ssh/id_ed25519"
SSH_OPTS="-o StrictHostKeyChecking=no -o LogLevel=ERROR -i $SSH_KEY"

echo "=== Network Connectivity Check from AGX ==="
echo "Date: $(date)"
echo "Running checks on AGX ($AGX_IP) via SSH"
echo

# Function to run command on AGX via SSH
run_on_agx() {
    ssh $SSH_OPTS $SSH_USER@$AGX_IP "$1"
}

# Function to check ping from AGX
check_ping_from_agx() {
    local host=$1
    local ip=$2
    echo -n "Pinging $host ($ip) from AGX... "
    if run_on_agx "ping -c 3 -W 2 $ip > /dev/null 2>&1"; then
        echo "✓ SUCCESS"
        return 0
    else
        echo "✗ FAILED"
        return 1
    fi
}

# Check connectivity from AGX to cluster nodes
echo "=== Checking connectivity from AGX to cluster nodes ==="
FAILED_NODES=""

# Tower
if ! check_ping_from_agx "tower" "192.168.1.150"; then
    FAILED_NODES="$FAILED_NODES tower"
fi

# Spark1
if ! check_ping_from_agx "spark1" "192.168.1.201"; then
    FAILED_NODES="$FAILED_NODES spark1"
fi

# Spark2
if ! check_ping_from_agx "spark2" "192.168.1.202"; then
    FAILED_NODES="$FAILED_NODES spark2"
fi

# Nano
if ! check_ping_from_agx "nano" "192.168.1.181"; then
    FAILED_NODES="$FAILED_NODES nano"
fi

echo

# Check default gateway on AGX
echo "=== Checking default gateway on AGX ==="
GATEWAYS=$(run_on_agx "ip route show default | awk '{print \$3}' | tr '\n' ' '")
if echo "$GATEWAYS" | grep -q "192.168.1.1"; then
    echo "✓ Default gateway includes 192.168.1.1 (ER605 router)"
    echo "  All gateways: $GATEWAYS"
else
    echo "✗ Default gateway does not include 192.168.1.1. Got: $GATEWAYS"
fi

echo

# Check DNS resolution from AGX
echo "=== Checking DNS resolution from AGX ==="
echo -n "Resolving google.com from AGX... "
if run_on_agx "nslookup google.com > /dev/null 2>&1 || host google.com > /dev/null 2>&1"; then
    echo "✓ SUCCESS"
else
    echo "✗ FAILED"
fi

echo

# Check AGX's local network configuration
echo "=== AGX Network Configuration ==="
echo "AGX IP addresses:"
run_on_agx "ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print \"  \" \$2}'"

echo
echo "AGX routing table (default routes):"
run_on_agx "ip route show | grep '^default' | sed 's/^/  /'"

echo

# Summary
echo "=== Summary ==="
if [ -n "$FAILED_NODES" ]; then
    echo "✗ Failed to ping nodes from AGX:$FAILED_NODES"
    exit 1
else
    echo "✓ All nodes are reachable from AGX"
fi

echo "✓ Network configuration check from AGX completed"