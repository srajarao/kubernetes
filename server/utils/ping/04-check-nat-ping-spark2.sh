#!/bin/bash

# 04-check-nat-ping-spark2.sh
# Network connectivity check script for Spark2 (run from Tower via SSH)
# Checks ping to all cluster nodes, default gateway, and DNS resolution from Spark2

SPARK2_IP="192.168.1.202"
SSH_USER="sanjay"
SSH_KEY="$HOME/.ssh/id_ed25519"
SSH_OPTS="-o StrictHostKeyChecking=no -o LogLevel=ERROR -i $SSH_KEY"

echo "=== Network Connectivity Check from Spark2 ==="
echo "Date: $(date)"
echo "Running checks on Spark2 ($SPARK2_IP) via SSH"
echo

# Function to run command on Spark2 via SSH
run_on_spark2() {
    ssh $SSH_OPTS $SSH_USER@$SPARK2_IP "$1"
}

# Function to check ping from Spark2
check_ping_from_spark2() {
    local host=$1
    local ip=$2
    echo -n "Pinging $host ($ip) from Spark2... "
    if run_on_spark2 "ping -c 3 -W 2 $ip > /dev/null 2>&1"; then
        echo "✓ SUCCESS"
        return 0
    else
        echo "✗ FAILED"
        return 1
    fi
}

# Check connectivity from Spark2 to cluster nodes
echo "=== Checking connectivity from Spark2 to cluster nodes ==="
FAILED_NODES=""

# Tower
if ! check_ping_from_spark2 "tower" "192.168.1.150"; then
    FAILED_NODES="$FAILED_NODES tower"
fi

# Spark1
if ! check_ping_from_spark2 "spark1" "192.168.1.201"; then
    FAILED_NODES="$FAILED_NODES spark1"
fi

# AGX
if ! check_ping_from_spark2 "agx" "192.168.1.244"; then
    FAILED_NODES="$FAILED_NODES agx"
fi

# Nano
if ! check_ping_from_spark2 "nano" "192.168.1.181"; then
    FAILED_NODES="$FAILED_NODES nano"
fi

echo

# Check default gateway on Spark2
echo "=== Checking default gateway on Spark2 ==="
GATEWAYS=$(run_on_spark2 "ip route show default | awk '{print \$3}' | tr '\n' ' '")
if echo "$GATEWAYS" | grep -q "192.168.1.1"; then
    echo "✓ Default gateway includes 192.168.1.1 (ER605 router)"
    echo "  All gateways: $GATEWAYS"
else
    echo "✗ Default gateway does not include 192.168.1.1. Got: $GATEWAYS"
fi

echo

# Check DNS resolution from Spark2
echo "=== Checking DNS resolution from Spark2 ==="
echo -n "Resolving google.com from Spark2... "
if run_on_spark2 "nslookup google.com > /dev/null 2>&1 || host google.com > /dev/null 2>&1"; then
    echo "✓ SUCCESS"
else
    echo "✗ FAILED"
fi

echo

# Check Spark2's local network configuration
echo "=== Spark2 Network Configuration ==="
echo "Spark2 IP addresses:"
run_on_spark2 "ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print \"  \" \$2}'"

echo
echo "Spark2 routing table (default routes):"
run_on_spark2 "ip route show | grep '^default' | sed 's/^/  /'"

echo

# Summary
echo "=== Summary ==="
if [ -n "$FAILED_NODES" ]; then
    echo "✗ Failed to ping nodes from Spark2:$FAILED_NODES"
    exit 1
else
    echo "✓ All nodes are reachable from Spark2"
fi

echo "✓ Network configuration check from Spark2 completed"