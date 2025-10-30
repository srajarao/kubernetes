#!/bin/bash

# 03-check-nat-ping-spark1.sh
# Network connectivity check script for Spark1 (run from Tower via SSH)
# Checks ping to all cluster nodes, default gateway, and DNS resolution from Spark1

SPARK1_IP="192.168.1.201"
SSH_USER="sanjay"
SSH_KEY="$HOME/.ssh/id_ed25519"
SSH_OPTS="-o StrictHostKeyChecking=no -o LogLevel=ERROR -i $SSH_KEY"

echo "=== Network Connectivity Check from Spark1 ==="
echo "Date: $(date)"
echo "Running checks on Spark1 ($SPARK1_IP) via SSH"
echo

# Function to run command on Spark1 via SSH
run_on_spark1() {
    ssh $SSH_OPTS $SSH_USER@$SPARK1_IP "$1"
}

# Function to check ping from Spark1
check_ping_from_spark1() {
    local host=$1
    local ip=$2
    echo -n "Pinging $host ($ip) from Spark1... "
    if run_on_spark1 "ping -c 3 -W 2 $ip > /dev/null 2>&1"; then
        echo "✓ SUCCESS"
        return 0
    else
        echo "✗ FAILED"
        return 1
    fi
}

# Check connectivity from Spark1 to cluster nodes
echo "=== Checking connectivity from Spark1 to cluster nodes ==="
FAILED_NODES=""

# Tower
if ! check_ping_from_spark1 "tower" "192.168.1.150"; then
    FAILED_NODES="$FAILED_NODES tower"
fi

# Spark2
if ! check_ping_from_spark1 "spark2" "192.168.1.202"; then
    FAILED_NODES="$FAILED_NODES spark2"
fi

# AGX
if ! check_ping_from_spark1 "agx" "192.168.1.244"; then
    FAILED_NODES="$FAILED_NODES agx"
fi

# Nano
if ! check_ping_from_spark1 "nano" "192.168.1.181"; then
    FAILED_NODES="$FAILED_NODES nano"
fi

echo

# Check default gateway on Spark1
echo "=== Checking default gateway on Spark1 ==="
GATEWAYS=$(run_on_spark1 "ip route show default | awk '{print \$3}' | tr '\n' ' '")
if echo "$GATEWAYS" | grep -q "192.168.1.1"; then
    echo "✓ Default gateway includes 192.168.1.1 (ER605 router)"
    echo "  All gateways: $GATEWAYS"
else
    echo "✗ Default gateway does not include 192.168.1.1. Got: $GATEWAYS"
fi

echo

# Check DNS resolution from Spark1
echo "=== Checking DNS resolution from Spark1 ==="
echo -n "Resolving google.com from Spark1... "
if run_on_spark1 "nslookup google.com > /dev/null 2>&1 || host google.com > /dev/null 2>&1"; then
    echo "✓ SUCCESS"
else
    echo "✗ FAILED"
fi

echo

# Check Spark1's local network configuration
echo "=== Spark1 Network Configuration ==="
echo "Spark1 IP addresses:"
run_on_spark1 "ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print \"  \" \$2}'"

echo
echo "Spark1 routing table (default routes):"
run_on_spark1 "ip route show | grep '^default' | sed 's/^/  /'"

echo

# Summary
echo "=== Summary ==="
if [ -n "$FAILED_NODES" ]; then
    echo "✗ Failed to ping nodes from Spark1:$FAILED_NODES"
    exit 1
else
    echo "✓ All nodes are reachable from Spark1"
fi

echo "✓ Network configuration check from Spark1 completed"