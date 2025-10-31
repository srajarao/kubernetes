#!/bin/bash

# 06-check-nat-ping-krithi.sh
# Network connectivity and configuration check script for Krithi
# Checks ping to all cluster nodes, default gateway, and DNS resolution

echo "=== Network Connectivity Check from Krithi ==="
echo "Date: $(date)"
echo

# Function to check ping
check_ping() {
    local host=$1
    local ip=$2
    echo -n "Pinging $host ($ip)... "
    if ping -c 3 -W 2 $ip > /dev/null 2>&1; then
        echo "✓ SUCCESS"
        return 0
    else
        echo "✗ FAILED"
        return 1
    fi
}

# Check connectivity to cluster nodes
echo "=== Checking connectivity to cluster nodes ==="
FAILED_NODES=""

# Tower
if ! check_ping "tower" "192.168.1.150"; then
    FAILED_NODES="$FAILED_NODES tower"
fi

# Spark1
if ! check_ping "spark1" "192.168.1.201"; then
    FAILED_NODES="$FAILED_NODES spark1"
fi

# Spark2
if ! check_ping "spark2" "192.168.1.202"; then
    FAILED_NODES="$FAILED_NODES spark2"
fi

# AGX
if ! check_ping "agx" "192.168.1.244"; then
    FAILED_NODES="$FAILED_NODES agx"
fi

# Nano
if ! check_ping "nano" "192.168.1.181"; then
    FAILED_NODES="$FAILED_NODES nano"
fi

echo

# Check default gateway
echo "=== Checking default gateway ==="
GATEWAYS=$(ip route show default | awk '{print $3}' | tr '\n' ' ')
if echo "$GATEWAYS" | grep -q "192.168.1.1"; then
    echo "✓ Default gateway includes 192.168.1.1 (ER605 router)"
    echo "  All gateways: $GATEWAYS"
else
    echo "✗ Default gateway does not include 192.168.1.1. Got: $GATEWAYS"
fi

echo

# Check DNS resolution
echo "=== Checking DNS resolution ==="
echo -n "Resolving google.com... "
if nslookup google.com > /dev/null 2>&1 || host google.com > /dev/null 2>&1; then
    echo "✓ SUCCESS"
else
    echo "✗ FAILED"
fi

echo

# Summary
echo "=== Summary ==="
if [ -n "$FAILED_NODES" ]; then
    echo "✗ Failed to ping nodes:$FAILED_NODES"
    exit 1
else
    echo "✓ All nodes are reachable"
fi

echo "✓ Network configuration check completed"
