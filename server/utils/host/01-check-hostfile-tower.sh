#!/bin/bash

# Script: 01-check-hostfile-tower.sh
# Purpose: Review the host file to ensure all required entries are present
# Required entries: agx, nano, spark1, spark2, krithi (192.168.1.100)

echo "=== Host File Review Script ==="
echo "Checking /etc/hosts for required entries..."
echo

# Define required host entries with their IPs
declare -A required_hosts=(
    ["agx"]="192.168.1.244"
    ["nano"]="192.168.1.181"
    ["spark1"]="192.168.1.201"
    ["spark2"]="192.168.1.202"
    ["krithi"]="192.168.1.100"
)

HOSTS_FILE="/etc/hosts"
all_present=true
declare -A missing_hosts

echo "Required host entries:"
echo "----------------------"

for host in "${!required_hosts[@]}"; do
    ip="${required_hosts[$host]}"

    # Check if the IP and hostname combination exists
    if grep -q "^${ip}[[:space:]]*${host}" "$HOSTS_FILE" 2>/dev/null; then
        echo "✅ ${host} (${ip}) - PRESENT"
    else
        echo "❌ ${host} (${ip}) - MISSING"
        all_present=false
        missing_hosts["$host"]="$ip"
    fi
done

echo
echo "=== Adding Missing Entries ==="
echo "------------------------------"

if [ ${#missing_hosts[@]} -gt 0 ]; then
    echo "Adding missing host entries..."
    for host in "${!missing_hosts[@]}"; do
        ip="${missing_hosts[$host]}"
        echo "Adding: ${ip} ${host}"
        sudo sh -c "echo '${ip} ${host}' >> '$HOSTS_FILE'"
        if [ $? -eq 0 ]; then
            echo "✅ Successfully added ${host}"
        else
            echo "❌ Failed to add ${host}"
        fi
    done
    echo
    echo "=== Updated /etc/hosts content ==="
    echo "-----------------------------------"
    cat "$HOSTS_FILE"
else
    echo "No missing entries to add."
fi

echo
echo "=== Current /etc/hosts content ==="
echo "-----------------------------------"
if [ -f "$HOSTS_FILE" ]; then
    cat "$HOSTS_FILE"
else
    echo "❌ Host file not found at $HOSTS_FILE"
    exit 1
fi

echo
echo "=== Summary ==="
echo "---------------"
if [ "$all_present" = true ]; then
    echo "✅ All required host entries are present!"
    exit 0
else
    echo "✅ Missing host entries have been automatically added!"
    exit 0
fi