#!/bin/bash

# Script: 04-check-hostfile-agx.sh
# Purpose: Check and update host file on agx node remotely
# This script can be run from any machine but executes on agx via SSH

# Configuration
AGX_HOST="agx"
SSH_USER="sanjay"

echo "=== Host File Check for AGX (Remote Execution) ==="
echo "Connecting to agx and checking /etc/hosts..."
echo

# Remote script to execute on agx
REMOTE_SCRIPT=$(cat << 'EOF'
#!/bin/bash

# Define required host entries with their IPs
declare -A required_hosts=(
    ["tower"]="192.168.1.150"
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
        echo "${ip} ${host}" | sudo tee -a "$HOSTS_FILE" > /dev/null
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
EOF
)

# Execute the script on agx via SSH
echo "Executing host file check on agx..."
ssh -o ConnectTimeout=10 "$SSH_USER@$AGX_HOST" "bash -s" << EOF
$REMOTE_SCRIPT
EOF

# Check the exit status
if [ $? -eq 0 ]; then
    echo
    echo "✅ Host file check completed successfully on agx"
else
    echo
    echo "❌ Host file check failed on agx"
    exit 1
fi