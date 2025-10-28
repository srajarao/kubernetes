#!/bin/bash
set -e

# Script to update Docker insecure registry configuration on all devices
# Run this from Tower to update AGX and Nano

TOWER_IP="192.168.1.150"
REGISTRY_PORT="5000"

echo "🔧 Updating Docker insecure registry configuration..."
echo "   Registry: $TOWER_IP:$REGISTRY_PORT"

# Function to update Docker daemon.json on a device
update_docker_registry() {
    local device=$1
    local device_name=$2

    echo ""
    echo "📡 Updating $device_name ($device)..."

    # Create a script to run on the remote device
    cat << EOF > /tmp/update_registry_$device.sh
#!/bin/bash
set -e

TOWER_IP="$TOWER_IP"
REGISTRY_PORT="$REGISTRY_PORT"

echo "   🔧 Updating Docker daemon.json on $device_name..."

# Backup current daemon.json if it exists
if [ -f /etc/docker/daemon.json ]; then
    sudo cp /etc/docker/daemon.json /etc/docker/daemon.json.backup.\$(date +%Y%m%d_%H%M%S)
    echo "   📋 Backed up existing daemon.json"
fi

# Update or create daemon.json with insecure registry
if command -v jq &> /dev/null; then
    # Use jq if available
    if [ -f /etc/docker/daemon.json ]; then
        sudo jq 'if .["insecure-registries"] then .["insecure-registries"] += ["'\${TOWER_IP}':'\${REGISTRY_PORT}'"] | .["insecure-registries"] |= unique else . + {"insecure-registries": ["'\${TOWER_IP}':'\${REGISTRY_PORT}'"]} end' /etc/docker/daemon.json | sudo tee /etc/docker/daemon.json.tmp > /dev/null
        sudo mv /etc/docker/daemon.json.tmp /etc/docker/daemon.json
    else
        echo '{"insecure-registries": ["'\${TOWER_IP}':'\${REGISTRY_PORT}'"]}' | sudo tee /etc/docker/daemon.json > /dev/null
    fi
else
    # Fallback without jq
    echo '{"insecure-registries": ["'\${TOWER_IP}':'\${REGISTRY_PORT}'"]}' | sudo tee /etc/docker/daemon.json > /dev/null
fi

echo "   ✅ Updated daemon.json with insecure registry: \${TOWER_IP}:\${REGISTRY_PORT}"

# Restart Docker daemon
echo "   🔄 Restarting Docker daemon..."
sudo systemctl restart docker

echo "   ✅ Docker registry configuration updated on $device_name"
EOF

    chmod +x /tmp/update_registry_$device.sh

    # Copy and run the script on the remote device
    if scp /tmp/update_registry_$device.sh sanjay@$device:~ > /dev/null 2>&1; then
        echo "   ✅ Copied update script to $device"

        if ssh -o StrictHostKeyChecking=no sanjay@$device "bash update_registry_$device.sh" > /dev/null 2>&1; then
            echo "   ✅ Updated Docker registry on $device"
        else
            echo "   ❌ Failed to update Docker registry on $device"
        fi

        # Clean up remote script
        ssh -o StrictHostKeyChecking=no sanjay@$device "rm -f update_registry_$device.sh" > /dev/null 2>&1
    else
        echo "   ❌ Failed to copy script to $device"
    fi

    # Clean up local script
    rm -f /tmp/update_registry_$device.sh
}

# Update AGX
update_docker_registry "agx" "AGX Orin"

# Update Nano
update_docker_registry "nano" "Jetson Nano"

echo ""
echo "🏠 Updating Tower..."
# Update Tower locally
echo "   🔧 Updating Docker daemon.json on Tower..."

# Backup current daemon.json if it exists
if [ -f /etc/docker/daemon.json ]; then
    sudo cp /etc/docker/daemon.json /etc/docker/daemon.json.backup.$(date +%Y%m%d_%H%M%S)
    echo "   📋 Backed up existing daemon.json"
fi

# Update or create daemon.json with insecure registry
if command -v jq &> /dev/null; then
    # Use jq if available
    if [ -f /etc/docker/daemon.json ]; then
        sudo jq 'if .["insecure-registries"] then .["insecure-registries"] += ["'${TOWER_IP}':'${REGISTRY_PORT}'"] | .["insecure-registries"] |= unique else . + {"insecure-registries": ["'${TOWER_IP}':'${REGISTRY_PORT}'"]} end' /etc/docker/daemon.json | sudo tee /etc/docker/daemon.json.tmp > /dev/null
        sudo mv /etc/docker/daemon.json.tmp /etc/docker/daemon.json
    else
        echo '{"insecure-registries": ["'${TOWER_IP}':'${REGISTRY_PORT}'"]}' | sudo tee /etc/docker/daemon.json > /dev/null
    fi
else
    # Fallback without jq
    echo '{"insecure-registries": ["'${TOWER_IP}':'${REGISTRY_PORT}'"]}' | sudo tee /etc/docker/daemon.json > /dev/null
fi

echo "   ✅ Updated daemon.json with insecure registry: ${TOWER_IP}:${REGISTRY_PORT}"

# Restart Docker daemon
echo "   🔄 Restarting Docker daemon..."
sudo systemctl restart docker

echo ""
echo "🎉 Docker insecure registry update complete on all devices!"
echo "   All devices now have the correct registry configuration: ${TOWER_IP}:${REGISTRY_PORT}"