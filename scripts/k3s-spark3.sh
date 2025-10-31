#!/bin/bash

# K3s Agent Installation Script for spark3
# This script installs and configures K3s agent on spark3 node

set -e

#!/bin/bash

# K3s Agent Installation Script for spark3
# This script should be run from the tower server and will install K3s agent on spark3 remotely

set -e

# Configuration - modify these as needed
TARGET_NODE="spark3"
TARGET_IP="192.168.1.203"  # Update this if the IP is different
SERVER_IP="192.168.1.150"
SERVER_PORT="6443"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" >&2
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

# Check if running on tower server
if ! hostname | grep -q "tower"; then
    error "This script should be run from the tower server"
    exit 1
fi

log "Starting K3s agent installation on $TARGET_NODE ($TARGET_IP) from tower"

# Check connectivity to target node
log "Checking connectivity to $TARGET_NODE ($TARGET_IP)..."
if ! ping -c 2 -W 2 "$TARGET_IP" >/dev/null 2>&1; then
    error "Cannot reach $TARGET_NODE at $TARGET_IP"
    exit 1
fi

# Test SSH connectivity
if ! ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$TARGET_NODE" "echo 'SSH OK'" >/dev/null 2>&1; then
    error "Cannot SSH to $TARGET_NODE. Please ensure SSH keys are set up."
    exit 1
fi

log "✅ Connectivity to $TARGET_NODE confirmed"

# Update system on target node
log "Updating system packages on $TARGET_NODE..."
ssh -o StrictHostKeyChecking=no "$TARGET_NODE" "sudo apt update && sudo apt upgrade -y"

# Install required packages on target node
log "Installing required packages on $TARGET_NODE..."
ssh -o StrictHostKeyChecking=no "$TARGET_NODE" "sudo apt install -y curl wget htop iotop jq"

# Stop and disable any existing k3s service on target node
log "Stopping any existing K3s services on $TARGET_NODE..."
ssh -o StrictHostKeyChecking=no "$TARGET_NODE" "sudo systemctl stop k3s-agent || true"
ssh -o StrictHostKeyChecking=no "$TARGET_NODE" "sudo systemctl disable k3s-agent || true"

# Remove old k3s data if it exists on target node
log "Cleaning up old K3s data on $TARGET_NODE..."
ssh -o StrictHostKeyChecking=no "$TARGET_NODE" "sudo rm -rf /var/lib/rancher/k3s"
ssh -o StrictHostKeyChecking=no "$TARGET_NODE" "sudo rm -rf /etc/rancher/k3s"

# Get the current server token
log "Retrieving server token..."
TOKEN=$(sudo cat /var/lib/rancher/k3s/server/node-token)
if [ -z "$TOKEN" ]; then
    error "Could not retrieve server token from local server"
    exit 1
fi

# Create k3s configuration directory on target node
ssh -o StrictHostKeyChecking=no "$TARGET_NODE" "sudo mkdir -p /etc/rancher/k3s"

# Save the token on target node
echo "$TOKEN" | ssh -o StrictHostKeyChecking=no "$TARGET_NODE" "sudo tee /etc/rancher/k3s/k3s-agent-token > /dev/null"
ssh -o StrictHostKeyChecking=no "$TARGET_NODE" "sudo chmod 600 /etc/rancher/k3s/k3s-agent-token"

# Install K3s agent
log "Installing K3s agent..."
curl -sfL https://get.k3s.io | \
    K3S_URL=https://$SERVER_IP:$SERVER_PORT \
    K3S_TOKEN=$TOKEN \
    K3S_NODE_NAME=$NODE_NAME \
    K3S_NODE_IP=$NODE_IP \
    sh -s - agent

# Wait for service to start
log "Waiting for K3s agent to start..."
sleep 10

# Check service status
if systemctl is-active --quiet k3s-agent; then
    log "✅ K3s agent installed and running successfully"

    # Verify node registration
    log "Verifying node registration..."
    sleep 5

    # Check if node appears in cluster (will need kubectl access)
    log "Installation complete. Node should appear in cluster shortly."
    log "Run 'kubectl get nodes' on the server to verify."

else
    error "❌ K3s agent failed to start"
    systemctl status k3s-agent --no-pager -l
    exit 1
fi

log "🎉 K3s agent installation completed successfully on $NODE_NAME"