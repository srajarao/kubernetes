#!/bin/bash

# =============================================================================
# Remove K3s Agent from Nano Node
# =============================================================================
# This script removes the K3s agent service from the Nano node
# Date: October 28, 2025
# =============================================================================

set -e  # Exit on any error

# Configuration
NANO_IP="192.168.1.181"
SSH_USER="sanjay"
LOG_FILE="/home/sanjay/containers/kubernetes/rmvagent_nano_$(date +%Y%m%d_%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

# SSH command wrapper
ssh_cmd() {
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i /home/sanjay/.ssh/id_ed25519 "$SSH_USER@$NANO_IP" "$*"
}

# Header
echo "==================================================================================" | tee "$LOG_FILE"
echo "🗑️  REMOVE K3S AGENT FROM NANO" | tee -a "$LOG_FILE"
echo "==================================================================================" | tee -a "$LOG_FILE"
echo "Date: $(date)" | tee -a "$LOG_FILE"
echo "Target: Nano ($NANO_IP)" | tee -a "$LOG_FILE"
echo "Log file: $LOG_FILE" | tee -a "$LOG_FILE"
echo "==================================================================================" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 1: Stop K3s Agent Service
# =============================================================================
echo -e "${BLUE}📊 STEP 1: Stop K3s Agent Service${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Stopping k3s-agent service on Nano..."
if ssh_cmd "sudo systemctl stop k3s-agent 2>/dev/null || true"; then
    echo -e "${GREEN}✅ K3s agent service stopped${NC}" | tee -a "$LOG_FILE"
else
    echo -e "${YELLOW}⚠️  Could not stop k3s-agent service (may not be running)${NC}" | tee -a "$LOG_FILE"
fi

# =============================================================================
# STEP 2: Disable K3s Agent Service
# =============================================================================
echo -e "${BLUE}📊 STEP 2: Disable K3s Agent Service${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Disabling k3s-agent service on Nano..."
if ssh_cmd "sudo systemctl disable k3s-agent 2>/dev/null || true"; then
    echo -e "${GREEN}✅ K3s agent service disabled${NC}" | tee -a "$LOG_FILE"
else
    echo -e "${YELLOW}⚠️  Could not disable k3s-agent service${NC}" | tee -a "$LOG_FILE"
fi

# =============================================================================
# STEP 3: Uninstall K3s Agent
# =============================================================================
echo -e "${BLUE}📊 STEP 3: Uninstall K3s Agent${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Running k3s-agent-uninstall.sh on Nano..."
if ssh_cmd "sudo /usr/local/bin/k3s-agent-uninstall.sh 2>/dev/null || true"; then
    echo -e "${GREEN}✅ K3s agent uninstalled${NC}" | tee -a "$LOG_FILE"
else
    echo -e "${YELLOW}⚠️  K3s agent uninstall script not found or failed${NC}" | tee -a "$LOG_FILE"
fi

# =============================================================================
# STEP 4: Clean Up K3s Directories and Files
# =============================================================================
echo -e "${BLUE}📊 STEP 4: Clean Up K3s Files${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Removing k3s directories and configuration files..."
ssh_cmd "sudo rm -rf /etc/rancher/k3s 2>/dev/null || true"
ssh_cmd "sudo rm -rf /var/lib/rancher/k3s 2>/dev/null || true"
ssh_cmd "sudo rm -rf /var/lib/kubelet 2>/dev/null || true"
ssh_cmd "sudo rm -f /usr/local/bin/k3s 2>/dev/null || true"
ssh_cmd "sudo rm -f /usr/local/bin/k3s-agent-uninstall.sh 2>/dev/null || true"
ssh_cmd "sudo rm -f /etc/systemd/system/k3s-agent.service 2>/dev/null || true"
ssh_cmd "sudo rm -rf /etc/systemd/system/k3s-agent.service.d 2>/dev/null || true"
echo -e "${GREEN}✅ K3s files and directories cleaned up${NC}" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 5: Reload Systemd
# =============================================================================
echo -e "${BLUE}📊 STEP 5: Reload Systemd${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Reloading systemd daemon..."
ssh_cmd "sudo systemctl daemon-reload"
echo -e "${GREEN}✅ Systemd reloaded${NC}" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 6: Verify Removal
# =============================================================================
echo -e "${BLUE}📊 STEP 6: Verify Removal${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Checking if k3s processes are still running..."
RUNNING_PROCESSES=$(ssh_cmd "ps aux | grep k3s | grep -v grep || true")
if [ -z "$RUNNING_PROCESSES" ]; then
    echo -e "${GREEN}✅ No k3s processes running${NC}" | tee -a "$LOG_FILE"
else
    echo -e "${YELLOW}⚠️  Some k3s processes may still be running:${NC}" | tee -a "$LOG_FILE"
    echo "$RUNNING_PROCESSES" | tee -a "$LOG_FILE"
fi

log "Checking if k3s directories still exist..."
DIRS_EXIST=$(ssh_cmd "ls -d /etc/rancher/k3s /var/lib/rancher/k3s 2>/dev/null || true")
if [ -z "$DIRS_EXIST" ]; then
    echo -e "${GREEN}✅ K3s directories removed${NC}" | tee -a "$LOG_FILE"
else
    echo -e "${YELLOW}⚠️  Some k3s directories may still exist:${NC}" | tee -a "$LOG_FILE"
    echo "$DIRS_EXIST" | tee -a "$LOG_FILE"
fi

# =============================================================================
# Summary
# =============================================================================
echo "" | tee -a "$LOG_FILE"
echo "==================================================================================" | tee -a "$LOG_FILE"
echo "✅ K3S AGENT REMOVAL COMPLETED" | tee -a "$LOG_FILE"
echo "==================================================================================" | tee -a "$LOG_FILE"
echo "Nano node has been removed from the Kubernetes cluster." | tee -a "$LOG_FILE"
echo "Log file: $LOG_FILE" | tee -a "$LOG_FILE"
echo "==================================================================================" | tee -a "$LOG_FILE"

echo -e "${GREEN}🎉 K3s agent removal from Nano completed successfully!${NC}"