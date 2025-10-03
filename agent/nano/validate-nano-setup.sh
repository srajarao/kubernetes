#!/bin/bash

# Nano Agent Validation Script
# This script validates the nano k3s agent setup

# Setup colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'
TICK="${GREEN}✅${NC}"
CROSS="${RED}❌${NC}"

# Source configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/nano-config.env" ]; then
    source "$SCRIPT_DIR/nano-config.env"
fi

echo -e "${GREEN}Nano Agent Validation${NC}"
echo "=================================="

# Check k3s agent status
echo -e "\n${GREEN}K3s Agent Status:${NC}"
if systemctl is-active --quiet k3s-agent; then
    echo -e "  k3s-agent service: $TICK"
else
    echo -e "  k3s-agent service: $CROSS"
fi

# Check node status in cluster
echo -e "\n${GREEN}Node Status in Cluster:${NC}"
if kubectl get nodes | grep -q "$(hostname)"; then
    NODE_STATUS=$(kubectl get nodes --no-headers | grep "$(hostname)" | awk '{print $2}')
    if [ "$NODE_STATUS" = "Ready" ]; then
        echo -e "  Node $(hostname): Ready $TICK"
    else
        echo -e "  Node $(hostname): $NODE_STATUS $CROSS"
    fi
else
    echo -e "  Node $(hostname): Not found in cluster $CROSS"
fi

# Check pod status
echo -e "\n${GREEN}FastAPI Pod Status:${NC}"
POD_NAME=$(kubectl get pods -l app=fastapi-nano -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -z "$POD_NAME" ]; then
    POD_NAME=$(kubectl get pods -l app=fastapi -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
fi

if [ -n "$POD_NAME" ]; then
    POD_STATUS=$(kubectl get pod "$POD_NAME" -o jsonpath='{.status.phase}' 2>/dev/null)
    if [ "$POD_STATUS" = "Running" ]; then
        echo -e "  FastAPI pod $POD_NAME: Running $TICK"
    else
        echo -e "  FastAPI pod $POD_NAME: $POD_STATUS $CROSS"
    fi
else
    echo -e "  FastAPI pod: Not found $CROSS"
fi

# Check network connectivity
echo -e "\n${GREEN}Network Connectivity:${NC}"
if ping -c 1 "$TOWER_IP" >/dev/null 2>&1; then
    echo -e "  Tower connectivity ($TOWER_IP): $TICK"
else
    echo -e "  Tower connectivity ($TOWER_IP): $CROSS"
fi

# Check registry connectivity
echo -e "\n${GREEN}Registry Connectivity:${NC}"
if curl -s "http://${TOWER_IP}:5000/v2/_catalog" >/dev/null 2>&1; then
    echo -e "  Registry access (${TOWER_IP}:5000): $TICK"
else
    echo -e "  Registry access (${TOWER_IP}:5000): $CROSS"
fi

echo -e "\n${GREEN}Validation Complete${NC}"