#!/bin/bash

# Nano Agent Cleanup Script
# This script cleans up the nano k3s agent installation

# Setup colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'
TICK="${GREEN}✅${NC}"
CROSS="${RED}❌${NC}"

echo -e "${GREEN}Nano Agent Cleanup${NC}"
echo "=================================="

# Stop and remove k3s agent
echo -e "\n${GREEN}Removing k3s Agent:${NC}"
if [ -f "/usr/local/bin/k3s-agent-uninstall.sh" ]; then
    sudo /usr/local/bin/k3s-agent-uninstall.sh
    echo -e "  k3s agent uninstalled: $TICK"
else
    echo -e "  k3s agent uninstall script not found: $CROSS"
fi

# Remove kubeconfig
echo -e "\n${GREEN}Removing Configuration:${NC}"
rm -f /home/sanjay/k3s.yaml
rm -rf /home/sanjay/.kube
echo -e "  Removed kubeconfig: $TICK"

# Remove any FastAPI systemd services
echo -e "\n${GREEN}Removing FastAPI Services:${NC}"
for service in $(systemctl list-units --type=service --all --no-legend | grep -i fastapi | awk '{print $1}'); do
    sudo systemctl stop "$service" 2>/dev/null || true
    sudo systemctl disable "$service" 2>/dev/null || true
    sudo rm -f "/etc/systemd/system/$service" 2>/dev/null || true
    echo -e "  Removed service: $service $TICK"
done
sudo systemctl daemon-reload
echo -e "  FastAPI services cleaned: $TICK"

# Remove any k3s-related systemd services
echo -e "\n${GREEN}Removing k3s Services:${NC}"
for service in $(systemctl list-units --type=service --all --no-legend | grep -i k3s | awk '{print $1}'); do
    sudo systemctl stop "$service" 2>/dev/null || true
    sudo systemctl disable "$service" 2>/dev/null || true
    sudo rm -f "/etc/systemd/system/$service" 2>/dev/null || true
    echo -e "  Removed service: $service $TICK"
done
sudo systemctl daemon-reload
echo -e "  k3s services cleaned: $TICK"

# Remove registries configuration
echo -e "\n${GREEN}Removing Registry Configuration:${NC}"
sudo rm -f /etc/rancher/k3s/registries.yaml
echo -e "  Removed registries.yaml: $TICK"

# Clean Docker images
echo -e "\n${GREEN}Cleaning Docker Images:${NC}"
sudo docker image prune -f
echo -e "  Removed dangling images: $TICK"

# Remove FastAPI images
docker rmi fastapi-nano:latest 2>/dev/null || true
docker rmi 192.168.5.1:5000/fastapi-nano:latest 2>/dev/null || true
echo -e "  Removed FastAPI images: $TICK"

# Clean up logs
echo -e "\n${GREEN}Cleaning Logs:${NC}"
# Remove k3s logs
sudo rm -rf /var/log/k3s* 2>/dev/null || true
echo -e "  Removed k3s logs: $TICK"
# Clear systemd journal for k3s and fastapi
sudo journalctl --vacuum-time=1s --grep="k3s" 2>/dev/null || true
sudo journalctl --vacuum-time=1s --grep="fastapi" 2>/dev/null || true
echo -e "  Cleared systemd journal for k3s/fastapi: $TICK"
# Clean Docker logs
sudo truncate -s 0 /var/lib/docker/containers/*/*-json.log 2>/dev/null || true
echo -e "  Truncated Docker container logs: $TICK"

echo -e "\n${GREEN}Cleanup Complete${NC}"