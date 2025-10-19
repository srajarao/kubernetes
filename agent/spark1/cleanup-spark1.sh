#!/bin/bash
# AGX Cleanup Script
# Use this to completely remove k3s agent and reset AGX for fresh setup

source "$(dirname "$0")/agx-config.env"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "\n${YELLOW}AGX k3s Agent Cleanup${NC}"
echo -e "This will completely remove k3s agent from AGX"
echo -e "Node: $NODE_NAME"

read -p "Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cleanup cancelled"
    exit 0
fi

echo -e "\n${GREEN}Stopping k3s agent service${NC}"
sudo systemctl stop k3s-agent 2>/dev/null || true

echo -e "\n${GREEN}Running k3s agent uninstall${NC}"
if [ -f /usr/local/bin/k3s-agent-uninstall.sh ]; then
    sudo /usr/local/bin/k3s-agent-uninstall.sh
else
    echo "No uninstall script found, doing manual cleanup"
fi

echo -e "\n${GREEN}Cleaning up files and directories${NC}"
sudo rm -rf /etc/rancher/k3s
sudo rm -rf /var/lib/rancher/k3s
sudo rm -rf /var/lib/kubelet
sudo rm -rf /run/k3s
sudo rm -rf /run/flannel
sudo rm -rf /var/lib/cni

echo -e "\n${GREEN}Removing binaries${NC}"
sudo rm -f /usr/local/bin/k3s
sudo rm -f /usr/local/bin/k3s-killall.sh
sudo rm -f /usr/local/bin/k3s-agent-uninstall.sh
sudo rm -f /usr/local/bin/crictl
sudo rm -f /usr/local/bin/ctr

echo -e "\n${GREEN}Cleaning network interfaces${NC}"
sudo ip link delete cni0 2>/dev/null || true
sudo ip link delete flannel.1 2>/dev/null || true
sudo ip link delete flannel-v6.1 2>/dev/null || true
sudo ip link delete kube-ipvs0 2>/dev/null || true
sudo ip link delete flannel-wg 2>/dev/null || true
sudo ip link delete flannel-wg-v6 2>/dev/null || true

echo -e "\n${GREEN}Flushing iptables rules${NC}"
sudo iptables -F 2>/dev/null || true
sudo iptables -X 2>/dev/null || true
sudo iptables -t nat -F 2>/dev/null || true
sudo iptables -t nat -X 2>/dev/null || true
sudo iptables -t mangle -F 2>/dev/null || true
sudo iptables -t mangle -X 2>/dev/null || true

echo -e "\n${GREEN}Cleaning systemd${NC}"
sudo systemctl daemon-reload

echo -e "\n${GREEN}Removing kubeconfig${NC}"
rm -f ~/.kube/config

echo -e "\n${GREEN}Cleanup complete!${NC}"
echo -e "AGX is ready for fresh k3s agent installation"
echo -e "Run ./k3s-agx-setup.sh to rejoin the cluster"