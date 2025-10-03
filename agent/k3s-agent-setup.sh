#!/bin/bash
clear

# Kubernetes Agent Setup Script for Nano/AGX Nodes
# 
# This script sets up k3s agent nodes to join the tower's Kubernetes cluster.
# Run this on nano or AGX devices to join them to the cluster.
#
# Prerequisites:
# 1. Tower must be running k3s server
# 2. Agent tokens must be available in shared storage
# 3. Network connectivity to tower
#
# Usage:
#   ./k3s-agent-setup.sh          # Full agent setup
#   DEBUG=1 ./k3s-agent-setup.sh  # Debug mode with verbose output

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color
TICK="${GREEN}✅${NC}"
CROSS="${RED}❌${NC}"

function print_result() {
    if [ "$1" -eq 0 ]; then
        echo -e "$2 $TICK"
    else
        echo -e "$2 $CROSS"
    fi
}

# Agent configuration
TOWER_SERVER_IP="192.168.5.1"  # Update this to match your tower IP
NODE_NAME=$(hostname)

function check_prerequisites() {
    echo -e "\n${GREEN}Checking Prerequisites${NC}"
    
    # Check network connectivity to tower
    ping -c 1 $TOWER_SERVER_IP >/dev/null 2>&1
    print_result $? "  Network connectivity to tower ($TOWER_SERVER_IP)"
    
    # Check if token files are available
    if [ "$NODE_NAME" = "nano" ]; then
        TOKEN_PATH="/export/vmstore/nano_home/containers/fastapi_nano/.token/node-token"
        KUBECONFIG_PATH="/export/vmstore/nano_home/containers/fastapi_nano/.token/k3s.yaml"
    else
        TOKEN_PATH="/export/vmstore/agx_home/containers/fastapi/.token/node-token"
        KUBECONFIG_PATH="/export/vmstore/agx_home/containers/fastapi/.token/k3s.yaml"
    fi
    
    [ -f "$TOKEN_PATH" ]
    print_result $? "  k3s server token available at $TOKEN_PATH"
    
    [ -f "$KUBECONFIG_PATH" ]
    print_result $? "  kubeconfig available at $KUBECONFIG_PATH"
}

function cleanup_existing_agent() {
    echo -e "\n${GREEN}Cleaning Up Existing k3s Agent${NC}"
    
    # Stop and remove existing k3s agent if present
    if command -v k3s >/dev/null 2>&1; then
        sudo systemctl stop k3s-agent >/dev/null 2>&1
        sudo /usr/local/bin/k3s-agent-uninstall.sh >/dev/null 2>&1
        print_result $? "  Removed existing k3s agent"
    else
        print_result 0 "  No existing k3s agent found"
    fi
    
    # Clean up network interfaces
    sudo ip link delete cni0 2>/dev/null
    sudo ip link delete flannel.1 2>/dev/null
    print_result 0 "  Cleaned up network interfaces"
}

function install_k3s_agent() {
    echo -e "\n${GREEN}Installing k3s Agent${NC}"
    
    # Read the token
    if [ -f "$TOKEN_PATH" ]; then
        TOKEN=$(cat "$TOKEN_PATH")
        print_result $? "  Read k3s server token"
    else
        print_result 1 "  Failed to read k3s server token"
        return 1
    fi
    
    # Install k3s agent
    curl -sfL https://get.k3s.io | K3S_URL="https://$TOWER_SERVER_IP:6443" K3S_TOKEN="$TOKEN" sh - >/dev/null 2>&1
    print_result $? "  Installed k3s agent"
    
    # Wait for agent to start
    sleep 5
    sudo systemctl is-active --quiet k3s-agent
    print_result $? "  k3s agent service running"
}

function setup_kubeconfig() {
    echo -e "\n${GREEN}Setting Up Kubeconfig${NC}"
    
    # Create .kube directory
    mkdir -p ~/.kube
    
    # Copy kubeconfig from shared storage
    if [ -f "$KUBECONFIG_PATH" ]; then
        cp "$KUBECONFIG_PATH" ~/.kube/config
        chmod 600 ~/.kube/config
        print_result $? "  Copied kubeconfig from shared storage"
    else
        print_result 1 "  kubeconfig not found in shared storage"
        return 1
    fi
    
    # Test kubectl connectivity
    kubectl get nodes >/dev/null 2>&1
    print_result $? "  kubectl connectivity to cluster"
}

function load_container_images() {
    echo -e "\n${GREEN}Loading Container Images${NC}"
    
    # Load images from shared registry if available
    REGISTRY_PATH="/export/vmstore/k3sRegistry"
    
    if [ -f "$REGISTRY_PATH/postgres.tar" ]; then
        docker load -i "$REGISTRY_PATH/postgres.tar" >/dev/null 2>&1
        print_result $? "  Loaded postgres image"
    fi
    
    if [ -f "$REGISTRY_PATH/pgadmin.tar" ]; then
        docker load -i "$REGISTRY_PATH/pgadmin.tar" >/dev/null 2>&1
        print_result $? "  Loaded pgadmin image"
    fi
    
    if [ -f "$REGISTRY_PATH/fastapi_nano.tar" ]; then
        docker load -i "$REGISTRY_PATH/fastapi_nano.tar" >/dev/null 2>&1
        print_result $? "  Loaded fastapi_nano image"
    fi
}

function validate_cluster_membership() {
    echo -e "\n${GREEN}Validating Cluster Membership${NC}"
    
    # Check if this node appears in cluster
    kubectl get nodes | grep -q "$NODE_NAME"
    print_result $? "  Node $NODE_NAME joined cluster"
    
    # Check node status
    NODE_STATUS=$(kubectl get node "$NODE_NAME" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)
    if [ "$NODE_STATUS" = "True" ]; then
        print_result 0 "  Node $NODE_NAME is Ready"
    else
        print_result 1 "  Node $NODE_NAME is not Ready (Status: $NODE_STATUS)"
    fi
    
    # List all cluster nodes
    echo -e "\n${GREEN}Cluster Nodes:${NC}"
    kubectl get nodes -o wide
}

function setup_nvidia_support() {
    echo -e "\n${GREEN}Setting Up NVIDIA Support (if applicable)${NC}"
    
    # Check if NVIDIA GPU is present
    if command -v nvidia-smi >/dev/null 2>&1; then
        nvidia-smi >/dev/null 2>&1
        print_result $? "  NVIDIA GPU detected"
        
        # Check if NVIDIA device plugin is running in cluster
        kubectl get pods -n kube-system | grep -q nvidia-device-plugin
        print_result $? "  NVIDIA device plugin available in cluster"
    else
        print_result 0 "  No NVIDIA GPU detected (skipping)"
    fi
}

# Main execution logic
DEBUG="${DEBUG:-0}"

echo -e "\n${GREEN}Starting k3s Agent Setup for $NODE_NAME${NC}"

if [ "$DEBUG" = "1" ]; then
    echo -e "\n${GREEN}Running in DEBUG mode - verbose output enabled${NC}"
fi

# Execute setup steps
check_prerequisites
cleanup_existing_agent
install_k3s_agent
setup_kubeconfig
load_container_images
setup_nvidia_support
validate_cluster_membership

echo -e "\n${GREEN}k3s Agent Setup Complete!${NC}"
echo -e "Node '$NODE_NAME' should now be part of the Kubernetes cluster."
echo -e "Use 'kubectl get nodes' to verify cluster membership."