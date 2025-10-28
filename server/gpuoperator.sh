#!/bin/bash

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Change to the script directory to ensure relative paths work correctly
cd "$SCRIPT_DIR" || exit 1

clear

# IP addresses
TOWER_IP="192.168.1.150"

# Debug mode (0 for silent, 1 for verbose)
DEBUG=0

# Helper functions for logging
step_echo_start() {
    local type="$1"
    local node="$2"
    local ip="$3"
    local msg="$4"
    local timestamp=$(date '+%H:%M:%S')
    printf "[%s] {%s} [%-5s] [%s] %s" "$timestamp" "$type" "$node" "$ip" "$msg"
}

print_divider() {
    printf "%0.s-" {1..80}
    echo ""
}

cleanup_gpu_operator(){
# --------------------------------------------------------------------------------
# STEP 1: Clean up previous NVIDIA GPU Operator installation
# --------------------------------------------------------------------------------
    step_echo_start "s" "tower" "$TOWER_IP" "Cleaning up previous GPU Operator installation..."
    
    # Uninstall helm release from gpu-operator namespace if it exists
    if sudo helm status gpu-operator -n gpu-operator --kubeconfig /etc/rancher/k3s/k3s.yaml > /dev/null 2>&1; then
        echo "Uninstalling existing gpu-operator helm release from gpu-operator namespace..."
        sudo helm uninstall gpu-operator -n gpu-operator --kubeconfig /etc/rancher/k3s/k3s.yaml
    fi

    # The error mentioned a release in the default namespace. Let's find and clean that too.
    local failed_releases=$(sudo helm list -n default --failed -q --kubeconfig /etc/rancher/k3s/k3s.yaml | grep 'gpu-operator')
    for release in $failed_releases; do
        echo "Uninstalling failed helm release $release from default namespace..."
        sudo helm uninstall "$release" -n default --kubeconfig /etc/rancher/k3s/k3s.yaml
    done

    # Delete the ClusterRole and ClusterRoleBinding
    if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get clusterrole gpu-operator > /dev/null 2>&1; then
        echo "Deleting gpu-operator clusterrole..."
        sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete clusterrole gpu-operator
    fi
    if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get clusterrolebinding gpu-operator > /dev/null 2>&1; then
        echo "Deleting gpu-operator clusterrolebinding..."
        sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete clusterrolebinding gpu-operator
    fi
    # Delete the ClusterPolicy
    if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get clusterpolicy cluster-policy > /dev/null 2>&1; then
        echo "Deleting cluster-policy..."
        sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete clusterpolicy cluster-policy
    fi

    # Delete the namespace and wait for it to be terminated
    if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get namespace gpu-operator > /dev/null 2>&1; then
        echo "Deleting gpu-operator namespace..."
        sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete namespace gpu-operator
        echo "Waiting for gpu-operator namespace to be terminated..."
        sudo kubectl wait --for=delete namespace/gpu-operator --timeout=120s --kubeconfig /etc/rancher/k3s/k3s.yaml
    fi

    echo -e "✅"
    print_divider
}


install_gpu_operator(){
# --------------------------------------------------------------------------------
# STEP 2: Install NVIDIA GPU Operator
# --------------------------------------------------------------------------------
    step_echo_start "s" "tower" "$TOWER_IP" "Installing NVIDIA GPU Operator via Helm..."
    sleep 5
    # Add the NVIDIA Helm repository
    if sudo helm repo add nvidia https://helm.ngc.nvidia.com/nvidia && sudo helm repo update; then
        echo -e "✅ Helm repo added and updated"
    else
        echo -e "❌ Failed to add NVIDIA Helm repo"
        exit 1
    fi

    # Install the GPU Operator
    # This will taint the node and manage all GPU resources
    if sudo helm install --wait gpu-operator nvidia/gpu-operator \
        --kubeconfig /etc/rancher/k3s/k3s.yaml \
        -n gpu-operator --create-namespace \
        --set driver.enabled=false \
        --set toolkit.enabled=true \
        --set toolkit.env[0].name=CONTAINERD_CONFIG,toolkit.env[0].value=/var/lib/rancher/k3s/agent/etc/containerd/config.toml \
        --set toolkit.env[1].name=CONTAINERD_SOCKET,toolkit.env[1].value=/run/k3s/containerd/containerd.sock \
        --set toolkit.env[2].name=CONTAINERD_RUNTIME_DIR,toolkit.env[2].value=/run/k3s/containerd; then
        echo -e "✅ NVIDIA GPU Operator installed successfully"
    else
        echo -e "❌ Failed to install NVIDIA GPU Operator"
        exit 1
    fi
    print_divider
}

# Main script logic
cleanup_gpu_operator
install_gpu_operator

echo "GPU Operator script finished."
