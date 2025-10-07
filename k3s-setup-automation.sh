#!/bin/bash

clear

# K3s Setup and FastAPI Deployment Automation Script
# Automates the setup of K3s cluster with GPU support for FastAPI on Jetson Nano and AGX.
# Run this script   ssh  if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "export K3S_TOKEN=\"$TOKEN\"; sudo curl -sfL https://get.k3s.io | K3S_URL=https://$TOWER_IP:6443 K3S_TOKEN=\$K3S_TOKEN sh -" > /dev/null 2>&1; the  echo -n "{s} [tower] [192.168.010.001] 15/29. Verifying node status... "-o StrictHostKeyChecking=no sanjay@$NANO_IP "export K3S_TOKEN=\"$TOKEN\"; sudo curl -sfL https://get.k3s.io | K3S_URL=https://$TOWER_IP:6443 K3S_TOKEN=\$K3S_TOKEN sh -"n the server (tower) machine.
# Ensure SSH access to nano and agx is set up (e.g., key-based auth).

# Source configuration
source k3s-config.sh

DEBUG=${DEBUG:-0}

if [ "$DEBUG" = "1" ]; then
  echo "Starting K3s Setup and FastAPI Deployment..."
else
  echo "Starting K3s Setup and FastAPI Deployment in silent mode..."
fi

STEP=$((1 + 3))
if [ "$DEBUG" != "1" ]; then
  set +e
fi

# Function to wait for server readiness
wait_for_server() {
  local timeout=60
  local count=0
  if [ "$DEBUG" = "1" ]; then echo "Waiting for server to be ready..."; fi
  while ! sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes &>/dev/null; do
    if [ $count -ge $timeout ]; then
      echo "Server did not start within $timeout seconds"
      exit 1
    fi
    sleep 1
    count=$((count + 1))
  done
  if [ "$DEBUG" = "1" ]; then echo "Server is ready"; fi
}

# Function to wait for agent readiness
wait_for_agent() {
  local timeout=60
  local count=0
  if [ "$DEBUG" = "1" ]; then echo "Waiting for agent (nano) to be ready..."; fi
  while ! sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes | grep -q "nano.*Ready"; do
    if [ $count -ge $timeout ]; then
      echo "Agent did not join within $timeout seconds"
      exit 1
    fi
    sleep 1
    count=$((count + 1))
  done
  if [ "$DEBUG" = "1" ]; then echo "Agent is ready"; fi
}

# Function to wait for GPU capacity
wait_for_gpu_capacity() {
  local timeout=120
  local count=0
  if [ "$DEBUG" = "1" ]; then echo "Waiting for GPU..."; fi
  while ! sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get node nano -o jsonpath='{.status.capacity.nvidia\.com/gpu}' | grep -q '1'; do
    if [ $count -ge $timeout ]; then
      echo "GPU capacity not added within $timeout seconds"
      exit 1
    fi
    sleep 5
    count=$((count + 5))
  done
    if [ "$DEBUG" = "1" ]; then echo "GPU capacity added"; fi
}

# Uninstall Server
wait_for_gpu_capacity() {
  local timeout=120
  local count=0
  echo -e "\033[32m================================================================================\033[0m"
  echo "Waiting for GPU..."
  while ! sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get node nano -o jsonpath='{.status.capacity.nvidia\.com/gpu}' | grep -q '1'; do
    if [ $count -ge $timeout ]; then
      echo "GPU capacity not added within $timeout seconds"
      exit 1
    fi
    sleep 5
    count=$((count + 5))
  done
  echo "GPU ready"
  echo -e "\033[32m================================================================================\033[0m"
}

# Network Setup Steps
echo -n "{s} [tower] [192.168.010.001] 01/29. Setting up Tower network configuration..."
if [ "$DEBUG" = "1" ]; then
  bash /home/sanjay/containers/kubernetes/bridgenfs/1-setup_tower_network.sh
else
  if bash /home/sanjay/containers/kubernetes/bridgenfs/1-setup_tower_network.sh > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi

# Wait for network configuration to take effect
echo "Waiting for network interfaces to come up and IPs to be assigned..."
sleep 5
# Verify interfaces have the correct IPs
echo "Verifying Tower network configuration..."
if ip addr show enp1s0f0 | grep -q "192.168.10.1"; then
  echo "  ✅ enp1s0f0 has IP 192.168.10.1"
else
  echo "  ❌ enp1s0f0 missing IP 192.168.10.1"
fi
if ip addr show eno2 | grep -q "192.168.5.1"; then
  echo "  ✅ eno2 has IP 192.168.5.1"
else
  echo "  ❌ eno2 missing IP 192.168.5.1"
fi
sleep 10

STEP=$((2 + 3))
# Start iperf3 server on Tower for network testing
echo -n "{s} [tower] [192.168.010.001] 02/29. Starting iperf3 server for network testing... "
iperf3 -s -B 192.168.10.1 -D
if [ $? -eq 0 ]; then
  echo -e "\033[32m✅\033[0m"
else
  echo -e "\033[31m❌\033[0m"
fi

if [ "$INSTALL_AGX_AGENT" = true ]; then
  echo -n "{a} [agx] [192.168.010.011] 03/29. Setting up AGX network configuration..."
  if ping -c 1 -W 1 $AGX_IP > /dev/null 2>&1; then
    if [ "$DEBUG" = "1" ]; then
      scp /home/sanjay/containers/kubernetes/bridgenfs/2-setup_agx_network.sh sanjay@$AGX_IP:~
      ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "bash 2-setup_agx_network.sh"
      echo -e "\033[32m✅\033[0m"
    else
      if scp /home/sanjay/containers/kubernetes/bridgenfs/2-setup_agx_network.sh sanjay@$AGX_IP:~ > /dev/null 2>&1 && ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "bash 2-setup_agx_network.sh" > /dev/null 2>&1; then
        echo -e "\033[32m✅\033[0m"
      else
        echo -e "\033[31m❌\033[0m"
        exit 1
      fi
    fi
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
else
  echo "{a} [agx] [192.168.010.011] 03/29. AGX network setup skipped (not enabled)"
fi


STEP=$((4 + 3))
if [ "$INSTALL_NANO_AGENT" = true ]; then
  echo -n "{a} [nano ] [192.168.005.021] 04/29. Setting up Nano network configuration..."
  if ping -c 1 -W 1 $NANO_IP > /dev/null 2>&1; then
    if [ "$DEBUG" = "1" ]; then
      scp /home/sanjay/containers/kubernetes/bridgenfs/3-setup_nano_network.sh sanjay@$NANO_IP:~
      ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "bash 3-setup_nano_network.sh"
      echo -e "\033[32m✅\033[0m"
    else
      if scp /home/sanjay/containers/kubernetes/bridgenfs/3-setup_nano_network.sh sanjay@$NANO_IP:~ > /dev/null 2>&1 && ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "bash 3-setup_nano_network.sh" > /dev/null 2>&1; then
        echo -e "\033[32m✅\033[0m"
      else
        echo -e "\033[31m❌\033[0m"
        exit 1
      fi
    fi
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
else
  echo "{a} [nano ] [192.168.005.021] 04/29. Nano network setup skipped (not enabled)"
fi
STEP=$((4 + 3))

# Uninstall Server
if [ "$DEBUG" = "1" ]; then
  echo "Uninstalling Server..."
  sleep 5
  sudo /usr/local/bin/k3s-uninstall.sh
else
  echo -n "{s} [tower] [192.168.010.001] 04/29. Uninstalling K3s server... "
  sleep 5
  if sudo /usr/local/bin/k3s-uninstall.sh > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
  echo -en " ✅\033[0m\n"  # Print checkmark anyway, as uninstall may not exist
  fi
fi
STEP=$((5 + 3))

# Install Server
echo "{s} [tower] [192.168.010.001] 05/29. Installing K3s server... "
echo -e "\033[32m$(printf '%.0s=' {1..80})\033[0m"
sleep 5
sudo curl -sfL https://get.k3s.io | sh -s - server
echo -e "\033[32m$(printf '%.0s=' {1..80})\033[0m"
echo -n "{s} [tower] [192.168.010.001] 05/29. Installing K3s server... "
echo -e "\033[32m✅\033[0m"
STEP=$((6 + 3))

# Get Token
if [ "$DEBUG" = "1" ]; then echo "Getting Token..."; fi
sleep 5
TOKEN=$(sudo cat /var/lib/rancher/k3s/server/node-token)
if [ "$DEBUG" = "1" ]; then echo "Token: $TOKEN"; fi
sleep 5

# Uninstall Agent (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Uninstalling Agent..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo /usr/local/bin/k3s-agent-uninstall.sh"
else
  echo -n "{a} [nano ] [192.168.005.021] 06/29. Uninstalling K3s agent on nano... "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[32m✅\033[0m"  # Print checkmark anyway, as uninstall may not exist
  fi
fi
STEP=$((4 + 3))

# Reinstall Agent (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Reinstalling Agent..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "export K3S_TOKEN=\"$TOKEN\"; sudo curl -sfL https://get.k3s.io | K3S_URL=https://192.168.5.1:6443 K3S_TOKEN=\$K3S_TOKEN sh -"
  wait_for_agent
else
  echo -n "{a} [nano ] [192.168.005.021] 07/29. Reinstalling K3s agent on nano... "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "export K3S_TOKEN=\"$TOKEN\"; sudo curl -sfL https://get.k3s.io | K3S_URL=https://192.168.5.1:6443 K3S_TOKEN=\$K3S_TOKEN sh -" > /dev/null 2>&1; then
    wait_for_agent
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
STEP=$((5 + 3))

if [ "$INSTALL_AGX_AGENT" = true ]; then

# Uninstall Agent on agx (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Uninstalling Agent on agx..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh"
else
  echo -n "{a} [agx] [192.168.010.011] 05/29. Uninstalling K3s agent on agx... "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
  echo -en " ✅\033[0m\n"  # Print checkmark anyway
  fi
fi
STEP=$((6 + 3))

# Reinstall Agent on agx (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Reinstalling Agent on agx..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "export K3S_TOKEN=\"$TOKEN\"; sudo curl -sfL https://get.k3s.io | K3S_URL=https://$TOWER_IP:6443 K3S_TOKEN=\$K3S_TOKEN sh -"
  wait_for_agent
else
  echo -n "{a} [agx] [192.168.010.011] 06/29. Reinstalling K3s agent on agx... "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "export K3S_TOKEN=\"$TOKEN\"; sudo curl -sfL https://get.k3s.io | K3S_URL=https://$TOWER_IP:6443 K3S_TOKEN=\$K3S_TOKEN sh -" > /dev/null 2>&1; then
    wait_for_agent
  echo -en " ✅\033[0m\n"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi

# Configure Registry for AGX (via SSH)
if [ "$INSTALL_AGX_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Configuring Registry for AGX..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo mkdir -p /etc/rancher/k3s/"
    ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "echo 'configs: \"$REGISTRY_IP:$REGISTRY_PORT\": insecure_skip_verify: true' | sudo tee /etc/rancher/k3s/registries.yaml > /dev/null"
    ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
configs:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    insecure_skip_verify: true
    http: true
EOF"
    ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT"
    ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"http://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
EOF"
  else
    echo -n "{a} [agx] [192.168.010.011] 07/29. Configuring registry for agx... "
    sleep 5
    if ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo mkdir -p /etc/rancher/k3s/" > /dev/null 2>&1 && ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "echo 'configs: \"$REGISTRY_IP:$REGISTRY_PORT\": insecure_skip_verify: true' | sudo tee /etc/rancher/k3s/registries.yaml > /dev/null" > /dev/null 2>&1 && ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
configs:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    insecure_skip_verify: true
    http: true
EOF" > /dev/null 2>&1 && ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT" > /dev/null 2>&1 && ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"http://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
EOF" > /dev/null 2>&1; then
      echo -e "\033[32m✅\033[0m"
    else
      echo -e "\033[31m❌\033[0m"
      exit 1
    fi
  fi
fi

STEP=$((8 + 3))

# Add Registry Config Dir (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Adding Registry Config Dir..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo mkdir -p /etc/rancher/k3s/"
else
  echo -n "{s} [tower] [192.168.010.001] 07/29. Creating registry configuration directory... "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo mkdir -p /etc/rancher/k3s/" > /dev/null 2>&1; then
  echo -en " ✅\033[0m\n"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
STEP=$((9 + 3))

# Add Insecure Registry (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Adding Insecure Registry..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "echo 'configs: \"$REGISTRY_IP:$REGISTRY_PORT\": insecure_skip_verify: true' | sudo tee /etc/rancher/k3s/registries.yaml > /dev/null"
else
  echo -n "{s} [tower] [192.168.010.001] 08/29. Adding insecure registry configuration... "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "echo 'configs: \"$REGISTRY_IP:$REGISTRY_PORT\": insecure_skip_verify: true' | sudo tee /etc/rancher/k3s/registries.yaml > /dev/null" > /dev/null 2>&1; then
  echo -en " ✅\033[0m\n"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
STEP=$((10 + 3))

# Fix Registry YAML Syntax (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Fixing Registry YAML Syntax..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
configs:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    insecure_skip_verify: true
    http: true
EOF"
else
  echo -n "{s} [tower] [192.168.010.001] 09/29. Fixing registry YAML syntax... "
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
configs:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    insecure_skip_verify: true
    http: true
EOF" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
  echo -en " ✅\033[0m\n"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
STEP=$((11 + 3))

# Configure Containerd for Registry (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Configuring Containerd for Registry..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT"
  ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"http://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
EOF"
else
  echo -n "{s} [tower] [192.168.010.001] 10/29. Configuring containerd for registry... "
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT" > /dev/null 2>&1 && ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"http://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
EOF" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
  echo -en " ✅\033[0m\n"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
STEP=$((12 + 3))

# Restart Agent After Registry Config (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Restarting Agent After Registry Config..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo systemctl restart k3s-agent"
  wait_for_agent
else
  echo -n "{a} [nano ] [192.168.005.021] 11/29. Restarting K3s agent after registry config... "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo systemctl restart k3s-agent" > /dev/null 2>&1; then
    wait_for_agent
  echo -en " ✅\033[0m\n"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
STEP=$((13 + 3))

# Restart Server
if [ "$DEBUG" = "1" ]; then
  echo "Restarting Server..."
  sleep 5
  sudo systemctl restart k3s
  wait_for_server
else
  echo -n "{s} [tower] [192.168.010.001] 12/29. Restarting K3s server... "
  sleep 5
  if sudo systemctl restart k3s > /dev/null 2>&1; then
    wait_for_server
  echo -en " ✅\033[0m\n"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
STEP=$((14 + 3))
# Apply Taint
if [ "$DEBUG" = "1" ]; then
  echo "Applying Taint..."
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml taint node nano CriticalAddonsOnly=true:NoExecute --overwrite
else
  echo -n "{s} [tower] [192.168.010.001] 13/29. Applying taint to server node... "
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml taint node nano CriticalAddonsOnly=true:NoExecute --overwrite > /dev/null 2>&1; then
  echo -en " ✅\033[0m\n"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi

STEP=$((15 + 3))

# Verify Node Status
if [ "$DEBUG" = "1" ]; then
  echo "{s} [tower] [192.168.010.001] 14/29. Verifying Node Status..."
  sleep 5
  echo -e "\033[32m================================================================================\033[0m"
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes
  echo -e "\033[32m================================================================================\033[0m"
else
  echo -n "{s} [tower] [192.168.010.001] 12/26. Verifying node status... "
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes > /dev/null 2>&1; then
  echo -en " ✅\033[0m\n"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
STEP=$((14 + 3))

# Install NVIDIA RuntimeClass
if [ "$DEBUG" = "1" ]; then
  echo "Installing NVIDIA RuntimeClass..."
  sleep 5
  echo 'apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: nvidia
handler: nvidia
' | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f -
else
  echo -n "{s} [tower] [192.168.010.001] 15/29. Installing NVIDIA runtime class... "
  sleep 5
  echo 'apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: nvidia
handler: nvidia
' | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f - > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
STEP=$((15 + 3))

# Install NVIDIA Device Plugin
if [ "$DEBUG" = "1" ]; then
  echo "Installing NVIDIA Device Plugin..."
  echo ""
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f nvidia-ds-updated.yaml
  wait_for_gpu_capacity
else
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f nvidia-ds-updated.yaml > /dev/null 2>&1; then
    wait_for_gpu_capacity
    echo -n "{s} [tower] [192.168.010.001] 16/29. Installing NVIDIA device plugin... "
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
STEP=$((16 + 3))

# Configure NVIDIA Runtime on Agent (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Configuring NVIDIA Runtime on Agent..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo systemctl stop k3s-agent"
  # Assuming the config is already there from previous setups
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo systemctl start k3s-agent"
  wait_for_agent
else
  echo -n "  echo "{a} [nano ] [192.168.005.021] 19/29. Building Docker image on agent..." "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo systemctl stop k3s-agent" > /dev/null 2>&1 && ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo systemctl start k3s-agent" > /dev/null 2>&1; then
    wait_for_agent
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
STEP=$((17 + 3))

# Copy Files for Build
if [ "$DEBUG" = "1" ]; then
  echo "Copying Files for Build..."
  sleep 5
  scp /home/sanjay/containers/kubernetes/agent/nano/dockerfile.nano.req sanjay@$NANO_IP:~
  scp /home/sanjay/containers/kubernetes/agent/nano/requirements.nano.txt sanjay@$NANO_IP:~
  scp -r /home/sanjay/containers/kubernetes/agent/nano/app sanjay@$NANO_IP:~
else
  echo -n "{a} [nano ] [192.168.005.021] 18/29. Copying files for Docker build... "
  sleep 5
  if scp /home/sanjay/containers/kubernetes/agent/nano/dockerfile.nano.req sanjay@$NANO_IP:~ > /dev/null 2>&1 && scp /home/sanjay/containers/kubernetes/agent/nano/requirements.nano.txt sanjay@$NANO_IP:~ > /dev/null 2>&1 && scp -r /home/sanjay/containers/kubernetes/agent/nano/app sanjay@$NANO_IP:~ > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
STEP=$((18 + 3))

# Build Image (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Building Image..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo docker build -t fastapi_nano:latest -f dockerfile.nano.req ."
else
  echo -n "{a} [nano ] [192.168.005.021] 19/29. Building Docker image... "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo docker build -t fastapi_nano:latest -f dockerfile.nano.req ." > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
STEP=$((19 + 3))

# Tag Image (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Tagging Image..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo docker tag fastapi_nano:latest $REGISTRY_IP:$REGISTRY_PORT/fastapi_nano:latest"
else
  echo -n "{a} [nano ] [192.168.005.021] 20/29. Tagging Docker image... "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo docker tag fastapi_nano:latest $REGISTRY_IP:$REGISTRY_PORT/fastapi_nano:latest" > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
STEP=$((20 + 3))

# Push Image (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Pushing Image..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo docker push $REGISTRY_IP:$REGISTRY_PORT/fastapi_nano:latest"
else
  echo -n "{a} [nano ] [192.168.005.021] 21/29. Pushing Docker image to registry... "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo docker push $REGISTRY_IP:$REGISTRY_PORT/fastapi_nano:latest" > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
STEP=$((20 + 3))

# Create Deployment YAML
echo "{s} [tower] [192.168.010.001] 22/29. Creating Deployment YAML..."
sleep 5
rm -f fastapi-deployment-full.yaml
cat <<DEPLOYMENT > fastapi-deployment-full.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastapi-nano
  namespace: default
  labels:
    app: fastapi-nano
    device: nano
    tier: agent
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: fastapi-nano
  template:
    metadata:
      labels:
        app: fastapi-nano
        device: nano
        tier: agent
    spec:
      runtimeClassName: nvidia
      nodeSelector:
        kubernetes.io/hostname: nano
      containers:
      - name: fastapi-nano
        image: $REGISTRY_IP:$REGISTRY_PORT/fastapi_nano:latest
        ports:
        - containerPort: 8000
          name: http
        - containerPort: 8888
          name: jupyter
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
            nvidia.com/gpu: 1
          limits:
            memory: "2Gi"
            cpu: "1000m"
            nvidia.com/gpu: 1
        env:
        - name: DEVICE_TYPE
          value: "nano"
        - name: GPU_ENABLED
          value: "true"
        - name: FORCE_GPU_CHECKS
          value: "true"
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        volumeMounts:
        - name: vmstore
          mountPath: /mnt/vmstore
        - name: nano-home
          mountPath: /home/nano
        - name: nano-config
          mountPath: /app/app/config
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: vmstore
        nfs:
          server: $TOWER_IP
          path: /export/vmstore
      - name: nano-home
        nfs:
          server: $TOWER_IP
          path: /export/vmstore/nano_home
      - name: nano-config
        nfs:
          server: $TOWER_IP
          path: /export/vmstore/tower_home/kubernetes/agent/nano/app/config
      tolerations:
      - key: "node-role.kubernetes.io/agent"
        operator: "Exists"
        effect: "NoSchedule"
      - key: "CriticalAddonsOnly"
        operator: "Equal"
        value: "true"
        effect: "NoExecute"
---
apiVersion: v1
kind: Service
metadata:
  name: fastapi-nano-service
  namespace: default
  labels:
    app: fastapi-nano
    device: nano
spec:
  selector:
    app: fastapi-nano
  ports:
  - port: 8000
    targetPort: 8000
    protocol: TCP
    name: http
  - port: 8888
    targetPort: 8888
    protocol: TCP
    name: jupyter
  type: ClusterIP
---
apiVersion: v1
kind: Service
metadata:
  name: fastapi-nano-nodeport
  namespace: default
  labels:
    app: fastapi-nano
    device: nano
spec:
  selector:
    app: fastapi-nano
  ports:
  - port: 8000
    targetPort: 8000
    nodePort: 30002
    protocol: TCP
    name: http
  - port: 8888
    targetPort: 8888
    nodePort: 30003
    protocol: TCP
    name: jupyter
  type: NodePort
DEPLOYMENT
STEP=$((21 + 3))

# Deploy Application
if [ "$DEBUG" = "1" ]; then
  echo "Deploying Application..."
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f fastapi-deployment-full.yaml
else
  echo -n "{s} [tower] [192.168.010.001] 22/29. Deploying FastAPI application... "
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f fastapi-deployment-full.yaml > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
STEP=$((23 + 3))

# Monitor Pod Status
if [ "$DEBUG" = "1" ]; then
  echo "Monitoring Pod Status..."
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide
else
  echo -n "{s} [tower] [192.168.010.001] 22/26. Monitoring pod status... "
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
STEP=$((23 + 3))

# Force Restart if Stuck (optional, commented out)
# echo "Force Restart if Stuck..."
# sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete pod <pod-name> --force --grace-period=0
# sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml rollout restart deployment fastapi-nano

# Review and Validate Implementation
if [ "$DEBUG" = "1" ]; then
  echo "Reviewing and Validating Implementation..."
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml describe node nano | grep -A 5 Capacity
  curl http://$NANO_IP:30002/health
else
  STEP=$((24 + 3))
  echo -n "{s} [tower] [192.168.010.001] 24/29. Reviewing and validating implementation... "
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi

# Deploy PgAdmin
if [ "$DEBUG" = "1" ]; then
  echo "Deploying PgAdmin..."
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /home/sanjay/containers/kubernetes/server/pgadmin/pgadmin-secret.yaml
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /home/sanjay/containers/kubernetes/server/pgadmin/pgadmin-deployment.yaml
else
  STEP=$((26 + 3))
  echo -n "{s} [tower] [192.168.010.001] 26/29. Deploying PgAdmin secret... "
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /home/sanjay/containers/kubernetes/server/pgadmin/pgadmin-secret.yaml > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
  STEP=$((27 + 3))
  echo -n "{s} [tower] [192.168.010.001] 27/29. Deploying PgAdmin... "
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /home/sanjay/containers/kubernetes/server/pgadmin/pgadmin-deployment.yaml > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi

STEP=$((27 + 3))

# Apply NodePort services
if [ "$DEBUG" = "1" ]; then
  echo "Applying NodePort services..."
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /home/sanjay/containers/kubernetes/server/postgres-pgadmin-nodeport-services.yaml
else
  STEP=$((28 + 3))
  echo -n "{s} [tower] [192.168.010.001] 28/29. Applying NodePort services... "
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /home/sanjay/containers/kubernetes/server/postgres-pgadmin-nodeport-services.yaml > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi

# Final validation
if [ "$DEBUG" = "1" ]; then
  echo "Reviewing and Validating Implementation..."
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml describe node nano | grep -A 5 Capacity
  curl http://$NANO_IP:30002/health
  curl http://$TOWER_IP:30080
POD_NAME=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -l app=fastapi-nano -o jsonpath='{.items[0].metadata.name}')
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml exec $POD_NAME -- nvidia-smi 2>/dev/null






