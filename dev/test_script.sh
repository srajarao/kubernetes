#!/bin/bash

clear

# K3s Setup and FastAPI Deployment Automation Script
# Automates the setup of K3s cluster with GPU support for FastAPI on Jetson Nano and AGX.
# Run this script   ssh  if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "export K3S_TOKEN=\"$TOKEN\"; sudo curl -sfL https://get.k3s.io | K3S_URL=https://$TOWER_IP:6443 K3S_TOKEN=\$K3S_TOKEN sh -" > /dev/null 2>&1; the  echo -n "{s} [tower] [$TOWER_IP] 15/25. Verifying node status... "-o StrictHostKeyChecking=no sanjay@$NANO_IP "export K3S_TOKEN=\"$TOKEN\"; sudo curl -sfL https://get.k3s.io | K3S_URL=https://$TOWER_IP:6443 K3S_TOKEN=\$K3S_TOKEN sh -"n the server (tower) machine.
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
echo 'Test passed'
