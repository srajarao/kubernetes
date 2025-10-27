#!/bin/bash

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Change to the script directory to ensure relative paths work correctly
cd "$SCRIPT_DIR" || exit 1

clear
# k3s-config.sh

# K3s Installation Configuration
# Set to true to install the respective components

# Install K3s server on tower
INSTALL_SERVER=true # Set to true to allow server uninstall/install steps to run

# Install K3s agent on nano
INSTALL_NANO_AGENT=false

# Install K3s agent on agx
INSTALL_AGX_AGENT=false

# Install K3s agent on spark1
INSTALL_SPARK1_AGENT=false

# Install K3s agent on spark2
INSTALL_SPARK2_AGENT=false

# IP addresses
TOWER_IP="10.1.10.150"
NANO_IP="10.1.10.181"   # <-- Use the correct, reachable IP
AGX_IP="10.1.10.244"
SPARK1_IP="10.1.10.201"
SPARK2_IP="10.1.10.202"

# Registry settings
REGISTRY_IP="10.1.10.150"
REGISTRY_PORT="30500"
REGISTRY_PROTOCOL="http"  # "http" or "https"

# Database Configuration
POSTGRES_PASSWORD="postgres"  # PostgreSQL admin password
PGADMIN_PASSWORD="pgadmin"          # pgAdmin default password
PGADMIN_EMAIL="pgadmin@pgadmin.org" # pgAdmin default email

# Debug mode (0 for silent, 1 for verbose)
DEBUG=0

# Function to check if cluster is running
cluster_running() {
  kubectl cluster-info > /dev/null 2>&1
}


DEBUG=${DEBUG:-0}

# Define the initial script message to be logged
START_MESSAGE="Starting K3s Setup and FastAPI Deployment in SILENT NORMAL mode..."

if [ "$DEBUG" = "1" ]; then
    echo "Starting K3s Setup and FastAPI Deployment in **VERBOSE DEBUG** mode..."
else
    echo "Starting K3s Setup and FastAPI Deployment in **SILENT NORMAL** mode..."
fi

# Initialize Dynamic Step Counter
CURRENT_STEP=1

# NOTE: Total steps count is 36 (includes nano and AGX GPU enablement)
TOTAL_STEPS=39

# When not in DEBUG mode, disable 'set -e' globally to rely exclusively on explicit error checks
# to ensure the verbose/silent block structure works without immediate exit.
if [ "$DEBUG" != "1" ]; then
    set +e
fi

# Function to display step with timestamp and increment counter with fixed-width formatting
step_echo_start() {
    local type="$1"
    local node="$2"
    local ip="$3"
    local msg="$4"

    # Define fixed lengths for alignment
    local NODE_LENGTH=5  # e.g., "tower", "nano ", "agx  "

  # --- Dynamic Divider Length Calculation ---
  # Use grep and wc -L to find the length of the longest separator line
  # (e.g., # ================================= or # ------------------------------)
  # The output is used to ensure the print_divider function always matches the widest header.
  DIVIDER_LENGTH=$(grep -E '^# [=]{3,}|^# [-]{3,}' "$0" 2>/dev/null | wc -L)

  # FALLBACK: If the calculation fails (e.g., the script is run for the first time
  # and doesn't have the long separator lines yet), use a safe default of 75.
  if [ -z "$DIVIDER_LENGTH" ] || [ "$DIVIDER_LENGTH" -lt 1 ]; then
    DIVIDER_LENGTH=75
  fi

    # Add timestamp to each step
    local timestamp=$(date '+%H:%M:%S')

    # Use printf for fixed-width formatting with timestamp
    printf "[%s] {%s} [" "$timestamp" "$type"
    printf "%-${NODE_LENGTH}s" "$node"
    printf "] ["
    printf "%s" "$ip"
    printf "] %d/%d. %s" "$CURRENT_STEP" "$TOTAL_STEPS" "$msg"
}

# Function to print a separator line
print_divider() {
    # Generate a string of hyphens of the defined length
    # Note: We subtract 2 from the length here because the output includes '# ' (2 characters).
    HYPHENS=$(printf "%*s" $((DIVIDER_LENGTH - 2)) "" | tr ' ' '-')
    echo "# $HYPHENS"
    
}

# Function to increment step counter
step_increment() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
}

# --- NEW VARIABLE ---
# Define the log file name for the final verification output
FINAL_LOG_FILE="final_verification_output_$(date +%Y%m%d_%H%M%S).log"

# Function to run verification commands and log the output
# Note: The $2 parameter captures the script start message (e.g., "Starting K3s Setup...")
capture_final_log() {
    local log_file="$1"
    local start_msg="$2"

    echo "==================================================================================" >> "$log_file"
    echo "K3S FINAL DEPLOYMENT VERIFICATION LOG" >> "$log_file"
    echo "Timestamp: $(date)" >> "$log_file"
    echo "==================================================================================" >> "$log_file"
    
    # --- 0. SCRIPT EXECUTION START MESSAGE ---
    echo -e "
--- 0. SCRIPT EXECUTION START MESSAGE ---" >> "$log_file"
    echo "$start_msg" >> "$log_file"
    
    # --- 1. NODE STATUS ---
    echo -e "
--- 1. NODE STATUS (kubectl get nodes) ---" >> "$log_file"
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes >> "$log_file"

    # --- 2. APPLICATION PODS STATUS (FASTAPI) ---
    echo -e "
--- 2. APPLICATION PODS STATUS (kubectl get pods) ---" >> "$log_file"
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide >> "$log_file"

    # --- 3. NVIDIA DEVICE PLUGIN STATUS (KUBE-SYSTEM) ---
    echo -e "
--- 3. NVIDIA DEVICE PLUGIN STATUS (kube-system) ---" >> "$log_file"
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -n kube-system | grep nvidia-device-plugin >> "$log_file"
    
    # --- 4. FULL DEPLOYMENT DETAILS ---
    echo -e "
--- 4. FULL DEPLOYMENT DETAILS (kubectl get all) ---" >> "$log_file"
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get all >> "$log_file"

   # --- 5. CRITICAL: NANO K3S AGENT LOG ERRORS (Container Runtime Check) ---
    echo -e "
--- 5. CRITICAL: NANO K3S AGENT LOG ERRORS (Container Runtime Check) ---" >> "$log_file"
    # CORRECTED LINE 1: Change nsanjay to sanjay
    echo "Executing: ssh -i ~/.ssh/id_ed25519 sanjay@$NANO_IP 'sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E \"fastapi-nano|Error|Fail\"'" >> "$log_file"
    # CORRECTED LINE 2: Change nsanjay to sanjay
    ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E 'fastapi-nano|Error|Fail'" >> "$log_file" 2>/dev/null


    # --- 6. CRITICAL: AGX K3S AGENT LOG ERRORS (Automated SSH Check) ---
    echo -e "
--- 6. CRITICAL: AGX K3S AGENT LOG ERRORS (Container Runtime Check) ---" >> "$log_file"
    echo "Executing: ssh -i ~/.ssh/id_ed25519 sanjay@$AGX_IP 'sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E \"fastapi-agx|Error|Fail\"'" >> "$log_file"
    # Execute SSH command and pipe output directly to the log file
    ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E 'fastapi-agx|Error|Fail'" >> "$log_file" 2>/dev/null

    # --- 7. CRITICAL: SPARK1 K3S AGENT LOG ERRORS (Container Runtime Check) ---
    echo -e "
--- 7. CRITICAL: SPARK1 K3S AGENT LOG ERRORS (Container Runtime Check) ---" >> "$log_file"
    echo "Executing: ssh -i ~/.ssh/id_ed25519 sanjay@$SPARK1_IP 'sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E \"fastapi-spark1|Error|Fail\"'" >> "$log_file"
    # Execute SSH command and pipe output directly to the log file
    ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_ed25519 sanjay@$SPARK1_IP "sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E 'fastapi-spark1|Error|Fail'" >> "$log_file" 2>/dev/null

    echo -e "
--- LOG CAPTURE COMPLETE ---" >> "$log_file"
}



# Function to wait for server readiness (runs silently in normal mode)
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

# Function to wait for agent readiness (checks for 'nano' specifically)
wait_for_agent() {
  local timeout=30  # Reduced from 60 to 30 seconds
  local count=0
  if [ "$DEBUG" = "1" ]; then echo "Waiting for agent to be ready..."; fi
  while ! sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes 2>/dev/null | grep -q "Ready"; do
    if [ $count -ge $timeout ]; then
      echo "Agent did not join within $timeout seconds - continuing anyway"
      return 1
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
  if [ "$DEBUG" = "1" ]; then echo "Waiting for GPU capacity to be added..."; fi
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

# Function to wait for AGX GPU capacity
wait_for_agx_gpu_capacity() {
  local timeout=120
  local count=0
  if [ "$DEBUG" = "1" ]; then echo "Waiting for AGX GPU capacity to be added..."; fi
  while ! sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get node agx -o jsonpath='{.status.capacity.nvidia\.com/gpu}' | grep -q '1'; do
    if [ $count -ge $timeout ]; then
      echo "AGX GPU capacity not added within $timeout seconds"
      exit 1
    fi
    sleep 5
    count=$((count + 5))
  done
    if [ "$DEBUG" = "1" ]; then echo "AGX GPU capacity added"; fi
}

# Function to verify pod readiness
verify_pod_readiness() {
  local pod_name=$1
  local timeout=$2
  local count=0
  if [ "$DEBUG" = "1" ]; then echo "Waiting for pod $pod_name to be ready..."; fi
  while ! sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -l app=$pod_name -o jsonpath='{.items[0].status.phase}' 2>/dev/null | grep -q "Running"; do
    if [ $count -ge $timeout ]; then
      return 1
    fi
    sleep 1
    count=$((count + 1))
  done
  if [ "$DEBUG" = "1" ]; then echo "Pod $pod_name is ready"; fi
  return 0
}

# Function to deploy FastAPI (placeholder - deployments already done in steps 68/71)
deploy_fastapi() {
  local type=$1
  local device=$2
  local app_name=$3
  local ip=$4
  local message=$5
  # Deployments are already handled in steps 68 and 71
  # This function is called for consistency but does nothing
  if [ "$DEBUG" = "1" ]; then echo "FastAPI deployment for $device already completed"; fi
}


# Function for the critical ARP/Ping check
run_network_check() {
  local NODE_IP=$1
  local NODE_NAME=$2
  
  if ping -c 3 -W 1 $NODE_IP > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    ARP_STATUS=$(ip neigh show $NODE_IP 2>&1)
    
    if echo "$ARP_STATUS" | grep -q "INCOMPLETE"; then
      echo -e "[31m❌[0m"
      echo ""
      echo -e "[31m================================================================================[0m"
      echo -e "[31m🚨 CRITICAL ERROR: ${NODE_NAME} HOST UNREACHABLE (ARP/PING FAILED) 🚨[0m"
      echo -e "[33m   The Tower cannot resolve the ${NODE_NAME}'s MAC address at ${NODE_IP}.[0m"
      echo -e "[33m   ACTION REQUIRED: Please ensure the ${NODE_NAME} is fully booted and connected.[0m"
      echo -e "[33m   RECOMMENDATION: **Power cycle the Jetson ${NODE_NAME}** and rerun the script.[0m"
      echo -e "[31m================================================================================[0m"
      exit 1
    else
      echo -e "[31m❌ Ping Failed - Uncategorized Network Error for ${NODE_NAME}[0m"
      exit 1
    fi
  fi
}

# Function to test HTTP endpoints
test_http_endpoint() {
    local name=$1
    local url=$2
    local expected_code=${3:-200}

    echo -n "Testing $name ($url)... "
    response=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)

    if [ "$response" = "$expected_code" ] || ([ "$expected_code" = "200|302" ] && ([ "$response" = "200" ] || [ "$response" = "302" ])); then
        echo "✅ PASS (HTTP $response)"
        return 0
    else
        echo "❌ FAIL (HTTP $response)"
        return 1
    fi
}

# Function to test database connectivity
test_db_connection() {
    local name=$1
    local host=$2
    local port=$3
    local db=$4
    local user=$5
    local password=$6

    echo -n "Testing $name (PostgreSQL $host:$port)... "
    if PGPASSWORD="$password" psql -h "$host" -p "$port" -U "$user" -d "$db" -c "SELECT 1;" >/dev/null 2>&1; then
        echo "✅ PASS"
        return 0
    else
        echo "❌ FAIL"
        return 1
    fi
}


step_01(){
# -------------------------------------------------------------------------
# STEP 01: Tower Network Verification
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Tower Network Verification..."
echo ""
echo -e "[32m$(printf '%.0s=' {1..80})[0m"
echo "Waiting for network interfaces to come up and IPs to be assigned..."
sleep 5
echo "Verifying Tower network configuration..."
AGX_INTERFACE_AVAILABLE=false
if ip addr show enp1s0f1 | grep -q "$TOWER_IP"; then
  echo "  ✅ enp1s0f1 has IP $TOWER_IP"
  AGX_INTERFACE_AVAILABLE=true
else
  echo "  ❌ enp1s0f1 missing IP $TOWER_IP (10G interface not connected)"
  AGX_INTERFACE_AVAILABLE=false
  echo "  ⚠️  Skipping AGX setup - 10G network unavailable"
fi
echo -e "[32m$(printf '%.0s=' {1..80})[0m"
step_echo_start "s" "tower" "$TOWER_IP" "Tower Network Verification..."
echo -e "[32m✅[0m"
step_increment
print_divider
}


step_02(){
# -------------------------------------------------------------------------
# STEP 02: Complete K3s Cleanup
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Complete K3s cleanup..."

# Stop and disable k3s-agent service (ignore errors if service doesn't exist)
sudo systemctl stop k3s-agent || true
sudo systemctl disable k3s-agent || true
sudo rm -f /etc/systemd/system/k3s-agent.service
sudo rm -rf /etc/systemd/system/k3s-agent.service.d
sudo systemctl daemon-reload

# Remove k3s binaries and directories (including agent)
sudo rm -rf /etc/rancher/k3s /var/lib/rancher/k3s /usr/local/bin/k3s /usr/local/bin/k3s-agent

# Stop and disable k3s service (server) - ignore errors if service doesn't exist
sudo systemctl stop k3s || true
sudo systemctl disable k3s || true
sudo rm -f /etc/systemd/system/k3s.service
sudo rm -rf /etc/systemd/system/k3s.service.d
sudo systemctl daemon-reload
sudo rm -rf /etc/rancher/k3s /var/lib/rancher/k3s /usr/local/bin/k3s

# Remove all k3s related files and directories
sudo rm -rf /etc/k3s /var/log/k3s /var/lib/kubelet /var/log/pods /var/lib/cni /run/flannel /etc/cni /opt/cni /etc/rancher /var/lib/rancher /etc/systemd/system/k3s* /etc/systemd/system/k3s-agent* /etc/systemd/system/k3s-server*
sudo systemctl daemon-reload

echo -e "[32m✅ Complete K3s cleanup finished[0m"
echo ""
step_increment
print_divider
}

step_03(){
# -------------------------------------------------------------------------
# STEP 03: Start iperf3 server
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Starting iperf3 server for network testing..."
if [ "$AGX_INTERFACE_AVAILABLE" = true ]; then
  iperf3 -s -B $TOWER_IP -D
  if [ $? -eq 0 ]; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
  fi
else
  echo -e "[33m⚠️  Skipped (10G interface unavailable)[0m"
fi
print_divider
step_increment
}


step_04(){
# --------------------------------------------------------------------------------
# STEP 04: FIX NFS VOLUME PATHS (Addresses 'No such file or directory' error)
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Setting up NFS volumes..."
NFS_BASE="/export/vmstore"
# Paths identified from the Persistent Volume Claims (PVCs):
NFS_CONFIG_PATH="$NFS_BASE/tower_home/kubernetes/agent/nano/app/config"
NFS_HOME_PATH="$NFS_BASE/nano_home"

if sudo mkdir -p "$NFS_CONFIG_PATH" "$NFS_HOME_PATH" > /dev/null 2>&1; then
    # Re-export the volumes to ensure the new paths are available immediately
    sudo exportfs -a > /dev/null 2>&1
    echo -e "[32m✅[0m"
else
    echo -e "[31m❌[0m"
    echo -e "[31mFATAL: Failed to create required NFS directories.[0m"
    exit 1
fi
step_increment
print_divider

}




step_05(){
# -------------------------------------------------------------------------
# STEP 05: Delete FastAPI AGX Services
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI AGX services..."
if cluster_running && sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete service fastapi-agx-service fastapi-agx-nodeport -n default --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[32m✅[0m"  # Mark as success if no cluster or delete fails (nothing to delete)
fi
print_divider
step_increment
}

step_06(){
# -------------------------------------------------------------------------
# STEP 06: Delete FastAPI Nano Services
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI Nano services..."
if cluster_running && sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete service fastapi-nano-service fastapi-nano-nodeport -n default --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[32m✅[0m"  # Mark as success if no cluster or delete fails (nothing to delete)
fi
print_divider
step_increment
}



step_07(){
# -------------------------------------------------------------------------
# STEP 07: Delete FastAPI Spark1 Services
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI Spark1 services..."
if cluster_running && sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete service fastapi-spark1-service fastapi-spark1-nodeport -n default --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[32m✅[0m"  # Mark as success if no cluster or delete fails (nothing to delete)
fi
print_divider
step_increment
}




step_08(){
# -------------------------------------------------------------------------
# STEP 08: Delete FastAPI Spark2 Services
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI Spark2 services..."
if cluster_running && sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete service fastapi-spark2-service fastapi-spark2-nodeport -n default --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[32m✅[0m"  # Mark as success if no cluster or delete fails (nothing to delete)
fi
print_divider
step_increment
}

step_09(){
# -------------------------------------------------------------------------
# STEP 09: Delete FastAPI AGX Deployment
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI AGX deployment..."
if cluster_running && sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete deployment fastapi-agx -n default --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[32m✅[0m"  # Mark as success if no cluster or delete fails (nothing to delete)
fi
print_divider
step_increment
}

step_10(){
# -------------------------------------------------------------------------
# STEP 10: Delete FastAPI Nano Deployment
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI Nano deployment..."
if cluster_running && sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete deployment fastapi-nano -n default --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[32m✅[0m"  # Mark as success if no cluster or delete fails (nothing to delete)
fi
print_divider
step_increment
}

step_11(){
# -------------------------------------------------------------------------
# STEP 11: Delete FastAPI Spark1 Deployment
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI Spark1 deployment..."
if cluster_running && sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete deployment fastapi-spark1 -n default --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[32m✅[0m"  # Mark as success if no cluster or delete fails (nothing to delete)
fi
print_divider
step_increment
}



step_12(){
# -------------------------------------------------------------------------
# STEP 12: Delete FastAPI Spark2 Deployment
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI Spark2 deployment..."
if cluster_running && sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete deployment fastapi-spark2 -n default --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[32m✅[0m"  # Mark as success if no cluster or delete fails (nothing to delete)
fi
print_divider
step_increment
}

step_13(){
# -------------------------------------------------------------------------
# STEP 13: Delete FastAPI AGX Node
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI AGX node..."
if cluster_running && sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete node agx --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[32m✅[0m"  # Mark as success if no cluster or delete fails (nothing to delete)
fi
print_divider
step_increment
}

step_14(){
# -------------------------------------------------------------------------
# STEP 14: Delete FastAPI Nano Node
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI Nano node..."
if cluster_running && sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete node nano --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[32m✅[0m"  # Mark as success if no cluster or delete fails (nothing to delete)
fi
print_divider
step_increment
}


step_15(){
# -------------------------------------------------------------------------
# STEP 15: Delete FastAPI Spark1 Node
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI Spark1 node..."
if cluster_running && sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete node spark1 --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[32m✅[0m"  # Mark as success if no cluster or delete fails (nothing to delete)
fi
print_divider
step_increment
}




step_16(){
# -------------------------------------------------------------------------
# STEP 16: Delete FastAPI Spark2 Node
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI Spark2 node..."
if cluster_running && sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete node spark2 --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[32m✅[0m"  # Mark as success if no cluster or delete fails (nothing to delete)
fi
print_divider
step_increment
}

step_17(){
# -------------------------------------------------------------------------
# STEP 17: Uninstall Server
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Uninstalling Server... (Verbose output below)"
  sleep 5
  # Verbose execution in DEBUG mode
  sudo /usr/local/bin/k3s-uninstall.sh
else
  step_echo_start "s" "tower" "$TOWER_IP" "Uninstalling K3s server..."
  sleep 5
  # Silent execution in normal mode
  if sudo /usr/local/bin/k3s-uninstall.sh > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
  echo -en " ✅[0m
"  # Print checkmark anyway, as uninstall may not exist
  fi
fi
print_divider
step_increment
}


step_18(){
# -------------------------------------------------------------------------
# STEP 18: Install Server
# -------------------------------------------------------------------------
if [ "$INSTALL_SERVER" = true ]; then
  step_echo_start "s" "tower" "$TOWER_IP" "Installing K3s server..."
  echo ""
  echo -e "[32m$(printf '%.0s=' {1..80})[0m"
  sleep 5
  # The output of the curl | sh command is inherently verbose and NOT suppressed here,
  # but the surrounding messages provide the necessary structure.
  sudo curl -sfL https://get.k3s.io | sh -s - server --disable=traefik
  echo -e "Waiting for K3s server to fully initialize..."
  sleep 30
  echo -e "[32m$(printf '%.0s=' {1..80})[0m"
  step_echo_start "s" "tower" "$TOWER_IP" "IK3s server installed..."
  echo -e "[32m✅[0m"
  step_increment
  print_divider
fi
}



step_19(){
# -------------------------------------------------------------------------
# STEP 19: Correct K3s Network Configuration (SIMPLIFIED MESSAGE)
# -------------------------------------------------------------------------
if [ "$INSTALL_SERVER" = true ]; then
  step_echo_start "s" "tower" "$TOWER_IP" "Correcting K3s network configuration..."
  # Stop the service installed by the curl script (Silent in both modes)
  sudo systemctl stop k3s > /dev/null 2>&1
  # 2. Write the corrected config file (Silent in both modes)
  sudo tee /etc/rancher/k3s/config.yaml > /dev/null << EOF
bind-address: $TOWER_IP
advertise-address: $TOWER_IP
flannel-iface: enp1s0f1
disable-network-policy: true
node-ip: $TOWER_IP
EOF
  # 3. Reload daemon and restart k3s (Silent in normal mode, explicit if/else)
  sudo systemctl daemon-reload > /dev/null 2>&1
  if sudo systemctl restart k3s > /dev/null 2>&1; then
    wait_for_server # Ensure it's ready before proceeding
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌ Failed to restart K3s with corrected config\033[0m"
    exit 1
  fi
  step_increment
  print_divider
else
  # Skip server installation steps if INSTALL_SERVER is false
  step_echo_start "s" "tower" "$TOWER_IP" "K3s server installation skipped."
  step_increment
fi
}








step_20(){
# --------------------------------------------------------------------------------
# STEP 20: FIX KUBECONFIG IP (Addresses the 'i/o timeout' error)
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Patching Kubeconfig with correct API IP..."
# Fix the old/incorrect IP (e.g., 192.168.5.1) to the current static IP (10.1.10.150)
if sudo sed -i 's/192.168.5.1/10.1.10.150/g' /etc/rancher/k3s/k3s.yaml > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[31m❌[0m"
  echo -e "[31mFATAL: Failed to patch Kubeconfig IP address.[0m"
  exit 1
fi
step_increment
print_divider
}



step_21(){
# --------------------------------------------------------------------------------
# STEP 21: COPY UPDATED KUBECONFIG TO LOCAL USER
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Copying Kubeconfig to local user..."
# Copy the patched kubeconfig to the user's local kubeconfig directory
if sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config && sudo chown $USER:$USER ~/.kube/config; then
  echo -e "[32m✅[0m"
  # Verify the copy worked by checking the server IP
  if grep -q "server: https://$TOWER_IP:6443" ~/.kube/config; then
    echo -e "[32m✅ Kubeconfig verified - correct server IP ($TOWER_IP)[0m"
  else
    echo -e "[31m❌ Kubeconfig copy verification failed - wrong server IP[0m"
    exit 1
  fi
else
  echo -e "[31m❌ Failed to copy kubeconfig to local user[0m"
  exit 1
fi
step_increment
print_divider

}





step_22(){
# -------------------------------------------------------------------------
# STEP 22: Restart Server (Final Check)
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Restarting Server... (Verbose output below)"
  sleep 5
  sudo systemctl restart k3s
  wait_for_server
else
  step_echo_start "s" "tower" "$TOWER_IP" "Restarting K3s server (final check)..."
  sleep 5
  if sudo timeout 30 systemctl restart k3s > /dev/null 2>&1; then
    wait_for_server
    echo -en " ✅[0m
  "
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}



step_23(){
# -------------------------------------------------------------------------
# STEP 23: Install NVIDIA RuntimeClass
# -------------------------------------------------------------------------
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
  step_echo_start "s" "tower" "$TOWER_IP" "Installing NVIDIA runtime class..."
  echo 'apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: nvidia
handler: nvidia
' | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f - > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider

}


step_24(){
# -------------------------------------------------------------------------
# STEP 24: Install NVIDIA Device Plugin
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Installing NVIDIA Device Plugin... (Verbose output below)"
  echo ""
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f nvidia-ds-updated.yaml
else
  step_echo_start "s" "tower" "$TOWER_IP" "Installing NVIDIA device plugin..."
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f nvidia-ds-updated.yaml > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}



step_25(){
# -------------------------------------------------------------------------
# STEP 25: FIX NVIDIA DEVICE PLUGIN NODE AFFINITY (NEW SELF-HEALING STEP)
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Configuring NVIDIA node affinity..."
sleep 5

# Use kubectl patch to add nodeAffinity to the DaemonSet.
# This forces the DaemonSet to only schedule on 'nano' or 'agx' and evicts the one on 'tower'.
if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml patch daemonset nvidia-device-plugin-daemonset -n kube-system --type='json' -p='[{"op": "add", "path": "/spec/template/spec/affinity", "value": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [{"matchExpressions": [{"key": "kubernetes.io/hostname", "operator": "In", "values": ["nano", "agx"]}]}]}}}}]' > /dev/null 2>&1; then
    
    # After patching, manually delete the crashing pod on the Tower to force quick eviction.
    # Note: We use grep/awk/xargs to find and delete any crashing pod on the tower.
    CRASHING_POD=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -n kube-system -o wide | grep nvidia-device-plugin | grep CrashLoopBackOff | grep tower | awk '{print $1}')
    
    if [ ! -z "$CRASHING_POD" ]; then
        sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete pod "$CRASHING_POD" -n kube-system --grace-period=0 --force > /dev/null 2>&1
    fi
    
    echo -e "[32m✅[0m"
else
    echo -e "[31m❌ Failed to patch NVIDIA Device Plugin DaemonSet[0m"
    exit 1
fi
step_increment
print_divider

}


step_26(){
# --------------------------------------------------------------------------------
# STEP 26: Deploy Docker Registry and Configure K3s Private Registry
# --------------------------------------------------------------------------------
if [ "$INSTALL_SERVER" = true ]; then
  cd "$SCRIPT_DIR"  # Ensure we're in the correct directory

  step_echo_start "s" "tower" "$TOWER_IP" "Deploying Docker registry..."

  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f registry-deployment.yaml > /dev/null 2>&1; then
    # Verify registry pod readiness
    if verify_pod_readiness "registry" 30; then
      echo -e "\n ✅ Docker registry deployed and ready"
      # Configure Docker insecure registry for the NodePort
      sudo tee /etc/docker/daemon.json > /dev/null <<EOF
{
  "insecure-registries": ["$REGISTRY_IP:$REGISTRY_PORT"]
}
EOF
      sudo systemctl restart docker
      sleep 10

      # Configure K3s private registry
      sudo mkdir -p /etc/rancher/k3s
      sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
mirrors:
  "$REGISTRY_IP:$REGISTRY_PORT":
    endpoint:
      - "http://$REGISTRY_IP:$REGISTRY_PORT"
configs:
  "$REGISTRY_IP:$REGISTRY_PORT":
    tls:
      insecure_skip_verify: true
EOF

      # Restart k3s to pick up registry configuration
      if sudo systemctl restart k3s > /dev/null 2>&1; then
        wait_for_server
        echo -e "   ✅ K3s private registry configured"
      else
        echo -e "   ❌ Failed to restart K3s after registry configuration"
        echo -e "[31m❌[0m"
        exit 1
      fi
    else
      echo -e "  ❌ Docker registry health check failed"
      echo -e "[31m❌[0m"
      exit 1
    fi
  else
    echo -e "  ❌ Failed to deploy Docker registry"
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}

step_27(){
# --------------------------------------------------------------------------------
# STEP 27: ROBUST APPLICATION CLEANUP (Fixes stuck pods and 'Allocate failed' GPU error)
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Cleaning up stuck pods and old deployments..."

# 1. Force-delete ALL stuck pods (addresses the persistent 'Terminating' issue) except registry
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete pods -l app!=registry --force --grace-period=0 -n default --ignore-not-found=true > /dev/null 2>&1; then
    :
fi

# 2. Delete all Deployments (addressing the 'Allocate failed' GPU error for the new deployment) except registry
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete deployment -l app!=registry -n default --ignore-not-found=true > /dev/null 2>&1; then
  sleep 5 # Give 5 seconds for resources to be fully released before the next deployment
  echo -e "[32m✅[0m"
else
  echo -e "[31m❌[0m"
  echo -e "[31mFATAL: Failed to clean up old deployments.[0m"
  exit 1
fi

step_increment
print_divider
}


step_28(){
# -------------------------------------------------------------------------
# STEP 28: Create PostgreSQL Initialization ConfigMap
# -------------------------------------------------------------------------
if [ "$INSTALL_SERVER" = true ]; then
  step_echo_start "s" "tower" "$TOWER_IP" "Creating PostgreSQL init configmap..."
sleep 5

# Create the init-sql configmap for postgres initialization
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml create configmap init-sql --from-file=init.sql=/home/sanjay/containers/kubernetes/agent/nano/app/src/init_db.sql --dry-run=client -o yaml | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f - > /dev/null 2>&1

if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get configmap init-sql -n default > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[31m❌[0m"
  echo -e "[31mFATAL: Failed to create PostgreSQL init configmap.[0m"
  exit 1
fi
fi
step_increment
print_divider

}


step_29(){
# --------------------------------------------------------------------------------
# STEP 29: Build PostgreSQL Docker Image
# --------------------------------------------------------------------------------
if [ "$INSTALL_SERVER" = true ]; then
  cd "$SCRIPT_DIR"  # Ensure we're in the correct directory
if [ "$DEBUG" = "1" ]; then
  echo "Building PostgreSQL Docker image... (Verbose output below)"
  sleep 5
  cd postgres && sudo docker build -f dockerfile.postgres -t postgres:latest --build-arg OFFLINE_MODE=true .
else
  step_echo_start "s" "tower" "$TOWER_IP" "Building PostgreSQL Docker image..."
  sleep 5
  if cd postgres && sudo docker build -f dockerfile.postgres -t postgres:latest --build-arg OFFLINE_MODE=true . > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
fi
step_increment
print_divider
}


step_30(){
# --------------------------------------------------------------------------------
# STEP 30: Tag PostgreSQL Docker Image
# --------------------------------------------------------------------------------
if [ "$INSTALL_SERVER" = true ]; then
  cd "$SCRIPT_DIR"  # Ensure we're in the correct directory

# Configure Docker insecure registry
sudo tee /etc/docker/daemon.json > /dev/null <<EOF
{
  "insecure-registries": ["$REGISTRY_IP:$REGISTRY_PORT"]
}
EOF
sudo systemctl restart docker
sleep 2

if [ "$DEBUG" = "1" ]; then
  echo "Tagging PostgreSQL Docker image... (Verbose output below)"
  sleep 5
  sudo docker tag postgres:latest $REGISTRY_IP:$REGISTRY_PORT/postgres:latest
else
  step_echo_start "s" "tower" "$TOWER_IP" "Tagging PostgreSQL Docker image..."
  sleep 5
  if sudo docker tag postgres:latest $REGISTRY_IP:$REGISTRY_PORT/postgres:latest > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
fi
step_increment
print_divider
}

step_31(){
# --------------------------------------------------------------------------------
# STEP 31: Push PostgreSQL Docker Image to Registry
# --------------------------------------------------------------------------------
cd "$SCRIPT_DIR"  # Ensure we're in the correct directory
if [ "$DEBUG" = "1" ]; then
  echo "Pushing PostgreSQL Docker image to registry... (Verbose output below)"
  sleep 5
  sudo docker push $REGISTRY_IP:$REGISTRY_PORT/postgres:latest
else
  step_echo_start "s" "tower" "$TOWER_IP" "Pushing PostgreSQL Docker image to registry..."
  sleep 5
  if sudo docker push $REGISTRY_IP:$REGISTRY_PORT/postgres:latest > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}

step_32(){
# -------------------------------------------------------------------------
# STEP 32: Deploy PostgreSQL Database with Robust Error Handling
# -------------------------------------------------------------------------
if [ "$INSTALL_SERVER" = true ]; then
  cd "$SCRIPT_DIR"  # Ensure we're in the correct directory

  step_echo_start "s" "tower" "$TOWER_IP" "Deploying PostgreSQL database..."

# Create deployment YAML with environment variables substituted
sed "s/localhost:5000/$REGISTRY_IP:$REGISTRY_PORT/g" postgres/postgres-db-deployment.yaml | sed "s/\$POSTGRES_PASSWORD/$POSTGRES_PASSWORD/g" > /tmp/postgres-deployment-processed.yaml

# Apply services first
if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f postgres-pgadmin-nodeport-services.yaml > /dev/null 2>&1; then
    echo -e "\n  ✅ PostgreSQL services deployed"
else
    echo "  ❌ Failed to deploy PostgreSQL services"
    echo -e "[31m❌[0m"
    exit 1
fi

# Deploy PostgreSQL
if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /tmp/postgres-deployment-processed.yaml > /dev/null 2>&1; then

    # Verify PostgreSQL pod readiness
    if verify_pod_readiness "postgres-db" 30; then
        echo "  ✅ PostgreSQL health check passed"
    else
        echo "  ❌ PostgreSQL health check failed"
        echo -e "[31m❌[0m"
        exit 1
    fi
else
    echo "  ❌ PostgreSQL deployment failed"
    echo -e "[31m❌[0m"
    exit 1
fi

fi
step_increment
print_divider
}

step_33(){
# -------------------------------------------------------------------------
# STEP 33: Update FastAPI Database Configuration
# -------------------------------------------------------------------------
if [ "$INSTALL_SERVER" = true ]; then
  step_echo_start "s" "tower" "$TOWER_IP" "Updating FastAPI database config..."
  sleep 5

# Update postgres.env file in NFS mount with correct password and host
cat <<EOF > /export/vmstore/tower_home/kubernetes/agent/nano/app/config/postgres.env
# PostgreSQL Configuration for Nano Agent
POSTGRES_HOST=postgres-db
POSTGRES_PORT=5432
POSTGRES_DB=postgres
POSTGRES_USER=postgres
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
EOF

# Also update the local copy
cp /export/vmstore/tower_home/kubernetes/agent/nano/app/config/postgres.env /home/sanjay/containers/kubernetes/agent/nano/app/config/postgres.env

if [ -f "/export/vmstore/tower_home/kubernetes/agent/nano/app/config/postgres.env" ]; then
  echo -e "[32m✅[0m"
else
  echo -e "[31m❌[0m"
  echo -e "[31mFATAL: Failed to update FastAPI database configuration.[0m"
  exit 1
fi
fi
step_increment
print_divider
}

step_34(){
# --------------------------------------------------------------------------------
# STEP 34: Build pgAdmin Docker Image
# --------------------------------------------------------------------------------
cd "$SCRIPT_DIR"  # Ensure we're in the correct directory
if [ "$DEBUG" = "1" ]; then
  echo "Building pgAdmin Docker image... (Verbose output below)"
  sleep 5
  cd pgadmin && sudo docker build -f dockerfile.pgadmin -t pgadmin:latest .
else
  step_echo_start "s" "tower" "$TOWER_IP" "Building pgAdmin Docker image..."
  sleep 5
  if cd pgadmin && sudo docker build -f dockerfile.pgadmin -t pgadmin:latest . > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}

step_35(){
# --------------------------------------------------------------------------------
# STEP 35: Tag pgAdmin Docker Image
# --------------------------------------------------------------------------------
# Ensure Docker insecure registry is configured
sudo tee /etc/docker/daemon.json > /dev/null <<EOF
{
  "insecure-registries": ["$REGISTRY_IP:$REGISTRY_PORT"]
}
EOF
sudo systemctl restart docker
sleep 2

if [ "$DEBUG" = "1" ]; then
  echo "Tagging pgAdmin Docker image..."
  sleep 5
  sudo docker tag pgadmin:latest $REGISTRY_IP:$REGISTRY_PORT/pgadmin:latest
else
  step_echo_start "s" "tower" "$TOWER_IP" "Tagging pgAdmin Docker image..."
  sleep 5
  if sudo docker tag pgadmin:latest $REGISTRY_IP:$REGISTRY_PORT/pgadmin:latest > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}

step_36(){
# --------------------------------------------------------------------------------
# STEP 36: Push pgAdmin Docker Image to Registry
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Pushing pgAdmin Docker image to registry... (Verbose output below)"
  sleep 5
  sudo docker push $REGISTRY_IP:$REGISTRY_PORT/pgadmin:latest
else
  step_echo_start "s" "tower" "$TOWER_IP" "Pushing pgAdmin Docker image to registry..."
  sleep 5
  if sudo docker push $REGISTRY_IP:$REGISTRY_PORT/pgadmin:latest > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}





step_37(){
# -------------------------------------------------------------------------
# STEP 37: Deploy pgAdmin
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Deploying pgAdmin... (Verbose output below)"
  sleep 5
  # Apply pgAdmin deployment with hardcoded credentials
  sed "s/localhost:5000/$REGISTRY_IP:$REGISTRY_PORT/g" pgadmin-deployment.yaml | \
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f -
else
  step_echo_start "s" "tower" "$TOWER_IP" "Deploying pgAdmin management interface..."
  sleep 5
  if sed "s/localhost:5000/$REGISTRY_IP:$REGISTRY_PORT/g" pgadmin-deployment.yaml | \
     sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f - > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}





step_38(){
  # --------------------------------------------------------------------------------
  # STEP 38: Verify PostgreSQL and pgAdmin Deployment
  # --------------------------------------------------------------------------------
  step_echo_start "s" "tower" "$TOWER_IP" "Verifying PostgreSQL and pgAdmin..."

  # Give pgAdmin time to fully start up before verification
  sleep 120
  echo ""

  # Run the comprehensive verification script
  echo "Running database verification checks..."
  cd "$SCRIPT_DIR"
  if ./verify-postgres-pgadmin.sh; then
    echo -e "[32m✅ PostgreSQL and pgAdmin verification passed[0m"
  else
    echo -e "[31m❌ PostgreSQL and pgAdmin verification failed[0m"
    exit 1
  fi
  cd "$SCRIPT_DIR"
  step_increment
  print_divider
}





step_39(){
# ------------------------------------------------------------------------
# STEP 39: Final Success Message
# ------------------------------------------------------------------------

# Final success message
step_echo_start "s" "tower" "$TOWER_IP" "Deployment complete! Verify cluster and application status."
echo -e "[32m✅[0m"

# Final execution of the full script
if [ "$DEBUG" != "1" ]; then
  set -e
fi
step_increment
print_divider
}


#main script logic continues...
step_01
step_02
step_03
step_04
step_05
step_06
step_07
step_08
step_09
step_10
step_11
step_12
step_13
step_14
step_15
step_16
step_17
step_18
step_19
step_20
step_21
step_22
step_23
step_24
step_25
step_26
step_27
step_28
step_29
step_30
step_31
step_32
step_33
step_34
step_35
step_36
step_37
step_38
step_39
#End




