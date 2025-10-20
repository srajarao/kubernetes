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
INSTALL_NANO_AGENT=true

# Install K3s agent on agx
INSTALL_AGX_AGENT=true

# Install K3s agent on spark1
INSTALL_SPARK1_AGENT=true

# Install K3s agent on spark2
INSTALL_SPARK2_AGENT=true

# IP addresses
TOWER_IP="10.1.10.150"
NANO_IP="10.1.10.181"   # <-- Use the correct, reachable IP
AGX_IP="10.1.10.244"
SPARK1_IP="10.1.10.201"
SPARK2_IP="10.1.10.202"

# Registry settings
REGISTRY_IP="10.1.10.150"
REGISTRY_PORT="5000"
REGISTRY_PROTOCOL="http"  # "http" or "https"

# Database Configuration
POSTGRES_PASSWORD="postgres"  # PostgreSQL admin password
PGADMIN_PASSWORD="pgadmin"          # pgAdmin default password
PGADMIN_EMAIL="pgadmin@pgadmin.org" # pgAdmin default email

# Debug mode (0 for silent, 1 for verbose)
DEBUG=0


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

# NOTE: Total steps count is 72 (includes nano and AGX GPU enablement)
TOTAL_STEPS=97

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




  echo "🔍 COMPREHENSIVE POD VERIFICATION REPORT "
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
# STEP 02: Start iperf3 server
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


step_03(){
# --------------------------------------------------------------------------------
# STEP 03: FIX NFS VOLUME PATHS (Addresses 'No such file or directory' error)
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




step_04(){
# -------------------------------------------------------------------------
# STEP 04: Delete FastAPI AGX Services
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI AGX services..."
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete service fastapi-agx-service fastapi-agx-nodeport -n default --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[31m❌[0m"
fi
print_divider
step_increment
}

step_05(){
# -------------------------------------------------------------------------
# STEP 05: Delete FastAPI Nano Services
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI Nano services..."
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete service fastapi-nano-service fastapi-nano-nodeport -n default --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[31m❌[0m"
fi
print_divider
step_increment
}



step_06(){
# -------------------------------------------------------------------------
# STEP 06: Delete FastAPI Spark1 Services
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI Spark1 services..."
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete service fastapi-spark1-service fastapi-spark1-nodeport -n default --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[31m❌[0m"
fi
print_divider
step_increment
}







step_07(){
# -------------------------------------------------------------------------
# STEP 07: Delete FastAPI AGX Deployment
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI AGX deployment..."
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete deployment fastapi-agx -n default --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[31m❌[0m"
fi
print_divider
step_increment
}

step_08(){
# -------------------------------------------------------------------------
# STEP 08: Delete FastAPI Nano Deployment
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI Nano deployment..."
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete deployment fastapi-nano -n default --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[31m❌[0m"
fi
print_divider
step_increment
}

step_09(){
# -------------------------------------------------------------------------
# STEP 09: Delete FastAPI Spark1 Deployment
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI Spark1 deployment..."
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete deployment fastapi-spark1 -n default --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[31m❌[0m"
fi
print_divider
step_increment
}


step_10(){
# -------------------------------------------------------------------------
# STEP 10: Delete FastAPI AGX Node
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI AGX node..."
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete node agx --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[31m❌[0m"
fi
print_divider
step_increment
}

step_11(){
# -------------------------------------------------------------------------
# STEP 11: Delete FastAPI Nano Node
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI Nano node..."
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete node nano --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[31m❌[0m"
fi
print_divider
step_increment
}

step_12(){
# -------------------------------------------------------------------------
# STEP 12: Delete FastAPI Spark1 Node
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting FastAPI Spark1 node..."
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete node spark1 --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  echo -e "[31m❌[0m"
fi
print_divider
step_increment
}


#=============================================================================================================
step_13(){
# -------------------------------------------------------------------------
# STEP 13: Nano SSH Validation
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Running verbose Nano SSH check..."
  fi
  step_echo_start "a" "nano" "$NANO_IP" "Verifying Nano SSH connectivity..."
  sleep 5
  # Test SSH connection by running 'hostname' on the Nano
  if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "hostname" > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    # --- Corrected Verbose Error Handling (Replaces original simple error) ---
    echo -e "[31m❌ CRITICAL: Passwordless SSH Failed.[0m"
    echo ""
    echo -e "[31m================================================================================[0m"
    echo -e "[33mACTION REQUIRED: Please run './6-setup_tower_sshkeys.sh' manually[0m"
    echo -e "[33mand enter the password when prompted to enable passwordless SSH.[0m"
    echo -e "[31m================================================================================[0m"
    exit 1
  fi
else
  echo "{a} [nano  ] [$NANO_IP] ${CURRENT_STEP}/${TOTAL_STEPS}. Nano SSH verification skipped (not enabled)"
fi
step_increment
print_divider
}


step_14(){
# -------------------------------------------------------------------------
# STEP 14: AGX SSH Validation
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Running verbose AGX SSH check..."
  fi
  step_echo_start "a" "agx" "$AGX_IP" "Verifying AGX SSH connectivity..."
  sleep 5
  # Test SSH connection by running 'hostname' on the AGX
  if ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "hostname" > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    # --- Corrected Verbose Error Handling (Replaces original simple error) ---
    echo -e "[31m❌ CRITICAL: Passwordless SSH Failed.[0m"
    echo ""
    echo -e "[31m================================================================================[0m"
    echo -e "[33mACTION REQUIRED: Please run './6-setup_tower_sshkeys.sh' manually[0m"
    echo -e "[33mand enter the password when prompted to enable passwordless SSH.[0m"
    echo -e "[31m================================================================================[0m"
    exit 1
  fi
else
  echo "{a} [agx   ] [$AGX_IP] ${CURRENT_STEP}/${TOTAL_STEPS}. AGX SSH verification skipped (not enabled)"
fi
step_increment
print_divider
}

step_15(){
# -------------------------------------------------------------------------
# STEP 15: SPARK1 SSH Validation
# -------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Running verbose SPARK1 SSH check..."
  fi
  step_echo_start "a" "spark1" "$SPARK1_IP" "Verifying SPARK1 SSH connectivity..."
  sleep 5
  # Test SSH connection by running 'hostname' on the SPARK1
  if ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "hostname" > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    # --- Corrected Verbose Error Handling (Replaces original simple error) ---
    echo -e "[31m❌ CRITICAL: Passwordless SSH Failed.[0m"
    echo ""
    echo -e "[31m================================================================================[0m"
    echo -e "[33mACTION REQUIRED: Please run './6-setup_tower_sshkeys.sh' manually[0m"
    echo -e "[33mand enter the password when prompted to enable passwordless SSH.[0m"
    echo -e "[31m================================================================================[0m"
    exit 1
  fi
else
  echo "{a} [spark1] [$SPARK1_IP] ${CURRENT_STEP}/${TOTAL_STEPS}. SPARK1 SSH verification skipped (not enabled)"
fi
step_increment
print_divider
}

step_15b(){
# -------------------------------------------------------------------------
# STEP 15b: SPARK2 SSH Validation
# -------------------------------------------------------------------------
if [ "$INSTALL_SPARK2_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Running verbose SPARK2 SSH check..."
  fi
  step_echo_start "a" "spark2" "$SPARK2_IP" "Verifying SPARK2 SSH connectivity..."
  sleep 5
  # Test SSH connection by running 'hostname' on the SPARK2
  if ssh -o StrictHostKeyChecking=no sanjay@$SPARK2_IP "hostname" > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    # --- Corrected Verbose Error Handling (Replaces original simple error) ---
    echo -e "[31m❌ CRITICAL: Passwordless SSH Failed.[0m"
    echo ""
    echo -e "[31m================================================================================[0m"
    echo -e "[33mACTION REQUIRED: Please run './6-setup_tower_sshkeys.sh' manually[0m"
    echo -e "[33mand enter the password when prompted to enable passwordless SSH.[0m"
    echo -e "[31m================================================================================[0m"
    exit 1
  fi
else
  echo "{a} [spark2] [$SPARK2_IP] ${CURRENT_STEP}/${TOTAL_STEPS}. SPARK2 SSH verification skipped (not enabled)"
fi
step_increment
print_divider
}

#=============================================================================================================
step_16(){
# -------------------------------------------------------------------------
# STEP 16: NANO ARP/PING CHECK
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  step_echo_start "a" "nano" "$NANO_IP" "Verifying Nano network reachability (ARP/Ping)..."
  sleep 5
  run_network_check $NANO_IP "NANO"
fi
step_increment
print_divider
}

step_17(){
# -------------------------------------------------------------------------
# STEP 17: AGX ARP/PING CHECK
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  step_echo_start "a" "agx" "$AGX_IP" "Verifying AGX network reachability (ARP/Ping)..."
  sleep 5
  run_network_check $AGX_IP "AGX"
fi
step_increment
print_divider
}

step_18(){
# -------------------------------------------------------------------------
# STEP 18: SPARK1 ARP/PING CHECK
# -------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  step_echo_start "a" "spark1" "$SPARK1_IP" "Verifying SPARK1 network reachability (ARP/Ping)..."
  sleep 5
  run_network_check $SPARK1_IP "SPARK1"
fi
step_increment
print_divider
}
#=============================================================================================================
step_19(){
# -------------------------------------------------------------------------
# STEP 19: Uninstall K3s Agent on AGX
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Uninstalling Agent on AGX... (Verbose output below)"
    sleep 5
    # Check if k3s binaries exist before attempting uninstall
    if ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$AGX_IP "test -x /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
      ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$AGX_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh"
    else
      echo "k3s-agent-uninstall.sh not found on AGX - no uninstall needed"
    fi
  else
    step_echo_start "a" "agx" "$AGX_IP" "Uninstalling K3s agent on agx..."
    sleep 5
    # Check if k3s binaries exist before attempting uninstall
    if ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$AGX_IP "test -x /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
      if ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$AGX_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
        echo -e "[32m✅[0m"
      else
        echo -e "[32m✅[0m"  # Print checkmark anyway, as uninstall may have partial success
      fi
    else
      echo -e "[32m✅[0m"  # Print checkmark if uninstall script doesn't exist (already uninstalled)
    fi
  fi
fi
step_increment
print_divider
}

step_20(){
# -------------------------------------------------------------------------
# STEP 20: Uninstall K3s Agent on Nano
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Uninstalling Agent on Nano... (Verbose output below)"
    sleep 5
    # Check if k3s binaries exist before attempting uninstall
    if ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$NANO_IP "test -x /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
      ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$NANO_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh"
    else
      echo "k3s-agent-uninstall.sh not found on Nano - no uninstall needed"
    fi
  else
    step_echo_start "a" "nano" "$NANO_IP" "Uninstalling K3s agent on nano..."
    sleep 5
    # Check if k3s binaries exist before attempting uninstall
    if ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$NANO_IP "test -x /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
      if ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$NANO_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
        echo -e "[32m✅[0m"
      else
        echo -e "[32m✅[0m"  # Print checkmark anyway, as uninstall may have partial success
      fi
    else
      echo -e "[32m✅[0m"  # Print checkmark if uninstall script doesn't exist (already uninstalled)
    fi
  fi
fi
step_increment
print_divider
}

step_21(){
# -------------------------------------------------------------------------
# STEP 21: Uninstall K3s Agent on Spark1
# -------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Uninstalling Agent on Spark1... (Verbose output below)"
    sleep 5
    # Check if k3s binaries exist before attempting uninstall
    if ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$SPARK1_IP "test -x /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
      ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$SPARK1_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh"
    else
      echo "k3s-agent-uninstall.sh not found on Spark1 - no uninstall needed"
    fi
  else
    step_echo_start "a" "spark1" "$SPARK1_IP" "Uninstalling K3s agent on spark1..."
    sleep 5
    # Check if k3s binaries exist before attempting uninstall
    if ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$SPARK1_IP "test -x /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
      if ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$SPARK1_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
        echo -e "[32m✅[0m"
      else
        echo -e "[32m✅[0m"  # Print checkmark anyway, as uninstall may have partial success
      fi
    else
      echo -e "[32m✅[0m"  # Print checkmark if uninstall script doesn't exist (already uninstalled)
    fi
  fi
fi
step_increment
print_divider
}
#=============================================================================================================

step_22(){
# -------------------------------------------------------------------------
# STEP 22: Uninstall Server
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


step_23(){
# -------------------------------------------------------------------------
# STEP 23: Install Server
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



step_24(){
# -------------------------------------------------------------------------
# STEP 24: Correct K3s Network Configuration (SIMPLIFIED MESSAGE)
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



step_25(){
# ------------------------------------------------------------------------
# STEP 25: Get Token
# ------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then echo "Getting Token: $TOKEN"; fi
step_echo_start "s" "tower" "$TOWER_IP" "Getting server token..."
sleep 5
TOKEN=$(sudo cat /var/lib/rancher/k3s/server/node-token)
echo -e "[32m✅[0m"
step_increment
print_divider
}



step_26(){
# -------------------------------------------------------------------------
# STEP 26: Reinstall Nano Agent (BINARY TRANSFER INSTALL)
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  # Use binary transfer for consistent and reliable installation
  K3S_REINSTALL_CMD="export K3S_TOKEN=\"$TOKEN\";
    scp -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$TOWER_IP:/tmp/k3s-arm64-nano /tmp/k3s-arm64;
    sudo chmod +x /tmp/k3s-arm64;
    sudo cp /tmp/k3s-arm64 /usr/local/bin/k3s;
    sudo chmod +x /usr/local/bin/k3s;
    sudo mkdir -p /etc/systemd/system;
    sudo bash -c 'cat > /etc/systemd/system/k3s-agent.service << EOF
[Unit]
Description=Lightweight Kubernetes
Documentation=https://k3s.io
Wants=network-online.target
After=network-online.target

[Install]
WantedBy=multi-user.target

[Service]
Type=notify
EnvironmentFile=-/etc/default/%N
EnvironmentFile=-/etc/sysconfig/%N
EnvironmentFile=-/etc/systemd/system/k3s-agent.service.env
KillMode=process
Delegate=yes
User=root
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
TimeoutStartSec=0
Restart=always
RestartSec=5s
ExecStartPre=-/sbin/modprobe br_netfilter
ExecStartPre=-/sbin/modprobe overlay
ExecStart=/usr/local/bin/k3s agent --node-ip $NANO_IP
EOF';
    echo 'K3S_TOKEN=\"\$K3S_TOKEN\"' | sudo tee /etc/systemd/system/k3s-agent.service.env > /dev/null;
    echo 'K3S_URL=\"https://$TOWER_IP:6443\"' | sudo tee -a /etc/systemd/system/k3s-agent.service.env > /dev/null;
    sudo systemctl daemon-reload;
    sudo systemctl enable k3s-agent;
    sudo systemctl start k3s-agent"

  if [ "$DEBUG" = "1" ]; then
    echo "Reinstalling Agent on Nano with explicit node-ip $NANO_IP..."
    echo ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "$K3S_REINSTALL_CMD"
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "$K3S_REINSTALL_CMD"
    # Ensure environment file exists with correct server URL
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "sudo mkdir -p /etc/systemd/system && echo 'K3S_TOKEN=\"$TOKEN\"' | sudo tee /etc/systemd/system/k3s-agent.service.env > /dev/null && echo 'K3S_URL=\"https://$TOWER_IP:6443\"' | sudo tee -a /etc/systemd/system/k3s-agent.service.env > /dev/null" 2>/dev/null || true
    # CRITICAL: Ensure systemd loads environment variables after install
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "sudo systemctl daemon-reload && sudo systemctl restart k3s-agent" 2>/dev/null || true
    wait_for_agent
  else
    step_echo_start "a" "nano" "$NANO_IP" "Reinstalling K3s agent on nano..."
    sleep 5
    # Execute the robust reinstall command
    if ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "$K3S_REINSTALL_CMD" > /dev/null 2>&1; then
      # Ensure environment file exists with correct server URL
      ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "sudo mkdir -p /etc/systemd/system && echo 'K3S_TOKEN=\"$TOKEN\"' | sudo tee /etc/systemd/system/k3s-agent.service.env > /dev/null && echo 'K3S_URL=\"https://$TOWER_IP:6443\"' | sudo tee -a /etc/systemd/system/k3s-agent.service.env > /dev/null" > /dev/null 2>&1
      # CRITICAL: Ensure systemd loads environment variables after install
      ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "sudo systemctl daemon-reload && sudo systemctl restart k3s-agent" > /dev/null 2>&1
      wait_for_agent
      echo -en " ✅\033[0m\n"
    else
      echo -e "\033[31m❌\033[0m"
      exit 1
    fi
  fi
fi
step_increment
print_divider

}


step_27(){
# -------------------------------------------------------------------------
# STEP 27: Reinstall AGX Agent (BINARY TRANSFER INSTALL)
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  # Use binary transfer for AGX (curl fails due to network restrictions)
  K3S_REINSTALL_CMD="export K3S_TOKEN=\"$TOKEN\";
    scp -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$TOWER_IP:/tmp/k3s-arm64 /tmp/k3s-arm64;
    sudo chmod +x /tmp/k3s-arm64;
    sudo cp /tmp/k3s-arm64 /usr/local/bin/k3s;
    sudo chmod +x /usr/local/bin/k3s;
    sudo mkdir -p /etc/systemd/system;
    sudo bash -c 'cat > /etc/systemd/system/k3s-agent.service << EOF
[Unit]
Description=Lightweight Kubernetes
Documentation=https://k3s.io
Wants=network-online.target
After=network-online.target

[Install]
WantedBy=multi-user.target

[Service]
Type=notify
EnvironmentFile=-/etc/default/%N
EnvironmentFile=-/etc/sysconfig/%N
EnvironmentFile=-/etc/systemd/system/k3s-agent.service.env
KillMode=process
Delegate=yes
User=root
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
TimeoutStartSec=0
Restart=always
RestartSec=5s
ExecStartPre=-/sbin/modprobe br_netfilter
ExecStartPre=-/sbin/modprobe overlay
ExecStart=/usr/local/bin/k3s agent --node-ip $AGX_IP
EOF';
    echo 'K3S_TOKEN=\"\$K3S_TOKEN\"' | sudo tee /etc/systemd/system/k3s-agent.service.env > /dev/null;
    echo 'K3S_URL=\"https://$TOWER_IP:6443\"' | sudo tee -a /etc/systemd/system/k3s-agent.service.env > /dev/null;
    sudo ip route add default via 10.1.10.1 dev eno1 2>/dev/null || true;
    sudo systemctl daemon-reload;
    sudo systemctl enable k3s-agent;
    sudo systemctl start k3s-agent"

  if [ "$DEBUG" = "1" ]; then
    echo "Reinstalling Agent on AGX with binary transfer..."
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "$K3S_REINSTALL_CMD"
    # Ensure environment file exists with correct server URL
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "sudo mkdir -p /etc/systemd/system && echo 'K3S_TOKEN=\"$TOKEN\"' | sudo tee /etc/systemd/system/k3s-agent.service.env > /dev/null && echo 'K3S_URL=\"https://$TOWER_IP:6443\"' | sudo tee -a /etc/systemd/system/k3s-agent.service.env > /dev/null" 2>/dev/null || true
    # CRITICAL: Ensure systemd loads environment variables after install
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "sudo systemctl daemon-reload && sudo systemctl restart k3s-agent" 2>/dev/null || true
    wait_for_agent
  else
    step_echo_start "a" "agx" "$AGX_IP" "Reinstalling K3s agent on agx..."
    sleep 5
    # Execute the binary transfer install command
    if ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "$K3S_REINSTALL_CMD" > /dev/null 2>&1; then
      # Ensure environment file exists with correct server URL
      ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "sudo mkdir -p /etc/systemd/system && echo 'K3S_TOKEN=\"$TOKEN\"' | sudo tee /etc/systemd/system/k3s-agent.service.env > /dev/null && echo 'K3S_URL=\"https://$TOWER_IP:6443\"' | sudo tee -a /etc/systemd/system/k3s-agent.service.env > /dev/null" > /dev/null 2>&1
      # CRITICAL: Ensure systemd loads environment variables after install
      ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "sudo systemctl daemon-reload && sudo systemctl restart k3s-agent" > /dev/null 2>&1
      wait_for_agent
      echo -en " ✅[0m
"
    else
      echo -e "[31m❌[0m"
      exit 1
    fi
  fi
fi
step_increment
print_divider
}



step_28(){
# =========================================================================
# STEP 28: Systemd Service Override (force correct server/node IP) AGX
# =========================================================================
step_echo_start "a" "agx" "$AGX_IP" "Forcing K3s agx agent to use correct server IP..."

# Add AGX host key to known_hosts to avoid SSH warning
ssh-keyscan -H $AGX_IP >> ~/.ssh/known_hosts 2>/dev/null

# Create systemd override directory and file directly instead of using systemctl edit
ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "sudo mkdir -p /etc/systemd/system/k3s-agent.service.d/" > /dev/null 2>&1

ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "sudo tee /etc/systemd/system/k3s-agent.service.d/override.conf > /dev/null" << EOF
[Service]
Environment="K3S_URL=https://$TOWER_IP:6443"
Environment="K3S_NODE_IP=$AGX_IP"
EOF

# Reload daemon and restart the service
ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "sudo systemctl daemon-reload && sudo timeout 30 systemctl restart k3s-agent" > /dev/null 2>&1

# Check the exit status of the SSH command
if [ $? -eq 0 ]; then
    # Wait for the agent to re-join and be ready
    wait_for_agent 
  echo -e "✅\x1b[0m"
else
  echo -e "❌\x1b[0m"
  echo -e "\x1b[31mFATAL: Failed to overwrite AGX service file.\x1b[0m"
  exit 1
fi
step_increment
print_divider
}



step_29(){
# =========================================================================
# STEP 29: Systemd Service Override (force correct server/node IP) NANO
# =========================================================================
step_echo_start "a" "nano" "$NANO_IP" "Forcing K3s nano agent to use correct server IP..."

# Add NANO host key to known_hosts to avoid SSH warning
ssh-keyscan -H $NANO_IP >> ~/.ssh/known_hosts 2>/dev/null || true

# Use systemctl edit to create an override.conf file that specifically sets the
# correct server URL and node IP, clearing any old, cached settings.
ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "sudo systemctl edit k3s-agent.service" > /dev/null 2>&1 << EOF
[Service]
Environment="K3S_URL=https://$TOWER_IP:6443"
Environment="K3S_NODE_IP=$NANO_IP"
EOF

# Restart the service to apply the forced environment variables
ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "sudo systemctl daemon-reload && sudo timeout 30 systemctl restart k3s-agent" > /dev/null 2>&1

# Check the exit status of the SSH command
if [ $? -eq 0 ]; then
    # Wait for the agent to re-join and be ready
    wait_for_agent 
    echo -en "✅[0m
"
else
    echo -en "❌[0m
"
    echo -e "[31mFATAL: Failed to overwrite NANO service file.[0m"
    exit 1
fi
step_increment
print_divider

}

step_30(){
# =========================================================================
# STEP 30: Systemd Service Override (force correct server/node IP) SPARK1
# =========================================================================
step_echo_start "a" "spark1" "$SPARK1_IP" "Forcing K3s spark1 agent to use correct server IP..."

# Add SPARK1 host key to known_hosts to avoid SSH warning
ssh-keyscan -H $SPARK1_IP >> ~/.ssh/known_hosts 2>/dev/null || true

# Use systemctl edit to create an override.conf file that specifically sets the
# correct server URL and node IP, clearing any old, cached settings.
ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$SPARK1_IP "sudo systemctl edit k3s-agent.service" > /dev/null 2>&1 << EOF
[Service]
Environment="K3S_URL=https://$TOWER_IP:6443"
Environment="K3S_NODE_IP=$SPARK1_IP"
EOF

# Restart the service to apply the forced environment variables
ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$SPARK1_IP "sudo systemctl daemon-reload && sudo timeout 30 systemctl restart k3s-agent" > /dev/null 2>&1

# Check the exit status of the SSH command
if [ $? -eq 0 ]; then
    # Wait for the agent to re-join and be ready
    wait_for_agent 
    echo -en "✅[0m
"
else
    echo -en "❌[0m
"
    echo -e "[31mFATAL: Failed to overwrite SPARK1 service file.[0m"
    exit 1
fi
step_increment
print_divider

}


step_31(){
# -------------------------------------------------------------------------
# STEP 31: Create Registry Config Directory AGX
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Adding Registry Config Dir on AGX..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo mkdir -p /etc/rancher/k3s/"
    echo ""
  else
    step_echo_start "a" "agx" "$AGX_IP" "Creating agx registry configuration directory..."
    sleep 5
    if ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo mkdir -p /etc/rancher/k3s/" > /dev/null 2>&1; then
      echo -en " ✅\033[0m\n"
    else
      echo -e "\033[31m❌\033[0m"
      exit 1
    fi
  fi
  step_increment
  print_divider
fi

}

step_32(){
# -------------------------------------------------------------------------
# STEP 32: Create Registry Config Directory NANO
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Adding Registry Config Dir..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo mkdir -p /etc/rancher/k3s/"
    echo ""
  else
    step_echo_start "a" "nano" "$NANO_IP" "Creating nano registry configuration directory..."
    sleep 5
    if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo mkdir -p /etc/rancher/k3s/" > /dev/null 2>&1; then
      echo -e " ✅"
    else
      echo -e "❌"
      exit 1
    fi
  fi
  step_increment
  print_divider
 fi
}

step_33(){
# -------------------------------------------------------------------------
# STEP 33: Create Registry Config Directory SPARK1
# -------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Adding Registry Config Dir on SPARK1..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo mkdir -p /etc/rancher/k3s/"
    echo ""
  else
    step_echo_start "a" "spark1" "$SPARK1_IP" "Creating spark1 registry configuration directory..."
    sleep 5
    if ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo mkdir -p /etc/rancher/k3s/" > /dev/null 2>&1; then
      echo -en " ✅\033[0m\n"
    else
      echo -e "\033[31m❌\033[0m"
      exit 1
    fi
  fi
  step_increment
  print_divider
fi
}


step_34(){
# -------------------------------------------------------------------------
# STEP 34: Write Registry YAML and Containerd TOML (Nano)
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Fixing Registry YAML Syntax on Nano..."
    sleep 5
    if [[ "$REGISTRY_PROTOCOL" == "https" ]]; then
      ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null" <<EOF
mirrors:
  "$REGISTRY_IP:$REGISTRY_PORT":
    endpoint:
      - "https://$REGISTRY_IP:$REGISTRY_PORT"

configs:
  "$REGISTRY_IP:$REGISTRY_PORT":
    tls:
      ca_file: "/etc/docker/certs.d/$REGISTRY_IP/ca.crt"
      cert_file: "/etc/docker/certs.d/$REGISTRY_IP/registry.crt"
      key_file: "/etc/docker/certs.d/$REGISTRY_IP/registry.key"
EOF
      ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT"
      ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null" <<EOF
[host."https://$REGISTRY_IP:$REGISTRY_PORT"]
  capabilities = ["pull", "resolve", "push"]
  ca = "/etc/docker/certs.d/$REGISTRY_IP/ca.crt"
  client = ["/etc/docker/certs.d/$REGISTRY_IP/registry.crt", "/etc/docker/certs.d/$REGISTRY_IP/registry.key"]
EOF
    else
      ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null" <<EOF
mirrors:
  "$REGISTRY_IP:$REGISTRY_PORT":
    endpoint:
      - "http://$REGISTRY_IP:$REGISTRY_PORT"

configs:
  "$REGISTRY_IP:$REGISTRY_PORT":
    tls:
      insecure_skip_verify: true
EOF
      ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT"
      ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null" <<EOF
[host."http://$REGISTRY_IP:$REGISTRY_PORT"]
  capabilities = ["pull", "resolve", "push"]
EOF
    fi
  else
    step_echo_start "a" "nano" "$NANO_IP" "Write Registry YAML and Containerd TOML (Nano)..."
    sleep 5
    if [[ "$REGISTRY_PROTOCOL" == "https" ]]; then
      ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
mirrors:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    endpoint:
      - \"https://$REGISTRY_IP:$REGISTRY_PORT\"

configs:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    tls:
      ca_file: \"/etc/docker/certs.d/$REGISTRY_IP/ca.crt\"
      cert_file: \"/etc/docker/certs.d/$REGISTRY_IP/registry.crt\"
      key_file: \"/etc/docker/certs.d/$REGISTRY_IP/registry.key\"
EOF
" > /dev/null 2>&1
      ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT" > /dev/null 2>&1
      ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"https://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
  ca = \"/etc/docker/certs.d/$REGISTRY_IP/ca.crt\"
  client = [\"/etc/docker/certs.d/$REGISTRY_IP/registry.crt\", \"/etc/docker/certs.d/$REGISTRY_IP/registry.key\"]
EOF
" > /dev/null 2>&1
    else
      ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
mirrors:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    endpoint:
      - \"http://$REGISTRY_IP:$REGISTRY_PORT\"

configs:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    tls:
      insecure_skip_verify: true
EOF
" > /dev/null 2>&1
      ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT" > /dev/null 2>&1
      ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"http://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
EOF
" > /dev/null 2>&1
    fi
    if [ $? -eq 0 ]; then
      echo -en " ✅\033[0m\n"
    else
      echo -e "\033[31m❌\033[0m"
      exit 1
    fi
  fi
fi
step_increment
print_divider


}


step_35(){
# -------------------------------------------------------------------------
# STEP 35: Write Registry YAML and Containerd TOML (AGX)
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Fixing Registry YAML Syntax on AGX..."
    sleep 5
    if [[ "$REGISTRY_PROTOCOL" == "https" ]]; then
      ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null" <<EOF
mirrors:
  "$REGISTRY_IP:$REGISTRY_PORT":
    endpoint:
      - "https://$REGISTRY_IP:$REGISTRY_PORT"

configs:
  "$REGISTRY_IP:$REGISTRY_PORT":
    tls:
      ca_file: "/etc/docker/certs.d/$REGISTRY_IP/ca.crt"
      cert_file: "/etc/docker/certs.d/$REGISTRY_IP/registry.crt"
      key_file: "/etc/docker/certs.d/$REGISTRY_IP/registry.key"
EOF
      ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT"
      ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null" <<EOF
[host."https://$REGISTRY_IP:$REGISTRY_PORT"]
  capabilities = ["pull", "resolve", "push"]
  ca = "/etc/docker/certs.d/$REGISTRY_IP/ca.crt"
  client = ["/etc/docker/certs.d/$REGISTRY_IP/registry.crt", "/etc/docker/certs.d/$REGISTRY_IP/registry.key"]
EOF
    else
      ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null" <<EOF
mirrors:
  "$REGISTRY_IP:$REGISTRY_PORT":
    endpoint:
      - "http://$REGISTRY_IP:$REGISTRY_PORT"

configs:
  "$REGISTRY_IP:$REGISTRY_PORT":
    tls:
      insecure_skip_verify: true
EOF
      ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT"
      ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null" <<EOF
[host."http://$REGISTRY_IP:$REGISTRY_PORT"]
  capabilities = ["pull", "resolve", "push"]
EOF
    fi
  else
    step_echo_start "a" "agx" "$AGX_IP" "Write Registry YAML and Containerd TOML (AGX)"
    sleep 5
    if [[ "$REGISTRY_PROTOCOL" == "https" ]]; then
      ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
mirrors:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    endpoint:
      - \"https://$REGISTRY_IP:$REGISTRY_PORT\"

configs:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    tls:
      ca_file: \"/etc/docker/certs.d/$REGISTRY_IP/ca.crt\"
      cert_file: \"/etc/docker/certs.d/$REGISTRY_IP/registry.crt\"
      key_file: \"/etc/docker/certs.d/$REGISTRY_IP/registry.key\"
EOF
" > /dev/null 2>&1
      ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT" > /dev/null 2>&1
      ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"https://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
  ca = \"/etc/docker/certs.d/$REGISTRY_IP/ca.crt\"
  client = [\"/etc/docker/certs.d/$REGISTRY_IP/registry.crt\", \"/etc/docker/certs.d/$REGISTRY_IP/registry.key\"]
EOF
" > /dev/null 2>&1
    else
      ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
mirrors:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    endpoint:
      - \"http://$REGISTRY_IP:$REGISTRY_PORT\"

configs:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    tls:
      insecure_skip_verify: true
EOF
" > /dev/null 2>&1
      ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT" > /dev/null 2>&1
      ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"http://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
EOF
" > /dev/null 2>&1
    fi
    if [ $? -eq 0 ]; then
      echo -en " ✅\033[0m\n"
    else
      echo -e "\033[31m❌\033[0m"
      exit 1
    fi
  fi
fi
step_increment
print_divider

}

step_36(){
# -------------------------------------------------------------------------
# STEP 36: Write Registry YAML and Containerd TOML (SPARK1)
# -------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Fixing Registry YAML Syntax on SPARK1..."
    sleep 5
    if [[ "$REGISTRY_PROTOCOL" == "https" ]]; then
      ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null" <<EOF
mirrors:
  "$REGISTRY_IP:$REGISTRY_PORT":
    endpoint:
      - "https://$REGISTRY_IP:$REGISTRY_PORT"

configs:
  "$REGISTRY_IP:$REGISTRY_PORT":
    tls:
      ca_file: "/etc/docker/certs.d/$REGISTRY_IP/ca.crt"
      cert_file: "/etc/docker/certs.d/$REGISTRY_IP/registry.crt"
      key_file: "/etc/docker/certs.d/$REGISTRY_IP/registry.key"
EOF
      ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT"
      ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null" <<EOF
[host."https://$REGISTRY_IP:$REGISTRY_PORT"]
  capabilities = ["pull", "resolve", "push"]
  ca = "/etc/docker/certs.d/$REGISTRY_IP/ca.crt"
  client = ["/etc/docker/certs.d/$REGISTRY_IP/registry.crt", "/etc/docker/certs.d/$REGISTRY_IP/registry.key"]
EOF
    else
      ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null" <<EOF
mirrors:
  "$REGISTRY_IP:$REGISTRY_PORT":
    endpoint:
      - "http://$REGISTRY_IP:$REGISTRY_PORT"

configs:
  "$REGISTRY_IP:$REGISTRY_PORT":
    tls:
      insecure_skip_verify: true
EOF
      ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT"
      ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null" <<EOF
[host."http://$REGISTRY_IP:$REGISTRY_PORT"]
  capabilities = ["pull", "resolve", "push"]
EOF
    fi
  else
    step_echo_start "a" "spark1" "$SPARK1_IP" "Write Registry YAML and Containerd TOML (SPARK1)"
    sleep 5
    if [[ "$REGISTRY_PROTOCOL" == "https" ]]; then
      ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
mirrors:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    endpoint:
      - \"https://$REGISTRY_IP:$REGISTRY_PORT\"

configs:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    tls:
      ca_file: \"/etc/docker/certs.d/$REGISTRY_IP/ca.crt\"
      cert_file: \"/etc/docker/certs.d/$REGISTRY_IP/registry.crt\"
      key_file: \"/etc/docker/certs.d/$REGISTRY_IP/registry.key\"
EOF
sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT
sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"https://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
  ca = \"/etc/docker/certs.d/$REGISTRY_IP/ca.crt\"
  client = [\"/etc/docker/certs.d/$REGISTRY_IP/registry.crt\", \"/etc/docker/certs.d/$REGISTRY_IP/registry.key\"]
EOF
" > /dev/null 2>&1
    else
      ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
mirrors:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    endpoint:
      - \"http://$REGISTRY_IP:$REGISTRY_PORT\"

configs:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    tls:
      insecure_skip_verify: true
EOF
sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT
sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"http://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
EOF
" > /dev/null 2>&1
    fi
    if [ $? -eq 0 ]; then
      echo -en " ✅\033[0m\n"
    else
      echo -e "\033[31m❌\033[0m"
      exit 1
    fi
  fi
fi
step_increment
print_divider

}










step_37(){
# -------------------------------------------------------------------------
# STEP 37: Configure Registry for NANO
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Configuring Registry for NANO..."
    sleep 5
  else
    step_echo_start "a" "nano" "$NANO_IP" "Configuring registry for nano..."
    sleep 5
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$NANO_IP "sudo mkdir -p /etc/rancher/k3s/" > /dev/null 2>&1 && \
    ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
mirrors:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    endpoint:
      - \"http://$REGISTRY_IP:$REGISTRY_PORT\"

configs:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    tls:
      insecure_skip_verify: true
EOF
" > /dev/null 2>&1 && \
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$AGX_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT" > /dev/null 2>&1 && \
    ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"http://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
EOF
" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
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

step_38(){
# -------------------------------------------------------------------------
# STEP 38: Configure Registry for SPARK1
# -------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Configuring Registry for SPARK1..."
    sleep 5
  else
    step_echo_start "a" "spark1" "$SPARK1_IP" "Configuring registry for spark1..."
    sleep 5
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$SPARK1_IP "sudo mkdir -p /etc/rancher/k3s/" > /dev/null 2>&1 && \
    ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
mirrors:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    endpoint:
      - \"http://$REGISTRY_IP:$REGISTRY_PORT\"

configs:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    tls:
      insecure_skip_verify: true
EOF
" > /dev/null 2>&1 && \
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$SPARK1_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT" > /dev/null 2>&1 && \
    ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"http://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
EOF
" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
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




step_39(){
# --------------------------------------------------------------------------------
# STEP 39: FIX KUBECONFIG IP (Addresses the 'i/o timeout' error)
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



step_40(){
# --------------------------------------------------------------------------------
# STEP 40: COPY UPDATED KUBECONFIG TO LOCAL USER
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




step_41(){
# -------------------------------------------------------------------------
# STEP 41: Configure Containerd for Registry (AGX)
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Configuring Containerd for Registry on AGX..."
    sleep 5
  else
    step_echo_start "a" "agx" "$AGX_IP" "Configuring containerd for registry..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT" > /dev/null 2>&1 && \
    ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"http://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
EOF
" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
      echo -en " ✅\033[0m\n"
    else
      echo -e "\033[31m❌\033[0m"
      exit 1
    fi
  fi
  fi
step_increment
print_divider

}


step_42(){
# -------------------------------------------------------------------------
# STEP 42: Configure Containerd for Registry (Nano)
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Configuring Containerd for Registry on Nano..."
    sleep 5
  else
    step_echo_start "a" "nano" "$NANO_IP" "Configuring containerd for registry..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT" > /dev/null 2>&1 && \
    ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"http://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
EOF
" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
      echo -en " ✅\033[0m\n"
    else
      echo -e "\033[31m❌\033[0m"
      exit 1
    fi
  fi
step_increment
print_divider
fi
}


step_43(){
# -------------------------------------------------------------------------
# STEP 43: Configure Containerd for Registry (SPARK1)
# -------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Configuring Containerd for Registry on SPARK1..."
    sleep 5
  else
    step_echo_start "a" "spark1" "$SPARK1_IP" "Configuring containerd for registry..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT" > /dev/null 2>&1 && \
    ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"http://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
EOF
" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
      echo -en " ✅\033[0m\n"
    else
      echo -e "\033[31m❌\033[0m"
      exit 1
    fi
  fi
step_increment
print_divider
fi
}




step_44(){
# -------------------------------------------------------------------------
# STEP 44: Restart Agent After Registry Config AGX
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Restarting Agent After Registry Config AGX..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo systemctl restart k3s-agent"
  wait_for_agent
else
  step_echo_start "a" "agx" "$AGX_IP" "Restarting K3s agent after registry config..."
  sleep 5
  # Use timeout to prevent hanging on systemctl restart
  if ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo timeout 30 systemctl restart k3s-agent" > /dev/null 2>&1; then
    wait_for_agent
    echo -e "✅"
  else
    echo -e "[31m❌ Service restart failed or timed out[0m"
    echo -e "[33m⚠️  Continuing anyway - agent may restart on its own[0m"
    echo -e "⚠️"
  fi
fi
step_increment
print_divider

}


step_45(){
# -------------------------------------------------------------------------
# STEP 45: Restart Agent After Registry Config NANO
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
    echo "Restarting Agent After Registry Config Nano..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo systemctl restart k3s-agent"
    wait_for_agent
else
    step_echo_start "a" "nano" "$NANO_IP" "Restarting K3s agent after registry config..."
    sleep 5
    # Use timeout to prevent hanging on systemctl restart
    if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo timeout 30 systemctl restart k3s-agent" > /dev/null 2>&1; then
      wait_for_agent
      echo -e "✅"
    else
      echo -e "[31m❌ Service restart failed or timed out[0m"
      echo -e "[33m⚠️  Continuing anyway - agent may restart on its own[0m"
      echo -e "⚠️"
    fi
  fi
step_increment
print_divider
}

step_46(){
# -------------------------------------------------------------------------
# STEP 46: Restart Agent After Registry Config SPARK1
# -------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Restarting Agent After Registry Config SPARK1..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo systemctl restart k3s-agent"
    wait_for_agent
  else
    step_echo_start "a" "spark1" "$SPARK1_IP" "Restarting K3s agent after registry config..."
    sleep 5
    # Use timeout to prevent hanging on systemctl restart
    if ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo timeout 30 systemctl restart k3s-agent" > /dev/null 2>&1; then
      wait_for_agent
      echo -e "✅"
    else
      echo -e "[31m❌ Service restart failed or timed out[0m"
      echo -e "[33m⚠️  Continuing anyway - agent may restart on its own[0m"
      echo -e "⚠️"
    fi
  fi
fi
step_increment
print_divider
}



step_47(){
# -------------------------------------------------------------------------
# STEP 47: Restart Server (Final Check)
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


step_48(){
# =========================================================================
# STEP 48: COPY KUBECONFIG TO AGX AGENT (Ultra-Robust 'sudo scp' version)
# =========================================================================
if [ "$INSTALL_AGX_AGENT" = true ]; then
  step_echo_start "s" "tower" "$TOWER_IP" "Copying Kubeconfig to agx agent..."
# 1. Add AGX host key to known_hosts to avoid SSH warning
ssh-keyscan -H $AGX_IP >> ~/.ssh/known_hosts 2>/dev/null
# 2. Use 'sudo' with scp on the Tower side to read the root-owned Kubeconfig...
if sudo scp -i ~/.ssh/id_ed25519 /etc/rancher/k3s/k3s.yaml sanjay@$AGX_IP:/tmp/k3s.yaml.agx > /dev/null 2>&1; then
    # 2. On the AGX, use a single SSH command to move the file and set permissions.
    ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "
      sudo mkdir -p /etc/rancher/k3s-agent-config && \
      sudo mv /tmp/k3s.yaml.agx /etc/rancher/k3s-agent-config/kubeconfig.yaml && \
      sudo chown root:root /etc/rancher/k3s-agent-config/kubeconfig.yaml && \
      sudo chmod 644 /etc/rancher/k3s-agent-config/kubeconfig.yaml" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "✅"
    else
        echo -en " ❌[0m"
        echo -e "[31mFATAL: Failed to secure Kubeconfig on AGX. File may be in /tmp.[0m"
        exit 1
    fi
# THIS LINE MUST BE IMMEDIATELY FOLLOWED BY `else` WITH NO WHITESPACE/TABS
else
    echo -en " ❌[0m"
    echo -e "[31mFATAL: Failed to transfer Kubeconfig file to AGX /tmp directory.[0m"
    exit 1
fi
step_increment
print_divider
fi
}



step_49(){
# =========================================================================
# STEP 49: COPY KUBECONFIG TO NANO AGENT (Robust Copy using 'sudo cat')
# =========================================================================
step_echo_start "s" "tower" "$TOWER_IP" "Copying Kubeconfig to nano agent..."

# 1. Add NANO host key to known_hosts to avoid SSH warning
ssh-keyscan -H $NANO_IP >> ~/.ssh/known_hosts 2>/dev/null

# 2. Use 'sudo cat' to read the root-owned Kubeconfig file on the Tower,
#    pipe it over SSH, and use 'sudo tee' to write it securely on the NANO.
sudo cat /etc/rancher/k3s/k3s.yaml | ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "
  sudo mkdir -p /etc/rancher/k3s-agent-config && \
  sudo tee /etc/rancher/k3s-agent-config/kubeconfig.yaml > /dev/null
" > /dev/null 2>&1

# 2. Check the exit status of the SSH command
if [ $? -eq 0 ]; then
    # Ensure permissions are correct (readable by root on NANO)
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "sudo chown root:root /etc/rancher/k3s-agent-config/kubeconfig.yaml && sudo chmod 644 /etc/rancher/k3s-agent-config/kubeconfig.yaml"
    echo -e "✅"
else
    echo -en " ❌[0m"
    echo -e "[31mFATAL: Failed to copy Kubeconfig to NANO.[0m"
    exit 1
fi
step_increment
print_divider

}

step_50(){
# =========================================================================
# STEP 50: COPY KUBECONFIG TO SPARK1 AGENT (Robust Copy using 'sudo cat')
# =========================================================================
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  step_echo_start "s" "tower" "$TOWER_IP" "Copying Kubeconfig to spark1 agent..."

  # 1. Add SPARK1 host key to known_hosts to avoid SSH warning
  ssh-keyscan -H $SPARK1_IP >> ~/.ssh/known_hosts 2>/dev/null

  # 2. Use 'sudo cat' to read the root-owned Kubeconfig file on the Tower,
  #    pipe it over SSH, and use 'sudo tee' to write it securely on the SPARK1.
  sudo cat /etc/rancher/k3s/k3s.yaml | ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$SPARK1_IP "
    sudo mkdir -p /etc/rancher/k3s-agent-config && \
    sudo tee /etc/rancher/k3s-agent-config/kubeconfig.yaml > /dev/null
  " > /dev/null 2>&1

  # 2. Check the exit status of the SSH command
  if [ $? -eq 0 ]; then
      # Ensure permissions are correct (readable by root on SPARK1)
      ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$SPARK1_IP "sudo chown root:root /etc/rancher/k3s-agent-config/kubeconfig.yaml && sudo chmod 644 /etc/rancher/k3s-agent-config/kubeconfig.yaml"
      echo -e "✅"
  else
      echo -en " ❌[0m"
      echo -e "[31mFATAL: Failed to copy Kubeconfig to SPARK1.[0m"
      exit 1
  fi
fi
step_increment
print_divider

}



step_51() {
# =========================================================================
# STEP 51: Verify Agent Node Readiness
# =========================================================================
if [ "$DEBUG" = "1" ]; then
  echo "Verifying agent nodes are ready..."
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes
  echo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes
else
  step_echo_start "s" "tower" "$TOWER_IP" "Verifying agent nodes are ready..."
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes --no-headers | grep -E "(nano|agx)" | grep -q "Ready" 2>/dev/null; then
    echo -e "✅"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}


step_52(){
# -------------------------------------------------------------------------
# STEP 52: Install NVIDIA RuntimeClass
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


step_53(){
# -------------------------------------------------------------------------
# STEP 53: Install NVIDIA Device Plugin
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



step_54(){
# -------------------------------------------------------------------------
# STEP 54: FIX NVIDIA DEVICE PLUGIN NODE AFFINITY (NEW SELF-HEALING STEP)
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


step_55(){
# -------------------------------------------------------------------------
# STEP 55: Configure NVIDIA Runtime on AGX
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Restarting K3s Agent on AGX after containerd config..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo systemctl stop k3s-agent"
    ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo systemctl start k3s-agent"
    wait_for_agent
  else
    step_echo_start "a" "agx" "$AGX_IP" "Restarting K3s agent after containerd config..."
    sleep 5
    if ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo systemctl stop k3s-agent" > /dev/null 2>&1 && ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo systemctl start k3s-agent" > /dev/null 2>&1; then
      wait_for_agent
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




step_56(){
# -------------------------------------------------------------------------
# STEP 56: Configure NVIDIA Runtime on Nano
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Restarting K3s agent after containerd config..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo systemctl stop k3s-agent"
    ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo systemctl start k3s-agent"
    wait_for_agent
  else
    step_echo_start "a" "nano" "$NANO_IP" "Restarting K3s agent after containerd config..."
    sleep 5
    if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo systemctl stop k3s-agent" > /dev/null 2>&1 && ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo systemctl start k3s-agent" > /dev/null 2>&1; then
      wait_for_agent
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

step_57(){
# -------------------------------------------------------------------------
# STEP 57: Configure NVIDIA Runtime on SPARK1
# -------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Restarting K3s agent after containerd config on SPARK1..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo systemctl stop k3s-agent"
    ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo systemctl start k3s-agent"
    wait_for_agent
  else
    step_echo_start "a" "spark1" "$SPARK1_IP" "Restarting K3s agent after containerd config..."
    sleep 5
    if ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo systemctl stop k3s-agent" > /dev/null 2>&1 && ssh -o StrictHostKeyChecking=no sanjay@$SPARK1_IP "sudo systemctl start k3s-agent" > /dev/null 2>&1; then
      wait_for_agent
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


step_58(){
# --------------------------------------------------------------------------------
# STEP 58: Clean up FastAPI AGX Docker Image Tags
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Cleaning up FastAPI AGX Docker image tags... (Verbose output below)"
  sleep 5
  # Remove all tags related to fastapi-agx:latest
  sudo docker images | grep fastapi-agx | awk '{print $1":"$2}' | xargs -r sudo docker rmi
else
  step_echo_start "s" "tower" "$TOWER_IP" "Cleaning up FastAPI AGX Docker image tags..."
  sleep 5
  if sudo docker images | grep fastapi-agx | awk '{print $1":"$2}' | xargs -r sudo docker rmi > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[32m✅[0m"
  fi
fi
step_increment
print_divider
}


step_59(){
# --------------------------------------------------------------------------------
# STEP 59: Clean up FastAPI Nano Docker Image Tags
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Cleaning up FastAPI Nano Docker image tags... (Verbose output below)"
  sleep 5
  # Remove all tags related to fastapi-nano:latest
  sudo docker images | grep fastapi-nano | awk '{print $1":"$2}' | xargs -r sudo docker rmi
else
  step_echo_start "s" "tower" "$TOWER_IP" "Cleaning up FastAPI Nano Docker image tags..."
  sleep 5
  if sudo docker images | grep fastapi-nano | awk '{print $1":"$2}' | xargs -r sudo docker rmi > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[32m✅[0m"
  fi
fi
step_increment
print_divider
}

step_60(){
# --------------------------------------------------------------------------------
# STEP 60: Clean up FastAPI Spark1 Docker Image Tags
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Cleaning up FastAPI Spark1 Docker image tags... (Verbose output below)"
  sleep 5
  # Remove all tags related to fastapi-spark1:latest
  sudo docker images | grep fastapi-spark1 | awk '{print $1":"$2}' | xargs -r sudo docker rmi
else
  step_echo_start "s" "tower" "$TOWER_IP" "Cleaning up FastAPI Spark1 Docker image tags..."
  sleep 5
  if sudo docker images | grep fastapi-spark1 | awk '{print $1":"$2}' | xargs -r sudo docker rmi > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[32m✅[0m"
  fi
fi
step_increment
print_divider
}




step_61(){
# -------------------------------------------------------------------------
# STEP 61: Build Image
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Building Image... (Verbose output below)"
  sleep 5
  cd /home/sanjay/containers/kubernetes/agent/nano && sudo docker build -f dockerfile.nano.req -t fastapi-nano:latest .
else
  step_echo_start "s" "tower" "$TOWER_IP" "Building Docker image..."
  sleep 5
  if cd /home/sanjay/containers/kubernetes/agent/nano && sudo docker build -f dockerfile.nano.req -t fastapi-nano:latest . > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}


step_62(){
# -------------------------------------------------------------------------
# STEP 62: Tag Image
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Tagging Image..."
  sleep 5
  sudo docker tag fastapi-nano:latest $REGISTRY_IP:$REGISTRY_PORT/fastapi-nano:latest
else
  step_echo_start "s" "tower" "$TOWER_IP" "Tagging Docker image..."
  sleep 5
  if sudo docker tag fastapi-nano:latest $REGISTRY_IP:$REGISTRY_PORT/fastapi-nano:latest > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider

}


step_63(){
# -------------------------------------------------------------------------
# STEP 63: Push Image
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Pushing Image... (Verbose output below)"

  sleep 5
  sudo docker push $REGISTRY_IP:$REGISTRY_PORT/fastapi-nano:latest
else
  step_echo_start "s" "tower" "$TOWER_IP" "Pushing Docker image to registry..."
  sleep 5
  if sudo docker push $REGISTRY_IP:$REGISTRY_PORT/fastapi-nano:latest > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider

}


step_64(){
# --------------------------------------------------------------------------------
# STEP 64: Build AGX Docker Image
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Building AGX Docker image... (Verbose output below)"
  sleep 5
  cd /home/sanjay/containers/kubernetes/agent/agx && sudo docker buildx build --platform linux/arm64 -f dockerfile.agx.req -t fastapi-agx:latest --load .
else
  step_echo_start "s" "tower" "$TOWER_IP" "Building AGX Docker image..."
  sleep 5
  if cd /home/sanjay/containers/kubernetes/agent/agx && sudo docker buildx build --platform linux/arm64 -f dockerfile.agx.req -t fastapi-agx:latest --load . > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}

step_65(){
# --------------------------------------------------------------------------------
# STEP 65: Tag AGX Docker Image
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Tagging AGX Docker image..."
  sleep 5
  sudo docker tag fastapi-agx:latest $REGISTRY_IP:$REGISTRY_PORT/fastapi-agx:latest
else
  step_echo_start "s" "tower" "$TOWER_IP" "Tagging AGX Docker image..."
  sleep 5
  if sudo docker tag fastapi-agx:latest $REGISTRY_IP:$REGISTRY_PORT/fastapi-agx:latest > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}


step_66(){
# -------------------------------------------------------------------------
# STEP 66: Push Image
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Pushing Image... (Verbose output below)"

  sleep 5
  sudo docker push $REGISTRY_IP:$REGISTRY_PORT/fastapi-agx:latest
else
  step_echo_start "s" "tower" "$TOWER_IP" "Pushing Docker image to registry..."
  sleep 5
  if sudo docker push $REGISTRY_IP:$REGISTRY_PORT/fastapi-agx:latest > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider

}

step_67(){
# --------------------------------------------------------------------------------
# STEP 67: Build Spark1 Docker Image
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Building Spark1 Docker image... (Verbose output below)"
  sleep 5
  cd /home/sanjay/containers/kubernetes/agent/spark1 && sudo docker buildx build --platform linux/arm64 -f dockerfile.spark1.req -t fastapi-spark1:latest --load .
else
  step_echo_start "s" "tower" "$TOWER_IP" "Building Spark1 Docker image..."
  sleep 5
  if cd /home/sanjay/containers/kubernetes/agent/spark1 && sudo docker buildx build --platform linux/arm64 -f dockerfile.spark1.req -t fastapi-spark1:latest --load . > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}

step_68(){
# --------------------------------------------------------------------------------
# STEP 68: Tag Spark1 Docker Image
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Tagging Spark1 Docker image..."
  sleep 5
  sudo docker tag fastapi-spark1:latest $REGISTRY_IP:$REGISTRY_PORT/fastapi-spark1:latest
else
  step_echo_start "s" "tower" "$TOWER_IP" "Tagging Spark1 Docker image..."
  sleep 5
  if sudo docker tag fastapi-spark1:latest $REGISTRY_IP:$REGISTRY_PORT/fastapi-spark1:latest > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}

step_69(){
# -------------------------------------------------------------------------
# STEP 69: Push Spark1 Image
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Pushing Spark1 Image... (Verbose output below)"

  sleep 5
  sudo docker push $REGISTRY_IP:$REGISTRY_PORT/fastapi-spark1:latest
else
  step_echo_start "s" "tower" "$TOWER_IP" "Pushing Spark1 Docker image to registry..."
  sleep 5
  if sudo docker push $REGISTRY_IP:$REGISTRY_PORT/fastapi-spark1:latest > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider

}



step_70(){
# --------------------------------------------------------------------------------
# STEP 70: ROBUST APPLICATION CLEANUP (Fixes stuck pods and 'Allocate failed' GPU error)
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Cleaning up stuck pods and old deployments..."

# 1. Force-delete ALL stuck pods (addresses the persistent 'Terminating' issue)
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete pods --all --force --grace-period=0 -n default --ignore-not-found=true > /dev/null 2>&1; then
    :
fi

# 2. Delete all Deployments (addressing the 'Allocate failed' GPU error for the new deployment)
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete deployment --all -n default --ignore-not-found=true > /dev/null 2>&1; then
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


step_71(){

# -------------------------------------------------------------------------
# STEP 71: Create PostgreSQL Initialization ConfigMap
# -------------------------------------------------------------------------
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
step_increment
print_divider

}


step_72(){
# --------------------------------------------------------------------------------
# STEP 72: Build PostgreSQL Docker Image
# --------------------------------------------------------------------------------
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
step_increment
print_divider
}

step_73(){
# --------------------------------------------------------------------------------
# STEP 73: Tag PostgreSQL Docker Image
# --------------------------------------------------------------------------------
cd "$SCRIPT_DIR"  # Ensure we're in the correct directory
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
step_increment
print_divider
}

step_74(){
# --------------------------------------------------------------------------------
# STEP 74: Push PostgreSQL Docker Image to Registry
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

step_75(){
# -------------------------------------------------------------------------
# STEP 75: Deploy PostgreSQL Database with Robust Error Handling
# -------------------------------------------------------------------------
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

step_increment
print_divider
}

step_76(){
# -------------------------------------------------------------------------
# STEP 76: Update FastAPI Database Configuration
# -------------------------------------------------------------------------
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
step_increment
print_divider
}





step_77(){
# --------------------------------------------------------------------------------
# STEP 77: Build pgAdmin Docker Image
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

step_78(){
# --------------------------------------------------------------------------------
# STEP 78: Tag pgAdmin Docker Image
# --------------------------------------------------------------------------------
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

step_79(){
# --------------------------------------------------------------------------------
# STEP 79: Push pgAdmin Docker Image to Registry
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





step_80(){
# -------------------------------------------------------------------------
# STEP 80: Deploy pgAdmin
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





step_81(){
  # --------------------------------------------------------------------------------
  # STEP 81: Verify PostgreSQL and pgAdmin Deployment
  # --------------------------------------------------------------------------------
  step_echo_start "s" "tower" "$TOWER_IP" "Verifying PostgreSQL and pgAdmin..."

  # Give pgAdmin time to fully start up before verification
  sleep 120
  echo ""

  # Run the comprehensive verification script
  echo "Running database verification checks..."
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




step_82(){
# ------------------------------------------------------------------------
# STEP 82: Deploy FastAPI on Nano (CPU-only)
# ------------------------------------------------------------------------
step_echo_start "a" "nano" "$NANO_IP" "Deploying FastAPI on nano (CPU-only)"
sleep 5
# Create deployment YAML for FastAPI Nano without GPU resources
cat <<EOF | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastapi-nano
  namespace: default
  labels:
    app: fastapi-nano
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
    spec:
      nodeSelector:
        kubernetes.io/hostname: nano
      containers:
      - name: fastapi
        image: $REGISTRY_IP:$REGISTRY_PORT/fastapi-nano:latest
        ports:
        - containerPort: 8000
          name: http
        - containerPort: 8888
          name: jupyter
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        env:
        - name: DEVICE_TYPE
          value: "nano"
        - name: GPU_ENABLED
          value: "false"
        - name: FORCE_GPU_CHECKS
          value: "false"
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
          mountPath: /workspace/config
        - name: nano-workspace
          mountPath: /workspace
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
      - name: nano-workspace
        nfs:
          server: $TOWER_IP
          path: /export/vmstore/tower_home/kubernetes/agent/nano
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
EOF
if [ $? -eq 0 ]; then
  echo -e "[32m✅[0m"
else
  echo -e "[31m❌[0m"
  exit 1
fi
step_increment
print_divider
}

step_83(){
# ------------------------------------------------------------------------
# STEP 83: Deploy FastAPI on AGX (CPU-only)
# ------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  step_echo_start "a" "agx" "$AGX_IP" "Deploying AI Workload on agx (CPU-only)"
  sleep 5
  # Create deployment YAML for FastAPI AGX without GPU resources
  cat <<EOF | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastapi-agx
  namespace: default
  labels:
    app: fastapi-agx
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: fastapi-agx
  template:
    metadata:
      labels:
        app: fastapi-agx
    spec:
      nodeSelector:
        kubernetes.io/hostname: agx
      containers:
      - name: fastapi
        image: $REGISTRY_IP:$REGISTRY_PORT/fastapi-agx:latest
        ports:
        - containerPort: 8000
          name: http
        - containerPort: 8888
          name: jupyter
        - containerPort: 8001
          name: llm-api
        resources:
          requests:
            memory: "2Gi"
            cpu: "500m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
        env:
        - name: DEVICE_TYPE
          value: "agx"
        - name: GPU_ENABLED
          value: "false"
        - name: FORCE_GPU_CHECKS
          value: "false"
        - name: LLM_ENABLED
          value: "false"
        - name: RAG_ENABLED
          value: "false"
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        volumeMounts:
        - name: vmstore
          mountPath: /mnt/vmstore
        - name: agx-home
          mountPath: /home/agx
        - name: agx-config
          mountPath: /app/app/config
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 60
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 10
      volumes:
      - name: vmstore
        nfs:
          server: $TOWER_IP
          path: /export/vmstore
      - name: agx-home
        nfs:
          server: $TOWER_IP
          path: /export/vmstore/agx_home
      - name: agx-config
        nfs:
          server: $TOWER_IP
          path: /export/vmstore/tower_home/kubernetes/agent/agx/app/config
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
  name: fastapi-agx-service
  namespace: default
  labels:
    app: fastapi-agx
    device: agx
spec:
  selector:
    app: fastapi-agx
  ports:
  - port: 8000
    targetPort: 8000
    protocol: TCP
    name: http
  - port: 8888
    targetPort: 8888
    protocol: TCP
    name: jupyter
  - port: 8001
    targetPort: 8001
    protocol: TCP
    name: llm-api
  type: ClusterIP
---
apiVersion: v1
kind: Service
metadata:
  name: fastapi-agx-nodeport
  namespace: default
  labels:
    app: fastapi-agx
    device: agx
spec:
  selector:
    app: fastapi-agx
  ports:
  - port: 8000
    targetPort: 8000
    nodePort: 30004
    protocol: TCP
    name: http
  - port: 8888
    targetPort: 8888
    nodePort: 30005
    protocol: TCP
    name: jupyter
  - port: 8001
    targetPort: 8001
    nodePort: 30006
    protocol: TCP
    name: llm-api
  type: NodePort
EOF
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

step_84(){
# ------------------------------------------------------------------------
# STEP 84: Deploy FastAPI on Spark1 (CPU-only)
# ------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  step_echo_start "a" "spark1" "$SPARK1_IP" "Deploying AI Workload on spark1 (CPU-only)"
  sleep 5
  # Deploy SPARK1 AI Workload without GPU resources and services
  cat <<EOF | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastapi-spark1
  namespace: default
  labels:
    app: fastapi-spark1
spec:
  replicas: 1
  selector:
    matchLabels:
      app: fastapi-spark1
  template:
    metadata:
      labels:
        app: fastapi-spark1
    spec:
      nodeSelector:
        kubernetes.io/hostname: spark1
      tolerations:
      - key: CriticalAddonsOnly
        operator: Exists
      containers:
      - name: fastapi
        image: $REGISTRY_IP:$REGISTRY_PORT/fastapi-spark1:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 8000
          name: http
        - containerPort: 8888
          name: jupyter
        - containerPort: 8001
          name: llm-api
        resources:
          requests:
            memory: "4Gi"
            cpu: "1000m"
          limits:
            memory: "8Gi"
            cpu: "4000m"
        env:
        - name: DEVICE_TYPE
          value: "spark1"
        - name: GPU_ENABLED
          value: "false"
        - name: FORCE_GPU_CHECKS
          value: "false"
        - name: LLM_ENABLED
          value: "false"
        - name: RAG_ENABLED
          value: "false"
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        volumeMounts:
        - name: vmstore
          mountPath: /mnt/vmstore
        - name: spark1-home
          mountPath: /home/spark1
        - name: spark1-config
          mountPath: /app/app/config
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 60
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 10
      volumes:
      - name: vmstore
        nfs:
          server: $TOWER_IP
          path: /export/vmstore
      - name: spark1-home
        nfs:
          server: $TOWER_IP
          path: /export/vmstore/spark1_home
      - name: spark1-config
        nfs:
          server: $TOWER_IP
          path: /export/vmstore/tower_home/kubernetes/agent/spark1/app/config
---
apiVersion: v1
kind: Service
metadata:
  name: fastapi-spark1-service
  namespace: default
  labels:
    app: fastapi-spark1
    device: spark1
spec:
  selector:
    app: fastapi-spark1
  ports:
  - port: 8000
    targetPort: 8000
    protocol: TCP
    name: http
  - port: 8888
    targetPort: 8888
    protocol: TCP
    name: jupyter
  - port: 8001
    targetPort: 8001
    protocol: TCP
    name: llm-api
  type: ClusterIP
---
apiVersion: v1
kind: Service
metadata:
  name: fastapi-spark1-nodeport
  namespace: default
  labels:
    app: fastapi-spark1
    device: spark1
spec:
  selector:
    app: fastapi-spark1
  ports:
  - port: 8000
    targetPort: 8000
    nodePort: 30007
    protocol: TCP
    name: http
  - port: 8888
    targetPort: 8888
    nodePort: 30008
    protocol: TCP
    name: jupyter
  - port: 8001
    targetPort: 8001
    nodePort: 30009
    protocol: TCP
    name: llm-api
  type: NodePort
EOF
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



step_85(){
# --------------------------------------------------------------------------------
# STEP 85: AGX GPU CAPACITY VERIFICATION
# --------------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  step_echo_start "a" "agx" "$AGX_IP" "Verifying AGX GPU capacity..."
  sleep 5
  if wait_for_agx_gpu_capacity; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}



step_86(){
# --------------------------------------------------------------------------------
# STEP 86: NANO GPU CAPACITY VERIFICATION
# --------------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  step_echo_start "a" "nano" "$NANO_IP" "Verifying NANO GPU capacity..."
  sleep 5
  if wait_for_nano_gpu_capacity; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}


step_87(){
# --------------------------------------------------------------------------------
# STEP 87: SPARK1 GPU CAPACITY VERIFICATION
# --------------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  step_echo_start "a" "spark1" "$SPARK1_IP" "Verifying SPARK1 GPU capacity..."
  sleep 5
  if wait_for_spark1_gpu_capacity; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}


step_88(){
# --------------------------------------------------------------------------------
# STEP 88: AGX GPU RESOURCE CLEANUP
# --------------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  step_echo_start "a" "agx" "$AGX_IP" "Cleaning up AGX GPU resources for deployment..."

  # Check if AGX CPU deployment exists before cleanup
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get deployment fastapi-agx -n default --ignore-not-found=true | grep -q "fastapi-agx"; then
    # Force-delete any stuck pods on AGX node to free GPU resources
    if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete pods -l kubernetes.io/hostname=agx --force --grace-period=0 -n default --ignore-not-found=true > /dev/null 2>&1; then
      :
    fi

    # Delete AGX AI Workload deployment to free GPU resources
    if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete deployment fastapi-agx -n default --ignore-not-found=true > /dev/null 2>&1; then
      sleep 5 # Give time for GPU resources to be fully released
      echo -e "[32m✅[0m"
    else
      echo -e "[31m❌[0m"
      exit 1
    fi
  else
    echo -e "No AGX CPU deployment found, skipping cleanup"
    echo -e "[32m✅[0m"
  fi
fi
step_increment
print_divider
}

step_89(){
# --------------------------------------------------------------------------------
# STEP 89: NANO GPU RESOURCE CLEANUP
# --------------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  step_echo_start "a" "nano" "$NANO_IP" "Cleaning up Nano GPU resources for deployment..."

  # Check if NANO CPU deployment exists before cleanup
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get deployment fastapi-nano -n default --ignore-not-found=true | grep -q "fastapi-nano"; then
    # Force-delete any stuck pods on Nano node to free GPU resources
    if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete pods -l kubernetes.io/hostname=nano --force --grace-period=0 -n default --ignore-not-found=true > /dev/null 2>&1; then
      :
    fi

    # Delete Nano AI Workload deployment to free GPU resources
    if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete deployment fastapi-nano -n default --ignore-not-found=true > /dev/null 2>&1; then
      sleep 5 # Give time for GPU resources to be fully released
      echo -e "[32m✅[0m"
    else
      echo -e "[31m❌[0m"
      exit 1
    fi
  else
    echo -e "No NANO CPU deployment found, skipping cleanup"
    echo -e "[32m✅[0m"
  fi
fi
step_increment
print_divider
}

step_90(){
# --------------------------------------------------------------------------------
# STEP 90: SPARK1 GPU RESOURCE CLEANUP
# --------------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  step_echo_start "a" "spark1" "$SPARK1_IP" "Cleaning up Spark1 GPU resources for deployment..."

  # Check if SPARK1 CPU deployment exists before cleanup
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get deployment fastapi-spark1 -n default --ignore-not-found=true | grep -q "fastapi-spark1"; then
    # Force-delete any stuck pods on Spark1 node to free GPU resources
    if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete pods -l kubernetes.io/hostname=spark1 --force --grace-period=0 -n default --ignore-not-found=true > /dev/null 2>&1; then
      :
    fi

    # Delete Spark1 AI Workload deployment to free GPU resources
    if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete deployment fastapi-spark1 -n default --ignore-not-found=true > /dev/null 2>&1; then
      sleep 5 # Give time for GPU resources to be fully released
      echo -e "[32m✅[0m"
    else
      echo -e "[31m❌[0m"
      exit 1
    fi
  else
    echo -e "No SPARK1 CPU deployment found, skipping cleanup"
    echo -e "[32m✅[0m"
  fi
fi
step_increment
print_divider
}



step_91(){
# --------------------------------------------------------------------------------
# STEP 91: AGX GPU-ENABLED AI WORKLOAD DEPLOYMENT
# --------------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  step_echo_start "a" "agx" "$AGX_IP" "Deploying GPU-enabled AI Workload on AGX..."
  echo -e "[32m✅[0m"

  # Deploy AGX AI Workload with GPU resources and services
  cat > /tmp/fastapi-agx-gpu.yaml <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastapi-agx
  labels:
    app: fastapi-agx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: fastapi-agx
  template:
    metadata:
      labels:
        app: fastapi-agx
    spec:
      runtimeClassName: nvidia
      nodeSelector:
        kubernetes.io/hostname: agx
      tolerations:
      - key: CriticalAddonsOnly
        operator: Exists
      containers:
      - name: fastapi
        image: $REGISTRY_IP:$REGISTRY_PORT/fastapi-agx:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 8000
          name: http
        - containerPort: 8888
          name: jupyter
        - containerPort: 8001
          name: llm-api
        resources:
          requests:
            memory: "2Gi"
            cpu: "500m"
            nvidia.com/gpu: 1
          limits:
            memory: "4Gi"
            cpu: "2000m"
            nvidia.com/gpu: 1
        env:
        - name: DEVICE_TYPE
          value: "agx"
        - name: GPU_ENABLED
          value: "true"
        - name: FORCE_GPU_CHECKS
          value: "true"
        - name: LLM_ENABLED
          value: "true"
        - name: RAG_ENABLED
          value: "true"
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        volumeMounts:
        - name: vmstore
          mountPath: /mnt/vmstore
        - name: agx-home
          mountPath: /home/agx
        - name: agx-config
          mountPath: /app/app/config
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 60
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 10
      volumes:
      - name: vmstore
        nfs:
          server: $TOWER_IP
          path: /export/vmstore
      - name: agx-home
        nfs:
          server: $TOWER_IP
          path: /export/vmstore/agx_home
      - name: agx-config
        nfs:
          server: $TOWER_IP
          path: /export/vmstore/tower_home/kubernetes/agent/agx/app/config
---
apiVersion: v1
kind: Service
metadata:
  name: fastapi-agx-service
  namespace: default
  labels:
    app: fastapi-agx
    device: agx
spec:
  selector:
    app: fastapi-agx
  ports:
  - port: 8000
    targetPort: 8000
    protocol: TCP
    name: http
  - port: 8888
    targetPort: 8888
    protocol: TCP
    name: jupyter
  - port: 8001
    targetPort: 8001
    protocol: TCP
    name: llm-api
  type: ClusterIP
---
apiVersion: v1
kind: Service
metadata:
  name: fastapi-agx-nodeport
  namespace: default
  labels:
    app: fastapi-agx
    device: agx
spec:
  selector:
    app: fastapi-agx
  ports:
  - port: 8000
    targetPort: 8000
    nodePort: 30004
    protocol: TCP
    name: http
  - port: 8888
    targetPort: 8888
    nodePort: 30005
    protocol: TCP
    name: jupyter
  - port: 8001
    targetPort: 8001
    nodePort: 30006
    protocol: TCP
    name: llm-api
  type: NodePort
EOF

  if [ "$DEBUG" = "1" ]; then
    echo "Applying GPU-enabled AGX FastAPI deployment..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /tmp/fastapi-agx-gpu.yaml
    apply_exit=$?
  else
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /tmp/fastapi-agx-gpu.yaml > /dev/null 2>&1
    apply_exit=$?
  fi

  if [ $apply_exit -eq 0 ]; then
    # Wait for GPU-enabled pod to be running
    echo -e "\nWaiting for GPU-enabled FastAPI pod to be ready..."
    for i in {1..60}; do
      if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -l app=fastapi-agx -o jsonpath='{.items[0].status.phase}' 2>/dev/null | grep -q "Running"; then
        echo -e "✅ GPU-enabled AI Workload pod is running on AGX"
        break
      fi
      sleep 5
    done
    if [ $i -eq 60 ]; then
      echo -e "❌ GPU-enabled AI Workload pod did not start within 5 minutes"
      exit 1
    fi
  else
    echo -e "❌ Failed to deploy GPU-enabled AI Workload on AGX"
    exit 1
  fi
fi
step_increment
print_divider
}

step_92(){
# --------------------------------------------------------------------------------
# STEP 92: NANO GPU-ENABLED AI WORKLOAD DEPLOYMENT
# --------------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  step_echo_start "a" "nano" "$NANO_IP" "Deploying GPU-enabled AI Workload on NANO..."
  echo -e "[32m✅[0m"

  # Deploy NANO AI Workload with GPU resources and services
  cat > /tmp/fastapi-nano-gpu.yaml <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastapi-nano
  labels:
    app: fastapi-nano
spec:
  replicas: 1
  selector:
    matchLabels:
      app: fastapi-nano
  template:
    metadata:
      labels:
        app: fastapi-nano
    spec:
      runtimeClassName: nvidia
      nodeSelector:
        kubernetes.io/hostname: nano
      tolerations:
      - key: CriticalAddonsOnly
        operator: Exists
      containers:
      - name: fastapi
        image: $REGISTRY_IP:$REGISTRY_PORT/fastapi-nano:latest
        imagePullPolicy: Always
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
          mountPath: /workspace/config
        - name: nano-workspace
          mountPath: /workspace
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
      - name: nano-workspace
        nfs:
          server: $TOWER_IP
          path: /export/vmstore/tower_home/kubernetes/agent/nano
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
EOF

  if [ "$DEBUG" = "1" ]; then
    echo "Applying GPU-enabled NANO FastAPI deployment..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /tmp/fastapi-nano-gpu.yaml
    apply_exit=$?
  else
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /tmp/fastapi-nano-gpu.yaml > /dev/null 2>&1
    apply_exit=$?
  fi

  if [ $apply_exit -eq 0 ]; then
    # Wait for GPU-enabled pod to be running
    echo -e "\nWaiting for GPU-enabled FastAPI pod to be ready..."
    for i in {1..60}; do
      if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -l app=fastapi-nano -o jsonpath='{.items[0].status.phase}' 2>/dev/null | grep -q "Running"; then
        echo -e "✅ GPU-enabled AI Workload pod is running on NANO"
        break
      fi
      sleep 5
    done
    if [ $i -eq 60 ]; then
      echo -e "❌ GPU-enabled AI Workload pod did not start within 5 minutes"
      exit 1
    fi
  else
    echo -e "❌ Failed to deploy GPU-enabled AI Workload on NANO"
    exit 1
  fi
fi
step_increment
print_divider
}

step_93(){
# --------------------------------------------------------------------------------
# STEP 93: SPARK1 GPU-ENABLED AI WORKLOAD DEPLOYMENT
# --------------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  step_echo_start "a" "spark1" "$SPARK1_IP" "Deploying GPU-enabled AI Workload on SPARK1..."
  echo -e "[32m✅[0m"

  # Deploy SPARK1 AI Workload with GPU resources and services
  cat > /tmp/fastapi-spark1-gpu.yaml <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastapi-spark1
  labels:
    app: fastapi-spark1
spec:
  replicas: 1
  selector:
    matchLabels:
      app: fastapi-spark1
  template:
    metadata:
      labels:
        app: fastapi-spark1
    spec:
      runtimeClassName: nvidia
      nodeSelector:
        kubernetes.io/hostname: spark1
      tolerations:
      - key: CriticalAddonsOnly
        operator: Exists
      containers:
      - name: fastapi
        image: $REGISTRY_IP:$REGISTRY_PORT/fastapi-spark1:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 8000
          name: http
        - containerPort: 8888
          name: jupyter
        - containerPort: 8001
          name: llm-api
        resources:
          requests:
            memory: "4Gi"
            cpu: "1000m"
            nvidia.com/gpu: 1
          limits:
            memory: "8Gi"
            cpu: "4000m"
            nvidia.com/gpu: 1
        env:
        - name: DEVICE_TYPE
          value: "spark1"
        - name: GPU_ENABLED
          value: "true"
        - name: FORCE_GPU_CHECKS
          value: "true"
        - name: LLM_ENABLED
          value: "true"
        - name: RAG_ENABLED
          value: "true"
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        volumeMounts:
        - name: vmstore
          mountPath: /mnt/vmstore
        - name: spark1-home
          mountPath: /home/spark1
        - name: spark1-config
          mountPath: /app/app/config
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 60
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 10
      volumes:
      - name: vmstore
        nfs:
          server: $TOWER_IP
          path: /export/vmstore
      - name: spark1-home
        nfs:
          server: $TOWER_IP
          path: /export/vmstore/spark1_home
      - name: spark1-config
        nfs:
          server: $TOWER_IP
          path: /export/vmstore/tower_home/kubernetes/agent/spark1/app/config
---
apiVersion: v1
kind: Service
metadata:
  name: fastapi-spark1-service
  namespace: default
  labels:
    app: fastapi-spark1
    device: spark1
spec:
  selector:
    app: fastapi-spark1
  ports:
  - port: 8000
    targetPort: 8000
    protocol: TCP
    name: http
  - port: 8888
    targetPort: 8888
    protocol: TCP
    name: jupyter
  - port: 8001
    targetPort: 8001
    protocol: TCP
    name: llm-api
  type: ClusterIP
---
apiVersion: v1
kind: Service
metadata:
  name: fastapi-spark1-nodeport
  namespace: default
  labels:
    app: fastapi-spark1
    device: spark1
spec:
  selector:
    app: fastapi-spark1
  ports:
  - port: 8000
    targetPort: 8000
    nodePort: 30007
    protocol: TCP
    name: http
  - port: 8888
    targetPort: 8888
    nodePort: 30008
    protocol: TCP
    name: jupyter
  - port: 8001
    targetPort: 8001
    nodePort: 30009
    protocol: TCP
    name: llm-api
  type: NodePort
EOF

  if [ "$DEBUG" = "1" ]; then
    echo "Applying GPU-enabled SPARK1 FastAPI deployment..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /tmp/fastapi-spark1-gpu.yaml
    apply_exit=$?
  else
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /tmp/fastapi-spark1-gpu.yaml > /dev/null 2>&1
    apply_exit=$?
  fi

  if [ $apply_exit -eq 0 ]; then
    # Wait for GPU-enabled pod to be running
    echo -e "\nWaiting for GPU-enabled FastAPI pod to be ready..."
    for i in {1..60}; do
      if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -l app=fastapi-spark1 -o jsonpath='{.items[0].status.phase}' 2>/dev/null | grep -q "Running"; then
        echo -e "✅ GPU-enabled AI Workload pod is running on SPARK1"
        break
      fi
      sleep 5
    done
    if [ $i -eq 60 ]; then
      echo -e "❌ GPU-enabled AI Workload pod did not start within 5 minutes"
      exit 1
    fi
  else
    echo -e "❌ Failed to deploy GPU-enabled AI Workload on SPARK1"
    exit 1
  fi
fi
step_increment
print_divider
}






step_94() {
# --------------------------------------------------------------------------------
# STEP 94: FINAL DEPLOYMENT VERIFICATION AND LOGGING
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Running final verification and saving log..."
# FIX: Calling the function without output redirection.
capture_final_log "$FINAL_LOG_FILE" "$START_MESSAGE"
if [ $? -eq 0 ]; then # This checks the exit code of the previous command
    echo -en "✅[0m
"
    print_divider
    # Final success message, including the log file path
    echo -e "[32m🌟 SUCCESS: Deployment Complete and Verified! 🌟[0m"
    echo -e "Final status log saved to: [33m$FINAL_LOG_FILE[0m"
    echo -e "Please share this log file to confirm successful deployment."
    echo -e ""
    echo -e "[36m═══════════════════════════════════════════════════════════════════════════════[0m"
    echo -e "[36m                           🚀 ACCESS INFORMATION 🚀[0m"
    echo -e "[36m═══════════════════════════════════════════════════════════════════════════════[0m"
    echo -e ""
    echo -e "[33m📊 PostgreSQL Database:[0m"
    echo -e "   • Direct Access: [32m10.1.10.150:30432[0m"
    echo -e "   • Username: [32mpostgres[0m"
    echo -e "   • Password: [32mpostgres[0m"
    echo -e ""
    echo -e "[33m🖥️  pgAdmin Management Interface:[0m"
    echo -e "   • Web UI: [32mhttp://10.1.10.150:30080[0m"
    echo -e "   • Username: [32mpgadmin@pgadmin.org[0m"
    echo -e "   • Password: [32mpgadmin[0m"
    echo -e ""
    echo -e "[33m🤖 FastAPI Application (Nano GPU):[0m"
    echo -e "   • API Endpoint: [32mhttp://10.1.10.150:30002[0m"
    echo -e "   • Health Check: [32mhttp://10.1.10.150:30002/status[0m"
    echo -e "   • API Docs: [32mhttp://10.1.10.150:30002/docs[0m"
    echo -e ""
    echo -e "[33m📓 Jupyter Notebook (Nano GPU):[0m"
    echo -e "   • Jupyter Interface: [32mhttp://10.1.10.150:30003[0m"
    echo -e "   • Token: [32mNot required (open access)[0m"
    echo -e ""
    if [ "$INSTALL_AGX_AGENT" = true ]; then
        echo -e "[33m🤖 AI Workload (AGX GPU):[0m"
        echo -e "   • API Endpoint: [32mhttp://10.1.10.150:30004[0m"
        echo -e "   • Health Check: [32mhttp://10.1.10.150:30004/status[0m"
        echo -e "   • API Docs: [32mhttp://10.1.10.150:30004/docs[0m"
        echo -e "   • LLM API: [32mhttp://10.1.10.150:30006[0m"
        echo -e ""
        echo -e "[33m📓 Jupyter Notebook (AGX GPU):[0m"
        echo -e "   • Jupyter Interface: [32mhttp://10.1.10.150:30005[0m"
        echo -e "   • Token: [32mNot required (open access)[0m"
        echo -e ""
    fi
    echo -e "[36m═══════════════════════════════════════════════════════════════════════════════[0m"
else
    echo -e "[31m❌[0m"
    echo -e "[31mFATAL: Final verification failed. Check the log for details.[0m"
fi
step_increment
print_divider
}

step_95(){
# -------------------------------------------------------------------------
# STEP 95: Comprehensive Pod Verification
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Running comprehensive pod verification..."
echo ""
echo "🔍 COMPREHENSIVE POD VERIFICATION REPORT"
echo "=========================================="
echo ""
echo "📦 POD STATUS:"
echo "--------------"
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide
echo ""
echo "🌐 SERVICE ENDPOINTS:"
echo "---------------------"
# Test PostgreSQL database connectivity (not HTTP)
test_db_connection "PostgreSQL Database" "$TOWER_IP" "30432" "postgres" "postgres" "postgres"
# Test pgAdmin (302 redirect is normal - redirects to login)
test_http_endpoint "pgAdmin Web UI" "http://$TOWER_IP:30080" "200|302"
# Test Nano FastAPI endpoints
test_http_endpoint "Nano FastAPI Health" "http://$TOWER_IP:30002/health"
test_http_endpoint "Nano FastAPI Docs" "http://$TOWER_IP:30002/docs"
test_http_endpoint "Nano Jupyter" "http://$TOWER_IP:30003/jupyter" "200|302"
# Test AGX FastAPI endpoints
test_http_endpoint "AGX FastAPI Health" "http://$TOWER_IP:30004/health"
test_http_endpoint "AGX FastAPI Status" "http://$TOWER_IP:30004/status"
test_http_endpoint "AGX FastAPI Docs" "http://$TOWER_IP:30004/docs"
test_http_endpoint "AGX Jupyter" "http://$TOWER_IP:30005/jupyter" "200|302"
# Note: AGX LLM API (port 30006) is not implemented yet
echo "Testing AGX LLM API (http://$TOWER_IP:30006/docs)... ⚠️  SKIP (Not implemented)"
echo ""
echo "🔧 CLUSTER HEALTH:"
echo "------------------"
echo "Node Status:"
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes
echo ""
echo "Service Status:"
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get services
echo ""
echo "✅ VERIFICATION COMPLETE"
echo "bash ./verify-all_fixed.sh for detailed checks"
step_increment
print_divider
}


step_96(){
# ------------------------------------------------------------------------
# STEP 96: Final Success Message
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
step_15b
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
step_40
step_41
step_42
step_43
step_44
step_45
step_46
step_47
step_48
step_49
step_50
step_51
step_52
step_53
step_54
step_55
step_56
step_57
step_58
step_59
step_60
step_61
step_62
step_63
step_64
step_65
step_66
step_67
step_68
step_69
step_70
step_71
step_72
step_73
step_74
step_75
step_76
step_77
step_78
step_79
step_80
step_81
step_82
step_83
step_84
step_85
step_86
step_87
step_88
step_89
step_90
step_91
step_92
step_93
step_94
step_95
step_96



# End of script


