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
INSTALL_SERVER=false # Set to true to allow server uninstall/install steps to run

# Install K3s agent on nano
INSTALL_NANO_AGENT=false

# Install K3s agent on spark1
INSTALL_SPARK1_AGENT=true

# IP addresses
TOWER_IP="192.168.1.150"
NANO_IP="192.168.1.181"   # <-- Use the correct, reachable IP
AGX_IP="192.168.1.244"
SPARK1_IP="192.168.1.201"
SPARK2_IP="192.168.1.202"

# Registry settings
REGISTRY_IP="192.168.1.150"
REGISTRY_PORT="30500"
REGISTRY_PROTOCOL="http"  # "http" or "https"

# Database Configuration
POSTGRES_PASSWORD="postgres"  # PostgreSQL admin password
PGADMIN_PASSWORD="pgadmin"          # pgAdmin default password
PGADMIN_EMAIL="pgadmin@pgadmin.org" # pgAdmin default email

# Debug mode (0 for silent, 1 for verbose)
DEBUG=${DEBUG:-0}

# Define the initial script message to be logged
START_MESSAGE="Starting K3s Setup and FastAPI Deployment for SPARK1 in SILENT NORMAL mode..."

# SSH defaults (centralize options and key usage)
SSH_USER="${SSH_USER:-sanjay}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH_OPTS="-o StrictHostKeyChecking=no -o LogLevel=ERROR -i $SSH_KEY"
SSH_CMD="ssh $SSH_OPTS"
SCP_CMD="scp $SSH_OPTS"

# Helper to discover K3s server token. Will only fatal when an agent install is requested
get_k3s_token() {
  if [ -n "${TOKEN:-}" ]; then
    return 0
  fi

  if [ "$DEBUG" = "1" ]; then echo "Getting Token: $TOKEN"; fi
  TOKEN=$(sudo cat /var/lib/rancher/k3s/server/node-token 2>/dev/null || true)

  if [ -z "$TOKEN" ]; then
    echo -e "\n\033[31mFATAL: K3S token not found. Ensure /var/lib/rancher/k3s/server/node-token exists on the Tower host.\033[0m\n"
    exit 1
  fi
}

if [ "$DEBUG" = "1" ]; then
    echo "Starting K3s Setup and FastAPI Deployment in **VERBOSE DEBUG** mode..."
else
    echo "Starting K3s Setup and FastAPI Deployment in **SILENT NORMAL** mode..."
fi

# Initialize Dynamic Step Counter
CURRENT_STEP=1

# NOTE: Total steps count is 23 (agent cleanup and installation + GPU operator)
TOTAL_STEPS=23

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
  echo "Executing: $SSH_CMD $SSH_USER@$NANO_IP 'sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E \"fastapi-nano|Error|Fail\"'" >> "$log_file"
    # CORRECTED LINE 2: Change nsanjay to sanjay
  $SSH_CMD $SSH_USER@$NANO_IP "sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E 'fastapi-nano|Error|Fail'" >> "$log_file" 2>/dev/null


    # --- 6. CRITICAL: AGX K3S AGENT LOG ERRORS (Automated SSH Check) ---
    echo -e "
--- 6. CRITICAL: AGX K3S AGENT LOG ERRORS (Container Runtime Check) ---" >> "$log_file"
  echo "Executing: $SSH_CMD $SSH_USER@$AGX_IP 'sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E \"fastapi-agx|Error|Fail\"'" >> "$log_file"
    # Execute SSH command and pipe output directly to the log file
  $SSH_CMD $SSH_USER@$AGX_IP "sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E 'fastapi-agx|Error|Fail'" >> "$log_file" 2>/dev/null

    # --- 7. CRITICAL: SPARK1 K3S AGENT LOG ERRORS (Container Runtime Check) ---
    echo -e "
--- 7. CRITICAL: SPARK1 K3S AGENT LOG ERRORS (Container Runtime Check) ---" >> "$log_file"
  echo "Executing: $SSH_CMD $SSH_USER@$SPARK1_IP 'sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E \"fastapi-spark1|Error|Fail\"'" >> "$log_file"
    # Execute SSH command and pipe output directly to the log file
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E 'fastapi-spark1|Error|Fail'" >> "$log_file" 2>/dev/null

    echo -e "
--- 8. CRITICAL: SPARK2 K3S AGENT LOG ERRORS (Container Runtime Check) ---" >> "$log_file"
  echo "Executing: $SSH_CMD $SSH_USER@$SPARK1_IP 'sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E \"fastapi-spark1|Error|Fail\"'" >> "$log_file"
    # Execute SSH command and pipe output directly to the log file
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E 'fastapi-spark1|Error|Fail'" >> "$log_file" 2>/dev/null



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
  local node_name="${1:-}"
  local timeout=30  # Timeout in seconds
  local start_time=$(date +%s)
  local count=0
  if [ "$DEBUG" = "1" ]; then echo "Waiting for agent to be ready..."; fi

  if [ -n "$node_name" ]; then
    # Check the specific node's Ready condition
    while ! timeout 10 sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get node "$node_name" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null | grep -q "True"; do
      if [ "$DEBUG" = "1" ]; then
        local status=$(timeout 10 sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get node "$node_name" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Node not found")
        echo "DEBUG: Node $node_name status: '$status'"
      fi
      local current_time=$(date +%s)
      local elapsed=$((current_time - start_time))
      count=$((count + 1))
      if [ $elapsed -ge $timeout ] || [ $count -ge 30 ]; then
        echo "Agent $node_name did not join within $timeout seconds or after $count attempts - continuing anyway"
        return 1
      fi
      sleep 1
    done
  else
    # Fallback: wait until any node is Ready (legacy behavior)
    while ! timeout 10 sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes 2>/dev/null | grep -q "Ready"; do
      local current_time=$(date +%s)
      local elapsed=$((current_time - start_time))
      count=$((count + 1))
      if [ $elapsed -ge $timeout ] || [ $count -ge 30 ]; then
        echo "Agent did not join within $timeout seconds or after $count attempts - continuing anyway"
        return 1
      fi
      sleep 1
    done
  fi

  if [ "$DEBUG" = "1" ]; then echo "Agent is ready"; fi
  return 0
}

# Function to wait for GPU capacity
wait_for_gpu_capacity() {
  local timeout=30
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

# Function to wait for SPARK2 GPU capacity
wait_for_spark1_gpu_capacity() {
  local timeout=120
  local count=0
  if [ "$DEBUG" = "1" ]; then echo "Waiting for SPARK2 GPU capacity to be added..."; fi
  while ! sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get node spark1 -o jsonpath='{.status.capacity.nvidia\.com/gpu}' | grep -q '1'; do
    if [ $count -ge $timeout ]; then
      echo "SPARK2 GPU capacity not added within $timeout seconds"
      return 1
    fi
    sleep 5
    count=$((count + 5))
  done
    if [ "$DEBUG" = "1" ]; then echo "SPARK2 GPU capacity added"; fi
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


#=============================================================================================================
step_01(){
# -------------------------------------------------------------------------
# STEP 01: SPARK1 SSH Validation
# -------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  # Ensure we have the K3s server token available before attempting agent install
  get_k3s_token
  if [ "$DEBUG" = "1" ]; then
    echo "Running verbose SPARK1 SSH check..."
  fi
  step_echo_start "a" "spark1" "$SPARK1_IP" "Verifying SPARK1 SSH connectivity..."
  sleep 5
  # Test SSH connection by running 'hostname' on the SPARK1
  if $SSH_CMD $SSH_USER@$SPARK1_IP "hostname" > /dev/null 2>&1; then
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
  echo "{a} [spark1   ] [$SPARK1_IP] ${CURRENT_STEP}/${TOTAL_STEPS}. SPARK1 SSH verification skipped (not enabled)"
fi
if [ "$DEBUG" = "1" ]; then
  echo "SPARK1 SSH validation completed."
fi
step_increment
print_divider
}


step_02(){
# -------------------------------------------------------------------------
# STEP 02: SPARK2 ARP/PING CHECK
# -------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Running SPARK1 network connectivity check..."
    sleep 5
    echo "Pinging SPARK1 at $SPARK1_IP to verify network reachability..."
  fi
  step_echo_start "a" "spark1" "$SPARK1_IP" "Verifying SPARK1 network reachability (ARP/Ping)..."
  sleep 5
  run_network_check $SPARK1_IP "SPARK1"
fi
if [ "$DEBUG" = "1" ]; then
  echo "SPARK2 network reachability check completed."
fi
step_increment
print_divider
}


#=============================================================================================================
step_03(){
# -------------------------------------------------------------------------
# STEP 03: Uninstall K3s Agent on SPARK1 (Comprehensive Cleanup)
# -------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Uninstalling Agent on SPARK1... (Verbose output below)"
    sleep 5
    # Delete existing deployments and services if they exist to ensure clean uninstall
    echo "Deleting existing fastapi-spark1 deployment..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete job fastapi-spark1 --ignore-not-found=true
    echo "Deleting existing fastapi-spark1-service..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-spark1-service --ignore-not-found=true
    echo "Deleting existing fastapi-spark1-nodeport..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-spark1-nodeport --ignore-not-found=true
    echo "Deleting stale spark1 node entry from cluster..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete node spark1 --ignore-not-found=true
    # Check if k3s binaries exist before attempting uninstall
    echo "Checking for k3s-agent-uninstall.sh on SPARK2..."
    if $SSH_CMD $SSH_USER@$SPARK1_IP "test -x /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
      echo "Found k3s-agent-uninstall.sh, running uninstall..."
      $SSH_CMD $SSH_USER@$SPARK1_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh"
    else
      echo "k3s-agent-uninstall.sh not found on SPARK2 - no uninstall needed"
    fi
    # Additional manual cleanup
    echo "Performing additional agent cleanup..."
    echo "Stopping K3s agent service if running..."
    $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl stop k3s-agent" >/dev/null 2>&1 || true
    echo "Removing remaining K3s agent files and directories..."
    $SSH_CMD $SSH_USER@$SPARK1_IP "sudo rm -rf /var/lib/rancher/k3s/agent" >/dev/null 2>&1 || true
    $SSH_CMD $SSH_USER@$SPARK1_IP "sudo rm -rf /etc/rancher/k3s" >/dev/null 2>&1 || true
    $SSH_CMD $SSH_USER@$SPARK1_IP "sudo rm -f /etc/systemd/system/k3s-agent.service" >/dev/null 2>&1 || true
    $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl daemon-reload" >/dev/null 2>&1 || true
  else
    step_echo_start "a" "spark1" "$SPARK1_IP" "Uninstalling K3s agent on spark1 (comprehensive cleanup)..."
    sleep 5
    # Delete existing deployments and services if they exist to ensure clean uninstall
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete deployment fastapi-spark1 --ignore-not-found=true >/dev/null 2>&1 || true
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-spark1-service --ignore-not-found=true >/dev/null 2>&1 || true
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-spark1-nodeport --ignore-not-found=true >/dev/null 2>&1 || true
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete node spark1 --ignore-not-found=true >/dev/null 2>&1 || true
    if $SSH_CMD $SSH_USER@$SPARK1_IP "test -x /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
      if $SSH_CMD $SSH_USER@$SPARK1_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
        echo -e "[32m✅[0m"
      else
        echo -e "[32m✅[0m"  # Print checkmark anyway, as uninstall may have partial success
      fi
    else
      echo -e "[32m✅[0m"  # Print checkmark if uninstall script doesn't exist (already uninstalled)
    fi
    # Additional manual cleanup (silent)
    $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl stop k3s-agent" >/dev/null 2>&1 || true
    $SSH_CMD $SSH_USER@$SPARK1_IP "sudo rm -rf /var/lib/rancher/k3s/agent" >/dev/null 2>&1 || true
    $SSH_CMD $SSH_USER@$SPARK1_IP "sudo rm -rf /etc/rancher/k3s" >/dev/null 2>&1 || true
    $SSH_CMD $SSH_USER@$SPARK1_IP "sudo rm -f /etc/systemd/system/k3s-agent.service" >/dev/null 2>&1 || true
    $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl daemon-reload" >/dev/null 2>&1 || true
  fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "K3s agent uninstall and cleanup on SPARK2 completed."
fi
step_increment
print_divider
}

step_04(){
# -------------------------------------------------------------------------
# STEP 04: Reinstall SPARK1 Agent (BINARY TRANSFER INSTALL)
# -------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  # Use the official k3s install script for SPARK2
  K3S_REINSTALL_CMD="sudo curl -sfL https://get.k3s.io | K3S_URL='https://$TOWER_IP:6443' K3S_TOKEN='$TOKEN' sh -"
  echo "Installing Agent on SPARK1 using official k3s install script..."
  sleep 5
  if [ "$DEBUG" = "1" ]; then
    echo "Running k3s install script with server URL and token..."
    echo ""
    $SSH_CMD $SSH_USER@$SPARK1_IP "$K3S_REINSTALL_CMD"
    echo "Agent installation completed."
  else
    step_echo_start "a" "spark1" "$SPARK1_IP" "Reinstalling K3s agent on spark1..."
    sleep 5
    echo ""
    $SSH_CMD $SSH_USER@$SPARK1_IP "$K3S_REINSTALL_CMD" 
  fi
  wait_for_agent spark1
fi
step_increment
print_divider
}



step_05(){
# =========================================================================
# STEP 05: Systemd Service Override (force correct server/node IP) SPARK1
# =========================================================================
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
if [ "$DEBUG" = "1" ]; then
  echo "Forcing K3s SPARK1 agent to use correct server IP..."
  sleep 5
  echo "Adding SPARK1 host key to known_hosts..."
  ssh-keyscan -H $SPARK1_IP >> ~/.ssh/known_hosts 2>/dev/null
  echo "Creating systemd override directory..."
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo mkdir -p /etc/systemd/system/k3s-agent.service.d/"
  echo "Creating systemd override file with correct server URL and node IP..."
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo tee /etc/systemd/system/k3s-agent.service.d/override.conf > /dev/null" << EOF
[Service]
Environment="K3S_URL=https://$TOWER_IP:6443"
Environment="K3S_NODE_IP=$SPARK1_IP"
EOF
  echo "Reloading systemd daemon and restarting k3s-agent..."
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl daemon-reload && sudo timeout 30 systemctl restart k3s-agent" > /dev/null 2>&1
  echo "Waiting for SPARK1 agent to rejoin with correct configuration..."
  wait_for_agent spark1
  echo "SPARK1 agent service override completed successfully"
else
  step_echo_start "a" "spark1" "$SPARK1_IP" "Forcing K3s spark1 agent to use correct server IP..."

  # Add SPARK1 host key to known_hosts to avoid SSH warning
  ssh-keyscan -H $SPARK1_IP >> ~/.ssh/known_hosts 2>/dev/null

  # Create systemd override directory and file directly instead of using systemctl edit
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo mkdir -p /etc/systemd/system/k3s-agent.service.d/" > /dev/null 2>&1

  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo tee /etc/systemd/system/k3s-agent.service.d/override.conf > /dev/null" << EOF
[Service]
Environment="K3S_URL=https://$TOWER_IP:6443"
Environment="K3S_NODE_IP=$SPARK1_IP"
EOF

  # Reload daemon and restart the service
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl daemon-reload && sudo timeout 30 systemctl restart k3s-agent" > /dev/null 2>&1

  # Check the exit status of the SSH command
  if [ $? -eq 0 ]; then
      # Wait for the agent to re-join and be ready
    wait_for_agent spark1
    echo -e "✅\x1b[0m"
  else
    echo -e "❌\x1b[0m"
    echo -e "\x1b[31mFATAL: Failed to overwrite SPARK1 service file.\x1b[0m"
    exit 1
  fi
fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "K3s SPARK1 agent service override completed."
fi
step_increment
print_divider
}




step_06(){
# -------------------------------------------------------------------------
# STEP 06: Create Registry Config Directory SPARK1
# -------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Creating registry configuration directory on SPARK1..."
    sleep 5
    echo "Creating /etc/rancher/k3s/ directory for registry configuration..."
    $SSH_CMD $SSH_USER@$SPARK1_IP "sudo mkdir -p /etc/rancher/k3s/"
    echo "Registry config directory created successfully"
  else
    step_echo_start "a" "spark1" "$SPARK1_IP" "Creating spark1 registry configuration directory..."
    sleep 5
    if $SSH_CMD $SSH_USER@$SPARK1_IP "sudo mkdir -p /etc/rancher/k3s/" > /dev/null 2>&1; then
      echo -en " ✅\033[0m\n"
    else
      echo -e "\033[31m❌ Failed to create registry configuration directory on SPARK2\033[0m"
      exit 1
    fi
  fi
  if [ "$DEBUG" = "1" ]; then
    echo "Registry configuration directory creation completed."
  fi
  step_increment
  print_divider
fi
}





step_07(){
# -------------------------------------------------------------------------
# STEP 07: Configure Registry for SPARK1 (K3s + Containerd)
# -------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Configuring registry for SPARK1..."
    sleep 5
    echo "Registry protocol: $REGISTRY_PROTOCOL"
    echo "Registry IP: $REGISTRY_IP:$REGISTRY_PORT"
    if [[ "$REGISTRY_PROTOCOL" == "https" ]]; then
      echo "Setting up HTTPS registry configuration..."
      $SSH_CMD $SSH_USER@$SPARK1_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
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
" && \
      echo "Creating containerd certs directory..." && \
      $SSH_CMD $SSH_USER@$SPARK1_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT" && \
      echo "Creating containerd hosts.toml file..." && \
      $SSH_CMD $SSH_USER@$SPARK1_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"https://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
  ca = \"/etc/docker/certs.d/$REGISTRY_IP/ca.crt\"
  client = [\"/etc/docker/certs.d/$REGISTRY_IP/registry.crt\", \"/etc/docker/certs.d/$REGISTRY_IP/registry.key\"]
EOF
"
    else
      echo "Setting up HTTP registry configuration..."
      $SSH_CMD $SSH_USER@$SPARK1_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
mirrors:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    endpoint:
      - \"http://$REGISTRY_IP:$REGISTRY_PORT\"

configs:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    tls:
      insecure_skip_verify: true
EOF
" && \
      echo "Creating containerd certs directory..." && \
      $SSH_CMD $SSH_USER@$SPARK1_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT" && \
      echo "Creating containerd hosts.toml file..." && \
      $SSH_CMD $SSH_USER@$SPARK1_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"http://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
EOF
" && \
      echo "Creating complete containerd config with NVIDIA runtime and registry..." && \
      $SSH_CMD $SSH_USER@$SPARK1_IP "sudo tee /etc/containerd/config.toml > /dev/null << 'EOF'
version = 2
[plugins.\"io.containerd.grpc.v1.cri\"]
  sandbox_image = \"registry.k8s.io/pause:3.6\"
  [plugins.\"io.containerd.grpc.v1.cri\".containerd]
    [plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes]
      [plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc]
        runtime_type = \"io.containerd.runc.v2\"
        [plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc.options]
          SystemdCgroup = true
      [plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.nvidia]
        runtime_type = \"io.containerd.runc.v2\"
        [plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.nvidia.options]
          BinaryName = \"/usr/bin/nvidia-container-runtime\"
  [plugins.\"io.containerd.grpc.v1.cri\".registry]
    [plugins.\"io.containerd.grpc.v1.cri\".registry.configs]
      [plugins.\"io.containerd.grpc.v1.cri\".registry.configs.\"$REGISTRY_IP:$REGISTRY_PORT\"]
        insecure_skip_verify = true
        [plugins.\"io.containerd.grpc.v1.cri\".registry.configs.\"$REGISTRY_IP:$REGISTRY_PORT\".tls]
          insecure_skip_verify = true
EOF"
    fi
    echo "Registry configuration completed (K3s registries.yaml + containerd config.toml)"
  else
    step_echo_start "a" "spark1" "$SPARK1_IP" "Configuring registry for spark1 (K3s + containerd)..."
    sleep 5
    if [[ "$REGISTRY_PROTOCOL" == "https" ]]; then
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
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
" > /dev/null 2>&1 && \
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT" > /dev/null 2>&1 && \
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"https://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
  ca = \"/etc/docker/certs.d/$REGISTRY_IP/ca.crt\"
  client = [\"/etc/docker/certs.d/$REGISTRY_IP/registry.crt\", \"/etc/docker/certs.d/$REGISTRY_IP/registry.key\"]
EOF
" > /dev/null 2>&1
    else
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
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
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT" > /dev/null 2>&1 && \
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"http://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
EOF
" > /dev/null 2>&1 && \
  echo "Creating complete containerd config with NVIDIA runtime and registry..." && \
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo tee /etc/containerd/config.toml > /dev/null << 'EOF'
version = 2
[plugins.\"io.containerd.grpc.v1.cri\"]
  sandbox_image = \"registry.k8s.io/pause:3.6\"
  [plugins.\"io.containerd.grpc.v1.cri\".containerd]
    [plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes]
      [plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc]
        runtime_type = \"io.containerd.runc.v2\"
        [plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc.options]
          SystemdCgroup = true
      [plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.nvidia]
        runtime_type = \"io.containerd.runc.v2\"
        [plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.nvidia.options]
          BinaryName = \"/usr/bin/nvidia-container-runtime\"
  [plugins.\"io.containerd.grpc.v1.cri\".registry]
    [plugins.\"io.containerd.grpc.v1.cri\".registry.configs]
      [plugins.\"io.containerd.grpc.v1.cri\".registry.configs.\"$REGISTRY_IP:$REGISTRY_PORT\"]
        insecure_skip_verify = true
        [plugins.\"io.containerd.grpc.v1.cri\".registry.configs.\"$REGISTRY_IP:$REGISTRY_PORT\".tls]
          insecure_skip_verify = true
EOF"
    fi
    if [ $? -eq 0 ]; then
      echo -e "\e[32m✅\e[0m"
    else
      echo -e "\e[31m❌ Failed to configure registry for SPARK1\e[0m"
      exit 1
    fi
  fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "Registry configuration for SPARK1 completed (K3s + containerd)."
fi
step_increment
print_divider
}




step_08(){
# --------------------------------------------------------------------------------
# STEP 08: Restart Containerd After Config SPARK1
# --------------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Restarting containerd after configuration..."
    sleep 5
    echo "Running: sudo systemctl restart containerd on SPARK1"
    $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl restart containerd"
    echo "Waiting for containerd to be active..."
    sleep 10
    if $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl is-active --quiet containerd"; then
      echo "Containerd restarted successfully"
    else
      echo "Failed to restart containerd"
      exit 1
    fi
  else
  step_echo_start "a" "spark1" "$SPARK1_IP" "Restarting containerd after config..."
  sleep 5
  if $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl restart containerd" > /dev/null 2>&1; then
    sleep 10
    if $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl is-active --quiet containerd"; then
      echo -e "✅"
    else
      echo -e "[31m❌ Containerd restart failed[0m"
      exit 1
    fi
  else
    echo -e "[31m❌ Containerd restart command failed[0m"
    exit 1
  fi
fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "Containerd restart after config completed."
fi
step_increment
print_divider
}




step_09(){
# -------------------------------------------------------------------------
# STEP 09: Restart Agent After Registry Config SPARK1
# -------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Restarting K3s agent after registry configuration..."
    sleep 5
    echo "Running: sudo systemctl restart k3s-agent on SPARK1"
    $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl restart k3s-agent"
    echo "Waiting for SPARK1 agent to be ready after restart..."
    wait_for_agent spark1
    echo "SPARK1 agent restarted successfully"
  else
  step_echo_start "a" "spark1" "$SPARK1_IP" "Restarting K3s agent after registry config..."
  sleep 5
  # Use timeout to prevent hanging on systemctl restart
  if $SSH_CMD $SSH_USER@$SPARK1_IP "sudo timeout 30 systemctl restart k3s-agent" > /dev/null 2>&1; then
    wait_for_agent spark1
    echo -e "✅"
  else
    echo -e "[31m❌ Service restart failed or timed out[0m"
    echo -e "[33m⚠️  Continuing anyway - agent may restart on its own[0m"
    echo -e "⚠️"
  fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "K3s agent restart after registry config completed."
fi
fi
step_increment
print_divider

}




step_23(){
# --------------------------------------------------------------------------------
# STEP 23: Restart K3s agent on SPARK1 (workaround for containerd config)
# --------------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
if [ "$DEBUG" = "1" ]; then
  echo "Restarting K3s agent on SPARK1 after containerd configuration..."
  sleep 5
  echo "Stopping k3s-agent service..."
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl stop k3s-agent"
  echo "Starting k3s-agent service..."
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl start k3s-agent"
  echo "Waiting for SPARK1 agent to be ready..."
  wait_for_agent spark1
  echo "SPARK1 agent restart completed successfully"
else
  step_echo_start "a" "spark1" "$SPARK1_IP" "Restarting K3s agent after containerd config..."
  sleep 5
  if $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl stop k3s-agent" > /dev/null 2>&1 && $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl start k3s-agent" > /dev/null 2>&1; then
    wait_for_agent spark1
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌ Failed to restart K3s agent after containerd config[0m"
    exit 1
  fi
fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "K3s agent restart after containerd config completed."
fi
step_increment
print_divider
}




step_23(){
# --------------------------------------------------------------------------------
# STEP 09 (CLEANUP): Force-delete conflicting components (excluding GPU Operator)
# --------------------------------------------------------------------------------
# NOTE: For DGX Spark systems with pre-installed NVIDIA GPU drivers and NVIDIA Container Toolkit,
# refer to: https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/getting-started.html#pre-installed-nvidia-gpu-drivers-and-nvidia-container-toolkit
# This ensures proper GPU Operator installation on systems with factory-installed NVIDIA components.
# GPU Operator components are preserved and will be properly configured in STEP 16.
if [ "$DEBUG" = "1" ]; then
  echo "Force-deleting conflicting components (preserving GPU Operator for proper installation)..."
  sleep 5
  
  # --- App Cleanup Only (GPU Operator preserved for proper installation) ---
  echo "Force-deleting old 'fastapi-spark1' application components..."
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete deployment fastapi-spark1 -n default --grace-period=0 --force --ignore-not-found=true
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete pod -n default -l app=fastapi-spark1 --grace-period=0 --force --ignore-not-found=true
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-spark1-service -n default --ignore-not-found=true
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-spark1-nodeport -n default --ignore-not-found=true

  echo "Waiting for old components to terminate..."
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml wait --for=delete deployment fastapi-spark1 -n default --timeout=60s --ignore-not-found=true
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml wait --for=delete pod -n default -l app=fastapi-spark1 --timeout=60s --ignore-not-found=true
  echo "Old components terminated."

else
  step_echo_start "s" "tower" "$TOWER_IP" "Force-deleting conflicting components (preserving GPU Operator)..."
  sleep 5
  
  # --- App Cleanup Only (GPU Operator preserved for proper installation) ---
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete deployment fastapi-spark1 -n spark1 --grace-period=0 --force --ignore-not-found=true > /dev/null 2>&1
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete pod -n spark1 -l app=fastapi-spark1 --grace-period=0 --force --ignore-not-found=true > /dev/null 2>&1
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-spark1-service -n spark1 --ignore-not-found=true > /dev/null 2>&1
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-spark1-nodeport -n spark1 --ignore-not-found=true > /dev/null 2>&1

  echo -e "\nWaiting for old components to terminate (this may take a minute)..."
  # --- Wait for App Only ---
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml wait --for=delete deployment fastapi-spark1 -n spark1 --timeout=60s --ignore-not-found=true > /dev/null 2>&1
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml wait --for=delete pod -n spark1 -l app=fastapi-spark1 --timeout=60s --ignore-not-found=true > /dev/null 2>&1
  
  echo -e "✅"
fi
if [ "$DEBUG" = "1" ]; then
  echo "NVIDIA & App component cleanup completed."
fi
step_increment
print_divider
}

step_23(){
# --------------------------------------------------------------------------------
# STEP 23: Force Restart K3s Agent and Containerd on SPARK2
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Performing forceful restart of k3s-agent and containerd on SPARK2..."
  sleep 5
  
  echo "Stopping k3s-agent service..."
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl stop k3s-agent"
  sleep 5
  
  echo "Forcefully killing remaining k3s/containerd processes..."
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo pkill -9 k3s"
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo pkill -9 containerd"
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo pkill -9 containerd-shim"
  sleep 5
  
  echo "Starting k3s-agent service..."
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl start k3s-agent"
  
  echo "Waiting 60 seconds for agent to stabilize..."
  sleep 60
  echo "Checking agent status..."
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl status k3s-agent --no-pager"

else
  step_echo_start "a" "spark1" "$SPARK1_IP" "Force restarting K3s agent & containerd..."
  
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl stop k3s-agent" > /dev/null 2>&1
  sleep 5
  
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo pkill -9 k3s" > /dev/null 2>&1
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo pkill -9 containerd" > /dev/null 2>&1
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo pkill -9 containerd-shim" > /dev/null 2>&1
  sleep 5
  
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl start k3s-agent" > /dev/null 2>&1
  
  echo -e "\nWaiting 60 seconds for agent to stabilize..."
  sleep 60
  
  # Check status in silent mode too, maybe just check for active state
  if $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl is-active k3s-agent" | grep -q "active"; then
    echo -e "✅ Agent restarted successfully."
  else
    echo -e "❌ Agent failed to restart after forceful stop."
    # Optionally add exit 1 here if this is critical
  fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "Forceful agent restart completed."
fi
step_increment
print_divider
}


step_23(){
# --------------------------------------------------------------------------------
# STEP 23: Install NVIDIA Device Plugin for GPU Support
# --------------------------------------------------------------------------------
  if [ "$DEBUG" = "1" ]; then
    echo "Installing NVIDIA Device Plugin for GPU support..."
    sleep 5
    echo "Applying NVIDIA device plugin DaemonSet YAML..."
    cat <<EOF | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: nvidia-device-plugin-spark1
  namespace: kube-system

spec:
  selector:
    matchLabels:
      name: nvidia-device-plugin-spark1
  template:
    metadata:
      labels:
        name: nvidia-device-plugin-spark1

    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: kubernetes.io/hostname
                operator: In
                values:
                - spark1
      containers:
      - env:
        - name: DEVICE_DISCOVERY_STRATEGY
          value: nvml
        - name: FAIL_ON_INIT_ERROR
          value: "false"
        image: nvcr.io/nvidia/k8s-device-plugin:v0.18.0
        name: nvidia-device-plugin-ctr
        securityContext:
          privileged: true
        volumeMounts:
        - mountPath: /var/lib/kubelet/device-plugins
          name: device-plugin
        - mountPath: /sys
          name: sys
        - mountPath: /usr/lib
          name: usr-lib
        - mountPath: /dev/nvidia0
          name: nvidia-dev
        - mountPath: /dev/nvidiactl
          name: nvidia-ctl
        - mountPath: /dev/nvidia-modeset
          name: nvidia-modeset
      tolerations:
      - effect: NoSchedule
        key: nvidia.com/gpu
        operator: Exists
      - key: CriticalAddonsOnly
        operator: Exists

      volumes:
      - hostPath:
          path: /var/lib/kubelet/device-plugins
          type: ""
        name: device-plugin
      - hostPath:
          path: /sys
          type: ""
        name: sys
      - hostPath:
          path: /usr/lib
          type: ""
        name: usr-lib
      - hostPath:
          path: /dev/nvidia0
          type: ""
        name: nvidia-dev
      - hostPath:
          path: /dev/nvidiactl
          type: ""
        name: nvidia-ctl
      - hostPath:
          path: /dev/nvidia-modeset
          type: ""
        name: nvidia-modeset
EOF
    if [ $? -eq 0 ]; then
      echo "NVIDIA Device Plugin applied successfully (unchanged if already exists)"
    else
      echo "Failed to apply NVIDIA Device Plugin"
      exit 1
    fi
  else
    step_echo_start "s" "tower" "$TOWER_IP" "Installing NVIDIA Device Plugin for GPU support..."
    sleep 5
    # Apply the NVIDIA device plugin DaemonSet with correct configuration for Jetson AGX
    cat <<EOF | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f - > /dev/null 2>&1
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: nvidia-device-plugin-spark1
  namespace: kube-system

spec:
  selector:
    matchLabels:
      name: nvidia-device-plugin-spark1
  template:
    metadata:
      labels:
        name: nvidia-device-plugin-spark1

    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: kubernetes.io/hostname
                operator: In
                values:
                - spark1
      containers:
      - env:
        - name: DEVICE_DISCOVERY_STRATEGY
          value: nvml
        - name: FAIL_ON_INIT_ERROR
          value: "false"
        image: nvcr.io/nvidia/k8s-device-plugin:v0.14.1
        name: nvidia-device-plugin-ctr
        securityContext:
          privileged: true
        volumeMounts:
        - mountPath: /var/lib/kubelet/device-plugins
          name: device-plugin
        - mountPath: /sys
          name: sys
        - mountPath: /usr/lib
          name: usr-lib
        - mountPath: /dev/nvidia0
          name: nvidia-dev
        - mountPath: /dev/nvidiactl
          name: nvidia-ctl
        - mountPath: /dev/nvidia-modeset
          name: nvidia-modeset
      tolerations:
      - effect: NoSchedule
        key: nvidia.com/gpu
        operator: Exists
      - key: CriticalAddonsOnly
        operator: Exists

      volumes:
      - hostPath:
          path: /var/lib/kubelet/device-plugins
          type: ""
        name: device-plugin
      - hostPath:
          path: /sys
          type: ""
        name: sys
      - hostPath:
          path: /usr/lib
          type: ""
        name: usr-lib
      - hostPath:
          path: /dev/nvidia0
          type: ""
        name: nvidia-dev
      - hostPath:
          path: /dev/nvidiactl
          type: ""
        name: nvidia-ctl
      - hostPath:
          path: /dev/nvidia-modeset
          type: ""
        name: nvidia-modeset
EOF
    if [ $? -eq 0 ]; then
      echo -e "\n✅ NVIDIA Device Plugin applied (unchanged if already exists)"
    else
      echo -e "\n❌ Failed to apply NVIDIA Device Plugin"
      exit 1
    fi
  fi
if [ "$DEBUG" = "1" ]; then
  echo "NVIDIA Device Plugin installation completed."
fi
step_increment
print_divider
}

step_23(){
# --------------------------------------------------------------------------------
# STEP 23: Clean up FastAPI SPARK2 Docker image tags
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Cleaning up FastAPI SPARK2 Docker image tags..."
  sleep 5
  echo "Removing existing Docker images for fastapi-spark1..."
  sudo docker rmi "$REGISTRY_IP:$REGISTRY_PORT/spark1:latest" > /dev/null 2>&1
  echo "Docker image cleanup complete"
else
  step_echo_start "s" "tower" "$TOWER_IP" "Cleaning up FastAPI SPARK2 Docker image tags..."
  sleep 5
  if sudo docker rmi "$REGISTRY_IP:$REGISTRY_PORT/spark1:latest" > /dev/null 2>&1; then
    echo -e "✅"
  else
    echo -e "✅" # Always show success, even if image didn't exist
  fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "FastAPI SPARK2 Docker image cleanup completed."
fi
step_increment
print_divider
}


step_23(){
# --------------------------------------------------------------------------------
# STEP 23: Build SPARK2 Docker image
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Building SPARK2 Docker image..."
  sleep 5
  echo "Running docker build for fastapi-spark1..."
  sudo docker build -f dockerfile.spark1.wheels -t spark1:latest .
  if [ $? -eq 0 ]; then
    echo "SPARK2 Docker image built successfully"
  else
    echo "Failed to build SPARK2 Docker image"
    exit 1
  fi
else
  step_echo_start "s" "tower" "$TOWER_IP" "Building SPARK2 Docker image for ARM64 and AMD64..."
  sleep 5
  output=$(sudo docker buildx build --platform linux/arm64 -f dockerfile.spark1.wheels -t spark1:latest . --load 2>&1)
  if [ $? -eq 0 ]; then
    echo -e "✅"
  else
    echo -e "❌"
    echo "$output"
    exit 1
  fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "SPARK2 Docker image build completed."
fi
step_increment
print_divider
}


step_23(){
# --------------------------------------------------------------------------------
# STEP 23: Tag SPARK2 Docker image
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Tagging SPARK2 Docker image..."
  sleep 5
  echo "Tagging spark1:latest as $REGISTRY_IP:$REGISTRY_PORT/spark1:latest"
  sudo docker tag spark1:latest "$REGISTRY_IP:$REGISTRY_PORT/spark1:latest"
  if [ $? -eq 0 ]; then
    echo "SPARK2 Docker image tagged successfully"
  else
    echo "Failed to tag SPARK2 Docker image"
    exit 1
  fi
else
  step_echo_start "s" "tower" "$TOWER_IP" "Tagging SPARK2 Docker image..."
  sleep 5
  if sudo docker tag spark1:latest "$REGISTRY_IP:$REGISTRY_PORT/spark1:latest" > /dev/null 2>&1; then
    echo -e "✅"
  else
    echo -e "❌"
    exit 1
  fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "SPARK2 Docker image tagging completed."
fi
step_increment
print_divider
}


step_23(){
# --------------------------------------------------------------------------------
# STEP 23: Push Docker image to registry
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Pushing Docker image to registry..."
  sleep 5
  echo "Pushing $REGISTRY_IP:$REGISTRY_PORT/spark1:latest"
  sudo docker push "$REGISTRY_IP:$REGISTRY_PORT/spark1:latest"
  if [ $? -eq 0 ]; then
    echo "Docker image pushed successfully"
  else
    echo "Failed to push Docker image"
    exit 1
  fi
else
  step_echo_start "s" "tower" "$TOWER_IP" "Pushing Docker image to registry..."
  sleep 5
  if sudo docker push "$REGISTRY_IP:$REGISTRY_PORT/spark1:latest" > /dev/null 2>&1; then
    echo -e "✅"
  else
    echo -e "❌"
    exit 1
  fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "Docker image push to registry completed."
fi
step_increment
print_divider
}




step_23(){
# --------------------------------------------------------------------------------
# STEP 23: Install NVIDIA GPU Operator for DGX Spark (Pre-installed Drivers) - v25.10.0
# --------------------------------------------------------------------------------
# Installs GPU Operator with configuration for pre-installed NVIDIA drivers and container toolkit
# as documented at: https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/getting-started.html#pre-installed-nvidia-gpu-drivers-and-nvidia-container-toolkit
if [ "$DEBUG" = "1" ]; then
  echo "Installing NVIDIA GPU Operator v25.10.0 for DGX Spark with pre-installed drivers..."
  sleep 5
  
  echo "Checking if Helm is installed..."
  if ! command -v helm &> /dev/null; then
    echo "Helm not found. Installing Helm..."
    curl https://get.helm.sh/helm-v3.14.0-linux-amd64.tar.gz -o helm.tar.gz
    tar -zxvf helm.tar.gz
    sudo mv linux-amd64/helm /usr/local/bin/helm
    rm -rf linux-amd64 helm.tar.gz
  fi
  
  echo "Adding NVIDIA Helm repository..."
  helm repo add nvidia https://helm.ngc.nvidia.com/nvidia --force-update
  helm repo update
  
  echo "Installing GPU Operator with pre-installed driver configuration..."
  helm upgrade --install gpu-operator nvidia/gpu-operator \
    --version=v25.10.0 \
    --create-namespace \
    --namespace gpu-operator \
    --set driver.enabled=false \
    --set toolkit.enabled=true \
    --set operator.defaultRuntime=containerd \
    --wait --timeout=600s
  
  if [ $? -eq 0 ]; then
    echo "GPU Operator installed successfully"
  else
    echo "Failed to install GPU Operator"
    exit 1
  fi
  
  echo "Waiting for GPU Operator pods to be ready..."
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml wait --for=condition=ready pod -l app.kubernetes.io/name=gpu-operator --namespace gpu-operator --timeout=300s
  
else
  step_echo_start "s" "tower" "$TOWER_IP" "Installing NVIDIA GPU Operator v25.10.0 (pre-installed drivers)..."
  sleep 5
  
  if ! command -v helm &> /dev/null; then
    curl https://get.helm.sh/helm-v3.14.0-linux-amd64.tar.gz -o helm.tar.gz > /dev/null 2>&1
    tar -zxvf helm.tar.gz > /dev/null 2>&1
    sudo mv linux-amd64/helm /usr/local/bin/helm > /dev/null 2>&1
    rm -rf linux-amd64 helm.tar.gz > /dev/null 2>&1
  fi
  
  helm repo add nvidia https://helm.ngc.nvidia.com/nvidia --force-update > /dev/null 2>&1
  helm repo update > /dev/null 2>&1
  
  output=$(helm upgrade --install gpu-operator nvidia/gpu-operator \
    --version=v25.10.0 \
    --create-namespace \
    --namespace gpu-operator \
    --set driver.enabled=false \
    --set toolkit.enabled=true \
    --set operator.defaultRuntime=containerd \
    --wait --timeout=600s 2>&1)
  
  if [ $? -eq 0 ]; then
    echo -e "✅"
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml wait --for=condition=ready pod -l app.kubernetes.io/name=gpu-operator --namespace gpu-operator --timeout=300s > /dev/null 2>&1
  else
    echo -e "❌"
    echo "$output"
    exit 1
  fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "GPU Operator installation completed."
fi
step_increment
print_divider
}




step_23(){
# --------------------------------------------------------------------------------
# STEP 23: Deploy FastAPI to SPARK1
# --------------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Deploying FastAPI to SPARK2..."
    sleep 5
    echo "Deleting existing fastapi-spark1 pod if exists..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete pod fastapi-spark1 --ignore-not-found=true
    echo "Deleting existing spark1 job if exists..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete job spark1 --ignore-not-found=true
    echo "Applying deployment YAML for fastapi-spark1 from file..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f fastapi-deployment-spark1.yaml
    if [ $? -eq 0 ]; then
      echo "FastAPI deployment to SPARK1 applied successfully"
    else
      echo "Failed to apply FastAPI deployment to SPARK1"
      exit 1
    fi
  else
    step_echo_start "s" "tower" "$TOWER_IP" "Deploying FastAPI to SPARK1..."
    sleep 5
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete pod fastapi-spark1 --ignore-not-found=true > /dev/null 2>&1
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete job spark1 --ignore-not-found=true > /dev/null 2>&1
    output=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f fastapi-deployment-spark1.yaml 2>&1)
    if [ $? -eq 0 ]; then
      echo -e "✅"
    else
      echo -e "❌"
      echo "$output"
      exit 1
    fi
  fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "FastAPI deployment to SPARK2 completed."
fi
step_increment
print_divider
}



step_23(){
# --------------------------------------------------------------------------------
# STEP 23: SPARK1 GPU CAPACITY VERIFICATION
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




step_23(){
# --------------------------------------------------------------------------------
# STEP 23: SPARK1 GPU RESOURCE CLEANUP
# --------------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  step_echo_start "a" "spark1" "$SPARK1_IP" "Cleaning up SPARK1 GPU resources for deployment..."

  # Allow time for resources to be released
  sleep 5

  # Function to backup containerd configuration
  backup_containerd_config() {
    local backup_file="/var/lib/rancher/k3s/agent/etc/containerd/config.toml.backup.$(date +%Y%m%d_%H%M%S)"
    if $SSH_CMD $SSH_USER@$SPARK1_IP "sudo test -f /var/lib/rancher/k3s/agent/etc/containerd/config.toml"; then
      if [ "$DEBUG" = "1" ]; then
        echo "Backing up existing containerd config to $backup_file"
      fi
      $SSH_CMD $SSH_USER@$SPARK1_IP "sudo cp /var/lib/rancher/k3s/agent/etc/containerd/config.toml $backup_file" 2>/dev/null || true
      echo "$backup_file"
    else
      echo ""
    fi
  }

  # Function to restore containerd configuration
  restore_containerd_config() {
    local backup_file="$1"
    if [ -n "$backup_file" ] && $SSH_CMD $SSH_USER@$SPARK1_IP "sudo test -f $backup_file"; then
      if [ "$DEBUG" = "1" ]; then
        echo "Restoring containerd config from $backup_file"
      fi
      $SSH_CMD $SSH_USER@$SPARK1_IP "sudo cp $backup_file /var/lib/rancher/k3s/agent/etc/containerd/config.toml" 2>/dev/null || true
    fi
  }

  # Function to validate NVIDIA container runtime installation
  validate_nvidia_installation() {
    # Check if nvidia-container-runtime is available
    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "which nvidia-container-runtime" >/dev/null 2>&1; then
      return 1
    fi
    # Check if at least one NVIDIA runtime binary exists
    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "test -x /usr/bin/nvidia-container-runtime || test -x /usr/local/nvidia/toolkit/nvidia-container-runtime" >/dev/null 2>&1; then
      return 1
    fi
    return 0
  }

  # Function to validate containerd configuration
  validate_containerd_config() {
    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "sudo test -f /var/lib/rancher/k3s/agent/etc/containerd/config.toml"; then
      return 1
    fi
    # Check if NVIDIA runtime is configured with correct format
    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "sudo grep -q \"plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.'nvidia'\" /var/lib/rancher/k3s/agent/etc/containerd/config.toml" >/dev/null 2>&1; then
      return 1
    fi
    # Check if BinaryName is set
    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "sudo grep -A 5 \"plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.'nvidia'\" /var/lib/rancher/k3s/agent/etc/containerd/config.toml | grep -q 'BinaryName'" >/dev/null 2>&1; then
      return 1
    fi
    return 0
  }

  # Function to restart k3s-agent with timeout
  restart_k3s_agent_with_timeout() {
    local timeout=60
    local count=0

    if [ "$DEBUG" = "1" ]; then
      echo "Restarting k3s-agent service with $timeout second timeout..."
    fi

    # Start the restart in background
    $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl restart k3s-agent" &
    local pid=$!

    # Wait for completion or timeout
    while kill -0 $pid 2>/dev/null; do
      if [ $count -ge $timeout ]; then
        if [ "$DEBUG" = "1" ]; then
          echo "Restart command timed out, killing process..."
        fi
        kill -9 $pid 2>/dev/null || true
        return 1
      fi
      sleep 2
      count=$((count + 2))
    done

    # Check if systemctl command succeeded
    wait $pid
    local exit_code=$?

    if [ $exit_code -ne 0 ]; then
      if [ "$DEBUG" = "1" ]; then
        echo "systemctl restart failed with exit code $exit_code"
      fi
      return 1
    fi

    return 0
  }

  # Function to perform comprehensive preflight validation
  preflight_gpu_validation() {
    local validation_errors=0

    echo "🔍 Performing comprehensive GPU preflight validation..."
    echo

    # 1. GPU Hardware Detection
    echo "1. Checking GPU Hardware..."
    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "nvidia-smi --query-gpu=name --format=csv,noheader | grep -q 'NVIDIA'"; then
      echo "❌ CRITICAL: No NVIDIA GPU detected on spark1"
      validation_errors=$((validation_errors + 1))
    else
      local gpu_model
      gpu_model=$($SSH_CMD $SSH_USER@$SPARK1_IP "nvidia-smi --query-gpu=name --format=csv,noheader")
      echo "✅ GPU detected: $gpu_model"
    fi

    # 2. Device Node Permissions
    echo "2. Checking GPU Device Permissions..."
    local device_check_passed=true
    for device in /dev/nvidia0 /dev/nvidiactl /dev/nvidia-uvm /dev/nvidia-modeset; do
      if ! $SSH_CMD $SSH_USER@$SPARK1_IP "test -c $device && ls -la $device | grep -q 'crw-rw-rw-'"; then
        echo "❌ Device $device not accessible or has wrong permissions"
        device_check_passed=false
        validation_errors=$((validation_errors + 1))
      fi
    done
    if $device_check_passed; then
      echo "✅ All GPU device nodes accessible with correct permissions"
    fi

    # 3. CUDA Libraries
    echo "3. Checking CUDA Libraries..."
    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "test -L /usr/lib/aarch64-linux-gnu/libcuda.so || test -f /usr/lib/aarch64-linux-gnu/libcuda.so"; then
      echo "❌ CUDA libraries not found at expected location"
      validation_errors=$((validation_errors + 1))
    else
      echo "✅ CUDA libraries available"
    fi

    # 4. NVIDIA Container Runtime
    echo "4. Checking NVIDIA Container Runtime..."
    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "which nvidia-container-runtime >/dev/null 2>&1"; then
      echo "❌ nvidia-container-runtime binary not found"
      validation_errors=$((validation_errors + 1))
    elif ! $SSH_CMD $SSH_USER@$SPARK1_IP "nvidia-container-runtime --version >/dev/null 2>&1"; then
      echo "❌ nvidia-container-runtime not functional"
      validation_errors=$((validation_errors + 1))
    else
      local runtime_version
      runtime_version=$($SSH_CMD $SSH_USER@$SPARK1_IP "nvidia-container-runtime --version | head -1")
      echo "✅ NVIDIA container runtime functional: $runtime_version"
    fi

    # 5. Containerd Service Status
    echo "5. Checking Containerd Service..."
    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl is-active --quiet containerd"; then
      echo "❌ Containerd service not active"
      validation_errors=$((validation_errors + 1))
    else
      echo "✅ Containerd service active"
    fi

    # 6. Containerd NVIDIA Configuration
    echo "6. Checking Containerd NVIDIA Configuration..."
    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "sudo test -f /var/lib/rancher/k3s/agent/etc/containerd/config.toml"; then
      echo "❌ Containerd config file not found"
      validation_errors=$((validation_errors + 1))
    elif ! $SSH_CMD $SSH_USER@$SPARK1_IP "sudo grep -q \"plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.'nvidia'\" /var/lib/rancher/k3s/agent/etc/containerd/config.toml"; then
      echo "⚠️ NVIDIA runtime not configured in containerd (will be configured by script)"
    else
      echo "✅ NVIDIA runtime already configured in containerd"
    fi

    # 7. K3s Agent Status
    echo "7. Checking K3s Agent Status..."
    local agent_status
    agent_status=$($SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl is-active k3s-agent 2>/dev/null || echo 'not-active'")
    if [ "$agent_status" = "active" ]; then
      echo "✅ K3s agent active"
    elif [ "$agent_status" = "activating" ]; then
      echo "⚠️ K3s agent activating (normal for new agent)"
    else
      echo "❌ K3s agent not running"
      validation_errors=$((validation_errors + 1))
    fi

    # 8. Runtime Class Availability
    echo "8. Checking Runtime Class Availability..."
    if ! sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get runtimeclass nvidia >/dev/null 2>&1; then
      echo "❌ Runtime class 'nvidia' not available in cluster"
      validation_errors=$((validation_errors + 1))
    else
      echo "✅ Runtime class 'nvidia' available"
    fi

    # 9. Deployment YAML Validation
    echo "9. Validating Deployment YAML..."
    if ! sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f fastapi-deployment-spark1.yaml --dry-run=server >/dev/null 2>&1; then
      echo "❌ Deployment YAML validation failed"
      validation_errors=$((validation_errors + 1))
    else
      echo "✅ Deployment YAML validates successfully"
    fi

    # 10. Manual GPU Mounting Configuration
    echo "10. Checking Manual GPU Mounting Configuration..."
    local required_mounts=("/dev/nvidia0" "/dev/nvidiactl" "/dev/nvidia-uvm" "/dev/nvidia-modeset")
    local mount_check_passed=true

    for mount_path in "${required_mounts[@]}"; do
      if ! grep -q "path:.*$mount_path" fastapi-deployment-spark1.yaml; then
        echo "❌ Required mount $mount_path not found in deployment YAML"
        mount_check_passed=false
        validation_errors=$((validation_errors + 1))
      fi
    done

    if $mount_check_passed; then
      echo "✅ All required GPU mounts configured in deployment"
    fi

    # Summary
    echo
    if [ $validation_errors -eq 0 ]; then
      echo "🎉 PREFLIGHT VALIDATION PASSED - All systems ready for GPU setup!"
      echo "The manual GPU mounting approach will work successfully."
      return 0
    else
      echo "❌ PREFLIGHT VALIDATION FAILED - $validation_errors critical issues found"
      echo "Manual GPU mounting may not work. Please resolve issues before proceeding."
      return 1
    fi
  }

  # Function to validate and setup NVIDIA package repository
  setup_nvidia_repository() {
    # Check if NVIDIA Docker repository is already configured
    if $SSH_CMD $SSH_USER@$SPARK1_IP "grep -q 'nvidia.github.io' /etc/apt/sources.list.d/*.list 2>/dev/null"; then
      if [ "$DEBUG" = "1" ]; then
        echo "NVIDIA Docker repository already configured"
      fi
      return 0
    fi

    if [ "$DEBUG" = "1" ]; then
      echo "Setting up NVIDIA Docker repository..."
    fi

    # Get distribution info
    local distribution
    distribution=$($SSH_CMD $SSH_USER@$SPARK1_IP ". /etc/os-release; echo \$ID\$VERSION_ID")

    # Add NVIDIA GPG key
    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "curl -s -L https://nvidia.github.io/nvidia-docker/gpgkey | sudo apt-key add -"; then
      echo "Failed to add NVIDIA GPG key"
      return 1
    fi

    # Add NVIDIA Docker repository
    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "curl -s -L https://nvidia.github.io/nvidia-docker/\$distribution/nvidia-docker.list | sudo tee /etc/apt/sources.list.d/nvidia-docker.list"; then
      echo "Failed to add NVIDIA Docker repository"
      return 1
    fi

    # Update package lists
    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "sudo apt-get update"; then
      echo "Failed to update package lists after repository setup"
      return 1
    fi

    return 0
  }

  # Function to monitor package health
  monitor_package_health() {
    local package_status
    local package_version
    local repository_status

    # Check package installation status
    package_status=$($SSH_CMD $SSH_USER@$SPARK1_IP "dpkg -l nvidia-docker2 2>/dev/null | grep '^ii' | awk '{print \$1,\$2,\$3}'" || echo "NOT_INSTALLED")

    # Check package version and repository
    package_version=$($SSH_CMD $SSH_USER@$SPARK1_IP "apt-cache policy nvidia-docker2 2>/dev/null | grep 'Installed:' | awk '{print \$2}'" || echo "UNKNOWN")

    # Check repository availability
    repository_status=$($SSH_CMD $SSH_USER@$SPARK1_IP "apt-cache policy nvidia-docker2 2>/dev/null | grep -c 'nvidia.github.io'" || echo "0")

    if [ "$DEBUG" = "1" ]; then
      echo "Package Status: $package_status"
      echo "Package Version: $package_version"
      echo "Repository Available: $repository_status"
    fi

    # Validate everything is working
    if [[ "$package_status" != *"ii nvidia-docker2"* ]]; then
      echo "nvidia-docker2 package not properly installed"
      return 1
    fi

    if [ "$repository_status" -eq 0 ]; then
      echo "NVIDIA Docker repository not available"
      return 1
    fi

    return 0
  }

  # Comprehensive pre-flight validation
  if ! preflight_gpu_validation; then
    echo "❌ CRITICAL: Preflight validation failed. Cannot proceed with GPU setup."
    echo "Please resolve the issues above before running the script."
    echo -e "❌"
    exit 1
  fi

  echo
  echo "🎉 Preflight validation passed - GPU setup complete with privileged mounts!"
  echo

  # GPU setup skipped - using privileged mounts for direct access

  # Success
  if [ "$DEBUG" = "1" ]; then
    echo "GPU resource cleanup completed successfully (NVIDIA Container Toolkit skipped - using privileged mounts)"
  fi
  echo -e "✅"
  return 0
  if [ "$DEBUG" = "1" ]; then
    echo "Ensuring NVIDIA Docker repository is configured..."
  fi
  if ! setup_nvidia_repository; then
    echo "Failed to setup NVIDIA Docker repository on SPARK2"
    echo -e "❌"
    exit 1
  fi

  # Function to safely manage NVIDIA Container Toolkit
  manage_nvidia_container_toolkit() {
    local force_reinstall=${1:-false}

    # Check if nvidia-docker2 is already installed and working
    if ! $force_reinstall && $SSH_CMD $SSH_USER@$SPARK1_IP "dpkg -l | grep -q '^ii.*nvidia-docker2'" >/dev/null 2>&1; then
      if [ "$DEBUG" = "1" ]; then
        echo "nvidia-docker2 already installed, checking if it's working..."
      fi
      # Test if the package is functional
      if $SSH_CMD $SSH_USER@$SPARK1_IP "which nvidia-container-runtime >/dev/null 2>&1 && nvidia-container-runtime --version >/dev/null 2>&1"; then
        if [ "$DEBUG" = "1" ]; then
          echo "nvidia-docker2 is already installed and functional"
        fi
        return 0
      else
        if [ "$DEBUG" = "1" ]; then
          echo "nvidia-docker2 installed but not functional, will reinstall"
        fi
      fi
    fi

    # Stop any containers using NVIDIA runtime before package operations
    if [ "$DEBUG" = "1" ]; then
      echo "Stopping containers that might use NVIDIA runtime..."
    fi
    $SSH_CMD $SSH_USER@$SPARK1_IP "sudo crictl ps --label io.kubernetes.container.name 2>/dev/null | grep -v CONTAINER | awk '{print \$1}' | xargs -r sudo crictl stop" >/dev/null 2>&1 || true
    $SSH_CMD $SSH_USER@$SPARK1_IP "sudo crictl ps --label io.kubernetes.pod.name 2>/dev/null | grep -v CONTAINER | awk '{print \$1}' | xargs -r sudo crictl rmd" >/dev/null 2>&1 || true

    # Purge existing package safely
    if [ "$DEBUG" = "1" ]; then
      echo "Safely removing existing nvidia-docker2 package..."
    fi
    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "sudo dpkg --purge --force-depends nvidia-docker2" >/dev/null 2>&1; then
      if [ "$DEBUG" = "1" ]; then
        echo "dpkg purge failed, trying apt-get purge..."
      fi
      $SSH_CMD $SSH_USER@$SPARK1_IP "sudo apt-get purge -y --allow-change-held-packages nvidia-docker2" >/dev/null 2>&1 || true
    fi

    # Clean up any leftover configuration
    $SSH_CMD $SSH_USER@$SPARK1_IP "sudo apt-get autoremove -y && sudo apt-get autoclean" >/dev/null 2>&1 || true

    # Install NVIDIA Container Toolkit
    if [ "$DEBUG" = "1" ]; then
      echo "Installing NVIDIA Container Toolkit..."
    fi
    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "sudo apt-get install -y --no-install-recommends nvidia-docker2"; then
      echo "Failed to install NVIDIA Container Toolkit on SPARK2"
      return 1
    fi

    # Verify installation
    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "which nvidia-container-runtime >/dev/null 2>&1"; then
      echo "nvidia-container-runtime not found after installation"
      return 1
    fi

    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "nvidia-container-runtime --version >/dev/null 2>&1"; then
      echo "nvidia-container-runtime not functional after installation"
      return 1
    fi

    return 0
  }

  # Step 1: Manage NVIDIA Container Toolkit safely (SKIPPED - using privileged mounts)
  # if [ "$DEBUG" = "1" ]; then
  #   echo "Managing NVIDIA Container Toolkit installation..."
  # fi
  # if ! manage_nvidia_container_toolkit; then
  #   echo "Failed to manage NVIDIA Container Toolkit on SPARK2"
  #   restore_containerd_config "$BACKUP_FILE"
  #   echo -e "❌"
  #   exit 1
  # fi

  # Step 2: Monitor package health (SKIPPED - using privileged mounts)
  # if [ "$DEBUG" = "1" ]; then
  #   echo "Monitoring NVIDIA package health..."
  # fi
  # if ! monitor_package_health; then
  #   echo "NVIDIA package health check failed on SPARK2"
  #   restore_containerd_config "$BACKUP_FILE"
  #   echo -e "❌"
  #   exit 1
  # fi

  # Step 3: Update package lists
  if [ "$DEBUG" = "1" ]; then
    echo "Updating package lists..."
  fi
  if ! $SSH_CMD $SSH_USER@$SPARK1_IP "sudo apt-get update" >/dev/null 2>&1; then
    echo "Failed to update package lists on SPARK2"
    restore_containerd_config "$BACKUP_FILE"
    echo -e "❌"
    exit 1
  fi

  # Step 4: Validate NVIDIA installation (SKIPPED - using privileged mounts)
  # if [ "$DEBUG" = "1" ]; then
  #   echo "Validating NVIDIA Container Toolkit installation..."
  # fi
  # if ! validate_nvidia_installation; then
  #   echo "NVIDIA Container Toolkit validation failed on SPARK2"
  #   restore_containerd_config "$BACKUP_FILE"
  #   echo -e "❌"
  #   exit 1
  # fi

  # Step 5: Configure containerd for NVIDIA runtime
  if [ "$DEBUG" = "1" ]; then
    echo "Configuring containerd for NVIDIA runtime..."
  fi
  if ! $SSH_CMD $SSH_USER@$SPARK1_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd" >/dev/null 2>&1; then
    echo "Failed to create containerd config directory on SPARK2"
    restore_containerd_config "$BACKUP_FILE"
    echo -e "❌"
    exit 1
  fi

  # Check which NVIDIA runtime path exists and use it
  if $SSH_CMD $SSH_USER@$SPARK1_IP "test -x /usr/local/nvidia/toolkit/nvidia-container-runtime"; then
    NVIDIA_RUNTIME_PATH="/usr/local/nvidia/toolkit/nvidia-container-runtime"
    NVIDIA_CDI_PATH="/usr/local/nvidia/toolkit/nvidia-container-runtime.cdi"
  elif $SSH_CMD $SSH_USER@$SPARK1_IP "test -x /usr/bin/nvidia-container-runtime"; then
    NVIDIA_RUNTIME_PATH="/usr/bin/nvidia-container-runtime"
    NVIDIA_CDI_PATH=""
  else
    echo "No NVIDIA container runtime found on SPARK2"
    restore_containerd_config "$BACKUP_FILE"
    echo -e "❌"
    exit 1
  fi

  # Read existing config and append NVIDIA runtime configuration
  if ! $SSH_CMD $SSH_USER@$SPARK1_IP "sudo tee -a /var/lib/rancher/k3s/agent/etc/containerd/config.toml > /dev/null <<EOF

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.'nvidia']
  runtime_type = \"io.containerd.runc.v2\"

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.'nvidia'.options]
  BinaryName = \"$NVIDIA_RUNTIME_PATH\"
  SystemdCgroup = true
EOF"; then
    echo "Failed to configure containerd for NVIDIA runtime on SPARK2"
    restore_containerd_config "$BACKUP_FILE"
    echo -e "❌"
    exit 1
  fi

  # Add CDI runtime if available
  if [ -n "$NVIDIA_CDI_PATH" ]; then
    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "sudo tee -a /var/lib/rancher/k3s/agent/etc/containerd/config.toml > /dev/null <<EOF

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.'nvidia-cdi']
  runtime_type = \"io.containerd.runc.v2\"

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.'nvidia-cdi'.options]
  BinaryName = \"$NVIDIA_CDI_PATH\"
  SystemdCgroup = true
EOF"; then
      echo "Failed to configure containerd CDI runtime on SPARK2"
      restore_containerd_config "$BACKUP_FILE"
      echo -e "❌"
      exit 1
    fi
  fi

  # Step 6: Validate containerd configuration
  if [ "$DEBUG" = "1" ]; then
    echo "Validating containerd configuration..."
  fi
  if ! validate_containerd_config; then
    echo "Containerd configuration validation failed on SPARK2"
    restore_containerd_config "$BACKUP_FILE"
    echo -e "❌"
    exit 1
  fi

  # Step 7: Restart containerd to load NVIDIA runtime
  if [ "$DEBUG" = "1" ]; then
    echo "Restarting containerd to load NVIDIA runtime configuration..."
  fi
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl restart containerd" &
  local containerd_pid=$!
  local containerd_timeout=30
  local containerd_count=0

  # Wait for containerd restart to complete
  while kill -0 $containerd_pid 2>/dev/null; do
    if [ $containerd_count -ge $containerd_timeout ]; then
      if [ "$DEBUG" = "1" ]; then
        echo "Containerd restart timed out, killing process..."
      fi
      kill -9 $containerd_pid 2>/dev/null || true
      echo "Failed to restart containerd on SPARK2 within timeout"
      restore_containerd_config "$BACKUP_FILE"
      echo -e "❌"
      exit 1
    fi
    sleep 2
    containerd_count=$((containerd_count + 2))
  done

  # Check if containerd restart succeeded
  wait $containerd_pid
  local containerd_exit_code=$?
  if [ $containerd_exit_code -ne 0 ]; then
    if [ "$DEBUG" = "1" ]; then
      echo "containerd restart failed with exit code $containerd_exit_code"
    fi
    echo "Failed to restart containerd on SPARK2"
    restore_containerd_config "$BACKUP_FILE"
    echo -e "❌"
    exit 1
  fi

  # Verify containerd is actually running and configuration is loaded
  if ! $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl is-active --quiet containerd"; then
    echo "Containerd service is not active after restart"
    restore_containerd_config "$BACKUP_FILE"
    echo -e "❌"
    exit 1
  fi

  # Final validation of containerd configuration
  if ! validate_containerd_config; then
    echo "Containerd configuration validation failed after restart"
    restore_containerd_config "$BACKUP_FILE"
    echo -e "❌"
    exit 1
  fi

  # Step 8: Restart K3s agent with timeout
  if [ "$DEBUG" = "1" ]; then
    echo "Restarting K3s agent service..."
  fi
  if ! restart_k3s_agent_with_timeout; then
    echo "Failed to restart k3s-agent service on SPARK2 within timeout"
    restore_containerd_config "$BACKUP_FILE"
    echo -e "❌"
    exit 1
  fi

  # Step 9: Wait for agent to be ready
  if [ "$DEBUG" = "1" ]; then
    echo "Waiting for SPARK1 agent to be ready after restart..."
  fi
  if ! wait_for_agent spark1; then
    echo "SPARK1 agent failed to become ready after GPU resource cleanup"
    restore_containerd_config "$BACKUP_FILE"
    echo -e "❌"
    exit 1
  fi

  # Function to perform final GPU setup health check
  final_gpu_health_check() {
    local health_status=0

    if [ "$DEBUG" = "1" ]; then
      echo "Performing final post-setup GPU health check..."
    fi

    # Quick verification that setup didn't break anything critical
    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "nvidia-smi --query-gpu=name --format=csv,noheader | grep -q 'NVIDIA'"; then
      echo "❌ GPU hardware not accessible after setup"
      health_status=1
    fi

    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl is-active --quiet containerd"; then
      echo "❌ Containerd service not healthy after setup"
      health_status=1
    fi

    if ! $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl is-active k3s-agent >/dev/null 2>&1"; then
      echo "❌ K3s agent service not healthy after setup"
      health_status=1
    fi

    return $health_status
  }

  # Step 10: Cleanup old containerd backup files
  if [ "$DEBUG" = "1" ]; then
    echo "Cleaning up old containerd backup files..."
  fi
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo find /var/lib/rancher/k3s/agent/etc/containerd -name 'config.toml.backup.*' -mtime +7 -delete" >/dev/null 2>&1 || true

  # Step 11: Final GPU health check
  if [ "$DEBUG" = "1" ]; then
    echo "Performing final GPU setup health check..."
  fi
  if ! final_gpu_health_check; then
    echo "Final GPU health check failed on SPARK2"
    restore_containerd_config "$BACKUP_FILE"
    echo -e "❌"
    exit 1
  fi

  # Success
  if [ "$DEBUG" = "1" ]; then
    echo "GPU resource cleanup completed successfully (NVIDIA Container Toolkit skipped - using privileged mounts)"
  fi
  echo -e "✅"
fi
step_increment
print_divider
}




step_23(){
# --------------------------------------------------------------------------------
# STEP 23: FINAL VERIFICATION - NODE AND POD STATUS
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Starting final verification of node and pod status..."
fi
step_echo_start "s" "tower" "$TOWER_IP" "Final verification: Node and pod status..."
sleep 5

# Wait for all pods to be ready and no pods terminating
if [ "$DEBUG" = "1" ]; then
  echo "Waiting for all pods to be ready and no terminating pods..."
fi
echo "Waiting for all pods to be ready and no terminating pods..."
timeout=600  # 10 minutes
count=0
while true; do
  # Check if all pods are Ready
  not_ready_count=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods --all-namespaces -o jsonpath='{.items[*].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null | grep -v True | wc -l)
  # Check for terminating pods
  terminating_count=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods --all-namespaces -o jsonpath='{.items[*].status.phase}' 2>/dev/null | grep -c Terminating)
  
  if [ "$not_ready_count" -eq 0 ] && [ "$terminating_count" -eq 0 ]; then
    if [ "$DEBUG" = "1" ]; then
      echo "All pods are ready and no terminating pods found."
    fi
    break
  fi
  
  if [ $count -ge $timeout ]; then
    if [ "$DEBUG" = "1" ]; then
      echo "Timeout reached, proceeding with status check despite pods not being fully ready."
    fi
    echo "Warning: Pods not fully ready or terminating pods still present within $timeout seconds, proceeding with status check..."
    break
  fi
  echo "Pods not ready or terminating pods present, waiting... ($((count / 10 + 1))/60)"
  sleep 10
  count=$((count + 10))
done

if [ "$DEBUG" = "1" ]; then
  echo "Retrieving node and pod status..."
fi
echo ""
echo "=== NODE STATUS ==="
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes
echo ""
echo "=== POD STATUS ==="
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide
echo ""
echo -e "✅ Final verification complete"
if [ "$DEBUG" = "1" ]; then
  echo "Final verification completed."
fi
step_increment
print_divider
}


step_23(){
# --------------------------------------------------------------------------------
# STEP 23: DISPLAY SERVICE ENDPOINTS
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Starting display of service endpoints..."
fi
step_echo_start "s" "tower" "$TOWER_IP" "Displaying available service endpoints..."
sleep 2
if [ "$DEBUG" = "1" ]; then
  echo "Displaying service endpoint information..."
fi
echo ""
echo "Services Available:"
echo "FastAPI: http://192.168.1.201:30013"
echo "Jupyter: http://192.168.1.201:30014"
echo "LLM API: http://192.168.1.201:30015"
echo "Health Check: http://192.168.1.201:30013/health"
echo "Swagger UI: http://192.168.1.201:30013/docs"
echo ""
echo -e "✅ Service endpoints displayed"
if [ "$DEBUG" = "1" ]; then
  echo "Service endpoints display completed."
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





# Capture final verification output
capture_final_log "$FINAL_LOG_FILE" "$START_MESSAGE"



# End of script


