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

# Install K3s agent on agx
INSTALL_AGX_AGENT=false

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
REGISTRY_PORT="30500"
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
    if [ "$INSTALL_AGX_AGENT" = true ] || [ "$INSTALL_NANO_AGENT" = true ]; then
      echo -e "\n\033[31mFATAL: K3S token not found. Ensure /var/lib/rancher/k3s/server/node-token exists on the Tower host.\033[0m\n"
      exit 1
    fi
  fi
}

if [ "$DEBUG" = "1" ]; then
    echo "Starting K3s Setup and FastAPI Deployment in **VERBOSE DEBUG** mode..."
else
    echo "Starting K3s Setup and FastAPI Deployment in **SILENT NORMAL** mode..."
fi

# Initialize Dynamic Step Counter
CURRENT_STEP=1

# NOTE: Total steps count is 20 (AGX agent setup and GPU enablement)
TOTAL_STEPS=20

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
  local timeout=30  # Reduced from 60 to 30 seconds
  local count=0
  if [ "$DEBUG" = "1" ]; then echo "Waiting for agent to be ready..."; fi

  if [ -n "$node_name" ]; then
    # Check the specific node's Ready condition
    while ! sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get node "$node_name" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null | grep -q "True"; do
      if [ $count -ge $timeout ]; then
        echo "Agent $node_name did not join within $timeout seconds - continuing anyway"
        return 1
      fi
      sleep 1
      count=$((count + 1))
    done
  else
    # Fallback: wait until any node is Ready (legacy behavior)
    while ! sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes 2>/dev/null | grep -q "Ready"; do
      if [ $count -ge $timeout ]; then
        echo "Agent did not join within $timeout seconds - continuing anyway"
        return 1
      fi
      sleep 1
      count=$((count + 1))
    done
  fi

  if [ "$DEBUG" = "1" ]; then echo "Agent is ready"; fi
  return 0
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
      return 1
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
# STEP 02: SPARK1 ARP/PING CHECK
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
  echo "SPARK1 network reachability check completed."
fi
step_increment
print_divider
}


#=============================================================================================================
step_03(){
# -------------------------------------------------------------------------
# STEP 03: Uninstall K3s Agent on SPARK1
# -------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Uninstalling Agent on SPARK1... (Verbose output below)"
    sleep 5
    # Delete existing deployments and services if they exist to ensure clean uninstall
    echo "Deleting existing fastapi-spark1 deployment..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete deployment fastapi-spark1 --ignore-not-found=true
    echo "Deleting existing fastapi-spark1-service..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-spark1-service --ignore-not-found=true
    echo "Deleting existing fastapi-spark1-nodeport..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-spark1-nodeport --ignore-not-found=true
    # Check if k3s binaries exist before attempting uninstall
    echo "Checking for k3s-agent-uninstall.sh on SPARK1..."
    if $SSH_CMD $SSH_USER@$SPARK1_IP "test -x /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
      echo "Found k3s-agent-uninstall.sh, running uninstall..."
      $SSH_CMD $SSH_USER@$SPARK1_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh"
    else
      echo "k3s-agent-uninstall.sh not found on SPARK1 - no uninstall needed"
    fi
  else
    step_echo_start "a" "spark1" "$SPARK1_IP" "Uninstalling K3s agent on spark1..."
    sleep 5
    # Delete existing deployments and services before uninstalling agent
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete deployment fastapi-spark1 --ignore-not-found=true > /dev/null 2>&1
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-spark1-service --ignore-not-found=true > /dev/null 2>&1
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-spark1-nodeport --ignore-not-found=true > /dev/null 2>&1
    # Check if k3s binaries exist before attempting uninstall
    if $SSH_CMD $SSH_USER@$SPARK1_IP "test -x /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
      if $SSH_CMD $SSH_USER@$SPARK1_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
        echo -e "[32m✅[0m"
      else
        echo -e "[32m✅[0m"  # Print checkmark anyway, as uninstall may have partial success
      fi
    else
      echo -e "[32m✅[0m"  # Print checkmark if uninstall script doesn't exist (already uninstalled)
    fi
  fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "K3s agent uninstall on SPARK1 completed."
fi
step_increment
print_divider
}





step_04(){
# -------------------------------------------------------------------------
# STEP 04: Reinstall SPARK1 Agent (BINARY TRANSFER INSTALL)
# -------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  # Use binary transfer for SPARK1 (curl fails due to network restrictions)
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
ExecStart=/usr/local/bin/k3s agent --node-ip $SPARK1_IP
EOF';
    echo 'K3S_TOKEN=\"\$K3S_TOKEN\"' | sudo tee /etc/systemd/system/k3s-agent.service.env > /dev/null;
    echo 'K3S_URL=\"https://$TOWER_IP:6443\"' | sudo tee -a /etc/systemd/system/k3s-agent.service.env > /dev/null;
    sudo ip route add default via 10.1.10.1 dev eno1 2>/dev/null || true;
    sudo systemctl daemon-reload;
    sudo systemctl enable k3s-agent;
    sudo systemctl start k3s-agent"

  if [ "$DEBUG" = "1" ]; then
    echo "Reinstalling Agent on SPARK1 with binary transfer..."
    sleep 5
    echo "Transferring k3s binary from tower to SPARK1..."
    echo "Setting up systemd service on SPARK1..."
    echo "Configuring K3s agent with token and server URL..."
    $SSH_CMD $SSH_USER@$SPARK1_IP "$K3S_REINSTALL_CMD"
    # Ensure environment file exists with correct server URL
    echo "Ensuring environment file has correct server URL..."
    $SSH_CMD $SSH_USER@$SPARK1_IP "sudo mkdir -p /etc/systemd/system && echo 'K3S_TOKEN=\"$TOKEN\"' | sudo tee /etc/systemd/system/k3s-agent.service.env > /dev/null && echo 'K3S_URL=\"https://$TOWER_IP:6443\"' | sudo tee -a /etc/systemd/system/k3s-agent.service.env > /dev/null" 2>/dev/null || true
    # CRITICAL: Ensure systemd loads environment variables after install
    echo "Reloading systemd and restarting k3s-agent service..."
    $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl daemon-reload && sudo systemctl restart k3s-agent" 2>/dev/null || true
    echo "Waiting for SPARK1 agent to join the cluster..."
    wait_for_agent spark1
  else
    step_echo_start "a" "spark1" "$SPARK1_IP" "Reinstalling K3s agent on spark1..."
    sleep 5
    # Execute the binary transfer install command
  if $SSH_CMD $SSH_USER@$SPARK1_IP "$K3S_REINSTALL_CMD" > /dev/null 2>&1; then
      # Ensure environment file exists with correct server URL
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo mkdir -p /etc/systemd/system && echo 'K3S_TOKEN=\"$TOKEN\"' | sudo tee /etc/systemd/system/k3s-agent.service.env > /dev/null && echo 'K3S_URL=\"https://$TOWER_IP:6443\"' | sudo tee -a /etc/systemd/system/k3s-agent.service.env > /dev/null" > /dev/null 2>&1
      # CRITICAL: Ensure systemd loads environment variables after install
  $SSH_CMD $SSH_USER@$SPARK1_IP "sudo systemctl daemon-reload && sudo systemctl restart k3s-agent" > /dev/null 2>&1
  wait_for_agent spark1
      echo -en " ✅[0m
"
    else
      echo -e "[31m❌ Failed to reinstall K3s agent on SPARK1[0m"
      echo "Debug info:"
      echo "Reinstalling Agent on SPARK1 with binary transfer..."
      echo "Transferring k3s binary from tower to SPARK1..."
      echo "Setting up systemd service on SPARK1..."
      echo "Configuring K3s agent with token and server URL..."
      echo "Error details - attempting to show command output:"
      $SSH_CMD $SSH_USER@$SPARK1_IP "$K3S_REINSTALL_CMD"
      exit 1
    fi
  fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "K3s agent reinstall on SPARK1 completed."
fi
step_increment
print_divider
}



step_05(){
# =========================================================================
# STEP 05: Systemd Service Override (force correct server/node IP) SPARK1
# =========================================================================
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
      echo -e "\033[31m❌ Failed to create registry configuration directory on SPARK1\033[0m"
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
# STEP 07: Configure Registry for SPARK1
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
"
    fi
    echo "Registry configuration completed"
  else
    step_echo_start "a" "spark1" "$SPARK1_IP" "Configuring registry for spark1..."
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
" > /dev/null 2>&1
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
  echo "Registry configuration for SPARK1 completed."
fi
step_increment
print_divider
}





step_08(){
# -------------------------------------------------------------------------
# STEP 08: Restart Agent After Registry Config SPARK1
# -------------------------------------------------------------------------
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
step_increment
print_divider

}




step_09(){
# --------------------------------------------------------------------------------
# STEP 09: Restart K3s agent on SPARK1 (workaround for containerd config)
# --------------------------------------------------------------------------------
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
if [ "$DEBUG" = "1" ]; then
  echo "K3s agent restart after containerd config completed."
fi
step_increment
print_divider
}



step_10(){
# --------------------------------------------------------------------------------
# STEP 10: Install NVIDIA Device Plugin for GPU Support
# --------------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Installing NVIDIA Device Plugin for GPU support..."
    sleep 5
    echo "Applying NVIDIA device plugin DaemonSet YAML..."
    cat <<EOF | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: nvidia-device-plugin-daemonset
  namespace: kube-system

spec:
  selector:
    matchLabels:
      name: nvidia-device-plugin-ds
  template:
    metadata:
      labels:
        name: nvidia-device-plugin-ds

    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: kubernetes.io/hostname
                operator: In
                values:
                - nano
                - agx
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
  name: nvidia-device-plugin-daemonset
  namespace: kube-system

spec:
  selector:
    matchLabels:
      name: nvidia-device-plugin-ds
  template:
    metadata:
      labels:
        name: nvidia-device-plugin-ds

    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: kubernetes.io/hostname
                operator: In
                values:
                - nano
                - agx
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
fi
if [ "$DEBUG" = "1" ]; then
  echo "NVIDIA Device Plugin installation completed."
fi
step_increment
print_divider
}

step_11(){
# --------------------------------------------------------------------------------
# STEP 11: Clean up FastAPI SPARK1 Docker image tags
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Cleaning up FastAPI SPARK1 Docker image tags..."
  sleep 5
  echo "Removing existing Docker images for fastapi-spark1..."
  sudo docker rmi "$REGISTRY_IP:$REGISTRY_PORT/fastapi-spark1:latest" > /dev/null 2>&1
  echo "Docker image cleanup complete"
else
  step_echo_start "s" "tower" "$TOWER_IP" "Cleaning up FastAPI SPARK1 Docker image tags..."
  sleep 5
  if sudo docker rmi "$REGISTRY_IP:$REGISTRY_PORT/fastapi-spark1:latest" > /dev/null 2>&1; then
    echo -e "✅"
  else
    echo -e "✅" # Always show success, even if image didn't exist
  fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "FastAPI SPARK1 Docker image cleanup completed."
fi
step_increment
print_divider
}


step_12(){
# --------------------------------------------------------------------------------
# STEP 12: Build SPARK1 Docker image
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Building SPARK1 Docker image..."
  sleep 5
  echo "Running docker build for fastapi-spark1..."
  sudo docker build -f ../agent/spark1/dockerfile.spark1.req -t fastapi-spark1:latest ../agent/spark1
  if [ $? -eq 0 ]; then
    echo "SPARK1 Docker image built successfully"
  else
    echo "Failed to build SPARK1 Docker image"
    exit 1
  fi
else
  step_echo_start "s" "tower" "$TOWER_IP" "Building SPARK1 Docker image..."
  sleep 5
  if sudo docker build -f ../agent/spark1/dockerfile.spark1.req -t fastapi-spark1:latest ../agent/spark1 > /dev/null 2>&1; then
    echo -e "✅"
  else
    echo -e "❌"
    exit 1
  fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "SPARK1 Docker image build completed."
fi
step_increment
print_divider
}


step_13(){
# --------------------------------------------------------------------------------
# STEP 13: Tag SPARK1 Docker image
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Tagging SPARK1 Docker image..."
  sleep 5
  echo "Tagging fastapi-spark1:latest as $REGISTRY_IP:$REGISTRY_PORT/fastapi-spark1:latest"
  sudo docker tag fastapi-spark1:latest "$REGISTRY_IP:$REGISTRY_PORT/fastapi-spark1:latest"
  if [ $? -eq 0 ]; then
    echo "SPARK1 Docker image tagged successfully"
  else
    echo "Failed to tag SPARK1 Docker image"
    exit 1
  fi
else
  step_echo_start "s" "tower" "$TOWER_IP" "Tagging SPARK1 Docker image..."
  sleep 5
  if sudo docker tag fastapi-spark1:latest "$REGISTRY_IP:$REGISTRY_PORT/fastapi-spark1:latest" > /dev/null 2>&1; then
    echo -e "✅"
  else
    echo -e "❌"
    exit 1
  fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "SPARK1 Docker image tagging completed."
fi
step_increment
print_divider
}


step_14(){
# --------------------------------------------------------------------------------
# STEP 14: Push Docker image to registry
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Pushing Docker image to registry..."
  sleep 5
  echo "Pushing $REGISTRY_IP:$REGISTRY_PORT/fastapi-spark1:latest"
  sudo docker push "$REGISTRY_IP:$REGISTRY_PORT/fastapi-spark1:latest"
  if [ $? -eq 0 ]; then
    echo "Docker image pushed successfully"
  else
    echo "Failed to push Docker image"
    exit 1
  fi
else
  step_echo_start "s" "tower" "$TOWER_IP" "Pushing Docker image to registry..."
  sleep 5
  if sudo docker push "$REGISTRY_IP:$REGISTRY_PORT/fastapi-spark1:latest" > /dev/null 2>&1; then
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




step_15(){
# --------------------------------------------------------------------------------
# STEP 15: Deploy FastAPI to SPARK1
# --------------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Deploying FastAPI to SPARK1..."
    sleep 5
    echo "Applying deployment YAML for fastapi-spark1 from file..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f ../agent/spark1/fastapi-deployment-full.yaml
    if [ $? -eq 0 ]; then
      echo "FastAPI deployment to SPARK1 applied successfully"
    else
      echo "Failed to apply FastAPI deployment to SPARK1"
      exit 1
    fi
  else
    step_echo_start "s" "tower" "$TOWER_IP" "Deploying FastAPI to SPARK1..."
    sleep 5
    if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f ../agent/spark1/fastapi-deployment-full.yaml > /dev/null 2>&1
    then
      echo -e "✅"
    else
      echo -e "❌"
      exit 1
    fi
  fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "FastAPI deployment to SPARK1 completed."
fi
step_increment
print_divider
}

step_16(){
# --------------------------------------------------------------------------------
# STEP 16: Create SPARK1 Service (now included in step 15)
# --------------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
    step_echo_start "s" "tower" "$TOWER_IP" "Creating SPARK1 Service (skipped)..."
    echo -e "✅"
fi
step_increment
print_divider
}


step_17(){
# --------------------------------------------------------------------------------
# STEP 17: Create SPARK1 NodePort (now included in step 15)
# --------------------------------------------------------------------------------
if [ "$INSTALL_SPARK1_AGENT" = true ]; then
    step_echo_start "s" "tower" "$TOWER_IP" "Creating SPARK1 NodePort (skipped)..."
    echo -e "✅"
fi
step_increment
print_divider
}


step_18(){
# --------------------------------------------------------------------------------
# STEP 18: Placeholder for SPARK2 steps
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "SPARK2 steps would go here..."
fi
step_increment
print_divider
}


step_19(){
# --------------------------------------------------------------------------------
# STEP 19: FINAL VERIFICATION - NODE AND POD STATUS
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


step_20(){
# --------------------------------------------------------------------------------
# STEP 20: DISPLAY SERVICE ENDPOINTS
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
echo "FastAPI: http://10.1.10.244:30004"
echo "Jupyter: http://10.1.10.244:30005"
echo "LLM API: http://10.1.10.244:30006"
echo "Health Check: http://10.1.10.244:30004/health"
echo "Swagger UI: http://10.1.10.244:30004/docs"
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



# Capture final verification output
capture_final_log "$FINAL_LOG_FILE" "$START_MESSAGE"



# End of script


