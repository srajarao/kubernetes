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
INSTALL_NANO_AGENT=true

# Install K3s agent on agx
INSTALL_AGX_AGENT=false

# Install K3s agent on spark1
INSTALL_SPARK1_AGENT=false

# Install K3s agent on spark2
INSTALL_SPARK2_AGENT=true

# Enable SSH verification
SSH_ENABLED=true

# IP addresses
TOWER_IP="10.1.10.150"
NANO_IP="10.1.10.181"   # <-- Use the correct, reachable IP
AGX_IP="10.1.10.244"
SPARK1_IP="10.1.10.201"
SPARK2_IP="10.1.10.202"

# Set node variables based on which agent is enabled
if [ "$INSTALL_NANO_AGENT" = true ]; then
  NODE_NAME="nano"
  NODE_IP="$NANO_IP"
  NODE_DISPLAY="Nano"
elif [ "$INSTALL_AGX_AGENT" = true ]; then
  NODE_NAME="agx"
  NODE_IP="$AGX_IP"
  NODE_DISPLAY="AGX"
elif [ "$INSTALL_SPARK1_AGENT" = true ]; then
  NODE_NAME="spark1"
  NODE_IP="$SPARK1_IP"
  NODE_DISPLAY="Spark1"
elif [ "$INSTALL_SPARK2_AGENT" = true ]; then
  NODE_NAME="spark2"
  NODE_IP="$SPARK2_IP"
  NODE_DISPLAY="Spark2"
else
  echo "No agent installation enabled"
  exit 1
fi

# Registry settings - Registry is on Tower
REGISTRY_IP="$TOWER_IP"  # Tower
REGISTRY_PROTOCOL="http"  # "http" or "https"

# Auto-detect registry NodePort
REGISTRY_NODE_PORT=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get svc registry-service -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || echo "30500")
REGISTRY_PORT="$REGISTRY_NODE_PORT"

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

# NOTE: Total steps count is 20 (Nano agent setup and GPU enablement)
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


    # --- 6. CRITICAL: NANO K3S AGENT LOG ERRORS (Automated SSH Check) ---
    echo -e "
--- 6. CRITICAL: NANO K3S AGENT LOG ERRORS (Container Runtime Check) ---" >> "$log_file"
  echo "Executing: $SSH_CMD $SSH_USER@$NODE_IP 'sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E \"fastapi-nano|Error|Fail\"'" >> "$log_file"
    # Execute SSH command and pipe output directly to the log file
  $SSH_CMD $SSH_USER@$NODE_IP "sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E 'fastapi-nano|Error|Fail'" >> "$log_file" 2>/dev/null

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

# Function to wait for Nano GPU capacity
wait_for_gpu_capacity() {
  local timeout=120
  local count=0
  if [ "$DEBUG" = "1" ]; then echo "Waiting for $NODE_DISPLAY GPU capacity to be added..."; fi
  while ! sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get node $NODE_NAME -o jsonpath='{.status.capacity.nvidia\.com/gpu}' | grep -q '1'; do
    if [ $count -ge $timeout ]; then
      echo "$NODE_DISPLAY GPU capacity not added within $timeout seconds"
      return 1
    fi
    sleep 5
    count=$((count + 5))
  done
    if [ "$DEBUG" = "1" ]; then echo "$NODE_DISPLAY GPU capacity added"; fi
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
# STEP 01: Nano SSH Validation
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  # Ensure we have the K3s server token available before attempting agent install
  get_k3s_token
  if [ "$DEBUG" = "1" ]; then
    echo "Running verbose Nano SSH check..."
  fi
  step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Verifying $NODE_DISPLAY SSH connectivity..."
  sleep 5
  # Test SSH connection by running 'hostname' on the Nano
  if [ "$DEBUG" = "1" ]; then
    echo "Executing SSH command: $SSH_CMD $SSH_USER@$NODE_IP 'hostname'"
  fi
  if $SSH_CMD $SSH_USER@$NODE_IP "hostname" > /dev/null 2>&1; then
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
  echo "{a} [$NODE_NAME] [$NODE_IP] ${CURRENT_STEP}/${TOTAL_STEPS}. $NODE_DISPLAY SSH verification skipped (not enabled)"
fi
step_increment
print_divider
}


step_02(){
# -------------------------------------------------------------------------
# STEP 02: Nano ARP/PING CHECK
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Verifying $NODE_DISPLAY network reachability (ARP/Ping)..."
  sleep 5
  run_network_check $NODE_IP "$NODE_DISPLAY"
fi
step_increment
print_divider
}


#=============================================================================================================
step_03(){
# -------------------------------------------------------------------------
# STEP 03: Uninstall K3s Agent on Nano
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  # Delete existing deployments and services before uninstalling agent
  if [ "$DEBUG" = "1" ]; then
    echo "Deleting existing Nano deployments and services before agent uninstall..."
  fi
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete deployment fastapi-nano --ignore-not-found=true > /dev/null 2>&1
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-nano-service --ignore-not-found=true > /dev/null 2>&1
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-nano-nodeport --ignore-not-found=true > /dev/null 2>&1
  # Also clean up any AGX services that may exist
  if [ "$DEBUG" = "1" ]; then
    echo "Cleaning up any leftover AGX services..."
  fi
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-agx-nodeport --ignore-not-found=true > /dev/null 2>&1
  if [ "$DEBUG" = "1" ]; then
    echo "Uninstalling Agent on Nano... (Verbose output below)"
    sleep 5
    # Check if k3s binaries exist before attempting uninstall
  if $SSH_CMD $SSH_USER@$NODE_IP "test -x /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
  $SSH_CMD $SSH_USER@$NODE_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh"
    else
      echo "k3s-agent-uninstall.sh not found on Nano - no uninstall needed"
    fi
  else
    step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Uninstalling K3s agent on $NODE_NAME..."
    sleep 5
    # Check if k3s binaries exist before attempting uninstall
  if [ "$DEBUG" = "1" ]; then
    echo "Checking if k3s-agent-uninstall.sh exists on $NODE_DISPLAY..."
  fi
  if $SSH_CMD $SSH_USER@$NODE_IP "test -x /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
  if [ "$DEBUG" = "1" ]; then
    echo "Running k3s-agent-uninstall.sh on $NODE_DISPLAY..."
  fi
  if $SSH_CMD $SSH_USER@$NODE_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
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





step_04(){
# -------------------------------------------------------------------------
# STEP 04: Reinstall Nano Agent (BINARY TRANSFER INSTALL)
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  # Use binary transfer for Nano (curl fails due to network restrictions)
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
ExecStart=/usr/local/bin/k3s agent --node-ip $NODE_IP
EOF';
    echo 'K3S_TOKEN=\"\$K3S_TOKEN\"' | sudo tee /etc/systemd/system/k3s-agent.service.env > /dev/null;
    echo 'K3S_URL=\"https://$TOWER_IP:6443\"' | sudo tee -a /etc/systemd/system/k3s-agent.service.env > /dev/null;
    sudo ip route add default via 10.1.10.1 dev eno1 2>/dev/null || true;
    sudo systemctl daemon-reload;
    sudo systemctl enable k3s-agent;
    sudo systemctl start k3s-agent"

  if [ "$DEBUG" = "1" ]; then
    echo "Reinstalling Agent on Nano with binary transfer..."
  $SSH_CMD $SSH_USER@$NODE_IP "$K3S_REINSTALL_CMD"
    # Ensure environment file exists with correct server URL
  $SSH_CMD $SSH_USER@$NODE_IP "sudo mkdir -p /etc/systemd/system && echo 'K3S_TOKEN=\"$TOKEN\"' | sudo tee /etc/systemd/system/k3s-agent.service.env > /dev/null && echo 'K3S_URL=\"https://$TOWER_IP:6443\"' | sudo tee -a /etc/systemd/system/k3s-agent.service.env > /dev/null" 2>/dev/null || true
    # CRITICAL: Ensure systemd loads environment variables after install
  $SSH_CMD $SSH_USER@$NODE_IP "sudo systemctl daemon-reload && sudo systemctl restart k3s-agent" 2>/dev/null || true
  wait_for_agent $NODE_NAME
  else
    step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Reinstalling K3s agent on $NODE_NAME..."
    sleep 5
    # Execute the binary transfer install command
  if [ "$DEBUG" = "1" ]; then
    echo "Running K3s agent install command on $NODE_DISPLAY..."
  fi
  if $SSH_CMD $SSH_USER@$NODE_IP "$K3S_REINSTALL_CMD" > /dev/null 2>&1; then
      # Ensure environment file exists with correct server URL
  if [ "$DEBUG" = "1" ]; then
    echo "Setting up K3s environment files on $NODE_DISPLAY..."
  fi
  $SSH_CMD $SSH_USER@$NODE_IP "sudo mkdir -p /etc/systemd/system && echo 'K3S_TOKEN=\"$TOKEN\"' | sudo tee /etc/systemd/system/k3s-agent.service.env > /dev/null && echo 'K3S_URL=\"https://$TOWER_IP:6443\"' | sudo tee -a /etc/systemd/system/k3s-agent.service.env > /dev/null" > /dev/null 2>&1
      # CRITICAL: Ensure systemd loads environment variables after install
  if [ "$DEBUG" = "1" ]; then
    echo "Reloading systemd and restarting k3s-agent on $NODE_DISPLAY..."
  fi
  $SSH_CMD $SSH_USER@$NODE_IP "sudo systemctl daemon-reload && sudo systemctl restart k3s-agent" > /dev/null 2>&1
  wait_for_agent $NODE_NAME
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



step_05(){
# =========================================================================
# STEP 05: Systemd Service Override (force correct server/node IP) Nano
# =========================================================================
step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Forcing K3s $NODE_NAME agent to use correct server IP..."

# Add Nano host key to known_hosts to avoid SSH warning
if [ "$DEBUG" = "1" ]; then
  echo "Adding $NODE_DISPLAY host key to known_hosts..."
fi
ssh-keyscan -H $NODE_IP >> ~/.ssh/known_hosts 2>/dev/null

# Create systemd override directory and file directly instead of using systemctl edit
if [ "$DEBUG" = "1" ]; then
  echo "Creating systemd override directory on $NODE_DISPLAY..."
fi
$SSH_CMD $SSH_USER@$NODE_IP "sudo mkdir -p /etc/systemd/system/k3s-agent.service.d/" > /dev/null 2>&1

if [ "$DEBUG" = "1" ]; then
  echo "Creating systemd override file on $NODE_DISPLAY..."
fi
$SSH_CMD $SSH_USER@$NODE_IP "sudo tee /etc/systemd/system/k3s-agent.service.d/override.conf > /dev/null" << EOF
[Service]
Environment="K3S_URL=https://$TOWER_IP:6443"
Environment="K3S_NODE_IP=$NODE_IP"
EOF

# Reload daemon and restart the service
if [ "$DEBUG" = "1" ]; then
  echo "Reloading systemd and restarting k3s-agent on $NODE_DISPLAY..."
fi
$SSH_CMD $SSH_USER@$NODE_IP "sudo systemctl daemon-reload && sudo timeout 30 systemctl restart k3s-agent" > /dev/null 2>&1

# Check the exit status of the SSH command
if [ $? -eq 0 ]; then
    # Wait for the agent to re-join and be ready
  wait_for_agent $NODE_NAME
  echo -e "✅\x1b[0m"
else
  echo -e "❌\x1b[0m"
  echo -e "\x1b[31mFATAL: Failed to overwrite $NODE_DISPLAY service file.\x1b[0m"
  exit 1
fi
step_increment
print_divider
}




step_06(){
# -------------------------------------------------------------------------
# STEP 06: Create Registry Config Directory Nano
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Adding Registry Config Dir on Nano..."
    sleep 5
  $SSH_CMD $SSH_USER@$NODE_IP "sudo mkdir -p /etc/rancher/k3s/"
    echo ""
  else
    step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Creating $NODE_NAME registry configuration directory..."
    sleep 5
  if [ "$DEBUG" = "1" ]; then
    echo "Creating /etc/rancher/k3s/ directory on $NODE_DISPLAY..."
  fi
  if $SSH_CMD $SSH_USER@$NODE_IP "sudo mkdir -p /etc/rancher/k3s/" > /dev/null 2>&1; then
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





step_07(){
# -------------------------------------------------------------------------
# STEP 07: Configure Registry for Nano
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Configuring Registry for Nano..."
    sleep 5
  else
    step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Configuring registry for $NODE_NAME..."
    sleep 5
    if [[ "$REGISTRY_PROTOCOL" == "https" ]]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Configuring HTTPS registry on $NODE_DISPLAY..."
  fi
  $SSH_CMD $SSH_USER@$NODE_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
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
  $SSH_CMD $SSH_USER@$NODE_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT" > /dev/null 2>&1 && \
  $SSH_CMD $SSH_USER@$NODE_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"https://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
  ca = \"/etc/docker/certs.d/$REGISTRY_IP/ca.crt\"
  client = [\"/etc/docker/certs.d/$REGISTRY_IP/registry.crt\", \"/etc/docker/certs.d/$REGISTRY_IP/registry.key\"]
EOF
" > /dev/null 2>&1
    else
  if [ "$DEBUG" = "1" ]; then
    echo "Configuring HTTP registry on $NODE_DISPLAY..."
  fi
  $SSH_CMD $SSH_USER@$NODE_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
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
  $SSH_CMD $SSH_USER@$NODE_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT" > /dev/null 2>&1 && \
  $SSH_CMD $SSH_USER@$NODE_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"http://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
EOF
" > /dev/null 2>&1
    fi
    if [ $? -eq 0 ]; then
      echo -e "\e[32m✅\e[0m"
    else
      echo -e "\e[31m❌\e[0m"
      exit 1
    fi
  fi
fi
step_increment
print_divider
}





step_08(){
# -------------------------------------------------------------------------
# STEP 08: Restart Agent After Registry Config
# -------------------------------------------------------------------------
  if [ "$DEBUG" = "1" ]; then
  echo "Restarting Agent After Registry Config Nano..."
  sleep 5
  $SSH_CMD $SSH_USER@$NODE_IP "sudo systemctl restart k3s-agent"
  wait_for_agent $NODE_NAME
else
  step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Restarting K3s agent after registry config..."
  sleep 5
  # Use timeout to prevent hanging on systemctl restart
  if $SSH_CMD $SSH_USER@$NODE_IP "sudo timeout 30 systemctl restart k3s-agent" > /dev/null 2>&1; then
    wait_for_agent $NODE_NAME
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




step_09(){
# --------------------------------------------------------------------------------
# STEP 09: Configure NVIDIA Runtime on Nano
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Restarting K3s Agent on Nano after containerd config..."
  sleep 5
  $SSH_CMD $SSH_USER@$NODE_IP "sudo systemctl stop k3s-agent"
  $SSH_CMD $SSH_USER@$NODE_IP "sudo systemctl start k3s-agent"
  wait_for_agent $NODE_NAME
else
  step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Restarting K3s agent after containerd config..."
  sleep 5
  if $SSH_CMD $SSH_USER@$NODE_IP "sudo systemctl stop k3s-agent" > /dev/null 2>&1 && $SSH_CMD $SSH_USER@$NODE_IP "sudo systemctl start k3s-agent" > /dev/null 2>&1; then
    wait_for_agent $NODE_NAME
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}


step_10(){
# --------------------------------------------------------------------------------
# STEP 10: Install NVIDIA Device Plugin for GPU Support
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Installing NVIDIA Device Plugin for GPU support..."
sleep 5
# Apply the NVIDIA device plugin DaemonSet with correct configuration for Jetson Nano
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
step_increment
print_divider
}

step_11(){
# --------------------------------------------------------------------------------
# STEP 11: Configure Docker for Insecure Registry
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Configuring Docker daemon for insecure registry... (Verbose output below)"
  sleep 5
  # Configure Docker daemon for insecure registry
  if ! command -v jq >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y jq >/dev/null 2>&1
  fi
  if [ -f /etc/docker/daemon.json ] && command -v jq >/dev/null 2>&1; then
    sudo jq '.["insecure-registries"] = ["10.1.10.150:30500", "10.1.10.244:30500", "10.1.10.181:30500", "10.1.10.201:30500", "10.1.10.202:30500"]' /etc/docker/daemon.json | sudo tee /etc/docker/daemon.json.tmp > /dev/null
    sudo mv /etc/docker/daemon.json.tmp /etc/docker/daemon.json
  else
    echo '{"insecure-registries": ["10.1.10.150:30500", "10.1.10.244:30500", "10.1.10.181:30500", "10.1.10.201:30500", "10.1.10.202:30500"]}' | sudo tee /etc/docker/daemon.json > /dev/null
  fi
  sudo systemctl restart docker
else
  step_echo_start "s" "tower" "$TOWER_IP" "Configuring Docker for insecure registry..."
  sleep 5
  if ! command -v jq >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y jq >/dev/null 2>&1
  fi
  if [ -f /etc/docker/daemon.json ] && command -v jq >/dev/null 2>&1; then
    sudo jq '.["insecure-registries"] = ["10.1.10.150:30500", "10.1.10.244:30500", "10.1.10.181:30500", "10.1.10.201:30500", "10.1.10.202:30500"]' /etc/docker/daemon.json | sudo tee /etc/docker/daemon.json.tmp > /dev/null
    sudo mv /etc/docker/daemon.json.tmp /etc/docker/daemon.json
  else
    echo '{"insecure-registries": ["10.1.10.150:30500", "10.1.10.244:30500", "10.1.10.181:30500", "10.1.10.201:30500", "10.1.10.202:30500"]}' | sudo tee /etc/docker/daemon.json > /dev/null
  fi
  if sudo systemctl restart docker > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[32m✅[0m"
  fi
fi
step_increment
print_divider
}

step_12(){
# --------------------------------------------------------------------------------
# STEP 12: Clean up FastAPI Nano Docker Image Tags
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

step_12(){
# --------------------------------------------------------------------------------
# STEP 12: Build Nano Docker Image
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Building Nano Docker image... (Verbose output below)"
  sleep 5
  cd /home/sanjay/containers/kubernetes/agent/nano && sudo docker buildx build --platform linux/arm64 -f dockerfile.nano.req -t fastapi-nano:latest --load .
else
  step_echo_start "s" "tower" "$TOWER_IP" "Building Nano Docker image..."
  sleep 5
  if cd /home/sanjay/containers/kubernetes/agent/nano && sudo docker buildx build --platform linux/arm64 -f dockerfile.nano.req -t fastapi-nano:latest --load . > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}

step_13(){
# --------------------------------------------------------------------------------
# STEP 13: Tag Nano Docker Image
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Tagging Nano Docker image..."
  sleep 5
  sudo docker tag fastapi-nano:latest $REGISTRY_IP:$REGISTRY_NODE_PORT/fastapi-nano:latest
else
  step_echo_start "s" "tower" "$TOWER_IP" "Tagging Nano Docker image..."
  sleep 5
  if sudo docker tag fastapi-nano:latest $REGISTRY_IP:$REGISTRY_NODE_PORT/fastapi-nano:latest > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider
}

step_14(){
# -------------------------------------------------------------------------
# STEP 14: Push Image
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Pushing Image... (Verbose output below)"

  sleep 5
  sudo docker push $REGISTRY_IP:$REGISTRY_NODE_PORT/fastapi-nano:latest
else
  step_echo_start "s" "tower" "$TOWER_IP" "Pushing Docker image to registry..."
  sleep 5
  if sudo docker push $REGISTRY_IP:$REGISTRY_NODE_PORT/fastapi-nano:latest > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider

}




step_15(){
# ------------------------------------------------------------------------
# STEP 15: Deploy FastAPI on Nano (CPU-only)
# ------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Deploying AI Workload on nano (CPU-only)..."
    sleep 5
    # Delete existing deployment and services if they exist to ensure clean apply
    echo "Checking for services using nodePort 30004..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get services --all-namespaces -o wide | grep 30004 || echo "No services found using 30004"
    # Also delete AGX services that may be using conflicting ports
    echo "Deleting existing fastapi-agx-nodeport service..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-agx-nodeport --ignore-not-found=true
    echo "Deleting existing fastapi-nano deployment..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete deployment fastapi-nano --ignore-not-found=true
    echo "Deleting existing fastapi-nano-service..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-nano-service --ignore-not-found=true
    echo "Deleting existing fastapi-nano-nodeport..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-nano-nodeport --ignore-not-found=true
    sleep 5
    # Create deployment YAML for FastAPI Nano without GPU resources
    echo "Applying FastAPI deployment YAML..."
  fi
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
        image: $REGISTRY_IP:$REGISTRY_NODE_PORT/fastapi-nano:latest
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
          value: "nano"
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
        - name: nano-home
          mountPath: /home/nano
        - name: nano-config
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
  - port: 8001
    targetPort: 8001
    protocol: TCP
    name: llm-api
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
    echo -e "\n✅ AI Workload deployed on $NODE_NAME (CPU-only)"
  else
    echo -e "\n❌ Failed to deploy AI Workload on $NODE_NAME"
    exit 1
  fi
  else
    step_echo_start "a" "nano" "$NANO_IP" "Deploying AI Workload on nano (CPU-only)"
    sleep 5
    # Delete existing deployment and services if they exist to ensure clean apply
    echo "Checking for services using nodePort 30004..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get services --all-namespaces -o wide | grep 30004 || echo "No services found using 30004"
    # Also delete AGX services that may be using conflicting ports
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-agx-nodeport --ignore-not-found=true > /dev/null 2>&1
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete deployment fastapi-nano --ignore-not-found=true > /dev/null 2>&1
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-nano-service --ignore-not-found=true > /dev/null 2>&1
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-nano-nodeport --ignore-not-found=true > /dev/null 2>&1
    sleep 5
    # Create deployment YAML for FastAPI Nano without GPU resources
    cat <<EOF | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f - 2>&1
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
        image: $REGISTRY_IP:$REGISTRY_NODE_PORT/fastapi-nano:latest
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
          value: "nano"
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
        - name: nano-home
          mountPath: /home/nano
        - name: nano-config
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
  - port: 8001
    targetPort: 8001
    protocol: TCP
    name: llm-api
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
    echo -e "\n✅ AI Workload deployed on $NODE_NAME (CPU-only)"
  else
    echo -e "\n❌ Failed to deploy AI Workload on $NODE_NAME"
    exit 1
  fi
fi
step_increment
print_divider
}




step_16(){
# --------------------------------------------------------------------------------
# STEP 16: GPU CAPACITY VERIFICATION
# --------------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ] || [ "$INSTALL_AGX_AGENT" = true ]; then
  step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Verifying $NODE_DISPLAY GPU capacity..."
  sleep 5
  if wait_for_gpu_capacity; then
    GPU_AVAILABLE=true
    echo -e "[32m✅[0m"
  else
    GPU_AVAILABLE=false
    echo -e "[33m⚠️ GPU not available, skipping GPU steps[0m"
  fi
fi
step_increment
print_divider
}


step_17(){
# --------------------------------------------------------------------------------
# STEP 17: GPU RESOURCE CLEANUP
# --------------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ] || [ "$INSTALL_AGX_AGENT" = true ] && [ "$GPU_AVAILABLE" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Cleaning up $NODE_DISPLAY GPU resources for deployment..."
    # Check if CPU deployment exists before cleanup
    echo "Checking if CPU deployment exists..."
    if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get deployment fastapi-$NODE_NAME -n default --ignore-not-found=true | grep -q "fastapi-$NODE_NAME"; then
      # Force-delete any stuck pods on node to free GPU resources
      echo "Force-deleting stuck pods on node to free GPU resources..."
      sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete pods -l kubernetes.io/hostname=$NODE_NAME --force --grace-period=0 -n default --ignore-not-found=true
      # Delete Nano AI Workload deployment to free GPU resources
      echo "Deleting Nano AI Workload deployment to free GPU resources..."
      sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete deployment fastapi-nano -n default --ignore-not-found=true
      sleep 5 # Give time for GPU resources to be fully released
      echo "GPU resources cleaned up successfully"
    else
      echo "No Nano CPU deployment found, skipping cleanup"
    fi
  else
    step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Cleaning up $NODE_DISPLAY GPU resources for deployment..."

    # Check if CPU deployment exists before cleanup
    if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get deployment fastapi-$NODE_NAME -n default --ignore-not-found=true | grep -q "fastapi-$NODE_NAME"; then
      # Force-delete any stuck pods on node to free GPU resources
      if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete pods -l kubernetes.io/hostname=$NODE_NAME --force --grace-period=0 -n default --ignore-not-found=true > /dev/null 2>&1; then
        :
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
      echo -e "No Nano CPU deployment found, skipping cleanup"
      echo -e "[32m✅[0m"
    fi
  fi
fi
step_increment
print_divider
}


step_18(){
# --------------------------------------------------------------------------------
# STEP 18: NANO GPU-ENABLED AI WORKLOAD DEPLOYMENT
# --------------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ] && [ "$GPU_AVAILABLE" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Deploying GPU-enabled AI Workload on Nano..."
    # Deploy Nano AI Workload with GPU resources and services
    # Delete existing deployment and services if they exist to ensure clean apply
    # Also delete AGX services that may be using conflicting ports
    echo "Deleting existing fastapi-agx-nodeport service..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-agx-nodeport --ignore-not-found=true
    echo "Deleting existing fastapi-nano deployment..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete deployment fastapi-nano --ignore-not-found=true
    echo "Deleting existing fastapi-nano-service..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-nano-service --ignore-not-found=true
    echo "Deleting existing fastapi-nano-nodeport..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-nano-nodeport --ignore-not-found=true
    echo "Creating GPU-enabled deployment YAML..."
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
        image: $REGISTRY_IP:$REGISTRY_NODE_PORT/fastapi-nano:latest
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
          value: "nano"
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
        - name: nano-home
          mountPath: /home/nano
        - name: nano-config
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
      - name: nano-home
        nfs:
          server: $TOWER_IP
          path: /export/vmstore/nano_home
      - name: nano-config
        nfs:
          server: $TOWER_IP
          path: /export/vmstore/tower_home/kubernetes/agent/nano/app/config
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
  - port: 8001
    targetPort: 8001
    protocol: TCP
    name: llm-api
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
    echo "Applying GPU-enabled $NODE_DISPLAY FastAPI deployment..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /tmp/fastapi-nano-gpu.yaml
    apply_exit=$?
  else
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /tmp/fastapi-nano-gpu.yaml > /dev/null 2>&1
    apply_exit=$?
  fi

  if [ $apply_exit -eq 0 ]; then
    echo -e "✅ GPU-enabled AI Workload deployed on $NODE_DISPLAY"
    # Wait for GPU-enabled pod to be running
    echo -e "Waiting for GPU-enabled FastAPI pod to be ready..."
    for i in {1..60}; do
      if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -l app=fastapi-nano -o jsonpath='{.items[0].status.phase}' 2>/dev/null | grep -q "Running"; then
        echo -e "✅ GPU-enabled AI Workload pod is running on $NODE_DISPLAY"
        break
      fi
      sleep 5
    done
    if [ $i -eq 60 ]; then
      echo -e "❌ GPU-enabled AI Workload pod did not start within 5 minutes"
      exit 1
    fi
  else
    echo -e "❌ Failed to deploy GPU-enabled AI Workload on $NODE_DISPLAY"
    exit 1
  fi
  else
    step_echo_start "a" "nano" "$NANO_IP" "Deploying GPU-enabled AI Workload on Nano..."
    echo -e "[32m✅[0m"

    # Deploy Nano AI Workload with GPU resources and services
    # Delete existing deployment and services if they exist to ensure clean apply
    # Also delete AGX services that may be using conflicting ports
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-agx-nodeport --ignore-not-found=true > /dev/null 2>&1
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete deployment fastapi-nano --ignore-not-found=true > /dev/null 2>&1
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-nano-service --ignore-not-found=true > /dev/null 2>&1
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete service fastapi-nano-nodeport --ignore-not-found=true > /dev/null 2>&1
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
        image: $REGISTRY_IP:$REGISTRY_NODE_PORT/fastapi-nano:latest
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
          value: "nano"
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
        - name: nano-home
          mountPath: /home/nano
        - name: nano-config
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
      - name: nano-home
        nfs:
          server: $TOWER_IP
          path: /export/vmstore/nano_home
      - name: nano-config
        nfs:
          server: $TOWER_IP
          path: /export/vmstore/tower_home/kubernetes/agent/nano/app/config
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
  - port: 8001
    targetPort: 8001
    protocol: TCP
    name: llm-api
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
      echo "Applying GPU-enabled $NODE_DISPLAY FastAPI deployment..."
      sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /tmp/fastapi-nano-gpu.yaml
      apply_exit=$?
    else
      sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /tmp/fastapi-nano-gpu.yaml > /dev/null 2>&1
      apply_exit=$?
    fi

    if [ $apply_exit -eq 0 ]; then
      echo -e "✅ GPU-enabled AI Workload deployed on $NODE_DISPLAY"
      # Wait for GPU-enabled pod to be running
      echo -e "Waiting for GPU-enabled FastAPI pod to be ready..."
      for i in {1..60}; do
        if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -l app=fastapi-nano -o jsonpath='{.items[0].status.phase}' 2>/dev/null | grep -q "Running"; then
          echo -e "✅ GPU-enabled AI Workload pod is running on $NODE_DISPLAY"
          break
        fi
        sleep 5
      done
      if [ $i -eq 60 ]; then
        echo -e "❌ GPU-enabled AI Workload pod did not start within 5 minutes"
        exit 1
      fi
    else
      echo -e "❌ Failed to deploy GPU-enabled AI Workload on $NODE_DISPLAY"
      exit 1
    fi
  fi
fi
step_increment
print_divider
}


step_19(){
# --------------------------------------------------------------------------------
# STEP 19: FINAL VERIFICATION - NODE AND POD STATUS
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Final verification: Node and pod status..."
  sleep 5

  # Wait for all pods to be ready and no pods terminating
  echo "Waiting for all pods to be ready and no terminating pods..."
  timeout=600  # 10 minutes
  count=0
  while true; do
    # Check if all pods are Ready
    not_ready_count=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods --all-namespaces -o jsonpath='{.items[*].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null | grep -v True | wc -l)
    # Check for terminating pods
    terminating_count=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods --all-namespaces -o jsonpath='{.items[*].status.phase}' 2>/dev/null | grep -c Terminating)
    
    if [ "$not_ready_count" -eq 0 ] && [ "$terminating_count" -eq 0 ]; then
      break
    fi
    
    if [ $count -ge $timeout ]; then
      echo "Warning: Pods not fully ready or terminating pods still present within $timeout seconds, proceeding with status check..."
      break
    fi
    echo "Pods not ready or terminating pods present, waiting... ($((count / 10 + 1))/60)"
    sleep 10
    count=$((count + 10))
  done

  echo ""
  echo "=== NODE STATUS ==="
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes
  echo ""
  echo "=== POD STATUS ==="
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide
  echo ""
  echo -e "✅ Final verification complete"
else
  step_echo_start "s" "tower" "$TOWER_IP" "Final verification: Node and pod status..."
  sleep 5

  # Wait for all pods to be ready and no pods terminating
  echo "Waiting for all pods to be ready and no terminating pods..."
  timeout=600  # 10 minutes
  count=0
  while true; do
    # Check if all pods are Ready
    not_ready_count=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods --all-namespaces -o jsonpath='{.items[*].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null | grep -v True | wc -l)
    # Check for terminating pods
    terminating_count=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods --all-namespaces -o jsonpath='{.items[*].status.phase}' 2>/dev/null | grep -c Terminating)
    
    if [ "$not_ready_count" -eq 0 ] && [ "$terminating_count" -eq 0 ]; then
      break
    fi
    
    if [ $count -ge $timeout ]; then
      echo "Warning: Pods not fully ready or terminating pods still present within $timeout seconds, proceeding with status check..."
      break
    fi
    echo "Pods not ready or terminating pods present, waiting... ($((count / 10 + 1))/60)"
    sleep 10
    count=$((count + 10))
  done

  echo ""
  echo "=== NODE STATUS ==="
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes
  echo ""
  echo "=== POD STATUS ==="
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide
  echo ""
  echo -e "✅ Final verification complete"
fi
step_increment
print_divider
}


step_20(){
# --------------------------------------------------------------------------------
# STEP 20: DISPLAY SERVICE ENDPOINTS
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Displaying available service endpoints..."
  sleep 2
  echo ""
  echo "Services Available:"
  echo "FastAPI: http://$NODE_IP:30002"
  echo "Jupyter: http://$NODE_IP:30003"
  echo "LLM API: http://$NODE_IP:30007"
  echo "Health Check: http://$NODE_IP:30002/health"
  echo "Swagger UI: http://$NODE_IP:30002/docs"
  echo ""
  echo -e "✅ Service endpoints displayed"
else
  step_echo_start "s" "tower" "$TOWER_IP" "Displaying available service endpoints..."
  sleep 2
  echo ""
  echo "Services Available:"
  echo "FastAPI: http://$NODE_IP:30002"
  echo "Jupyter: http://$NODE_IP:30003"
  echo "LLM API: http://$NODE_IP:30007"
  echo "Health Check: http://$NODE_IP:30002/health"
  echo "Swagger UI: http://$NODE_IP:30002/docs"
  echo ""
  echo -e "✅ Service endpoints displayed"
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


