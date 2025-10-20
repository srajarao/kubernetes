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

# IP addresses
TOWER_IP="10.1.10.150"
NANO_IP="10.1.10.181"   # <-- Updated: Nano is now at 10.1.10.181
AGX_IP="10.1.10.244"
SPARK1_IP="10.1.10.201"
SPARK2_IP="10.1.10.202"

# Initialize uninstall success flag
UNINSTALL_SUCCESS=false

# Parse command line argument for node type
NODE_TYPE=${1:-agx}

if [ "$NODE_TYPE" = "agx" ]; then
  INSTALL_AGX_AGENT=true
  INSTALL_NANO_AGENT=false
  NODE_IP=$AGX_IP
  NODE_NAME="agx"
  NODE_DISPLAY="AGX"
elif [ "$NODE_TYPE" = "nano" ]; then
  INSTALL_AGX_AGENT=false
  INSTALL_NANO_AGENT=true
  INSTALL_SPARK1_AGENT=false
  INSTALL_SPARK2_AGENT=false
  NODE_IP=$NANO_IP
  NODE_NAME="nano"
  NODE_DISPLAY="Nano"
elif [ "$NODE_TYPE" = "spark1" ]; then
  INSTALL_AGX_AGENT=false
  INSTALL_NANO_AGENT=false
  INSTALL_SPARK1_AGENT=true
  INSTALL_SPARK2_AGENT=false
  NODE_IP=$SPARK1_IP
  NODE_NAME="spark1"
  NODE_DISPLAY="Spark1"
elif [ "$NODE_TYPE" = "spark2" ]; then
  INSTALL_AGX_AGENT=false
  INSTALL_NANO_AGENT=false
  INSTALL_SPARK1_AGENT=false
  INSTALL_SPARK2_AGENT=true
  NODE_IP=$SPARK2_IP
  NODE_NAME="spark2"
  NODE_DISPLAY="Spark2"
else
  echo "Usage: $0 [agx|nano|spark1|spark2]"
  echo "Example: $0 agx"
  exit 1
fi

echo "Configuring K3s agent for $NODE_DISPLAY ($NODE_IP)"

# Set default HOME/CONFIG paths and default preferred NodePorts so they are
# available to all steps (they may be adjusted later if ports are already
# in use on the cluster).
if [ "$NODE_TYPE" = "agx" ]; then
  HOME_PATH="/export/vmstore/agx_home"
  CONFIG_PATH="/export/vmstore/tower_home/kubernetes/agent/agx/app/config"
  DEFAULT_NODEPORT_HTTP=30004
  DEFAULT_NODEPORT_JUPYTER=30005
  DEFAULT_NODEPORT_LLM=30006
elif [ "$NODE_TYPE" = "nano" ]; then
  HOME_PATH="/export/vmstore/nano_home"
  CONFIG_PATH="/export/vmstore/tower_home/kubernetes/agent/nano/app/config"
  DEFAULT_NODEPORT_HTTP=30014
  DEFAULT_NODEPORT_JUPYTER=30015
  DEFAULT_NODEPORT_LLM=30016
elif [ "$NODE_TYPE" = "spark1" ]; then
  HOME_PATH="/export/vmstore/spark1_home"
  CONFIG_PATH="/export/vmstore/tower_home/kubernetes/agent/spark1/app/config"
  DEFAULT_NODEPORT_HTTP=30024
  DEFAULT_NODEPORT_JUPYTER=30025
  DEFAULT_NODEPORT_LLM=30026
elif [ "$NODE_TYPE" = "spark2" ]; then
  HOME_PATH="/export/vmstore/spark2_home"
  CONFIG_PATH="/export/vmstore/tower_home/kubernetes/agent/spark2/app/config"
  DEFAULT_NODEPORT_HTTP=30034
  DEFAULT_NODEPORT_JUPYTER=30035
  DEFAULT_NODEPORT_LLM=30036
else
  # Fallback to nano-style defaults for unknown node types
  HOME_PATH="/export/vmstore/nano_home"
  CONFIG_PATH="/export/vmstore/tower_home/kubernetes/agent/nano/app/config"
  DEFAULT_NODEPORT_HTTP=30014
  DEFAULT_NODEPORT_JUPYTER=30015
  DEFAULT_NODEPORT_LLM=30016
fi

# Helper: find a free NodePort on the cluster. Prefers the provided port if
# it's available or already owned by this node's FastAPI service; otherwise
# scans a small range and returns the first free port.
find_free_nodeport(){
  preferred=$1
  svc_lines=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get svc --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.name} {range .spec.ports[*]}{.nodePort} {" "}{end}{"\n"}{end}' 2>/dev/null || true)
  used_ports=$(echo "$svc_lines" | awk '{for (i=3;i<=NF;i++) printf "%s ", $i}')

  # If preferred is not in use at all, return it
  if [ -z "$used_ports" ] || ! echo "$used_ports" | tr ' ' '\n' | grep -qw "$preferred"; then
    echo "$preferred"
    return 0
  fi

  # If preferred is already in use by this node's fastapi service, accept it
  svc_using=$(echo "$svc_lines" | awk -v p="$preferred" '$0 ~ (" "p" ") {print $2; exit}')
  if [ -n "$svc_using" ] && echo "$svc_using" | grep -q "^fastapi-$NODE_NAME"; then
    echo "$preferred"
    return 0
  fi

  # Otherwise find a free port in a reasonable range
  for p in $(seq 30004 30100); do
    if ! echo "$used_ports" | tr ' ' '\n' | grep -qw "$p"; then
      echo "$p"
      return 0
    fi
  done

  # If nothing found, return empty string
  echo ""
  return 1
}

# Install K3s agent on spark1
INSTALL_SPARK1_AGENT=false

# Install K3s agent on spark2
INSTALL_SPARK2_AGENT=false

# Registry settings - Auto-detect available GPU node for registry
# Try AGX first (more powerful), then nano, then tower as fallback
if ping -c 1 -W 1 10.1.10.244 >/dev/null 2>&1; then
  REGISTRY_IP="10.1.10.244"  # AGX
elif ping -c 1 -W 1 10.1.10.181 >/dev/null 2>&1; then
  REGISTRY_IP="10.1.10.181"  # Nano
else
  REGISTRY_IP="10.1.10.150"  # Tower fallback
fi
REGISTRY_PORT="5000"
REGISTRY_PROTOCOL="http"  # "http" or "https"

# NVIDIA device plugin image (override by setting NVIDIA_DEVICE_PLUGIN_IMAGE env var)
# Default to the latest tag; change this to a pinned version for reproducible
# deployments if you prefer (e.g. v0.17.1).
NVIDIA_DEVICE_PLUGIN_IMAGE="${NVIDIA_DEVICE_PLUGIN_IMAGE:-nvcr.io/nvidia/k8s-device-plugin:v0.14.1}"

# Auto-download configuration for missing k3s binary on the Tower.
# Set K3S_DOWNLOAD_URL to override the default download target.
K3S_DOWNLOAD_URL="${K3S_DOWNLOAD_URL:-https://github.com/k3s-io/k3s/releases/download/v1.33.5+k3s1/k3s-arm64}"
# When AUTO_DOWNLOAD_K3S=1 the script will attempt to download the official
# k3s arm64 binary into /tmp if the expected /tmp/$BINARY is not present.
AUTO_DOWNLOAD_K3S="${AUTO_DOWNLOAD_K3S:-1}"

# Database Configuration
POSTGRES_PASSWORD="postgres"  # PostgreSQL admin password
PGADMIN_PASSWORD="pgadmin"          # pgAdmin default password
PGADMIN_EMAIL="pgadmin@pgadmin.org" # pgAdmin default email

# Debug mode (0 for silent, 1 for verbose)
DEBUG=0


DEBUG=${DEBUG:-0}

# Define the initial script message to be logged
START_MESSAGE="Starting K3s $NODE_DISPLAY Agent Setup and FastAPI Deployment in SILENT NORMAL mode..."

# SSH defaults (centralize options and key usage)
SSH_USER="${SSH_USER:-sanjay}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH_OPTS="-o StrictHostKeyChecking=no -o LogLevel=ERROR -i $SSH_KEY"
SSH_CMD="ssh $SSH_OPTS"
SCP_CMD="scp $SSH_OPTS"
# -------------------------------------------------------------------------
# Early pre-check: ensure SSH key file exists and is readable when node agent
# operations are requested. Fail fast with clear guidance to the user.
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ] || [ "$INSTALL_NANO_AGENT" = true ] || \
   [ "$INSTALL_SPARK1_AGENT" = true ] || [ "$INSTALL_SPARK2_AGENT" = true ]; then
  if [ -z "$SSH_KEY" ]; then
    echo -e "\n\033[31mFATAL: SSH_KEY is not set. This script needs a private SSH key for passwordless Tower→node access.\033[0m\n"
    echo "ACTION: Set SSH_KEY to point to a readable private key file, e.g.:"
    echo "  export SSH_KEY=\$HOME/.ssh/id_ed25519"
    echo "Alternatively, run './6-setup_tower_sshkeys.sh' to configure Tower's SSH keys on the nodes."
    exit 1
  fi

  if [ ! -f "$SSH_KEY" ]; then
    echo -e "\n\033[31mFATAL: SSH key file not found: $SSH_KEY\033[0m\n"
    echo "ACTION: Place the private key at the path above, or set SSH_KEY to a valid key."
    echo "You can create and install keys by running './6-setup_tower_sshkeys.sh' or by manually copying the public key to the nodes' ~/.ssh/authorized_keys."
    exit 1
  fi

  if [ ! -r "$SSH_KEY" ]; then
    echo -e "\n\033[31mFATAL: SSH key file exists but is not readable by this user: $SSH_KEY\033[0m\n"
    echo "ACTION: Fix permissions and ownership, e.g.:"
    echo "  chmod 600 $SSH_KEY"
    echo "  chown $(whoami) $SSH_KEY"
    exit 1
  fi
  if [ "$DEBUG" = "1" ]; then
    echo "SSH key $SSH_KEY exists and is readable - proceeding..."
  fi
fi

# Helper to discover K3s server token. Will only fatal when an agent install is requested
get_k3s_token() {
  if [ -n "${TOKEN:-}" ]; then
    return 0
  fi

  if [ "$DEBUG" = "1" ]; then echo "Getting Token: $TOKEN"; fi
  TOKEN=$(sudo cat /var/lib/rancher/k3s/server/node-token 2>/dev/null || true)

  if [ -z "$TOKEN" ]; then
    if [ "$INSTALL_AGX_AGENT" = true ] || [ "$INSTALL_NANO_AGENT" = true ] || [ "$INSTALL_SPARK1_AGENT" = true ] || [ "$INSTALL_SPARK2_AGENT" = true ]; then
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

   # --- 5. CRITICAL: $NODE_DISPLAY K3S AGENT LOG ERRORS (Container Runtime Check) ---
    echo -e "
--- 5. CRITICAL: $NODE_DISPLAY K3S AGENT LOG ERRORS (Container Runtime Check) ---" >> "$log_file"
  echo "Executing: $SSH_CMD $SSH_USER@$NODE_IP 'sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E \"fastapi-$NODE_NAME|Error|Fail\"'" >> "$log_file"
    # Execute SSH command and pipe output directly to the log file
  $SSH_CMD $SSH_USER@$NODE_IP "sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E 'fastapi-$NODE_NAME|Error|Fail'" >> "$log_file" 2>/dev/null

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

# Generic function to wait for GPU capacity on a named node.
# Usage: wait_for_node_gpu_capacity <node-name> [timeout_seconds] [display-name]
wait_for_node_gpu_capacity() {
  local target_node="${1:-}"
  local timeout="${2:-120}"
  local display_name="${3:-$target_node}"
  local count=0

  if [ -z "$target_node" ]; then
    echo "wait_for_node_gpu_capacity: target node not provided"
    return 1
  fi

  if [ "$DEBUG" = "1" ]; then
    echo "Waiting for GPU capacity to be added on $display_name ($target_node)..."
  fi

  # Query the node's reported GPU capacity and treat any numeric value >= 1
  # as indicating GPU availability. This correctly handles nodes that report
  # more than one GPU (e.g., '2', '4', etc.) instead of relying on a
  # literal '1' match which would miss higher counts.
  while true; do
    capacity=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get node "$target_node" -o jsonpath='{.status.capacity.nvidia\.com/gpu}' 2>/dev/null || true)
    capacity=${capacity:-0}

    # Only treat strictly numeric values; ignore empty/non-numeric output
    if [[ "$capacity" =~ ^[0-9]+$ ]]; then
      if [ "$capacity" -ge 1 ]; then
        if [ "$DEBUG" = "1" ]; then
          echo "Detected GPU capacity $capacity on $display_name ($target_node)"
        fi
        break
      fi
    fi

    if [ $count -ge $timeout ]; then
      echo "GPU capacity not added on $display_name ($target_node) within $timeout seconds"
      return 1
    fi
    sleep 5
    count=$((count + 5))
  done

  if [ "$DEBUG" = "1" ]; then
    echo "GPU capacity added on $display_name ($target_node)"
  fi
  return 0
}

# Backwards-compatible wrappers for common nodes
wait_for_gpu_capacity() {
  # Default behavior preserved: wait for 'nano' if no argument supplied
  wait_for_node_gpu_capacity "${1:-nano}" "${2:-120}" "${3:-Nano}"
}

wait_for_agx_gpu_capacity() {
  wait_for_node_gpu_capacity "$NODE_NAME" "${1:-120}" "$NODE_DISPLAY"
}

wait_for_spark1_gpu_capacity() {
  wait_for_node_gpu_capacity "spark1" "${1:-120}" "Spark1"
}

wait_for_spark2_gpu_capacity() {
  wait_for_node_gpu_capacity "spark2" "${1:-120}" "Spark2"
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
# STEP 01: $NODE_DISPLAY SSH Validation
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ] || [ "$INSTALL_NANO_AGENT" = true ] || [ "$INSTALL_SPARK1_AGENT" = true ] || [ "$INSTALL_SPARK2_AGENT" = true ]; then
  # Ensure we have the K3s server token available before attempting agent install
  get_k3s_token
  if [ "$DEBUG" = "1" ]; then
    echo "Running verbose $NODE_DISPLAY SSH check..."
  fi
  step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Verifying $NODE_DISPLAY SSH connectivity..."
  sleep 5
  # Test SSH connection by running 'hostname' on the node
  if $SSH_CMD $SSH_USER@$NODE_IP "hostname" > /dev/null 2>&1; then
    echo -e "✅"
  else
    # --- Corrected Verbose Error Handling (Replaces original simple error) ---
    echo -e "❌ CRITICAL: Passwordless SSH Failed."
    echo ""
    echo -e "❌================================================================================❌"
    echo -e "❌🚨 CRITICAL ERROR: ${NODE_DISPLAY} HOST UNREACHABLE (SSH FAILED) 🚨❌"
    echo -e "❌   The Tower cannot connect to ${NODE_DISPLAY} at ${NODE_IP}.❌"
    echo -e "❌   ACTION REQUIRED: Please run './6-setup_tower_sshkeys.sh' manually❌"
    echo -e "❌   and enter the password when prompted to enable passwordless SSH.❌"
    echo -e "❌================================================================================❌"
    exit 1
  fi
else
  echo "{a} [$NODE_NAME  ] [$NODE_IP] ${CURRENT_STEP}/${TOTAL_STEPS}. $NODE_DISPLAY SSH verification skipped (not enabled)"
fi
step_increment
print_divider
}





step_02(){
# -------------------------------------------------------------------------
# STEP 02: $NODE_DISPLAY ARP/PING CHECK
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ] || [ "$INSTALL_NANO_AGENT" = true ] || [ "$INSTALL_SPARK1_AGENT" = true ] || [ "$INSTALL_SPARK2_AGENT" = true ]; then
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
# STEP 03: Uninstall K3s Agent on $NODE_DISPLAY
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ] || [ "$INSTALL_NANO_AGENT" = true ] || [ "$INSTALL_SPARK1_AGENT" = true ] || [ "$INSTALL_SPARK2_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Uninstalling Agent on $NODE_DISPLAY... (Verbose output below)"
    sleep 5
    # Check if k3s binaries exist before attempting uninstall
  if $SSH_CMD $SSH_USER@$NODE_IP "test -x /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
  $SSH_CMD $SSH_USER@$NODE_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh"
    else
      echo "k3s-agent-uninstall.sh not found on $NODE_DISPLAY - no uninstall needed"
    fi
  else
    step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Uninstalling K3s agent on $NODE_NAME..."
    sleep 5
    # Check if k3s binaries exist before attempting uninstall
  if $SSH_CMD $SSH_USER@$NODE_IP "test -x /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
  if $SSH_CMD $SSH_USER@$NODE_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
        echo -e "✅"
        UNINSTALL_SUCCESS=true
      else
        echo -e "❌ (uninstall failed - will attempt reinstallation)"
        UNINSTALL_SUCCESS=false
      fi
    else
      echo -e "✅ (already uninstalled)"
      UNINSTALL_SUCCESS=true
    fi
  fi
fi
step_increment
print_divider
}





step_04(){
# -------------------------------------------------------------------------
# STEP 04: Reinstall $NODE_DISPLAY Agent (BINARY TRANSFER INSTALL)
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ] || [ "$INSTALL_NANO_AGENT" = true ] || [ "$INSTALL_SPARK1_AGENT" = true ] || [ "$INSTALL_SPARK2_AGENT" = true ]; then
  # Always attempt reinstallation to ensure proper setup

  # Determine binary name based on node type. AGX uses the standard arm64
  # build; Nano and Spark nodes (Jetson-style devices) use the 'nano'
  # variant which includes necessary patches/drivers.
  if [ "$NODE_TYPE" = "agx" ]; then
    BINARY="k3s-arm64"
  elif [ "$NODE_TYPE" = "nano" ] || [ "$NODE_TYPE" = "spark1" ] || [ "$NODE_TYPE" = "spark2" ]; then
    BINARY="k3s-arm64-nano"
  else
    # Conservative default: use the nano variant for unrecognized/edge nodes
    BINARY="k3s-arm64-nano"
  fi
  
  # Use binary transfer for reliable installation
  K3S_REINSTALL_CMD="export K3S_TOKEN=\"$TOKEN\";
    # Binary is expected to already be present at /tmp/$BINARY on the node.
    # The tower will copy the file to the node prior to running the
    # installation commands so no remote-side scp is required here.
    sudo chmod +x /tmp/$BINARY;
    sudo cp /tmp/$BINARY /usr/local/bin/k3s;
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
ExecStart=/usr/local/bin/k3s agent --node-name $NODE_NAME --node-ip $NODE_IP --disable-apiserver-lb
EOF';
    echo 'K3S_TOKEN=\"$TOKEN\"' | sudo tee /etc/systemd/system/k3s-agent.service.env > /dev/null;
    echo 'K3S_URL=\"https://$TOWER_IP:6443\"' | sudo tee -a /etc/systemd/system/k3s-agent.service.env > /dev/null;
    sudo ip route add default via 10.1.10.1 dev eno1 2>/dev/null || true;
    sudo systemctl daemon-reload;
    sudo systemctl enable k3s-agent;
    sudo systemctl start k3s-agent"

  # If the expected binary does not exist locally on the Tower, attempt an
  # automated download of the official k3s ARM64 binary and create the
  # expected filename. This supports environments where the 'nano' variant
  # is not maintained separately and the generic ARM64 binary is sufficient.
  if [ ! -f "/tmp/$BINARY" ] && [ "$AUTO_DOWNLOAD_K3S" = "1" ]; then
    if [ "$DEBUG" = "1" ]; then echo "DEBUG: /tmp/$BINARY not found - attempting auto-download from $K3S_DOWNLOAD_URL"; fi
    # Prefer curl, fall back to wget. Download to /tmp/k3s-arm64 first.
    if command -v curl >/dev/null 2>&1; then
      if curl -fsSL "$K3S_DOWNLOAD_URL" -o /tmp/k3s-arm64; then
        chmod +x /tmp/k3s-arm64 || true
        if [ "$BINARY" != "k3s-arm64" ]; then
          cp /tmp/k3s-arm64 /tmp/$BINARY || true
          chmod +x /tmp/$BINARY || true
        fi
        if [ "$DEBUG" = "1" ]; then echo "DEBUG: downloaded k3s-arm64 and prepared /tmp/$BINARY"; fi
      else
        echo "WARNING: automatic download via curl failed for $K3S_DOWNLOAD_URL"
      fi
    elif command -v wget >/dev/null 2>&1; then
      if wget -q -O /tmp/k3s-arm64 "$K3S_DOWNLOAD_URL"; then
        chmod +x /tmp/k3s-arm64 || true
        if [ "$BINARY" != "k3s-arm64" ]; then
          cp /tmp/k3s-arm64 /tmp/$BINARY || true
          chmod +x /tmp/$BINARY || true
        fi
        if [ "$DEBUG" = "1" ]; then echo "DEBUG: downloaded k3s-arm64 and prepared /tmp/$BINARY"; fi
      else
        echo "WARNING: automatic download via wget failed for $K3S_DOWNLOAD_URL"
      fi
    else
      echo "WARNING: neither curl nor wget is available; cannot auto-download k3s binary"
    fi
  fi

  # --- Tower-side copy of the binary to the node ---
  if [ -f "/tmp/$BINARY" ]; then
    if $SCP_CMD /tmp/$BINARY $SSH_USER@$NODE_IP:/tmp/$BINARY > /dev/null 2>&1; then
      if [ "$DEBUG" = "1" ]; then echo "Copied $BINARY to $NODE_DISPLAY ($NODE_IP)"; fi
    else
      echo -e "\n\033[31mERROR: Failed to copy $BINARY to $NODE_DISPLAY via SCP from Tower.\033[0m"
      echo "Ensure passwordless SSH from Tower to $NODE_DISPLAY is configured (run ./6-setup_tower_sshkeys.sh) or pre-place $BINARY on the node at /tmp." 
      exit 1
    fi
  else
    echo -e "\n\033[31mERROR: Local binary /tmp/$BINARY not found on Tower.\033[0m"
    echo "ACTION: Place $BINARY at /tmp on the Tower, or set AUTO_DOWNLOAD_K3S=1 and ensure the Tower has network access to download $K3S_DOWNLOAD_URL."
    exit 1
  fi

  if [ "$DEBUG" = "1" ]; then
    echo "Reinstalling Agent on $NODE_DISPLAY with binary transfer..."
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
  if $SSH_CMD $SSH_USER@$NODE_IP "$K3S_REINSTALL_CMD" > /dev/null 2>&1; then
      # Ensure environment file exists with correct server URL
  $SSH_CMD $SSH_USER@$NODE_IP "sudo mkdir -p /etc/systemd/system && echo 'K3S_TOKEN=\"$TOKEN\"' | sudo tee /etc/systemd/system/k3s-agent.service.env > /dev/null && echo 'K3S_URL=\"https://$TOWER_IP:6443\"' | sudo tee -a /etc/systemd/system/k3s-agent.service.env > /dev/null" > /dev/null 2>&1
      # CRITICAL: Ensure systemd loads environment variables after install
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
# --------------------------------------------------------------------------------
# STEP 5: Deploy Docker Registry
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deploying Docker Registry on $REGISTRY_IP..."
sleep 5

# Check if registry is already running
if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -l app=registry -o jsonpath='{.items[0].status.phase}' 2>/dev/null | grep -q "Running"; then
  echo -e "\n✅ Docker Registry already running"
else
  # Determine the target node for registry
  if [ "$REGISTRY_IP" = "10.1.10.244" ]; then
    REGISTRY_NODE="agx"
  elif [ "$REGISTRY_IP" = "10.1.10.181" ]; then
    REGISTRY_NODE="nano"
  else
    REGISTRY_NODE="tower"
  fi
  
  # Deploy registry on the selected node
  cat <<EOF | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f - >/dev/null 2>&1
apiVersion: apps/v1
kind: Deployment
metadata:
  name: registry
  labels:
    app: registry
spec:
  replicas: 1
  selector:
    matchLabels:
      app: registry
  template:
    metadata:
      labels:
        app: registry
    spec:
      nodeSelector:
        kubernetes.io/hostname: "$REGISTRY_NODE"
      containers:
      - name: registry
        image: registry:2.8
        ports:
        - containerPort: 5000
        env:
        - name: REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY
          value: /var/lib/registry
        - name: REGISTRY_HTTP_ADDR
          value: 0.0.0.0:5000
        - name: REGISTRY_HTTP_TLS_CERTIFICATE
          value: ""
        - name: REGISTRY_HTTP_TLS_KEY
          value: ""
        volumeMounts:
        - name: registry-storage
          mountPath: /var/lib/registry
      volumes:
      - name: registry-storage
        hostPath:
          path: /mnt/vmstore/registry
          type: DirectoryOrCreate
---
apiVersion: v1
kind: Service
metadata:
  name: registry-service
  labels:
    app: registry
spec:
  selector:
    app: registry
  ports:
  - port: 5000
    targetPort: 5000
  type: NodePort
EOF

  # Wait for registry to be ready
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml wait --for=condition=available --timeout=60s deployment/registry >/dev/null 2>&1; then
    echo -e "\n✅ Docker Registry deployed successfully"
    # Configure Docker insecure registry for both AGX and tower registries
    sudo tee /etc/docker/daemon.json > /dev/null <<EOF
{
  "insecure-registries": ["10.1.10.244:31201", "10.1.10.150:31201"]
}
EOF
    sudo systemctl restart docker
  else
    echo -e "\n❌ Failed to deploy Docker Registry"
    exit 1
  fi
fi
step_increment
print_divider
}



step_06(){
# =========================================================================
# STEP 06: Systemd Service Override (force correct server/node IP) $NODE_DISPLAY
# =========================================================================
step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Configuring K3s $NODE_NAME agent systemd configuration..."

# Add $NODE_DISPLAY host key to known_hosts to avoid SSH warning
ssh-keyscan -H $NODE_IP >> ~/.ssh/known_hosts 2>/dev/null

# Always apply systemd configuration to ensure it's correct

# Create systemd override directory and file directly instead of using systemctl edit
$SSH_CMD $SSH_USER@$NODE_IP "sudo mkdir -p /etc/systemd/system/k3s-agent.service.d/" > /dev/null 2>&1

$SSH_CMD $SSH_USER@$NODE_IP "sudo tee /etc/systemd/system/k3s-agent.service.d/override.conf > /dev/null" << EOF
[Service]
Environment="K3S_URL=https://$TOWER_IP:6443"
Environment="K3S_NODE_IP=$NODE_IP"
EOF

# Reload daemon and restart the service
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




step_07(){
# -------------------------------------------------------------------------
# STEP 07: Create Registry Config Directory $NODE_DISPLAY
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ] || [ "$INSTALL_NANO_AGENT" = true ] || [ "$INSTALL_SPARK1_AGENT" = true ] || [ "$INSTALL_SPARK2_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Adding Registry Config Dir on $NODE_DISPLAY..."
    sleep 5
  $SSH_CMD $SSH_USER@$NODE_IP "sudo mkdir -p /etc/rancher/k3s/"
    echo ""
  else
    step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Creating $NODE_NAME registry configuration directory..."
    sleep 5
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





step_08(){
# -------------------------------------------------------------------------
# STEP 08: Configure Registry for $NODE_DISPLAY
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ] || [ "$INSTALL_NANO_AGENT" = true ] || [ "$INSTALL_SPARK1_AGENT" = true ] || [ "$INSTALL_SPARK2_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Configuring Registry for $NODE_DISPLAY..."
    sleep 5
  else
    step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Configuring registry for $NODE_NAME..."
    sleep 5
    if [[ "$REGISTRY_PROTOCOL" == "https" ]]; then
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





step_09(){
# -------------------------------------------------------------------------
# STEP 09: Restart Agent After Registry Config $NODE_DISPLAY
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ] || [ "$INSTALL_NANO_AGENT" = true ] || [ "$INSTALL_SPARK1_AGENT" = true ] || [ "$INSTALL_SPARK2_AGENT" = true ]; then
  # Always restart after registry configuration to ensure changes take effect
  if [ "$DEBUG" = "1" ]; then
  echo "Restarting Agent After Registry Config $NODE_DISPLAY..."
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
fi
}




step_11(){
# --------------------------------------------------------------------------------
# STEP 11: Configure NVIDIA Runtime on $NODE_DISPLAY
# --------------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ] || [ "$INSTALL_NANO_AGENT" = true ] || [ "$INSTALL_SPARK1_AGENT" = true ] || [ "$INSTALL_SPARK2_AGENT" = true ]; then
  # Always restart after containerd config to ensure changes take effect
  if [ "$DEBUG" = "1" ]; then
    echo "Restarting K3s Agent on $NODE_DISPLAY after containerd config..."
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
      echo -e "[31m❌ Service restart failed or timed out[0m"
      echo -e "[33m⚠️  Continuing anyway - agent may restart on its own[0m"
      echo -e "⚠️"
    fi
  fi
fi
step_increment
print_divider
}


step_12(){
# --------------------------------------------------------------------------------
# STEP 12: Install NVIDIA Device Plugin for GPU Support
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Installing NVIDIA Device Plugin for GPU support..."
sleep 5

# Check if NVIDIA device plugin is already working on ANY GPU node
if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get daemonset nvidia-device-plugin-daemonset -n kube-system >/dev/null 2>&1; then
  # Check if it covers all GPU nodes (agx, nano)
  GPU_NODES=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes -l kubernetes.io/hostname=agx,kubernetes.io/hostname=nano --no-headers 2>/dev/null | wc -l)
  GPU_PODS=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -n kube-system -l name=nvidia-device-plugin-ds --no-headers 2>/dev/null | wc -l)
  if [ "$GPU_PODS" -ge "$GPU_NODES" ] && sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get node "$NODE_NAME" -o jsonpath='{.status.capacity.nvidia\.com/gpu}' 2>/dev/null | grep -q '[0-9]'; then
    echo -e "\n✅ NVIDIA Device Plugin already installed and working on all GPU nodes"
  else
    # Update existing DaemonSet to run on all GPU nodes
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f - <<EOF
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: nvidia-device-plugin-daemonset
  namespace: kube-system
spec:
  selector:
    matchLabels:
      name: nvidia-device-plugin-ds
  updateStrategy:
    type: RollingUpdate
  template:
    metadata:
      labels:
        name: nvidia-device-plugin-ds
    spec:
      tolerations:
      - key: nvidia.com/gpu
        operator: Exists
        effect: NoSchedule
      - key: CriticalAddonsOnly
        operator: Exists
      - key: node.kubernetes.io/disk-pressure
        operator: Exists
        effect: NoSchedule
      - key: node.kubernetes.io/memory-pressure
        operator: Exists
        effect: NoSchedule
      - key: node.kubernetes.io/pid-pressure
        operator: Exists
        effect: NoSchedule
      - key: node.kubernetes.io/unschedulable
        operator: Exists
        effect: NoSchedule
      - key: node.kubernetes.io/network-unavailable
        operator: Exists
        effect: NoSchedule
      nodeSelector:
        kubernetes.io/hostname: agx
      priorityClassName: system-node-critical
      containers:
      - image: nvcr.io/nvidia/k8s-device-plugin:v0.14.1
        name: nvidia-device-plugin-ctr
        env:
          - name: FAIL_ON_INIT_ERROR
            value: "false"
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
        volumeMounts:
          - name: device-plugin
            mountPath: /var/lib/kubelet/device-plugins
      volumes:
        - name: device-plugin
          hostPath:
            path: /var/lib/kubelet/device-plugins
EOF
  fi
else
  # Deploy NVIDIA device plugin
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f - <<EOF
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: nvidia-device-plugin-daemonset
  namespace: kube-system
spec:
  selector:
    matchLabels:
      name: nvidia-device-plugin-ds
  updateStrategy:
    type: RollingUpdate
  template:
    metadata:
      labels:
        name: nvidia-device-plugin-ds
    spec:
      tolerations:
      - key: nvidia.com/gpu
        operator: Exists
        effect: NoSchedule
      - key: CriticalAddonsOnly
        operator: Exists
      - key: node.kubernetes.io/disk-pressure
        operator: Exists
        effect: NoSchedule
      - key: node.kubernetes.io/memory-pressure
        operator: Exists
        effect: NoSchedule
      - key: node.kubernetes.io/pid-pressure
        operator: Exists
        effect: NoSchedule
      - key: node.kubernetes.io/unschedulable
        operator: Exists
        effect: NoSchedule
      - key: node.kubernetes.io/network-unavailable
        operator: Exists
        effect: NoSchedule
      nodeSelector:
        kubernetes.io/hostname: agx
      priorityClassName: system-node-critical
      containers:
      - image: nvcr.io/nvidia/k8s-device-plugin:v0.14.1
        name: nvidia-device-plugin-ctr
        env:
          - name: FAIL_ON_INIT_ERROR
            value: "false"
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
        volumeMounts:
          - name: device-plugin
            mountPath: /var/lib/kubelet/device-plugins
      volumes:
        - name: device-plugin
          hostPath:
            path: /var/lib/kubelet/device-plugins
EOF
fi
if [ $? -eq 0 ]; then
  echo -e "\n✅ NVIDIA Device Plugin applied successfully"
else
  echo -e "\n❌ Failed to apply NVIDIA Device Plugin"
  exit 1
fi
step_increment
print_divider
}

step_13(){
# --------------------------------------------------------------------------------
# STEP 13: Clean up FastAPI $NODE_DISPLAY Docker Image Tags
# --------------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ] || [ "$INSTALL_NANO_AGENT" = true ] || [ "$INSTALL_SPARK1_AGENT" = true ] || [ "$INSTALL_SPARK2_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Cleaning up FastAPI $NODE_DISPLAY Docker image tags... (Verbose output below)"
    sleep 5
    # Remove all tags related to fastapi-$NODE_NAME:latest
    sudo docker images | grep fastapi-$NODE_NAME | awk '{print $1":"$2}' | xargs -r sudo docker rmi
  else
    step_echo_start "s" "tower" "$TOWER_IP" "Cleaning up FastAPI $NODE_DISPLAY Docker image tags..."
    sleep 5
    if sudo docker images | grep fastapi-$NODE_NAME | awk '{print $1":"$2}' | xargs -r sudo docker rmi > /dev/null 2>&1; then
      echo -e "[32m✅[0m"
    else
      echo -e "[32m✅[0m"
    fi
  fi
fi
step_increment
print_divider
}

step_14(){
# --------------------------------------------------------------------------------
# STEP 14: Build $NODE_DISPLAY Docker Image
# --------------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ] || [ "$INSTALL_NANO_AGENT" = true ] || [ "$INSTALL_SPARK1_AGENT" = true ] || [ "$INSTALL_SPARK2_AGENT" = true ]; then
  # Determine dockerfile and directory based on node type (include Spark nodes)
  if [ "$NODE_TYPE" = "agx" ]; then
    DOCKERFILE="dockerfile.agx.req"
    DIR="agx"
  elif [ "$NODE_TYPE" = "nano" ]; then
    DOCKERFILE="dockerfile.nano.req"
    DIR="nano"
  elif [ "$NODE_TYPE" = "spark1" ]; then
    DOCKERFILE="dockerfile.nano.req"
    DIR="spark1"
  elif [ "$NODE_TYPE" = "spark2" ]; then
    DOCKERFILE="dockerfile.nano.req"
    DIR="spark2"
  else
    # Conservative default: use nano variant in nano directory
    DOCKERFILE="dockerfile.nano.req"
    DIR="nano"
  fi
  
  if [ "$DEBUG" = "1" ]; then
    echo "Building $NODE_DISPLAY Docker image... (Verbose output below)"
    sleep 5
    cd /home/sanjay/containers/kubernetes/agent/$DIR && sudo docker buildx build --platform linux/arm64 -f $DOCKERFILE -t fastapi-$NODE_NAME:latest --load .
  else
    step_echo_start "s" "tower" "$TOWER_IP" "Building $NODE_DISPLAY Docker image..."
    sleep 5
    # Check if image already exists
    if sudo docker images | grep -q "fastapi-$NODE_NAME.*latest"; then
      echo -e "[32m✅[0m (Image already exists, skipping build)"
    else
      if cd /home/sanjay/containers/kubernetes/agent/$DIR && sudo docker buildx build --platform linux/arm64 -f $DOCKERFILE -t fastapi-$NODE_NAME:latest --load . > /dev/null 2>&1; then
        echo -e "[32m✅[0m"
      else
        echo -e "[31m❌[0m"
        exit 1
      fi
    fi
  fi
fi
step_increment
print_divider
}

step_15(){
# --------------------------------------------------------------------------------
# STEP 15: Tag $NODE_DISPLAY Docker Image
# --------------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ] || [ "$INSTALL_NANO_AGENT" = true ] || [ "$INSTALL_SPARK1_AGENT" = true ] || [ "$INSTALL_SPARK2_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Tagging $NODE_DISPLAY Docker image..."
    sleep 5
    sudo docker tag fastapi-$NODE_NAME:latest $REGISTRY_IP:$REGISTRY_PORT/fastapi-$NODE_NAME:latest
  else
    step_echo_start "s" "tower" "$TOWER_IP" "Tagging $NODE_DISPLAY Docker image..."
    sleep 5
    REGISTRY_NODE_PORT=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get svc registry-service -o jsonpath='{.spec.ports[0].nodePort}')
    if sudo docker tag fastapi-$NODE_NAME:latest $REGISTRY_IP:$REGISTRY_NODE_PORT/fastapi-$NODE_NAME:latest > /dev/null 2>&1; then
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

step_16(){
# -------------------------------------------------------------------------
# STEP 16: Push Image
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ] || [ "$INSTALL_NANO_AGENT" = true ] || [ "$INSTALL_SPARK1_AGENT" = true ] || [ "$INSTALL_SPARK2_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Pushing Image... (Verbose output below)"
  
    sleep 5
    REGISTRY_NODE_PORT=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get svc registry-service -o jsonpath='{.spec.ports[0].nodePort}')
    sudo docker push $REGISTRY_IP:$REGISTRY_NODE_PORT/fastapi-$NODE_NAME:latest
  else
    step_echo_start "s" "tower" "$TOWER_IP" "Pushing Docker image to registry..."
    sleep 5
    REGISTRY_NODE_PORT=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get svc registry-service -o jsonpath='{.spec.ports[0].nodePort}')
    if sudo docker push $REGISTRY_IP:$REGISTRY_NODE_PORT/fastapi-$NODE_NAME:latest > /dev/null 2>&1; then
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




step_17(){
# ------------------------------------------------------------------------
# STEP 17: Deploy FastAPI on $NODE_DISPLAY (CPU-only)
# ------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ] || [ "$INSTALL_NANO_AGENT" = true ] || [ "$INSTALL_SPARK1_AGENT" = true ] || [ "$INSTALL_SPARK2_AGENT" = true ]; then
  step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Deploying AI Workload on $NODE_NAME (CPU-only)"
  sleep 5
  # Determine NodePort values based on node type to avoid conflicts. Use
  # the preferred defaults but pick free ports if the preferred ones are
  # already allocated by other services.
  # If a nodeport service already exists for this device, reuse its ports to
  # avoid patching and potential allocation conflicts. Otherwise allocate
  # preferred/free ports.
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get svc fastapi-$NODE_NAME-nodeport -n default --ignore-not-found=true 2>/dev/null | grep -q "fastapi-$NODE_NAME-nodeport"; then
    NODEPORT_HTTP=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get svc fastapi-$NODE_NAME-nodeport -n default -o jsonpath='{.spec.ports[?(@.name=="http")].nodePort}' 2>/dev/null || echo "")
    NODEPORT_JUPYTER=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get svc fastapi-$NODE_NAME-nodeport -n default -o jsonpath='{.spec.ports[?(@.name=="jupyter")].nodePort}' 2>/dev/null || echo "")
    NODEPORT_LLM=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get svc fastapi-$NODE_NAME-nodeport -n default -o jsonpath='{.spec.ports[?(@.name=="llm-api")].nodePort}' 2>/dev/null || echo "")
  else
    NODEPORT_HTTP=$(find_free_nodeport $DEFAULT_NODEPORT_HTTP)
    NODEPORT_JUPYTER=$(find_free_nodeport $DEFAULT_NODEPORT_JUPYTER)
    NODEPORT_LLM=$(find_free_nodeport $DEFAULT_NODEPORT_LLM)
  fi

  if [ -z "$NODEPORT_HTTP" ] || [ -z "$NODEPORT_JUPYTER" ] || [ -z "$NODEPORT_LLM" ]; then
    echo -e "\n❌ Could not allocate NodePorts for $NODE_NAME; please free some NodePorts and retry."
    exit 1
  fi

  if [ "$DEBUG" = "1" ]; then
    echo "Using NodePorts: HTTP=$NODEPORT_HTTP JUPYTER=$NODEPORT_JUPYTER LLM=$NODEPORT_LLM"
  fi
  
  # Ensure HOME_PATH/CONFIG_PATH are set (fall back to sane defaults if not)
  if [ -z "$HOME_PATH" ]; then
    HOME_PATH="/export/vmstore/${NODE_NAME}_home"
    echo "Warning: HOME_PATH was empty, defaulting to $HOME_PATH"
  fi
  if [ -z "$CONFIG_PATH" ]; then
    CONFIG_PATH="/export/vmstore/tower_home/kubernetes/agent/${NODE_NAME}/app/config"
    echo "Warning: CONFIG_PATH was empty, defaulting to $CONFIG_PATH"
  fi

  # Create deployment YAML for FastAPI $NODE_DISPLAY without GPU resources
  cat <<EOF | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastapi-$NODE_NAME
  namespace: default
  labels:
    app: fastapi-$NODE_NAME
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: fastapi-$NODE_NAME
  template:
    metadata:
      labels:
        app: fastapi-$NODE_NAME
    spec:
      nodeSelector:
        kubernetes.io/hostname: $NODE_NAME
      containers:
      - name: fastapi
        image: $REGISTRY_IP:$REGISTRY_NODE_PORT/fastapi-$NODE_NAME:latest
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
          value: "$NODE_NAME"
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
        - name: $NODE_NAME-home
          mountPath: /home/$NODE_NAME
        - name: $NODE_NAME-config
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
      - name: $NODE_NAME-home
        nfs:
          server: $TOWER_IP
          path: $HOME_PATH
      - name: $NODE_NAME-config
        nfs:
          server: $TOWER_IP
          path: $CONFIG_PATH
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
  name: fastapi-$NODE_NAME-service
  namespace: default
  labels:
    app: fastapi-$NODE_NAME
    device: $NODE_NAME
spec:
  selector:
    app: fastapi-$NODE_NAME
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
  name: fastapi-$NODE_NAME-nodeport
  namespace: default
  labels:
    app: fastapi-$NODE_NAME
    device: $NODE_NAME
spec:
  selector:
    app: fastapi-$NODE_NAME
  ports:
  - port: 8000
    targetPort: 8000
    nodePort: $NODEPORT_HTTP
    protocol: TCP
    name: http
  - port: 8888
    targetPort: 8888
    nodePort: $NODEPORT_JUPYTER
    protocol: TCP
    name: jupyter
  - port: 8001
    targetPort: 8001
    nodePort: $NODEPORT_LLM
    protocol: TCP
    name: llm-api
  type: NodePort
EOF
  # Check if deployment was successful by waiting for pod to become Running
  echo -e "\nWaiting for FastAPI pod to be created and enter Running state..."
  for i in {1..60}; do
    if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -l app=fastapi-$NODE_NAME -o jsonpath='{.items[0].status.phase}' 2>/dev/null | grep -q "Running"; then
      echo -e "\n✅ AI Workload deployed on $NODE_NAME (CPU-only)"
      break
    fi
    sleep 5
  done
  if [ $i -eq 60 ]; then
    echo -e "\n❌ Failed to deploy AI Workload on $NODE_NAME (pod did not reach Running in time)"
    exit 1
  fi
fi
step_increment
print_divider
}




step_18(){
# --------------------------------------------------------------------------------
# STEP 18: $NODE_DISPLAY GPU CAPACITY VERIFICATION
# --------------------------------------------------------------------------------
# Include spark nodes in the GPU verification step so GPU-capable Spark nodes
# can be detected and handled in the same way as AGX/Nano.
if [ "$INSTALL_AGX_AGENT" = true ] || [ "$INSTALL_NANO_AGENT" = true ] || [ "$INSTALL_SPARK1_AGENT" = true ] || [ "$INSTALL_SPARK2_AGENT" = true ]; then
  step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Verifying $NODE_DISPLAY GPU capacity..."
  sleep 5
  # Use the generic node-aware wait function to detect GPU capacity
  if wait_for_node_gpu_capacity "$NODE_NAME" 120 "$NODE_DISPLAY"; then
    GPU_AVAILABLE=true
    echo -e "\e[32m✅\e[0m"
  else
    GPU_AVAILABLE=false
    echo -e "\e[33m⚠️ GPU not available, skipping GPU steps\e[0m"
  fi
fi
step_increment
print_divider
}


step_19(){
# --------------------------------------------------------------------------------
# STEP 19: $NODE_DISPLAY GPU RESOURCE CLEANUP
# --------------------------------------------------------------------------------
# Only perform GPU cleanup when GPU is actually available for the current node
# and when the install flag for that node type was requested. Also include
# Spark nodes in the GPU flow.
if [ "$GPU_AVAILABLE" = true ] && { [ "$INSTALL_AGX_AGENT" = true ] || [ "$INSTALL_NANO_AGENT" = true ] || [ "$INSTALL_SPARK1_AGENT" = true ] || [ "$INSTALL_SPARK2_AGENT" = true ]; }; then
  step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Cleaning up $NODE_DISPLAY GPU resources for deployment..."

  # Check if $NODE_DISPLAY CPU deployment exists before cleanup
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get deployment fastapi-$NODE_NAME -n default --ignore-not-found=true | grep -q "fastapi-$NODE_NAME"; then
    # Force-delete any stuck pods on $NODE_DISPLAY node to free GPU resources
    if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete pods -l kubernetes.io/hostname=$NODE_NAME --force --grace-period=0 -n default --ignore-not-found=true > /dev/null 2>&1; then
      :
    fi

    # Delete $NODE_DISPLAY AI Workload deployment to free GPU resources
    if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete deployment fastapi-$NODE_NAME -n default --ignore-not-found=true > /dev/null 2>&1; then
      sleep 5 # Give time for GPU resources to be fully released
      echo -e "[32m✅[0m"
    else
      echo -e "[31m❌[0m"
      exit 1
    fi
  else
    echo -e "No $NODE_DISPLAY CPU deployment found, skipping cleanup"
    echo -e "[32m✅[0m"
  fi
fi
step_increment
print_divider
}


step_20(){
# --------------------------------------------------------------------------------
# STEP 20: $NODE_DISPLAY GPU-ENABLED AI WORKLOAD DEPLOYMENT
# --------------------------------------------------------------------------------
if [ "$GPU_AVAILABLE" = true ] && { [ "$INSTALL_AGX_AGENT" = true ] || [ "$INSTALL_NANO_AGENT" = true ] || [ "$INSTALL_SPARK1_AGENT" = true ] || [ "$INSTALL_SPARK2_AGENT" = true ]; }; then
  step_echo_start "a" "$NODE_NAME" "$NODE_IP" "Deploying GPU-enabled AI Workload on $NODE_DISPLAY..."
  echo -e "[32m✅[0m"

  # Deploy $NODE_DISPLAY AI Workload with GPU resources and services
  cat > /tmp/fastapi-$NODE_NAME-gpu.yaml <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastapi-$NODE_NAME
  labels:
    app: fastapi-$NODE_NAME
spec:
  replicas: 1
  selector:
    matchLabels:
      app: fastapi-$NODE_NAME
  template:
    metadata:
      labels:
        app: fastapi-$NODE_NAME
    spec:
      runtimeClassName: nvidia
      nodeSelector:
        kubernetes.io/hostname: $NODE_NAME
      tolerations:
      - key: CriticalAddonsOnly
        operator: Exists
      containers:
      - name: fastapi
        image: $REGISTRY_IP:$REGISTRY_NODE_PORT/fastapi-$NODE_NAME:latest
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
          value: "$NODE_NAME"
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
        - name: $NODE_NAME-home
          mountPath: /home/$NODE_NAME
        - name: $NODE_NAME-config
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
      - name: $NODE_NAME-home
        nfs:
          server: $TOWER_IP
          path: $HOME_PATH
      - name: $NODE_NAME-config
        nfs:
          server: $TOWER_IP
          path: $CONFIG_PATH
---
apiVersion: v1
kind: Service
metadata:
  name: fastapi-$NODE_NAME-service
  namespace: default
  labels:
    app: fastapi-$NODE_NAME
    device: $NODE_NAME
spec:
  selector:
    app: fastapi-$NODE_NAME
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
  name: fastapi-$NODE_NAME-nodeport
  namespace: default
  labels:
    app: fastapi-$NODE_NAME
    device: $NODE_NAME
spec:
  selector:
    app: fastapi-$NODE_NAME
  ports:
  - port: 8000
    targetPort: 8000
    nodePort: $NODEPORT_HTTP
    protocol: TCP
    name: http
  - port: 8888
    targetPort: 8888
    nodePort: $NODEPORT_JUPYTER
    protocol: TCP
    name: jupyter
  - port: 8001
    targetPort: 8001
    nodePort: $NODEPORT_LLM
    protocol: TCP
    name: llm-api
  type: NodePort
EOF

  if [ "$DEBUG" = "1" ]; then
    echo "Applying GPU-enabled $NODE_DISPLAY FastAPI deployment..."
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /tmp/fastapi-$NODE_NAME-gpu.yaml
    apply_exit=$?
  else
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /tmp/fastapi-$NODE_NAME-gpu.yaml > /dev/null 2>&1
    apply_exit=$?
  fi

  if [ $apply_exit -eq 0 ]; then
    echo -e "✅ GPU-enabled AI Workload deployed on $NODE_DISPLAY"
    # Wait for GPU-enabled pod to be running
    echo -e "Waiting for GPU-enabled FastAPI pod to be ready..."
    for i in {1..60}; do
      if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -l app=fastapi-$NODE_NAME -o jsonpath='{.items[0].status.phase}' 2>/dev/null | grep -q "Running"; then
        echo -e "✅ GPU-enabled AI Workload pod is running on $NODE_DISPLAY"
        break
      fi
      sleep 5
    done
    if [ $i -eq 60 ]; then
      echo -e "❌ GPU-enabled AI Workload pod did not start within 5 minutes"
      # Clean up temporary YAML unless we're in debug mode (keep it for debugging)
      if [ "$DEBUG" != "1" ]; then
        rm -f /tmp/fastapi-$NODE_NAME-gpu.yaml 2>/dev/null || true
      fi
      exit 1
    fi
    # Clean up the temporary YAML now that deployment succeeded
    rm -f /tmp/fastapi-$NODE_NAME-gpu.yaml 2>/dev/null || true
  else
    echo -e "❌ Failed to deploy GPU-enabled AI Workload on $NODE_DISPLAY"
    # Remove temporary manifest on failure unless debugging
    if [ "$DEBUG" != "1" ]; then
      rm -f /tmp/fastapi-$NODE_NAME-gpu.yaml 2>/dev/null || true
    fi
    exit 1
  fi
fi
step_increment
print_divider
}


step_21(){
# --------------------------------------------------------------------------------
# STEP 21: FINAL VERIFICATION - NODE AND POD STATUS
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Final verification: Node and pod status..."
sleep 5

# Wait for all pods to be ready and no pods terminating
echo "Waiting for all pods to be ready and no terminating pods..."
timeout=600  # 10 minutes
count=0
EXTRA_TERMINATION_WAIT=180 # Additional wait (seconds) for terminating pods to finish
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

# If we exited due to timeout but there are terminating pods, give them a
# short additional grace period so we can observe the cleaned state rather
# than printing transient 'Terminating' lines.
terminating_count=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods --all-namespaces -o jsonpath='{.items[*].status.phase}' 2>/dev/null | grep -c Terminating || true)
if [ "$terminating_count" -gt 0 ]; then
  echo "Detected $terminating_count terminating pods; waiting up to $EXTRA_TERMINATION_WAIT seconds for them to finish..."
  extra_elapsed=0
  while [ "$terminating_count" -gt 0 ] && [ $extra_elapsed -lt $EXTRA_TERMINATION_WAIT ]; do
    sleep 5
    extra_elapsed=$((extra_elapsed + 5))
    terminating_count=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods --all-namespaces -o jsonpath='{.items[*].status.phase}' 2>/dev/null | grep -c Terminating || true)
    if [ "$terminating_count" -eq 0 ]; then
      echo "Terminating pods completed after ${extra_elapsed}s"
      break
    fi
  done
  if [ "$terminating_count" -gt 0 ]; then
    echo "Terminating pods still present after ${EXTRA_TERMINATION_WAIT}s; proceeding with current status"
  fi
fi

echo ""
echo "=== NODE STATUS ==="
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes
echo ""
echo "=== POD STATUS ==="
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide
echo ""
echo -e "✅ Final verification complete"
step_increment
print_divider
}


step_22(){
# --------------------------------------------------------------------------------
# STEP 22: DISPLAY $NODE_DISPLAY SERVICE ENDPOINTS
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Displaying available $NODE_DISPLAY service endpoints..."
sleep 2
echo ""
echo "Services Available:"
# Query service to get actual nodePort values and fall back to allocated vars
HTTP_PORT=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get svc fastapi-$NODE_NAME-nodeport -n default -o jsonpath='{.spec.ports[?(@.name=="http")].nodePort}' 2>/dev/null || echo "")
JUP_PORT=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get svc fastapi-$NODE_NAME-nodeport -n default -o jsonpath='{.spec.ports[?(@.name=="jupyter")].nodePort}' 2>/dev/null || echo "")
LLM_PORT=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get svc fastapi-$NODE_NAME-nodeport -n default -o jsonpath='{.spec.ports[?(@.name=="llm-api")].nodePort}' 2>/dev/null || echo "")

HTTP_PORT=${HTTP_PORT:-$NODEPORT_HTTP}
JUP_PORT=${JUP_PORT:-$NODEPORT_JUPYTER}
LLM_PORT=${LLM_PORT:-$NODEPORT_LLM}

echo "FastAPI: http://$NODE_IP:$HTTP_PORT"
echo "Jupyter: http://$NODE_IP:$JUP_PORT"
echo "LLM API: http://$NODE_IP:$LLM_PORT"
echo "Health Check: http://$NODE_IP:$HTTP_PORT/health"
echo "Swagger UI: http://$NODE_IP:$HTTP_PORT/docs"
echo ""
echo -e "✅ Service endpoints displayed"
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



# Capture final verification output
capture_final_log "$FINAL_LOG_FILE" "$START_MESSAGE"



# End of script


