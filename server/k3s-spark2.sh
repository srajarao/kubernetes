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
INSTALL_SPARK1_AGENT=false

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

# NOTE: Total steps count is 7 (spark2 agent setup and GPU enablement)
TOTAL_STEPS=7

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
--- 7. CRITICAL: SPARK2 K3S AGENT LOG ERRORS (Container Runtime Check) ---" >> "$log_file"
  echo "Executing: $SSH_CMD $SSH_USER@$SPARK2_IP 'sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E \"fastapi-spark2|Error|Fail\"'" >> "$log_file"
    # Execute SSH command and pipe output directly to the log file
  $SSH_CMD $SSH_USER@$SPARK2_IP "sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E 'fastapi-spark2|Error|Fail'" >> "$log_file" 2>/dev/null

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





step_01(){
# --------------------------------------------------------------------------------
# STEP 01: Clean up FastAPI SPARK2 Docker image tags
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Cleaning up FastAPI SPARK2 Docker image tags..."
  sleep 5
  echo "Removing existing Docker images for fastapi-spark2..."
  sudo docker rmi "$REGISTRY_IP:$REGISTRY_PORT/fastapi-spark2:latest" > /dev/null 2>&1
  echo "Docker image cleanup complete"
else
  step_echo_start "s" "tower" "$TOWER_IP" "Cleaning up FastAPI SPARK2 Docker image tags..."
  sleep 5
  if sudo docker rmi "$REGISTRY_IP:$REGISTRY_PORT/fastapi-spark2:latest" > /dev/null 2>&1; then
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




step_02(){
# --------------------------------------------------------------------------------
# STEP 02: Build SPARK2 Docker image
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Building SPARK2 Docker image..."
  sleep 5
  echo "Running docker build for fastapi-spark2..."
  sudo docker build -f ../agent/spark2/dockerfile.spark2.req -t fastapi-spark2:latest ../agent/spark2
  if [ $? -eq 0 ]; then
    echo "SPARK2 Docker image built successfully"
  else
    echo "Failed to build SPARK2 Docker image"
    exit 1
  fi
else
  step_echo_start "s" "tower" "$TOWER_IP" "Building SPARK2 Docker image..."
  sleep 5
  if sudo docker build -f ../agent/spark2/dockerfile.spark2.req -t fastapi-spark2:latest ../agent/spark2 > /dev/null 2>&1; then
    echo -e "✅"
  else
    echo -e "❌"
    exit 1
  fi
fi
if [ "$DEBUG" = "1" ]; then
  echo "SPARK2 Docker image build completed."
fi
step_increment
print_divider
}


step_03(){
# --------------------------------------------------------------------------------
# STEP 03: Tag SPARK2 Docker image
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Tagging SPARK2 Docker image..."
  sleep 5
  echo "Tagging fastapi-spark2:latest as $REGISTRY_IP:$REGISTRY_PORT/fastapi-spark2:latest"
  sudo docker tag fastapi-spark2:latest "$REGISTRY_IP:$REGISTRY_PORT/fastapi-spark2:latest"
  if [ $? -eq 0 ]; then
    echo "SPARK2 Docker image tagged successfully"
  else
    echo "Failed to tag SPARK2 Docker image"
    exit 1
  fi
else
  step_echo_start "s" "tower" "$TOWER_IP" "Tagging SPARK2 Docker image..."
  sleep 5
  if sudo docker tag fastapi-spark2:latest "$REGISTRY_IP:$REGISTRY_PORT/fastapi-spark2:latest" > /dev/null 2>&1; then
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

step_04(){
# --------------------------------------------------------------------------------
# STEP 04: Push Docker image to registry
# --------------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Pushing Docker image to registry..."
  sleep 5
  echo "Pushing $REGISTRY_IP:$REGISTRY_PORT/fastapi-spark2:latest"
  sudo docker push "$REGISTRY_IP:$REGISTRY_PORT/fastapi-spark2:latest"
  if [ $? -eq 0 ]; then
    echo "Docker image pushed successfully"
  else
    echo "Failed to push Docker image"
    exit 1
  fi
else
  step_echo_start "s" "tower" "$TOWER_IP" "Pushing Docker image to registry..."
  sleep 5
  if sudo docker push "$REGISTRY_IP:$REGISTRY_PORT/fastapi-spark2:latest" > /dev/null 2>&1; then
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

step_05(){
# --------------------------------------------------------------------------------
# STEP 05: Deploy FastAPI to SPARK2 (using GPU Operator)
# --------------------------------------------------------------------------------
if [ "$INSTALL_SPARK2_AGENT" = true ]; then
    step_echo_start "s" "tower" "$TOWER_IP" "Cleaning up and deploying FastAPI application to SPARK2..."
    sleep 2
    
    # Find and delete any pod on spark2 using a GPU
    echo "Searching for existing GPU pods on spark2..."
    gpu_pods=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods --all-namespaces -o jsonpath='{range .items[?(@.spec.containers[*].resources.requests."nvidia.com/gpu")]}{.spec.nodeName}{" "}{.metadata.namespace}{"/"}{.metadata.name}{"\n"}{end}' | grep '^spark2 ' | awk '{print $2}')

    if [ -n "$gpu_pods" ]; then
        echo "Found and deleting existing GPU pods on spark2:"
        for pod_to_delete in $gpu_pods; do
            namespace=$(echo "$pod_to_delete" | cut -d'/' -f1)
            pod_name=$(echo "$pod_to_delete" | cut -d'/' -f2)
            echo " - Deleting pod $pod_name in namespace $namespace"
            sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml -n "$namespace" delete pod "$pod_name"
        done
        echo "Waiting for pods to be fully terminated..."
        sleep 15
    else
        echo "No existing GPU pods found on spark2."
    fi

    # Clean up old deployment resources first to avoid conflicts
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete deployment fastapi-spark2 --ignore-not-found=true > /dev/null 2>&1
    
    echo "Applying new deployment..."
    if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f ../agent/spark2/fastapi-deployment-spark2.yaml; then
        echo -e "✅ FastAPI deployment to SPARK2 applied successfully"
    else
        echo -e "❌ Failed to apply FastAPI deployment to SPARK2"
        exit 1
    fi
fi
step_increment
print_divider
}


step_06(){
# --------------------------------------------------------------------------------
# STEP 06: FINAL VERIFICATION - NODE AND POD STATUS
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
echo ""
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


step_07(){
# --------------------------------------------------------------------------------
# STEP 07: DISPLAY SERVICE ENDPOINTS
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
echo "FastAPI: http://10.1.10.202:30010"
echo "Jupyter: http://10.1.10.202:30011"
echo "LLM API: http://10.1.10.202:30012"
echo "Health Check: http://10.1.10.202:30010/health"
echo "Swagger UI: http://10.1.10.202:30010/docs"
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


# --------------------------------------------------------------------------------












# Capture final verification output
capture_final_log "$FINAL_LOG_FILE" "$START_MESSAGE"



# End of script


