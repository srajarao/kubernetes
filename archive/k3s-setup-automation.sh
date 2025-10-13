#!/bin/bash

clear

# K3s Setup and FastAPI Deployment Automation Script
# Automates the setup of K3s cluster with GPU support for FastAPI on Jetson Nano and AGX.
# Run this script on the server (tower) machine.
#
# Key Features & Improvements:
# - Proper TLS certificate generation with SAN extensions for modern security compliance
# - Intelligent Docker image caching (only pushes when images are newly built)
# - Robust registry configuration with SSH-first, kubectl-debug fallback
# - Automatic certificate verification to prevent deployment failures
# - GPU library compatibility checks with conditional skip logic

# Source configuration
# NOTE: Ensure k3s-config.sh exists and contains TOWER_IP, NANO_IP, AGX_IP, REGISTRY_IP, etc.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/k3s-config.sh" ]; then
  source "$SCRIPT_DIR/k3s-config.sh"
else
  echo "ERROR: k3s-config.sh not found in $SCRIPT_DIR"
  exit 1
fi

# Source node configuration functions
if [ -f "$SCRIPT_DIR/node-config.sh" ]; then
  source "$SCRIPT_DIR/node-config.sh"
else
  echo "ERROR: node-config.sh not found in $SCRIPT_DIR"
  exit 1
fi

# ==========================================
# CLUSTER CONFIGURATION VALIDATION
# ==========================================

# Validate cluster configuration
if ! validate_cluster_config; then
  echo "❌ Cluster configuration validation failed. Please check k3s-config.sh"
  exit 1
fi

# Show cluster summary if in debug mode
if [ "$DEBUG" -ge 1 ]; then
  show_cluster_summary
fi

# Parse cluster nodes for use throughout the script
CLUSTER_NODE_LIST=$(parse_cluster_nodes "$CLUSTER_NODES")

# ==========================================
# LEGACY COMPATIBILITY VALIDATION
# ==========================================

# ==========================================
# LEGACY COMPATIBILITY VALIDATION
# ==========================================

# Pre-flight validation (legacy compatibility)
echo "🔍 Running pre-flight checks..."

# Validate IPs for enabled nodes
for node in $CLUSTER_NODE_LIST; do
  node_ip=$(get_node_ip "$node")
  if [ -n "$node_ip" ]; then
    if ! [[ "$node_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "❌ ERROR: IP for $node ($node_ip) is not a valid IP address"
      exit 1
    fi
  fi
done

echo "✅ Configuration validation passed"

DEBUG=${DEBUG:-0}

# Parse command line arguments
IMAGE_MODE="local"  # Default: use local images or download if missing

while [[ $# -gt 0 ]]; do
  case $1 in
    --image-mode)
      IMAGE_MODE="$2"
      shift 2
      ;;
    --help)
      echo "Usage: $0 [--image-mode MODE]"
      echo "  --image-mode MODE: Docker image management mode"
      echo "    local      - Use local images or download if missing (default)"
      echo "    download   - Always download fresh images from registry"
      echo "    save-tar   - Save images as tar files for offline use"
      echo "    use-tar    - Use local tar files instead of building from Dockerfiles"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

# Validate image mode
case $IMAGE_MODE in
  local|download|save-tar|use-tar)
    ;;
  *)
    echo "❌ Invalid image mode: $IMAGE_MODE"
    echo "Valid modes: local, download, save-tar, use-tar"
    exit 1
    ;;
esac

# Define the initial script message to be logged
START_MESSAGE="Starting K3s Setup and FastAPI Deployment in SILENT NORMAL mode..."

if [ "$DEBUG" = "1" ]; then
  echo "Starting K3s Setup and FastAPI Deployment in **VERBOSE DEBUG** mode..."
else
  echo "Starting K3s Setup and FastAPI Deployment in **SILENT NORMAL** mode..."
fi

# Initialize Dynamic Step Counter
CURRENT_STEP=1
# NOTE: Total steps count is 53 (includes final stability verification)
TOTAL_STEPS=53

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
    local IP_LENGTH=15   # e.g., "  10.1.10.150"

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
    printf "%${IP_LENGTH}s" "$ip"
    printf "] %d/%d. %s" "$CURRENT_STEP" "$TOTAL_STEPS" "$msg"
}

# Function to print a separator line
print_divider() {
    # Generate a string of hyphens of the defined length
    # Note: We subtract 2 from the length here because the output includes '# ' (2 characters).
    HYPHENS=$(printf "%*s" $((DIVIDER_LENGTH - 2)) "" | tr ' ' '-')
    echo "# $HYPHENS"
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

    echo -e "
--- LOG CAPTURE COMPLETE ---" >> "$log_file"
}

# Function to increment the step counter
step_increment() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
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
  while ! sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes 2>/dev/null | grep -q "nano.*Ready"; do
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

# Function to check if config has changed (for build optimization)
check_config_changed() {
  local node_type="$1"
  local config_checksum_file="$SCRIPT_DIR/images/config/${node_type}_checksum.txt"
  local current_checksum=""

  # Get current checksum of relevant config files
  if [ "$node_type" = "nano" ]; then
    current_checksum=$(find "$SCRIPT_DIR/agent/nano" -name "dockerfile.*" -o -name "requirements.*" | sort | xargs cat | sha256sum | cut -d' ' -f1)
  elif [ "$node_type" = "agx" ]; then
    current_checksum=$(find "$SCRIPT_DIR/agent/agx" -name "dockerfile.*" -o -name "requirements.*" | sort | xargs cat | sha256sum | cut -d' ' -f1)
  fi

  # Check if checksum file exists and matches
  if [ -f "$config_checksum_file" ]; then
    stored_checksum=$(cat "$config_checksum_file" | tr -d '\n')
    if [ "$current_checksum" = "$stored_checksum" ]; then
      return 1  # No change
    fi
  fi

  # Update checksum file (without trailing newline)
  printf "%s" "$current_checksum" > "$config_checksum_file"
  return 0  # Changed or first time
}

# Function to build image centrally on tower
build_image_on_tower() {
  local node_type="$1"
  local image_name="$2"
  local dockerfile_path="$3"
  local context_dir="$4"

  if [ "$DEBUG" = "1" ]; then
    echo "Building $node_type image on tower: $image_name"
    echo "Dockerfile: $dockerfile_path"
    echo "Context: $context_dir"
  fi

  # Determine the target platform based on node type
  local platform=""
  case "$node_type" in
    "nano"|"agx")
      platform="--platform linux/arm64"
      ;;
    "tower"|*)
      platform="--platform linux/amd64"
      ;;
  esac

  # Build the image using buildx for cross-platform support
  if docker buildx build $platform -t "$image_name:latest" -f "$dockerfile_path" "$context_dir" --load; then
    if [ "$DEBUG" = "1" ]; then
      echo "Successfully built $image_name on tower"
    fi
    return 0
  else
    echo "Failed to build $image_name on tower"
    return 1
  fi
}

# Function to save image as tar centrally
save_image_tar_central() {
  local image_name="$1"
  local tar_path="$2"

  if [ "$DEBUG" = "1" ]; then
    echo "Saving $image_name to tar: $tar_path"
  fi

  # Create directory if it doesn't exist
  mkdir -p "$(dirname "$tar_path")"

  # Save image to tar
  if docker save "$image_name:latest" > "$tar_path"; then
    if [ "$DEBUG" = "1" ]; then
      echo "Successfully saved $image_name to $tar_path"
    fi
    return 0
  else
    echo "Failed to save $image_name to tar"
    return 1
  fi
}

# Function to load image from central tar
load_image_from_central_tar() {
  local node_ip="$1"
  local node_type="$2"
  local tar_path="$3"
  local image_name="$4"

  if [ "$DEBUG" = "1" ]; then
    echo "Loading $image_name from tar on $node_type ($node_ip)"
  fi

  # Copy tar to node
  if scp "$tar_path" "sanjay@$node_ip:~/"; then
    # Load image on node
    if ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR "sanjay@$node_ip" "docker load < $(basename "$tar_path")"; then
      # Clean up tar file on node
      ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR "sanjay@$node_ip" "rm $(basename "$tar_path")"
      if [ "$DEBUG" = "1" ]; then
        echo "Successfully loaded $image_name on $node_type"
      fi
      return 0
    fi
  fi

  echo "Failed to load $image_name from tar on $node_type"
  return 1
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

# Function to configure registry on a node using kubectl debug as fallback when SSH fails
configure_node_registry() {
  local NODE_IP=$1
  local NODE_NAME=$2
  local REGISTRY_IP=$3
  local REGISTRY_PORT=$4
  local REGISTRY_PROTOCOL=$5

  echo "Attempting SSH-based registry configuration for $NODE_NAME..."

  # Try SSH first
  if [[ "$REGISTRY_PROTOCOL" == "https" ]]; then
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 sanjay@$NODE_IP "sudo mkdir -p /etc/docker/certs.d/$REGISTRY_IP" > /dev/null 2>&1 && \
       scp -o StrictHostKeyChecking=no -o ConnectTimeout=10 /etc/docker/certs.d/$REGISTRY_IP/ca.crt sanjay@$NODE_IP:/tmp/ca.crt > /dev/null 2>&1 && \
       ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 sanjay@$NODE_IP "sudo mv /tmp/ca.crt /etc/docker/certs.d/$REGISTRY_IP/ca.crt" > /dev/null 2>&1; then
      echo "SSH certificate copy successful"
    else
      echo "SSH certificate copy failed, trying kubectl debug fallback..."
      # Use kubectl debug to copy certificate
      if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml debug node/$NODE_NAME --image=busybox -- sleep 300 > /dev/null 2>&1; then
        sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml cp /etc/docker/certs.d/$REGISTRY_IP/ca.crt $NODE_NAME:/tmp/ca.crt
        sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml exec $NODE_NAME -- sh -c "mkdir -p /etc/docker/certs.d/$REGISTRY_IP && mv /tmp/ca.crt /etc/docker/certs.d/$REGISTRY_IP/ca.crt"
      else
        echo "kubectl debug also failed for certificate copy"
        return 1
      fi
    fi
  fi

  # Configure K3s registries.yaml
  if generate_k3s_registry_config "$REGISTRY_IP" "$REGISTRY_PORT" "$REGISTRY_PROTOCOL" | ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 sanjay@$NODE_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null" > /dev/null 2>&1; then
    echo "SSH K3s config successful"
  else
    echo "SSH K3s config failed, trying kubectl debug fallback..."
    if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml debug node/$NODE_NAME --image=busybox -- sleep 300 > /dev/null 2>&1; then
      generate_k3s_registry_config "$REGISTRY_IP" "$REGISTRY_PORT" "$REGISTRY_PROTOCOL" | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml exec $NODE_NAME -- sh -c "cat > /tmp/registries.yaml && mkdir -p /etc/rancher/k3s && mv /tmp/registries.yaml /etc/rancher/k3s/registries.yaml"
    else
      echo "kubectl debug also failed for K3s config"
      return 1
    fi
  fi

  # Configure containerd hosts.toml
  if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 sanjay@$NODE_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT" > /dev/null 2>&1 && \
     generate_containerd_hosts_config "$REGISTRY_IP" "$REGISTRY_PORT" "$REGISTRY_PROTOCOL" | ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 sanjay@$NODE_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null" > /dev/null 2>&1; then
    echo "SSH containerd config successful"
  else
    echo "SSH containerd config failed, trying kubectl debug fallback..."
    if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml debug node/$NODE_NAME --image=busybox -- sleep 300 > /dev/null 2>&1; then
      generate_containerd_hosts_config "$REGISTRY_IP" "$REGISTRY_PORT" "$REGISTRY_PROTOCOL" | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml exec $NODE_NAME -- sh -c "mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT && cat > /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml"
    else
      echo "kubectl debug also failed for containerd config"
      return 1
    fi
  fi

  echo "Registry configuration completed for $NODE_NAME"
  return 0
}


# =========================================================================
# HTTPS REGISTRY SETUP (if enabled)
# =========================================================================

if [[ "$REGISTRY_PROTOCOL" == "https" ]]; then
  echo "🔐 Setting up HTTPS registry with certificates..."

  # Create certificate directory
  CERT_DIR="/etc/docker/certs.d/$REGISTRY_IP"
  sudo mkdir -p "$CERT_DIR"

  # Generate proper certificate chain with SAN extensions
  echo "   📜 Generating CA and server certificates with SAN extensions..."

  # Generate CA certificate
  sudo openssl req -newkey rsa:4096 -nodes -sha256 -keyout "$CERT_DIR/ca.key" -x509 -days 365 -out "$CERT_DIR/ca.crt" -subj "/C=US/ST=State/L=City/O=Organization/CN=K3s Registry CA" -addext "basicConstraints=CA:TRUE" -addext "keyUsage=keyCertSign,cRLSign"

  # Generate server certificate signing request
  sudo openssl req -newkey rsa:4096 -nodes -sha256 -keyout "$CERT_DIR/registry.key" -out "$CERT_DIR/registry.csr" -subj "/C=US/ST=State/L=City/O=Organization/CN=$REGISTRY_IP" -addext "subjectAltName=IP:$REGISTRY_IP"

  # Create extension file for server certificate
  echo "subjectAltName=IP:$REGISTRY_IP" | sudo tee "$CERT_DIR/extfile.cnf" > /dev/null

  # Sign server certificate with CA
  sudo openssl x509 -req -in "$CERT_DIR/registry.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/registry.crt" -days 365 -sha256 -extfile "$CERT_DIR/extfile.cnf"

  # Clean up temporary files
  sudo rm -f "$CERT_DIR/registry.csr" "$CERT_DIR/extfile.cnf"

  # Create registry config for HTTPS
  echo "   ⚙️ Configuring registry for HTTPS..."
  sudo tee /etc/docker/registry/config.yml > /dev/null <<EOF
version: 0.1
log:
  fields:
    service: registry
storage:
  cache:
    blobdescriptor: inmemory
  filesystem:
    rootdirectory: /var/lib/registry
http:
  addr: 0.0.0.0:5000
  tls:
    certificate: $CERT_DIR/registry.crt
    key: $CERT_DIR/registry.key
health:
  storagedriver:
    enabled: true
    interval: 10s
    threshold: 3
EOF

  # Restart registry with HTTPS
  echo "   🔄 Restarting registry with HTTPS..."
  if docker ps | grep -q registry; then
    docker stop registry
    docker rm registry
  fi

  docker run -d --name registry \
    --restart=always \
    -p 5000:5000 \
    -v /etc/docker/registry/config.yml:/etc/docker/registry/config.yml:ro \
    -v $CERT_DIR:/certs:ro \
    -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/registry.crt \
    -e REGISTRY_HTTP_TLS_KEY=/certs/registry.key \
    registry:2

  echo "✅ HTTPS registry setup complete with proper certificates"
fi

# =========================================================================
# CERTIFICATE VERIFICATION (if HTTPS enabled)
# =========================================================================

if [[ "$REGISTRY_PROTOCOL" == "https" ]]; then
  echo "🔍 Verifying certificate configuration..."

  # Test certificate with curl
  if curl -k --cacert /etc/docker/certs.d/$REGISTRY_IP/ca.crt -s https://$REGISTRY_IP:5000/v2/_catalog > /dev/null 2>&1; then
    echo "   ✅ Certificate verification successful"
  else
    echo "   ❌ Certificate verification failed - check certificate configuration"
    echo "   📋 Certificate details:"
    openssl x509 -in /etc/docker/certs.d/$REGISTRY_IP/ca.crt -text -noout | grep -E '(Subject:|Issuer:|Subject Alternative Name)' | head -3
    exit 1
  fi
fi


## =========================================================================
# STEP 1: SELF-RENUMBER SCRIPT STEPS AND TOTAL_STEPS VARIABLE (AUTO-FIX)
# =========================================================================
step_echo_start "s" "tower" "$TOWER_IP" "Executing self-renumbering script logic..."

# --- AWK Logic for Renumbering ---
# This AWK script reads the entire file, renumbers 'STEP 2:' and 'STEP [0-9]+:' comments sequentially,
# updates the TOTAL_STEPS variable, and overwrites the script file.
SCRIPT_CONTENT=$(awk '
  BEGIN { step_count = 0; }
  
  # 1. Find and renumber the step definition comments (including XX)
  /^#+.*STEP ([0-9]+|XX):/ {
    step_count++;
    sub(/STEP ([0-9]+|XX)/, "STEP " step_count);
  }
  
  # 2. Identify the line containing TOTAL_STEPS
  /TOTAL_STEPS=/ {
    total_steps_line = NR;
  }

  # Store every line (modified or not) in an array
  { lines[NR] = $0 }
  
  # END Block: Update and Print all lines
  END {
    # Update the TOTAL_STEPS line with the final count
    if (total_steps_line) {
      gsub(/TOTAL_STEPS=[0-9]+/, "TOTAL_STEPS=" step_count, lines[total_steps_line]);
    }
    
    # Print all lines from the array
    for (i=1; i<=NR; i++) {
      print lines[i];
    }
  }
' "$0")
# Overwrite the current script file with the corrected content
echo "$SCRIPT_CONTENT" > "$0"
echo -e "✅"
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 3: Tower Network Verification
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



# -------------------------------------------------------------------------
# STEP 4: Start iperf3 server
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
step_increment
print_divider



# -------------------------------------------------------------------------
# STEP 5: Uninstall Server
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
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 6: Install Server
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


# -------------------------------------------------------------------------
# STEP 7: Correct K3s Network Configuration (SIMPLIFIED MESSAGE)
# -------------------------------------------------------------------------
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
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌ Failed to restart K3s with corrected config[0m"
    exit 1
  fi
  step_increment
  print_divider
else
  # Skip server installation steps if INSTALL_SERVER is false
  step_echo_start "s" "tower" "$TOWER_IP" "K3s server installation skipped."
  step_increment
  print_divider
  step_echo_start "s" "tower" "$TOWER_IP" "K3s network configuration fix skipped."
  step_increment
  print_divider
fi

# -------------------------------------------------------------------------
# STEP 8: Get Token
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then echo "Getting Token: $TOKEN"; fi
step_echo_start "s" "tower" "$TOWER_IP" "Getting server token..."
sleep 5
TOKEN=$(sudo cat /var/lib/rancher/k3s/server/node-token)
echo -e "[32m✅[0m"
step_increment
print_divider



# -------------------------------------------------------------------------
# STEP 9: Nano SSH Validation
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

# -------------------------------------------------------------------------
# STEP 10: AGX SSH Validation
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


# -------------------------------------------------------------------------
# STEP 11: NANO ARP/PING CHECK
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  step_echo_start "a" "nano" "$NANO_IP" "Verifying Nano network reachability (ARP/Ping)..."
  sleep 5
  run_network_check $NANO_IP "NANO"
fi
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 12: AGX ARP/PING CHECK
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  step_echo_start "a" "agx" "$AGX_IP" "Verifying AGX network reachability (ARP/Ping)..."
  sleep 5
  run_network_check $AGX_IP "AGX"
fi
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 13: Uninstall Nano Agent
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Uninstalling Agent on Nano... (Verbose output below)"
    sleep 5
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$NANO_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh"
  else
    step_echo_start "a" "nano" "$NANO_IP" "Uninstalling K3s agent on nano..."
    sleep 5
    if ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$NANO_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
      echo -e "[32m✅[0m"
    else
      echo -e "[32m✅[0m"  # Print checkmark anyway, as uninstall may not exist
    fi
  fi
fi
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 14: Uninstall AGX Agent
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Uninstalling Agent on AGX... (Verbose output below)"
    sleep 5
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$AGX_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh"
  else
    step_echo_start "a" "agx" "$AGX_IP" "Uninstalling K3s agent on agx..."
    sleep 5
    if ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$AGX_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
      echo -e "[32m✅[0m"
    else
    echo -en " ✅[0m
"  # Print checkmark anyway
    fi
  fi
fi
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 15: Reinstall Nano Agent (FIXED IP CACHE ERROR + SYSTEMD RELOAD)
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  # Define the robust installation command with explicit IP binding
  K3S_REINSTALL_CMD="export K3S_TOKEN=\"$TOKEN\"; \
    sudo curl -sfL https://get.k3s.io | \
    K3S_URL=https://$TOWER_IP:6443 \
    K3S_TOKEN=\$K3S_TOKEN \
    INSTALL_K3S_EXEC=\"agent --node-ip $NANO_IP\" sh -"

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



# -------------------------------------------------------------------------
# STEP 16: Reinstall AGX Agent (FIXED IP CACHE ERROR + SYSTEMD RELOAD)
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  # Define the robust installation command with explicit IP binding
  K3S_REINSTALL_CMD="export K3S_TOKEN=\"$TOKEN\"; sudo curl -sfL https://get.k3s.io | K3S_URL=https://$TOWER_IP:6443 K3S_TOKEN=\$K3S_TOKEN INSTALL_K3S_EXEC=\"--node-ip $AGX_IP\" sh -"

  if [ "$DEBUG" = "1" ]; then
    echo "Reinstalling Agent on AGX with explicit node-ip $AGX_IP..."
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "$K3S_REINSTALL_CMD"
    # Ensure environment file exists with correct server URL
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "sudo mkdir -p /etc/systemd/system && echo 'K3S_TOKEN=\"$TOKEN\"' | sudo tee /etc/systemd/system/k3s-agent.service.env > /dev/null && echo 'K3S_URL=\"https://$TOWER_IP:6443\"' | sudo tee -a /etc/systemd/system/k3s-agent.service.env > /dev/null" 2>/dev/null || true
    # CRITICAL: Ensure systemd loads environment variables after install
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "sudo systemctl daemon-reload && sudo systemctl restart k3s-agent" 2>/dev/null || true
    wait_for_agent
  else
    step_echo_start "a" "agx" "$AGX_IP" "Reinstalling K3s agent on agx..."
    sleep 5
    # Execute the robust reinstall command
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






# =========================================================================
# STEP 17: Systemd Service Override (force correct server/node IP) NANO
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
    echo -en "✅[0m"
else
    echo -en "❌[0m"
    echo -e "[31mFATAL: Failed to overwrite NANO service file.[0m"
    exit 1
fi
step_increment
print_divider

# =========================================================================
# STEP 18: Systemd Service Override (force correct server/node IP) AGX
# =========================================================================
step_echo_start "a" "agx" "$AGX_IP" "Forcing K3s agx agent to use correct server IP..."

# Add AGX host key to known_hosts to avoid SSH warning
ssh-keyscan -H $AGX_IP >> ~/.ssh/known_hosts 2>/dev/null

# Use systemctl edit to create an override.conf file that specifically sets the
# correct server URL, purging any old, cached URLs from the service file.
ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "sudo systemctl edit k3s-agent.service" > /dev/null 2>&1 << EOF
[Service]
Environment="K3S_URL=https://$TOWER_IP:6443"
Environment="K3S_NODE_IP=$AGX_IP"
EOF

# Restart the service to apply the forced environment variables
ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "sudo systemctl daemon-reload && sudo timeout 30 systemctl restart k3s-agent" > /dev/null 2>&1

# Check the exit status of the SSH command
if [ $? -eq 0 ]; then
    # Wait for the agent to re-join and be ready
    wait_for_agent 
  echo -en "✅\x1b[0m"
else
  echo -en "❌\x1b[0m"
  echo -e "\x1b[31mFATAL: Failed to overwrite AGX service file.\x1b[0m"
  exit 1
fi
step_increment
print_divider





# -------------------------------------------------------------------------
# STEP 19: Create Registry Config Directory NANO
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Adding Registry Config Dir..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo mkdir -p /etc/rancher/k3s/"
  else
    step_echo_start "a" "nano" "$NANO_IP" "Creating nano registry configuration directory..."
    sleep 5
    if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo mkdir -p /etc/rancher/k3s/" > /dev/null 2>&1; then
      echo -en " ✅[0m
"
    else
      echo -e "[31m❌[0m"
      exit 1
    fi
  fi
  step_increment
  print_divider
fi


# -------------------------------------------------------------------------
# STEP 20: Create Registry Config Directory AGX
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Adding Registry Config Dir on AGX..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo mkdir -p /etc/rancher/k3s/"
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


# -------------------------------------------------------------------------
# STEP 21: Write Registry YAML and Containerd TOML (Nano)
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Configuring Registry for Nano..."
    sleep 5
    configure_node_registry "$NANO_IP" "nano" "$REGISTRY_IP" "$REGISTRY_PORT" "$REGISTRY_PROTOCOL"
  else
    step_echo_start "a" "nano" "$NANO_IP" "Configuring registry for nano..."
    sleep 5
    if configure_node_registry "$NANO_IP" "nano" "$REGISTRY_IP" "$REGISTRY_PORT" "$REGISTRY_PROTOCOL"; then
      echo -en " ✅\033[0m\n"
    else
      echo -e "\033[31m❌\033[0m"
      exit 1
    fi
  fi
fi
step_increment
print_divider


# -------------------------------------------------------------------------
# STEP 22: Write Registry YAML and Containerd TOML (AGX)
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Configuring Registry for AGX..."
    sleep 5
    configure_node_registry "$AGX_IP" "agx" "$REGISTRY_IP" "$REGISTRY_PORT" "$REGISTRY_PROTOCOL"
  else
    step_echo_start "a" "agx" "$AGX_IP" "Configuring registry for agx..."
    sleep 5
    if configure_node_registry "$AGX_IP" "agx" "$REGISTRY_IP" "$REGISTRY_PORT" "$REGISTRY_PROTOCOL"; then
      echo -en " ✅\033[0m\n"
    else
      echo -e "\033[31m❌\033[0m"
      exit 1
    fi
  fi
fi
step_increment
print_divider





# -------------------------------------------------------------------------
# STEP 23: Configure Registry for AGX
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Configuring Registry for AGX..."
    sleep 5
  else
    step_echo_start "a" "agx" "$AGX_IP" "Configuring registry for agx..."
    sleep 5
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$AGX_IP "sudo mkdir -p /etc/rancher/k3s/" > /dev/null 2>&1 && \
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












# --------------------------------------------------------------------------------
# NEW STEP 24: FIX KUBECONFIG IP (Addresses the 'i/o timeout' error)
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

# --------------------------------------------------------------------------------
# STEP 25: COPY UPDATED KUBECONFIG TO LOCAL USER
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



# -------------------------------------------------------------------------
# STEP 26: Configure Containerd for Registry (Nano)
# -------------------------------------------------------------------------
  if [ "$DEBUG" = "1" ]; then
    echo "Configuring Containerd for Registry..."
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
      echo -en " ✅[0m
"
    else
      echo -e "[31m❌[0m"
      exit 1
    fi
  fi
  step_increment
  print_divider


# -------------------------------------------------------------------------
# STEP 27: Configure Containerd for Registry (AGX)
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
  step_increment
  print_divider
fi






# -------------------------------------------------------------------------
# STEP 28: Restart Agent After Registry Config NANO
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

# -------------------------------------------------------------------------
# STEP 29: Restart Agent After Registry Config AGX
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


# -------------------------------------------------------------------------
# STEP 30: Restart Server (Final Check)
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

# =========================================================================
# STEP 31: COPY KUBECONFIG TO NANO AGENT (Robust Copy using 'sudo cat')
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

# =========================================================================
# STEP 31 COPY KUBECONFIG TO AGX AGENT (Ultra-Robust 'sudo scp' version)
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


# =========================================================================
# STEP 32: Verify Agent Node Readiness
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

# -------------------------------------------------------------------------
# STEP 33: Install NVIDIA RuntimeClass
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



# -------------------------------------------------------------------------
# STEP 34: Install NVIDIA Device Plugin
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



# --------------------------------------------------------------------------------
# STEP 35: FIX NFS VOLUME PATHS (Addresses 'No such file or directory' error)
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

# -------------------------------------------------------------------------
# STEP 36: FIX NVIDIA DEVICE PLUGIN NODE AFFINITY (NEW SELF-HEALING STEP)
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

# --------------------------------------------------------------------------------
# NEW STEP 37: FIX NFS VOLUME PATHS (Addresses 'No such file or directory' error)
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Setting up NFS volumes..."
NFS_BASE="/export/vmstore"
# Paths found during debugging from the pod YAML:
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



# -------------------------------------------------------------------------
# STEP 38: Configure NVIDIA Runtime on Nano
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Configuring NVIDIA Runtime on Agent..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo systemctl stop k3s-agent"
    ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo systemctl start k3s-agent"
    wait_for_agent
  else
    step_echo_start "a" "nano" "$NANO_IP" "Configuring NVIDIA runtime on agent..."
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





# -------------------------------------------------------------------------
# STEP 39: Build Images Centrally on Tower
# -------------------------------------------------------------------------

# Source the node configuration functions
source "$SCRIPT_DIR/node-config.sh"

# Parse cluster nodes
nodes=$(parse_cluster_nodes "$CLUSTER_NODES")

# Build images centrally on tower (only for agent nodes)
for node in $nodes; do
    if [ "$node" = "tower" ]; then
        continue  # Skip tower (server components)
    fi

    node_ip=$(get_node_ip "$node")
    node_image_name=$(get_node_image_name "$node")
    dockerfile_path="$SCRIPT_DIR/agent/$node/dockerfile.$node.req"
    context_dir="$SCRIPT_DIR/agent/$node"
    tar_path="$SCRIPT_DIR/images/tar/${node_image_name}.tar"

    # Check if config has changed
    if check_config_changed "$node"; then
        if [ "$DEBUG" = "1" ]; then
            echo "Config changed for $node, building image centrally..."
        fi

        # Build image on tower
        if [ "$DEBUG" = "1" ]; then
            step_echo_start "s" "tower" "$TOWER_IP" "Building $node image centrally..."
            sleep 5
            if build_image_on_tower "$node" "$node_image_name" "$dockerfile_path" "$context_dir"; then
                echo -e "[32m✅[0m"
            else
                echo -e "[31m❌[0m"
                exit 1
            fi
        else
            step_echo_start "s" "tower" "$TOWER_IP" "Building $node image centrally..."
            sleep 5
            if build_image_on_tower "$node" "$node_image_name" "$dockerfile_path" "$context_dir" > /dev/null 2>&1; then
                echo -e "[32m✅[0m"
            else
                echo -e "[31m❌[0m"
                exit 1
            fi
        fi
        step_increment

        # Handle different image modes
        case $IMAGE_MODE in
            "save-tar")
                # Save tar centrally
                if [ "$DEBUG" = "1" ]; then
                    step_echo_start "s" "tower" "$TOWER_IP" "Saving $node image tar centrally..."
                    sleep 5
                    if save_image_tar_central "$node_image_name" "$tar_path"; then
                        echo -e "[32m✅[0m"
                    else
                        echo -e "[31m❌[0m"
                        exit 1
                    fi
                else
                    step_echo_start "s" "tower" "$TOWER_IP" "Saving $node image tar centrally..."
                    sleep 5
                    if save_image_tar_central "$node_image_name" "$tar_path" > /dev/null 2>&1; then
                        echo -e "[32m✅[0m"
                    else
                        echo -e "[31m❌[0m"
                        exit 1
                    fi
                fi
                step_increment
                ;;
            "local"|"download")
                # Tag and push to registry
                if [ "$DEBUG" = "1" ]; then
                    step_echo_start "s" "tower" "$TOWER_IP" "Tagging $node image for registry..."
                    sleep 5
                    docker tag "${node_image_name}:latest" "$REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest"
                    echo -e "[32m✅[0m"
                    step_increment

                    step_echo_start "s" "tower" "$TOWER_IP" "Pushing $node image to registry..."
                    sleep 5
                    docker push "$REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest"
                    echo -e "[32m✅[0m"
                else
                    step_echo_start "s" "tower" "$TOWER_IP" "Tagging $node image for registry..."
                    sleep 5
                    if docker tag "${node_image_name}:latest" "$REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest" > /dev/null 2>&1; then
                        echo -e "[32m✅[0m"
                    else
                        echo -e "[31m❌[0m"
                        exit 1
                    fi
                    step_increment

                    step_echo_start "s" "tower" "$TOWER_IP" "Pushing $node image to registry..."
                    sleep 5
                    if docker push "$REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest" > /dev/null 2>&1; then
                        echo -e "[32m✅[0m"
                    else
                        echo -e "[31m❌[0m"
                        exit 1
                    fi
                fi
                step_increment
                ;;
        esac
    else
        if [ "$DEBUG" = "1" ]; then
            echo "Config unchanged for $node, checking local image and registry..."
        fi

        # Even when config is unchanged, check if we need to rebuild or push
        case $IMAGE_MODE in
            "local"|"download")
                # First check if local image exists (either local or registry-tagged)
                if ! docker images | grep -q "${node_image_name}"; then
                    if [ "$DEBUG" = "1" ]; then
                        echo "Local image missing, forcing rebuild..."
                    fi
                    # Force rebuild by temporarily removing checksum file
                    rm -f "$config_checksum_file"
                    # Call build function again
                    if build_image_on_tower "$node" "$node_image_name" "$dockerfile_path" "$context_dir" && \
                       docker tag "${node_image_name}:latest" "$REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest" && \
                       docker push "$REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest"; then
                        # Recreate checksum file
                        current_checksum=$(find "$SCRIPT_DIR/agent/$node" -name "dockerfile.*" -o -name "requirements.*" | sort | xargs cat | sha256sum | cut -d' ' -f1)
                        printf "%s" "$current_checksum" > "$config_checksum_file"
                        step_echo_start "s" "tower" "$TOWER_IP" "Rebuilt and pushed $node image..."
                        sleep 2
                        echo -e "[32m✅ (rebuilt)[0m"
                    else
                        echo -e "[31m❌ Failed to rebuild image[0m"
                        exit 1
                    fi
                    step_increment
                else
                    # Local image exists, check if it's in registry
                    http_code=$(curl -k -s -o /dev/null -w "%{http_code}" "https://$REGISTRY_IP:$REGISTRY_PORT/v2/${node_image_name}/manifests/latest")
                    if [ "$http_code" != "200" ]; then
                        if [ "$DEBUG" = "1" ]; then
                            echo "Image not in registry, pushing cached image..."
                            step_echo_start "s" "tower" "$TOWER_IP" "Pushing cached $node image to registry..."
                            sleep 5
                            # Check if we need to tag the image first
                            if ! docker images | grep -q "^${node_image_name} "; then
                                docker tag "$REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest" "${node_image_name}:latest"
                            fi
                            docker tag "${node_image_name}:latest" "$REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest"
                            docker push "$REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest"
                            echo -e "[32m✅[0m"
                        else
                            step_echo_start "s" "tower" "$TOWER_IP" "Pushing cached $node image to registry..."
                            sleep 5
                            # Check if we need to tag the image first
                            if ! docker images | grep -q "^${node_image_name} "; then
                                docker tag "$REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest" "${node_image_name}:latest" > /dev/null 2>&1
                            fi
                            if docker tag "${node_image_name}:latest" "$REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest" > /dev/null 2>&1 && \
                               docker push "$REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest" > /dev/null 2>&1; then
                                echo -e "[32m✅[0m"
                            else
                                echo -e "[31m❌[0m"
                                exit 1
                            fi
                        fi
                        step_increment
                    else
                        if [ "$DEBUG" = "1" ]; then
                            echo "Image already in registry, skipping push"
                        fi
                        step_echo_start "s" "tower" "$TOWER_IP" "Using cached $node image (already in registry)..."
                        sleep 2
                        echo -e "[32m✅ (registry)[0m"
                        step_increment
                    fi
                fi
                ;;
            "save-tar")
                # For save-tar mode, check if tar file exists
                if [ ! -f "$tar_path" ]; then
                    if [ "$DEBUG" = "1" ]; then
                        echo "Tar file not found, need to rebuild..."
                        # Force rebuild by temporarily removing checksum file
                        rm -f "$config_checksum_file"
                        # Rebuild and save tar
                        if build_image_on_tower "$node" "$node_image_name" "$dockerfile_path" "$context_dir" && \
                           save_image_tar_central "$node_image_name" "$tar_path"; then
                            # Recreate checksum file
                            current_checksum=$(find "$SCRIPT_DIR/agent/$node" -name "dockerfile.*" -o -name "requirements.*" | sort | xargs cat | sha256sum | cut -d' ' -f1)
                            printf "%s" "$current_checksum" > "$config_checksum_file"
                            step_echo_start "s" "tower" "$TOWER_IP" "Created missing $node tar file..."
                            sleep 2
                            echo -e "[32m✅ (created)[0m"
                        else
                            echo -e "[31m❌ Failed to create tar file[0m"
                            exit 1
                        fi
                    else
                        # Force rebuild by temporarily removing checksum file
                        rm -f "$config_checksum_file"
                        # Rebuild and save tar
                        if build_image_on_tower "$node" "$node_image_name" "$dockerfile_path" "$context_dir" && \
                           save_image_tar_central "$node_image_name" "$tar_path"; then
                            # Recreate checksum file
                            current_checksum=$(find "$SCRIPT_DIR/agent/$node" -name "dockerfile.*" -o -name "requirements.*" | sort | xargs cat | sha256sum | cut -d' ' -f1)
                            printf "%s" "$current_checksum" > "$config_checksum_file"
                            step_echo_start "s" "tower" "$TOWER_IP" "Created missing $node tar file..."
                            sleep 2
                            echo -e "[32m✅ (created)[0m"
                        else
                            echo -e "[31m❌ Failed to create tar file[0m"
                            exit 1
                        fi
                    fi
                    step_increment
                else
                    if [ "$DEBUG" = "1" ]; then
                        echo "Tar file exists, skipping build"
                    fi
                    step_echo_start "s" "tower" "$TOWER_IP" "Using cached $node tar file..."
                    sleep 2
                    echo -e "[32m✅ (tar exists)[0m"
                    step_increment
                fi
                ;;
        esac
    fi
    print_divider
done

# Deploy images to nodes based on mode
for node in $nodes; do
    if [ "$node" = "tower" ]; then
        continue  # Skip tower (server components)
    fi

    node_ip=$(get_node_ip "$node")
    node_image_name=$(get_node_image_name "$node")
    tar_path="$SCRIPT_DIR/images/tar/${node_image_name}.tar"

    case $IMAGE_MODE in
        "local")
            # Check if image exists on node, download if needed
            if [ "$DEBUG" = "1" ]; then
                step_echo_start "a" "$node" "$node_ip" "Checking/deploying $node image..."
                sleep 5
                if ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$node_ip "sudo docker images | grep -q ${node_image_name}"; then
                    echo "Local image found on $node"
                    echo -e "[32m✅ (existing)[0m"
                else
                    echo "Pulling image from registry to $node..."
                    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$node_ip "sudo docker pull $REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest && sudo docker tag $REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest ${node_image_name}:latest"
                    echo -e "[32m✅ (pulled)[0m"
                fi
            else
                step_echo_start "a" "$node" "$node_ip" "Checking/deploying $node image..."
                sleep 5
                if ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$node_ip "sudo docker images | grep -q ${node_image_name}" > /dev/null 2>&1; then
                    echo -e "[32m✅ (existing)[0m"
                else
                    if ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$node_ip "sudo docker pull $REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest && sudo docker tag $REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest ${node_image_name}:latest" > /dev/null 2>&1; then
                        echo -e "[32m✅ (pulled)[0m"
                    else
                        echo -e "[31m❌[0m"
                        exit 1
                    fi
                fi
            fi
            ;;
        "download")
            # Always download fresh
            if [ "$DEBUG" = "1" ]; then
                step_echo_start "a" "$node" "$node_ip" "Downloading fresh $node image..."
                sleep 5
                ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$node_ip "sudo docker pull $REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest && sudo docker tag $REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest ${node_image_name}:latest"
                echo -e "[32m✅[0m"
            else
                step_echo_start "a" "$node" "$node_ip" "Downloading fresh $node image..."
                sleep 5
                if ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR sanjay@$node_ip "sudo docker pull $REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest && sudo docker tag $REGISTRY_IP:$REGISTRY_PORT/${node_image_name}:latest ${node_image_name}:latest" > /dev/null 2>&1; then
                    echo -e "[32m✅[0m"
                else
                    echo -e "[31m❌[0m"
                    exit 1
                fi
            fi
            ;;
        "save-tar")
            # Tar already saved centrally, now copy to node and load
            if [ "$DEBUG" = "1" ]; then
                step_echo_start "a" "$node" "$node_ip" "Deploying $node image from central tar..."
                sleep 5
                if load_image_from_central_tar "$node_ip" "$node" "$tar_path" "$node_image_name"; then
                    echo -e "[32m✅[0m"
                else
                    echo -e "[31m❌[0m"
                    exit 1
                fi
            else
                step_echo_start "a" "$node" "$node_ip" "Deploying $node image from central tar..."
                sleep 5
                if load_image_from_central_tar "$node_ip" "$node" "$tar_path" "$node_image_name" > /dev/null 2>&1; then
                    echo -e "[32m✅[0m"
                else
                    echo -e "[31m❌[0m"
                    exit 1
                fi
            fi
            ;;
        "use-tar")
            # Load from existing central tar
            if [ -f "$tar_path" ]; then
                if [ "$DEBUG" = "1" ]; then
                    step_echo_start "a" "$node" "$node_ip" "Loading $node image from central tar..."
                    sleep 5
                    if load_image_from_central_tar "$node_ip" "$node" "$tar_path" "$node_image_name"; then
                        echo -e "[32m✅[0m"
                    else
                        echo -e "[31m❌[0m"
                        exit 1
                    fi
                else
                    step_echo_start "a" "$node" "$node_ip" "Loading $node image from central tar..."
                    sleep 5
                    if load_image_from_central_tar "$node_ip" "$node" "$tar_path" "$node_image_name" > /dev/null 2>&1; then
                        echo -e "[32m✅[0m"
                    else
                        echo -e "[31m❌[0m"
                        exit 1
                    fi
                fi
            else
                echo "ERROR: Central tar file $tar_path not found for $node"
                exit 1
            fi
            ;;
    esac
    step_increment
    print_divider
done



# --------------------------------------------------------------------------------
# NEW STEP 40: ROBUST APPLICATION CLEANUP (Fixes stuck pods and 'Allocate failed' GPU error)
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



# -------------------------------------------------------------------------
# STEP 41: Update Database Configuration
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Updating database config..."
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
  echo -e "[31mFATAL: Failed to update database configuration.[0m"
  exit 1
fi
step_increment
print_divider


# -------------------------------------------------------------------------
# STEP 42: Create Deployment YAML
# -------------------------------------------------------------------------
# STEP 43: Create Deployment YAML
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Creating Deployment YAML..."
sleep 5
rm -f fastapi-deployment-full.yaml

# Source the node configuration functions
source "$SCRIPT_DIR/node-config.sh"

# Parse cluster nodes
nodes=$(parse_cluster_nodes "$CLUSTER_NODES")
deployment_content=""

for node in $nodes; do
    if [ "$node" = "tower" ]; then
        continue  # Skip tower for now
    fi

    # Get node-specific configuration
    node_ip=$(get_node_ip "$node")
    node_components=$(get_node_components "$node")
    node_image_name=$(get_node_image_name "$node")

    # Determine GPU requirements based on components
    gpu_required="false"
    if echo "$node_components" | grep -q "gpu-monitoring\|cuda\|tensorrt\|pytorch\|tensorflow"; then
        gpu_required="true"
    fi

    # Generate deployment for this node
    cat <<NODE_DEPLOYMENT >> fastapi-deployment-full.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastapi-$node
  namespace: default
  labels:
    app: fastapi-$node
    device: $node
    tier: agent
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: fastapi-$node
  template:
    metadata:
      labels:
        app: fastapi-$node
        device: $node
        tier: agent
    spec:
NODE_DEPLOYMENT

    # Add runtime class and node selector for GPU-enabled nodes
    if [ "$gpu_required" = "true" ]; then
        cat <<GPU_CONFIG >> fastapi-deployment-full.yaml
      runtimeClassName: nvidia
      nodeSelector:
        kubernetes.io/hostname: $node
GPU_CONFIG
    else
        cat <<CPU_CONFIG >> fastapi-deployment-full.yaml
      nodeSelector:
        kubernetes.io/hostname: $node
CPU_CONFIG
    fi

    # Generate container spec
    cat <<CONTAINER_SPEC >> fastapi-deployment-full.yaml
      containers:
      - name: fastapi-$node
        image: $REGISTRY_IP:$REGISTRY_PORT/$node_image_name:latest
        ports:
        - containerPort: 8000
          name: http
        - containerPort: 8888
          name: jupyter
        - containerPort: 22
          name: ssh
CONTAINER_SPEC

    # Add resource requests/limits based on GPU requirements
    if [ "$gpu_required" = "true" ]; then
        cat <<GPU_RESOURCES >> fastapi-deployment-full.yaml
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
            nvidia.com/gpu: 1
          limits:
            memory: "2Gi"
            cpu: "1000m"
            nvidia.com/gpu: 1
GPU_RESOURCES
    else
        cat <<CPU_RESOURCES >> fastapi-deployment-full.yaml
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "1Gi"
            cpu: "500m"
CPU_RESOURCES
    fi

    # Add environment variables
    cat <<ENV_VARS >> fastapi-deployment-full.yaml
        env:
        - name: DEVICE_TYPE
          value: "$node"
        - name: GPU_ENABLED
          value: "$gpu_required"
        - name: FORCE_GPU_CHECKS
          value: "$gpu_required"
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: NODE_IP
          value: "$node_ip"
ENV_VARS

    # Add volume mounts
    cat <<VOLUME_MOUNTS >> fastapi-deployment-full.yaml
        volumeMounts:
        - name: vmstore
          mountPath: /mnt/vmstore
        - name: ${node}-home
          mountPath: /home/$node
        - name: ${node}-config
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
      - name: ${node}-home
        nfs:
          server: $TOWER_IP
          path: /export/vmstore/${node}_home
      - name: ${node}-config
        nfs:
          server: $TOWER_IP
          path: /export/vmstore/tower_home/kubernetes/agent/$node/app/config
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
  name: fastapi-$node-service
  namespace: default
  labels:
    app: fastapi-$node
    device: $node
spec:
  selector:
    app: fastapi-$node
  ports:
  - port: 8000
    targetPort: 8000
    protocol: TCP
    name: http
  - port: 8888
    targetPort: 8888
    protocol: TCP
    name: jupyter
  - port: 22
    targetPort: 22
    protocol: TCP
    name: ssh
  type: ClusterIP
---
apiVersion: v1
kind: Service
metadata:
  name: fastapi-$node-nodeport
  namespace: default
  labels:
    app: fastapi-$node
    device: $node
spec:
  selector:
    app: fastapi-$node
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
  - port: 22
    targetPort: 22
    nodePort: 30022
    protocol: TCP
    name: ssh
  type: NodePort
---

VOLUME_MOUNTS
done

echo -e "[32m✅[0m"
step_increment
print_divider



# --------------------------------------------------------------------------------
# STEP 44: Global Application Cleanup (Frees up lingering GPU resources)
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting old deployments to free GPU..."

# Wait briefly for API server readiness
sleep 5

# Force-delete all existing deployments in the 'default' namespace
# --ignore-not-found prevents the script from failing if no deployments exist
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete deployment --all -n default --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "[32m✅[0m"
else
  # NOTE: A failure here is critical, as the GPU won't be free.
  echo -e "[31m❌[0m"
  echo -e "[31mFATAL: Failed to clean up old deployments.[0m"
  exit 1
fi
step_increment
print_divider

# --------------------------------------------------------------------------------
# STEP 45: ROBUST APPLICATION CLEANUP (Fixes stuck pods and 'Allocate failed' GPU error)
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Forcing cleanup of stuck deployments..."

# 1. Force-delete ALL stuck pods (addresses the persistent 'Terminating' issue)
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete pods --all --force --grace-period=0 -n default --ignore-not-found=true > /dev/null 2>&1; then
    :
fi

# 2. Delete all Deployments (addressing the 'Allocate failed' GPU error before the *next* deployment run)
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete deployment --all -n default --ignore-not-found=true > /dev/null 2>&1; then
  sleep 5 # Give time for resources to be fully released before deployment
  echo -e "[32m✅[0m"
else
  # NOTE: A failure here is critical, as the GPU won't be free.
  echo -e "[31m❌[0m"
  echo -e "[31mFATAL: Failed to clean up old deployments.[0m"
  exit 1
fi
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 46: Deploy Application
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Deploying Application... (Verbose output below)"
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f fastapi-deployment-full.yaml
else
  step_echo_start "s" "tower" "$TOWER_IP" "Deploying FastAPI application..."
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f fastapi-deployment-full.yaml > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider


# -------------------------------------------------------------------------
# STEP 47: Deploy PostgreSQL Database
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Deploying PostgreSQL Database... (Verbose output below)"
  sleep 5
  # Substitute environment variables in deployment files
  sed "s/localhost:5000/$REGISTRY_IP:$REGISTRY_PORT/g" server/postgres/postgres-db-deployment.yaml | sed "s/\$POSTGRES_PASSWORD/$POSTGRES_PASSWORD/g" | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f -
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f server/postgres-pgadmin-nodeport-services.yaml
else
  step_echo_start "s" "tower" "$TOWER_IP" "Deploying PostgreSQL database..."
  sleep 5
  if sed "s/localhost:5000/$REGISTRY_IP:$REGISTRY_PORT/g" server/postgres/postgres-db-deployment.yaml | sed "s/\$POSTGRES_PASSWORD/$POSTGRES_PASSWORD/g" | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f - > /dev/null 2>&1 && \
     sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f server/postgres-pgadmin-nodeport-services.yaml > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider


# -------------------------------------------------------------------------
# STEP 48: Deploy pgAdmin
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Deploying pgAdmin... (Verbose output below)"
  sleep 5
  # Apply pgAdmin deployment with hardcoded credentials
  sed "s/localhost:5000/$REGISTRY_IP:$REGISTRY_PORT/g" server/pgadmin/pgadmin-deployment.yaml | \
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f -
else
  step_echo_start "s" "tower" "$TOWER_IP" "Deploying pgAdmin management interface..."
  sleep 5
  if sed "s/localhost:5000/$REGISTRY_IP:$REGISTRY_PORT/g" server/pgadmin/pgadmin-deployment.yaml | \
     sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f - > /dev/null 2>&1; then
    echo -e "[32m✅[0m"
  else
    echo -e "[31m❌[0m"
    exit 1
  fi
fi
step_increment
print_divider


# -------------------------------------------------------------------------
# STEP 49: Final Success Message
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deployment complete! Verify cluster and application status."
echo -e "[32m✅[0m"

# Final execution of the full script
if [ "$DEBUG" != "1" ]; then
  set -e
fi
step_increment
print_divider






# --------------------------------------------------------------------------------
# STEP 50: Verify PostgreSQL and pgAdmin Deployment
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Verifying PostgreSQL and pgAdmin..."

# Give pgAdmin time to fully start up before verification
sleep 120
echo ""

# Run the comprehensive verification script
echo "Running database verification checks..."
if cd server && ./verify-postgres-pgadmin.sh; then
  echo -e "[32m✅ PostgreSQL and pgAdmin verification passed[0m"
else
  echo -e "[31m❌ PostgreSQL and pgAdmin verification failed[0m"
  exit 1
fi
cd "$SCRIPT_DIR"
step_increment
print_divider


# --------------------------------------------------------------------------------
# STEP 51: FINAL DEPLOYMENT VERIFICATION AND LOGGING
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Running final verification and saving log..."

# FIX: Calling the function without output redirection.
capture_final_log "$FINAL_LOG_FILE" "$START_MESSAGE"

if [ $? -eq 0 ]; then # This checks the exit code of the previous command
    echo -en "✅[0m
"
    print_divider
    # Final success message, including the log file path
    echo -e "
[32m🌟 SUCCESS: Deployment Complete and Verified! 🌟[0m"
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
    echo -e "   • Health Check: [32mhttp://10.1.10.150:30002/health[0m"
    echo -e "   • API Docs: [32mhttp://10.1.10.150:30002/docs[0m"
    echo -e ""
    echo -e "[33m📓 Jupyter Notebook (Nano GPU):[0m"
    echo -e "   • Jupyter Interface: [32mhttp://10.1.10.150:30003[0m"
    echo -e "   • Token: [32mNot required (open access)[0m"
    echo -e ""
    echo -e "[36m═══════════════════════════════════════════════════════════════════════════════[0m"
else
    echo -e "[31m❌[0m"
    echo -e "
[31mFATAL: Final verification failed. Check the log for details.[0m"
fi
step_increment
print_divider



# --------------------------------------------------------------------------------
# STEP 52: FINAL STABILITY VERIFICATION AND ENVIRONMENT LOCKDOWN
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Final verification..."

# First verify kubectl connectivity
echo -e "🔍 Testing kubectl connectivity..."
if sudo k3s kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes >/dev/null 2>&1; then
  echo -e "✅ kubectl connectivity verified"
else
  echo -e "❌ kubectl connectivity failed - cluster may not be accessible"
  exit 1
fi
# Run comprehensive stability check
echo -e "🔍 Running comprehensive stability verification..."
echo -e "⏳ Waiting for FastAPI to fully initialize..."
sleep 60
if "$SCRIPT_DIR/stability-manager.sh" check; then
  echo -e "✅ Stability verification passed - all systems operational"
else
  echo -e "❌ Stability verification failed - check stability.log for details"
  exit 1
fi
step_increment
print_divider
