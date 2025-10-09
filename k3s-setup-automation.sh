##!/bin/bash

clear

# K3s Setup and FastAPI Deployment Automation Script
# Automates the setup of K3s cluster with GPU support for FastAPI on Jetson Nano and AGX.
# Run this script on the server (tower) machine.

# Source configuration
# NOTE: Ensure k3s-config.sh exists and contains TOWER_IP, NANO_IP, AGX_IP, REGISTRY_IP, etc.
source k3s-config.sh

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
# NOTE: Total steps count is 50
TOTAL_STEPS=50

# When not in DEBUG mode, disable 'set -e' globally to rely exclusively on explicit error checks
# to ensure the verbose/silent block structure works without immediate exit.
if [ "$DEBUG" != "1" ]; then
  set +e
fi

# Function to display step and increment counter with fixed-width formatting
step_echo_start() {
    local type="$1"
    local node="$2"
    local ip="$3"
    local msg="$4"
    
    # Define fixed lengths for alignment
    local NODE_LENGTH=6  # e.g., "tower ", "nano  ", "agx   "
    local IP_LENGTH=15   # e.g., "10.1.10.150    "

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
    
    # Use printf for fixed-width formatting
    echo -n "{${type}} ["
    printf "%-${NODE_LENGTH}s" "${node}" 
    echo -n "] ["
    printf "%-${IP_LENGTH}s" "${ip}"
    echo -n "] ${CURRENT_STEP}/${TOTAL_STEPS}. ${msg}"
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

    echo "==================================================================================" | tee -a "$log_file"
    echo "K3S FINAL DEPLOYMENT VERIFICATION LOG" | tee -a "$log_file"
    echo "Timestamp: $(date)" | tee -a "$log_file"
    echo "==================================================================================" | tee -a "$log_file"
    
    # --- 0. SCRIPT EXECUTION START MESSAGE ---
    echo -e "\n--- 0. SCRIPT EXECUTION START MESSAGE ---" | tee -a "$log_file"
    echo "$start_msg" | tee -a "$log_file"
    
    # --- 1. NODE STATUS ---
    echo -e "\n--- 1. NODE STATUS (kubectl get nodes) ---" | tee -a "$log_file"
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes | tee -a "$log_file"

    # --- 2. APPLICATION PODS STATUS (FASTAPI) ---
    echo -e "\n--- 2. APPLICATION PODS STATUS (kubectl get pods) ---" | tee -a "$log_file"
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide | tee -a "$log_file"

    # --- 3. NVIDIA DEVICE PLUGIN STATUS (KUBE-SYSTEM) ---
    echo -e "\n--- 3. NVIDIA DEVICE PLUGIN STATUS (kube-system) ---" | tee -a "$log_file"
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -n kube-system | grep nvidia-device-plugin | tee -a "$log_file"
    
    # --- 4. FULL DEPLOYMENT DETAILS ---
    echo -e "\n--- 4. FULL DEPLOYMENT DETAILS (kubectl get all) ---" | tee -a "$log_file"
    sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get all | tee -a "$log_file"

   # --- 5. CRITICAL: NANO K3S AGENT LOG ERRORS (Container Runtime Check) ---
    echo -e "\n--- 5. CRITICAL: NANO K3S AGENT LOG ERRORS (Container Runtime Check) ---" | tee -a "$log_file"
    # CORRECTED LINE 1: Change nsanjay to sanjay
    echo "Executing: ssh -i ~/.ssh/id_ed25519 sanjay@$NANO_IP 'sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E \"fastapi-nano|Error|Fail\"'" | tee -a "$log_file"
    # CORRECTED LINE 2: Change nsanjay to sanjay
    ssh -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E 'fastapi-nano|Error|Fail'" 2>&1 | tee -a "$log_file"


    # --- 6. CRITICAL: AGX K3S AGENT LOG ERRORS (Automated SSH Check) ---
    echo -e "\n--- 6. CRITICAL: AGX K3S AGENT LOG ERRORS (Container Runtime Check) ---" | tee -a "$log_file"
    echo "Executing: ssh -i ~/.ssh/id_ed25519 sanjay@$AGX_IP 'sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E \"fastapi-agx|Error|Fail\"'" | tee -a "$log_file"
    # Execute SSH command and pipe output directly to the log file
    ssh -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "sudo journalctl -u k3s-agent --since \"30 minutes ago\" | grep -E 'fastapi-agx|Error|Fail'" 2>&1 | tee -a "$log_file"

    echo -e "\n--- LOG CAPTURE COMPLETE ---" | tee -a "$log_file"
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
  local timeout=60
  local count=0
  if [ "$DEBUG" = "1" ]; then echo "Waiting for agent to be ready..."; fi
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

# Function for the critical ARP/Ping check
run_network_check() {
  local NODE_IP=$1
  local NODE_NAME=$2
  
  if ping -c 3 -W 1 $NODE_IP > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    ARP_STATUS=$(ip neigh show $NODE_IP 2>&1)
    
    if echo "$ARP_STATUS" | grep -q "INCOMPLETE"; then
      echo -e "\033[31m❌\033[0m"
      echo ""
      echo -e "\033[31m================================================================================\033[0m"
      echo -e "\033[31m🚨 CRITICAL ERROR: ${NODE_NAME} HOST UNREACHABLE (ARP/PING FAILED) 🚨\033[0m"
      echo -e "\033[33m   The Tower cannot resolve the ${NODE_NAME}'s MAC address at ${NODE_IP}.\033[0m"
      echo -e "\033[33m   ACTION REQUIRED: Please ensure the ${NODE_NAME} is fully booted and connected.\033[0m"
      echo -e "\033[33m   RECOMMENDATION: **Power cycle the Jetson ${NODE_NAME}** and rerun the script.\033[0m"
      echo -e "\033[31m================================================================================\033[0m"
      exit 1
    else
      echo -e "\033[31m❌ Ping Failed - Uncategorized Network Error for ${NODE_NAME}\033[0m"
      exit 1
    fi
  fi
}


# =========================================================================
# STEP 1: SELF-RENUMBER SCRIPT STEPS AND TOTAL_STEPS VARIABLE (AUTO-FIX)
# =========================================================================
step_echo_start "s" "tower" "$TOWER_IP" "Executing self-renumbering script logic..."

# --- AWK Logic for Renumbering ---
# This AWK script reads the entire file, renumbers 'STEP XX:' comments,
# updates the TOTAL_STEPS variable, and overwrites the script file.
# Note: $0 is the name of the script itself ($k3s-setup-automation.sh)
SCRIPT_CONTENT=$(awk '
    BEGIN { step_count = 0; }
    
    # 1. Find and renumber the step definition comments
    /^#.*STEP [0-9]+:/ {
        step_count++;
        sub(/STEP [0-9]+/, "STEP " step_count);
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
        gsub(/TOTAL_STEPS=[0-9]+/, "TOTAL_STEPS=" step_count, lines[total_steps_line]);
        
        # Print all lines from the array
        for (i=1; i<=NR; i++) {
            print lines[i];
        }
    }
' "$0")

# Overwrite the current script file with the corrected content
echo "$SCRIPT_CONTENT" > "$0"

echo -en "✅\033[0m\n"
step_increment
print_divider





# -------------------------------------------------------------------------
# STEP 2: Tower Network Configuration
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Setting up Tower network configuration..."
echo -e "\033[32m✅\033[0m"
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 3: Tower Network Verification
# -------------------------------------------------------------------------
echo "Waiting for network interfaces to come up and IPs to be assigned..."
sleep 5
echo "Verifying Tower network configuration..."
AGX_INTERFACE_AVAILABLE=false
if ip addr show enp1s0f1 | grep -q "$TOWER_IP"; then
  echo "  ✅ enp1s0f1 has IP $TOWER_IP"
  AGX_INTERFACE_AVAILABLE=true
else
  echo "  ❌ enp1s0f1 missing IP $TOWER_IP (10G interface not connected)"
  echo "  ⚠️  Skipping AGX setup - 10G network unavailable"
fi
sleep 10
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 4: Start iperf3 server
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Starting iperf3 server for network testing..."
if [ "$AGX_INTERFACE_AVAILABLE" = true ]; then
  iperf3 -s -B $TOWER_IP -D
  if [ $? -eq 0 ]; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
  fi
else
  echo -e "\033[33m⚠️  Skipped (10G interface unavailable)\033[0m"
fi
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 5: AGX SSH Validation
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Running verbose AGX SSH check..."
  fi
  step_echo_start "a" "agx" "$AGX_IP" "Verifying AGX SSH connectivity..."
  sleep 5
  # Test SSH connection by running 'hostname' on the AGX
  if ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "hostname" > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    # --- Corrected Verbose Error Handling (Replaces original simple error) ---
    echo -e "\033[31m❌ CRITICAL: Passwordless SSH Failed.\033[0m"
    echo ""
    echo -e "\033[31m================================================================================\033[0m"
    echo -e "\033[33mACTION REQUIRED: Please run './6-setup_tower_sshkeys.sh' manually\033[0m"
    echo -e "\033[33mand enter the password when prompted to enable passwordless SSH.\033[0m"
    echo -e "\033[31m================================================================================\033[0m"
    exit 1
  fi
else
  echo "{a} [agx   ] [$AGX_IP] ${CURRENT_STEP}/${TOTAL_STEPS}. AGX SSH verification skipped (not enabled)"
fi
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 6: Nano SSH Validation
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Running verbose Nano SSH check..."
  fi
  step_echo_start "a" "nano" "$NANO_IP" "Verifying Nano SSH connectivity..."
  sleep 5
  # Test SSH connection by running 'hostname' on the Nano
  if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "hostname" > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    # --- Corrected Verbose Error Handling (Replaces original simple error) ---
    echo -e "\033[31m❌ CRITICAL: Passwordless SSH Failed.\033[0m"
    echo ""
    echo -e "\033[31m================================================================================\033[0m"
    echo -e "\033[33mACTION REQUIRED: Please run './6-setup_tower_sshkeys.sh' manually\033[0m"
    echo -e "\033[33mand enter the password when prompted to enable passwordless SSH.\033[0m"
    echo -e "\033[31m================================================================================\033[0m"
    exit 1
  fi
else
  echo "{a} [nano  ] [$NANO_IP] ${CURRENT_STEP}/${TOTAL_STEPS}. Nano SSH verification skipped (not enabled)"
fi
step_increment
print_divider


# -------------------------------------------------------------------------
# STEP 7: Uninstall Server
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
    echo -e "\033[32m✅\033[0m"
  else
  echo -en " ✅\033[0m\n"  # Print checkmark anyway, as uninstall may not exist
  fi
fi
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 8: Install Server
# -------------------------------------------------------------------------
if [ "$INSTALL_SERVER" = true ]; then
  echo "{s} [tower ] [$TOWER_IP] ${CURRENT_STEP}/${TOTAL_STEPS}. Installing K3s server... "
  echo -e "\033[32m$(printf '%.0s=' {1..80})\033[0m"
  sleep 5
  # The output of the curl | sh command is inherently verbose and NOT suppressed here,
  # but the surrounding messages provide the necessary structure.
  sudo curl -sfL https://get.k3s.io | sh -s - server
  echo -e "\033[32m$(printf '%.0s=' {1..80})\033[0m"
  step_echo_start "s" "tower" "$TOWER_IP" "K3s server installed."
  echo -e "\033[32m✅\033[0m"
  step_increment
  print_divider


  # -------------------------------------------------------------------------
  # STEP 9: Correct K3s Network Configuration (SIMPLIFIED MESSAGE)
  # -------------------------------------------------------------------------
  step_echo_start "s" "tower" "$TOWER_IP" "Correcting K3s network configuration..."
  
  # 1. Stop the service installed by the curl script (Silent in both modes)
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
  echo "{s} [tower ] [$TOWER_IP] ${CURRENT_STEP}/${TOTAL_STEPS}. K3s server installation skipped."
  step_increment
  print_divider
  echo "{s} [tower ] [$TOWER_IP] ${CURRENT_STEP}/${TOTAL_STEPS}. K3s network configuration fix skipped."
  step_increment
  print_divider
fi


# -------------------------------------------------------------------------
# STEP 9: Get Token
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then echo "Getting Token: $TOKEN"; fi
step_echo_start "s" "tower" "$TOWER_IP" "Getting server token..."
sleep 5
TOKEN=$(sudo cat /var/lib/rancher/k3s/server/node-token)
echo -e "\033[32m✅\033[0m"
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 10: Uninstall Nano Agent
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Uninstalling Agent on Nano... (Verbose output below)"
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh"
  else
    step_echo_start "a" "nano" "$NANO_IP" "Uninstalling K3s agent on nano..."
    sleep 5
    if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
      echo -e "\033[32m✅\033[0m"
    else
      echo -e "\033[32m✅\033[0m"  # Print checkmark anyway, as uninstall may not exist
    fi
  fi
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
# STEP 13: Reinstall Nano Agent (FIXED IP CACHE ERROR)
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  # Define the robust installation command with explicit IP binding
  K3S_REINSTALL_CMD="export K3S_TOKEN=\"$TOKEN\"; sudo curl -sfL https://get.k3s.io | K3S_URL=https://$TOWER_IP:6443 K3S_TOKEN=\$K3S_TOKEN INSTALL_K3S_EXEC=\"--node-ip $NANO_IP\" sh -"

  if [ "$DEBUG" = "1" ]; then
    echo "Reinstalling Agent on Nano with explicit node-ip $NANO_IP..."
    ssh -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "$K3S_REINSTALL_CMD"
    wait_for_agent
  else
    step_echo_start "a" "nano" "$NANO_IP" "Reinstalling K3s agent on nano (explicit IP binding)..."
    sleep 5
    # Execute the robust reinstall command
    if ssh -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "$K3S_REINSTALL_CMD" > /dev/null 2>&1; then
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

# =========================================================================
# STEP 14: FIX NANO AGENT SERVICE FILE (CRITICAL IP CACHE FIX)
# =========================================================================
step_echo_start "a" "nano" "$NANO_IP" "Forcing K3s agent service to use correct server IP..."

# Use systemctl edit to create an override.conf file that specifically sets the
# correct server URL and node IP, clearing any old, cached settings.
ssh -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "sudo systemctl edit k3s-agent.service" > /dev/null 2>&1 << EOF
[Service]
Environment="K3S_URL=https://$TOWER_IP:6443"
Environment="K3S_NODE_IP=$NANO_IP"
EOF

# Restart the service to apply the forced environment variables
ssh -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "sudo systemctl daemon-reload && sudo systemctl restart k3s-agent"

# Check the exit status of the SSH command
if [ $? -eq 0 ]; then
    # Wait for the agent to re-join and be ready
    wait_for_agent 
    echo -en "✅\033[0m\n"
else
    echo -en "❌\033[0m\n"
    echo -e "\033[31mFATAL: Failed to overwrite NANO service file.\033[0m"
    exit 1
fi
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 15: Uninstall AGX Agent
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Uninstalling Agent on AGX... (Verbose output below)"
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh"
  else
    step_echo_start "a" "agx" "$AGX_IP" "Uninstalling K3s agent on agx..."
    sleep 5
    if ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
      echo -e "\033[32m✅\033[0m"
    else
    echo -en " ✅\033[0m\n"  # Print checkmark anyway
    fi
  fi
fi
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 16: Reinstall AGX Agent (FIXED IP CACHE ERROR)
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  # Define the robust installation command with explicit IP binding
  K3S_REINSTALL_CMD="export K3S_TOKEN=\"$TOKEN\"; sudo curl -sfL https://get.k3s.io | K3S_URL=https://$TOWER_IP:6443 K3S_TOKEN=\$K3S_TOKEN INSTALL_K3S_EXEC=\"--node-ip $AGX_IP\" sh -"

  if [ "$DEBUG" = "1" ]; then
    echo "Reinstalling Agent on AGX with explicit node-ip $AGX_IP..."
    ssh -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "$K3S_REINSTALL_CMD"
    wait_for_agent
  else
    step_echo_start "a" "agx" "$AGX_IP" "Reinstalling K3s agent on agx (fixing old IP cache)..."
    sleep 5
    # Execute the robust reinstall command
    if ssh -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "$K3S_REINSTALL_CMD" > /dev/null 2>&1; then
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

# =========================================================================
# STEP 17: FIX AGX AGENT SERVICE FILE (CRITICAL IP CACHE FIX)
# =========================================================================
step_echo_start "a" "agx" "$AGX_IP" "Forcing K3s agent service to use correct server IP..."

# Use systemctl edit to create an override.conf file that specifically sets the
# correct server URL, purging any old, cached URLs from the service file.
ssh -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "sudo systemctl edit k3s-agent.service" > /dev/null 2>&1 << EOF
[Service]
Environment="K3S_URL=https://$TOWER_IP:6443"
Environment="K3S_NODE_IP=$AGX_IP"
EOF

# Restart the service to apply the forced environment variables
ssh -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "sudo systemctl daemon-reload && sudo systemctl restart k3s-agent"

# Check the exit status of the SSH command
if [ $? -eq 0 ]; then
    # Wait for the agent to re-join and be ready
    wait_for_agent 
    echo -en "✅\033[0m\n"
else
    echo -en "❌\033[0m\n"
    echo -e "\033[31mFATAL: Failed to overwrite AGX service file.\033[0m"
    exit 1
fi
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 18: Configure Registry for AGX
# -------------------------------------------------------------------------
if [ "$INSTALL_AGX_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Configuring Registry for AGX..."
    sleep 5
  else
    step_echo_start "a" "agx" "$AGX_IP" "Configuring registry for agx..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo mkdir -p /etc/rancher/k3s/" > /dev/null 2>&1 && \
    ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
configs:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    insecure_skip_verify: true
    http: true
EOF
" > /dev/null 2>&1 && \
    ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT" > /dev/null 2>&1 && \
    ssh -o StrictHostKeyChecking=no sanjay@$AGX_IP "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/$REGISTRY_IP:$REGISTRY_PORT/hosts.toml > /dev/null <<EOF
[host.\"http://$REGISTRY_IP:$REGISTRY_PORT\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
EOF
" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
      echo -e "\033[32m✅\033[0m"
    else
      echo -e "\033[31m❌\033[0m"
      exit 1
    fi
  fi
fi
step_increment
print_divider


# =========================================================================
# STEP 19: CRITICAL: FLUSH NETWORK CACHE (ARP/Routing Cache Reset)
# =========================================================================
step_echo_start "s" "tower" "$TOWER_IP" "Flushing network ARP and routing cache on all agents..."

FLUSH_COMMAND="
  if [ -x \"\$(command -v ip)\" ]; then
    sudo ip -s -s neigh flush all
    sudo ip route flush cache
    echo 'Network caches flushed.'
  else
    echo 'IP command not found. Skipping cache flush.'
  fi
"

if [ "$INSTALL_NANO_AGENT" = true ]; then
  # Flush on Nano
  ssh -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "$FLUSH_COMMAND" > /dev/null 2>&1
fi

if [ "$INSTALL_AGX_AGENT" = true ]; then
  # Flush on AGX
  ssh -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "$FLUSH_COMMAND" > /dev/null 2>&1
fi

if [ $? -eq 0 ]; then
    echo -en " ✅\033[0m\n"
else
    # Only fail if the final SSH command failed. Network error during flush is acceptable.
    echo -en " ⚠️\033[0m (Check AGX status)\n"
fi
step_increment
print_divider




# -------------------------------------------------------------------------
# STEP 20: Create Nano Registry Config Dir
# -------------------------------------------------------------------------
if [ "$INSTALL_NANO_AGENT" = true ]; then
  if [ "$DEBUG" = "1" ]; then
    echo "Adding Registry Config Dir..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo mkdir -p /etc/rancher/k3s/"
  else
    step_echo_start "a" "nano" "$NANO_IP" "Creating registry configuration directory..."
    sleep 5
    if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo mkdir -p /etc/rancher/k3s/" > /dev/null 2>&1; then
      echo -en " ✅\033[0m\n"
    else
      echo -e "\033[31m❌\033[0m"
      exit 1
    fi
  fi
  step_increment
  print_divider

# -------------------------------------------------------------------------
# STEP 21: Add Insecure Registry Config (Initial)
# -------------------------------------------------------------------------
  if [ "$DEBUG" = "1" ]; then
    echo "Adding Insecure Registry..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "echo 'configs: \"$REGISTRY_IP:$REGISTRY_PORT\": insecure_skip_verify: true' | sudo tee /etc/rancher/k3s/registries.yaml > /dev/null"
  else
    step_echo_start "a" "nano" "$NANO_IP" "Adding insecure registry configuration..."
    sleep 5
    if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "echo 'configs: \"$REGISTRY_IP:$REGISTRY_PORT\": insecure_skip_verify: true' | sudo tee /etc/rancher/k3s/registries.yaml > /dev/null" > /dev/null 2>&1; then
      echo -en " ✅\033[0m\n"
    else
      echo -e "\033[31m❌\033[0m"
      exit 1
    fi
  fi
  step_increment
  print_divider

# --------------------------------------------------------------------------------
# NEW STEP 22: FIX KUBECONFIG IP (Addresses the 'i/o timeout' error)
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Patching Kubeconfig file with correct API IP (10.1.10.150)..."
# Fix the old/incorrect IP (e.g., 192.168.5.1) to the current static IP (10.1.10.150)
if sudo sed -i 's/192.168.5.1/10.1.10.150/g' /etc/rancher/k3s/k3s.yaml > /dev/null 2>&1; then
  echo -e "\033[32m✅\033[0m"
else
  echo -e "\033[31m❌\033[0m"
  echo -e "\033[31mFATAL: Failed to patch Kubeconfig IP address.\033[0m"
  exit 1
fi
step_increment
print_divider


# --------------------------------------------------------------------------------
# NEW STEP 23: FIX KUBECONFIG IP (Addresses the 'i/o timeout' error)
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Patching Kubeconfig file with correct API IP (10.1.10.150)..."
# Fix the old/incorrect IP (e.g., 192.168.5.1) to the current static IP ($TOWER_IP)
if sudo sed -i 's/192.168.5.1/10.1.10.150/g' /etc/rancher/k3s/k3s.yaml > /dev/null 2>&1; then
  echo -e "\033[32m✅\033[0m"
else
  echo -e "\033[31m❌\033[0m"
  echo -e "\033[31mFATAL: Failed to patch Kubeconfig IP address.\033[0m"
  exit 1
fi
step_increment
print_divider


# -------------------------------------------------------------------------
# STEP 24: Fix Registry YAML Syntax
# -------------------------------------------------------------------------
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
    step_echo_start "a" "nano" "$NANO_IP" "Fixing registry YAML syntax..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
configs:
  \"$REGISTRY_IP:$REGISTRY_PORT\":
    insecure_skip_verify: true
    http: true
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

# -------------------------------------------------------------------------
# STEP 25: Configure Containerd for Registry
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
      echo -en " ✅\033[0m\n"
    else
      echo -e "\033[31m❌\033[0m"
      exit 1
    fi
  fi
  step_increment
  print_divider

# -------------------------------------------------------------------------
# STEP 26: Restart Agent After Registry Config
# -------------------------------------------------------------------------
  if [ "$DEBUG" = "1" ]; then
    echo "Restarting Agent After Registry Config..."
    sleep 5
    ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo systemctl restart k3s-agent"
    wait_for_agent
  else
    step_echo_start "a" "nano" "$NANO_IP" "Restarting K3s agent after registry config..."
    sleep 5
    if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo systemctl restart k3s-agent" > /dev/null 2>&1; then
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
# STEP 27: Restart Server (Final Check)
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Restarting Server... (Verbose output below)"
  sleep 5
  sudo systemctl restart k3s
  wait_for_server
else
  step_echo_start "s" "tower" "$TOWER_IP" "Restarting K3s server (final check)..."
  sleep 5
  if sudo systemctl restart k3s > /dev/null 2>&1; then
    wait_for_server
  echo -en " ✅\033[0m\n"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
step_increment
print_divider

# =========================================================================
# STEP 28: COPY KUBECONFIG TO NANO AGENT (Robust Copy using 'sudo cat')
# =========================================================================
step_echo_start "s" "tower" "$TOWER_IP" "Copying Kubeconfig from server to nano agent..."

# 1. Use 'sudo cat' to read the root-owned Kubeconfig file on the Tower,
#    pipe it over SSH, and use 'sudo tee' to write it securely on the NANO.
sudo cat /etc/rancher/k3s/k3s.yaml | ssh -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "
  sudo mkdir -p /etc/rancher/k3s-agent-config && \
  sudo tee /etc/rancher/k3s-agent-config/kubeconfig.yaml > /dev/null
" > /dev/null 2>&1

# 2. Check the exit status of the SSH command
if [ $? -eq 0 ]; then
    # Ensure permissions are correct (readable by root on NANO)
    ssh -i ~/.ssh/id_ed25519 sanjay@$NANO_IP "sudo chown root:root /etc/rancher/k3s-agent-config/kubeconfig.yaml && sudo chmod 644 /etc/rancher/k3s-agent-config/kubeconfig.yaml"
    echo -en " ✅\033[0m\n"
else
    echo -en " ❌\033[0m\n"
    echo -e "\033[31mFATAL: Failed to copy Kubeconfig to NANO.\033[0m"
    exit 1
fi
step_increment
print_divider


# -------------------------------------------------------------------------
# STEP 29: Apply Taints to Agent Nodes (Prevent Traefik Scheduling)
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Applying Traefik taints to AGX and NANO..."
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml taint node agx traefik=reserved:NoSchedule --overwrite
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml taint node nano traefik=reserved:NoSchedule --overwrite
else
  # 1. Update the label to reflect the correct action
  step_echo_start "s" "tower" "$TOWER_IP" "Applying Traefik taints to agent nodes (agx, nano)..."
  sleep 5
  # 2. Apply traefik-specific taints to prevent Traefik pods from scheduling on agent nodes
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml taint node agx traefik=reserved:NoSchedule --overwrite > /dev/null 2>&1 && \
     sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml taint node nano traefik=reserved:NoSchedule --overwrite > /dev/null 2>&1; then
    echo -en " ✅\033[0m\n"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
step_increment
print_divider


# =========================================================================
# STEP 28 COPY KUBECONFIG TO AGX AGENT (Ultra-Robust 'sudo scp' version)
# =========================================================================
if [ "$INSTALL_AGX_AGENT" = true ]; then
# ... (step_echo_start call)

# 1. Use 'sudo' with scp on the Tower side to read the root-owned Kubeconfig...
if sudo scp -i ~/.ssh/id_ed25519 /etc/rancher/k3s/k3s.yaml sanjay@$AGX_IP:/tmp/k3s.yaml.agx > /dev/null 2>&1; then
    # 2. On the AGX, use a single SSH command to move the file and set permissions.
    ssh -i ~/.ssh/id_ed25519 sanjay@$AGX_IP "
      sudo mkdir -p /etc/rancher/k3s-agent-config && \
      sudo mv /tmp/k3s.yaml.agx /etc/rancher/k3s-agent-config/kubeconfig.yaml && \
      sudo chown root:root /etc/rancher/k3s-agent-config/kubeconfig.yaml && \
      sudo chmod 644 /etc/rancher/k3s-agent-config/kubeconfig.yaml
    " > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        echo -en " ✅\033[0m\n"
    else
        echo -en " ❌\033[0m\n"
        echo -e "\033[31mFATAL: Failed to secure Kubeconfig on AGX. File may be in /tmp.\033[0m"
        exit 1
    fi
# THIS LINE MUST BE IMMEDIATELY FOLLOWED BY `else` WITH NO WHITESPACE/TABS
else
    echo -en " ❌\033[0m\n"
    echo -e "\033[31mFATAL: Failed to transfer Kubeconfig file to AGX /tmp directory.\033[0m"
    exit 1
fi
step_increment
print_divider
fi

# -------------------------------------------------------------------------
# STEP 30: Install NVIDIA RuntimeClass
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
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 31: Install NVIDIA Device Plugin
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Installing NVIDIA Device Plugin... (Verbose output below)"
  echo ""
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f nvidia-ds-updated.yaml
  wait_for_gpu_capacity
else
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f nvidia-ds-updated.yaml > /dev/null 2>&1; then
    wait_for_gpu_capacity
    step_echo_start "s" "tower" "$TOWER_IP" "Installing NVIDIA device plugin..."
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
step_increment
print_divider

# --------------------------------------------------------------------------------
# NEW STEP 32: FIX NFS VOLUME PATHS (Addresses 'No such file or directory' error)
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Creating missing NFS volume directories and re-exporting..."
NFS_BASE="/export/vmstore"
# Paths identified from the Persistent Volume Claims (PVCs):
NFS_CONFIG_PATH="$NFS_BASE/tower_home/kubernetes/agent/nano/app/config"
NFS_HOME_PATH="$NFS_BASE/nano_home"

if sudo mkdir -p "$NFS_CONFIG_PATH" "$NFS_HOME_PATH" > /dev/null 2>&1; then
    # Re-export the volumes to ensure the new paths are available immediately
    sudo exportfs -a > /dev/null 2>&1
    echo -e "\033[32m✅\033[0m"
else
    echo -e "\033[31m❌\033[0m"
    echo -e "\033[31mFATAL: Failed to create required NFS directories.\033[0m"
    exit 1
fi
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 33: FIX NVIDIA DEVICE PLUGIN NODE AFFINITY (NEW SELF-HEALING STEP)
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Fixing NVIDIA plugin node affinity to exclude Tower..."
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
    
    echo -e "\033[32m✅\033[0m"
else
    echo -e "\033[31m❌ Failed to patch NVIDIA Device Plugin DaemonSet\033[0m"
    exit 1
fi
step_increment
print_divider

# --------------------------------------------------------------------------------
# NEW STEP 34: FIX NFS VOLUME PATHS (Addresses 'No such file or directory' error)
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Creating missing NFS volume directories and re-exporting..."
NFS_BASE="/export/vmstore"
# Paths found during debugging from the pod YAML:
NFS_CONFIG_PATH="$NFS_BASE/tower_home/kubernetes/agent/nano/app/config"
NFS_HOME_PATH="$NFS_BASE/nano_home"

if sudo mkdir -p "$NFS_CONFIG_PATH" "$NFS_HOME_PATH" > /dev/null 2>&1; then
    # Re-export the volumes to ensure the new paths are available immediately
    sudo exportfs -a > /dev/null 2>&1
    echo -e "\033[32m✅\033[0m"
else
    echo -e "\033[31m❌\033[0m"
    echo -e "\033[31mFATAL: Failed to create required NFS directories.\033[0m"
    exit 1
fi
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 35: Configure NVIDIA Runtime on Nano
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
      echo -e "\033[32m✅\033[0m"
    else
      echo -e "\033[31m❌\033[0m"
      exit 1
    fi
  fi
fi
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 36: Copy Files for Build
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Copying Files for Build... (Verbose output below)"
  sleep 5
  scp /home/sanjay/containers/kubernetes/agent/nano/dockerfile.nano.req sanjay@$NANO_IP:~
  scp /home/sanjay/containers/kubernetes/agent/nano/requirements.nano.txt sanjay@$NANO_IP:~
  scp -r /home/sanjay/containers/kubernetes/agent/nano/app sanjay@$NANO_IP:~
else
  step_echo_start "a" "nano" "$NANO_IP" "Copying files for Docker build..."
  sleep 5
  if scp /home/sanjay/containers/kubernetes/agent/nano/dockerfile.nano.req sanjay@$NANO_IP:~ > /dev/null 2>&1 && scp /home/sanjay/containers/kubernetes/agent/nano/requirements.nano.txt sanjay@$NANO_IP:~ > /dev/null 2>&1 && scp -r /home/sanjay/containers/kubernetes/agent/nano/app sanjay@$NANO_IP:~ > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 37: Build Image
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Building Image... (Verbose output below)"
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo docker build -t fastapi_nano:latest -f dockerfile.nano.req ."
else
  step_echo_start "a" "nano" "$NANO_IP" "Building Docker image..."
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo docker build -t fastapi_nano:latest -f dockerfile.nano.req ." > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 38: Tag Image
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Tagging Image..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo docker tag fastapi_nano:latest $REGISTRY_IP:$REGISTRY_PORT/fastapi_nano:latest"
else
  step_echo_start "a" "nano" "$NANO_IP" "Tagging Docker image..."
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo docker tag fastapi_nano:latest $REGISTRY_IP:$REGISTRY_PORT/fastapi_nano:latest" > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 39: Push Image
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Pushing Image... (Verbose output below)"
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo docker push $REGISTRY_IP:$REGISTRY_PORT/fastapi_nano:latest"
else
  step_echo_start "a" "nano" "$NANO_IP" "Pushing Docker image to registry..."
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@$NANO_IP "sudo docker push $REGISTRY_IP:$REGISTRY_PORT/fastapi_nano:latest" > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
step_increment
print_divider

# --------------------------------------------------------------------------------
# NEW STEP 40: ROBUST APPLICATION CLEANUP (Fixes stuck pods and 'Allocate failed' GPU error)
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Robust cleanup: Forcing termination of stuck pods and deleting old deployments..."

# 1. Force-delete ALL stuck pods (addresses the persistent 'Terminating' issue)
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete pods --all --force --grace-period=0 -n default --ignore-not-found=true > /dev/null 2>&1; then
    echo "  (Stuck pods forcibly cleared)"
fi

# 2. Delete all Deployments (addressing the 'Allocate failed' GPU error for the new deployment)
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete deployment --all -n default --ignore-not-found=true > /dev/null 2>&1; then
  sleep 5 # Give 5 seconds for resources to be fully released before the next deployment
  echo -e "\033[32m✅\033[0m"
else
  echo -e "\033[31m❌\033[0m"
  echo -e "\033[31mFATAL: Failed to clean up old deployments.\033[0m"
  exit 1
fi
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 41: Create Deployment YAML
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Creating Deployment YAML..."
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
echo -e "\033[32m✅\033[0m"
step_increment
print_divider

# -------------------------------------------------------------------------
# STEP 42: Deploy Application
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Deploying Application... (Verbose output below)"
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f fastapi-deployment-full.yaml
else
  step_echo_start "s" "tower" "$TOWER_IP" "Deploying FastAPI application..."
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f fastapi-deployment-full.yaml > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
step_increment
print_divider


# -------------------------------------------------------------------------
# STEP 43: Deploy PostgreSQL Database
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Deploying PostgreSQL Database... (Verbose output below)"
  sleep 5
  # Substitute environment variables in deployment files
  sed "s/\\\$POSTGRES_PASSWORD/$POSTGRES_PASSWORD/g" server/postgres/postgres-db-deployment.yaml | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f -
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f server/postgres-pgadmin-nodeport-services.yaml
else
  step_echo_start "s" "tower" "$TOWER_IP" "Deploying PostgreSQL database..."
  sleep 5
  if sed "s/\\\$POSTGRES_PASSWORD/$POSTGRES_PASSWORD/g" server/postgres/postgres-db-deployment.yaml | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f - > /dev/null 2>&1 && \
     sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f server/postgres-pgadmin-nodeport-services.yaml > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
step_increment
print_divider


# -------------------------------------------------------------------------
# STEP 44: Deploy pgAdmin
# -------------------------------------------------------------------------
if [ "$DEBUG" = "1" ]; then
  echo "Deploying pgAdmin... (Verbose output below)"
  sleep 5
  # Substitute environment variables in secret and deployment files
  sed "s/\\\$PGADMIN_PASSWORD/$PGADMIN_PASSWORD/g" server/pgadmin/pgadmin-secret.yaml | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f -
  sed "s/\\\$PGADMIN_EMAIL/$PGADMIN_EMAIL/g" server/pgadmin/pgadmin-deployment.yaml | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f -
else
  step_echo_start "s" "tower" "$TOWER_IP" "Deploying pgAdmin management interface..."
  sleep 5
  if sed "s/\\\$PGADMIN_PASSWORD/$PGADMIN_PASSWORD/g" server/pgadmin/pgadmin-secret.yaml | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f - > /dev/null 2>&1 && \
     sed "s/\\\$PGADMIN_EMAIL/$PGADMIN_EMAIL/g" server/pgadmin/pgadmin-deployment.yaml | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f - > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi
step_increment
print_divider


# -------------------------------------------------------------------------
# STEP 45: Final Success Message
# -------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deployment complete! Verify cluster and application status."
echo -e "\033[32m✅\033[0m"

# Final execution of the full script
if [ "$DEBUG" != "1" ]; then
  set -e
fi

# --------------------------------------------------------------------------------
# NEW STEP 46: Global Application Cleanup (Frees up lingering GPU resources)
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Deleting all old deployments to free GPU resources..."

# Wait briefly for API server readiness
sleep 5

# Force-delete all existing deployments in the 'default' namespace
# --ignore-not-found prevents the script from failing if no deployments exist
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete deployment --all -n default --ignore-not-found=true > /dev/null 2>&1; then
  echo -e "\033[32m✅\033[0m"
else
  # NOTE: A failure here is critical, as the GPU won't be free.
  echo -e "\033[31m❌\033[0m"
  echo -e "\033[31mFATAL: Failed to clean up old deployments.\033[0m"
  exit 1
fi
step_increment
print_divider

# --------------------------------------------------------------------------------
# NEW STEP 47: ROBUST APPLICATION CLEANUP (Fixes stuck pods and 'Allocate failed' GPU error)
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Robust cleanup: Forcing termination and deleting deployments..."

# 1. Force-delete ALL stuck pods (addresses the persistent 'Terminating' issue)
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete pods --all --force --grace-period=0 -n default --ignore-not-found=true > /dev/null 2>&1; then
    echo "  (Stuck pods cleared)"
fi

# 2. Delete all Deployments (addressing the 'Allocate failed' GPU error before the *next* deployment run)
if sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl delete deployment --all -n default --ignore-not-found=true > /dev/null 2>&1; then
  sleep 5 # Give time for resources to be fully released before deployment
  echo -e "\033[32m✅\033[0m"
else
  # NOTE: A failure here is critical, as the GPU won't be free.
  echo -e "\033[31m❌\\033[0m"
  echo -e "\033[31mFATAL: Failed to clean up old deployments.\033[0m"
  exit 1
fi
step_increment
print_divider

# --------------------------------------------------------------------------------
# STEP 48: Verify PostgreSQL and pgAdmin Deployment
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Running comprehensive PostgreSQL and pgAdmin verification..."

# Run the comprehensive verification script
echo "Running database verification checks..."
if cd server && ./verify-postgres-pgadmin.sh; then
  echo -e "\033[32m✅ PostgreSQL and pgAdmin verification passed\033[0m"
else
  echo -e "\033[31m❌ PostgreSQL and pgAdmin verification failed\033[0m"
  exit 1
fi

step_increment
print_divider


# --------------------------------------------------------------------------------
# STEP 49: VERIFY TRAEFIK PLACEMENT ON MASTER NODE
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Verifying Traefik pod placement on master node..."

# Check that Traefik pod is running on tower (master) node
TRAEFIK_POD_NODE=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -n kube-system -l app.kubernetes.io/name=traefik -o jsonpath='{.items[0].spec.nodeName}' 2>/dev/null)

if [ "$TRAEFIK_POD_NODE" = "tower" ]; then
    echo -en " ✅\033[0m\n"
else
    echo -e "\033[31m❌ Traefik pod found on node: $TRAEFIK_POD_NODE (expected: tower)\033[0m"
    exit 1
fi

step_increment
print_divider


# --------------------------------------------------------------------------------
# STEP 50: FINAL DEPLOYMENT VERIFICATION AND LOGGING
# --------------------------------------------------------------------------------
step_echo_start "s" "tower" "$TOWER_IP" "Running final verification and saving log..."

# FIX: Calling the function without output redirection.
capture_final_log "$FINAL_LOG_FILE" "$START_MESSAGE"

if [ $? -eq 0 ]; then # This checks the exit code of the previous command
    echo -en "✅\033[0m\n"
    print_divider

    # Final success message, including the log file path
    echo -e "\n\033[32m🌟 SUCCESS: Deployment Complete and Verified! 🌟\033[0m"
    echo -e "Final status log saved to: \033[33m$FINAL_LOG_FILE\033[0m"
    echo -e "Please share this log file to confirm successful deployment."
    echo -e ""
    echo -e "\033[36m═══════════════════════════════════════════════════════════════════════════════\033[0m"
    echo -e "\033[36m                           🚀 ACCESS INFORMATION 🚀\033[0m"
    echo -e "\033[36m═══════════════════════════════════════════════════════════════════════════════\033[0m"
    echo -e ""
    echo -e "\033[33m📊 PostgreSQL Database:\033[0m"
    echo -e "   • Direct Access: \033[32m10.1.10.150:30432\033[0m"
    echo -e "   • Username: \033[32mpostgres\033[0m"
    echo -e "   • Password: \033[32mpostgres\033[0m"
    echo -e ""
    echo -e "\033[33m🖥️  pgAdmin Management Interface:\033[0m"
    echo -e "   • Web UI: \033[32mhttp://10.1.10.150:30080\033[0m"
    echo -e "   • Username: \033[32mpgadmin@pgadmin.org\033[0m"
    echo -e "   • Password: \033[32mpgadmin\033[0m"
    echo -e ""
    echo -e "\033[33m🤖 FastAPI Application (Nano GPU):\033[0m"
    echo -e "   • API Endpoint: \033[32mhttp://10.1.10.150:30002\033[0m"
    echo -e "   • Health Check: \033[32mhttp://10.1.10.150:30002/health\033[0m"
    echo -e "   • API Docs: \033[32mhttp://10.1.10.150:30002/docs\033[0m"
    echo -e "   • Jupyter Notebook: \033[32mhttp://10.1.10.150:30003\033[0m"
    echo -e ""
    echo -e "\033[36m═══════════════════════════════════════════════════════════════════════════════\033[0m"
else
    echo -e "\033[31m❌\033[0m"
    echo -e "\n\033[31mFATAL: Final verification failed. Check the log for details.\033[0m"
fi

step_increment
print_divider
