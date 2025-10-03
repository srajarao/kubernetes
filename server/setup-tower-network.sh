#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status

# --- TOWER IP ASSIGNMENTS ---
# AGX 10G Network: 192.168.10.x/24 (Tower IP: 192.168.10.1)
# Nano 1G Network: 192.168.5.x/24 (Tower IP: 192.168.5.1)

echo "#####################################################"
echo "# Starting Tower Dedicated Network Configuration... #"
echo "#####################################################"

# Create backup directory
BACKUP_DIR="/tmp/netplan_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "0. Creating backup of current network configuration..."
# Backup existing netplan files
if ls /etc/netplan/*.yaml 1> /dev/null 2>&1; then
    sudo cp /etc/netplan/*.yaml "$BACKUP_DIR/"
    echo "   ✅ Netplan files backed up to: $BACKUP_DIR"
fi

# Backup current IP configuration
ip addr show > "$BACKUP_DIR/ip_addr_before.txt"
ip route show > "$BACKUP_DIR/ip_route_before.txt"
echo "   ✅ Current network state backed up"

# Check if we're re-running and clean up previous configs
NETPLAN_FILE="/etc/netplan/50-dedicated-networks.yaml"
if [ -f "$NETPLAN_FILE" ]; then
    echo "   ⚠️  Found existing dedicated network config - will update"
fi

# --- STEP 1: Flush Conflicting IP Addresses ---
echo "1. Flushing existing IPs from 10G (enp1s0f0) and 1G (eno2) ports..."
sudo ip addr flush dev enp1s0f0
sudo ip addr flush dev eno2
echo "   ...IPs flushed."

# --- STEP 2: Create and Apply Netplan Configuration ---
NETPLAN_FILE="/etc/netplan/50-dedicated-networks.yaml"

echo "2. Creating/updating Netplan configuration file: $NETPLAN_FILE"
# NOTE: Using enp1s0f0 for 10G based on ethtool confirmation.
cat << EOF | sudo tee $NETPLAN_FILE > /dev/null
network:
  version: 2
  ethernets:
    # 1. 10G Link to AGX (IP: 192.168.10.1)
    enp1s0f0:
      dhcp4: false
      addresses: [192.168.10.1/24]
      
    # 2. 1G Link to Nano (IP: 192.168.5.1)
    eno2:
      dhcp4: false
      addresses: [192.168.5.1/24]
EOF

# Secure file permissions (Fixes the WARNING)
echo "   Securing Netplan file permissions..."
sudo chmod 600 $NETPLAN_FILE

echo "   Applying new Netplan configuration..."
sudo netplan apply
echo "   ...Netplan applied."


# --- STEP 3: Configure and Restart NFS ---
# Note: /etc/exports and /export/vmstore must exist before this step.
echo "3. Reloading NFS service..."
sudo exportfs -ra
# The restart command is critical for ensuring the NFS server picks up the changes
# and uses the new static IPs defined in /etc/exports.
sudo systemctl restart nfs-kernel-server
echo "   ...NFS service reloaded."


# --- STEP 4: Final Tower IP Verification ---
echo ""
echo "4. VERIFYING TOWER's NEW IP ADDRESSES:"
echo "--------------------------------------"
ip addr | grep -E 'enp1s0f0|eno2'
echo "--------------------------------------"
echo "  Tower IPs should show 192.168.10.1 on enp1s0f0 (10G) and 192.168.5.1 on eno2 (1G)."


# --- STEP 5: Connectivity Test (Requires Clients to be Configured) ---
echo ""
echo "5. TESTING CONNECTIVITY (AGX/Nano IPs must be set first):"
echo "--------------------------------------------------------"
ping -c 3 192.168.10.11 || echo "   Ping to AGX (192.168.10.11) FAILED. Check AGX IP setup."
ping -c 3 192.168.5.21 || echo "   Ping to Nano (192.168.5.21) FAILED. Check Nano IP setup."
echo "--------------------------------------------------------"
echo "Configuration script finished. Move to client configuration now."