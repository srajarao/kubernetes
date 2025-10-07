#!/bin/bash
set -e

# --- Configuration Variables (AUTO-DETECTED INTERFACE NAME) ---
AGX_IFACE=$(ip link show | grep -E '^[0-9]+: en' | head -1 | cut -d: -f2 | tr -d ' ') # Auto-detect primary ethernet interface
AGX_IP="192.168.10.11"
TOWER_IP="192.168.10.1"
NETMASK="/24"
MOUNT_POINT="/mnt/vmstore"
BACKUP_DIR="/tmp/agx_netplan_backup_$(date +%Y%m%d_%H%M%S)"

echo "#####################################################"
echo "# Configuring Jetson AGX Orin for 10G Link...       #"
echo "#####################################################"

# Validate interface detection
if [ -z "$AGX_IFACE" ]; then
    echo "❌ ERROR: Could not auto-detect ethernet interface"
    echo "Available interfaces:"
    ip link show | grep -E '^[0-9]+:'
    exit 1
fi
echo "🔍 Auto-detected ethernet interface: $AGX_IFACE"

# Create backup directory
mkdir -p "$BACKUP_DIR"

echo "0. Creating backup of current network configuration..."
# Backup existing netplan files
if ls /etc/netplan/*.yaml 1> /dev/null 2>&1; then
    sudo cp /etc/netplan/*.yaml "$BACKUP_DIR/"
    echo "   ✅ Netplan files backed up to: $BACKUP_DIR"
fi

# Backup current network state
ip addr show > "$BACKUP_DIR/ip_addr_before.txt"
ip route show > "$BACKUP_DIR/ip_route_before.txt"
df -h | grep vmstore > "$BACKUP_DIR/nfs_mounts_before.txt" 2>/dev/null || echo "No NFS mounts found" > "$BACKUP_DIR/nfs_mounts_before.txt"
echo "   ✅ Current network state backed up"

# --- STEP 0: Clean Up and Install Prerequisites ---
echo "1. Cleaning up old Netplan and installing NFS client..."
# Remove any conflicting netplan files starting with 99- or 50-
if ls /etc/netplan/99-*-static.yaml 1> /dev/null 2>&1; then
    sudo mv /etc/netplan/99-*-static.yaml "$BACKUP_DIR/"
    echo "   Moved old static netplan files to backup"
fi
if ls /etc/netplan/50-dedicated-networks.yaml 1> /dev/null 2>&1; then
    sudo mv /etc/netplan/50-dedicated-networks.yaml "$BACKUP_DIR/"
    echo "   Moved old dedicated network files to backup"
fi

# Fix broken Kubernetes repository if it exists
if [ -f /etc/apt/sources.list.d/kubernetes.list ]; then
    echo "   Fixing broken Kubernetes repository..."
    sudo rm -f /etc/apt/sources.list.d/kubernetes.list
fi

# Use apt-get instead of apt for scripts (avoids CLI stability warning)
sudo apt-get update -qq && sudo apt-get install -y nfs-common

# --- STEP 1: Apply Static IP (using Netplan) ---
NETPLAN_FILE="/etc/netplan/99-agx-static.yaml"

echo "2. Creating/updating Netplan configuration for $AGX_IFACE with $AGX_IP..."
cat << EOF | sudo tee $NETPLAN_FILE > /dev/null
network:
  version: 2
  ethernets:
    $AGX_IFACE:
      dhcp4: false
      addresses: [$AGX_IP$NETMASK]
EOF

sudo chmod 600 $NETPLAN_FILE
sudo netplan apply
echo "   ...Static IP applied."

echo ""
echo "💾 BACKUP INFORMATION:"
echo "   Backup location: $BACKUP_DIR"
echo "   To restore if needed:"
echo "   sudo cp $BACKUP_DIR/*.yaml /etc/netplan/"
echo "   sudo netplan apply"

# --- STEP 3: Update /etc/hosts for hostname resolution ---
echo "3. Updating /etc/hosts for device hostname resolution..."
HOST_ENTRIES="
192.168.10.1 tower
192.168.10.11 agx
192.168.5.21 nano
"
if ! grep -q "192.168.10.1 tower" /etc/hosts; then
    echo "$HOST_ENTRIES" | sudo tee -a /etc/hosts > /dev/null
    echo "   ✅ Host entries added to /etc/hosts"
else
    echo "   ✅ Host entries already in /etc/hosts"
fi

# --- STEP 4: Verify Connectivity ---
echo "2. Testing connectivity to Tower ($TOWER_IP)..."
ping -c 3 $TOWER_IP

if [ $? -eq 0 ]; then
    echo "   ...Ping successful. Basic connectivity confirmed."

    # --- STEP 3: Clean up and Test NFS Mount ---
    echo "3. Testing NFS mount from $TOWER_IP:/export/vmstore..."
    # Attempt to unmount any existing mount at the location
    sudo umount -l $MOUNT_POINT 2>/dev/null || true
    sudo mkdir -p $MOUNT_POINT
    sudo mount $TOWER_IP:/export/vmstore $MOUNT_POINT

    if df -h | grep $MOUNT_POINT; then
        echo "   ✅ NFS Mount successful!"
        
        # Make mount persistent in /etc/fstab
        FSTAB_ENTRY="$TOWER_IP:/export/vmstore $MOUNT_POINT nfs noauto,x-systemd.automount,nofail,nfsvers=4 0 0"
        if ! grep -q "$FSTAB_ENTRY" /etc/fstab; then
            echo "$FSTAB_ENTRY" | sudo tee -a /etc/fstab > /dev/null
            echo "   ✅ Added persistent mount to /etc/fstab"
        else
            echo "   ✅ Persistent mount already in /etc/fstab"
        fi
        
    else
        echo "   ❌ NFS Mount FAILED. Check Tower NFS status."
    fi

    # --- STEP 4: 10G Speed Test (Requires iperf3 on both) ---
    if command -v iperf3 &> /dev/null; then
        echo "4. Running iperf3 speed test (Tower must be running 'iperf3 -s -B $TOWER_IP')..."
        iperf3 -c $TOWER_IP -P 8 -t 10
        echo "   ✅ iperf3 speed test completed successfully"
    else
        echo "4. iperf3 not found. Install with 'sudo apt install iperf3' to test 10G speed."
        exit 1
    fi

else
    echo "   ❌ Ping FAILED. Check cable and Tower (192.168.10.1) configuration."
fi
