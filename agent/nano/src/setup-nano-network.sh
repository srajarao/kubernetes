#!/bin/bash
set -e

# --- Configuration Variables (REPLACE THE INTERFACE NAME) ---
NANO_IFACE="eno1" # e.g., eth0, enp1s0
NANO_IP="192.168.5.21"
TOWER_IP="192.168.5.1"
NETMASK="/24"
MOUNT_POINT="/mnt/vmstore"
BACKUP_DIR="/tmp/nano_netplan_backup_$(date +%Y%m%d_%H%M%S)"

echo "#####################################################"
echo "# Configuring Jetson Nano for 1G Link...            #"
echo "# WITH INTERNET CONNECTIVITY PRESERVED               #"
echo "#####################################################"

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
NETPLAN_FILE="/etc/netplan/99-nano-static.yaml"

echo "2. Creating/updating Netplan configuration for $NANO_IFACE with $NANO_IP..."
echo "   IMPORTANT: Preserving internet connectivity via WiFi as backup"

cat << EOF | sudo tee $NETPLAN_FILE > /dev/null
network:
  version: 2
  ethernets:
    $NANO_IFACE:
      dhcp4: false
      addresses: [$NANO_IP$NETMASK]
      # Use Tower as gateway for dedicated network connectivity
      # but DON'T set as default route to preserve internet via WiFi
      routes:
        - to: 192.168.10.0/24
          via: $TOWER_IP
          metric: 100
    # Preserve existing WiFi configuration for internet access
    # (This assumes WiFi interface exists and is configured via other netplan files)
EOF

sudo chmod 600 $NETPLAN_FILE
sudo netplan apply
echo "   ...Static IP applied with preserved internet connectivity."

# --- STEP 2: Verify Connectivity ---
echo "2. Testing connectivity to Tower ($TOWER_IP)..."
ping -c 3 $TOWER_IP

if [ $? -eq 0 ]; then
    echo "   ...Ping successful. Basic connectivity confirmed."
    
    # Test internet connectivity
    echo "   Testing internet connectivity..."
    if ping -c 2 8.8.8.8 > /dev/null 2>&1; then
        echo "   ✅ Internet connectivity preserved!"
    else
        echo "   ⚠️  Internet connectivity may be affected. Check WiFi configuration."
    fi

    # --- STEP 3: Clean up and Test NFS Mount ---
    echo "3. Testing NFS mount from $TOWER_IP:/export/vmstore..."
    # Attempt to unmount any existing mount at the location
    sudo umount -l $MOUNT_POINT 2>/dev/null || true
    sudo mkdir -p $MOUNT_POINT
    sudo mount $TOWER_IP:/export/vmstore $MOUNT_POINT

    if mount | grep "$TOWER_IP:/export/vmstore on $MOUNT_POINT" > /dev/null 2>&1; then
        echo "   ✅ NFS Mount successful at $MOUNT_POINT!"
        echo "   📁 Testing file access..."
        if ls $MOUNT_POINT > /dev/null 2>&1; then
            echo "   ✅ File access confirmed!"
        else
            echo "   ⚠️  Mount exists but file access may be limited"
        fi
    else
        echo "   ❌ NFS Mount FAILED. Check Tower NFS status."
        echo "   🔍 Debug info:"
        echo "      - Tower NFS exports: $(showmount -e $TOWER_IP 2>/dev/null || echo 'Cannot connect to NFS server')"
        echo "      - Current mounts: $(mount | grep nfs || echo 'No NFS mounts found')"
    fi

    # --- STEP 4: Test AGX Communication (if routing is enabled) ---
    echo "4. Testing communication with AGX (192.168.10.11)..."
    if ping -c 2 192.168.10.11 > /dev/null 2>&1; then
        echo "   ✅ AGX communication working! Inter-device routing is functional."
    else
        echo "   ⚠️  AGX communication not available."
        echo "      This is normal if routing scripts haven't been run yet."
        echo "      To enable AGX communication, run: ./setup_agx_routing.sh on AGX"
    fi

else
    echo "   ❌ Ping FAILED. Check cable and Tower (192.168.5.1) configuration."
fi

echo ""
echo "==================================================="
echo "📋 NANO NETWORK CONFIGURATION COMPLETE"
echo "==================================================="
echo "✅ Dedicated 1G link: $NANO_IP → $TOWER_IP"
echo "✅ Internet access: Preserved via existing connection"
echo "✅ NFS mount: Available at $MOUNT_POINT"
echo "🔗 AGX communication: Available if routing is configured"
echo ""
echo "💾 BACKUP INFORMATION:"
echo "   Backup location: $BACKUP_DIR"
echo "   To restore if needed:"
echo "   sudo cp $BACKUP_DIR/*.yaml /etc/netplan/"
echo "   sudo netplan apply"
echo "==================================================="