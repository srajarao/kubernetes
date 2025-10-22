#!/bin/bash
set -e

echo "########################################"
echo "## NFS Client Setup for DGX Spark     ##"
echo "## Device                              ##"
echo "########################################"

# Configuration
TOWER_IP="10.1.10.150"
NFS_SHARE="/export/vmstore"
MOUNT_POINT="/mnt/vmstore"

echo "Setting up NFS client on DGX Spark device..."
echo "NFS Server: $TOWER_IP"
echo "Share: $NFS_SHARE"
echo "Mount Point: $MOUNT_POINT"
echo ""

# Install NFS client
echo "1. Installing NFS client..."
sudo apt update
sudo apt install -y nfs-common
echo "   ✅ NFS client installed"

# Create mount directory
echo "2. Creating mount directory..."
sudo mkdir -p "$MOUNT_POINT"
echo "   ✅ Mount directory created: $MOUNT_POINT"

# Mount NFS share
echo "3. Mounting NFS share..."
sudo mount "$TOWER_IP:$NFS_SHARE" "$MOUNT_POINT"
echo "   ✅ NFS share mounted"

# Test mount
echo "4. Testing NFS access..."
if ls "$MOUNT_POINT" > /dev/null 2>&1; then
    echo "   ✅ NFS mount accessible"
else
    echo "   ❌ NFS mount not accessible"
    exit 1
fi

# Add to fstab for persistence
echo "5. Configuring persistent mount in /etc/fstab..."
FSTAB_ENTRY="$TOWER_IP:$NFS_SHARE $MOUNT_POINT nfs defaults 0 0"
if ! grep -q "$FSTAB_ENTRY" /etc/fstab; then
    echo "$FSTAB_ENTRY" | sudo tee -a /etc/fstab > /dev/null
    echo "   ✅ Added to /etc/fstab"
else
    echo "   ✅ Already in /etc/fstab"
fi

# Set permissions (optional, adjust as needed)
echo "6. Setting permissions..."
sudo chown -R sanjay:sanjay "$MOUNT_POINT" 2>/dev/null || true
echo "   ✅ Permissions set"

echo ""
echo "NFS setup complete! The share will auto-mount on boot."
echo "Test with: ls $MOUNT_POINT"