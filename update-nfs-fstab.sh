#!/bin/bash
set -e

# Script to update NFS mounts in /etc/fstab with correct Tower IP
# Run this on each device (Tower, AGX, Nano) after IP address changes

TOWER_IP="10.1.10.150"
MOUNT_POINT="/mnt/vmstore"
NFS_EXPORT="/export/vmstore"

echo "🔧 Updating NFS mount in /etc/fstab..."
echo "   Tower IP: $TOWER_IP"
echo "   Mount Point: $MOUNT_POINT"
echo "   NFS Export: $NFS_EXPORT"

# Backup current fstab
FSTAB_BACKUP="/etc/fstab.backup.$(date +%Y%m%d_%H%M%S)"
sudo cp /etc/fstab "$FSTAB_BACKUP"
echo "   📋 Backed up current fstab to: $FSTAB_BACKUP"

# Remove any existing vmstore entries
sudo sed -i '/vmstore/d' /etc/fstab

# Add the new NFS mount entry
FSTAB_ENTRY="$TOWER_IP:$NFS_EXPORT $MOUNT_POINT nfs defaults,nofail 0 0"
echo "$FSTAB_ENTRY" | sudo tee -a /etc/fstab > /dev/null

echo "   ✅ Added NFS mount to fstab:"
echo "      $FSTAB_ENTRY"

# Test the mount
echo "   🧪 Testing NFS mount..."
sudo mkdir -p "$MOUNT_POINT"

# Unmount if already mounted
sudo umount -l "$MOUNT_POINT" 2>/dev/null || true

# Mount using fstab entry
sudo mount "$MOUNT_POINT"

if mount | grep "$MOUNT_POINT" > /dev/null; then
    echo "   ✅ NFS mount successful!"
    echo "   📁 Mount point: $MOUNT_POINT"
    echo "   🖥️  Server: $TOWER_IP:$NFS_EXPORT"
else
    echo "   ❌ NFS mount failed!"
    echo "   🔍 Check NFS server on Tower and network connectivity"
fi

echo ""
echo "📋 FSTAB UPDATE COMPLETE"
echo "   Mount will persist across reboots"
echo "   To restore old fstab: sudo cp $FSTAB_BACKUP /etc/fstab"