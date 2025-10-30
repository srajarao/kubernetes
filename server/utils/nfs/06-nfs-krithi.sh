#!/bin/bash
set -e

echo "=========================================="
echo "🔍 NFS Client Validation on Krithi"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
NFS_SERVER="192.168.1.150"
NFS_SHARE="/export/vmstore"
MOUNT_POINT="/mnt/vmstore"

# Function to print status
print_status() {
    local status=$1
    local message=$2
    if [ "$status" -eq 0 ]; then
        echo -e "${GREEN}✅ $message${NC}"
    else
        echo -e "${RED}❌ $message${NC}"
    fi
}

echo "Validating NFS client setup on Krithi..."
echo "Server: $NFS_SERVER, Share: $NFS_SHARE, Mount: $MOUNT_POINT"
echo ""

# 1. Check if NFS client is installed
echo "1. Checking NFS client installation..."
if command -v mount.nfs &> /dev/null; then
    print_status 0 "NFS client utilities are installed"
else
    print_status 1 "NFS client utilities are NOT installed"
    echo "   Please install NFS client: sudo apt update && sudo apt install nfs-common"
    exit 1
fi

# 2. Check current NFS mounts
echo ""
echo "2. Checking current NFS mounts..."
NFS_MOUNTS=$(mount | grep nfs 2>/dev/null || true)
if [ -n "$NFS_MOUNTS" ]; then
    print_status 0 "NFS mounts found:"
    echo "$NFS_MOUNTS" | while read -r line 2>/dev/null || true; do
        echo "   $line"
    done
else
    print_status 1 "No NFS mounts found"
fi

# 3. Check if mount point exists
echo ""
echo "3. Checking mount point..."
if [ -d "$MOUNT_POINT" ]; then
    print_status 0 "Mount point $MOUNT_POINT exists"
else
    print_status 1 "Mount point $MOUNT_POINT does NOT exist"
    echo "   Create mount point: sudo mkdir -p $MOUNT_POINT"
fi

# 4. Check NFS server connectivity
echo ""
echo "4. Checking NFS server connectivity..."
if timeout 5 bash -c "echo > /dev/tcp/$NFS_SERVER/2049" 2>/dev/null; then
    print_status 0 "NFS server $NFS_SERVER is reachable on port 2049"
else
    print_status 1 "NFS server $NFS_SERVER is NOT reachable on port 2049"
    echo "   Check if NFS server is running on $NFS_SERVER"
fi

# 5. Check NFS share availability
echo ""
echo "5. Checking NFS share availability..."
if showmount -e "$NFS_SERVER" &>/dev/null; then
    print_status 0 "NFS server $NFS_SERVER is responding to showmount"
    echo "   Available shares:"
    showmount -e "$NFS_SERVER" | tail -n +2 | while read line; do
        echo "   $line"
    done
else
    print_status 1 "NFS server $NFS_SERVER is NOT responding to showmount"
    echo "   Check NFS server configuration"
fi

# 6. Check if specific share is exported
echo ""
echo "6. Checking if share $NFS_SHARE is exported..."
EXPORTED_SHARES=$(showmount -e "$NFS_SERVER" 2>/dev/null | awk '{print $1}')
if echo "$EXPORTED_SHARES" | grep -q "^$NFS_SHARE$"; then
    print_status 0 "Share $NFS_SHARE is exported by $NFS_SERVER"
else
    print_status 1 "Share $NFS_SHARE is NOT exported by $NFS_SERVER"
    echo "   Available shares: $EXPORTED_SHARES"
fi

# 7. Test NFS mount
echo ""
echo "7. Testing NFS mount..."
if sudo mount -t nfs "$NFS_SERVER:$NFS_SHARE" "$MOUNT_POINT" 2>/dev/null; then
    print_status 0 "Successfully mounted $NFS_SERVER:$NFS_SHARE to $MOUNT_POINT"

    # Check if mount is accessible
    if ls "$MOUNT_POINT" &>/dev/null; then
        print_status 0 "Mount point $MOUNT_POINT is accessible"
        echo "   Contents preview:"
        ls -la "$MOUNT_POINT" | head -5
    else
        print_status 1 "Mount point $MOUNT_POINT is NOT accessible"
    fi

    # Unmount test mount
    if sudo umount "$MOUNT_POINT" 2>/dev/null; then
        print_status 0 "Successfully unmounted test mount"
    else
        print_status 1 "Failed to unmount test mount"
    fi
else
    print_status 1 "Failed to mount $NFS_SERVER:$NFS_SHARE to $MOUNT_POINT"
    echo "   Check NFS server exports and client permissions"
fi

# 8. Check /etc/fstab for persistent mount
echo ""
echo "8. Checking /etc/fstab for persistent mount..."
if grep -q "$NFS_SERVER:$NFS_SHARE" /etc/fstab; then
    print_status 0 "Persistent mount found in /etc/fstab"
    grep "$NFS_SERVER:$NFS_SHARE" /etc/fstab
else
    print_status 1 "No persistent mount found in /etc/fstab"
    echo "   To add persistent mount, add this line to /etc/fstab:"
    echo "   $NFS_SERVER:$NFS_SHARE $MOUNT_POINT nfs defaults 0 0"
fi

# 9. Check mount on boot
echo ""
echo "9. Checking if mount is configured for boot..."
if systemctl is-enabled nfs-client.target &>/dev/null; then
    print_status 0 "NFS client target is enabled"
else
    print_status 1 "NFS client target is NOT enabled"
    echo "   Enable with: sudo systemctl enable nfs-client.target"
fi

echo ""
echo "=========================================="
echo "🏁 NFS Client Validation Complete"
echo "=========================================="

# Summary
echo ""
echo "Summary for Krithi NFS Client:"
echo "- NFS Server: $NFS_SERVER"
echo "- NFS Share: $NFS_SHARE"
echo "- Mount Point: $MOUNT_POINT"
echo ""
echo "If any checks failed, please address the issues above."
echo "For Kubernetes persistent volumes, ensure NFS is working properly."