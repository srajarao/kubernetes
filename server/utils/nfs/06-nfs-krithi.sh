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
    # Use a safer approach to avoid pipeline issues with set -e
    while IFS= read -r line; do
        echo "   $line"
    done <<< "$NFS_MOUNTS"
else
    print_status 1 "No NFS mounts found"
fi

# 3. Check if expected mount point exists
echo ""
echo "3. Checking mount point..."
if [ -d "$MOUNT_POINT" ]; then
    print_status 0 "Mount point $MOUNT_POINT exists"
    ls -la "$MOUNT_POINT" | head -5  # Show some contents
else
    print_status 1 "Mount point $MOUNT_POINT does NOT exist"
    echo "   Create mount point: sudo mkdir -p $MOUNT_POINT"
fi

# 4. Check /etc/fstab for NFS entries
echo ""
echo "4. Checking /etc/fstab for NFS persistence..."
FSTAB_NFS=$(grep -E "^[^#]*nfs" /etc/fstab 2>/dev/null || true)
if [ -n "$FSTAB_NFS" ]; then
    print_status 0 "NFS entries found in /etc/fstab:"
    echo "$FSTAB_NFS" | while read line; do
        echo "     $line"
    done
else
    print_status 1 "No NFS entries found in /etc/fstab"
    echo "   Add to /etc/fstab: $NFS_SERVER:$NFS_SHARE $MOUNT_POINT nfs defaults 0 0"
fi

# 5. Check if mount is active
echo ""
echo "5. Checking if NFS share is mounted..."
if mount | grep -q "$MOUNT_POINT"; then
    print_status 0 "NFS share is mounted at $MOUNT_POINT"
else
    print_status 1 "NFS share is NOT mounted at $MOUNT_POINT"
    echo "   Mount manually: sudo mount $MOUNT_POINT"
    echo "   Or mount all: sudo mount -a"
fi

# 6. Test NFS connectivity
echo ""
echo "6. Testing NFS server connectivity..."
if showmount -e "$NFS_SERVER" &>/dev/null; then
    print_status 0 "NFS server $NFS_SERVER is reachable"
    echo "   Available exports:"
    showmount -e "$NFS_SERVER" | tail -n +2 | while read line; do
        echo "     $line"
    done
else
    print_status 1 "NFS server $NFS_SERVER is NOT reachable"
    echo "   Check network connectivity and NFS server status"
fi

# 7. Test mount functionality (if not mounted)
echo ""
echo "7. Testing mount functionality..."
if mount | grep -q "$MOUNT_POINT"; then
    echo "   Mount already active, testing access..."
    if ls "$MOUNT_POINT" &>/dev/null; then
        print_status 0 "Can access mounted NFS share"
    else
        print_status 1 "Cannot access mounted NFS share"
        echo "   Check permissions and NFS server configuration"
    fi
else
    echo "   Attempting test mount..."
    TEST_DIR="/tmp/nfs_test_$(date +%s)"
    mkdir -p "$TEST_DIR"
    if sudo mount -t nfs "$NFS_SERVER:$NFS_SHARE" "$TEST_DIR" 2>/dev/null; then
        print_status 0 "Test mount successful"
        if ls "$TEST_DIR" &>/dev/null; then
            print_status 0 "Can access test-mounted NFS share"
        else
            print_status 1 "Cannot access test-mounted NFS share"
        fi
        sudo umount "$TEST_DIR" 2>/dev/null
    else
        print_status 1 "Test mount failed"
        echo "   Check NFS server exports and network connectivity"
    fi
    rmdir "$TEST_DIR"
fi

# 8. Check mount persistence
echo ""
echo "8. Checking mount persistence..."
if grep -q "$MOUNT_POINT" /etc/fstab && systemctl is-enabled --quiet rpcbind 2>/dev/null; then
    print_status 0 "NFS mount appears to be configured for persistence"
else
    print_status 1 "NFS mount may not persist across reboots"
    echo "   Ensure /etc/fstab has the entry and rpcbind is enabled"
fi

echo ""
echo "=========================================="
echo "🎉 NFS Client Validation Complete!"
echo "=========================================="
echo "If all checks passed, NFS client is properly configured on Krithi."
echo "The share should be accessible at $MOUNT_POINT"
echo ""
echo "Manual mount commands:"
echo "  sudo mount $MOUNT_POINT"
echo "  sudo mount -a  # Mount all from fstab"
echo "=========================================="
