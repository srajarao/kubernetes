#!/bin/bash
set -e

# Script to update NFS mounts in /etc/fstab on all devices
# Run this from Tower to update AGX and Nano

echo "🔧 Updating NFS mounts in /etc/fstab on all devices..."
echo "   New Tower IP: 10.1.10.150"

# Copy the update script to each device and run it
DEVICES=("agx" "nano")

for device in "${DEVICES[@]}"; do
    echo ""
    echo "📡 Updating $device..."

    # Copy the script to the device
    if scp /home/sanjay/containers/kubernetes/update-nfs-fstab.sh sanjay@$device:~ > /dev/null 2>&1; then
        echo "   ✅ Copied update script to $device"

        # Run the script on the device
        if ssh -o StrictHostKeyChecking=no sanjay@$device "bash update-nfs-fstab.sh" > /dev/null 2>&1; then
            echo "   ✅ Updated NFS mount on $device"
        else
            echo "   ❌ Failed to update NFS mount on $device"
        fi
    else
        echo "   ❌ Failed to copy script to $device"
    fi
done

echo ""
echo "🏠 Updating Tower..."
# Run locally on Tower
if bash /home/sanjay/containers/kubernetes/update-nfs-fstab.sh > /dev/null 2>&1; then
    echo "   ✅ Updated NFS mount on Tower"
else
    echo "   ❌ Failed to update NFS mount on Tower"
fi

echo ""
echo "🎉 NFS fstab update complete on all devices!"
echo "   All devices now have persistent NFS mounts with correct Tower IP"