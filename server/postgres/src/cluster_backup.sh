#!/bin/bash
# Unified backup script for k3s cluster machines
# Automatically detects machine type (server, nano agent, agx agent) and backs up appropriate content
# Run this on any machine in the cluster to backup its home directory and configurations

set -e

# Detect machine type
HOSTNAME=$(hostname)
if [[ "$HOSTNAME" == *"tower"* ]] || [[ "$HOSTNAME" == *"server"* ]]; then
    MACHINE_TYPE="server"
    BACKUP_SUFFIX="tower"
elif [[ "$HOSTNAME" == *"nano"* ]]; then
    MACHINE_TYPE="nano"
    BACKUP_SUFFIX="nano"
elif [[ "$HOSTNAME" == *"agx"* ]]; then
    MACHINE_TYPE="agx"
    BACKUP_SUFFIX="agx"
else
    echo "❌ Cannot determine machine type from hostname: $HOSTNAME"
    echo "Expected hostnames to contain: tower/server, nano, or agx"
    exit 1
fi

BACKUP_ROOT="/mnt/vmstore"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="$BACKUP_ROOT/${BACKUP_SUFFIX}_backup_$TIMESTAMP"

echo "=== Unified Cluster Backup ==="
echo "Machine Type: $MACHINE_TYPE"
echo "Hostname: $HOSTNAME"
echo "Backup Directory: $BACKUP_DIR"
echo "Timestamp: $TIMESTAMP"
echo

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Function to backup with proper error handling
backup_with_rsync() {
    local src="$1"
    local dest="$2"
    local name="$3"

    echo "Backing up $name..."
    echo "  Source: $src"
    echo "  Destination: $dest"

    if [ -d "$src" ]; then
        rsync -avh --delete \
            --exclude='.git' \
            --exclude='.cache' \
            --exclude='Cache' \
            --exclude='__pycache__' \
            --exclude='.mozilla' \
            --exclude='.config/google-chrome' \
            --exclude='.config/chromium' \
            --exclude='.thumbnails' \
            --exclude='.local/share/Trash' \
            "$src/" "$dest/" 2>/dev/null && echo "  ✅ $name backup completed" || echo "  ⚠️  $name backup had issues (may be normal for NFS)"
    else
        echo "  ⚠️  Source directory $src does not exist"
    fi
    echo
}

# Backup the complete home directory (main objective)
echo "=== Backing up Home Directory ==="
backup_with_rsync "/home/sanjay" "$BACKUP_DIR/home" "Home directory"

# Backup machine-specific kubernetes configurations
echo "=== Backing up Kubernetes Configurations ==="
case $MACHINE_TYPE in
    "server")
        # Server: backup server-specific configs
        backup_with_rsync "/home/sanjay/containers/kubernetes/server" "$BACKUP_DIR/kubernetes/server" "Server kubernetes configs"
        backup_with_rsync "/home/sanjay/containers/kubernetes/agent" "$BACKUP_DIR/kubernetes/shared_agents" "Shared agent configs"
        ;;
    "nano")
        # Nano agent: backup nano-specific configs
        backup_with_rsync "/home/sanjay/containers/kubernetes/agent/nano" "$BACKUP_DIR/kubernetes/nano" "Nano agent configs"
        ;;
    "agx")
        # AGX agent: backup agx-specific configs
        backup_with_rsync "/home/sanjay/containers/kubernetes/agent/agx" "$BACKUP_DIR/kubernetes/agx" "AGX agent configs"
        ;;
esac

# Create backup manifest
echo "=== Creating Backup Manifest ==="
cat > "$BACKUP_DIR/backup_manifest.txt" << EOF
$MACHINE_TYPE Backup Manifest
===========================
Created: $TIMESTAMP
Machine Type: $MACHINE_TYPE
Hostname: $HOSTNAME
Backup Location: $BACKUP_DIR

Home Directory:
Files: $(find "$BACKUP_DIR/home" -type f 2>/dev/null | wc -l)
Directories: $(find "$BACKUP_DIR/home" -type d 2>/dev/null | wc -l)

Kubernetes Configurations:
$(find "$BACKUP_DIR/kubernetes" -type f 2>/dev/null | wc -l) config files backed up

Machine-specific Notes:
$(case $MACHINE_TYPE in
    "server") echo "- Server contains cluster control plane configs";;
    "nano") echo "- Nano agent contains Jetson Nano specific configs and GPU workloads";;
    "agx") echo "- AGX agent contains Jetson AGX specific configs and GPU workloads";;
esac)

User: sanjay (consistent across all machines)
NFS Note: chown operations may fail on NFS mounts - this is normal.
EOF

echo "✅ Backup manifest created: $BACKUP_DIR/backup_manifest.txt"

# List recent backups for cleanup reference
echo
echo "=== Recent Backups (consider cleanup) ==="
ls -la "$BACKUP_ROOT" | grep "${BACKUP_SUFFIX}_backup" | head -5

echo
echo "=== Backup Summary ==="
echo "✅ $MACHINE_TYPE backup completed to: $BACKUP_DIR"
echo "📋 Check backup_manifest.txt for details"
echo "🧹 Consider cleaning up old backups to save space"
echo "🔄 Run this script on other machines for complete cluster backup"