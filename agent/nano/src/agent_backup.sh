#!/bin/bash
# Agent-specific backup script
# Run this on each agent (nano, agx) to backup local configurations
# This complements the server-side cluster backup

set -e

# Detect which agent we're on
if hostname | grep -q nano; then
    AGENT_TYPE="nano"
    BACKUP_SRC="/home/sanjay"
    AGENT_CONFIG_SRC="/home/sanjay/containers/kubernetes/agent/nano"
elif hostname | grep -q agx; then
    AGENT_TYPE="agx"
    BACKUP_SRC="/home/sanjay"
    AGENT_CONFIG_SRC="/home/sanjay/containers/kubernetes/agent/agx"
else
    echo "❌ Cannot determine agent type from hostname: $(hostname)"
    exit 1
fi

BACKUP_ROOT="/mnt/vmstore"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="$BACKUP_ROOT/${AGENT_TYPE}_backup_$TIMESTAMP"

echo "=== Agent-Specific Backup for $AGENT_TYPE ==="
echo "Agent: $AGENT_TYPE"
echo "Home Source: $BACKUP_SRC"
echo "Config Source: $AGENT_CONFIG_SRC"
echo "Destination: $BACKUP_DIR"
echo "Timestamp: $TIMESTAMP"
echo

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup full home directory
echo "Backing up $AGENT_TYPE home directory..."
if [ -d "$BACKUP_SRC" ]; then
    rsync -avh --delete \
        --exclude='.git' \
        --exclude='.cache' \
        --exclude='__pycache__' \
        "$BACKUP_SRC/" "$BACKUP_DIR/home/" 2>/dev/null && echo "✅ Home directory backup completed" || echo "⚠️  Home backup had issues (may be normal for NFS)"
else
    echo "❌ Source directory $BACKUP_SRC does not exist"
fi

# Backup agent-specific kubernetes configs
echo "Backing up $AGENT_TYPE kubernetes configurations..."
if [ -d "$AGENT_CONFIG_SRC" ]; then
    rsync -avh --delete \
        --exclude='.git' \
        --exclude='.cache' \
        --exclude='__pycache__' \
        "$AGENT_CONFIG_SRC/" "$BACKUP_DIR/kubernetes/" 2>/dev/null && echo "✅ Kubernetes configs backup completed" || echo "⚠️  Kubernetes backup had issues (may be normal for NFS)"
else
    echo "⚠️  Agent config directory $AGENT_CONFIG_SRC does not exist"
fi

# Create agent manifest
cat > "$BACKUP_DIR/agent_manifest.txt" << EOF
$AGENT_TYPE Agent Backup Manifest
===============================
Created: $TIMESTAMP
Agent Type: $AGENT_TYPE
Hostname: $(hostname)
Home Source: $BACKUP_SRC
Config Source: $AGENT_CONFIG_SRC
Destination: $BACKUP_DIR

Home Directory Files: $(find "$BACKUP_DIR/home" -type f 2>/dev/null | wc -l)
Home Directory Directories: $(find "$BACKUP_DIR/home" -type d 2>/dev/null | wc -l)
Kubernetes Config Files: $(find "$BACKUP_DIR/kubernetes" -type f 2>/dev/null | wc -l)
Kubernetes Config Directories: $(find "$BACKUP_DIR/kubernetes" -type d 2>/dev/null | wc -l)

Note: This backup contains the complete $AGENT_TYPE home directory
and kubernetes configurations that complement the server-side cluster backup.
EOF

echo "✅ Agent manifest created: $BACKUP_DIR/agent_manifest.txt"

echo
echo "=== Agent Backup Summary ==="
echo "✅ $AGENT_TYPE agent backup completed to: $BACKUP_DIR"
echo "📋 Check agent_manifest.txt for details"