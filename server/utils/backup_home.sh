#!/bin/bash
# Backup /home/sanjay/containers to the appropriate vmstore location based on hostname, excluding cache and temp directories
# Runs rsync as the calling user to avoid NFS root squashing issues

if [ "$EUID" -eq 0 ]; then
    echo "This script should not be run as root. Please run as your regular user."
    exit 1
fi

SRC="/home/sanjay/containers"

# Determine destination based on hostname
HOSTNAME=$(hostname)
case "$HOSTNAME" in
    tower)
        BASE_PATH="/export/vmstore"
        ;;
    *)
        BASE_PATH="/mnt/vmstore"
        ;;
esac

case "$HOSTNAME" in
    tower)
        DEST="$BASE_PATH/tower_home/containers"
        ;;
    nano)
        DEST="$BASE_PATH/nano_home/containers"
        ;;
    agx)
        DEST="$BASE_PATH/agx_home/containers"
        ;;
    spark1)
        DEST="$BASE_PATH/spark1_home/containers"
        ;;
    spark2)
        DEST="$BASE_PATH/spark2_home/containers"
        ;;
    krithi)
        DEST="$BASE_PATH/krithi_home/containers"
        ;;
    *)
        echo "Unknown hostname: $HOSTNAME. Defaulting to tower_home."
        DEST="$BASE_PATH/tower_home/containers"
        ;;
esac


# Add .git to the exclusion list
EXCLUDES="--exclude=.git --exclude=.cache --exclude=Cache --exclude=__pycache__ --exclude=.mozilla --exclude=.config/google-chrome --exclude=.config/chromium --exclude=.thumbnails --exclude=.local/share/Trash --exclude=rag/reference/azure-ai-search-multimodal-sample/data/"

# Perform the backup with --delete to remove files from the destination that are not in the source.
# Use --ignore-errors to continue on permission issues, --no-owner and --no-group to skip chown operations
# Use --inplace to avoid creating temporary files that fail on NFS root squashing
rsync -avh --delete --ignore-errors --no-owner --no-group --inplace $EXCLUDES "$SRC/" "$DEST/"

# Note: chown is skipped on NFS mounts due to root squashing security feature
# Files will retain their original ownership from the source
echo "Note: File ownership not changed due to NFS root squashing security policy"

# Verify the backup using rsync's --dry-run
# Use --ignore-errors to handle permission issues gracefully, --no-owner and --no-group to skip chown operations
# Use --inplace for consistency with the backup command
echo "Verifying backup for differences..."
rsync -avn --delete --ignore-errors --no-owner --no-group --inplace $EXCLUDES "$SRC/" "$DEST/" 2>/dev/null | grep -E '^<|>|^deleting' &> /tmp/backup_home.log

if [ ! -s /tmp/backup_home.log ]; then
    echo "No differences found between source and backup."
else
    echo "Differences found between source and backup (some may be due to permission restrictions):"
    cat /tmp/backup_home.log
fi
