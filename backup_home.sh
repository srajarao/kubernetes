#!/bin/bash
# Backup /home/sanjay/containers to the appropriate vmstore location based on hostname, excluding cache and temp directories
# Automatically re-executes with sudo if not run as root

if [ "$EUID" -ne 0 ]; then
    exec sudo "$0" "$@"
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
    *)
        echo "Unknown hostname: $HOSTNAME. Defaulting to tower_home."
        DEST="$BASE_PATH/tower_home/containers"
        ;;
esac


# Add .git to the exclusion list
EXCLUDES="--exclude=.git --exclude=.cache --exclude=Cache --exclude=__pycache__ --exclude=.mozilla --exclude=.config/google-chrome --exclude=.config/chromium --exclude=.thumbnails --exclude=.local/share/Trash"

# Perform the backup with --delete to remove files from the destination that are not in the source.
rsync -avh --delete $EXCLUDES "$SRC/" "$DEST/"

# Change ownership of backup to invoking user
if [ -n "$SUDO_USER" ]; then
    chown -R "$SUDO_USER:$SUDO_USER" "$DEST"
fi

# Verify the backup using rsync's --dry-run
echo "Verifying backup for differences..."
rsync -avn --delete $EXCLUDES "$SRC/" "$DEST/" | grep -E '^<|>|^deleting' &> /tmp/backup_home.log

if [ ! -s /tmp/backup_home.log ]; then
    echo "No differences found between source and backup."
else
    echo "Differences found between source and backup:"
    cat /tmp/backup_home.log
fi
