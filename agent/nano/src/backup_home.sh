#!/bin/bash
# Backup /home/sanjay/containers to /mnt/vmstore/nano_home, excluding cache and temp directories
# Automatically re-executes with sudo if not run as root

if [ "$EUID" -ne 0 ]; then
    exec sudo "$0" "$@"
fi

SRC="/home/sanjay/containers"
DEST="/mnt/vmstore/nano_home/containers"

# Add .git to the exclusion list
EXCLUDES="--exclude=.git --exclude=.cache --exclude=Cache --exclude=__pycache__ --exclude=.mozilla --exclude=.config/google-chrome --exclude=.config/chromium --exclude=.thumbnails --exclude=.local/share/Trash"

# Perform the backup with --delete to remove files from the destination that are not in the source.
# Suppress permission errors during transfer
rsync -avh --delete $EXCLUDES "$SRC/" "$DEST/" 2>/dev/null

# Change ownership of backup to invoking user (skip if permission denied)
if [ -n "$SUDO_USER" ]; then
    chown -R "$SUDO_USER:$SUDO_USER" "$DEST" 2>/dev/null || echo "Warning: Could not change ownership of some files (permission denied)"
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
