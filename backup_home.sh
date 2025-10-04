#!/bin/bash
# Backup /home/sanjay to /mnt/vmstore/tower_home, excluding cache and temp directories
# Run as regular user since 'sanjay' is consistent across all machines

SRC="/home/sanjay/containers"
DEST="/mnt/vmstore/tower_home"

# Clean up VS Code cache and config before backup
echo "Cleaning up VS Code configuration and cache..."
rm -rf "$SRC/.config/Code"

# Exclusion list - exclude all dot directories except .token, .devcontainer, and .config
EXCLUDES="--include=.token --include=.token/** --include=.devcontainer --include=.devcontainer/** --include=.config --include=.config/** --exclude=snap --exclude=*.tar --exclude=.* --exclude=Cache --exclude=__pycache__ --exclude=.local/share/Trash --exclude=.rancher --exclude=jps --exclude=.local/share/flatpak --exclude=.var"

# Perform the backup with --delete to remove files from the destination that are not in the source.
# Using --no-inc-recursive to avoid temporary file creation issues on NFS
rsync -avh --no-inc-recursive --delete $EXCLUDES "$SRC/" "$DEST/"

# Note: chown operation removed - NFS preserves ownership from source
# and user 'sanjay' is consistent across all machines

# Verify the backup using rsync's --dry-run
echo "Verifying backup for differences..."
rsync -avn --delete $EXCLUDES "$SRC/" "$DEST/" | grep -E '^<|>|^deleting' &> /tmp/backup_home.log

if [ ! -s /tmp/backup_home.log ]; then
    echo "No differences found between source and backup."
else
    echo "Differences found between source and backup:"
    cat /tmp/backup_home.log
fi
