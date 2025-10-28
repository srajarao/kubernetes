#!/bin/bash
set -e

# Script to update NFS exports on Tower with correct client IPs
# Run this on Tower after IP address changes

echo "🔧 Updating NFS exports on Tower..."

# Backup current exports
EXPORTS_BACKUP="/etc/exports.backup.$(date +%Y%m%d_%H%M%S)"
sudo cp /etc/exports "$EXPORTS_BACKUP"
echo "   📋 Backed up current exports to: $EXPORTS_BACKUP"

# Update exports with all current IPs
sudo tee /etc/exports > /dev/null << 'EXPORTS_EOF'
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/export/vmstore 192.168.1.150(rw,sync,no_subtree_check,no_root_squash) 192.168.1.244(rw,sync,no_subtree_check,no_root_squash) 192.168.1.181(rw,sync,no_subtree_check,no_root_squash) 192.168.1.201(rw,sync,no_subtree_check,no_root_squash) 192.168.1.202(rw,sync,no_subtree_check,no_root_squash)
EXPORTS_EOF

# Reload exports
sudo exportfs -ra

echo "   ✅ NFS exports updated!"
echo "   📋 Current exports:"
sudo exportfs -v

# Restart NFS server
sudo systemctl restart nfs-kernel-server

echo ""
echo "📋 NFS EXPORTS UPDATE COMPLETE"
echo "   All nodes can now access NFS shares"
echo "   To restore old exports: sudo cp $EXPORTS_BACKUP /etc/exports && sudo exportfs -ra"
