#!/bin/bash
set -e

echo "########################################"
echo "## NETWORK CONFIGURATION ROLLBACK     ##"
echo "## Restore from automatic backups     ##"
echo "########################################"

# Function to list available backups
list_backups() {
    echo "Available backup directories:"
    echo ""
    
    # SSH backups
    if ls ~/.ssh/backup_* 1> /dev/null 2>&1; then
        echo "🔑 SSH Configuration Backups:"
        ls -d ~/.ssh/backup_* | while read dir; do
            echo "   $(basename $dir) - $(stat -c %y "$dir" | cut -d. -f1)"
        done
        echo ""
    fi
    
    # Network backups
    if ls /tmp/*netplan*backup* 1> /dev/null 2>&1; then
        echo "🌐 Network Configuration Backups:"
        ls -d /tmp/*netplan*backup* | while read dir; do
            echo "   $(basename $dir) - $(stat -c %y "$dir" | cut -d. -f1)"
        done
        echo ""
    fi
    
    # Firewall backups
    if ls /tmp/*iptables*backup* 1> /dev/null 2>&1; then
        echo "🛡️ Firewall Configuration Backups:"
        ls -d /tmp/*iptables*backup* | while read dir; do
            echo "   $(basename $dir) - $(stat -c %y "$dir" | cut -d. -f1)"
        done
        echo ""
    fi
    
    # Routing backups
    if ls /tmp/*routing*backup* 1> /dev/null 2>&1; then
        echo "🔄 Routing Configuration Backups:"
        ls -d /tmp/*routing*backup* | while read dir; do
            echo "   $(basename $dir) - $(stat -c %y "$dir" | cut -d. -f1)"
        done
        echo ""
    fi
}

# Function to restore SSH configuration
restore_ssh() {
    local backup_dir="$1"
    echo "Restoring SSH configuration from: $backup_dir"
    
    if [ -f "$backup_dir/config.backup" ]; then
        cp "$backup_dir/config.backup" ~/.ssh/config
        chmod 600 ~/.ssh/config
        echo "   ✅ SSH config restored"
    fi
    
    if [ -f "$backup_dir/id_ed25519" ]; then
        cp "$backup_dir/id_ed25519"* ~/.ssh/
        chmod 600 ~/.ssh/id_ed25519
        chmod 644 ~/.ssh/id_ed25519.pub 2>/dev/null || true
        echo "   ✅ SSH keys restored"
    fi
}

# Function to restore network configuration
restore_network() {
    local backup_dir="$1"
    echo "Restoring network configuration from: $backup_dir"
    
    if ls "$backup_dir"/*.yaml 1> /dev/null 2>&1; then
        sudo cp "$backup_dir"/*.yaml /etc/netplan/
        sudo netplan apply
        echo "   ✅ Netplan configuration restored"
    else
        echo "   ⚠️  No netplan files found in backup"
    fi
}

# Function to restore firewall configuration
restore_firewall() {
    local backup_dir="$1"
    echo "Restoring firewall configuration from: $backup_dir"
    
    if [ -f "$backup_dir/iptables_rules.backup" ]; then
        sudo iptables-restore < "$backup_dir/iptables_rules.backup"
        echo "   ✅ Iptables rules restored"
        
        # Save the restored rules
        sudo mkdir -p /etc/iptables
        sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null
        echo "   ✅ Restored rules saved for persistence"
    else
        echo "   ⚠️  No iptables backup found"
    fi
    
    if [ -f "$backup_dir/sysctl.conf.backup" ]; then
        sudo cp "$backup_dir/sysctl.conf.backup" /etc/sysctl.conf
        sudo sysctl -p
        echo "   ✅ Sysctl configuration restored"
    else
        echo "   ⚠️  No sysctl backup found"
    fi
}

# Main menu
echo "This script helps you restore configurations from automatic backups."
echo ""

if [ "$#" -eq 0 ]; then
    list_backups
    echo "Usage: $0 <backup_directory>"
    echo ""
    echo "Example:"
    echo "  $0 /tmp/netplan_backup_20251001_173045"
    echo "  $0 ~/.ssh/backup_20251001_173045"
    echo ""
    exit 0
fi

BACKUP_DIR="$1"

if [ ! -d "$BACKUP_DIR" ]; then
    echo "❌ ERROR: Backup directory not found: $BACKUP_DIR"
    echo ""
    list_backups
    exit 1
fi

echo "Restoring from backup directory: $BACKUP_DIR"
echo ""

# Detect backup type and restore accordingly
if [[ "$BACKUP_DIR" == *"ssh"* ]]; then
    restore_ssh "$BACKUP_DIR"
elif [[ "$BACKUP_DIR" == *"iptables"* ]]; then
    restore_firewall "$BACKUP_DIR"
elif [[ "$BACKUP_DIR" == *"netplan"* || "$BACKUP_DIR" == *"routing"* ]]; then
    restore_network "$BACKUP_DIR"
else
    echo "Auto-detecting backup contents..."
    
    # Try to restore based on what's in the directory
    if [ -f "$BACKUP_DIR/config.backup" ] || [ -f "$BACKUP_DIR/id_ed25519" ]; then
        restore_ssh "$BACKUP_DIR"
    fi
    
    if [ -f "$BACKUP_DIR/iptables_rules.backup" ]; then
        restore_firewall "$BACKUP_DIR"
    fi
    
    if ls "$BACKUP_DIR"/*.yaml 1> /dev/null 2>&1; then
        restore_network "$BACKUP_DIR"
    fi
fi

echo ""
echo "🎯 RESTORATION COMPLETE!"
echo ""
echo "📋 Next steps:"
echo "   • Test network connectivity"
echo "   • Verify services are working"
echo "   • Check 'ip addr show' and 'ip route show'"
echo ""
echo "💡 TIP: Keep backup directories until you're sure everything works!"
echo "=========================================="