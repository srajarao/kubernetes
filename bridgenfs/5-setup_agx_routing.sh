#!/bin/bash
set -e

# --- Configuration Variables ---
AGX_IFACE=$(ip link show | grep -E '^[0-9]+: en' | head -1 | cut -d: -f2 | tr -d ' ') # Auto-detect primary ethernet interface
AGX_IP="192.168.10.11"
TOWER_IP="192.168.10.1"
NETMASK="/24"
BACKUP_DIR="/tmp/agx_routing_backup_$(date +%Y%m%d_%H%M%S)"

echo "########################################"
echo "## AGX ROUTING UPDATE                  ##"
echo "## Add route to Nano network via Tower##"
echo "########################################"

# Create backup directory
mkdir -p "$BACKUP_DIR"

echo "0. Creating backup of current routing configuration..."
# Backup existing netplan files
if ls /etc/netplan/*.yaml 1> /dev/null 2>&1; then
    sudo cp /etc/netplan/*.yaml "$BACKUP_DIR/"
    echo "   ✅ Netplan files backed up to: $BACKUP_DIR"
fi

# Backup current routing state
ip route show > "$BACKUP_DIR/routes_before.txt"
echo "   ✅ Current routing state backed up"

NETPLAN_FILE="/etc/netplan/99-agx-static.yaml"

# Check if AGX netplan config exists
if [ ! -f "$NETPLAN_FILE" ]; then
    echo "❌ ERROR: AGX netplan config not found at $NETPLAN_FILE"
    echo "   Please run setup_agx_network.sh first"
    echo "💾 Backup location: $BACKUP_DIR"
    exit 1
fi

echo "1. Updating AGX Netplan configuration with routing to Nano network..."
cat << EOF | sudo tee $NETPLAN_FILE > /dev/null
network:
  version: 2
  ethernets:
    $AGX_IFACE:
      dhcp4: false
      addresses: [$AGX_IP$NETMASK]
      routes:
        - to: 192.168.5.0/24
          via: $TOWER_IP
EOF

# Secure the file
sudo chmod 600 $NETPLAN_FILE

# Apply the configuration
echo "2. Applying updated Netplan configuration..."
sudo netplan apply

echo "3. Testing connectivity to Nano network..."
if ping -c 3 192.168.5.21 > /dev/null 2>&1; then
    echo "   ✅ AGX → Nano communication successful!"
else
    echo "   ⚠️  AGX → Nano communication failed. Check Tower routing configuration."
fi

echo ""
echo "✅ AGX routing configured successfully!"
echo "The AGX can now communicate with Nano via Tower routing."
echo ""
echo "💾 BACKUP INFORMATION:"
echo "   Backup location: $BACKUP_DIR"
echo "   To restore if needed:"
echo "   sudo cp $BACKUP_DIR/*.yaml /etc/netplan/"
echo "   sudo netplan apply"