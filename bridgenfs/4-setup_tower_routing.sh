#!/bin/bash
set -e

echo "########################################"
echo "## TOWER INTERNET SHARING SETUP       ##"
echo "## WITH AUTOMATIC DEVICE CONFIG       ##"
echo "########################################"

# Configuration
NANO_HOST="nano"  # Using SSH config alias
AGX_HOST="agx"    # Using SSH config alias
NANO_IP="192.168.5.21"
AGX_IP="192.168.10.11"
BACKUP_DIR="/tmp/iptables_backup_$(date +%Y%m%d_%H%M%S)"

# Create backup directory
mkdir -p "$BACKUP_DIR"

echo "0. Creating backup of current firewall configuration..."
# Backup current iptables rules
sudo iptables-save > "$BACKUP_DIR/iptables_rules.backup"
echo "   ✅ Current iptables rules backed up to: $BACKUP_DIR/iptables_rules.backup"

# Backup sysctl configuration
cp /etc/sysctl.conf "$BACKUP_DIR/sysctl.conf.backup"
echo "   ✅ Current sysctl config backed up"

# Get the current internet interface (usually WiFi)
INTERNET_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
echo "Detected internet interface: $INTERNET_IFACE"

if [ -z "$INTERNET_IFACE" ]; then
    echo "❌ ERROR: Could not detect internet interface. Please check your internet connection."
    echo "💾 Backup location: $BACKUP_DIR"
    exit 1
fi

# Function to test SSH connectivity
test_ssh() {
    local host=$1
    local ip=$2
    echo -n "   Testing SSH to $host ($ip)... "
    if ssh -o ConnectTimeout=5 -o BatchMode=yes "$host" "echo 'SSH OK'" >/dev/null 2>&1; then
        echo "✅ Passwordless SSH working"
        return 0
    else
        echo "⚠️  SSH failed, will use IP with password prompts"
        return 1
    fi
}

# Enable IP forwarding permanently
echo "1. Enabling IP forwarding..."
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
    echo "   Added to /etc/sysctl.conf"
else
    echo "   Already enabled in /etc/sysctl.conf"
fi
sudo sysctl -p

# Add NAT rule for 192.168.5.x network (Nano)
echo "2. Configuring NAT for Nano internet access..."
if ! sudo iptables -t nat -C POSTROUTING -s 192.168.5.0/24 -o $INTERNET_IFACE -j MASQUERADE 2>/dev/null; then
    sudo iptables -t nat -A POSTROUTING -s 192.168.5.0/24 -o $INTERNET_IFACE -j MASQUERADE
    echo "   NAT rule added for 192.168.5.0/24 → $INTERNET_IFACE"
else
    echo "   NAT rule already exists"
fi

# Add forwarding rules
echo "3. Configuring forwarding rules..."
if ! sudo iptables -C FORWARD -s 192.168.5.0/24 -j ACCEPT 2>/dev/null; then
    sudo iptables -I FORWARD 1 -s 192.168.5.0/24 -j ACCEPT
    echo "   Forward rule added for outgoing traffic from 192.168.5.0/24"
else
    echo "   Outgoing forward rule already exists"
fi

if ! sudo iptables -C FORWARD -d 192.168.5.0/24 -j ACCEPT 2>/dev/null; then
    sudo iptables -I FORWARD 2 -d 192.168.5.0/24 -j ACCEPT
    echo "   Forward rule added for incoming traffic to 192.168.5.0/24"
else
    echo "   Incoming forward rule already exists"
fi

# Optional: Add NAT for 10G network too (AGX) if needed
echo "4. Configuring NAT for AGX internet access (optional)..."
if ! sudo iptables -t nat -C POSTROUTING -s 192.168.10.0/24 -o $INTERNET_IFACE -j MASQUERADE 2>/dev/null; then
    sudo iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o $INTERNET_IFACE -j MASQUERADE
    echo "   NAT rule added for 192.168.10.0/24 → $INTERNET_IFACE"
else
    echo "   NAT rule already exists for AGX network"
fi

if ! sudo iptables -C FORWARD -s 192.168.10.0/24 -j ACCEPT 2>/dev/null; then
    sudo iptables -I FORWARD 1 -s 192.168.10.0/24 -j ACCEPT
    echo "   Forward rule added for outgoing traffic from 192.168.10.0/24"
else
    echo "   Outgoing forward rule already exists for AGX network"
fi

if ! sudo iptables -C FORWARD -d 192.168.10.0/24 -j ACCEPT 2>/dev/null; then
    sudo iptables -I FORWARD 2 -d 192.168.10.0/24 -j ACCEPT
    echo "   Forward rule added for incoming traffic to 192.168.10.0/24"
else
    echo "   Incoming forward rule already exists for AGX network"
fi

# Add inter-network routing (Nano ↔ AGX)
echo "5. Configuring inter-network routing..."
if ! sudo iptables -C FORWARD -s 192.168.5.0/24 -d 192.168.10.0/24 -j ACCEPT 2>/dev/null; then
    sudo iptables -A FORWARD -s 192.168.5.0/24 -d 192.168.10.0/24 -j ACCEPT
    echo "   Forward rule added: Nano → AGX"
else
    echo "   Forward rule already exists: Nano → AGX"
fi

if ! sudo iptables -C FORWARD -s 192.168.10.0/24 -d 192.168.5.0/24 -j ACCEPT 2>/dev/null; then
    sudo iptables -A FORWARD -s 192.168.10.0/24 -d 192.168.5.0/24 -j ACCEPT
    echo "   Forward rule added: AGX → Nano"
else
    echo "   Forward rule already exists: AGX → Nano"
fi

# Make rules persistent
echo "6. Making firewall rules persistent..."
sudo mkdir -p /etc/iptables
sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null
echo "   ✅ Updated rules saved to /etc/iptables/rules.v4"

# Install iptables-persistent if not already installed
if ! dpkg -l | grep -q iptables-persistent; then
    echo "   Installing iptables-persistent..."
    sudo apt update && sudo apt install -y iptables-persistent
else
    echo "   iptables-persistent already installed"
fi

echo ""
echo "💾 BACKUP INFORMATION:"
echo "   Backup location: $BACKUP_DIR"
echo "   To restore if needed:"
echo "   sudo iptables-restore < $BACKUP_DIR/iptables_rules.backup"
echo "   sudo cp $BACKUP_DIR/sysctl.conf.backup /etc/sysctl.conf"

# Test connectivity to devices and verify internet access
echo ""
echo "7. Testing device connectivity and internet access..."

# Test Nano
echo ""
echo "Testing Nano connectivity..."
test_ssh "$NANO_HOST" "$NANO_IP"
NANO_SSH_OK=$?

if [ $NANO_SSH_OK -eq 0 ]; then
    NANO_TARGET="$NANO_HOST"
else
    NANO_TARGET="$NANO_IP"
fi

echo "   Testing Nano internet access..."
if ssh "$NANO_TARGET" "ping -c 2 8.8.8.8 > /dev/null 2>&1"; then
    echo "   ✅ Nano has internet access!"
else
    echo "   ⚠️  Nano internet access test failed"
fi

# Test AGX
echo ""
echo "Testing AGX connectivity..."
test_ssh "$AGX_HOST" "$AGX_IP"
AGX_SSH_OK=$?

if [ $AGX_SSH_OK -eq 0 ]; then
    AGX_TARGET="$AGX_HOST"
else
    AGX_TARGET="$AGX_IP"
fi

echo "   Testing AGX internet access..."
if ssh "$AGX_TARGET" "ping -c 2 8.8.8.8 > /dev/null 2>&1"; then
    echo "   ✅ AGX has internet access!"
else
    echo "   ⚠️  AGX internet access test failed"
fi

# Test inter-device communication
echo ""
echo "Testing inter-device communication..."
echo "   Testing Nano → AGX..."
if ssh "$NANO_TARGET" "ping -c 2 $AGX_IP > /dev/null 2>&1"; then
    echo "   ✅ Nano can reach AGX!"
else
    echo "   ⚠️  Nano → AGX communication failed"
fi

echo "   Testing AGX → Nano..."
if ssh "$AGX_TARGET" "ping -c 2 $NANO_IP > /dev/null 2>&1"; then
    echo "   ✅ AGX can reach Nano!"
else
    echo "   ⚠️  AGX → Nano communication failed"
fi

echo ""
echo "✅ Tower internet sharing and routing configured successfully!"
echo ""
echo "📋 SUMMARY:"
echo "   • IP forwarding: Enabled"
echo "   • NAT for Nano (192.168.5.x): Enabled via $INTERNET_IFACE"
echo "   • NAT for AGX (192.168.10.x): Enabled via $INTERNET_IFACE"
echo "   • Inter-device routing: Enabled (Nano ↔ AGX)"
echo "   • Rules persistence: Configured"
if [ $NANO_SSH_OK -eq 0 ] && [ $AGX_SSH_OK -eq 0 ]; then
    echo "   • Passwordless SSH: Working to both devices"
else
    echo "   • SSH: Some connections require passwords"
fi
echo ""
echo "🔗 The Tower now provides:"
echo "   • Internet access for both Nano and AGX"
echo "   • Inter-device communication between Nano and AGX"
echo "   • Dedicated high-speed links maintained"