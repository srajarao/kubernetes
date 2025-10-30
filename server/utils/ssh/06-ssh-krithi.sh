#!/bin/bash
set -e

echo "########################################"
echo "## SSH Key Setup for Passwordless     ##"
echo "## Authentication (Krithi → Others)   ##"
echo "########################################"

# Configuration
TOWER_IP="192.168.1.150"
NANO_IP="192.168.1.181"
AGX_IP="192.168.1.244"
SPARK1_IP="192.168.1.201"
SPARK2_IP="192.168.1.202"
SSH_USER="sanjay"
KEY_TYPE="ed25519"
KEY_FILE="$HOME/.ssh/id_${KEY_TYPE}"
BACKUP_DIR="$HOME/.ssh/backup_$(date +%Y%m%d_%H%M%S)"

echo "Setting up passwordless SSH from Krithi to Tower, Nano, AGX, Spark1, and Spark2..."
echo "Target devices: Tower ($TOWER_IP), Nano ($NANO_IP), AGX ($AGX_IP), Spark1 ($SPARK1_IP), Spark2 ($SPARK2_IP)"
echo ""

# Backup existing SSH configuration
echo "0. Creating backup of SSH configuration..."
mkdir -p "$BACKUP_DIR"
if [ -f "$HOME/.ssh/config" ]; then
    cp "$HOME/.ssh/config" "$BACKUP_DIR/config.backup"
    echo "   ✅ SSH config backed up to: $BACKUP_DIR/config.backup"
fi
if [ -f "${KEY_FILE}" ]; then
    cp "${KEY_FILE}" "$BACKUP_DIR/"
    cp "${KEY_FILE}.pub" "$BACKUP_DIR/" 2>/dev/null || true
    echo "   ✅ Existing SSH keys backed up to: $BACKUP_DIR/"
fi

# Step 1: Generate SSH key if it doesn't exist
if [ ! -f "$KEY_FILE" ]; then
    echo "1. Generating SSH key pair ($KEY_TYPE)..."
    ssh-keygen -t $KEY_TYPE -f "$KEY_FILE" -N "" -C "${SSH_USER}@krithi-$(date +%Y%m%d)"
    echo "   ✅ SSH key generated: $KEY_FILE"
else
    echo "1. SSH key already exists: $KEY_FILE"
fi

# Step 2: Copy public key to Tower
echo ""
echo "2. Setting up passwordless access to Tower ($TOWER_IP)..."
echo "   Please enter the password for $SSH_USER@$TOWER_IP when prompted:"

if ssh-copy-id -o StrictHostKeyChecking=no -i "${KEY_FILE}.pub" "$SSH_USER@$TOWER_IP"; then
    echo "   ✅ SSH key copied to Tower successfully"
else
    echo "   ❌ Failed to copy SSH key to Tower"
    exit 1
fi

# Test passwordless SSH to Tower
echo -n "   Testing passwordless SSH to Tower... "
if ssh -o ConnectTimeout=5 -o BatchMode=yes "$SSH_USER@$TOWER_IP" "echo 'SSH to Tower: SUCCESS'" 2>/dev/null; then
    echo "✅ SUCCESS"
else
    echo "❌ FAILED"
    exit 1
fi

# Step 3: Copy public key to Nano
echo ""
echo "3. Setting up passwordless access to Nano ($NANO_IP)..."
echo "   Please enter the password for $SSH_USER@$NANO_IP when prompted:"

if ssh-copy-id -o StrictHostKeyChecking=no -i "${KEY_FILE}.pub" "$SSH_USER@$NANO_IP"; then
    echo "   ✅ SSH key copied to Nano successfully"
else
    echo "   ❌ Failed to copy SSH key to Nano"
    exit 1
fi

# Test passwordless SSH to Nano
echo -n "   Testing passwordless SSH to Nano... "
if ssh -o ConnectTimeout=5 -o BatchMode=yes "$SSH_USER@$NANO_IP" "echo 'SSH to Nano: SUCCESS'" 2>/dev/null; then
    echo "✅ SUCCESS"
else
    echo "❌ FAILED"
    exit 1
fi

# Step 4: Copy public key to AGX
echo ""
echo "4. Setting up passwordless access to AGX ($AGX_IP)..."
echo "   Please enter the password for $SSH_USER@$AGX_IP when prompted:"

if ssh-copy-id -o StrictHostKeyChecking=no -i "${KEY_FILE}.pub" "$SSH_USER@$AGX_IP"; then
    echo "   ✅ SSH key copied to AGX successfully"
else
    echo "   ❌ Failed to copy SSH key to AGX"
    exit 1
fi

# Test passwordless SSH to AGX
echo -n "   Testing passwordless SSH to AGX... "
if ssh -o ConnectTimeout=5 -o BatchMode=yes "$SSH_USER@$AGX_IP" "echo 'SSH to AGX: SUCCESS'" 2>/dev/null; then
    echo "✅ SUCCESS"
else
    echo "❌ FAILED"
    exit 1
fi

# Step 5: Copy public key to Spark1
echo ""
echo "5. Setting up passwordless access to Spark1 ($SPARK1_IP)..."
echo "   Please enter the password for $SSH_USER@$SPARK1_IP when prompted:"

if ssh-copy-id -o StrictHostKeyChecking=no -i "${KEY_FILE}.pub" "$SSH_USER@$SPARK1_IP"; then
    echo "   ✅ SSH key copied to Spark1 successfully"
else
    echo "   ❌ Failed to copy SSH key to Spark1"
    exit 1
fi

# Test passwordless SSH to Spark1
echo -n "   Testing passwordless SSH to Spark1... "
if ssh -o ConnectTimeout=5 -o BatchMode=yes "$SSH_USER@$SPARK1_IP" "echo 'SSH to Spark1: SUCCESS'" 2>/dev/null; then
    echo "✅ SUCCESS"
else
    echo "❌ FAILED"
    exit 1
fi

# Step 6: Copy public key to Spark2
echo ""
echo "6. Setting up passwordless access to Spark2 ($SPARK2_IP)..."
echo "   Please enter the password for $SSH_USER@$SPARK2_IP when prompted:"

if ssh-copy-id -o StrictHostKeyChecking=no -i "${KEY_FILE}.pub" "$SSH_USER@$SPARK2_IP"; then
    echo "   ✅ SSH key copied to Spark2 successfully"
else
    echo "   ❌ Failed to copy SSH key to Spark2"
    exit 1
fi

# Test passwordless SSH to Spark2
echo -n "   Testing passwordless SSH to Spark2... "
if ssh -o ConnectTimeout=5 -o BatchMode=yes "$SSH_USER@$SPARK2_IP" "echo 'SSH to Spark2: SUCCESS'" 2>/dev/null; then
    echo "✅ SUCCESS"
else
    echo "❌ FAILED"
    exit 1
fi

# Step 7: Update SSH config for easy access
echo ""
echo "7. Updating SSH config for easy access..."

# Backup existing config
if [ -f "$HOME/.ssh/config" ]; then
    cp "$HOME/.ssh/config" "$HOME/.ssh/config.backup.$(date +%Y%m%d_%H%M%S)"
fi

# Add host entries to SSH config
cat >> "$HOME/.ssh/config" << EOF

# Krithi SSH configuration - $(date)
Host tower-from-krithi
    HostName $TOWER_IP
    User $SSH_USER
    IdentityFile $KEY_FILE

Host nano-from-krithi
    HostName $NANO_IP
    User $SSH_USER
    IdentityFile $KEY_FILE

Host agx-from-krithi
    HostName $AGX_IP
    User $SSH_USER
    IdentityFile $KEY_FILE

Host spark1-from-krithi
    HostName $SPARK1_IP
    User $SSH_USER
    IdentityFile $KEY_FILE

Host spark2-from-krithi
    HostName $SPARK2_IP
    User $SSH_USER
    IdentityFile $KEY_FILE
EOF

echo "   ✅ SSH config updated"

# Step 8: Final verification
echo ""
echo "8. Final verification - Testing all connections..."

echo -n "   Testing 'ssh tower-from-krithi'... "
if ssh -o ConnectTimeout=5 -o BatchMode=yes tower-from-krithi "hostname" 2>/dev/null; then
    echo "✅ SUCCESS"
else
    echo "❌ FAILED"
fi

echo -n "   Testing 'ssh nano-from-krithi'... "
if ssh -o ConnectTimeout=5 -o BatchMode=yes nano-from-krithi "hostname" 2>/dev/null; then
    echo "✅ SUCCESS"
else
    echo "❌ FAILED"
fi

echo -n "   Testing 'ssh agx-from-krithi'... "
if ssh -o ConnectTimeout=5 -o BatchMode=yes agx-from-krithi "hostname" 2>/dev/null; then
    echo "✅ SUCCESS"
else
    echo "❌ FAILED"
fi

echo -n "   Testing 'ssh spark1-from-krithi'... "
if ssh -o ConnectTimeout=5 -o BatchMode=yes spark1-from-krithi "hostname" 2>/dev/null; then
    echo "✅ SUCCESS"
else
    echo "❌ FAILED"
fi

echo -n "   Testing 'ssh spark2-from-krithi'... "
if ssh -o ConnectTimeout=5 -o BatchMode=yes spark2-from-krithi "hostname" 2>/dev/null; then
    echo "✅ SUCCESS"
else
    echo "❌ FAILED"
fi

echo ""
echo "########################################"
echo "## SSH Setup Complete!                 ##"
echo "########################################"
echo ""
echo "You can now SSH to other nodes from Krithi using:"
echo "  • ssh tower-from-krithi   # Connect to Tower"
echo "  • ssh nano-from-krithi    # Connect to Nano"
echo "  • ssh agx-from-krithi     # Connect to AGX"
echo "  • ssh spark1-from-krithi  # Connect to Spark1"
echo "  • ssh spark2-from-krithi  # Connect to Spark2"
echo ""
echo "Or use direct IPs:"
echo "  • ssh sanjay@192.168.1.150  # Tower"
echo "  • ssh sanjay@192.168.1.181  # Nano"
echo "  • ssh sanjay@192.168.1.244  # AGX"
echo "  • ssh sanjay@192.168.1.201  # Spark1"
echo "  • ssh sanjay@192.168.1.202  # Spark2"
echo ""
echo "SSH keys backed up to: $BACKUP_DIR"