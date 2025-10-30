#!/bin/bash
set -e

echo "########################################"
echo "## SSH Key Setup for Passwordless     ##"
echo "## Authentication (Spark2 → Others)   ##"
echo "########################################"

# Configuration
TOWER_IP="192.168.1.150"
NANO_IP="192.168.1.181"
AGX_IP="192.168.1.244"
SPARK1_IP="192.168.1.201"
SSH_USER="sanjay"
KEY_TYPE="ed25519"
KEY_FILE="$HOME/.ssh/id_${KEY_TYPE}"
BACKUP_DIR="$HOME/.ssh/backup_$(date +%Y%m%d_%H%M%S)"

echo "Setting up passwordless SSH from Spark2 to Tower, Nano, AGX, and Spark1..."
echo "Target devices: Tower ($TOWER_IP), Nano ($NANO_IP), AGX ($AGX_IP), Spark1 ($SPARK1_IP)"
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
    ssh-keygen -t $KEY_TYPE -f "$KEY_FILE" -N "" -C "${SSH_USER}@spark2-$(date +%Y%m%d)"
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
    
    # Test the connection
    echo "   Testing passwordless connection to Tower..."
    if ssh -o ConnectTimeout=5 -o BatchMode=yes "$SSH_USER@$TOWER_IP" "echo 'Passwordless SSH to Tower: SUCCESS'" 2>/dev/null; then
        echo "   ✅ Passwordless SSH to Tower is working!"
    else
        echo "   ⚠️  Passwordless SSH test failed. You may need to enter password manually."
    fi
else
    echo "   ❌ Failed to copy SSH key to Tower"
fi

# Step 3: Copy public key to Nano
echo ""
echo "3. Setting up passwordless access to Nano ($NANO_IP)..."
echo "   Please enter the password for $SSH_USER@$NANO_IP when prompted:"

if ssh-copy-id -o StrictHostKeyChecking=no -i "${KEY_FILE}.pub" "$SSH_USER@$NANO_IP"; then
    echo "   ✅ SSH key copied to Nano successfully"
    
    # Test the connection
    echo "   Testing passwordless connection to Nano..."
    if ssh -o ConnectTimeout=5 -o BatchMode=yes "$SSH_USER@$NANO_IP" "echo 'Passwordless SSH to Nano: SUCCESS'" 2>/dev/null; then
        echo "   ✅ Passwordless SSH to Nano is working!"
    else
        echo "   ⚠️  Passwordless SSH test failed. You may need to enter password manually."
    fi
else
    echo "   ❌ Failed to copy SSH key to Nano"
fi

# Step 3b: Copy public key to AGX
echo ""
echo "3b. Setting up passwordless access to AGX ($AGX_IP)..."
echo "    Please enter the password for $SSH_USER@$AGX_IP when prompted:"

if ssh-copy-id -o StrictHostKeyChecking=no -i "${KEY_FILE}.pub" "$SSH_USER@$AGX_IP"; then
    echo "    ✅ SSH key copied to AGX successfully"
    
    # Test the connection
    echo "    Testing passwordless connection to AGX..."
    if ssh -o ConnectTimeout=5 -o BatchMode=yes "$SSH_USER@$AGX_IP" "echo 'Passwordless SSH to AGX: SUCCESS'" 2>/dev/null; then
        echo "    ✅ Passwordless SSH to AGX is working!"
    else
        echo "    ⚠️  Passwordless SSH test failed. You may need to enter password manually."
    fi
else
    echo "    ❌ Failed to copy SSH key to AGX"
fi

# Step 3c: Copy public key to Spark1
echo ""
echo "3c. Setting up passwordless access to Spark1 ($SPARK1_IP)..."
echo "    Please enter the password for $SSH_USER@$SPARK1_IP when prompted:"

if ssh-copy-id -o StrictHostKeyChecking=no -i "${KEY_FILE}.pub" "$SSH_USER@$SPARK1_IP"; then
    echo "    ✅ SSH key copied to Spark1 successfully"
    
    # Test the connection
    echo "    Testing passwordless connection to Spark1..."
    if ssh -o ConnectTimeout=5 -o BatchMode=yes "$SSH_USER@$SPARK1_IP" "echo 'Passwordless SSH to Spark1: SUCCESS'" 2>/dev/null; then
        echo "    ✅ Passwordless SSH to Spark1 is working!"
    else
        echo "    ⚠️  Passwordless SSH test failed. You may need to enter password manually."
    fi
else
    echo "    ❌ Failed to copy SSH key to Spark1"
fi

# Step 4: Create SSH config for easier access
echo ""
echo "4. Creating SSH config file for easier access..."
SSH_CONFIG="$HOME/.ssh/config"

# Remove any existing entries for our hosts to avoid duplicates
if [ -f "$SSH_CONFIG" ]; then
    # Create a temp file without our host entries
    awk '
    /^Host (tower-from-spark2|nano-from-spark2|agx-from-spark2|spark1-from-spark2)$/ { skip = 1; next }
    skip && /^Host / { skip = 0 }
    !skip { print }
    ' "$SSH_CONFIG" > "${SSH_CONFIG}.tmp"
    mv "${SSH_CONFIG}.tmp" "$SSH_CONFIG"
    echo "   Cleaned existing tower-from-spark2/nano-from-spark2/agx-from-spark2/spark1-from-spark2 entries from SSH config"
fi

# Add or update entries
cat >> "$SSH_CONFIG" << EOF

# Jetson Network Configuration - Added $(date)
Host tower-from-spark2
    HostName $TOWER_IP
    User $SSH_USER
    IdentitiesOnly yes
    IdentityFile $KEY_FILE

Host nano-from-spark2
    HostName $NANO_IP
    User $SSH_USER
    IdentitiesOnly yes
    IdentityFile $KEY_FILE

Host agx-from-spark2
    HostName $AGX_IP
    User $SSH_USER
    IdentitiesOnly yes
    IdentityFile $KEY_FILE

Host spark1-from-spark2
    HostName $SPARK1_IP
    User $SSH_USER
    IdentitiesOnly yes
    IdentityFile $KEY_FILE
EOF

chmod 600 "$SSH_CONFIG"
echo "   ✅ SSH config updated. You can now use:"
echo "      ssh tower-from-spark2     # Connect to Tower"
echo "      ssh nano-from-spark2      # Connect to Nano"
echo "      ssh agx-from-spark2       # Connect to AGX"
echo "      ssh spark1-from-spark2    # Connect to Spark1"

# Step 5: Final verification
echo ""
echo "5. Final verification of passwordless SSH..."

echo -n "   Testing 'ssh tower-from-spark2'... "
if ssh -o ConnectTimeout=5 -o BatchMode=yes tower-from-spark2 "hostname" 2>/dev/null; then
    echo "✅ SUCCESS"
else
    echo "❌ FAILED"
fi

echo -n "   Testing 'ssh nano-from-spark2'... "
if ssh -o ConnectTimeout=5 -o BatchMode=yes nano-from-spark2 "hostname" 2>/dev/null; then
    echo "✅ SUCCESS"
else
    echo "❌ FAILED"
fi

echo -n "   Testing 'ssh agx-from-spark2'... "
if ssh -o ConnectTimeout=5 -o BatchMode=yes agx-from-spark2 "hostname" 2>/dev/null; then
    echo "✅ SUCCESS"
else
    echo "❌ FAILED"
fi

echo -n "   Testing 'ssh spark1-from-spark2'... "
if ssh -o ConnectTimeout=5 -o BatchMode=yes spark1-from-spark2 "hostname" 2>/dev/null; then
    echo "✅ SUCCESS"
else
    echo "❌ FAILED"
fi

echo ""
echo "=========================================="
echo "🔑 SSH KEY SETUP COMPLETE!"
echo "=========================================="
echo "✅ You can now use passwordless SSH:"
echo "   • ssh tower-from-spark2"
echo "   • ssh nano-from-spark2"
echo "   • ssh agx-from-spark2"
echo "   • ssh spark1-from-spark2"
echo "   • ssh $SSH_USER@$TOWER_IP"
echo "   • ssh $SSH_USER@$NANO_IP"
echo "   • ssh $SSH_USER@$AGX_IP"
echo "   • ssh $SSH_USER@$SPARK1_IP"
echo ""
echo "🔧 Scripts can now run without password prompts!"
echo "=========================================="