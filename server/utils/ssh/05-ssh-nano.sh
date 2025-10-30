#!/bin/bash
set -e

echo "########################################"
echo "## SSH Key Setup for Passwordless     ##"
echo "## Authentication (Nano → Tower/AGX)  ##"
echo "########################################"

# Configuration
TOWER_IP="192.168.1.150"
AGX_IP="192.168.1.244"
SPARK1_IP="192.168.1.201"
SPARK2_IP="192.168.1.202"
SSH_USER="sanjay"
KEY_TYPE="ed25519"
KEY_FILE="$HOME/.ssh/id_${KEY_TYPE}"
BACKUP_DIR="$HOME/.ssh/backup_$(date +%Y%m%d_%H%M%S)"

echo "Setting up passwordless SSH from Nano to Tower, AGX, Spark1, and Spark2..."
echo "Target devices: Tower ($TOWER_IP), AGX ($AGX_IP), Spark1 ($SPARK1_IP), Spark2 ($SPARK2_IP)"
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
    ssh-keygen -t $KEY_TYPE -f "$KEY_FILE" -N "" -C "${SSH_USER}@nano-$(date +%Y%m%d)"
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

# Step 3: Copy public key to AGX
echo ""
echo "3. Setting up passwordless access to AGX ($AGX_IP)..."
echo "   Please enter the password for $SSH_USER@$AGX_IP when prompted:"

if ssh-copy-id -o StrictHostKeyChecking=no -i "${KEY_FILE}.pub" "$SSH_USER@$AGX_IP"; then
    echo "   ✅ SSH key copied to AGX successfully"

    # Test the connection
    echo "   Testing passwordless connection to AGX..."
    if ssh -o ConnectTimeout=5 -o BatchMode=yes "$SSH_USER@$AGX_IP" "echo 'Passwordless SSH to AGX: SUCCESS'" 2>/dev/null; then
        echo "   ✅ Passwordless SSH to AGX is working!"
    else
        echo "   ⚠️  Passwordless SSH test failed. You may need to enter password manually."
    fi
else
    echo "   ❌ Failed to copy SSH key to AGX"
fi

# Step 3b: Copy public key to Spark1
echo ""
echo "3b. Setting up passwordless access to Spark1 ($SPARK1_IP)..."
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

# Step 3c: Copy public key to Spark2
echo ""
echo "3c. Setting up passwordless access to Spark2 ($SPARK2_IP)..."
echo "    Please enter the password for $SSH_USER@$SPARK2_IP when prompted:"

if ssh-copy-id -o StrictHostKeyChecking=no -i "${KEY_FILE}.pub" "$SSH_USER@$SPARK2_IP"; then
    echo "    ✅ SSH key copied to Spark2 successfully"

    # Test the connection
    echo "    Testing passwordless connection to Spark2..."
    if ssh -o ConnectTimeout=5 -o BatchMode=yes "$SSH_USER@$SPARK2_IP" "echo 'Passwordless SSH to Spark2: SUCCESS'" 2>/dev/null; then
        echo "    ✅ Passwordless SSH to Spark2 is working!"
    else
        echo "    ⚠️  Passwordless SSH test failed. You may need to enter password manually."
    fi
else
    echo "    ❌ Failed to copy SSH key to Spark2"
fi

# Step 4: Create SSH config for easier access
echo ""
echo "4. Creating SSH config file for easier access..."
SSH_CONFIG="$HOME/.ssh/config"

# Remove any existing entries for our hosts to avoid duplicates
if [ -f "$SSH_CONFIG" ]; then
    # Create a temp file without our host entries
    awk '
    /^Host (tower-from-nano|agx-from-nano|spark1-from-nano|spark2-from-nano)$/ { skip = 1; next }
    skip && /^Host / { skip = 0 }
    !skip { print }
    ' "$SSH_CONFIG" > "${SSH_CONFIG}.tmp"
    mv "${SSH_CONFIG}.tmp" "$SSH_CONFIG"
    echo "   Cleaned existing tower-from-nano/agx-from-nano/spark1-from-nano/spark2-from-nano entries from SSH config"
fi

# Add or update entries
cat >> "$SSH_CONFIG" << EOF

# Jetson Network Configuration - Added $(date)
Host tower-from-nano
    HostName $TOWER_IP
    User $SSH_USER
    IdentitiesOnly yes
    IdentityFile $KEY_FILE

Host agx-from-nano
    HostName $AGX_IP
    User $SSH_USER
    IdentitiesOnly yes
    IdentityFile $KEY_FILE

Host spark1-from-nano
    HostName $SPARK1_IP
    User $SSH_USER
    IdentitiesOnly yes
    IdentityFile $KEY_FILE

Host spark2-from-nano
    HostName $SPARK2_IP
    User $SSH_USER
    IdentitiesOnly yes
    IdentityFile $KEY_FILE
EOF

echo "   ✅ SSH config updated with tower-from-nano, agx-from-nano, spark1-from-nano, and spark2-from-nano aliases"

# Step 5: Final verification
echo ""
echo "5. Final verification of SSH setup..."
echo "   Testing connections:"

# Test Tower connection
echo -n "   Tower ($TOWER_IP): "
if ssh -o ConnectTimeout=3 -o BatchMode=yes tower-from-nano "hostname" 2>/dev/null; then
    echo "✅ Connected"
else
    echo "❌ Failed"
fi

# Test AGX connection
echo -n "   AGX ($AGX_IP): "
if ssh -o ConnectTimeout=3 -o BatchMode=yes agx-from-nano "hostname" 2>/dev/null; then
    echo "✅ Connected"
else
    echo "❌ Failed"
fi

# Test Spark1 connection
echo -n "   Spark1 ($SPARK1_IP): "
if ssh -o ConnectTimeout=3 -o BatchMode=yes spark1-from-nano "hostname" 2>/dev/null; then
    echo "✅ Connected"
else
    echo "❌ Failed"
fi

# Test Spark2 connection
echo -n "   Spark2 ($SPARK2_IP): "
if ssh -o ConnectTimeout=3 -o BatchMode=yes spark2-from-nano "hostname" 2>/dev/null; then
    echo "✅ Connected"
else
    echo "❌ Failed"
fi

echo ""
echo "==================================================="
echo "🎉 SSH Key Setup Complete!"
echo "==================================================="
echo "✅ Passwordless SSH configured from Nano to:"
echo "   • Tower: ssh tower-from-nano"
echo "   • AGX:  ssh agx-from-nano"
echo "   • Spark1: ssh spark1-from-nano"
echo "   • Spark2: ssh spark2-from-nano"
echo ""
echo "💾 Backup location: $BACKUP_DIR"
echo "==================================================="