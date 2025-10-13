#!/bin/bash
set -e

echo "########################################"
echo "## SSH Key Setup for Passwordless     ##"
echo "## Authentication (Nano → Tower/AGX)  ##"
echo "########################################"

# Configuration
TOWER_IP="10.1.10.150"
AGX_IP="10.1.10.244"
SSH_USER="sanjay"
KEY_TYPE="ed25519"
KEY_FILE="$HOME/.ssh/id_${KEY_TYPE}"
BACKUP_DIR="$HOME/.ssh/backup_$(date +%Y%m%d_%H%M%S)"

echo "Setting up passwordless SSH from Nano to Tower and AGX..."
echo "Target devices: Tower ($TOWER_IP), AGX ($AGX_IP)"
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

if ssh-copy-id -i "${KEY_FILE}.pub" "$SSH_USER@$TOWER_IP"; then
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

if ssh-copy-id -i "${KEY_FILE}.pub" "$SSH_USER@$AGX_IP"; then
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

# Step 4: Create SSH config for easier access
echo ""
echo "4. Creating SSH config file for easier access..."
SSH_CONFIG="$HOME/.ssh/config"

# Remove any existing entries for our hosts to avoid duplicates
if [ -f "$SSH_CONFIG" ]; then
    # Create a temp file without our host entries
    grep -v -E "^Host (tower|agx)$" "$SSH_CONFIG" | \
    awk '/^Host tower$/,/^Host [^t]/ {if(/^Host [^t]/) print; next} 1' | \
    awk '/^Host agx$/,/^Host [^a]/ {if(/^Host [^a]/) print; next} 1' > "${SSH_CONFIG}.tmp"
    mv "${SSH_CONFIG}.tmp" "$SSH_CONFIG"
    echo "   Cleaned existing tower/agx entries from SSH config"
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
EOF

echo "   ✅ SSH config updated with tower-from-nano and agx-from-nano aliases"

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

echo ""
echo "==================================================="
echo "🎉 SSH Key Setup Complete!"
echo "==================================================="
echo "✅ Passwordless SSH configured from Nano to:"
echo "   • Tower: ssh tower-from-nano"
echo "   • AGX:  ssh agx-from-nano"
echo ""
echo "💾 Backup location: $BACKUP_DIR"
echo "==================================================="