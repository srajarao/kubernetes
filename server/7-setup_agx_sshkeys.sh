#!/bin/bash
set -e

echo "########################################"
echo "## SSH Key Setup for Passwordless     ##"
echo "## Authentication (AGX → Tower/Nano)  ##"
echo "########################################"

# Configuration
TOWER_IP="10.1.10.150"
NANO_IP="10.1.10.181"
SSH_USER="sanjay"
KEY_TYPE="ed25519"
KEY_FILE="$HOME/.ssh/id_${KEY_TYPE}"
BACKUP_DIR="$HOME/.ssh/backup_$(date +%Y%m%d_%H%M%S)"

echo "Setting up passwordless SSH from AGX to Tower and Nano..."
echo "Target devices: Tower ($TOWER_IP), Nano ($NANO_IP)"
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
    ssh-keygen -t $KEY_TYPE -f "$KEY_FILE" -N "" -C "${SSH_USER}@agx-$(date +%Y%m%d)"
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

# Step 3: Copy public key to Nano
echo ""
echo "3. Setting up passwordless access to Nano ($NANO_IP)..."
echo "   Please enter the password for $SSH_USER@$NANO_IP when prompted:"

if ssh-copy-id -i "${KEY_FILE}.pub" "$SSH_USER@$NANO_IP"; then
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

# Step 4: Create SSH config for easier access
echo ""
echo "4. Creating SSH config file for easier access..."
SSH_CONFIG="$HOME/.ssh/config"

# Remove any existing entries for our hosts to avoid duplicates
if [ -f "$SSH_CONFIG" ]; then
    # Create a temp file without our host entries
    grep -v -E "^Host (tower|nano)$" "$SSH_CONFIG" | \
    awk '/^Host tower$/,/^Host [^t]/ {if(/^Host [^t]/) print; next} 1' | \
    awk '/^Host nano$/,/^Host [^n]/ {if(/^Host [^n]/) print; next} 1' > "${SSH_CONFIG}.tmp"
    mv "${SSH_CONFIG}.tmp" "$SSH_CONFIG"
    echo "   Cleaned existing tower/nano entries from SSH config"
fi

# Add or update entries
cat >> "$SSH_CONFIG" << EOF

# Jetson Network Configuration - Added $(date)
Host tower
    HostName $TOWER_IP
    User $SSH_USER
    IdentitiesOnly yes
    IdentityFile $KEY_FILE

Host nano-from-agx
    HostName $NANO_IP
    User $SSH_USER
    IdentitiesOnly yes
    IdentityFile $KEY_FILE
EOF

echo "   ✅ SSH config updated with tower and nano-from-agx aliases"

# Step 5: Final verification
echo ""
echo "5. Final verification of SSH setup..."
echo "   Testing connections:"

# Test Tower connection
echo -n "   Tower ($TOWER_IP): "
if ssh -o ConnectTimeout=3 -o BatchMode=yes tower "hostname" 2>/dev/null; then
    echo "✅ Connected"
else
    echo "❌ Failed"
fi

# Test Nano connection
echo -n "   Nano ($NANO_IP): "
if ssh -o ConnectTimeout=3 -o BatchMode=yes nano-from-agx "hostname" 2>/dev/null; then
    echo "✅ Connected"
else
    echo "❌ Failed"
fi

echo ""
echo "==================================================="
echo "🎉 SSH Key Setup Complete!"
echo "==================================================="
echo "✅ Passwordless SSH configured from AGX to:"
echo "   • Tower: ssh tower"
echo "   • Nano:  ssh nano-from-agx"
echo ""
echo "💾 Backup location: $BACKUP_DIR"
echo "==================================================="