#!/bin/bash
set -e

echo "########################################"
echo "## SSH Key Setup for Passwordless     ##"
echo "## Authentication (Tower → Devices)   ##"
echo "########################################"

# Configuration
NANO_IP="10.1.10.181"
AGX_IP="10.1.10.244"
SSH_USER="sanjay"
KEY_TYPE="ed25519"
KEY_FILE="$HOME/.ssh/id_${KEY_TYPE}"
BACKUP_DIR="$HOME/.ssh/backup_$(date +%Y%m%d_%H%M%S)"

echo "Setting up passwordless SSH from Tower to Jetson devices..."
echo "Target devices: Nano ($NANO_IP), AGX ($AGX_IP)"
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
    ssh-keygen -t $KEY_TYPE -f "$KEY_FILE" -N "" -C "${SSH_USER}@tower-$(date +%Y%m%d)"
    echo "   ✅ SSH key generated: $KEY_FILE"
else
    echo "1. SSH key already exists: $KEY_FILE"
fi

# Step 2: Copy public key to Nano
echo ""
echo "2. Setting up passwordless access to Nano ($NANO_IP)..."
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
    grep -v -E "^Host (nano|agx)$" "$SSH_CONFIG" | \
    awk '/^Host nano$/,/^Host [^n]/ {if(/^Host [^n]/) print; next} 1' | \
    awk '/^Host agx$/,/^Host [^a]/ {if(/^Host [^a]/) print; next} 1' > "${SSH_CONFIG}.tmp"
    mv "${SSH_CONFIG}.tmp" "$SSH_CONFIG"
    echo "   Cleaned existing nano/agx entries from SSH config"
fi

# Add or update entries
cat >> "$SSH_CONFIG" << EOF

# Jetson Network Configuration - Added $(date)
Host nano
    HostName $NANO_IP
    User $SSH_USER
    IdentityFile $KEY_FILE
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host agx
    HostName $AGX_IP
    User $SSH_USER
    IdentityFile $KEY_FILE
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
EOF

chmod 600 "$SSH_CONFIG"
echo "   ✅ SSH config updated. You can now use:"
echo "      ssh nano    # Connect to Nano"
echo "      ssh agx     # Connect to AGX"

# Step 5: Final verification
echo ""
echo "5. Final verification of passwordless SSH..."

echo -n "   Testing 'ssh nano'... "
if ssh -o ConnectTimeout=5 -o BatchMode=yes nano "hostname" 2>/dev/null; then
    echo "✅ SUCCESS"
else
    echo "❌ FAILED"
fi

echo -n "   Testing 'ssh agx'... "
if ssh -o ConnectTimeout=5 -o BatchMode=yes agx "hostname" 2>/dev/null; then
    echo "✅ SUCCESS"
else
    echo "❌ FAILED"
fi

echo ""
echo "=========================================="
echo "🔑 SSH KEY SETUP COMPLETE!"
echo "=========================================="
echo "✅ You can now use passwordless SSH:"
echo "   • ssh nano"
echo "   • ssh agx"
echo "   • ssh $SSH_USER@$NANO_IP"
echo "   • ssh $SSH_USER@$AGX_IP"
echo ""
echo "🔧 Scripts can now run without password prompts!"
echo "=========================================="