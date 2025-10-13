#!/bin/bash
# Phase 1.5: PostgreSQL Remote Access Configuration
# This script configures PostgreSQL to accept remote connections from AGX and Nano

set -e

echo "=== Phase 1.5: PostgreSQL Remote Access Configuration ==="

# Source configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/db-config.sh"

# PostgreSQL configuration files
PG_HBA="/etc/postgresql/14/main/pg_hba.conf"
PG_CONF="/etc/postgresql/14/main/postgresql.conf"

# Backup original files
echo "Backing up original PostgreSQL configuration..."
sudo cp ${PG_HBA} ${PG_HBA}.backup
sudo cp ${PG_CONF} ${PG_CONF}.backup

# Configure pg_hba.conf for remote access
echo "Configuring pg_hba.conf for remote access..."
sudo bash -c "cat >> ${PG_HBA}" << EOF

# RAG System remote access
# Allow connections from AGX (10G network)
host    ${DB_NAME}    ${DB_USER}    192.168.10.0/24    md5
# Allow connections from Nano (1G network)
host    ${DB_NAME}    ${DB_USER}    192.168.1.0/24     md5
# Allow local connections
local   ${DB_NAME}    ${DB_USER}                        md5
EOF

# Configure postgresql.conf for remote access
echo "Configuring postgresql.conf for remote access..."
sudo sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" ${PG_CONF}

# Restart PostgreSQL to apply changes
echo "Restarting PostgreSQL service..."
sudo systemctl restart postgresql

# Test remote connectivity (will work once network is set up)
echo "PostgreSQL configured for remote access!"
echo "Note: Remote connections will work after Phase 0 network setup"
echo ""
echo "Configuration Summary:"
echo "- Listen Address: All interfaces (*)"
echo "- AGX Network: 192.168.10.0/24"
echo "- Nano Network: 192.168.1.0/24"
echo "- Authentication: MD5 password"