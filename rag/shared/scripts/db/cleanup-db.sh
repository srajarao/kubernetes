#!/bin/bash
# Database Cleanup Script
# This script removes the RAG database and user (use with caution!)

set -e

echo "=== Database Cleanup Script ==="
echo "WARNING: This will permanently delete the RAG database and user!"
echo ""

read -p "Are you sure you want to continue? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Cleanup cancelled."
    exit 0
fi

# Source configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/db-config.sh"

echo "Cleaning up RAG database..."

# Drop database and user
echo "Dropping database and user..."
sudo -u postgres psql << EOF
DROP DATABASE IF EXISTS ${DB_NAME};
DROP USER IF EXISTS ${DB_USER};
EOF

# Remove pgvector extension (optional, as it might be used by other databases)
echo "Note: pgvector extension remains installed for potential reuse"

# Stop PostgreSQL service
echo "Stopping PostgreSQL service..."
sudo systemctl stop postgresql

# Remove PostgreSQL (optional - uncomment if complete removal is desired)
# echo "Removing PostgreSQL packages..."
# sudo apt remove --purge -y postgresql postgresql-contrib
# sudo apt autoremove -y
# sudo apt autoclean

echo "Database cleanup completed."
echo "To reinstall, run the setup scripts again."