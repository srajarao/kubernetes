#!/bin/bash
# Phase 1.1: PostgreSQL Installation and Setup
# This script installs and configures PostgreSQL with pgvector support

set -e

echo "=== Phase 1.1: PostgreSQL Installation ==="

# Update package list
echo "Updating package list..."
sudo apt update

# Install PostgreSQL
echo "Installing PostgreSQL..."
sudo apt install -y postgresql postgresql-contrib

# Install build dependencies for pgvector
echo "Installing build dependencies for pgvector..."
sudo apt install -y build-essential git postgresql-server-dev-all

# Start and enable PostgreSQL service
echo "Starting PostgreSQL service..."
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Verify installation
echo "Verifying PostgreSQL installation..."
sudo systemctl status postgresql --no-pager

echo "PostgreSQL installation completed successfully!"
echo "Next: Run 1.2-pgvector-install.sh to install pgvector extension"