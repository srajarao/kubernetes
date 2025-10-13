#!/bin/bash
# Phase 1.2: pgvector Extension Installation
# This script downloads, builds, and installs the pgvector extension

set -e

echo "=== Phase 1.2: pgvector Extension Installation ==="

# Define variables
PGVECTOR_VERSION="0.7.4"
PGVECTOR_DIR="/tmp/pgvector-${PGVECTOR_VERSION}"

# Download pgvector source
echo "Downloading pgvector ${PGVECTOR_VERSION}..."
cd /tmp
git clone --branch v${PGVECTOR_VERSION} https://github.com/pgvector/pgvector.git pgvector-${PGVECTOR_VERSION}

# Build and install pgvector
echo "Building pgvector extension..."
cd ${PGVECTOR_DIR}
make
sudo make install

# Clean up
echo "Cleaning up temporary files..."
cd /tmp
rm -rf ${PGVECTOR_DIR}

# Verify installation
echo "Verifying pgvector installation..."
ls -la /usr/share/postgresql/*/extension/vector*

echo "pgvector extension installed successfully!"
echo "Next: Run 1.3-db-schema-create.sh to create the RAG database schema"