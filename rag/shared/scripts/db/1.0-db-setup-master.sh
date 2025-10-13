#!/bin/bash
# Phase 1: Database Foundation Master Script
# This script runs all database setup scripts in sequence

set -e

echo "=========================================="
echo "Phase 1: Database Foundation Setup"
echo "=========================================="
echo "This will install and configure:"
echo "1. PostgreSQL database server"
echo "2. pgvector extension for vector operations"
echo "3. RAG database schema with tables and functions"
echo "4. Database connectivity tests"
echo "5. Remote access configuration for AGX/Nano"
echo ""

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Function to run a script with error handling
run_script() {
    local script_name="$1"
    local script_path="${SCRIPT_DIR}/${script_name}"

    if [ ! -f "${script_path}" ]; then
        echo "Error: Script ${script_name} not found at ${script_path}"
        exit 1
    fi

    echo ""
    echo "Running ${script_name}..."
    bash "${script_path}"

    if [ $? -eq 0 ]; then
        echo "✓ ${script_name} completed successfully"
    else
        echo "✗ ${script_name} failed"
        exit 1
    fi
}

# Run database setup scripts in order
run_script "1.1-postgres-install.sh"
run_script "1.2-pgvector-install.sh"
run_script "1.3-db-schema-create.sh"
run_script "1.4-db-test-connection.sh"
run_script "1.5-postgres-remote-config.sh"

echo ""
echo "=========================================="
echo "Phase 1: Database Foundation - COMPLETE!"
echo "=========================================="
echo ""
echo "Database Details:"
echo "- Database: rag_system"
echo "- User: rag_user"
echo "- Host: localhost"
echo "- Port: 5432"
echo ""
echo "Next Steps:"
echo "1. Phase 2: LLM Setup on AGX"
echo "2. Phase 3: RAG API on Nano"
echo "3. Phase 4: System Integration"
echo "4. Phase 5: Production Deployment"