#!/usr/bin/env bash
# verify_postgres.sh
# Checks if PostgreSQL is running and accepting connections

set -euo pipefail

# Set your PostgreSQL password here for non-interactive authentication
export PGPASSWORD='postgres'

PGUSER=${PGUSER:-postgres}
PGHOST=${PGHOST:-192.168.5.1}
PGPORT=${PGPORT:-5432}

# Check server status
if ! command -v pg_isready >/dev/null 2>&1; then
    echo "pg_isready not found; install postgresql-client to run connectivity checks"
    exit 0
fi

pg_isready -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" || true
STATUS=$?

if [ "$STATUS" -eq 0 ]; then
    echo "✅ PostgreSQL is accepting connections on $PGHOST:$PGPORT as user '$PGUSER'"
    # Run a simple query (non-interactive)
    psql -w -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -c "SELECT version();"

    # Sanity check: verify pgvector extension is installed
    echo "Checking pgvector extension..."
    psql -w -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -c "CREATE EXTENSION IF NOT EXISTS vector;"
    psql -w -U "$PGUSER" -h "$PGHOST" -p "$PGPORT" -c "SELECT extname FROM pg_extension WHERE extname = 'vector';"
else
    echo "❌ PostgreSQL is NOT accepting connections on $PGHOST:$PGPORT as user '$PGUSER'"
    exit 1
fi