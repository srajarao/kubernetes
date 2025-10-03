#!/bin/sh
# Sanity check script for PostgreSQL and pgAdmin

# Resolve script directory and load postgres.env from ../config/postgres.env if present
SCRIPT_DIR=$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)
# Prefer the absolute host config path if available
ABS_ENV_FILE="/home/sanjay/containers/config/postgres.env"
ENV_FILE="$SCRIPT_DIR/../config/postgres.env"
if [ -f "$ABS_ENV_FILE" ]; then
    ENV_FILE="$ABS_ENV_FILE"
fi
if [ -f "$ENV_FILE" ]; then
    # shellcheck disable=SC1090
    . "$ENV_FILE"
fi

# Use sensible defaults if env vars missing (prefer the host bound in compose)
: ${POSTGRES_HOST:=192.168.5.1}
: ${POSTGRES_PORT:=5432}
: ${POSTGRES_USER:=postgres}

# Check for pg_isready first
echo "Checking for pg_isready (PostgreSQL client)..."
if ! command -v pg_isready >/dev/null 2>&1; then
    echo "pg_isready not found. PostgreSQL client is not installed."
    echo "Skipping PostgreSQL connectivity check. If you want this check to run, install the postgresql client."
else
    echo "Checking PostgreSQL connection to ${POSTGRES_HOST}:${POSTGRES_PORT} as ${POSTGRES_USER}..."
    # Capture output but don't let a failed connection cause the whole script to exit non-zero.
    PG_CONN_CHECK=$(pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" 2>&1 || true)
    echo "$PG_CONN_CHECK"
    if echo "$PG_CONN_CHECK" | grep -q "accepting connections"; then
        echo "PostgreSQL is reachable."
    else
        # Non-fatal: in many dev scenarios the DB container may not be up yet.
        echo "Warning: PostgreSQL connection failed or no response. This is non-fatal for the devcontainer setup and will not stop the postCreateCommand."
    fi
fi

# Check pgAdmin installation (warning only)
echo "Checking pgAdmin installation..."
if command -v pgadmin4 >/dev/null 2>&1; then
    echo "pgAdmin is installed."
else
    echo "Warning: pgAdmin is NOT installed! You can install it in the container if needed."
fi

echo "Sanity check completed (exit 0)."

exit 0
