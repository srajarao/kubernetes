# Database Configuration for RAG System
# This file contains all database-related configuration variables

# Database Connection Details
export DB_NAME="rag_system"
export DB_USER="rag_user"
export DB_PASSWORD="rag_password_2025"
export DB_HOST="192.168.10.1"  # Tower server IP on 10G network
export DB_PORT="5432"

# Vector Configuration
export VECTOR_DIMENSION="1536"  # OpenAI text-embedding-ada-002 dimension

# Database URLs for different components
export DATABASE_URL="postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
export TOWER_DB_URL="${DATABASE_URL}"
export AGX_DB_URL="${DATABASE_URL}"
export NANO_DB_URL="${DATABASE_URL}"

# Connection Pool Settings
export DB_POOL_SIZE="10"
export DB_MAX_OVERFLOW="20"
export DB_POOL_TIMEOUT="30"

# Backup Configuration
export DB_BACKUP_DIR="/var/lib/postgresql/backups"
export DB_BACKUP_RETENTION_DAYS="7"

# Logging
export DB_LOG_LEVEL="INFO"