# Database Scripts for RAG System

This directory contains all database-related scripts for the RAG (Retrieval-Augmented Generation) system.

## Directory Structure

```
shared/scripts/db/
├── 1.0-db-setup-master.sh        # Master script to run all setup steps
├── 1.1-postgres-install.sh       # PostgreSQL installation
├── 1.2-pgvector-install.sh        # pgvector extension installation
├── 1.3-db-schema-create.sh        # Database schema creation
├── 1.4-db-test-connection.sh      # Database connection and functionality tests
├── 1.5-postgres-remote-config.sh  # Remote access configuration
├── db-config.sh                   # Database configuration variables
├── cleanup-db.sh                  # Database cleanup script
└── README.md                      # This file
```

## Quick Start

To set up the complete database foundation, run:

```bash
cd /home/sanjay/containers/rag/shared/scripts/db
chmod +x *.sh
./1.0-db-setup-master.sh
```

## Individual Scripts

### 1.0-db-setup-master.sh
**Purpose**: Runs all database setup scripts in the correct order
**Usage**: `./1.0-db-setup-master.sh`
**Prerequisites**: None
**Output**: Complete database setup with verification

### 1.1-postgres-install.sh
**Purpose**: Installs and configures PostgreSQL
**Usage**: `./1.1-postgres-install.sh`
**Prerequisites**: Ubuntu/Debian system
**Output**: PostgreSQL service running and enabled

### 1.2-pgvector-install.sh
**Purpose**: Downloads, builds, and installs pgvector extension
**Usage**: `./1.2-pgvector-install.sh`
**Prerequisites**: PostgreSQL installed, build tools available
**Output**: pgvector extension available in PostgreSQL

### 1.3-db-schema-create.sh
**Purpose**: Creates the RAG database schema with tables and functions
**Usage**: `./1.3-db-schema-create.sh`
**Prerequisites**: PostgreSQL and pgvector installed
**Output**: Database `rag_system` with complete schema

### 1.4-db-test-connection.sh
**Purpose**: Tests database connection and functionality
**Usage**: `./1.4-db-test-connection.sh`
**Prerequisites**: Database schema created
**Output**: Verification of all database components

### 1.5-postgres-remote-config.sh
**Purpose**: Configures PostgreSQL for remote access from AGX and Nano devices
**Usage**: `./1.5-postgres-remote-config.sh`
**Prerequisites**: Database schema created
**Output**: PostgreSQL accepting connections from 192.168.10.0/24 (AGX) and 192.168.1.0/24 (Nano)

## Database Schema

The database includes the following tables:

- **documents**: Stores source documents with metadata
- **embeddings**: Stores vector embeddings for similarity search
- **conversations**: Stores chat history and sessions
- **search_queries**: Stores search analytics

Key features:
- Vector similarity search using pgvector
- Full-text search capabilities
- JSON metadata storage
- Automatic timestamp updates
- Optimized indexes for performance

## Configuration

Database settings are defined in `db-config.sh`:

- Database: `rag_system`
- User: `rag_user`
- Host: 192.168.10.1 (Tower server on 10G network)
- Port: 5432
- Networks: Accessible from 192.168.10.0/24 (AGX) and 192.168.1.0/24 (Nano)
- Vector Dimension: 1536 (OpenAI ada-002 compatible)
- Connection pooling settings
- Backup configuration

## Cleanup

To remove the database and start fresh:

```bash
./cleanup-db.sh
```

**Warning**: This permanently deletes all data!

## Troubleshooting

### Common Issues

1. **Permission denied**: Run scripts with sudo or as postgres user
2. **pgvector build fails**: Ensure build-essential and postgresql-server-dev-all are installed
3. **Connection refused**: Check if PostgreSQL service is running
4. **Extension not found**: Verify pgvector was installed correctly

### Verification Commands

```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check database exists
sudo -u postgres psql -l

# Check pgvector extension
sudo -u postgres psql -d rag_system -c "SELECT * FROM pg_extension WHERE extname = 'vector';"

# Test vector operations
sudo -u postgres psql -d rag_system -c "SELECT '[1,2,3]'::vector(3) <=> '[4,5,6]'::vector(3);"
```

## Next Steps

After successful database setup:

1. **Phase 2**: LLM Setup on AGX device
2. **Phase 3**: RAG API development on Nano
3. **Phase 4**: System integration and testing
4. **Phase 5**: Production deployment

## Support

For issues with database setup, check:
- PostgreSQL logs: `/var/log/postgresql/`
- System logs: `journalctl -u postgresql`
- pgvector documentation: https://github.com/pgvector/pgvector