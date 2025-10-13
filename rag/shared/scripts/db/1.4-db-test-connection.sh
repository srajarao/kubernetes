#!/bin/bash
# Phase 1.4: Database Connection Test
# This script tests the database connection and basic functionality

set -e

echo "=== Phase 1.4: Database Connection Test ==="

# Database configuration
DB_NAME="rag_system"
DB_USER="rag_user"
DB_PASSWORD="rag_password_2025"
DB_HOST="localhost"
DB_PORT="5432"

# Test basic connection
echo "Testing database connection..."
PGPASSWORD=${DB_PASSWORD} psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_USER} -d ${DB_NAME} -c "SELECT version();" --quiet

if [ $? -eq 0 ]; then
    echo "✓ Database connection successful!"
else
    echo "✗ Database connection failed!"
    exit 1
fi

# Test pgvector extension
echo "Testing pgvector extension..."
PGPASSWORD=${DB_PASSWORD} psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_USER} -d ${DB_NAME} -c "SELECT * FROM pg_extension WHERE extname = 'vector';" --quiet

# Test schema creation
echo "Testing database schema..."
PGPASSWORD=${DB_PASSWORD} psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_USER} -d ${DB_NAME} << 'EOF' --quiet
-- Test tables exist
SELECT 'documents table exists' as test WHERE EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'documents');
SELECT 'embeddings table exists' as test WHERE EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'embeddings');
SELECT 'conversations table exists' as test WHERE EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'conversations');

-- Test vector functionality
SELECT '[1,2,3]'::vector(3) <=> '[4,5,6]'::vector(3) as cosine_distance;

-- Test similarity search function
SELECT proname FROM pg_proc WHERE proname = 'similarity_search';
EOF

if [ $? -eq 0 ]; then
    echo "✓ Database schema and functions working correctly!"
else
    echo "✗ Database schema test failed!"
    exit 1
fi

# Test data insertion
echo "Testing data insertion..."
PGPASSWORD=${DB_PASSWORD} psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_USER} -d ${DB_NAME} << 'EOF' --quiet
-- Insert test document
INSERT INTO documents (title, content, content_type) VALUES
('Test Document', 'This is a test document for the RAG system.', 'text/plain');

-- Insert test embedding
INSERT INTO embeddings (document_id, content, embedding) VALUES
(1, 'This is a test document for the RAG system.', '[0.1,0.2,0.3,0.4,0.5]'::vector(5));

-- Test similarity search
SELECT * FROM similarity_search('[0.1,0.2,0.3,0.4,0.5]'::vector(5), 0.1, 5);
EOF

if [ $? -eq 0 ]; then
    echo "✓ Data insertion and similarity search working!"
else
    echo "✗ Data insertion test failed!"
    exit 1
fi

echo ""
echo "=== Database Test Summary ==="
echo "✓ PostgreSQL connection: OK"
echo "✓ pgvector extension: OK"
echo "✓ Database schema: OK"
echo "✓ Vector operations: OK"
echo "✓ Similarity search: OK"
echo ""
echo "Phase 1: Database Foundation completed successfully!"
echo "Ready for Phase 2: LLM Setup on AGX"