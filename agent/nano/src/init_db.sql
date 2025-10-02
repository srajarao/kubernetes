-- PostgreSQL Schema for Local Multimodal RAG
-- Run this script in the postgres database

-- Create documents table
CREATE TABLE IF NOT EXISTS documents (
    id SERIAL PRIMARY KEY,
    title TEXT,
    content TEXT,
    file_path TEXT,
    doc_type TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create citations table
CREATE TABLE IF NOT EXISTS citations (
    id SERIAL PRIMARY KEY,
    document_id INTEGER REFERENCES documents(id),
    citation_text TEXT,
    citation_type TEXT,
    page_number INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create chat_history table
CREATE TABLE IF NOT EXISTS chat_history (
    id SERIAL PRIMARY KEY,
    user_message TEXT,
    response TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create embeddings table (optional - requires pgvector extension)
-- CREATE EXTENSION IF NOT EXISTS vector;
-- CREATE TABLE IF NOT EXISTS embeddings (
--     id SERIAL PRIMARY KEY,
--     document_id INTEGER REFERENCES documents(id),
--     embedding VECTOR(1536), -- Adjust dimension as needed
--     embedding_type TEXT,
--     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
-- );

-- Insert some sample data for testing
INSERT INTO documents (title, content, file_path, doc_type) VALUES
('Sample Document 1', 'This is a sample document for testing the search functionality.', '/path/to/sample1.txt', 'text'),
('Sample Document 2', 'Another sample document with different content for search testing.', '/path/to/sample2.txt', 'text'),
('AI Research Paper', 'This paper discusses artificial intelligence and machine learning advancements.', '/path/to/ai_paper.pdf', 'pdf')
ON CONFLICT DO NOTHING;