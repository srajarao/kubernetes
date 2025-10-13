# 🚀 Distributed RAG System - Jetson Cluster Architecture

## Project Overview

This project implements a high-performance Retrieval-Augmented Generation (RAG) system distributed across a Jetson cluster, replacing Azure AI Search functionality with a custom FastAPI service.

### Architecture Vision

**Reference Project**: Azure AI Search Multimodal RAG Demo
**Our Implementation**: Distributed Jetson-based RAG with custom components

| Component | Reference (Azure) | Our System (Jetson) |
|-----------|------------------|-------------------|
| Vector Search | Azure AI Search | **FastAPI on Nano** |
| LLM Inference | Azure OpenAI | **GPU-accelerated on AGX** |
| Vector Database | Azure Storage/CosmosDB | **PostgreSQL + pgvector on Tower** |
| Document Processing | Azure AI Document Intelligence | **Custom pipeline on Tower** |

## 🏗️ System Architecture

### Data Flow Architecture
```
User Query → FastAPI (Nano) → Vector Search (Tower) → Context Retrieval → LLM (AGX) → Response
```

### Component Breakdown

#### 🏰 **Tower (Database & Storage)**
- **Role**: Vector database and document storage
- **Services**:
  - PostgreSQL with pgvector extension
  - Document storage and indexing
  - Vector similarity search
  - Data persistence and backup
- **Network**: 192.168.10.1 (10G), 192.168.5.1 (1G)

#### 🖥️ **AGX Orin (LLM Inference)**
- **Role**: GPU-accelerated large language model serving
- **Services**:
  - LLM model hosting (Llama, Mistral, etc.)
  - TensorRT optimization for Jetson
  - REST API for text generation
  - GPU memory management
- **Network**: 192.168.10.11 (10G to Tower)

#### 🚀 **Jetson Nano (RAG API)**
- **Role**: FastAPI service replacing Azure Search functionality
- **Services**:
  - Query processing and routing
  - Vector search against Tower database
  - Context retrieval and ranking
  - Response aggregation
  - API endpoint management
- **Network**: 192.168.5.21 (1G to Tower)

## 📋 Implementation Phases

### ✅ Phase 0: Network Foundation (COMPLETED)
**Goal**: Establish dual-network infrastructure for device communication

**Completed Tasks**:
- [x] Integrated bridgenfs network setup scripts
- [x] Configured dual-network (10G for AGX, 1G for Nano)
- [x] Set up inter-device routing and communication
- [x] Synchronized kubernetes infrastructure

**Deliverables**:
- Network setup scripts (bridgenfs/)
- Device communication validation
- SSH key distribution automation

### ✅ Phase 1: Database Foundation (COMPLETED)
**Goal**: Set up PostgreSQL + pgvector for vector storage and search

**Completed Tasks**:
- [x] Created comprehensive database setup scripts
- [x] Installed and configured pgvector extension
- [x] Created RAG database schema with tables and functions
- [x] Implemented vector similarity search functions
- [x] Set up document metadata storage
- [x] Configured remote database access for AGX/Nano
- [x] Updated database host to use IP addresses (192.168.10.1)

**Deliverables**:
- Database schema SQL scripts (`shared/scripts/db/`)
- Vector search utility functions
- Connection configuration with remote access
- Performance benchmarks and testing scripts

### Phase 2: LLM Service (AGX)
**Goal**: Deploy GPU-accelerated LLM inference service

**Tasks**:
- [ ] Select and download LLM model (GGUF format)
- [ ] Set up llama.cpp or TensorRT-LLM
- [ ] Create REST API for text generation
- [ ] Implement GPU memory optimization
- [ ] Add streaming response support
- [ ] Configure model quantization

**Deliverables**:
- LLM service API (FastAPI)
- Model configuration files
- GPU optimization scripts
- Performance monitoring

### Phase 3: RAG API (Nano)
**Goal**: Build FastAPI service replacing Azure Search

**Tasks**:
- [ ] Analyze Azure Search API patterns
- [ ] Implement vector search endpoints
- [ ] Create document ingestion pipeline
- [ ] Build query processing logic
- [ ] Integrate with Tower database
- [ ] Connect to AGX LLM service
- [ ] Implement response formatting

**Deliverables**:
- FastAPI application with RAG endpoints
- Document processing pipeline
- Query routing and aggregation
- API documentation (Swagger/OpenAPI)

### Phase 4: Document Processing Pipeline
**Goal**: Handle multimodal document ingestion

**Tasks**:
- [ ] PDF text extraction
- [ ] Image processing and OCR
- [ ] Document chunking strategies
- [ ] Embedding generation
- [ ] Metadata extraction
- [ ] Batch processing capabilities

**Deliverables**:
- Document processor service
- Embedding generation scripts
- Data ingestion workflows
- Processing monitoring

### Phase 5: Integration & Testing
**Goal**: End-to-end system integration

**Tasks**:
- [ ] Kubernetes deployments for all components
- [ ] Network configuration and service discovery
- [ ] End-to-end testing pipeline
- [ ] Performance optimization
- [ ] Monitoring and logging setup

**Deliverables**:
- Kubernetes manifests
- Integration tests
- Performance benchmarks
- Monitoring dashboards

## 🛠️ Technical Specifications

### Database Schema (Tower)
```sql
-- Documents table for storing source documents
CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    title VARCHAR(500) NOT NULL,
    content TEXT NOT NULL,
    source_url VARCHAR(1000),
    file_path VARCHAR(1000),
    content_type VARCHAR(100),
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Embeddings table for vector storage
CREATE TABLE embeddings (
    id SERIAL PRIMARY KEY,
    document_id INTEGER REFERENCES documents(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    embedding vector(1536), -- OpenAI text-embedding-ada-002 dimension
    chunk_index INTEGER,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Conversations table for chat history
CREATE TABLE conversations (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL,
    user_message TEXT NOT NULL,
    assistant_message TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Search queries table for analytics
CREATE TABLE search_queries (
    id SERIAL PRIMARY KEY,
    query TEXT NOT NULL,
    results_count INTEGER,
    response_time_ms INTEGER,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Vector search functions
CREATE INDEX ON embeddings USING ivfflat (embedding vector_cosine_ops);
CREATE OR REPLACE FUNCTION similarity_search(query_embedding vector(1536), match_threshold float DEFAULT 0.1, match_count int DEFAULT 10)
RETURNS TABLE(id integer, document_id integer, content text, similarity float) AS $$
BEGIN
    RETURN QUERY
    SELECT e.id, e.document_id, e.content, 1 - (e.embedding <=> query_embedding) as similarity
    FROM embeddings e
    WHERE 1 - (e.embedding <=> query_embedding) > match_threshold
    ORDER BY e.embedding <=> query_embedding
    LIMIT match_count;
END;
$$ LANGUAGE plpgsql;
```

### API Endpoints (Nano)

#### Search Endpoints
```
POST /api/v1/search
GET  /api/v1/documents/{id}
POST /api/v1/ingest
DELETE /api/v1/documents/{id}
```

#### RAG Endpoints
```
POST /api/v1/rag/query          # Main RAG query endpoint
POST /api/v1/rag/chat           # Conversational interface
GET  /api/v1/rag/history        # Query history
```

### LLM Service Endpoints (AGX)
```
POST /api/v1/generate           # Text generation
POST /api/v1/generate/stream    # Streaming generation
GET  /api/v1/models             # Available models
GET  /api/v1/health             # Service health
```

## 📊 Performance Targets

### Latency Requirements
- **Vector Search**: <100ms for top-k retrieval
- **LLM Generation**: <2s for 100-token responses
- **End-to-End Query**: <3s total response time
- **Document Ingestion**: <5s per document

### Throughput Goals
- **Concurrent Users**: 50+ simultaneous queries
- **Document Processing**: 100+ documents/hour
- **Vector Operations**: 1000+ searches/second

### Resource Utilization
- **AGX GPU**: <80% memory utilization during inference
- **Nano CPU**: <70% utilization during peak load
- **Tower DB**: <50% CPU, efficient indexing

## 🔧 Development Environment

### Prerequisites
- Ubuntu 22.04 on all devices
- Python 3.10+
- Docker and Docker Compose
- kubectl and k3s
- NVIDIA JetPack (AGX/Nano)

### Development Tools
- **IDE**: VS Code with remote development
- **Version Control**: Git with GitHub
- **Container Registry**: Local registry on Tower
- **Monitoring**: Prometheus + Grafana

## � Project Structure

```
/home/sanjay/containers/rag/
├── tower/                    # Database & storage services
├── agx/                      # LLM inference services
├── nano/                     # RAG API services
├── shared/                   # Shared utilities and scripts
│   ├── config/              # Configuration files
│   ├── scripts/             # Utility scripts
│   │   └── db/              # Database setup scripts
│   └── docs/                # Documentation
├── kubernetes/              # K3s cluster infrastructure
│   ├── bridgenfs/           # Network setup scripts
│   ├── agent/               # K3s agent configurations
│   └── server/              # K3s server configurations
├── deployments/             # Kubernetes manifests
└── reference/               # Azure AI Search reference
```

### Azure Sample Project
**Location**: `/reference/azure-ai-search-multimodal-sample/`
**Purpose**: Study Azure Search API patterns and RAG implementation
**Key Learnings**:
- Multimodal data processing
- Vector search algorithms
- API design patterns
- Deployment architectures

### Adaptation Strategy
1. **Replace Azure Search** → Custom FastAPI on Nano
2. **Replace Azure OpenAI** → Local LLM on AGX
3. **Replace Azure Storage** → PostgreSQL + pgvector on Tower
4. **Maintain RAG Logic** → Adapt query processing and response generation

## 🚀 Getting Started

### Phase 0: Network Setup (Prerequisites)
```bash
# Run network foundation setup (bridgenfs scripts)
cd /home/sanjay/containers/rag/kubernetes/bridgenfs
./1-setup_tower_network.sh    # Tower network configuration
./2-setup_agx_network.sh      # AGX network configuration
./3-setup_nano_network.sh     # Nano network configuration
./4-setup_tower_routing.sh    # Inter-device routing
./5-setup_agx_routing.sh      # AGX routing
./6-setup_nano_routing.sh     # Nano routing
./7-connectivity-test.sh      # Validate all connections
```

### Phase 1: Database Setup (Tower)
```bash
# Complete database foundation setup
cd /home/sanjay/containers/rag/shared/scripts/db
./1.0-db-setup-master.sh       # Run all database setup steps
# This includes PostgreSQL install, pgvector, schema creation, and remote access
```

### Development Workflow
1. **Network Setup**: Run Phase 0 scripts for device communication
2. **Database Setup**: Run Phase 1 scripts for vector storage foundation
3. **Local Development**: Use VS Code dev containers
4. **Testing**: Unit tests + integration tests
5. **Deployment**: Kubernetes manifests from `kubernetes/` directory
6. **Monitoring**: Logs and metrics collection

## 🎯 Success Metrics

### Functional Requirements
- [ ] End-to-end RAG queries working
- [ ] Multimodal document processing
- [ ] GPU-accelerated LLM inference
- [ ] Distributed component communication
- [ ] API documentation and testing

### Performance Requirements
- [ ] Sub-3-second query response time
- [ ] 99% uptime across all services
- [ ] Efficient resource utilization
- [ ] Scalable architecture

### Quality Requirements
- [ ] Comprehensive test coverage
- [ ] Production-ready logging
- [ ] Security best practices
- [ ] Documentation completeness

## 📝 Next Steps

### Immediate Actions
1. **✅ COMPLETED**: Network foundation setup scripts integrated
2. **✅ COMPLETED**: Database foundation with PostgreSQL + pgvector
3. **🔄 CURRENT**: Begin Phase 2 - LLM Service Setup on AGX
4. **🔄 NEXT**: Phase 3 - RAG API development on Nano
5. **🔄 FUTURE**: Phase 4 - Document processing pipeline
6. **🔄 FUTURE**: Phase 5 - Integration and production deployment

### Decision Points
- **LLM Model Selection**: Llama 2/3, Mistral, or Phi-2
- **Embedding Model**: sentence-transformers vs OpenAI (updated to 1536-dim for OpenAI ada-002)
- **API Framework**: FastAPI vs Flask vs Express
- **Deployment Strategy**: Kubernetes manifests ready in `kubernetes/` directory

---

**Project Status**: Phase 1 Complete - Ready for Phase 2
**Last Updated**: October 7, 2025
**Architecture**: Distributed Jetson RAG System
**Reference**: Azure AI Search Multimodal Sample
**Completed**: Network Foundation + Database Foundation
**Next Phase**: LLM Service Setup on AGX</content>
<parameter name="filePath">/home/sanjay/containers/rag/PROJECT_PLAN.md