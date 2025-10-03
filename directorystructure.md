# Kubernetes Container Project Directory Structure

This document outlines the complete directory and file structure of the Kubernetes container project.

## Project Overview
This is a Kubernetes-based containerization project focused on PostgreSQL database deployment with pgAdmin interface and vector extension support.

**Generated on:** October 1, 2025  
**Root Directory:** `/home/sanjay/containers/kubernetes`

## Directory Structure

```
kubernetes/
├── agent/                                          # Agent node setup (nano/AGX)
│   ├── k3s-agent-setup.sh                         # k3s agent installation script
│   └── README.md                                   # Agent setup documentation
├── server/                                         # Tower server components
│   ├── k8s-setup-validate.sh                      # k3s server setup script
│   ├── k8s-setup-checklist.md                     # Server setup checklist
│   ├── update-summary.md                           # Update documentation
│   ├── docs/                                       # Documentation
│   │   ├── helper.md                               # Helper documentation
│   │   ├── kubernetes.md                           # Kubernetes-specific documentation
│   │   └── README.md                               # Main README file
│   ├── dockerfile.online.req                      # Docker requirements file
│   ├── k8s-setup-checklist.md                     # Kubernetes setup checklist
│   ├── k8s-setup-validate.sh                      # Kubernetes validation script
│   ├── docs/                                       # Documentation
│   │   ├── helper.md                               # Helper documentation
│   │   ├── kubernetes.md                           # Kubernetes-specific documentation
│   │   └── README.md                               # Main README file
│   ├── pgadmin/                                    # pgAdmin container configuration
│   │   ├── dockerfile.pgadmin                     # pgAdmin Dockerfile
│   │   ├── pgadmin-deployment.yaml                # pgAdmin Kubernetes deployment
│   │   ├── pgadmin-secret.yaml                    # pgAdmin secrets configuration
│   │   ├── requirement.pgadmin.txt                # pgAdmin requirements
│   │   ├── config/                                 # pgAdmin configuration
│   │   │   └── postgres.env                       # PostgreSQL environment variables
│   │   ├── data/                                   # pgAdmin data directory (access restricted)
│   │   ├── docs/                                   # pgAdmin documentation
│   │   │   ├── helper.md                           # pgAdmin helper documentation
│   │   │   └── README.md                           # pgAdmin README
│   │   └── src/                                    # pgAdmin source scripts
│   │       └── sanity_check.sh                    # pgAdmin sanity check script
│   └── postgres/                                   # PostgreSQL container configuration
│       ├── dockerfile.postgres                    # PostgreSQL Dockerfile
│       ├── postgres-db-deployment.yaml            # PostgreSQL Kubernetes deployment
│       ├── postgres-pgadmin-services.yaml         # Services configuration
│       ├── requirements.postgress.txt             # PostgreSQL requirements
│       ├── config/                                 # PostgreSQL configuration
│       │   └── postgres.env                       # PostgreSQL environment variables
│       ├── pgvector_repo/                         # pgvector extension repository
│       │   ├── .editorconfig                      # Editor configuration
│       │   ├── CHANGELOG.md                       # pgvector changelog
│       │   ├── Dockerfile                         # pgvector Dockerfile
│       │   ├── LICENSE                            # pgvector license
│       │   ├── Makefile                           # Build configuration (Unix)
│       │   ├── Makefile.win                       # Build configuration (Windows)
│       │   ├── META.json                          # Extension metadata
│       │   ├── README.md                          # pgvector documentation
│       │   ├── vector.control                     # PostgreSQL extension control file
│       │   ├── sql/                               # SQL migration scripts
│       │   │   ├── vector.sql                     # Main vector extension SQL
│       │   │   ├── vector--0.1.0--0.1.1.sql      # Version migration scripts
│       │   │   ├── vector--0.1.1--0.1.3.sql
│       │   │   ├── vector--0.1.3--0.1.4.sql
│       │   │   ├── vector--0.1.4--0.1.5.sql
│       │   │   ├── vector--0.1.5--0.1.6.sql
│       │   │   ├── vector--0.1.6--0.1.7.sql
│       │   │   ├── vector--0.1.7--0.1.8.sql
│       │   │   ├── vector--0.1.8--0.2.0.sql
│       │   │   ├── vector--0.2.0--0.2.1.sql
│       │   │   ├── vector--0.2.1--0.2.2.sql
│       │   │   ├── vector--0.2.2--0.2.3.sql
│       │   │   ├── vector--0.2.3--0.2.4.sql
│       │   │   ├── vector--0.2.4--0.2.5.sql
│       │   │   ├── vector--0.2.5--0.2.6.sql
│       │   │   ├── vector--0.2.6--0.2.7.sql
│       │   │   ├── vector--0.2.7--0.3.0.sql
│       │   │   ├── vector--0.3.0--0.3.1.sql
│       │   │   ├── vector--0.3.1--0.3.2.sql
│       │   │   ├── vector--0.3.2--0.4.0.sql
│       │   │   ├── vector--0.4.0--0.4.1.sql
│       │   │   ├── vector--0.4.1--0.4.2.sql
│       │   │   ├── vector--0.4.2--0.4.3.sql
│       │   │   ├── vector--0.4.3--0.4.4.sql
│       │   │   ├── vector--0.4.4--0.5.0.sql
│       │   │   ├── vector--0.5.0--0.5.1.sql
│       │   │   ├── vector--0.5.1--0.6.0.sql
│       │   │   ├── vector--0.6.0--0.6.1.sql
│       │   │   ├── vector--0.6.1--0.6.2.sql
│       │   │   ├── vector--0.6.2--0.7.0.sql
│       │   │   ├── vector--0.7.0--0.7.1.sql
│       │   │   ├── vector--0.7.1--0.7.2.sql
│       │   │   ├── vector--0.7.2--0.7.3.sql
│       │   │   ├── vector--0.7.3--0.7.4.sql
│       │   │   ├── vector--0.7.4--0.8.0.sql
│       │   │   └── vector--0.8.0--0.8.1.sql
│       │   ├── src/                               # pgvector C source code
│       │   │   ├── bitutils.c                     # Bit utilities implementation
│       │   │   ├── bitutils.h                     # Bit utilities header
│       │   │   ├── bitvec.c                       # Bit vector implementation
│       │   │   ├── bitvec.h                       # Bit vector header
│       │   │   ├── halfutils.c                    # Half precision utilities
│       │   │   ├── halfutils.h                    # Half precision utilities header
│       │   │   ├── halfvec.c                      # Half precision vector implementation
│       │   │   ├── halfvec.h                      # Half precision vector header
│       │   │   ├── hnsw.c                         # HNSW algorithm implementation
│       │   │   ├── hnsw.h                         # HNSW algorithm header
│       │   │   ├── hnswbuild.c                    # HNSW index building
│       │   │   ├── hnswinsert.c                   # HNSW insertion operations
│       │   │   ├── hnswscan.c                     # HNSW scanning operations
│       │   │   ├── hnswutils.c                    # HNSW utility functions
│       │   │   ├── hnswvacuum.c                   # HNSW vacuum operations
│       │   │   ├── ivfbuild.c                     # IVF index building
│       │   │   ├── ivfflat.c                      # IVF flat implementation
│       │   │   ├── ivfflat.h                      # IVF flat header
│       │   │   ├── ivfinsert.c                    # IVF insertion operations
│       │   │   ├── ivfkmeans.c                    # IVF k-means clustering
│       │   │   ├── ivfscan.c                      # IVF scanning operations
│       │   │   ├── ivfutils.c                     # IVF utility functions
│       │   │   ├── ivfvacuum.c                    # IVF vacuum operations
│       │   │   ├── sparsevec.c                    # Sparse vector implementation
│       │   │   ├── sparsevec.h                    # Sparse vector header
│       │   │   ├── vector.c                       # Main vector implementation
│       │   │   └── vector.h                       # Main vector header
│       │   └── test/                              # Test suite
│       │       ├── expected/                      # Expected test outputs
│       │       │   ├── bit.out                    # Bit operations test output
│       │       │   ├── btree.out                  # B-tree test output
│       │       │   ├── cast.out                   # Type casting test output
│       │       │   ├── copy.out                   # Copy operations test output
│       │       │   ├── halfvec.out                # Half vector test output
│       │       │   ├── hnsw_bit.out               # HNSW bit test output
│       │       │   ├── hnsw_halfvec.out           # HNSW half vector test output
│       │       │   ├── hnsw_sparsevec.out         # HNSW sparse vector test output
│       │       │   ├── hnsw_vector.out            # HNSW vector test output
│       │       │   ├── ivfflat_bit.out            # IVF flat bit test output
│       │       │   ├── ivfflat_halfvec.out        # IVF flat half vector test output
│       │       │   ├── ivfflat_vector.out         # IVF flat vector test output
│       │       │   ├── sparsevec.out              # Sparse vector test output
│       │       │   └── vector_type.out            # Vector type test output
│       │       ├── perl/                          # Perl test utilities
│       │       │   └── PostgreSQL/
│       │       │       └── Test/
│       │       │           ├── Cluster.pm         # PostgreSQL test cluster module
│       │       │           └── Utils.pm           # PostgreSQL test utilities module
│       │       ├── sql/                           # SQL test scripts
│       │       │   ├── bit.sql                    # Bit operations tests
│       │       │   ├── btree.sql                  # B-tree tests
│       │       │   ├── cast.sql                   # Type casting tests
│       │       │   ├── copy.sql                   # Copy operations tests
│       │       │   ├── halfvec.sql                # Half vector tests
│       │       │   ├── hnsw_bit.sql               # HNSW bit tests
│       │       │   ├── hnsw_halfvec.sql           # HNSW half vector tests
│       │       │   ├── hnsw_sparsevec.sql         # HNSW sparse vector tests
│       │       │   ├── hnsw_vector.sql            # HNSW vector tests
│       │       │   ├── ivfflat_bit.sql            # IVF flat bit tests
│       │       │   ├── ivfflat_halfvec.sql        # IVF flat half vector tests
│       │       │   ├── ivfflat_vector.sql         # IVF flat vector tests
│       │       │   ├── sparsevec.sql              # Sparse vector tests
│       │       │   └── vector_type.sql            # Vector type tests
│       │       └── t/                             # Perl test scripts
│       │           ├── 001_ivfflat_wal.pl         # IVF flat WAL tests
│       │           ├── 002_ivfflat_vacuum.pl      # IVF flat vacuum tests
│       │           ├── 003_ivfflat_vector_build_recall.pl
│       │           ├── 004_ivfflat_vector_insert_recall.pl
│       │           ├── 005_ivfflat_query_recall.pl
│       │           ├── 006_ivfflat_lists.pl
│       │           ├── 007_ivfflat_inserts.pl
│       │           ├── 008_ivfflat_centers.pl
│       │           ├── 009_ivfflat_filtering.pl
│       │           ├── 010_hnsw_wal.pl            # HNSW WAL tests
│       │           ├── 011_hnsw_vacuum.pl         # HNSW vacuum tests
│       │           ├── 012_hnsw_vector_build_recall.pl
│       │           ├── 013_hnsw_vector_insert_recall.pl
│       │           ├── 014_hnsw_vector_vacuum_recall.pl
│       │           ├── 015_hnsw_vector_duplicates.pl
│       │           ├── 016_hnsw_inserts.pl
│       │           ├── 017_hnsw_filtering.pl
│       │           ├── 018_aggregates.pl
│       │           ├── 019_storage.pl
│       │           ├── 020_hnsw_bit_build_recall.pl
│       │           ├── 021_hnsw_bit_insert_recall.pl
│       │           ├── 022_hnsw_bit_vacuum_recall.pl
│       │           ├── 023_hnsw_bit_duplicates.pl
│       │           ├── 024_hnsw_halfvec_build_recall.pl
│       │           ├── 025_hnsw_halfvec_insert_recall.pl
│       │           ├── 026_hnsw_halfvec_vacuum_recall.pl
│       │           ├── 027_hnsw_halfvec_duplicates.pl
│       │           ├── 028_hnsw_sparsevec_build_recall.pl
│       │           ├── 029_hnsw_sparsevec_insert_recall.pl
│       │           ├── 030_hnsw_sparsevec_vacuum_recall.pl
│       │           ├── 031_hnsw_sparsevec_duplicates.pl
│       │           ├── 032_ivfflat_halfvec_build_recall.pl
│       │           ├── 033_comparison.pl
│       │           ├── 034_distance_functions.pl
│       │           ├── 035_ivfflat_bit_build_recall.pl
│       │           ├── 036_ivfflat_bit_centers.pl
│       │           ├── 037_inputs.pl
│       │           ├── 038_hnsw_sparsevec_vacuum_insert.pl
│       │           ├── 039_hnsw_cost.pl
│       │           ├── 040_ivfflat_cost.pl
│       │           ├── 041_ivfflat_iterative_scan.pl
│       │           ├── 042_ivfflat_iterative_scan_recall.pl
│       │           ├── 043_hnsw_iterative_scan.pl
│       │           └── 044_hnsw_iterative_scan_recall.pl
│       └── src/                                   # PostgreSQL source scripts
│           ├── backup_home.sh                     # Home backup script
│           ├── verify_postgres.sh                 # PostgreSQL verification script
│           └── init.sql/                          # SQL initialization directory
│               └── init.sql                       # Database initialization script
└── directorystructure.md                         # This file
```

## Component Descriptions

### Main Components

1. **agent/**: Empty directory reserved for future agent-based functionality
2. **server/**: Core server infrastructure containing all containerized services

### Server Components

#### Documentation (`docs/`)
- Comprehensive documentation including Kubernetes setup guides and helper documentation

#### pgAdmin (`pgadmin/`)
- Web-based PostgreSQL administration interface
- Kubernetes deployment configurations
- Security configurations with secrets management
- Health check and validation scripts

#### PostgreSQL (`postgres/`)
- Main database server with vector extension support
- pgvector integration for AI/ML vector operations
- Comprehensive test suite for vector operations
- Support for multiple vector types: dense, sparse, half-precision, and bit vectors
- Advanced indexing algorithms: HNSW (Hierarchical Navigable Small World) and IVF (Inverted File)

### Key Features

- **Vector Database Support**: Full pgvector extension with multiple vector types
- **Advanced Indexing**: HNSW and IVF indexing for efficient similarity search
- **Kubernetes Native**: Complete Kubernetes deployment configurations
- **Comprehensive Testing**: Extensive test suite covering all vector operations
- **Security**: Proper secrets management and environment configuration
- **Scalability**: Container-based architecture for easy scaling

### File Types Summary

- **Configuration Files**: 6 files (Dockerfiles, YAML configs, environment files)
- **Documentation**: 8 markdown files
- **Scripts**: 4 shell scripts for setup and validation
- **SQL Files**: 40+ SQL migration and test files
- **C Source Code**: 25 C source and header files
- **Test Files**: 60+ test scripts and expected outputs
- **Build Files**: Makefiles for Unix and Windows platforms

---

*This directory structure represents a comprehensive Kubernetes-based PostgreSQL deployment with advanced vector database capabilities for AI/ML applications.*