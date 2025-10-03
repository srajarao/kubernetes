# Kubernetes Multi-Node Cluster Setup

This repository contains the configuration and setup scripts for a multi-node Kubernetes cluster with specialized nodes for different AI/ML workloads.

## Cluster Architecture

- **Tower** (Control Plane): AMD64 server acting as master node
- **AGX** (Agent): NVIDIA Jetson AGX Orin for heavy AI workloads  
- **Nano** (Agent): NVIDIA Jetson Nano for lightweight AI tasks

## Features

### All Nodes
- K3s Kubernetes distribution
- Docker registry at 192.168.5.1:5000
- NFS shared storage from tower
- NVIDIA GPU support with runtime class

### Node-Specific Applications
- **FastAPI Applications**: Deployed on each node with health checks
- **Jupyter Lab**: Running on port 8888 for interactive development
- **PostgreSQL**: Database services
- **GPU Resource Management**: Automatic GPU allocation

## Directory Structure

```
agent/
├── nano/                    # Nano-specific configurations
│   ├── dockerfile.nano.req  # Optimized Dockerfile for Jetson Nano
│   ├── requirements.nano.txt # Python dependencies
│   ├── config/             # Configuration files
│   │   ├── nano-config.env
│   │   ├── postgres.env
│   │   └── start-fastapi-nano.yaml
│   └── src/                # Source code and scripts
│       ├── fastapi_app.py  # Main FastAPI application
│       ├── fastapi_healthcheck.py
│       ├── k3s-nano-agent-setup.sh
│       └── validate-nano-setup.sh
```

## Quick Start

### Nano Node Setup
```bash
cd agent/nano/src
./k3s-nano-agent-setup.sh
```

### Validation
```bash
./validate-nano-setup.sh
```

## Access Points

- **FastAPI Swagger UI**: `http://<node-ip>:30002/docs`
- **Jupyter Lab**: `http://<node-ip>:30003/jupyter`
- **Health Check**: `http://<node-ip>:30002/health`

## Performance Optimizations

- Optimized image building with redundancy elimination
- Streamlined cleanup processes (1s vs 25s+)
- Comprehensive health checks for all ML frameworks
- GPU resource conflict resolution

## Health Checks

Each node performs comprehensive health checks:
- ✅ libstdc++ compatibility
- ✅ cuSPARSELt GPU library
- ✅ PyTorch with CUDA support
- ✅ TensorFlow GPU acceleration
- ✅ TensorRT inference engine
- ✅ Jupyter Lab functionality
- ✅ FastAPI dependencies
- ✅ Database connectivity

## Recent Updates

- Fixed path resolution issues in setup scripts
- Added comprehensive timestamps for performance monitoring
- Implemented optimized Docker image handling
- Added Jupyter Lab auto-start functionality
- Enhanced pod cleanup with GPU resource management
- Standardized kubectl configurations

## Contributing

When making changes:
1. Test on one node first
2. Commit and push to GitHub
3. Pull changes on other nodes to maintain sync
4. Validate deployments across all nodes

## Troubleshooting

### Common Issues
- Pod restart loops: Check `/health` and `/ready` endpoints
- GPU resource conflicts: Verify nvidia.com/gpu allocation
- Image pull failures: Check registry connectivity to 192.168.5.1:5000
- Performance issues: Review timestamps in setup script output

### Logs
```bash
kubectl logs <pod-name>
kubectl describe pod <pod-name>
```