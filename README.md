# Kubernetes Multi-Node Cluster Setup

This repository contains the configuration and setup scripts for a multi-node Kubernetes cluster with specialized nodes for different AI/ML workloads.## Health Checks

Each node performs comprehensive health checks:
- ✅ libstdc++ compatibility (ARM64)
- ✅ cuSPARSELt GPU library (NVIDIA optimized)
- ✅ PyTorch GPU acceleration (CUDA available: True, GPU: Orin)
- ✅ TensorFlow GPU acceleration (GPU visible, CUDA built)
- ✅ TensorRT inference engine (GPU optimized)
- ✅ Jupyter Lab functionality (port 8888-8889)
- ✅ FastAPI dependencies (configurable ports)
- ✅ Database connectivity (PostgreSQL on Tower)
- ✅ NFS mount validation (/mnt/vmstore)
- ✅ Network connectivity (all cluster nodes)Architecture

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
kubernetes/
├── network/                # Network setup scripts (from bridgenfs)
│   ├── 1-setup_tower_network.sh    # Tower dual-interface setup
│   ├── 2-setup_agx_network.sh      # AGX 10G network config
│   ├── 3-setup_nano_network.sh     # Nano 1G network config
│   ├── 4-setup_tower_routing.sh    # Tower internet sharing
│   ├── 5-setup_agx_routing.sh      # AGX inter-device routing
│   ├── 6-8-setup_*_sshkeys.sh      # Passwordless SSH setup
│   ├── inconsistencyCheck.sh       # Network consistency validation
│   └── restore_backup.sh           # Configuration restore
├── agent/
│   ├── nano/                    # Nano-specific configurations
│   │   ├── dockerfile.nano.req  # GPU-enabled Dockerfile (JetPack r36.4.0 base)
│   │   ├── requirements.nano.txt # Python deps: PyTorch, TensorFlow, TensorRT
│   │   ├── config/             # Configuration files
│   │   │   ├── postgres.env    # PostgreSQL connection (192.168.5.1:5432)
│   │   │   ├── nano-config.env # Nano-specific config
│   │   │   └── start-fastapi-nano.yaml # K8s deployment YAML with GPU support
│   │   └── src/                # Source code and scripts
│   │       ├── fastapi_app.py  # FastAPI with GPU-accelerated ML support
│   │       ├── fastapi_healthcheck.py # GPU library health checks
│   │       ├── k3s-nano-agent-setup.sh
│   │       └── validate-nano-setup.sh # Comprehensive validation
│   └── agx/                    # AGX-specific configurations (similar structure)
├── server/                     # Tower server setup
│   └── k8s-setup-validate.sh   # K3s server installation
└── README.md                   # This file
```

## Setup Sequence (Critical - Follow Order Strictly)

**Important**: Network setup must be completed BEFORE k3s installation to avoid connectivity issues. k3s modifies iptables and routes, which can break manual network configurations.

### Phase 1: Network Foundation (Run on Correct Devices)
1. **Tower**: `./network/1-setup_tower_network.sh` - Configure dual 10G/1G interfaces + NFS
2. **AGX**: `./network/2-setup_agx_network.sh` - Configure 10G network + NFS mount
3. **Nano**: `./network/3-setup_nano_network.sh` - Configure 1G network + NFS mount
4. **Tower**: `./network/4-setup_tower_routing.sh` - Enable internet sharing + routing
5. **AGX** (Optional): `./network/5-setup_agx_routing.sh` - Add routes for Nano access

### Phase 2: SSH Setup (Optional but Recommended)
- Run `./network/6-setup_tower_sshkeys.sh` on Tower for passwordless access to devices

### Phase 3: Kubernetes Setup
1. **Tower**: `./server/k8s-setup-validate.sh` - Install k3s server
2. **AGX**: `./agent/agx/k3s-agx-agent-setup.sh` - Install k3s agent
3. **Nano**: `./agent/nano/k3s-nano-agent-setup.sh` - Install k3s agent

### Phase 4: Validation
- Run `./validate-k3s-agent.sh` on each agent to verify complete setup
- Use `./agent/nano/validate-nano-setup.sh` for node-specific checks

## Validation & Testing

**Important**: The validation script is run **AFTER** installation to verify everything works:

```bash
# After completing setup on each device
./validate-k3s-agent.sh
```

This comprehensive script tests all 7 critical components:
- Network connectivity between all devices
- K3s service status and processes  
- Kubernetes cluster access and node readiness
- Docker registry connectivity
- NFS mounts accessibility
- Routing tables correctness
- iptables rules for inter-device traffic

**All output includes timestamps** to help identify performance bottlenecks and long-running steps.

See `K3S_SETUP_WORKFLOW.md` for detailed setup and validation procedures.

## Quick Start

### Prerequisites
- All devices connected via Ethernet (10G for AGX, 1G for Nano)
- Ubuntu/Linux on all devices
- Sudo access

### Complete Setup (Multi-Device)
```bash
# On Tower
cd /home/sanjay/containers/kubernetes
./network/1-setup_tower_network.sh

# On AGX (after Tower network is ready)
./network/2-setup_agx_network.sh

# On Nano (after Tower network is ready)  
./network/3-setup_nano_network.sh

# Back on Tower
./network/4-setup_tower_routing.sh
./server/k8s-setup-validate.sh

# On AGX
./agent/agx/k3s-agx-agent-setup.sh

# On Nano
./agent/nano/k3s-nano-agent-setup.sh
```

### Validation
```bash
# Check consistency
./network/inconsistencyCheck.sh

# Check cluster status
kubectl get nodes
```

## Troubleshooting

### Network Issues
- **Connectivity Lost After k3s Install**: k3s modifies routes/iptables. Re-run network scripts or use `./network/restore_backup.sh`
- **NFS Mount Fails**: Check Tower NFS exports with `showmount -e 192.168.5.1`
- **Inter-Device Communication**: Ensure routing scripts are run

### k3s Issues  
- **Agent Won't Join**: Verify node-token and server CA cert
- **Pods Not Starting**: Check GPU runtime class and NVIDIA drivers

### Recovery
- **Network Restore**: `./network/restore_backup.sh` (device-specific)
- **k3s Cleanup**: `./agent/nano/cleanup-nano.sh` (removes k3s and services)

## Network Architecture Details

- **Tower**: 192.168.10.1 (10G), 192.168.5.1 (1G)
- **AGX**: 192.168.10.11 (10G to Tower)
- **Nano**: 192.168.5.21 (1G to Tower)
- **NFS**: `/export/vmstore` on Tower, mounted at `/mnt/vmstore` on agents
- **Registry**: Docker registry at 192.168.5.1:5000

See `network/` scripts for detailed network configuration.

### Validation
```bash
./validate-nano-setup.sh
```

## Access Points

- **FastAPI Swagger UI**: `http://<node-ip>:<FASTAPI_PORT>/docs` (default: 8000, nano: 8001)
- **Jupyter Lab**: `http://<node-ip>:8889/jupyter/lab` (nano, GPU-enabled environment)
- **Health Check**: `http://<node-ip>:<FASTAPI_PORT>/health`
- **System Info**: `http://<node-ip>:<FASTAPI_PORT>/info`
- **Metrics**: `http://<node-ip>:<FASTAPI_PORT>/metrics`
- **Database**: PostgreSQL at `192.168.5.1:5432` (Tower)
- **System Info**: `http://<node-ip>:<FASTAPI_PORT>/info`
- **Metrics**: `http://<node-ip>:<FASTAPI_PORT>/metrics`
- **Database**: PostgreSQL at `192.168.5.1:5432` (Tower)
- **System Info**: `http://<node-ip>:<FASTAPI_PORT>/info`
- **Metrics**: `http://<node-ip>:<FASTAPI_PORT>/metrics`
- **Database**: PostgreSQL at `192.168.5.1:5432` (Tower)

## Performance Optimizations

- Optimized image building with redundancy elimination
- Streamlined cleanup processes (1s vs 25s+)
- Comprehensive health checks for all ML frameworks
- GPU resource conflict resolution

## Health Checks

Each node performs comprehensive health checks:
- ✅ libstdc++ compatibility (ARM64)
- ✅ cuSPARSELt GPU library (NVIDIA optimized)
- ✅ PyTorch CPU inference (ARM64 wheels)
- ✅ TensorFlow CPU (ARM64 optimized)
- ✅ TensorRT inference engine (CPU fallback)
- ✅ Jupyter Lab functionality (port 8888-8889)
- ✅ FastAPI dependencies (configurable ports)
- ✅ Database connectivity (PostgreSQL on Tower)
- ✅ NFS mount validation (/mnt/vmstore)
- ✅ Network connectivity (all cluster nodes)

## Recent Updates

## Recent Updates

- **October 2025**: Complete GPU-enabled ML container setup for Jetson Nano
  - NVIDIA JetPack r36.4.0 base image with full GPU support
  - PyTorch, TensorFlow, TensorRT with GPU acceleration enabled
  - FORCE_GPU_CHECKS environment variable for container GPU access
  - Configurable FastAPI ports to resolve conflicts (FASTAPI_PORT env var)
  - PostgreSQL connectivity to Tower database (192.168.5.1:5432)
  - Comprehensive health checks for all GPU libraries
  - Pod structure alignment with Kubernetes expectations
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
- **Port Conflicts**: Use `FASTAPI_PORT` environment variable (e.g., `FASTAPI_PORT=8001`)
- **Database Connection**: Verify `postgres.env` file at `/app/app/config/postgres.env`
- **Pod restart loops**: Check `/health` and `/ready` endpoints
- **GPU resource conflicts**: Verify nvidia.com/gpu allocation
- **Image pull failures**: Check registry connectivity to 192.168.5.1:5000
- **Performance issues**: Review timestamps in setup script output
- **ML Library Issues**: Check ARM64 compatibility and CPU-only configuration

### Container-Specific Issues
```bash
# Test container locally
docker run --rm -it --runtime=nvidia --network=host \
  -e FASTAPI_PORT=8001 \
  -v /home/sanjay:/mnt/vmstore \
  fastapi_nano

# Check health inside container
python app/src/fastapi_healthcheck.py

# Test database connection
python -c "
import psycopg2
import os
from dotenv import load_dotenv
load_dotenv('/app/app/config/postgres.env')
conn = psycopg2.connect(
    host=os.getenv('DB_HOST'),
    port=os.getenv('DB_PORT'),
    dbname=os.getenv('DB_NAME'),
    user=os.getenv('DB_USER'),
    password=os.getenv('DB_PASSWORD')
)
print('Database connection successful')
"
```