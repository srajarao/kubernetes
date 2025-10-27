# Spark2 Kubernetes Agent Setup

This directory contains all files needed for setting up and managing the Spark2 device as a k3s agent node with GPU health validation.

## Overview

The Spark2 agent runs a streamlined health-check application that validates GPU functionality and exits. It performs comprehensive checks on:
- CUDA libraries and GPU availability
- PyTorch and TensorFlow GPU support
- TensorRT capabilities
- Database connectivity (optional)

## Files Overview

### Core Application
- **`spark2_app.py`** - Main health-check script that validates GPU functionality
- **`requirements.spark2.txt`** - Minimal Python dependencies (empty - uses pre-built wheels)
- **`wheels/`** - Pre-downloaded Python packages for fast container builds

### Build & Deployment
- **`build.sh`** - Docker build script using optimized wheels-based Dockerfile
- **`dockerfile.spark2.wheels`** - Optimized Dockerfile using pre-downloaded wheels
- **`dockerfile.spark2.req`** - Alternative Dockerfile using pip installs (slower)
- **`k3s-spark2.sh`** - Complete K3s agent setup and deployment script

### Configuration
- **`postgres.env`** - PostgreSQL database connection settings
- **`app/config/`** - Application configuration directory

## Spark2 Device Configuration

### Network Settings
- **IP Address**: 10.1.10.202
- **Node Name**: spark2
- **K3s Server**: 10.1.10.150:6443

### GPU Requirements
- NVIDIA GPU with CUDA support
- CUDA 12.0+ runtime
- TensorRT support (optional)

## Setup Process

### 1. Build Container
```bash
# Build optimized container with pre-downloaded wheels
./build.sh

# Or build with --clean for fresh build
./build.sh --clean
```

### 2. Deploy Agent
```bash
# Run complete setup (server + agent)
./k3s-spark2.sh
```

### 3. Validation
```bash
# Check cluster status
kubectl get nodes
kubectl get pods -n spark2

# View health check logs
kubectl logs -n spark2 deployment/spark2-healthcheck
```

## Health Checks Performed

The application validates:

1. **Library Loading**
   - `libstdc++.so.6` - C++ standard library
   - `libcusparseLt.so` - cuSPARSELt library

2. **GPU Frameworks**
   - PyTorch CUDA support and GPU operations
   - TensorFlow GPU detection and computation
   - TensorRT availability (optional)

3. **Database** (optional)
   - PostgreSQL connectivity test

## Container Behavior

- **Runs once**: Performs all checks and exits with status code
- **Exit codes**:
  - `0` = All checks passed
  - `1` = libstdc++ load failed
  - `2` = cuSPARSELt load failed
  - `3` = PyTorch check failed
  - `4` = TensorFlow check failed
  - `5` = TensorRT check failed
  - `7` = Database connection failed

## Architecture

```
Tower (10.1.10.150)           Spark2 Agent (10.1.10.202)
├── k3s server               ├── k3s agent
├── PostgreSQL               ├── GPU health validation
├── Docker Registry          ├── CUDA/PyTorch/TensorFlow checks
└── Container images         └── Exit with status code
```

## Troubleshooting

### Build Issues
```bash
# Clean build
./build.sh --clean

# Check build logs
docker buildx build --platform linux/arm64 -f dockerfile.spark2.wheels -t spark2 . --load
```

### Agent Issues
```bash
# Check agent status
sudo systemctl status k3s-agent

# View agent logs
sudo journalctl -u k3s-agent -f

# Restart agent
sudo systemctl restart k3s-agent
```

### GPU Issues
```bash
# Check GPU status
nvidia-smi

# Test CUDA
nvcc --version

# Check NVIDIA runtime
docker run --rm --gpus all nvidia/cuda:11.0-base nvidia-smi
```

## Development

### Local Testing
```bash
# Run health checks locally
python3 spark2_app.py

# With GPU enabled
GPU_ENABLED=true python3 spark2_app.py

# Skip database check
SKIP_DB_CHECK=true python3 spark2_app.py
```

### Modifying Health Checks
Edit `spark2_app.py` to add new validation checks. The script will:
1. Run all checks in sequence
2. Report results for each check
3. Exit with appropriate status code

## Notes

- Container uses NVIDIA runtime for GPU access
- Pre-downloaded wheels enable fast, offline builds
- Health checks run on container startup and exit
- No persistent services - designed for validation only
- Compatible with ARM64/aarch64 architecture