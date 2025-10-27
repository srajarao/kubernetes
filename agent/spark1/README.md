# Spark1 Kubernetes Agent Setup

This directory contains all files needed for setting up and managing the Spark1 device as a k3s agent node.

## Files Overview

### Main Scripts
- **`k3s-spark1.sh`** - Primary Spark1 agent setup script with comprehensive deployment
- **`k3s-spark1-agent-setup.sh`** - Alternative Spark1 agent setup script
- **`setup-spark1-network.sh`** - Network configuration for Spark1 device
- **`build.sh`** - Docker image build script for Spark1

### Configuration
- **`spark1_app.py`** - Health check application for Spark1
- **`fastapi-deployment-spark1.yaml`** - Kubernetes deployment manifest
- **`requirements.spark1.txt`** - Python dependencies
- **`dockerfile.spark1.req`** - Docker build configuration
- **`postgres.env`** - Database configuration

## Spark1 Device Configuration

### Network Settings
- **IP Address**: 10.1.10.201
- **Node Name**: spark1
- **API Server**: https://10.1.10.150:6443

### Hardware
- **GPU**: NVIDIA GB10
- **Architecture**: ARM64
- **CUDA**: 13.0 support

### Service Access
- **PostgreSQL**: 10.1.10.150:30432
- **pgAdmin**: http://10.1.10.150:30080
- **Docker Registry**: 10.1.10.150:30500

## Setup Process

### 1. Initial Setup
```bash
# Run comprehensive setup
./k3s-spark1.sh

# Alternative: Use simplified setup
./k3s-spark1-agent-setup.sh
```

### 2. Build and Deploy
```bash
# Build Docker image
./build.sh

# Deploy to Kubernetes
kubectl apply -f fastapi-deployment-spark1.yaml
```

### 3. Validation
```bash
# Check pod status
kubectl get pods -l app=fastapi-spark1

# Check health endpoint
curl http://10.1.10.150:30001/health
```
```bash
# Validate setup
./validate-agx-setup.sh

# Check cluster status
kubectl get nodes
kubectl get pods --all-namespaces
```

### 3. Troubleshooting
```bash
# If setup fails, clean and retry
./cleanup-agx.sh
./k3s-agx-setup.sh

# Debug mode
DEBUG=1 ./k3s-agx-setup.sh
```

## Integration with Tower

### Token Synchronization
The tower automatically exports tokens to:
- `/export/vmstore/agx_home/containers/fastapi/.token/node-token`
- `/export/vmstore/agx_home/containers/fastapi/.token/k3s.yaml`  
- `/export/vmstore/agx_home/containers/fastapi/.token/server-ca.crt`

### Image Distribution
Container images are saved by tower to:
- `/export/vmstore/k3sRegistry/postgres.tar`
- `/export/vmstore/k3sRegistry/pgadmin.tar`
- `/export/vmstore/k3sRegistry/fastapi_nano.tar`

## Customization

### Replace Template Script
The `k3s-agx-setup.sh` is currently a template. Replace it with your proven working AGX script:

```bash
# Backup template
cp k3s-agx-setup.sh k3s-agx-setup.sh.template

# Copy your working script
cp /path/to/your/working/agx-script.sh k3s-agx-setup.sh

# Make executable
chmod +x k3s-agx-setup.sh
```

### Environment Configuration
Edit `agx-config.env` to match your specific setup:
- Network addresses
- Storage paths  
- Service endpoints
- Timeouts

## Architecture

```
Tower (192.168.10.1)          AGX Agent
├── k3s server               ├── k3s agent
├── PostgreSQL               ├── Workload pods
├── pgAdmin                  ├── Container runtime
├── Docker Registry          └── Storage access
└── Token distribution
```

## Common Commands

```bash
# Check agent status
sudo systemctl status k3s-agent

# View logs
sudo journalctl -u k3s-agent -f

# Test connectivity
kubectl get nodes
kubectl describe node agx

# Restart agent
sudo systemctl restart k3s-agent

# Complete reset
./cleanup-agx.sh && ./k3s-agx-setup.sh
```

## Notes

- This setup assumes shared storage is mounted and accessible
- Network connectivity between AGX (192.168.10.x) and tower (192.168.10.1) is required
- The AGX acts as an agent node - all control plane operations happen on the tower
- Replace the template script with your proven working implementation