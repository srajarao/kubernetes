# AGX Kubernetes Agent Setup

This directory contains all files needed for setting up and managing the AGX device as a k3s agent node.

## Files Overview

### Main Scripts
- **`k3s-agx-setup.sh`** - Primary AGX agent setup script (template - replace with your working script)
- **`agx-setup-directories.sh`** - Creates directory structure on AGX system
- **`validate-agx-setup.sh`** - Validates AGX agent installation and connectivity
- **`cleanup-agx.sh`** - Completely removes k3s agent for fresh setup

### Configuration
- **`agx-config.env`** - AGX-specific configuration variables
- **`README.md`** - This documentation

## AGX Device Configuration

### Network Settings
- **Tower Access**: 192.168.10.1 (AGX subnet)
- **Node Name**: agx
- **API Server**: https://192.168.10.1:6443

### Storage Paths
- **Tokens**: `/export/vmstore/agx_home/containers/fastapi/.token/`
- **Registry**: `/export/vmstore/k3sRegistry/`
- **Config**: `/export/vmstore/agx_home/containers/fastapi/`

### Service Access
- **PostgreSQL**: 192.168.10.1:5432
- **pgAdmin**: http://192.168.10.1:8080
- **Docker Registry**: 192.168.10.1:5000

## Setup Process

### 1. Initial Setup
```bash
# Create directory structure on AGX
./agx-setup-directories.sh

# Configure environment (edit if needed)
vi agx-config.env

# Run agent setup (replace with your working script)
./k3s-agx-setup.sh
```

### 2. Validation
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