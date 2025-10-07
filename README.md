# 🚀 K3s Multi-Node AI Cluster with Dual-Network Setup

This repository provides a complete, automated setup for a high-performance Kubernetes cluster optimized for AI/ML workloads on Jetson devices. It combines K3s (lightweight Kubernetes), dual-network architecture (10G + 1G), GPU acceleration, and comprehensive application deployments.

## 🎯 What This Project Provides

### ✅ Complete AI-Ready Kubernetes Cluster
- **Automated Setup**: Single-command cluster deployment with network configuration
- **GPU Optimization**: NVIDIA GPU support with runtime classes and device plugins
- **Dual-Network Performance**: 10G dedicated link for AGX Orin, 1G for Jetson Nano
- **Application Suite**: FastAPI, Jupyter Lab, PostgreSQL, PgAdmin
- **Enterprise Features**: NFS storage, health checks, monitoring

### 🏆 Performance Achievements
- **AGX Orin**: Up to 10 Gbps bandwidth with ultra-low latency for AI inference
- **Jetson Nano**: Stable 1 Gbps with preserved internet connectivity
- **Zero Interference**: Isolated networks prevent bandwidth sharing issues
- **GPU Acceleration**: CUDA, TensorRT, PyTorch, TensorFlow optimized

## 🏗️ Architecture Overview

### Network Topology
```
                    TOWER (Ubuntu Server)
                    ├── 10G Port: enp1s0f0 (192.168.10.1)
                    │   └── AGX Orin (192.168.10.11) - High-performance AI
                    └── 1G Port: eno2 (192.168.5.1)
                        └── Jetson Nano (192.168.5.21) - IoT/Monitoring
```

### Cluster Components
- **Tower (Control Plane)**: K3s server, NFS storage, PostgreSQL, PgAdmin
- **AGX Orin (Agent)**: GPU-accelerated FastAPI, Jupyter Lab, AI workloads
- **Jetson Nano (Agent)**: Lightweight FastAPI, monitoring, IoT tasks

### Key Technologies
- **K3s**: Lightweight Kubernetes for edge computing
- **Dual-Network**: Isolated 10G/1G links for optimal performance
- **NVIDIA GPU**: Runtime classes, device plugins, CUDA acceleration
- **Docker Registry**: Local image registry at tower:5000
- **NFS Storage**: Shared persistent storage across all nodes

## 📁 Project Structure

```
kubernetes/
├── k3s-config.sh                    # Configuration file (IPs, enable/disable components)
├── k3s-setup-automation.sh          # Main automated setup script
├── README.md                        # This documentation
├── validate-k3s-agent.sh            # Cluster validation script
├── fastapi-deployment-full.yaml     # K8s deployment manifests
├── nvidia-ds-updated.yaml           # NVIDIA device plugin
├── nvidia-plugin-clean-ds.yaml      # GPU cleanup
├── .git/                            # Git repository
├── .gitignore                       # Git ignore rules
├── bridgenfs/                       # Network setup scripts
│   ├── 1-setup_tower_network.sh     # Tower dual-interface config
│   ├── 2-setup_agx_network.sh       # AGX 10G network setup
│   ├── 3-setup_nano_network.sh      # Nano 1G network setup
│   ├── 4-setup_tower_routing.sh     # Internet sharing & routing
│   ├── 5-setup_agx_routing.sh       # Inter-device routing
│   ├── 6-8-*_sshkeys.sh             # Passwordless SSH setup
│   ├── README.md                    # Network setup documentation
│   ├── inconsistencyCheck.sh        # Network validation
│   └── restore_backup.sh            # Configuration backup/restore
├── agent/                           # Agent-specific configurations
│   ├── nano/                        # Jetson Nano setup
│   │   ├── dockerfile.nano.req      # GPU-enabled Dockerfile
│   │   ├── requirements.nano.txt    # Python dependencies
│   │   ├── app/                     # FastAPI application
│   │   │   ├── src/fastapi_app.py   # Main FastAPI app
│   │   │   ├── config/              # Configuration files
│   │   │   └── docs/                # API documentation
│   │   ├── k3s-nano-agent-setup.sh  # Nano K3s agent setup
│   │   ├── validate-nano-setup.sh   # Nano validation
│   │   ├── cleanup-nano.sh          # Cleanup scripts
│   │   └── README.md                # Nano-specific docs
│   └── agx/                         # Jetson AGX Orin setup
│       ├── fastapi_app.py           # AGX FastAPI app
│       ├── k3s-agx-agent-setup.sh   # AGX K3s agent setup
│       ├── validate-agx-setup.sh    # AGX validation
│       ├── setup-agx-network.sh     # AGX network config
│       └── README.md                # AGX-specific docs
└── server/                          # Tower server components
    ├── pgadmin/                     # PgAdmin web interface
    │   ├── dockerfile.pgadmin       # PgAdmin Dockerfile
    │   ├── pgadmin-deployment.yaml  # K8s deployment
    │   ├── pgadmin-secret.yaml      # Secrets
    │   └── docs/                    # PgAdmin docs
    ├── postgres/                    # PostgreSQL database
    │   ├── dockerfile.postgres      # PostgreSQL Dockerfile
    │   ├── postgres-db-deployment.yaml
    │   ├── postgres-pgadmin-services.yaml
    │   └── docs/                    # PostgreSQL docs
    ├── docs/                        # Server documentation
    ├── jupyter/                     # Jupyter configurations
    ├── k8s-setup-validate.sh        # Server validation
    ├── postgres-pgadmin-nodeport-services.yaml
    └── verify-postgres-pgadmin.sh   # Service verification
```

## 🚀 Quick Start

### Prerequisites
- Ubuntu Server (Tower) with dual NICs (10G + 1G)
- NVIDIA Jetson AGX Orin (10G connected to Tower)
- NVIDIA Jetson Nano (1G connected to Tower)
- SSH access between devices

### Automated Setup (Recommended)
1. **Configure Settings**:
   ```bash
   # Edit k3s-config.sh to set IPs and enable/disable components
   nano k3s-config.sh
   ```

2. **Run Complete Setup**:
   ```bash
   # This handles network setup, K3s cluster, and applications
   ./k3s-setup-automation.sh
   ```

### Manual Setup (Alternative)
If you prefer manual control:

1. **Network Setup** (Critical - Do this first):
   ```bash
   # On Tower
   ./bridgenfs/1-setup_tower_network.sh
   ./bridgenfs/4-setup_tower_routing.sh

   # On AGX
   ./bridgenfs/2-setup_agx_network.sh

   # On Nano
   ./bridgenfs/3-setup_nano_network.sh
   ```

2. **K3s Cluster**:
   ```bash
   # On Tower
   ./server/k8s-setup-validate.sh

   # On AGX
   ./agent/agx/k3s-agx-agent-setup.sh

   # On Nano
   ./agent/nano/k3s-nano-agent-setup.sh
   ```

## 🔧 Configuration

Edit `k3s-config.sh` to customize:

```bash
# Enable/disable components
INSTALL_SERVER=true
INSTALL_NANO_AGENT=true
INSTALL_AGX_AGENT=true

# Network IPs
TOWER_IP="192.168.10.1"
NANO_IP="192.168.5.21"
AGX_IP="192.168.10.11"
REGISTRY_IP="192.168.10.1"
```

## 📊 Services & Access

After successful setup, access these services:

| Service | URL | Description |
|---------|-----|-------------|
| **FastAPI (AGX)** | http://192.168.10.1:30002 | GPU-accelerated API |
| **FastAPI (Nano)** | http://192.168.5.1:30002 | Lightweight API |
| **Jupyter Lab** | http://192.168.10.1:30002/jupyter/lab | Interactive development |
| **Health Checks** | http://192.168.10.1:30002/health | System health |
| **Swagger UI** | http://192.168.10.1:30002/docs | API documentation |
| **PgAdmin** | http://192.168.10.1:30080 | Database admin (admin@pgadmin.org / pgadmin) |
| **PostgreSQL** | 192.168.10.1:30432 | Database (postgres / mysecretpassword) |

## ✅ Validation & Health Checks

Run comprehensive validation:

```bash
# Cluster validation
./validate-k3s-agent.sh

# Node-specific validation
./agent/nano/validate-nano-setup.sh  # Nano checks
./agent/agx/validate-agx-setup.sh    # AGX checks
./server/k8s-setup-validate.sh       # Server checks
```

Health checks include:
- ✅ Network connectivity between all nodes
- ✅ GPU acceleration (CUDA, TensorRT, PyTorch, TensorFlow)
- ✅ NFS storage mounts
- ✅ Database connectivity
- ✅ Application health endpoints
- ✅ Kubernetes cluster status

## 🔧 Troubleshooting

### Network Issues
- Run `./bridgenfs/inconsistencyCheck.sh` for network diagnostics
- Use `./bridgenfs/restore_backup.sh` to restore configurations
- Check `/tmp/` for backup files created during setup

### K3s Issues
- Verify cluster: `sudo kubectl get nodes`
- Check pods: `sudo kubectl get pods -A`
- View logs: `sudo kubectl logs <pod-name>`

### GPU Issues
- Check GPU status: `nvidia-smi`
- Verify runtime class: `sudo kubectl get runtimeclass`
- Check device plugin: `sudo kubectl get pods -n kube-system | grep nvidia`

### Common Issues
- **Port Conflicts**: Use `FASTAPI_PORT` environment variable (e.g., `FASTAPI_PORT=8001`)
- **Database Connection**: Verify `postgres.env` file at `/app/app/config/postgres.env`
- **Pod restart loops**: Check `/health` and `/ready` endpoints
- **GPU resource conflicts**: Verify nvidia.com/gpu allocation
- **Image pull failures**: Check registry connectivity to 192.168.5.1:5000
- **Performance issues**: Review timestamps in setup script output
- **ML Library Issues**: Check ARM64 compatibility and CPU-only configuration

### Recovery
- **Network Restore**: `./bridgenfs/restore_backup.sh` (device-specific)
- **k3s Cleanup**: `./agent/nano/cleanup-nano.sh` (removes k3s and services)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run validation scripts
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- K3s for lightweight Kubernetes
- NVIDIA Jetson ecosystem
- Docker for containerization
- NVIDIA GPU operators for Kubernetes

---

**Note**: This setup is optimized for the specific hardware configuration. Adjust network IPs and configurations as needed for your environment.