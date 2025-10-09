# 🚀 K3s Multi-Node AI Cluster with PostgreSQL & pgAdmin

This repository provides a complete, automated setup for a high-performance Kubernetes cluster optimized for AI/ML workloads on Jetson devices. It combines K3s (lightweight Kubernetes), dual-network architecture (10G + 1G), GPU acceleration, PostgreSQL database, and comprehensive application deployments.

## 🎯 What This Project Provides

### ✅ Complete AI-Ready Kubernetes Cluster
- **Automated Setup**: Single-command cluster deployment with network configuration
- **GPU Optimization**: NVIDIA GPU support with runtime classes and device plugins
- **Dual-Network Performance**: 10G dedicated link for AGX Orin, 1G for Jetson Nano
- **Database Suite**: PostgreSQL with pgvector extension + pgAdmin management interface
- **Application Suite**: FastAPI, Jupyter Lab, health monitoring, API documentation
- **Enterprise Features**: NFS storage, comprehensive health checks, automated verification

### 🏆 Performance Achievements
- **AGX Orin**: Up to 10 Gbps bandwidth with ultra-low latency for AI inference
- **Jetson Nano**: Stable 1 Gbps with preserved internet connectivity
- **Zero Interference**: Isolated networks prevent bandwidth sharing issues
- **GPU Acceleration**: CUDA, TensorRT, PyTorch, TensorFlow optimized
- **Database Performance**: pgvector extension for AI vector operations

## 🏗️ Architecture Overview

### Network Topology
```
                    TOWER (Ubuntu Server)
                    ├── 10G Port: enp1s0f1 (10.1.10.150)
                    │   └── AGX Orin (10.1.10.244) - High-performance AI
                    └── 1G Port: eno2 (192.168.5.1)
                        └── Jetson Nano (10.1.10.181) - IoT/Monitoring
```

### Cluster Components
- **Tower (Control Plane)**: K3s server, NFS storage, PostgreSQL, pgAdmin, Traefik ingress
- **AGX Orin (Agent)**: GPU-accelerated FastAPI, Jupyter Lab, AI workloads
- **Jetson Nano (Agent)**: Lightweight FastAPI, monitoring, IoT tasks

### Key Technologies
- **K3s**: Lightweight Kubernetes for edge computing (v1.33.5+k3s1)
- **Dual-Network**: Isolated 10G/1G links for optimal performance
- **NVIDIA GPU**: Runtime classes, device plugins, CUDA acceleration
- **PostgreSQL**: Advanced database with pgvector extension for AI
- **pgAdmin**: Web-based PostgreSQL management interface
- **Docker Registry**: Local image registry at tower:5000
- **NFS Storage**: Shared persistent storage across all nodes

## 📁 Project Structure

```
kubernetes/
├── k3s-config.sh                    # Configuration file (IPs, passwords, enable/disable components)
├── k3s-setup-automation.sh          # Main automated setup script (50 steps)
├── README.md                        # This comprehensive documentation
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
│       ├── k3s-agx-agent-setup.sh    # AGX K3s agent setup
│       ├── validate-agx-setup.sh    # AGX validation
│       ├── setup-agx-network.sh     # AGX network config
│       └── README.md                # AGX-specific docs
└── server/                          # Tower server components
    ├── pgadmin/                     # pgAdmin web interface
    │   ├── dockerfile.pgadmin       # pgAdmin Dockerfile
    │   ├── pgadmin-deployment.yaml  # K8s deployment (configurable)
    │   ├── pgadmin-secret.yaml      # Secrets (configurable password)
    │   └── docs/                    # pgAdmin documentation
    ├── postgres/                    # PostgreSQL database with pgvector
    │   ├── dockerfile.postgres      # PostgreSQL Dockerfile
    │   ├── postgres-db-deployment.yaml # K8s deployment (configurable)
    │   ├── postgres-pgadmin-services.yaml # Service definitions
    │   └── docs/                    # PostgreSQL documentation
    ├── docs/                        # Server documentation
    ├── jupyter/                     # Jupyter configurations
    ├── k8s-setup-validate.sh        # Server validation
    ├── postgres-pgadmin-nodeport-services.yaml # NodePort services
    └── verify-postgres-pgadmin.sh   # Comprehensive database verification
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

Edit `k3s-config.sh` to customize your deployment:

```bash
# Component Installation
INSTALL_SERVER=true          # Install K3s server on tower
INSTALL_NANO_AGENT=true      # Install K3s agent on nano
INSTALL_AGX_AGENT=true       # Install K3s agent on agx

# Network Configuration
TOWER_IP="10.1.10.150"       # Tower server IP
NANO_IP="10.1.10.181"        # Jetson Nano IP
AGX_IP="10.1.10.244"         # Jetson AGX Orin IP
REGISTRY_IP="10.1.10.150"    # Docker registry IP
REGISTRY_PORT="5000"         # Docker registry port

# Database Configuration
POSTGRES_PASSWORD="postgres"         # PostgreSQL admin password
PGADMIN_PASSWORD="pgadmin"           # pgAdmin default password
PGADMIN_EMAIL="pgadmin@pgadmin.org"  # pgAdmin default email

# Debug Mode
DEBUG=0                            # 0=silent, 1=verbose
```

### Database Password Security
- **PostgreSQL**: Configure a strong password in `POSTGRES_PASSWORD`
- **pgAdmin**: Set admin credentials in `PGADMIN_PASSWORD` and `PGADMIN_EMAIL`
- **Automatic Deployment**: Passwords are automatically applied during setup
- **Runtime Configuration**: No need to rebuild containers - passwords injected at deployment time

## 📊 Services & Access Information

After successful deployment, all access information is automatically displayed and logged. Here are the services:

### 🖥️ **Management Interfaces**
| Service | URL | Credentials | Description |
|---------|-----|-------------|-------------|
| **pgAdmin** | http://10.1.10.150:30080 | pgadmin@pgadmin.org / pgadmin | PostgreSQL web admin interface |
| **Traefik Dashboard** | http://10.1.10.150:9000 | - | Kubernetes ingress dashboard |

### 🗄️ **Database Services**
| Service | Connection | Credentials | Description |
|---------|------------|-------------|-------------|
| **PostgreSQL** | 10.1.10.150:30432 | postgres / postgres | Primary database with pgvector |
| **PostgreSQL (Alt)** | 10.1.10.150:32432 | postgres / postgres | Alternative port access |

### 🤖 **FastAPI Applications**
| Service | URL | GPU Support | Description |
|---------|-----|-------------|-------------|
| **FastAPI (Nano)** | http://10.1.10.150:30002 | CPU Only | Lightweight API on Jetson Nano |
| **Health Check** | http://10.1.10.150:30002/health | - | Application health monitoring |
| **API Docs** | http://10.1.10.150:30002/docs | - | Interactive Swagger/OpenAPI docs |
| **Jupyter Lab** | http://10.1.10.150:30003 | - | Interactive development environment |

### 🔍 **Health & Monitoring**
- **Cluster Status**: `sudo kubectl get nodes`
- **Pod Status**: `sudo kubectl get pods -A`
- **Database Health**: `./server/verify-postgres-pgadmin.sh`
- **GPU Status**: `nvidia-smi` (on GPU nodes)

### 📝 **Configuration Files**
- **pgAdmin Connection**: Use PostgreSQL connection details above
- **Environment Variables**: Check `k3s-config.sh` for current settings
- **Logs**: Deployment logs saved automatically to timestamped files

## ✅ Validation & Health Checks

Run comprehensive validation after deployment:

```bash
# Complete cluster validation (includes database verification)
./k3s-setup-automation.sh  # Runs all validation steps automatically

# Individual component validation
./validate-k3s-agent.sh                    # Cluster health check
./server/verify-postgres-pgadmin.sh        # Database verification
./agent/nano/validate-nano-setup.sh        # Nano-specific checks
./agent/agx/validate-agx-setup.sh          # AGX-specific checks
./server/k8s-setup-validate.sh             # Server validation
```

### Automated Verification Includes:
- ✅ **Network connectivity** between all nodes
- ✅ **GPU acceleration** (CUDA, TensorRT, PyTorch, TensorFlow)
- ✅ **NFS storage mounts** and permissions
- ✅ **Database connectivity** and pgvector extension
- ✅ **pgAdmin web interface** accessibility
- ✅ **FastAPI health endpoints** (/health, /docs)
- ✅ **Kubernetes cluster status** and pod health
- ✅ **Traefik ingress controller** placement
- ✅ **Node tainting** and resource allocation

### Database-Specific Checks:
```bash
# Test PostgreSQL connection
psql -h 10.1.10.150 -p 30432 -U postgres

# Verify pgvector extension
psql -h 10.1.10.150 -p 30432 -U postgres -c "SELECT * FROM pg_extension WHERE extname = 'vector';"

# Access pgAdmin web interface
open http://10.1.10.150:30080
```

## 🔧 Troubleshooting

### Database Issues
- **Connection Failed**: Verify PostgreSQL pod is running: `sudo kubectl get pods | grep postgres`
- **pgAdmin Login**: Use credentials from `k3s-config.sh` (default: pgadmin@pgadmin.org / pgadmin)
- **pgvector Extension**: Check logs: `sudo kubectl logs deployment/postgres-db`
- **Password Issues**: Update `POSTGRES_PASSWORD` in `k3s-config.sh` and redeploy

### Network Issues
- **IP Conflicts**: Current IPs: Tower=10.1.10.150, Nano=10.1.10.181, AGX=10.1.10.244
- **Network Diagnostics**: Run `./bridgenfs/inconsistencyCheck.sh`
- **Configuration Restore**: Use `./bridgenfs/restore_backup.sh`
- **Backup Location**: Check `/tmp/` for automatic backup files

### K3s & Kubernetes Issues
- **Cluster Status**: `sudo kubectl get nodes` (should show Ready status)
- **Pod Issues**: `sudo kubectl get pods -A` (check for CrashLoopBackOff)
- **Traefik Placement**: Ensure pods aren't scheduled on agent nodes
- **Logs**: `sudo kubectl logs <pod-name> -n <namespace>`

### GPU Issues
- **GPU Detection**: Run `nvidia-smi` on GPU nodes
- **Runtime Classes**: `sudo kubectl get runtimeclass` (should show nvidia)
- **Device Plugin**: `sudo kubectl get pods -n kube-system | grep nvidia`
- **Resource Allocation**: Check `nvidia.com/gpu: 1` in pod specs

### Application Issues
- **FastAPI Health**: Check http://10.1.10.150:30002/health
- **API Documentation**: Visit http://10.1.10.150:30002/docs
- **Jupyter Access**: http://10.1.10.150:30003 (token required)
- **Port Conflicts**: Verify NodePort assignments (30002, 30003, 30080, 30432)

### Common Recovery Steps
- **Database Reset**: Delete and redeploy PostgreSQL: `sudo kubectl delete deployment postgres-db`
- **Network Restore**: `./bridgenfs/restore_backup.sh` (device-specific)
- **Complete Cleanup**: `./agent/nano/cleanup-nano.sh` (removes k3s and services)
- **GPU Reset**: `sudo systemctl restart nvidia-device-plugin-daemonset`

### Performance Optimization
- **Network Performance**: Verify 10G link for AGX, 1G for Nano
- **GPU Utilization**: Monitor with `nvidia-smi` during AI workloads
- **Database Tuning**: Adjust PostgreSQL resource limits in deployment YAML
- **Storage I/O**: Check NFS mount performance for persistent volumes

## 🚀 New Features (Latest Update)

### ✅ Automated Database Deployment
- **PostgreSQL + pgvector**: Automatic deployment with vector extension for AI workloads
- **pgAdmin Integration**: Web-based database management interface
- **Configurable Passwords**: Secure credential management via `k3s-config.sh`
- **Health Verification**: Comprehensive database connectivity and extension checks

### ✅ Enhanced Automation
- **50 Step Process**: Complete end-to-end cluster setup
- **Access Information Display**: Automatic endpoint reporting on successful deployment
- **Comprehensive Logging**: All operations logged with timestamps
- **Traefik Optimization**: Automatic node placement for ingress controller

### ✅ Production-Ready Features
- **Security**: Configurable passwords, no hardcoded credentials
- **Monitoring**: Health checks, readiness probes, comprehensive validation
- **Documentation**: Auto-generated API docs, interactive Swagger UI
- **Scalability**: Resource limits, GPU optimization, network isolation

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes with comprehensive testing
4. Update documentation as needed
5. Run validation scripts: `./server/verify-postgres-pgadmin.sh`
6. Commit with clear messages: `git commit -m "feat: Add your feature"`
7. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **K3s Team**: Lightweight Kubernetes for edge computing
- **NVIDIA Jetson Ecosystem**: GPU-accelerated edge computing platform
- **PostgreSQL Community**: Advanced open-source database
- **pgAdmin Team**: Comprehensive database management interface
- **pgvector Extension**: Vector similarity search for AI applications
- **Docker Community**: Containerization technology
- **NVIDIA GPU Operators**: Kubernetes GPU resource management

---

## 📞 Support & Resources

- **Issues**: Report bugs via GitHub Issues
- **Discussions**: Join community discussions
- **Documentation**: Check component-specific READMEs in subdirectories
- **Validation**: Always run `./server/verify-postgres-pgadmin.sh` after changes

---

**🎯 Note**: This setup is optimized for the specific hardware configuration (Tower + AGX Orin + Jetson Nano). Adjust network IPs and configurations as needed for your environment. The automated script handles 95% of the setup complexity, making deployment reliable and repeatable.