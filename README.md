# Kubernetes Container Infrastructure

## Overview

This project provides a complete Kubernetes infrastructure for deploying containerized applications across multiple devices (Tower server, AGX GPU node, and Nano CPU node). The setup includes PostgreSQL with pgvector extension, pgAdmin interface, Docker registry, and FastAPI applications optimized for each device type.

## Architecture

### Cluster Topology
```
Tower (Control Plane)          AGX Agent (GPU)          Nano Agent (CPU)
├── k3s server               ├── k3s agent             ├── k3s agent
├── PostgreSQL 16            ├── GPU workloads         ├── CPU workloads
├── pgAdmin 4                ├── FastAPI GPU           ├── FastAPI CPU
├── Docker Registry          ├── 10G network          ├── 1G network
├── NFS Server               └── 192.168.10.x         └── 192.168.5.x
└── Shared Storage
```

### Network Architecture
- **Tower Dual Networks**: 192.168.10.1/24 (10G AGX) + 192.168.5.1/24 (1G Nano)
- **AGX Node**: 192.168.10.11/24 (10G connection to Tower)
- **Nano Node**: 192.168.5.21/24 (1G connection to Tower)
- **Shared Storage**: NFS mount `/mnt/vmstore` across all devices

## Quick Start

### Prerequisites
- Ubuntu 20.04/22.04 on all devices
- SSH key authentication configured
- Network cables connected (10G for AGX, 1G for Nano)
- Internet access for initial setup

### 1. Tower Server Setup
```bash
cd /home/sanjay/containers/kubernetes/server
sudo ./k8s-setup-validate.sh
```

### 2. Network Configuration
```bash
# On Tower
sudo ./setup-tower-network.sh

# On AGX
cd /home/sanjay/containers/kubernetes/agent/agx
sudo ./setup-agx-network.sh

# On Nano
cd /home/sanjay/containers/kubernetes/agent/nano
sudo ./setup-nano-network.sh
```

### 3. Agent Setup
```bash
# On AGX
cd /home/sanjay/containers/kubernetes/agent/agx
sudo ./k3s-agx-setup.sh

# On Nano
cd /home/sanjay/containers/kubernetes/agent/nano
sudo ./k3s-nano-agent-setup.sh
```

### 4. Validation
```bash
# Check cluster status
kubectl get nodes

# Check services
kubectl get pods --all-namespaces
```

## Directory Structure

```
kubernetes/
├── ARCHITECTURE-SUMMARY.md           # Architecture overview
├── NETWORK-SETUP-GUIDE.md            # Network configuration guide
├── BRIDGE-NFS-UPDATE-SUMMARY.md      # Network script updates
├── NANO-SETUP-COMPLETE.md            # Nano setup completion
├── directorystructure.md             # Complete file inventory
├── server/                           # Tower server components
│   ├── k8s-setup-validate.sh        # Server setup script
│   ├── k8s-setup-checklist.md       # Setup checklist
│   ├── setup-tower-network.sh       # Tower network config
│   ├── docs/                        # Server documentation
│   ├── postgres/                    # PostgreSQL setup
│   └── pgadmin/                     # pgAdmin setup
└── agent/                           # Agent node setups
    ├── agx/                        # AGX GPU agent
    └── nano/                        # Nano CPU agent
```

## Component Details

### PostgreSQL + pgvector
- **Version**: PostgreSQL 16 with pgvector extension
- **Features**: Vector search, AI/ML support, multiple index types (HNSW, IVF)
- **Access**: `192.168.10.1:5432` (from cluster), `localhost:5432` (from Tower)
- **pgAdmin**: `http://192.168.10.1:8080` (default: pgadmin@pgadmin.org / admin)

### Docker Registry
- **URL**: `192.168.10.1:5000`
- **Purpose**: Local image distribution across cluster
- **Storage**: `/export/vmstore/k3sRegistry`

### FastAPI Applications
- **AGX Service**: GPU-optimized FastAPI on AGX node
- **Nano Service**: CPU-optimized FastAPI on Nano node
- **Access**: Internal cluster access via service names

## Network Configuration

### Tower (Server)
```bash
# Dual network interfaces
eno1: 192.168.10.1/24 (10G - AGX network)
eno2: 192.168.5.1/24 (1G - Nano network)

# NFS exports
/export/vmstore (shared storage for all agents)
```

### AGX Agent
```bash
# Network: 192.168.10.11/24 via eno1 (10G)
# NFS mount: /mnt/vmstore → tower:/export/vmstore
# Internet: Preserved via wireless
```

### Nano Agent
```bash
# Network: 192.168.5.21/24 via eno1 (1G)
# NFS mount: /mnt/vmstore → tower:/export/vmstore
# Internet: Preserved via wireless
```

## Kubernetes Services

### Cluster Access
```bash
# PostgreSQL service
kubectl get svc postgres-service

# pgAdmin service
kubectl get svc pgadmin-service

# FastAPI services
kubectl get svc fastapi-service      # AGX
kubectl get svc fastapi-nano-service # Nano
```

### Node Management
```bash
# Check all nodes
kubectl get nodes -o wide

# Check node-specific pods
kubectl get pods -o wide | grep agx
kubectl get pods -o wide | grep nano
```

## Troubleshooting

### Network Issues
```bash
# Test connectivity
ping 192.168.10.1    # Tower from AGX
ping 192.168.5.1     # Tower from Nano
ping 192.168.10.11   # AGX from Tower
ping 192.168.5.21    # Nano from Tower

# Check NFS mounts
df -h | grep vmstore

# Check routing
ip route show
```

### Kubernetes Issues
```bash
# Check cluster status
kubectl cluster-info

# Check node status
kubectl describe node <node-name>

# Check pod status
kubectl get pods --all-namespaces
kubectl describe pod <pod-name>

# View logs
kubectl logs <pod-name> -f
```

### Service Issues
```bash
# Check service endpoints
kubectl get endpoints

# Test service connectivity
kubectl run test --image=busybox --rm -it --restart=Never -- wget <service-name>:<port>
```

## Maintenance

### Backup Configuration
```bash
# Network configs
sudo cp /etc/netplan/*.yaml /tmp/netplan_backup/

# Application configs
cp -r /home/sanjay/containers/kubernetes/ /tmp/kubernetes_backup/
```

### Update Procedures
```bash
# Update PostgreSQL
cd server/postgres
docker build -t postgres-updated .
kubectl rollout restart deployment postgres

# Update applications
cd agent/agx  # or agent/nano
docker build -t app-updated .
kubectl rollout restart deployment <app-name>
```

### Reset Procedures
```bash
# Reset network (on agents)
sudo cp /tmp/*_netplan_backup_*/original_file.yaml /etc/netplan/
sudo netplan apply

# Reset k3s (on agents)
sudo /usr/local/bin/k3s-agent-uninstall.sh

# Reset k3s (on server)
sudo /usr/local/bin/k3s-uninstall.sh
```

## Performance Optimization

### AGX (GPU Node)
- **Network**: 10G dedicated link for high-throughput workloads
- **GPU**: NVIDIA GPU support for ML/AI workloads
- **Storage**: High-speed NFS access to shared storage
- **Scheduling**: GPU workloads automatically scheduled to AGX

### Nano (CPU Node)
- **Network**: 1G link optimized for control and monitoring
- **CPU**: ARM64 quad-core optimized for efficiency
- **Memory**: 4GB RAM with resource limits enforced
- **Scheduling**: CPU-only workloads scheduled to Nano

### Tower (Control Plane)
- **Network**: Dual interfaces for both subnets
- **Storage**: NFS server for shared storage
- **Services**: Control plane + database + registry
- **Routing**: Inter-subnet routing and internet sharing

## Security Considerations

### Network Security
- Isolated subnets (192.168.10.x, 192.168.5.x)
- SSH key authentication only
- Firewall rules for service access
- No external exposure by default

### Access Control
- Kubernetes RBAC for cluster access
- pgAdmin authentication required
- Service account tokens for automation
- Shared storage access controls

## Monitoring and Health Checks

### Built-in Health Checks
```bash
# PostgreSQL health
cd server/postgres/src
./verify_postgres.sh

# Application health
curl http://fastapi-service:8000/health
curl http://fastapi-nano-service:8000/health
```

### Kubernetes Monitoring
```bash
# Resource usage
kubectl top nodes
kubectl top pods

# Events
kubectl get events --sort-by=.metadata.creationTimestamp

# Logs aggregation
kubectl logs -l app=<app-name> --all-containers
```

## Development Workflow

### Local Development
```bash
# Use VS Code Dev Containers
# Open server/postgres or server/pgadmin
# Select "Reopen in Container"
```

### Image Building
```bash
# Build for registry
docker build -t 192.168.10.1:5000/<image-name>:latest .
docker push 192.168.10.1:5000/<image-name>:latest
```

### Deployment Updates
```bash
# Update deployment
kubectl apply -f <deployment>.yaml

# Rolling restart
kubectl rollout restart deployment <deployment-name>
```

## Support and Documentation

### Additional Resources
- [ARCHITECTURE-SUMMARY.md](ARCHITECTURE-SUMMARY.md) - Detailed architecture overview
- [NETWORK-SETUP-GUIDE.md](NETWORK-SETUP-GUIDE.md) - Network configuration details
- [server/docs/](server/docs/) - Server component documentation
- [agent/agx/README.md](agent/agx/README.md) - AGX agent documentation
- [agent/nano/README.md](agent/nano/README.md) - Nano agent documentation

### Getting Help
1. Check the troubleshooting section above
2. Review component-specific README files
3. Check logs: `kubectl logs` and `docker logs`
4. Validate network connectivity between devices
5. Ensure all prerequisites are met

---

**Last Updated**: October 2024
**Kubernetes Version**: k3s
**PostgreSQL Version**: 16 with pgvector
**Architecture**: Multi-node heterogeneous cluster</content>
<parameter name="filePath">/home/sanjay/containers/kubernetes/README.md