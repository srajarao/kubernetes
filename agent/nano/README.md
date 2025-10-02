# Jetson Nano Kubernetes Agent Setup

## Overview
Complete setup for Jetson Nano as a Kubernetes (k3s) agent node in the cluster. This configuration is optimized for the nano's limited resources and CPU-only operation.

## Directory Structure
```
/home/sanjay/containers/kubernetes/agent/nano/
├── config/
│   └── nano-config.env                 # Nano-specific configuration
├── src/
│   └── main.py                         # FastAPI application
├── k3s-nano-agent-setup.sh            # Main k3s agent setup script
├── setup-nano-network.sh              # Network configuration script
├── validate-nano-setup.sh             # Validation script
├── cleanup-nano.sh                    # Cleanup script
├── start-fastapi-nano.yaml            # Kubernetes deployment
├── dockerfile.nano.req                # Docker image definition
├── requirements.nano.txt              # Python dependencies
└── README.md                          # This file
```

## Hardware Specifications
- **Device**: NVIDIA Jetson Nano
- **CPU**: Quad-core ARM Cortex-A57 @ 1.43 GHz
- **Memory**: 4GB LPDDR4 
- **GPU**: None (CPU-only configuration)
- **Network**: Gigabit Ethernet (eno1)
- **Architecture**: ARM64

## Network Configuration
- **IP Address**: 192.168.5.21/24
- **Gateway**: 192.168.5.1 (Tower)
- **Interface**: eno1 (Gigabit Ethernet)
- **Internet**: Preserved via WiFi
- **NFS Mount**: /mnt/vmstore → tower:/export/vmstore

## Setup Instructions

### 1. Prerequisites
- Jetson Nano with Ubuntu 20.04/22.04
- Network cable connected to tower (1G interface)
- WiFi configured for internet access
- SSH access to nano device

### 2. Copy Files to Nano
```bash
# From tower, copy the entire nano directory
scp -r /home/sanjay/containers/kubernetes/agent/nano/ nano@nano-ip:/home/sanjay/containers/kubernetes/agent/
```

### 3. Network Setup
```bash
# On nano device
cd /home/sanjay/containers/kubernetes/agent/nano
sudo ./setup-nano-network.sh
```

**What this does:**
- Sets static IP 192.168.5.21 on eno1
- Preserves WiFi internet connectivity
- Mounts NFS from tower
- Tests connectivity to tower and AGX

### 4. Validate Setup
```bash
# On nano device
./validate-nano-setup.sh
```

### 5. K3s Agent Setup
```bash
# On nano device
sudo ./k3s-nano-agent-setup.sh
```

**What this does:**
- Installs k3s agent
- Joins the cluster using token from tower
- Builds and deploys FastAPI nano application
- Configures resource limits for nano

### 6. Verify Cluster Join
```bash
# From tower
kubectl get nodes
# Should show: nano-agent Ready

# Check nano pod
kubectl get pods -l app=fastapi-nano
```

## Application Details

### FastAPI Nano Service
- **Port**: 8000 (internal), 30002 (NodePort)
- **Resources**: 512Mi-2Gi memory, 250m-1000m CPU
- **Features**: CPU-only, health checks, metrics
- **Endpoints**:
  - `/` - Root status
  - `/health` - Health check
  - `/ready` - Readiness probe
  - `/info` - System information
  - `/metrics` - Prometheus metrics

### Resource Limits
```yaml
resources:
  requests:
    memory: "512Mi"
    cpu: "250m"
  limits:
    memory: "2Gi" 
    cpu: "1000m"
```

## Configuration Files

### nano-config.env
Contains all nano-specific settings:
- Network configuration (IPs, interfaces)
- Kubernetes settings (URLs, tokens)
- Path configurations
- Hardware settings (CPU-only)

### requirements.nano.txt
Minimal Python dependencies optimized for ARM64:
- FastAPI and Uvicorn
- System monitoring (psutil)
- HTTP libraries
- No GPU/CUDA packages

## Troubleshooting

### Network Issues
```bash
# Check network connectivity
ping 192.168.5.1          # Tower
ping 192.168.10.11        # AGX (if routing enabled)

# Check NFS mount
df -h | grep vmstore
ls /mnt/vmstore/

# Check routing
ip route show
```

### K3s Issues
```bash
# Check k3s agent status
sudo systemctl status k3s-agent

# Check k3s logs
sudo journalctl -u k3s-agent -f

# Check node from tower
kubectl describe node nano-agent
```

### Container Issues
```bash
# Check container logs
kubectl logs -l app=fastapi-nano

# Check pod status
kubectl get pods -o wide

# Debug pod
kubectl describe pod <fastapi-nano-pod-name>
```

### Resource Issues
```bash
# Check memory usage
free -h
htop

# Check disk space
df -h

# Check system load
uptime
```

## Performance Optimization

### Memory Management
- Single worker process (limited memory)
- Resource limits enforced
- No GPU memory allocation
- Minimal Python dependencies

### CPU Optimization
- ARM64 optimized packages
- Single-threaded FastAPI
- Efficient logging configuration
- Minimal background processes

### Network Optimization
- Dedicated 1G ethernet for cluster
- WiFi preserved for internet
- NFS for shared storage
- Efficient container networking

## Maintenance

### Update Application
```bash
# Rebuild and redeploy
cd /home/sanjay/containers/kubernetes/agent/nano
sudo docker build -t 192.168.5.1:5000/fastapi-nano:latest -f dockerfile.nano.req .
sudo docker push 192.168.5.1:5000/fastapi-nano:latest
kubectl rollout restart deployment fastapi-nano
```

### Monitor Resources
```bash
# System monitoring
htop
iostat
free -h

# Kubernetes monitoring
kubectl top nodes
kubectl top pods
```

### Backup Configuration
```bash
# Backup network configuration
sudo cp /etc/netplan/*.yaml /tmp/netplan_backup/

# Backup application configuration
cp -r /home/sanjay/containers/kubernetes/agent/nano/ /tmp/nano_backup/
```

## Cleanup

### Remove Nano from Cluster
```bash
# On nano device
./cleanup-nano.sh

# From tower, remove node
kubectl delete node nano-agent
```

### Reset Network
```bash
# Restore DHCP configuration
sudo cp /tmp/nano_netplan_backup_*/original_file.yaml /etc/netplan/
sudo netplan apply
```

## Integration with Cluster

### Service Discovery
- FastAPI nano accessible at: `fastapi-nano-service:8000`
- External access via NodePort: `nano-ip:30002`
- Health monitoring via `/health` and `/ready`

### Load Balancing
- CPU-only workloads can be scheduled on nano
- Memory-intensive workloads should avoid nano
- Use node selectors for appropriate workload placement

### Monitoring
- Prometheus metrics available at `/metrics`
- System information at `/info`
- Kubernetes native health checks