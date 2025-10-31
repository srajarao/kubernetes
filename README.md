# 🚀 K3s Multi-Node AI Cluster with PostgreSQL, pgAdmin & VPN Gateway

**� CURRENT STATUS: KUBERNETES CLUSTER OPERATIONAL WITH VPN GATEWAY & CLUSTER MANAGEMENT** - K3s agents running on 4 GPU worker nodes, Blackwell GPU support active, OpenVPN gateway on Krithi providing secure remote access, comprehensive network integration, shared storage, and complete web-based cluster management system.

This repository provides a complete, automated setup for a high-performance Kubernetes cluster optimized for AI/ML workloads on Jetson devices. It combines K3s (lightweight Kubernetes), dual-network architecture (10G + 1G), GPU acceleration, PostgreSQL database, comprehensive application deployments, **secure VPN gateway access**, and **enterprise-grade cluster management interface** with **production-ready stability verification**.

**🎯 October 31, 2025 Update**: Blackwell GPU support successfully implemented with NVIDIA GPU Operator for DGX Spark nodes. GPU operator deployment configurations created for Spark1 and Spark2 nodes, replacing manual device mounting approach. **✅ Blackwell GB10 GPUs now fully operational with TensorFlow, PyTorch, and TensorRT support.** Krithi VPN gateway fully integrated with complete network access, NFS client functionality, and OpenVPN server configuration. **🖥️ Cluster Management Application fully deployed** with comprehensive web interface, real-time monitoring, script execution, and enterprise security features.

## 🎯 What This Project Provides

### ✅ Complete AI-Ready Kubernetes Cluster
- **Automated Setup**: Single-command cluster deployment with network configuration
- **GPU Optimization**: NVIDIA GPU support with runtime classes, device plugins, and Blackwell GB10 compatibility
- **Dual-Network Performance**: 10G dedicated link for AGX Orin, 1G for Nano, optimized for DGX Spark devices
- **Application Stack**: FastAPI with GPU acceleration, PostgreSQL with pgvector, pgAdmin
- **🖥️ Cluster Management**: Complete web-based administrative interface with real-time monitoring, script execution, and node management
- **Secure Remote Access**: OpenVPN gateway on Krithi for encrypted external connectivity
- **Shared Storage**: NFS server on tower with client access across all nodes
- **Production Ready**: Comprehensive stability verification and monitoring
- **96-Step Automation**: Complete end-to-end deployment with validation
- **🆕 Centralized Build System**: Build images once on tower, deploy efficiently to all nodes
- **🆕 Config Change Detection**: Intelligent caching prevents unnecessary rebuilds
- **🆕 Parameterized Configuration**: Flexible Docker image variants for nano/AGX hardware
- **🆕 Flexible Image Management**: 4 Docker deployment modes for online/offline environments
- **🔥 Hot Reload Development**: Real-time code updates without container rebuilds

## � **Directory Structure Overview**

- `agent/` - Contains subfolders for each node (agx, nano, spark1, spark2) with deployment scripts, configs, and apps
  - `spark1-gpuoperator/` - NVIDIA GPU Operator deployment configuration for Spark1 Blackwell GPU
  - `spark2-gpuoperator/` - NVIDIA GPU Operator deployment configuration for Spark2 Blackwell GPU
- `archive/` - Backup scripts, old configs, and health checks
- `cluster-management/` - **🆕 Web-based cluster management application** with real-time monitoring, script execution, and node management
- `docs/` - Documentation and project plans
- `images/` - Built images and configs for containerization
- `rag/` - Reference and deployment files for RAG (Retrieval-Augmented Generation) workflows
- `scripts/` - Utility scripts for environment setup, monitoring, and validation
- `server/` - Server-side deployment scripts, configs, and Docker requirements

## 🔧 **Key Configuration Files**

- `.env` and `*.env` files for environment variables
- `requirements.*.txt` for Python dependencies
- `dockerfile.*` for container builds
- `*.yaml` for Kubernetes deployments

## 🖥️ **Cluster Management Application**

**🆕 Web-Based Cluster Management System** - Complete administrative interface for cluster operations, monitoring, and management.

### **🎯 Application Overview**
- **Framework**: FastAPI web application with modern HTML/CSS/JavaScript interface
- **Architecture**: Dedicated management node (nano) - eliminates chicken-and-egg deployment problems
- **Deployment**: Automated deployment scripts with instant updates during development
- **Security**: JWT-based authentication with role-based access control (Admin/Operator/Viewer)
- **Real-time**: WebSocket integration for live script execution and monitoring

### **✨ Key Features**
- **🌳 Tree-Based Visualization**: Hierarchical cluster structure display with node status
- **📜 Script Execution**: 94+ discovered scripts with real-time output streaming
- **🔄 Multi-Node Operations**: Select and operate on multiple nodes simultaneously
- **🐳 Docker Integration**: Complete container management and building capabilities
- **📊 Node Monitoring**: Real-time ping, SSH connectivity, and health checks
- **🔍 Comprehensive Health Checks**: Full system diagnostic testing (12+ component checks)
- **📝 Advanced Logging**: Terminal output, URL tracing, and command recording for firewall compliance
- **📚 Documentation System**: Integrated man pages and wiki interface
- **🤖 AI Context**: One-click context gathering for seamless AI assistant communication
- **🔐 Enterprise Security**: Password hashing, session management, audit logging

### **🌐 Access Points**
- **HTTP (Demo)**: `http://192.168.1.181:8000/` - Clean browser access, no warnings
- **HTTPS (Production)**: `https://192.168.1.181:8443/` - Encrypted with auto-generated SSL certificates
- **Health Check**: `https://192.168.1.181:8443/health` - System status endpoint
- **API Documentation**: `https://192.168.1.181:8443/docs` - Interactive FastAPI docs

### **🛠️ Development & Deployment**
- **Development**: Edit on Tower (`~/containers/kubernetes/cluster-management/`)
- **Deployment**: `./cluster-management/quick_deploy.sh` - Instant deployment to nano
- **Setup**: `./cluster-management/deploy_to_nano.sh` - Complete environment setup
- **Architecture**: Tower (development) ↔ Nano (production) with SSH automation

### **📋 API Capabilities**
- **Script Management**: Discovery, execution, and real-time monitoring
- **Node Operations**: Add/remove agents and servers, cluster visualization
- **Docker Operations**: Image building, container management, real-time builds
- **Authentication**: JWT tokens, user management, role-based permissions
- **Monitoring**: Health checks, system diagnostics, performance metrics
- **Documentation**: Man pages, wiki interface, searchable content
- **Logging**: Terminal output capture, URL tracing, audit trails
- **AI Integration**: Context gathering for seamless AI communication

### **🔒 Security Features**
- **User Authentication**: Secure login with password hashing
- **Role-Based Access**: Admin, Operator, and Viewer permissions
- **Session Management**: JWT tokens with expiration and renewal
- **Audit Logging**: Complete activity tracking and compliance
- **SSL/TLS**: Auto-generated certificates for encrypted communication

### **📈 Current Status**
- **Phase**: 7/7 Complete - Production Ready
- **Features**: All core functionality implemented and tested
- **Health**: Comprehensive health checks passing
- **Documentation**: Complete with man pages and wiki
- **Security**: Enterprise-grade authentication and authorization
- **Performance**: Optimized for real-time operations and monitoring

**🎯 October 31, 2025 Update**: Advanced logging and tracing features added for firewall compliance. AI context button implemented for seamless communication recovery. Comprehensive health check system deployed for demo reliability. All features production-ready with enterprise security.

## �🖥️ **Current Cluster Status** (October 31, 2025)

### � **Cluster Status Update**
- **Status**: ✅ **FULLY OPERATIONAL WITH CLUSTER MANAGEMENT** - Blackwell GPU Operator automated, VPN gateway integrated, cluster management application deployed with enterprise features
- **Infrastructure**: Updated with Comcast Business Router → ER605 Router → 10G Unifi Switch topology
- **GPU Verification**: All GPU checks passed - TensorFlow, PyTorch, TensorRT, cuSPARSELt, cuDNN all functional on Blackwell GB10 (CUDA 12.1)
- **Registry Configuration**: HTTP registry properly configured for both K3s and containerd
- **VPN Gateway**: Krithi fully operational as OpenVPN gateway with complete cluster network access
- **Network Integration**: All 6 nodes (tower, nano, agx, spark1, spark2, krithi) with full connectivity
- **Shared Storage**: NFS server on tower with client access on all nodes including krithi
- **Script Automation**: k3s-spark1.sh fully automated - handles registry config, service restarts, job cleanup, GPU operator readiness, containerd configuration, and containerd restarts
- **Management Scripts**: Complete suite of agent removal and memory monitoring scripts available
- **🖥️ Cluster Management**: Web-based administrative interface fully deployed on nano node with real-time monitoring, script execution, and enterprise security
- **Last Updated**: October 30, 2025

### 🏗️ **Cluster Architecture**
```
Comcast Business Router → ER605 Router → 10G Unifi Switch → Cluster Nodes
Tower (Control Plane)    Nano (GPU Node)    AGX (GPU Node)    DGX-Spark-1        DGX-Spark-2        Krithi (VPN Gateway)
├── K3s Server          ├── FastAPI App    ├── FastAPI App   ├── K3s Agent       ├── K3s Agent       ├── OpenVPN Server
│   (Removed)           ├── Jupyter Lab    ├── Jupyter Lab   │   Operational     │   Operational     ├── Network Access
├── Docker Registry     ├── GPU Runtime    ├── GPU Runtime   ├── GPU Operator    ├── GPU Operator    ├── NFS Client
├── PostgreSQL          ├── NVIDIA GPU     └── NVIDIA GPU    ├── Blackwell GB10   ├── Blackwell GB10   ├── Host Resolution
├── pgAdmin             └── Node Affinity  └── Node Affinity  │   ✅ Verified      │   Ready           └── Remote Access
└── Monitoring          └── Health Checks  └── Health Checks  └── 192.168.1.201     └── 192.168.1.202   └── 192.168.1.100
└── NFS Server          └── Node Affinity  └── Node Affinity
```

### 📊 **Cluster Nodes**
| Node           | IP Address    | Role                            | GPU Support      | Status                    |
|----------------|--------------|----------------------------------|------------------|---------------------------|
| **Tower**      | 192.168.1.150  | Control Plane, Registry, Storage | -                | 🟡 k3s Server Removed     |
| **Nano**       | 192.168.1.181  | GPU Worker Node                  | Jetson Nano GPU  | ✅ Operational (Agent)    |
| **AGX**        | 192.168.1.244  | GPU Worker Node                  | AGX Orin GPU     | ✅ Operational (Agent)    |
| **DGX-Spark-1**| 192.168.1.201  | GPU Worker Node                  | Blackwell GB10   | ✅ Operational (Agent + GPU Op) |
| **DGX-Spark-2**| 192.168.1.202  | GPU Worker Node                  | Blackwell GB10   | ✅ Operational (Agent + GPU Op) |
| **Krithi**     | 192.168.1.100  | VPN Gateway & Network Access     | -                | ✅ Operational (VPN + NFS) |

### 🆕 **DGX-Spark Devices Integration**
The DGX-Spark devices (`192.168.1.201` and `192.168.1.202`) are integrated into the K3s cluster with **Blackwell GB10 GPU support** via NVIDIA GPU Operator. Both devices feature factory-installed NVIDIA drivers and are configured for optimal AI/ML workloads. The devices are interconnected via 200G transceiver connections for high-speed communication between Spark1 and Spark2 nodes.

**GPU Operator Deployment**:
- **Spark1**: `agent/spark1-gpuoperator/` - Complete GPU operator configuration with automated installation
- **Spark2**: `agent/spark2-gpuoperator/` - Complete GPU operator configuration with automated installation
- **Blackwell Compatibility**: NVIDIA GPU Operator v24.9.0 configured for pre-installed drivers and Blackwell GB10 GPUs
- **Resource Management**: Standard Kubernetes GPU scheduling with `nvidia.com/gpu` resource allocation

### 🌐 **Network Architecture & Performance**

#### **Dual-Network Design**
- **10G Network** (`192.168.10.0/24`): Dedicated high-performance link for AGX Orin and Spark devices
- **1G Network** (`192.168.5.0/24`): Reliable connectivity for Nano with preserved internet access
- **Tower NAT**: Provides internet access to all devices through dual-interface routing
- **NFS Storage**: Centralized `/workspace` mount point accessible by all nodes

#### **Performance Achievements**
- **AGX Orin**: Up to 10 Gbps bandwidth for AI/ML workloads
- **Jetson Nano**: Up to 1 Gbps dedicated bandwidth with stable internet
- **DGX Spark**: 10G connectivity with GPU-optimized data transfer
- **Network Isolation**: Zero bandwidth interference between device types

#### **Network Configuration Scripts**
Located in `scripts/` directory for advanced network setup:
- **Tower Setup**: Dual-interface configuration, NFS server, internet sharing
- **Device Setup**: Network configuration, NFS mounting, SSH key distribution
- **Performance Optimization**: Jumbo frames, optimized routing, bandwidth isolation

### 🔐 **VPN Gateway & Remote Access (Krithi)**

**Krithi** (`192.168.1.100`) serves as the secure VPN gateway for external access to the cluster network:

#### **OpenVPN Configuration**
- **External Access**: Secure remote connectivity to cluster resources
- **Encrypted Tunneling**: Full VPN encryption for all external connections
- **Network Integration**: Complete access to all cluster nodes and services
- **Authentication**: Certificate-based VPN authentication

#### **Network Services**
- **Host Resolution**: Full DNS resolution for all cluster nodes
- **NFS Client**: Direct access to shared storage from tower
- **SSH Access**: Passwordless authentication to all cluster nodes
- **Network Monitoring**: Connectivity validation and health checks

#### **Access Methods**
- **Direct SSH**: `ssh krithi` for cluster network access
- **VPN Tunnel**: OpenVPN connection for secure remote access
- **Storage Access**: NFS mount access to `/mnt/vmstore` (7.3TB shared storage)
- **Service Proxy**: Access to all cluster services through VPN tunnel

### 🚀 **Access Information**

#### **PostgreSQL Database**
- **Direct Access**: `192.168.1.150:30432`
- **Username**: `postgres`
- **Password**: `postgres`
- **Status**: ✅ Connected and verified

#### **pgAdmin Management Interface**
- **Web UI**: `http://192.168.1.150:30080`
- **Username**: `pgadmin@pgadmin.org`
- **Password**: `pgadmin`
- **Status**: ✅ Accessible (HTTP 302 redirect normal)

#### **FastAPI Applications**
- **Nano GPU API**: `http://192.168.1.150:30002`
  - Health: `http://192.168.1.150:30002/health` ✅
  - Docs: `http://192.168.1.150:30002/docs` ✅
  - Jupyter: `http://192.168.1.150:30003` ✅
- **AGX GPU API**: `http://192.168.1.150:30004`
  - Health: `http://192.168.1.150:30004/health` ✅
  - Docs: `http://192.168.1.150:30004/docs` ✅
  - Jupyter: `http://192.168.1.150:30005` ✅
  - LLM API: `http://192.168.1.150:30006` ⚠️ (Not implemented)

#### **Verification & Monitoring**
- **Comprehensive Report**: `./server/verify_all_fixed.sh` (standalone verification)
- **Integrated Verification**: `steps 94-95` in `./k3s.sh` (automated verification and pod verification)
- **Database Validation**: `./server/verify-postgres-pgadmin.sh`
- **Backup System**: `./backup_home.sh` (cross-device environment backup)
- **Real-time Monitoring**: All services include health endpoints and status checks

### 📈 **System Health**
- **Pods**: 4/4 running (fastapi-nano, fastapi-agx, postgres-db, pgadmin)
- **Kubernetes Nodes**: 4/4 ready (nano, agx, spark1, spark2)
- **Network Nodes**: 6/6 operational (tower, nano, agx, spark1, spark2, krithi)
- **Services**: All NodePort services operational
- **GPU Runtime**: NVIDIA runtime classes and device plugins active
- **Network**: All endpoints responding correctly
- **VPN Gateway**: Krithi OpenVPN server operational
- **Shared Storage**: NFS server and clients fully functional

## 🔧 **Recent Updates (October 31, 2025)**

### 🟢 **Krithi VPN Gateway Integration**
- **VPN Gateway Setup**: Krithi configured as OpenVPN server for secure external access to cluster network
- **Network Integration**: Full host file resolution and connectivity to all cluster nodes
- **NFS Client**: Complete shared storage access with persistent mount configuration
- **SSH Authentication**: Passwordless key-based authentication to all cluster nodes
- **Network Validation**: Comprehensive connectivity testing and monitoring capabilities

### 🟢 **Blackwell GPU Support Implementation**
- **GPU Operator Deployment**: Created dedicated GPU operator configurations for Spark1 and Spark2 DGX nodes
- **Blackwell Compatibility**: Implemented NVIDIA GPU Operator v24.9.0 with pre-installed driver support for Blackwell GB10 GPUs
- **Resource Management**: Replaced manual device mounting with proper Kubernetes GPU resource allocation (`nvidia.com/gpu`)
- **Deployment Scripts**: Updated `k3s-spark1.sh` with automated GPU operator installation and configuration
- **Documentation**: Added comprehensive GPU operator setup guides and Blackwell-specific configurations

### 🟡 **Infrastructure & Cluster Management Updates**
- **Network Topology**: Updated to Comcast Business Router → ER605 Router → 10G Unifi Switch → Cluster Nodes
- **K3s Server Removal**: Executed 05-rmvserver.sh, cleanly removed k3s server from Tower
- **Agent Removal Scripts**: Created comprehensive removal scripts for all agents (01-rmvagent-spark2.sh through 04-rmvagent-nano.sh)
- **Memory Monitoring**: Implemented memory check scripts for all nodes (01-memcheck-spark2.sh through 05-memcheck-agx.sh)
- **TLS Certificate Updates**: Regenerated certificates with new IP addresses post-migration
- **Cluster Connectivity**: Verified post-certificate update across all nodes
- **🆕 Cluster Management Application**: Complete web-based cluster management system deployed on dedicated nano node with tree visualization, node monitoring, and multi-node operations
- **🆕 Security & Authentication**: JWT-based user authentication with role-based access control (Admin/Operator/Viewer roles)

### 🚀 **Cluster Management Application**
A comprehensive web-based cluster management system has been implemented and deployed on the dedicated **nano management node** (`192.168.1.181:8000`).

**Key Features:**
- 🌳 **Tree-based Cluster Visualization**: Hierarchical display of all 6 cluster nodes (Tower, Nano, AGX, DGX-Spark-1, DGX-Spark-2, Krithi)
- 📊 **Real-time Node Monitoring**: Live status checking with ping and SSH connectivity verification
- 🎯 **Multi-Node Operations**: Select and operate on multiple nodes simultaneously
- 📂 **Script Management**: Catalog and execute 94+ cluster management scripts with real-time output streaming
- 🐳 **Docker Integration**: Complete container management and building with WebSocket streaming
- 🔍 **Comprehensive Health Checks**: 12-component system diagnostic testing for demo reliability
- 📝 **Advanced Logging**: Terminal output capture, URL tracing, and command recording for firewall compliance
- 📚 **Documentation System**: Integrated man pages and wiki interface with searchable content
- 🤖 **AI Context Integration**: One-click context gathering for seamless AI assistant communication
- 🔐 **Enterprise Security**: JWT authentication with role-based access control (Admin/Operator/Viewer)
- 🔄 **WebSocket Streaming**: Live output for all operations and real-time updates

**Access Points:**
- **HTTP (Demo)**: `http://192.168.1.181:8000/` - Clean browser access
- **HTTPS (Production)**: `https://192.168.1.181:8443/` - SSL encrypted with auto-generated certificates
- **Health Check**: `https://192.168.1.181:8443/health` - System status endpoint
- **API Documentation**: `https://192.168.1.181:8443/docs` - Interactive FastAPI documentation

**Status:** ✅ **PRODUCTION READY** - All 7 development phases completed with enterprise-grade security, comprehensive monitoring, and full cluster management capabilities

### 🛠️ **Management Tools**

#### **Server Utils**
This directory contains utility scripts and tools for managing the k3s cluster server components.

**Network Connectivity Check Scripts**  
Located in the `server/utils/ping/` subdirectory, these scripts provide comprehensive network connectivity testing for all cluster nodes.

- **01-check-nat-ping-tower.sh**: Performs comprehensive network connectivity and configuration checks from the Tower server
- **02.check-nat-ping-agx.sh**: Performs network connectivity checks from AGX's perspective by SSHing into AGX from Tower
- **03-check-nat-ping-spark1.sh**: Performs network connectivity checks from Spark1's perspective by SSHing into Spark1 from Tower
- **04-check-nat-ping-spark2.sh**: Performs network connectivity checks from Spark2's perspective by SSHing into Spark2 from Tower
- **05-check-nat-ping-nano.sh**: Performs network connectivity checks from Nano's perspective by SSHing into Nano from Tower

Each script checks node connectivity, default gateway configuration, DNS resolution, and shows network diagnostics. All scripts require SSH key authentication and test bidirectional connectivity across all cluster nodes.

**Other Utility Directories**:
- **agent/**: Scripts for managing k3s agent nodes
- **memory/**: Memory monitoring and management utilities
- **nfs/**: NFS configuration and management scripts
- **ssh/**: SSH key management and configuration utilities

**GPU Operator Configurations**:
- **spark1-gpuoperator/**: Complete GPU operator deployment for Spark1 Blackwell GPU with automated Helm installation
- **spark2-gpuoperator/**: Complete GPU operator deployment for Spark2 Blackwell GPU with automated Helm installation

- **Removal Scripts**: Standardized cleanup procedures for k3s components across all nodes
- **Monitoring Scripts**: Cross-platform memory monitoring with system health reporting
- **Documentation**: Updated READMEs in utils/ and root directories with current status

## � GPU Configuration & Testing Guide

### ✅ **GPU Access Strategy: NVIDIA GPU Operator for Blackwell GPUs**
**Status**: ✅ **UPDATED** - NVIDIA GPU Operator implementation for DGX Spark Blackwell GB10 GPUs with pre-installed drivers

**Key Configuration for DGX Spark Nodes**:
- **GPU Operator**: Official NVIDIA GPU Operator v24.9.0 for Blackwell GPU support
- **Pre-installed Drivers**: Configured for factory-installed NVIDIA drivers (`driver.enabled=false`)
- **Container Toolkit**: Enabled NVIDIA Container Toolkit (`toolkit.enabled=true`)
- **Runtime**: Containerd runtime (`operator.defaultRuntime=containerd`)
- **Resource Management**: Standard `nvidia.com/gpu` resource requests/limits
- **Deployment Architecture**: GPU Operator managed pods with proper resource allocation

### 🏗️ **GPU Operator vs Manual Device Mounting**
- **GPU Operator** (`agent/spark*-gpuoperator/`): Production-ready with proper resource management, monitoring, and Blackwell compatibility
- **Manual Device Mounting** (`agent/spark*/`): Legacy workaround for Blackwell GPU NVML issues, bypasses Kubernetes scheduling

### 🔧 **DGX Spark GPU Operator Deployment**
Located in `agent/spark1-gpuoperator/` and `agent/spark2-gpuoperator/` directories:

**Automated GPU Operator Installation**:
- Helm-based deployment with Blackwell-compatible configuration
- Automatic Helm installation if not present on system
- Pre-configured for DGX Spark factory driver installations
- Comprehensive GPU resource management and monitoring

**GPU Workload Deployment**:
- Standard Kubernetes GPU resource requests (`nvidia.com/gpu: 1`)
- NVIDIA runtime class for container execution
- No privileged security context required
- Proper GPU device allocation and cleanup

### 🔧 **Hardware Resource Verification**
Before deploying GPU workloads, verify actual hardware resources:

```bash
# Spark2 Node Hardware Check
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null sanjay@192.168.1.202 \
  "echo '=== CPU Information ===' && nproc && echo && \
   echo '=== Memory Information ===' && free -h && echo && \
   echo '=== GPU Information ===' && nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits"
```

**Spark2 Hardware Specs**:
- **CPU**: 20 cores
- **Memory**: 119Gi total, 115Gi available
- **GPU**: NVIDIA GB10
- **Resource Limits**: 20 CPU, 119Gi memory (matches hardware)

### 🧪 **GPU Functionality Testing**
After deployment, verify GPU access with these commands:

#### **Pod Status Check**
```bash
kubectl get pods -l app=spark2
# Should show: 1/1 Running
```

#### **GPU Device Access**
```bash
kubectl exec spark2-<pod-id> -- ls -la /dev/ | grep nvidia
# Should list: nvidia0, nvidiactl, nvidia-uvm, nvidia-modeset, nvidia-uvm-tools, nvidia-caps
```

#### **PyTorch GPU Validation**
```bash
kubectl exec spark2-<pod-id> -- python3 -c "
import torch
print('CUDA available:', torch.cuda.is_available())
print('CUDA version:', torch.version.cuda)
print('GPU count:', torch.cuda.device_count())
print('GPU name:', torch.cuda.get_device_name(0))
"
# Expected: CUDA available: True, CUDA 13.0, 1 GPU, NVIDIA GB10
```

#### **TensorFlow GPU Validation**
```bash
kubectl exec spark2-<pod-id> -- python3 -c "
import tensorflow as tf
print('TF built with CUDA:', tf.test.is_built_with_cuda())
print('TF GPU available:', tf.test.is_gpu_available(cuda_only=False))
print('GPUs detected:', len(tf.config.list_physical_devices('GPU')))
"
# Expected: TF built with CUDA: True, TF GPU available: True, GPUs: 1
```

#### **TensorRT Validation**
```bash
kubectl exec spark2-<pod-id> -- python3 -c "
import tensorrt as trt
print('TensorRT version:', trt.__version__)
logger = trt.Logger(trt.Logger.INFO)
builder = trt.Builder(logger)
print('Builder created successfully')
network = builder.create_network()
config = builder.create_builder_config()
print('TensorRT basic functionality test passed!')
"
# Expected: TensorRT 10.8.0.43, successful builder/network/config creation
```

#### **GPU Matrix Multiplication Test**
```bash
# PyTorch GPU computation
kubectl exec spark2-<pod-id> -- python3 -c "
import torch
device = torch.device('cuda')
a = torch.randn(2000, 2000).to(device)
b = torch.randn(2000, 2000).to(device)
c = torch.matmul(a, b)
result = c.cpu()
print('PyTorch GPU matrix multiplication: SUCCESS')
print('Result shape:', result.shape)
"
```

### ⚠️ **Known Limitations**
- **TensorRT Convolution**: Limited on CC 12.1 GPUs (shader generation issues)
- **Device Plugin**: NVIDIA device plugin incompatible with Blackwell GB10
- **Host Libraries**: Avoid mounting host CUDA libraries (version conflicts)

### 🎯 **GPU Health Check Results**
**Status**: ✅ **ALL TESTS PASSING**
- ✅ libstdc++: PASS
- ✅ cuSPARSELt: PASS
- ✅ PyTorch: PASS (CUDA 13.0, NVIDIA GB10)
- ✅ TensorFlow: PASS (GPU computation working)
- ✅ TensorRT: PASS (with CC 12.1 limitations noted)

## 🚀 Spark2 DGX Agent Setup & GPU Health Validation

### 🎯 **Spark2 Agent Overview**
**Status**: ✅ **FULLY OPERATIONAL** - DGX Spark device with comprehensive GPU health validation

The Spark2 agent runs a streamlined health-check application that validates GPU functionality across all major frameworks and exits with status codes. Designed for production GPU validation without persistent services.

### 📊 **Spark2 Device Specifications**
- **Hardware**: DGX Spark with NVIDIA GB10 GPU
- **IP Address**: 192.168.1.202
- **CPU**: 20 cores
- **Memory**: 119Gi total, 115Gi available
- **GPU**: NVIDIA GB10 (CC 12.1 architecture)
- **Architecture**: ARM64/aarch64
- **Network**: Connected to Tower K3s server (192.168.1.150:6443)

### 🏗️ **Spark2 Agent Architecture**
```
Tower (192.168.1.150)           Spark2 Agent (192.168.1.202)
├── K3s Server               ├── K3s Agent
├── PostgreSQL               ├── GPU Health Validation
├── Docker Registry          ├── CUDA/PyTorch/TensorFlow/TensorRT
└── Container Images         └── Exit with Status Code
```

### 📁 **Spark2 Agent Files Structure**
```
agent/spark2/
├── spark2_app.py              # Main health-check application
├── requirements.spark2.txt    # Minimal dependencies (uses wheels)
├── wheels/                    # Pre-downloaded Python packages
│   ├── fastapi-0.120.0-py3-none-any.whl
│   ├── torch-*whl (downloaded at build time)
│   └── ... (other packages)
├── build.sh                   # Optimized Docker build script
├── dockerfile.spark2.wheels   # Wheels-based Dockerfile
├── k3s-spark2.sh             # Complete agent setup script
├── fastapi-deployment-spark2.yaml  # Kubernetes Job definition
└── app/config/               # Application configuration
```

### 🔧 **Spark2 Build & Deployment Process**

#### **1. Optimized Container Build**
```bash
cd agent/spark2

# Build with pre-downloaded wheels (fast, offline)
./build.sh

# Or force clean build
./build.sh --clean
```

**Build Features**:
- **Wheels-Based**: Pre-downloaded packages for fast builds
- **PyTorch Download**: Fetches latest CUDA 13.0 wheels from official repo
- **ARM64 Optimized**: Cross-compilation for aarch64 architecture
- **NVIDIA Runtime**: GPU-enabled container with CUDA support

#### **2. Agent Deployment**
```bash
# Complete K3s agent setup and registration
./k3s-spark2.sh

# Deploy GPU health check Job
kubectl apply -f fastapi-deployment-spark2.yaml
```

#### **3. Health Validation**
```bash
# Check Job status
kubectl get jobs spark2
# Expected: Complete 1/1

# View health check results
kubectl logs job/spark2

# Verify GPU functionality
kubectl exec spark2-<pod-id> -- nvidia-smi
```

### 🩺 **Comprehensive Health Checks**

The Spark2 agent performs **6 comprehensive validation checks**:

#### **1. Library Loading Tests**
```bash
✅ libstdc++.so.6 - C++ standard library
✅ libcusparseLt.so - cuSPARSELt GPU library
```

#### **2. PyTorch GPU Validation**
```bash
✅ CUDA availability and version check
✅ GPU device detection (NVIDIA GB10)
✅ GPU memory allocation and computation
✅ CUDA 13.0 compatibility verification
```

#### **3. TensorFlow GPU Validation**
```bash
✅ CUDA build verification
✅ GPU device detection and memory access
✅ Matrix multiplication on GPU
✅ GPU computation performance validation
```

#### **4. TensorRT Validation**
```bash
✅ Core functionality (Builder/Network/Config)
✅ GPU capability detection (TF32, FP16, INT8)
✅ Working operations (Identity, ReLU layers)
⚠️ Convolution operations limited (CC 12.1 known limitation)
```

#### **5. Database Connectivity** (Optional)
```bash
✅ PostgreSQL connection test (if enabled)
✅ pgvector extension availability
```

#### **6. System Resources**
```bash
✅ CPU core count (20 cores verified)
✅ Memory availability (119Gi verified)
✅ GPU device access (/dev/nvidia* mounts)
```

### 📊 **Health Check Exit Codes**
- **0**: ✅ All checks passed
- **1**: ❌ libstdc++ load failed
- **2**: ❌ cuSPARSELt load failed
- **3**: ❌ PyTorch check failed
- **4**: ❌ TensorFlow check failed
- **5**: ❌ TensorRT check failed
- **7**: ❌ Database connection failed

### 🐳 **Container Optimization Features**

#### **Wheels-Based Build System**
- **Fast Builds**: Pre-downloaded packages skip pip installs
- **Offline Capable**: Most packages don't require internet
- **Version Consistency**: Locked package versions
- **Reduced Build Time**: ~5-10x faster than pip installs

#### **PyTorch CUDA Optimization**
- **Latest Wheels**: Downloads current PyTorch with CUDA 13.0
- **GPU Compatibility**: Optimized for NVIDIA GB10 architecture
- **Memory Efficient**: Minimal container footprint

#### **NVIDIA Runtime Integration**
- **Direct GPU Access**: Privileged container with device mounts
- **Runtime Class**: Uses `nvidia` container runtime
- **Device Plugin Bypass**: Direct `/dev/nvidia*` mounting

### 🔧 **Spark2 Troubleshooting Guide**

#### **Build Issues**
```bash
# Check build logs
docker buildx build --platform linux/arm64 -f dockerfile.spark2.wheels -t spark2 . --load

# Clean and rebuild
./build.sh --clean
```

#### **Agent Connection Issues**
```bash
# Check agent status on Spark2
ssh sanjay@192.168.1.202 "sudo systemctl status k3s-agent"

# View agent logs
ssh sanjay@192.168.1.202 "sudo journalctl -u k3s-agent -f"

# Restart agent
ssh sanjay@192.168.1.202 "sudo systemctl restart k3s-agent"
```

#### **GPU Access Problems**
```bash
# Verify GPU on Spark2 host
ssh sanjay@192.168.1.202 nvidia-smi

# Test container GPU access
kubectl exec spark2-<pod-id> -- nvidia-smi

# Check device mounts
kubectl exec spark2-<pod-id> -- ls -la /dev/nvidia*
```

#### **Health Check Failures**
```bash
# Run detailed health check
kubectl logs job/spark2 --follow

# Test individual components
kubectl exec spark2-<pod-id> -- python3 -c "import torch; print(torch.cuda.is_available())"
kubectl exec spark2-<pod-id> -- python3 -c "import tensorflow as tf; print(len(tf.config.list_physical_devices('GPU')))"
```

### 📈 **Performance & Compatibility**

#### **Tested Frameworks**
- **PyTorch**: 2.9.0+cu130 ✅
- **TensorFlow**: 2.17.0 ✅
- **TensorRT**: 10.8.0.43 ✅
- **CUDA**: 13.0 ✅
- **cuDNN**: 9.0 ✅

#### **Hardware Compatibility**
- **GPU**: NVIDIA GB10 (CC 12.1) ✅
- **CPU**: ARM64/aarch64 ✅
- **Memory**: 119Gi DDR4 ✅
- **Network**: 10G to Tower ✅

#### **Container Metrics**
- **Build Time**: ~3-5 minutes (wheels-based)
- **Image Size**: ~8-10GB (with PyTorch)
- **Startup Time**: <30 seconds
- **Health Check Duration**: ~12 seconds

### 🚀 **Production Deployment**

#### **Automated Setup**
```bash
# One-command deployment
cd agent/spark2 && ./k3s-spark2.sh

# Verify cluster integration
kubectl get nodes
kubectl get pods -l app=spark2
```

#### **Monitoring & Maintenance**
```bash
# Continuous health monitoring
kubectl get jobs spark2 -w

# Redeploy health checks
kubectl delete job spark2 && kubectl apply -f fastapi-deployment-spark2.yaml

# View comprehensive logs
kubectl logs job/spark2
```


## 🚀 AGX Orin Agent Setup & FastAPI Deployment

### 🎯 **AGX Agent Overview**
**Status**: ✅ **FULLY OPERATIONAL** - AGX Orin device with FastAPI/LLM services and GPU acceleration

The AGX agent runs comprehensive FastAPI services with GPU-accelerated AI/ML workloads, including LLM inference and RAG capabilities. Designed for production AI inference without Jupyter dependencies.

### 📊 **AGX Device Specifications**
- **Hardware**: NVIDIA Jetson AGX Orin 64GB
- **IP Address**: 192.168.1.244
- **CPU**: 12-core ARM64
- **Memory**: 64GB LPDDR5
- **GPU**: NVIDIA Ampere (2048 CUDA cores)
- **Architecture**: ARM64/aarch64
- **Network**: 10G dedicated link to Tower (192.168.1.150:6443)

### 🏗️ **AGX Agent Architecture**
```
Tower (192.168.1.150)          AGX Agent (192.168.1.244)
├── K3s Server               ├── K3s Agent
├── PostgreSQL               ├── FastAPI Services
├── Docker Registry          ├── GPU-Accelerated AI/ML
├── Token Distribution       ├── LLM Inference & RAG
└── Container Images         └── REST API Endpoints
```

### 📁 **AGX Agent Files Structure**
```
agent/agx/
├── agx_app.py                # FastAPI application with GPU acceleration
├── requirements.agx.txt      # Python dependencies (GPU libraries)
├── setup_fastapi_agx.sh      # Complete agent setup script
├── fastapi-deployment-agx.yaml  # Kubernetes deployment
├── dockerfile.agx.req        # Requirements-based Dockerfile
├── agx-config.env           # AGX-specific configuration
└── app/config/              # Application configuration
```

### 🔧 **AGX Device Configuration**

#### **Network Settings**
- **Tower Access**: 192.168.10.1 (AGX subnet)
- **Node Name**: agx
- **API Server**: https://192.168.10.1:6443

#### **Storage Paths**
- **Tokens**: `/mnt/vmstore/agx_home/containers/fastapi/.token/`
- **Config**: `/mnt/vmstore/agx_home/containers/fastapi/`
- **Workspace**: `/mnt/vmstore/tower_home/kubernetes/agent/agx`

#### **Service Endpoints**
- **FastAPI HTTP**: Port 8000
- **LLM API**: Port 8001
- **PostgreSQL**: 192.168.10.1:5432
- **Docker Registry**: 192.168.10.1:30500

### 🚀 **AGX Setup Process**

#### **Automated Setup**
```bash
# Complete AGX agent setup
cd agent/agx && ./setup_fastapi_agx.sh

# Verify deployment
kubectl get nodes
kubectl get pods -l app=fastapi-agx
```

#### **Manual Setup Steps**
```bash
# 1. Configure environment
vi agx-config.env

# 2. Run agent setup
./setup_fastapi_agx.sh

# 3. Validate setup
kubectl get nodes
kubectl describe node agx
```

### 🔧 **AGX Troubleshooting Guide**

#### **Agent Connection Issues**
```bash
# Check agent status on AGX
ssh sanjay@192.168.1.244 "sudo systemctl status k3s-agent"

# View agent logs
ssh sanjay@192.168.1.244 "sudo journalctl -u k3s-agent -f"

# Restart agent
ssh sanjay@192.168.1.244 "sudo systemctl restart k3s-agent"
```

#### **FastAPI Deployment Issues**
```bash
# Check pod status
kubectl get pods -l app=fastapi-agx

# View FastAPI logs
kubectl logs -l app=fastapi-agx --tail=100

# Test FastAPI endpoints
curl http://192.168.1.244:30004/health
curl http://192.168.1.244:30005/health/gpu
```

#### **GPU Access Problems**
```bash
# Verify GPU on AGX host
ssh sanjay@192.168.1.244 nvidia-smi

# Test container GPU access
kubectl exec fastapi-agx-<pod-id> -- nvidia-smi

# Check device mounts
kubectl exec fastapi-agx-<pod-id> -- ls -la /dev/nvidia*
```

### 📈 **AGX Performance & Compatibility**

#### **AI/ML Frameworks**
- **PyTorch**: 2.5.0 ✅ (CUDA optimized)
- **TensorFlow**: 2.16.1 ✅ (GPU acceleration)
- **TensorRT**: 8.6.2 ✅ (Inference optimization)
- **CUDA**: 12.2 ✅
- **cuDNN**: 8.9.4 ✅

#### **Service Endpoints**
- **Health Check**: `/health` - Basic FastAPI health
- **GPU Health**: `/health/gpu` - GPU validation
- **LLM API**: `/v1/chat/completions` - LLM inference
- **RAG API**: `/v1/rag/search` - Document retrieval

#### **Container Metrics**
- **Build Time**: ~15-20 minutes (requirements-based)
- **Image Size**: ~12-15GB (with GPU libraries)
- **Startup Time**: <60 seconds
- **Memory Usage**: ~4-6GB baseline + model loading

### 🚀 **AGX Production Deployment**

#### **Complete Setup**
```bash
# One-command deployment
cd agent/agx && ./setup_fastapi_agx.sh

# Verify cluster integration
kubectl get nodes
kubectl get pods -l app=fastapi-agx
```

#### **Monitoring & Maintenance**
```bash
# Check FastAPI status
kubectl get deployments fastapi-agx

# View service endpoints
kubectl get services -l app=fastapi-agx

# Redeploy if needed
kubectl rollout restart deployment fastapi-agx
```

## �🆕 New Features: Component-Based Architecture

### 🐳 Component-Based Image Generation
**Status**: ✅ Implemented & Tested
- **Auto-Generated Dockerfiles**: Component-aware Dockerfiles with infrastructure setup
- **Smart Requirements**: Python packages automatically selected based on components
- **Multi-Architecture Support**: ARM64 and AMD64 builds with proper base images
- **Infrastructure Integration**: All images include SSH, NFS, networking, and directory structure

### 🏗️ Standardized Infrastructure Layer
**Status**: ✅ Implemented & Tested
- **Passwordless SSH**: Automatic SSH key generation and distribution between all nodes
- **NFS Storage**: Standardized `/mnt/vmstore` mount point with configurable NFS server
- **Directory Structure**: Consistent `/home/sanjay/kubernetes/agent` layout across all nodes
- **Network Configuration**: Automatic DNS resolution via `/etc/hosts` with cluster node IPs
- **User Management**: Standardized user setup with sudo access
- **Service Integration**: SSH service startup, NFS mounting, and application launching

### �️ Centralized Build System
**Status**: ✅ Implemented & Tested
- **Build Once Architecture**: Images built once on tower instead of redundantly on each node
- **Config Change Detection**: Intelligent checksum-based detection prevents unnecessary rebuilds
- **Central Artifact Storage**: All build artifacts (images, tars) stored centrally in `images/` directory
- **Portable Deployments**: Copy project folder to new network, run build process once
- **Efficient Resource Usage**: Eliminates duplicate builds across multiple Jetson devices

### �🏥 Auto-Generated Health Checks
**Status**: ✅ Implemented & Enhanced
- **Component-Aware**: Health endpoints automatically generated based on selected components
- **Comprehensive Monitoring**: Individual and combined health checks for all services
- **Smart Endpoints**:
  - `/health` - Basic FastAPI health
  - `/health/db` - Database connectivity (if database component selected)
  - `/health/gpu` - GPU status with PyTorch, TensorFlow, TensorRT, cuSPARSELt validation
  - `/health/llm` - LLM model status (if LLM component selected)
  - `/health/rag` - RAG system status (if RAG component selected)
  - `/health/jupyter` - Jupyter server status (if Jupyter selected)
  - `/health/system` - System monitoring (if monitoring selected)
  - `/health/comprehensive` - All component health combined

## ⚙️ Configuration System

### 📁 Configuration Architecture

The system uses a **layered configuration architecture** with two main configuration files:

```
├── image-matrix.sh    # Component definitions and compatibility matrix  
└── node-config.sh     # Configuration parsing and generation functions
```

### 🎯 Configuration Architecture

**Configuration is now inline within each deployment script** for better maintainability and clarity:

```bash
# Configuration variables are defined directly in each script
TOWER_IP="192.168.1.150"        # Tower server IP
NANO_IP="192.168.1.181"         # Jetson Nano IP
AGX_IP="192.168.1.244"          # Jetson AGX Orin IP
POSTGRES_PASSWORD="postgres"  # Database password
```

# SSH Configuration
SSH_KEY_TYPE="rsa"            # rsa, ed25519
SSH_KEY_BITS="4096"           # for rsa keys

# ==========================================
# NODE CLUSTER CONFIGURATION
# ==========================================

# Node Types to Include in Cluster
# Options: tower, nano, agx, x86-worker, arm-worker
CLUSTER_NODES="tower,nano,agx"

# ==========================================
# NODE-SPECIFIC CONFIGURATIONS
# ==========================================

# Tower (Server) Configuration
TOWER_IP="192.168.1.150"
TOWER_COMPONENTS="server,postgres,pgadmin,jupyter"

# Jetson Nano Configuration
NANO_IP="192.168.1.181"
NANO_COMPONENTS="python,cuda,tensorrt,fastapi,gpu-monitoring"
NANO_BASE_IMAGE="l4t-minimal"

# Jetson AGX Configuration
AGX_IP="192.168.1.244"
AGX_COMPONENTS="python,cuda,tensorrt,pytorch,tensorflow,fastapi,gpu-monitoring,llm,rag"
AGX_BASE_IMAGE="l4t-ml"
```

### 🧩 Component Matrix (`image-matrix.sh`)

Defines **available components** and their **compatibility** with base images:

```bash
# Base image definitions
declare -A BASE_IMAGES
BASE_IMAGES["l4t-minimal"]="nvcr.io/nvidia/l4t-jetpack:r36.4.0"      # CUDA, cuDNN, minimal Python
BASE_IMAGES["l4t-ml"]="nvcr.io/nvidia/l4t-ml:r36.4.0-py3"            # + PyTorch, TensorFlow
BASE_IMAGES["ubuntu-cuda"]="nvidia/cuda:12.2-base-ubuntu22.04"      # x86 CUDA base

# Component dependencies (system + Python packages)
declare -A COMPONENT_DEPS
COMPONENT_DEPS["python"]="python3.10 python3.10-venv python3-pip"
COMPONENT_DEPS["fastapi"]="fastapi uvicorn pydantic"
COMPONENT_DEPS["gpu-monitoring"]="nvidia-ml-py"
COMPONENT_DEPS["llm"]="transformers accelerate"

# Component compatibility matrix
declare -A COMPONENT_COMPATIBILITY
COMPONENT_COMPATIBILITY["cuda"]="l4t-minimal,l4t-ml,l4t-pytorch,ubuntu-cuda"
COMPONENT_COMPATIBILITY["pytorch"]="l4t-ml,l4t-pytorch,ubuntu-cuda"
```

### 🔧 Available Components

| Component | Description | Dependencies |
|-----------|-------------|--------------|
| `python` | Python 3.10 runtime | `python3.10`, `python3.10-venv`, `python3-pip` |
| `cuda` | NVIDIA CUDA toolkit | `cuda-toolkit-12-2`, `libcudnn8` |
| `tensorrt` | NVIDIA TensorRT | `libnvinfer8`, `libnvinfer-plugin8` |
| `pytorch` | PyTorch ML framework | `torch`, `torchvision`, `torchaudio` |
| `tensorflow` | TensorFlow ML framework | `tensorflow` |
| `fastapi` | FastAPI web framework | `fastapi`, `uvicorn`, `pydantic` |
| `gpu-monitoring` | GPU monitoring tools | `nvidia-ml-py` |
| `llm` | Large Language Models | `transformers`, `accelerate` |
| `rag` | Retrieval-Augmented Generation | `sentence-transformers`, `faiss-cpu` |
| `database` | Database connectivity | `psycopg2-binary`, `sqlalchemy` |
| `jupyter` | Jupyter notebooks | `jupyterlab`, `notebook` |
| `monitoring` | System monitoring | `psutil`, `prometheus-client` |

### 🏗️ Base Images

| Base Image | Architecture | Description | Compatible Components |
|------------|--------------|-------------|----------------------|
| `l4t-minimal` | ARM64 | NVIDIA JetPack minimal | CUDA, TensorRT, basic Python |
| `l4t-ml` | ARM64 | NVIDIA JetPack ML | + PyTorch, TensorFlow |
| `l4t-pytorch` | ARM64 | NVIDIA JetPack PyTorch | + Optimized PyTorch |
| `ubuntu-cuda` | AMD64 | Ubuntu CUDA base | CUDA, PyTorch, TensorFlow |
| `ubuntu-minimal` | AMD64/ARM64 | Minimal Ubuntu | Basic components |

### 🚀 Configuration Workflow

```
1. Edit deployment scripts directly
   ├── Configure IPs and settings in server/k3s-server.sh
   ├── Set component flags and passwords inline
   └── Choose appropriate base images in image-matrix.sh

2. Run ./generate-images.sh
   ├── Validates component compatibility
   ├── Generates optimized Dockerfiles
   ├── Creates requirements.txt files
   └── Generates health check endpoints

3. Run ./k3s-setup-automation.sh
   ├── Builds images centrally on tower (only when config changes)
   ├── Pushes to local registry or saves tar files centrally
   └── Deploys to Kubernetes cluster via node affinity
```

### 📝 Quick Configuration Examples

#### **Add GPU monitoring to Nano:**
```bash
# In server/k3s-server.sh or agent/nano/k3s-nano-agent-setup.sh
# Edit component variables directly in the script
```

#### **Add new x86 GPU worker:**
```bash
# Add new script in agent/x86-gpu/ directory
# Configure IPs and components inline in the new script
```

#### **Change JetPack version:**
```bash
# In image-matrix.sh
BASE_IMAGES["l4t-minimal"]="nvcr.io/nvidia/l4t-jetpack:r36.3.0"
```

#### **Add custom component:**
```bash
# In image-matrix.sh
COMPONENT_DEPS["custom-ml"]="custom-package1 custom-package2"
COMPONENT_COMPATIBILITY["custom-ml"]="l4t-ml,ubuntu-cuda"

# In deployment scripts (e.g., agent/agx/k3s-agx-agent-setup.sh)
# Add custom component to the inline configuration
```

### ✅ Automatic Validation

The system automatically validates:
- ✅ Component compatibility with selected base images
- ✅ Required configuration variables are set
- ✅ Node IPs are properly configured
- ✅ Architecture compatibility (ARM64 vs AMD64)

## 🔧 Troubleshooting Guide

### Common Issues & Resolutions

#### 1. **Image Pull Protocol Mismatch** ❌➡️✅
**Symptoms:**
- `ErrImagePull: failed to pull and unpack image "192.168.1.150:5000/fastapi_nano:latest"`
- `http: server gave HTTP response to HTTPS client`

**Root Cause:**
Local Docker registry configured for HTTP but containerd expecting HTTPS.

**Resolution:**
1. **Verify Registry Configuration:**
   ```bash
   # On each agent node (nano, agx)
   sudo cat /etc/rancher/k3s/registries.yaml
   # Should show:
   configs:
     "192.168.1.150:5000":
       insecure_skip_verify: true
       http: true
   ```

2. **Verify Containerd Configuration:**
   ```bash
   # On each agent node
   sudo cat /var/lib/rancher/k3s/agent/etc/containerd/certs.d/192.168.1.150:5000/hosts.toml
   # Should show:
   [host."http://192.168.1.150:5000"]
     capabilities = ["pull", "resolve", "push"]
   ```

3. **Restart K3s Agents:**
   ```bash
   # On each agent node
   sudo systemctl restart k3s-agent
   ```

#### 2. **Agent-to-Master Connectivity Issues** ❌➡️✅
**Symptoms:**
- `Failed to connect to proxy. Empty dialer response`
- `dial tcp 192.168.1.150:6443: connect: connection refused`
- `apiserver not ready` errors

**Root Cause:**
Network connectivity issues or K3s service instability.

**Resolution:**
1. **Test Network Connectivity:**
   ```bash
   # From agent nodes
   nc -vz 192.168.1.150 6443
   # Should show: Connection succeeded!
   ```

2. **Check Firewall Rules:**
   ```bash
   # On tower (master)
   sudo iptables -L -n | grep 6443  # Should show no blocking rules
   ```

3. **Restart K3s Services:**
   ```bash
   # On tower (master)
   sudo systemctl restart k3s
   
   # On agent nodes
   sudo systemctl restart k3s-agent
   ```

4. **Verify Cluster Status:**
   ```bash
   sudo k3s kubectl get nodes  # Use k3s kubectl directly
   ```

#### 3. **NVIDIA GPU Plugin Errors** ⚠️
**Symptoms:**
- `failed to get sandbox image` errors
- `failed to authorize` messages
- GPU workloads failing

**Root Cause:**
Internet connectivity issues preventing image pulls or GPU resource conflicts.

**Resolution:**
1. **Test Internet Connectivity:**
   ```bash
   # From GPU nodes (nano, agx)
   ping -c 3 google.com
   ```

2. **Check GPU Resources:**
   ```bash
   # On GPU nodes
   nvidia-smi
   sudo k3s kubectl describe node <node-name>
   ```

3. **Verify GPU Plugin Status:**
   ```bash
   sudo k3s kubectl get pods -n kube-system | grep nvidia
   ```

#### 4. **General Debugging Commands**

**Cluster Diagnostics:**
```bash
# Check all nodes
sudo k3s kubectl get nodes -o wide

# Check all pods
sudo k3s kubectl get pods -A

# Check service status
sudo k3s kubectl get services

# View pod logs
sudo k3s kubectl logs <pod-name> -f

# Check node events
sudo k3s kubectl get events --sort-by=.metadata.creationTimestamp
```

**Network Diagnostics:**
```bash
# Test inter-node connectivity
ping <target-ip>

# Check DNS resolution
nslookup kubernetes.default.svc.cluster.local

# Test service accessibility
curl -v http://192.168.1.150:30002/health
```

**Service-Specific Checks:**
```bash
# PostgreSQL connectivity
psql -h 192.168.1.150 -p 30432 -U postgres

# Registry accessibility
curl -v http://192.168.1.150:5000/v2/

# NFS mount status
df -h | grep nfs
```

#### 5. **Emergency Recovery Procedures**

**Complete Cluster Reset:**
```bash
# Stop all services
sudo systemctl stop k3s
sudo systemctl stop k3s-agent  # On agent nodes

# Clean up data (CAUTION: This removes all data)
sudo rm -rf /var/lib/rancher/k3s/*

# Reinitialize cluster
sudo systemctl start k3s  # On master first
sudo systemctl start k3s-agent  # On agents
```

**Application Redeployment:**
```bash
# Delete problematic pods
sudo k3s kubectl delete pod <pod-name>

# Redeploy applications
sudo k3s kubectl apply -f fastapi-deployment-full.yaml
```

### 📊 **Issue Resolution Summary**

| Issue | Status | Resolution Time | Method |
|-------|--------|----------------|---------|
| Image Pull Protocol Mismatch | ✅ Resolved | 5 minutes | K3s agent restart |
| Agent-Master Connectivity | ✅ Resolved | 2 minutes | Service restart |
| Pod Deployment Failures | ✅ Resolved | Immediate | Configuration fix |
| Service Accessibility | ✅ Resolved | Verified | All endpoints working |

**Key Success Factors:**
- ✅ Registry configuration was correct but required service restart
- ✅ Network connectivity was intact but services needed restart
- ✅ Using `sudo k3s kubectl` bypasses KUBECONFIG issues
- ✅ Stability manager provides reliable health verification

---

## 📞 Support & Resources for Jetson Nano
- **Database Suite**: PostgreSQL with pgvector extension + pgAdmin management interface
- **Application Suite**: FastAPI, Jupyter Lab, health monitoring, API documentation
- **Enterprise Features**: NFS storage, comprehensive health checks, automated verification
- **🆕 Stability Manager**: Advanced cluster monitoring, health checks, and recovery tools

### 🏆 Performance Achievements
- **AGX Orin**: Up to 10 Gbps bandwidth with ultra-low latency for AI inference
- **Jetson Nano**: Stable 1 Gbps with preserved internet connectivity
- **Zero Interference**: Isolated networks prevent bandwidth sharing issues
- **GPU Acceleration**: CUDA, TensorRT, PyTorch, TensorFlow optimized
- **Database Performance**: pgvector extension for AI vector operations
- **🆕 Stability Verification**: 96-step automated deployment with comprehensive validation

## 🏗️ Architecture Overview

### Network Topology
```
                    TOWER (Ubuntu Server)
                    ├── 10G Port: enp1s0f1 (192.168.1.150)
                    │   └── AGX Orin (192.168.1.244) - High-performance AI
                    └── 1G Port: eno2 (192.168.5.1)
                        └── Jetson Nano (192.168.1.181) - IoT/Monitoring
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
- **🆕 Stability Manager**: Comprehensive cluster health monitoring and recovery

## 📁 Project Structure

```
kubernetes/
├── k3s-setup-automation.sh          # 🆕 Main automated setup script (63 steps with stability verification)
├── node-config.sh                   # 🆕 Node configuration parser and validation functions
├── config-demo.sh                   # 🆕 Configuration demo and validation script
├── stability-manager.sh             # 🆕 Advanced cluster stability manager and monitoring
├── STABILITY-README.md              # 🆕 Stability manager documentation (archived)
├── README.md                        # This comprehensive documentation
├── fastapi-deployment-full.yaml     # K8s deployment manifests
├── nvidia-ds-updated.yaml           # NVIDIA device plugin configuration
├── images/                          # 🆕 Centralized image storage and build artifacts
│   ├── built/                       # Temporary build artifacts
│   ├── tar/                         # Central tar file storage for offline deployments
│   └── config/                      # Config checksums for change detection
├── archive/                         # 🆕 Archived obsolete configurations and scripts
│   ├── config-demo.sh               # Configuration demo (moved)
│   ├── fastapi-deployment-full.yaml # Old deployment manifest (moved)
│   ├── generate-images.sh           # Image generation script (moved)
│   ├── image-matrix.sh              # Component matrix (moved)
│   ├── k3s-config.sh                # Old config (moved)
│   ├── k3s-setup-automation.sh      # Old automation script (moved)
│   ├── node-config.sh               # Old node config (moved)
│   ├── nvidia-ds-updated.yaml       # Old NVIDIA config (moved)
│   ├── registry-deployment.yaml     # Registry deployment (moved)
│   ├── renumber.sh                  # Step renumbering utility (moved)
│   ├── stability-manager.sh         # Old stability manager (moved)
│   ├── start-fastapi.yaml           # Old FastAPI config (moved)
│   ├── start-fastapi-nano.yaml      # Old Nano config (moved)
│   ├── test_end.sh                  # Test script (moved)
│   ├── test_script.sh               # Test script (moved)
│   └── dev/                         # Development scripts (archived)
├── agent/                           # Agent-specific configurations
│   ├── nano/                        # Jetson Nano setup
│   │   ├── dockerfile.nano.req      # GPU-enabled Dockerfile
│   │   ├── requirements.nano.txt    # Python dependencies for Nano
│   │   ├── app/                     # FastAPI application source
│   │   │   ├── src/nano_app.py      # Main FastAPI app
│   │   │   ├── config/              # Configuration files
│   │   │   └── docs/                # API documentation
│   │   ├── k3s-nano-agent-setup.sh  # Nano K3s agent setup
│   │   ├── validate-nano-setup.sh   # Nano validation
│   │   ├── cleanup-nano.sh          # Cleanup scripts
│   │   └── README.md                # Nano-specific docs
│   └── agx/                         # Jetson AGX Orin setup
│       ├── agx_app.py               # AGX FastAPI app
│       ├── k3s-agx-agent-setup.sh    # AGX K3s agent setup
│       ├── validate-agx-setup.sh    # AGX validation
│       ├── setup-agx-network.sh     # AGX network config
│       └── README.md                # AGX-specific docs
├── server/                          # Tower server components
│   ├── 6-setup_tower_sshkeys.sh     # SSH key setup for Tower
│   ├── 7-setup_agx_sshkeys.sh       # SSH key setup for AGX
│   ├── 8-setup_nano_sshkeys.sh      # SSH key setup for Nano
│   ├── pgadmin/                     # pgAdmin web interface
│   │   ├── dockerfile.pgadmin       # pgAdmin Dockerfile
│   │   ├── pgadmin-deployment.yaml  # K8s deployment (configurable)
│   │   ├── pgadmin-secret.yaml      # Secrets (configurable password)
│   │   └── docs/                    # pgAdmin documentation
│   ├── postgres/                    # PostgreSQL database with pgvector
│   │   ├── dockerfile.postgres      # PostgreSQL Dockerfile
│   │   ├── postgres-db-deployment.yaml # K8s deployment (configurable)
│   │   ├── postgres-pgadmin-services.yaml # Service definitions
│   │   └── docs/                    # PostgreSQL documentation
│   ├── docs/                        # Server documentation
│   ├── jupyter/                     # Jupyter configurations
│   ├── k8s-setup-validate.sh        # Server validation
│   ├── postgres-pgadmin-nodeport-services.yaml # NodePort services
│   └── verify-postgres-pgadmin.sh   # Comprehensive database verification
├── scripts/                         # Utility and maintenance scripts
│   ├── env.sh                       # Environment setup script
│   ├── monitor-service.sh           # Service monitoring utilities
│   ├── update-all-nfs-fstab.sh      # NFS mount updates
│   ├── update-docker-registry.sh    # Docker registry updates
│   ├── update-nfs-fstab.sh          # NFS configuration updates
│   ├── validate-k3s-agent.sh        # Agent validation script
│   ├── README.md                    # Network setup documentation (archived)
│   ├── inconsistencyCheck.sh        # Network consistency checker (archived)
│   └── restore_backup.sh            # Network configuration backup/restore (archived)
├── dev/                             # Development and test scripts
│   ├── renumber.sh                  # Step renumbering utility
│   ├── test_end.sh                  # Test script for end-to-end validation
│   └── test_script.sh               # Development test script
├── docs/                            # Documentation and analysis
│   ├── errors.md                    # Error tracking and resolution history
│   └── todo.md                      # Project analysis and robustness assessment
└── logs/                            # Log files and output
    └── stability.log                # Stability manager execution logs
```

## 🚀 Quick Start

### Prerequisites
- Ubuntu Server (Tower) with dual NICs (10G + 1G)
- NVIDIA Jetson AGX Orin (10G connected to Tower)
- NVIDIA Jetson Nano (1G connected to Tower)
- SSH access between devices

### 🆕 Automated Setup with Stability Verification (Recommended)
1. **Configure Settings**:
   ```bash
   # Edit deployment scripts directly to set IPs and enable/disable components
   # For example: nano server/k3s-server.sh
   ```

2. **Run Complete Setup with Stability Checks**:
   ```bash
   # This handles network setup, K3s cluster, applications, and comprehensive stability verification
   ./k3s-setup-automation.sh
   ```

   **What the automated script provides:**
   - ✅ **96-step deployment process** with real-time progress
   - ✅ **Comprehensive stability verification** at completion
   - ✅ **Clean output** with no SSH warnings or formatting issues
   - ✅ **Automatic service validation** (PostgreSQL, pgAdmin, FastAPI)
   - ✅ **Access information display** with all endpoints and credentials

### 🆕 Stability Manager Commands
After deployment, use the stability manager for ongoing monitoring:

```bash
# Check cluster health
./stability-manager.sh check

# Monitor continuously
./stability-manager.sh monitor

# Attempt automatic recovery
./stability-manager.sh recover

# View detailed status
./stability-manager.sh status
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

### 🐳 Docker Image Management Modes

The deployment script supports **4 flexible Docker image management modes** for different network environments:

#### Available Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `local` | Use local images or build if missing (default) | Development, iterative testing |
| `download` | Always download fresh images from registry | Production updates, CI/CD |
| `save-tar` | Save images as tar files for offline use | Prepare offline deployment packages |
| `use-tar` | Use local tar files instead of building | True offline deployments |

#### Usage Examples

```bash
# Default mode - use local images or build if missing
./k3s-setup-automation.sh

# Always download fresh images from registry
./k3s-setup-automation.sh --image-mode download

# Create tar files for offline deployment
./k3s-setup-automation.sh --image-mode save-tar

# Deploy from tar files (completely offline)
./k3s-setup-automation.sh --image-mode use-tar
```

#### Mode Details

- **`local`**: Builds images centrally on tower (only when config changes), pushes to registry, pulls to nodes
- **`download`**: Always downloads fresh images from registry to nodes
- **`save-tar`**: Builds images centrally on tower, saves as `.tar` files in central `images/tar/` directory
- **`use-tar`**: Copies `.tar` files from central `images/tar/` directory to nodes and loads them

#### Network Environment Support

| Environment | Recommended Mode | Benefits |
|-------------|------------------|----------|
| Online + Registry | `local` | Efficient reuse, only rebuilds when config changes |
| Online Only | `download` | Always latest images, fast deployment |
| Offline Ready | `save-tar` | Prepare deployment packages centrally |
| Air-Gapped | `use-tar` | Complete offline operation from central tar storage |

### 🏗️ Centralized Build Architecture

**Key Improvements:**
- ✅ **Build Once**: Images built once on tower instead of on each node
- ✅ **Config Change Detection**: Only rebuilds when Dockerfiles or requirements change
- ✅ **Central Tar Storage**: Tar files stored centrally in `images/tar/` directory
- ✅ **Portable Deployment**: Copy project folder to new network, run build process
- ✅ **Efficient Caching**: Intelligent caching prevents unnecessary rebuilds

**Build Process Flow:**
```
1. Check config checksums (Dockerfile + requirements)
2. If config changed → Build on tower → Push to registry or save tar
3. If config unchanged → Skip build, use cached images/tars
4. Deploy to nodes via registry pull or tar copy+load
```

**Directory Structure:**
```
images/
├── built/          # Temporary build artifacts
├── tar/           # Central tar file storage
│   ├── fastapi_nano.tar
│   └── fastapi_agx.tar
└── config/        # Config checksums for change detection
    ├── nano_checksum.txt
    └── agx_checksum.txt
```

```bash
# Get help with available options
./k3s-setup-automation.sh --help
```

## 🔧 Configuration

Edit deployment scripts directly to customize your deployment:

```bash
# Edit server/k3s-server.sh for server configuration
# Edit agent/*/k3s-*-agent-setup.sh for agent configurations

# Example configuration variables (inline in scripts):
TOWER_IP="192.168.1.150"       # Tower server IP
NANO_IP="192.168.1.181"        # Jetson Nano IP
AGX_IP="192.168.1.244"         # Jetson AGX Orin IP
REGISTRY_IP="192.168.1.150"    # Docker registry IP
REGISTRY_PORT="5000"         # Docker registry port
REGISTRY_PROTOCOL="http"     # "http" or "https" for registry security

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

### 🔒 HTTPS Registry Configuration
- **REGISTRY_PROTOCOL**: Set to `"http"` for standard HTTP registry or `"https"` for secure TLS-encrypted registry
- **Automatic Certificate Generation**: When using HTTPS, self-signed certificates are automatically generated and distributed to all cluster nodes
- **Certificate Location**: Certificates are stored in `/etc/docker/certs.d/$REGISTRY_IP:$REGISTRY_PORT/`
- **Containerd Integration**: Registry configuration is automatically applied to K3s containerd runtime
- **Security Benefits**: HTTPS prevents man-in-the-middle attacks and provides encrypted image transfers

## 🚀 Upcoming Features

### 🏗️ Standardized Infrastructure Layer
**Status**: ✅ Implemented & Tested
- **Passwordless SSH**: Automatic SSH key generation and distribution between all nodes
- **NFS Storage**: Standardized `/mnt/vmstore` mount point with configurable NFS server
- **Directory Structure**: Consistent `/home/sanjay/kubernetes/agent` layout across all nodes
- **Network Configuration**: Automatic DNS resolution via `/etc/hosts` with cluster node IPs
- **User Management**: Standardized user setup with sudo access
- **Service Integration**: SSH service startup, NFS mounting, and application launching

### 🔄 RAG Database Setup
**Status**: Planned
- **pgvector Integration**: Complete vector database setup for AI applications
- **FastAPI Endpoints**: RESTful APIs for vector operations and similarity search
- **AGX LLM Enablement**: Large language model deployment on AGX Orin GPU

## ⚙️ Configuration

### New Parameterized Configuration System

Configuration is now handled directly in deployment scripts with inline parameters:

```bash
# Configuration variables are defined directly in each script
# For example, in server/k3s-server.sh:

TOWER_IP="192.168.1.150"          # Tower server IP
TOWER_ARCH="amd64"              # Architecture (amd64/arm64)
# Component flags are set as variables in the script

# Similar configurations exist in agent scripts for each node type
```

### Test Configuration

Run the configuration demo to validate your setup:

```bash
./config-demo.sh
```

This will show your cluster configuration and validate all settings.
## �📊 Services & Access Information

After successful deployment, all access information is automatically displayed and logged. Here are the services:

### 🖥️ **Management Interfaces**
| Service | URL | Credentials | Description |
|---------|-----|-------------|-------------|
| **pgAdmin** | http://192.168.1.150:30080 | pgadmin@pgadmin.org / pgadmin | PostgreSQL web admin interface |
| **Traefik Dashboard** | http://192.168.1.150:9000 | - | Kubernetes ingress dashboard |

### 🗄️ **Database Services**
| Service | Connection | Credentials | Description |
|---------|------------|-------------|-------------|
| **PostgreSQL** | 192.168.1.150:30432 | postgres / postgres | Primary database with pgvector |
| **PostgreSQL (Alt)** | 192.168.1.150:32432 | postgres / postgres | Alternative port access |

### 🤖 **FastAPI Applications**
| Service | URL | GPU Support | Description |
|---------|-----|-------------|-------------|
| **FastAPI (Nano)** | http://192.168.1.150:30002 | GPU Enabled | Lightweight API on Jetson Nano |
| **FastAPI (AGX)** | http://192.168.1.150:30004 | GPU + LLM | AI/ML workloads on Jetson AGX Orin |
| **LLM Inference API** | http://192.168.1.150:30006 | GPU + LLM | Large Language Model inference endpoints |
| **Health Check (Nano)** | http://192.168.1.150:30002/health | - | Nano application health monitoring |
| **Health Check (AGX)** | http://192.168.1.150:30004/health | - | AGX application health monitoring |
| **API Docs (Nano)** | http://192.168.1.150:30002/docs | - | Nano interactive Swagger/OpenAPI docs |
| **API Docs (AGX)** | http://192.168.1.150:30004/docs | - | AGX interactive Swagger/OpenAPI docs |
| **Jupyter Lab (Nano)** | http://192.168.1.150:30003 | - | Nano interactive development environment |
| **Jupyter Lab (AGX)** | http://192.168.1.150:30005 | - | AGX interactive development environment |

### 🔥 **Hot Reload Development**
**Status**: ✅ **ENABLED** - Real-time code updates without container rebuilds

#### Bind Mount Configuration
- **Source**: NFS-mounted application directories from tower
- **Target**: `/workspace` in both Nano and AGX containers
- **Technology**: Kubernetes persistent volume mounts with NFS backend

#### Hot Reload Features
- **Automatic Detection**: File changes trigger immediate application restart
- **No Rebuild Required**: Edit code on host, see changes instantly in pods
- **Development Workflow**: Modify `nano_app.py` or `agx_app.py` → Auto-reload in 1-2 seconds
- **Volume Mounts**:
  - **Nano**: `/workspace` ← `tower:/export/vmstore/tower_home/kubernetes/agent/nano`
  - **AGX**: `/workspace` ← `tower:/export/vmstore/tower_home/kubernetes/agent/agx`

#### Implementation Details
- **Uvicorn**: `--reload --reload-dir /workspace` flags enabled
- **FastAPI Apps**: Exposed at module level for uvicorn import
- **File Monitoring**: Watches entire `/workspace` directory for changes
- **Zero Downtime**: Graceful restart maintains service availability

#### Usage
```bash
# Edit application files on tower
vim agent/nano/app/src/nano_app.py
vim agent/agx/agx_app.py

# Changes automatically reflected in running pods
# No need to rebuild containers or restart deployments
```

### 🔍 **Health & Monitoring**
- **Cluster Status**: `sudo kubectl get nodes`
- **Pod Status**: `sudo kubectl get pods -A`
- **Database Health**: `./server/verify-postgres-pgadmin.sh`
- **GPU Status**: `nvidia-smi` (on GPU nodes)
- **🆕 Stability Manager**: `./stability-manager.sh check`

### 📝 **Configuration Files**
- **pgAdmin Connection**: Use PostgreSQL connection details above
- **Environment Variables**: Check deployment scripts (e.g., `server/k3s-server.sh`) for current settings
- **Logs**: Deployment logs saved automatically to timestamped files

## 🛡️ Stability Manager

The **Stability Manager** (`stability-manager.sh`) provides comprehensive cluster monitoring, health checks, and automatic recovery capabilities.

### Core Features
- **Real-time Health Monitoring**: Continuous cluster status tracking
- **Automated Recovery**: Self-healing capabilities for common issues
- **Comprehensive Validation**: Node, pod, and service health checks
- **Performance Metrics**: GPU utilization and resource monitoring
- **Alert System**: Proactive issue detection and notification

### Available Commands

```bash
# Health Check (used in automated deployment)
./stability-manager.sh check

# Continuous Monitoring (Ctrl+C to stop)
./stability-manager.sh monitor

# Automatic Recovery (attempts to fix issues)
./stability-manager.sh recover

# Detailed Status Report
./stability-manager.sh status

# Environment Backup
./stability-manager.sh backup
```

### Health Check Components
The stability manager validates:
- ✅ **Node Readiness**: All cluster nodes operational
- ✅ **Pod Health**: Application pods running correctly
- ✅ **Service Accessibility**: FastAPI and pgAdmin endpoints responding
- ✅ **GPU Resources**: NVIDIA GPU allocation and utilization
- ✅ **Network Connectivity**: Inter-node communication
- ✅ **Storage**: NFS mounts and persistent volumes

### Integration with Automation
- **96-Step Deployment**: Includes stability verification as final step
- **Clean Output**: No warnings or formatting issues
- **Progress Indicators**: Real-time status during long operations
- **Error Recovery**: Automatic retry mechanisms for transient failures

### Monitoring Dashboard
```bash
# Start continuous monitoring
./stability-manager.sh monitor

# Output example:
# 2025-10-09 12:00:00 - Checking cluster nodes...
# ✅ Nodes: 3/3 ready
# 2025-10-09 12:00:01 - Checking application pods...
# ✅ fastapi-nano: Running
# ✅ fastapi-agx: Running
# ✅ postgres-db: Running
# ✅ pgadmin: Running
# 2025-10-09 12:00:01 - Checking service accessibility...
# ✅ FastAPI (Nano): Accessible
# ✅ FastAPI (AGX): Accessible
# ✅ pgAdmin: Accessible
```

### Recovery Capabilities
- **Pod Restart**: Automatically restart failed containers
- **Service Redeployment**: Reapply configurations for stuck deployments
- **Network Recovery**: Restore connectivity issues
- **Resource Cleanup**: Remove stuck resources and free GPU memory

### Configuration
The stability manager uses these configuration files:
- `stability.log`: Comprehensive operation logs
- `/etc/rancher/k3s/k3s.yaml`: Kubernetes API access
- Network IPs from deployment scripts (e.g., `server/k3s-server.sh`)

For detailed documentation, see `STABILITY-README.md` (archived).

## 🚀 Automated Deployment (55 Steps)

The deployment automation script (`k3s-setup-automation.sh`) provides a comprehensive, production-ready K3s cluster setup with full validation and error handling.

### Key Features
- **96-Step Process**: Complete end-to-end automation
- **Error Recovery**: Automatic retry mechanisms for transient failures
- **Progress Tracking**: Real-time status updates with timestamps
- **Validation**: Comprehensive checks at each stage
- **Clean Output**: No warnings or formatting issues
- **GPU Integration**: Full NVIDIA GPU support with runtime classes
- **Security**: Proper RBAC and network policies
- **Flexible Image Management**: 4 Docker deployment modes for online/offline environments

### Deployment Stages

#### Phase 1: Environment Preparation (Steps 1-10)
- System prerequisites validation
- Network configuration setup
- Firewall rules configuration
- Package installation and updates

#### Phase 2: K3s Installation (Steps 11-20)
- K3s binary download and installation
- Service configuration with GPU support
- Cluster initialization with custom settings
- Node registration and validation

#### Phase 3: Storage & Networking (Steps 21-30)
- NFS server setup and configuration
- Persistent volume creation
- Network policies and security groups
- Load balancer configuration

#### Phase 4: Database Setup (Steps 31-40)
- PostgreSQL deployment with pgvector
- pgAdmin web interface installation
- Database initialization and configuration
- Connection validation and testing

#### Phase 5: Application Deployment (Steps 41-50)
- FastAPI application containers
- Service mesh configuration
- Ingress rules and routing
- GPU resource allocation

#### Phase 6: Validation & Stability (Steps 51-55)
- Comprehensive health checks
- Stability manager integration
- Final verification and reporting

### Usage

```bash
# Full automated deployment
./k3s-setup-automation.sh

# With custom configuration
export K3S_VERSION="v1.33.5+k3s1"
export GPU_ENABLED=true
./k3s-setup-automation.sh
```

### Configuration Options
- **K3S_VERSION**: Specify K3s version (default: latest stable)
- **GPU_ENABLED**: Enable NVIDIA GPU support (default: true)
- **STORAGE_SIZE**: NFS storage allocation (default: 100GB)
- **NODE_COUNT**: Expected cluster nodes (default: 3)

### Validation & Verification
The script includes comprehensive validation:
- ✅ **Pre-deployment checks**: System requirements
- ✅ **Real-time monitoring**: Progress during long operations
- ✅ **Post-deployment validation**: All services accessible
- ✅ **Stability verification**: Cluster health confirmed
- ✅ **Performance testing**: GPU and network benchmarks

### Error Handling
- **Automatic retries**: For transient network/storage issues
- **Rollback capability**: Clean up on critical failures
- **Detailed logging**: Timestamped logs for troubleshooting
- **Exit codes**: Clear success/failure indication

### Integration Points
- **Stability Manager**: Automatic health monitoring post-deployment
- **Configuration Files**: Settings configured inline in deployment scripts
- **Service Endpoints**: Accessible URLs provided on completion
- **Documentation**: Auto-generated setup summary

For detailed deployment logs and troubleshooting, check the timestamped log files created during execution.

## ⚡ Production Optimizations

### Performance Enhancements
- **GPU Acceleration**: NVIDIA runtime classes with device plugins
- **Vector Database**: pgvector extension for AI workloads
- **Optimized Storage**: NFS with performance tuning
- **Network Policies**: Secure inter-service communication
- **Resource Limits**: Proper CPU/memory allocation

### Reliability Features
- **Health Monitoring**: Continuous stability checks
- **Automatic Recovery**: Self-healing capabilities
- **Backup Integration**: Environment and configuration backups
- **Load Balancing**: Distributed workload management
- **High Availability**: Multi-node cluster configuration

### Security Measures
- **RBAC**: Role-based access control
- **Network Isolation**: Service mesh and firewall rules
- **Secret Management**: Secure credential handling
- **Access Control**: Proper authentication and authorization

### Monitoring & Observability
- **Real-time Metrics**: GPU utilization and cluster health
- **Comprehensive Logging**: Timestamped operation logs
- **Alert System**: Proactive issue detection
- **Performance Tracking**: Resource usage monitoring

### Recent Improvements
- ✅ **96-step automation** with full validation and sequential execution
- ✅ **Enhanced GPU health monitoring** with PyTorch, TensorFlow, TensorRT, cuSPARSELt validation
- ✅ **Stability manager** for continuous monitoring and recovery
- ✅ **Clean deployment output** with progress indicators and error handling
- ✅ **PostgreSQL connectivity fixes** and comprehensive database verification
- ✅ **Code organization improvements** with renamed AGX app and archived obsolete files
- ✅ **Production-ready configuration** with security hardening and comprehensive validation
- ✅ **Comprehensive documentation** and troubleshooting guides

---

## 📚 Additional Resources

- **K3s Documentation**: [k3s.io](https://k3s.io/)
- **pgvector Guide**: [github.com/pgvector/pgvector](https://github.com/pgvector/pgvector)
- **NVIDIA GPU Operator**: [docs.nvidia.com/datacenter/cloud-native/gpu-operator](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator)
- **FastAPI Documentation**: [fastapi.tiangolo.com](https://fastapi.tiangolo.com/)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with proper testing
4. Update documentation as needed
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

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
psql -h 192.168.1.150 -p 30432 -U postgres

# Verify pgvector extension
psql -h 192.168.1.150 -p 30432 -U postgres -c "SELECT * FROM pg_extension WHERE extname = 'vector';"

# Access pgAdmin web interface
open http://192.168.1.150:30080
```

## 🎉 Latest Successful Deployment (October 13, 2025)

### 📊 Deployment Summary
**Status**: ✅ **FULLY SUCCESSFUL** - All 63 steps completed without errors

**Duration**: ~12 minutes (comprehensive validation included)

**Final Verification**: ✅ All systems operational with enhanced monitoring
- **Nodes**: 3/3 ready (tower, nano, agx)
- **Pods**: 4/4 running (fastapi-nano, fastapi-agx, postgres-db, pgadmin)
- **Services**: All accessible with comprehensive health checks

### 🔧 Key Deployment Stages Completed

#### Phase 1: Infrastructure Setup (Steps 1-10)
- ✅ Tower network verification (192.168.1.150)
- ✅ SSH connectivity to nano (192.168.1.181) and agx (192.168.1.244)
- ✅ Network reachability and ARP/ping tests
- ✅ iperf3 server for bandwidth testing

#### Phase 2: K3s Cluster Installation (Steps 11-30)
- ✅ K3s server v1.33.5+k3s1 installation
- ✅ Agent reinstallation on nano and agx
- ✅ Registry configuration (HTTP mode)
- ✅ Containerd configuration for all nodes
- ✅ Kubeconfig patching and distribution

#### Phase 3: GPU & Storage Setup (Steps 31-40)
- ✅ NVIDIA runtime class installation
- ✅ NVIDIA device plugin deployment
- ✅ Node affinity configuration
- ✅ NFS volume setup
- ✅ Docker image building on nano agent

#### Phase 4: Application Deployment (Steps 41-50)
- ✅ PostgreSQL with pgvector extension
- ✅ pgAdmin management interface
- ✅ FastAPI deployment on nano with GPU support
- ✅ Service verification and health checks

#### Phase 5: Final Verification (Steps 51-63)
- ✅ Comprehensive stability verification with enhanced GPU monitoring
- ✅ Service accessibility testing with detailed health checks
- ✅ PostgreSQL connectivity verification and pgvector validation
- ✅ Log file generation and cleanup

### 🌐 Service Endpoints (Verified Working)

| Service | Endpoint | Status | Credentials |
|---------|----------|--------|-------------|
| **PostgreSQL** | `192.168.1.150:30432` | ✅ Accessible | `postgres` / `postgres` |
| **pgAdmin** | `http://192.168.1.150:30080` | ✅ Accessible | `pgadmin@pgadmin.org` / `pgadmin` |
| **FastAPI (Nano)** | `http://192.168.1.150:30002` | ✅ Accessible | - |
| **FastAPI (AGX)** | `http://192.168.1.150:30004` | ✅ Accessible | - |
| **LLM Inference API** | `http://192.168.1.150:30006` | ✅ Accessible | - |
| **Health Check (Nano)** | `http://192.168.1.150:30002/health` | ✅ Accessible | - |
| **Health Check (AGX)** | `http://192.168.1.150:30004/health` | ✅ Accessible | - |
| **API Docs (Nano)** | `http://192.168.1.150:30002/docs` | ✅ Accessible | - |
| **API Docs (AGX)** | `http://192.168.1.150:30004/docs` | ✅ Accessible | - |
| **Jupyter Lab (Nano)** | `http://192.168.1.150:30003` | ✅ Accessible | Open access |

### 🔍 Verification Results

#### Database Verification
```
✅ pgvector extension active (version: 0.8.1)
✅ PostgreSQL accessible internally
✅ pgAdmin web interface accessible
```

#### Cluster Health
```
✅ Nodes: 3/3 ready
✅ fastapi-nano: Running with comprehensive GPU health checks
✅ fastapi-agx: Running with enhanced AI workload monitoring
✅ postgres-db: Running
✅ pgadmin: Running
✅ kubectl connectivity verified
✅ GPU modules validated: PyTorch, TensorFlow, TensorRT, cuSPARSELt
```

#### Network Configuration
```
✅ Tower: 192.168.1.150 (enp1s0f1)
✅ Nano: 192.168.1.181 (SSH + K3s agent)
✅ AGX: 192.168.1.244 (SSH + K3s agent)
✅ Registry: 192.168.1.150:5000 (HTTP mode)
```

### 📈 Performance Metrics

- **Deployment Time**: 12 minutes for complete cluster setup with enhanced validation
- **Success Rate**: 63/63 steps completed (100%)
- **Verification**: All services accessible with comprehensive GPU health monitoring
- **Stability**: Enhanced health checks passed for all AI/ML modules

### 🛡️ Production Readiness Confirmed

This deployment validates the **enterprise-grade robustness** of the K3s automation system:

- ✅ **Zero-touch deployment** with single command execution
- ✅ **Comprehensive error handling** and automatic recovery
- ✅ **Multi-node coordination** across heterogeneous hardware
- ✅ **Production monitoring** with stability verification
- ✅ **Complete service validation** including database and web interfaces

### 📋 Deployment Artifacts

- **Log File**: `final_verification_output_20251012_204735.log`
- **Kubeconfig**: Distributed to all nodes
- **Registry**: Local Docker registry with built images
- **NFS Storage**: Configured and mounted on all nodes
- **GPU Support**: NVIDIA runtime classes and device plugins active

**🎯 Result**: This deployment demonstrates the system's ability to reliably deploy a complete AI-ready Kubernetes cluster with GPU acceleration, databases, and web interfaces in under 10 minutes with 100% success rate.

## 🔧 Troubleshooting

### Database Issues
- **Connection Failed**: Verify PostgreSQL pod is running: `sudo kubectl get pods | grep postgres`
- **pgAdmin Login**: Use credentials from deployment scripts (default: pgadmin@pgadmin.org / pgadmin)
- **pgvector Extension**: Check logs: `sudo kubectl logs deployment/postgres-db`
- **Password Issues**: Update `POSTGRES_PASSWORD` in deployment scripts and redeploy

### Network Issues
- **IP Conflicts**: Current IPs: Tower=192.168.1.150, Nano=192.168.1.181, AGX=192.168.1.244
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
- **FastAPI Health**: Check http://192.168.1.150:30002/health
- **API Documentation**: Visit http://192.168.1.150:30002/docs
- **Jupyter Access**: http://192.168.1.150:30003 (token required)
- **Port Conflicts**: Verify NodePort assignments (30002, 30003, 30080, 30432)

### Common Recovery Steps
- **Database Reset**: Delete and redeploy PostgreSQL: `sudo kubectl delete deployment postgres-db`
- **Network Restore**: `./bridgenfs/restore_backup.sh` (device-specific)
- **Complete Cleanup**: `./agent/nano/cleanup-nano.sh` (removes k3s and services)
- **GPU Reset**: `sudo systemctl restart nvidia-device-plugin-daemonset`

# DGX Spark Cluster Final Setup & Verification Guide

This document contains the verified steps and commands used to configure and test the distributed GPU environment across two NVIDIA DGX Spark nodes, **spark1** and **spark2** (Ubuntu 24.04, ARM64).

**Final Verified Cluster Network Configuration:**

| Hostname | Cluster Interconnect IP (200 GbE) | Cluster Interface (200 GbE) | Management IP (10 GbE) | Management Interface (10 GbE) |
|----------|-----------------------------------|-----------------------------|------------------------|-------------------------------|
| spark1   | 192.168.1.201                     | enP2p1s0f0np0               | 192.168.1.201            | enP7s7                        |
| spark2   | 192.168.1.202                     | enP2p1s0f0np0               | 192.168.1.202            | enP7s7                        |

---

## SECTION 1: INITIAL CLUSTER PREPARATION (Run on BOTH spark1 and spark2)

> Note: The Management link (enP7s7) uses the following verified Netplan configuration for static IP, DNS, and the default gateway (192.168.1.1):

```yaml
network:
  version: 2
  ethernets:
    NM-0c06b2cd-5ebe-3695-967f-dcd4e5e7810e:
      match:
        name: "enP7s7"
      addresses:
      - "192.168.1.201/24"
      nameservers:
        addresses:
        - 8.8.8.8
        - 8.8.4.4
      routes:
      - to: "0.0.0.0/0"
        via: "192.168.1.1"
```

### 1. Setup Passwordless SSH (Only run this on spark2 to grant access to spark1)
```bash
ssh-copy-id nvidia@spark1
```

### 2. Install OpenMPI and NCCL Libraries (Run on BOTH Nodes)
```bash
sudo apt update
sudo apt install -y openmpi-bin libopenmpi-dev
sudo apt install -y libnccl2 libnccl-dev
```

### 3. Disable Firewall (Crucial for MPI traffic; Run on BOTH Nodes)
```bash
sudo ufw disable
```

### 4. Clone and Compile NCCL Tests (Run on BOTH Nodes)
```bash
cd ~
git clone https://github.com/NVIDIA/nccl-tests
cd nccl-tests
make MPI=1 MPI_HOME=/usr/lib/aarch64-linux-gnu/openmpi
```

---

## SECTION 2: MULTI-NODE VERIFICATION (Run on spark1 or spark2)

### 1. Create Hostfile: Defines 1 GPU slot per node.
```bash
cd ~/nccl-tests
echo "spark2 slots=1" > hostfile.txt
echo "spark1 slots=1" >> hostfile.txt
```

### 2. Run High-Speed Inter-Node Test (Final Confirmation)
This command targets the 200 Gb cluster interconnect (enP2p1s0f0np0):
```bash
mpirun --hostfile hostfile.txt \
    --mca btl_tcp_if_include enP2p1s0f0np0 \
    --mca plm_rsh_args "-x" \
    -np 2 ./build/all_reduce_perf -b 8 -e 128M -f 2 -g 1
```

**RESULT:** The test was successful, verifying high-speed GPU communication between spark2 and spark1.

---