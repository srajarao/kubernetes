# 🚀 Cluster Management Application

This folder contains the **cluster management web application** that runs on the dedicated **nano management node**. This is a **bootstrap implementation** that will evolve into a full cluster management platform.

## 📁 Project Structure

### **Tower (Development Environment)**
```
~/containers/kubernetes/cluster-management/
├── bootstrap_app.py           # FastAPI web application (Phase 1)
├── bootstrap_requirements.txt # Python dependencies
├── quick_deploy.sh           # ⚡ Quick deployment to nano
├── deploy_to_nano.sh         # 🔧 Full setup & deployment
└── README.md                 # 📖 This documentation
```

### **Nano (Production Environment)**
```
/home/sanjay/containers/kubernetes/cluster-management/
├── bootstrap_app.py          # 🚀 Live application
├── bootstrap_requirements.txt # 📦 Dependencies
├── management_venv/          # 🐍 Python virtual environment
├── server.log                # 📋 Application logs
└── __pycache__/              # 💾 Python bytecode cache
```

## 🎯 Current Phase: Security & Authentication (Phase 7/7)

### ✅ **Completed Features**
- 🌐 **Web Server**: FastAPI application with HTML interface
- 🏗️ **Architecture**: Dedicated management node (nano) - no chicken-and-egg problem
- 📁 **Organization**: Consistent folder structure for easy backups
- 🚀 **Deployment**: Automated deployment scripts
- 🩺 **Health Monitoring**: Health checks and API endpoints
- 📊 **Script Discovery**: Automatic scanning and cataloging of 94+ scripts
- ▶️ **Script Execution**: Asynchronous execution with output capture
- 🔄 **Real-time Streaming**: WebSocket-based live output streaming during execution
- 🐳 **Docker Integration**: Complete Docker container management and building
- 🌳 **Cluster Visualization**: Tree-based cluster structure display
- 📊 **Node Monitoring**: Real-time node status checking (ping, SSH connectivity)
- 🎯 **Multi-Node Operations**: Select and operate on multiple nodes simultaneously
- 🔐 **User Authentication**: JWT-based login system with secure password hashing
- 👥 **Role-Based Access**: Admin, Operator, and Viewer roles with different permissions
- 🛡️ **Session Management**: Secure token-based authentication with expiration

### 🔄 **Next Phases**
1. ~~**Phase 2**: Script Discovery - Scan and catalog cluster scripts~~ ✅ **COMPLETED**
2. ~~**Phase 3**: Basic Script Execution - Run scripts with output capture~~ ✅ **COMPLETED**
3. ~~**Phase 4**: WebSocket Integration - Real-time streaming output~~ ✅ **COMPLETED**
4. ~~**Phase 5**: Container Building - Docker capabilities~~ ✅ **COMPLETED**
5. ~~**Phase 6**: Full Cluster UI - Tree structure and node management~~ ✅ **COMPLETED**
6. ~~**Phase 7**: Security & Authentication - User management and access control~~ ✅ **COMPLETED**

## 🚀 Development Workflow

### **Quick Development Cycle**
```bash
# 1. Make changes on Tower
cd ~/containers/kubernetes/cluster-management/
edit bootstrap_app.py

# 2. Deploy instantly to Nano
./quick_deploy.sh

# 3. Test live application
curl http://192.168.1.181:8000/
```

### **Full Setup (First Time)**
```bash
./deploy_to_nano.sh  # Complete environment setup
```

## 🌐 Live Application

### **HTTP (Demo Mode - No Warnings)**
- **URL**: http://192.168.1.181:8000/
- **Status**: Available (clean browser access)

### **HTTPS (Production - Encrypted)**
- **URL**: https://192.168.1.181:8443/
- **SSL**: Self-signed certificate (auto-generated)
- **Status**: ✅ Currently Running

### **SSL Certificate Notes**
- Self-signed certificate generated automatically
- Browser will show security warning (normal for internal use)
- Certificate valid for: `cluster-management.local`, `localhost`, `192.168.1.181`
- Safe to proceed past browser warnings for cluster management

### **Starting HTTPS Server**
```bash
# On nano node:
/home/sanjay/containers/kubernetes/cluster-management/start_https.sh
```

### **Testing HTTPS**
```bash
# Health check (ignore SSL warnings)
curl -k https://192.168.1.181:8443/health

# Main interface
curl -k https://192.168.1.181:8443/
```

### **Switching Between HTTP/HTTPS**
```bash
# Switch to HTTPS (Production)
ssh nano './start_https.sh'

# Switch to HTTP (Demo)
ssh nano 'pkill -f uvicorn && python bootstrap_app.py'
```

## 📋 API Endpoints

| Protocol | Endpoint | Method | Description | Status |
|----------|----------|--------|-------------|---------|
| HTTP | `http://192.168.1.181:8000/` | GET | Main web interface | ✅ Active |
| HTTPS | `https://192.168.1.181:8443/` | GET | Main web interface (encrypted) | ✅ Active |
| HTTP | `http://192.168.1.181:8000/health` | GET | Health check endpoint | ✅ Active |
| HTTPS | `https://192.168.1.181:8443/health` | GET | Health check endpoint | ✅ Active |
| HTTP | `http://192.168.1.181:8000/api/info` | GET | Application information | ✅ Active |
| HTTPS | `https://192.168.1.181:8443/api/info` | GET | Application information | ✅ Active |
| `/api/scripts/stats` | GET | Script statistics | ✅ Active |
| `/api/scripts/execute` | POST | Execute script (batch mode) | ✅ Active |
| `/api/scripts/execute/test` | GET | Test execution framework | ✅ Active |
| `/ws/execute` | WebSocket | **Real-time script execution with live output streaming** | ✅ **NEW** |
| `/api/docker/info` | GET | Docker system information | ✅ **NEW** |
| `/api/docker/images` | GET | List all Docker images | ✅ **NEW** |
| `/api/docker/containers` | GET | List all Docker containers | ✅ **NEW** |
| `/api/docker/build` | POST | Build Docker image from Dockerfile | ✅ **NEW** |
| `/ws/docker/build` | WebSocket | **Real-time Docker image building** | ✅ **NEW** |
| `/api/cluster/nodes` | GET | Cluster node information and configuration | ✅ **NEW** |
| `/api/cluster/status` | GET | Real-time cluster node status (ping, SSH) | ✅ **NEW** |
| `/api/cluster/ping` | POST | Ping selected nodes for connectivity | ✅ **NEW** |
| `/api/auth/login` | POST | User authentication - returns JWT token | ✅ **NEW** |
| `/api/auth/logout` | POST | User logout | ✅ **NEW** |
| `/api/auth/me` | GET | Get current user information | ✅ **NEW** |
| `/api/auth/users` | GET | List all users (admin only) | ✅ **NEW** |

### **Response Examples**
```bash
# Health Check
curl -k https://192.168.1.181:8443/health
{"status":"healthy","phase":"bootstrap","server":"native-python"}

# API Info
curl http://192.168.1.181:8000/api/info
{"name":"Script Executor Bootstrap","version":"0.1.0","phase":"bootstrap",...}

# WebSocket Real-time Execution
# Connect via WebSocket to ws://192.168.1.181:8000/ws/execute
# Send: {"script_path": "/path/to/script.sh", "timeout": 30}
# Receive: Real-time stdout/stderr streaming + completion status
```

## 🛠️ Deployment Scripts

### **quick_deploy.sh** - ⚡ Fast Deployment
- Copies code changes to nano
- Restarts application automatically
- Use for iterative development

### **deploy_to_nano.sh** - 🔧 Full Setup
- Creates directory structure on nano
- Sets up Python virtual environment
- Installs all dependencies
- Use for initial setup or major changes

## 🏗️ Architecture Overview

| Component | Tower (Dev) | Nano (Prod) | Purpose |
|-----------|-------------|-------------|---------|
| **Codebase** | `~/containers/kubernetes/cluster-management/` | `/home/sanjay/containers/kubernetes/cluster-management/` | Source code and scripts |
| **Runtime** | Local testing | Live production | Application execution |
| **Framework** | FastAPI + Uvicorn | FastAPI + Uvicorn | Web framework and server |
| **Deployment** | Manual/SSH | Automated scripts | Code deployment |
| **Backup** | Git repository | `backup_home.sh` compatible | Data persistence |

### **Key Architectural Decisions**
- ✅ **Dedicated Management Node**: Nano runs management app outside cluster
- ✅ **No Chicken-and-Egg Problem**: Management exists independently
- ✅ **Consistent Paths**: Same folder structure on both machines
- ✅ **Automated Deployment**: One-command deployment workflow
- ✅ **Backup Friendly**: Organized structure works with existing backup scripts

## 🔧 Technical Details

- **Python Version**: 3.10+ (both Tower and Nano)
- **Web Framework**: FastAPI (modern, fast, auto API docs)
- **ASGI Server**: Uvicorn (high-performance async server)
- **Deployment**: SSH + SCP automation
- **Virtual Environment**: Isolated Python environment on Nano
- **Logging**: File-based logging with rotation

## 📈 Roadmap

### **Immediate Next Steps**
- 🔍 **Script Discovery**: Scan filesystem for cluster management scripts
- ▶️ **Script Execution**: Basic script running with output capture
- 🔄 **Real-time Updates**: WebSocket integration for live output

### **Future Enhancements**
- 🐳 **Container Management**: Docker build and deployment capabilities
- 🌳 **Tree Interface**: Hierarchical cluster visualization
- 📊 **Node Monitoring**: Real-time cluster status and health
- 🔐 **Security**: Authentication and authorization
- 📱 **Mobile Support**: Responsive web interface

## 🤝 Contributing

1. Make changes in Tower's `cluster-management/` folder
2. Test locally if possible
3. Deploy to Nano: `./quick_deploy.sh`
4. Verify live application: http://192.168.1.181:8000/
5. Commit changes to git repository

---

**Status**: 🟢 **BOOTSTRAP COMPLETE - PRODUCTION READY** - All 7 phases successfully completed with enterprise-grade security and full cluster management capabilities
**Last Updated**: October 31, 2025
**Version**: 1.0.0 (Production Ready)