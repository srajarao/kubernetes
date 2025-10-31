# Script Execution Web Interface - Project Plan

## Overview
Create a web-based interface for executing cluster management scripts with real-time terminal output display.

## Technology Stack

### Backend
- **Framework**: FastAPI (Python)
  - Already familiar technology in the cluster
  - Excellent async support for script execution
  - Built-in OpenAPI documentation
  - Lightweight and fast

### Frontend
- **HTML5**: Structure and semantic markup
- **CSS3**: Styling with modern features (Flexbox, Grid, CSS Variables)
- **Vanilla JavaScript**: Interactivity and API communication
  - No heavy frameworks to reduce complexity
  - ES6+ features for modern browser support

### Real-time Communication
- **WebSocket**: For streaming script execution output
  - Bidirectional communication
  - Real-time updates as scripts run
  - Connection management for long-running scripts

### Hosting & Deployment
- **Platform**: Kubernetes (existing cluster)
- **Service Type**: ClusterIP with Ingress for external access
- **Container**: Docker with Python base image
- **Persistence**: None required (stateless application)

## Architecture

### Components
1. **Script Discovery Service**: Scans directories and categorizes scripts
2. **Script Execution Engine**: Runs scripts with output capture
3. **WebSocket Manager**: Handles real-time output streaming
4. **Web Interface**: User-friendly script selection and execution
5. **Terminal Emulator**: Displays script output in real-time

### Directory Structure
```
script-executor/
├── app/
│   ├── main.py              # FastAPI application
│   ├── script_manager.py    # Script discovery and execution
│   ├── websocket.py         # WebSocket handling
│   └── models.py            # Pydantic models
├── static/
│   ├── css/
│   │   └── styles.css
│   ├── js/
│   │   ├── app.js
│   │   └── terminal.js
│   └── index.html
├── Dockerfile
├── requirements.txt
└── deployment.yaml
```

## Script Categories & Locations

### Server Utilities (`server/utils/`)
- **Agent Management**: `agent/` - Add/remove cluster agents
- **Host Configuration**: `host/` - Host file and network setup
- **Memory Monitoring**: `memory/` - System memory checks
- **NFS Management**: `nfs/` - NFS mount configuration
- **Network Testing**: `ping/` - Connectivity verification
- **SSH Setup**: `ssh/` - SSH key distribution

### General Scripts (`scripts/`)
- **Backup/Restore**: `backup_home.sh`, `restore_backup.sh`
- **Service Monitoring**: `monitor-service.sh`
- **NFS Updates**: `update-nfs-*.sh`
- **Validation**: `validate-k3s-agent.sh`
- **Environment**: `env.sh`

### Agent Scripts (`agent/*/`)
- **Deployment Scripts**: FastAPI deployment configurations
- **Setup Scripts**: Node-specific initialization
- **Health Checks**: Service monitoring scripts

## Features

### Core Functionality
- [ ] Script discovery and categorization
- [ ] Script execution with parameter support
- [ ] Real-time output streaming
- [ ] Execution history and status tracking
- [ ] Error handling and timeout management

### User Interface
- [ ] Responsive design for desktop/mobile
- [ ] Script filtering and search
- [ ] Execution queue management
- [ ] Dark/light theme toggle
- [ ] Terminal output with syntax highlighting

### Security & Safety
- [ ] Script validation before execution
- [ ] Execution confirmation dialogs
- [ ] Timeout controls for long-running scripts
- [ ] Audit logging of script executions
- [ ] User authentication (if needed)

## Implementation Phases

### Phase 1: Core Backend (Week 1)
- FastAPI application setup
- Script discovery service
- Basic script execution endpoint
- Docker containerization

### Phase 2: Real-time Features (Week 2)
- WebSocket implementation
- Output streaming
- Execution status tracking
- Error handling

### Phase 3: Frontend Development (Week 3)
- HTML/CSS structure
- JavaScript functionality
- Terminal interface
- Responsive design

### Phase 4: Integration & Testing (Week 4)
- Kubernetes deployment
- End-to-end testing
- Performance optimization
- Documentation

## Dependencies

### Python Packages
```
fastapi==0.104.1
uvicorn[standard]==0.24.0
websockets==12.0
pydantic==2.5.0
python-multipart==0.0.6
```

### Frontend Libraries
- **xterm.js**: Terminal emulation (optional)
- **Font Awesome**: Icons
- **Google Fonts**: Monospace fonts for terminal

## Deployment Configuration

### Kubernetes Resources
- **Deployment**: Single replica with resource limits
- **Service**: ClusterIP for internal access
- **Ingress**: External access with TLS
- **ConfigMap**: Script directory paths
- **RBAC**: Service account permissions

### Environment Variables
```
SCRIPT_BASE_PATH=/home/sanjay/containers/kubernetes
ALLOWED_SCRIPT_DIRS=server/utils,scripts,agent
EXECUTION_TIMEOUT=300
WEBSOCKET_TIMEOUT=3600
```

## Success Criteria

### Functional Requirements
- [ ] All scripts discoverable through web interface
- [ ] Scripts execute successfully with real-time output
- [ ] Terminal-like display shows script progress
- [ ] Multiple scripts can run concurrently
- [ ] Execution history maintained

### Non-Functional Requirements
- [ ] Response time < 2 seconds for script listing
- [ ] WebSocket latency < 100ms for output streaming
- [ ] 99.9% uptime for the service
- [ ] Mobile-responsive interface
- [ ] Accessible design (WCAG 2.1 AA)

## Risk Assessment

### Technical Risks
- **Script Security**: Malicious script execution
  - Mitigation: Script validation and sandboxing
- **Resource Consumption**: Long-running scripts exhausting resources
  - Mitigation: Timeout controls and resource limits
- **WebSocket Complexity**: Real-time streaming implementation
  - Mitigation: Thorough testing and fallback mechanisms

### Operational Risks
- **Service Availability**: Single point of failure
  - Mitigation: Health checks and monitoring
- **User Errors**: Accidental execution of destructive scripts
  - Mitigation: Confirmation dialogs and execution logging

## Next Steps

1. **Immediate**: Create basic FastAPI application structure
2. **Week 1**: Implement script discovery and basic execution
3. **Week 2**: Add WebSocket support and frontend prototype
4. **Week 3**: Complete UI/UX and testing
5. **Week 4**: Production deployment and monitoring setup

---

*Document Version: 1.0*
*Last Updated: October 30, 2025*
*Author: AI Assistant*