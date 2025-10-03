#!/bin/bash
# AGX Directory Structure Setup Script
# Run this script ON THE AGX SYSTEM to create the Kubernetes directory structure

echo "Creating Kubernetes directory structure on AGX system..."

# Create main directory structure on AGX
mkdir -p /home/sanjay/containers/kubernetes/agent/agx
mkdir -p /home/sanjay/containers/kubernetes/agent/nano
mkdir -p /home/sanjay/containers/kubernetes/server

echo "✅ Created /home/sanjay/containers/kubernetes/agent/agx"
echo "✅ Created /home/sanjay/containers/kubernetes/agent/nano"
echo "✅ Created /home/sanjay/containers/kubernetes/server"

# Create AGX-specific README
cat > /home/sanjay/containers/kubernetes/agent/agx/README.md << 'EOF'
# Kubernetes AGX Agent Setup

This directory contains AGX-specific scripts and configurations for joining the tower's Kubernetes cluster.

## AGX Device Configuration:
- Server IP: 192.168.10.1 (AGX subnet access to tower)
- Node Name: agx
- Token Path: /export/vmstore/agx_home/containers/fastapi/.token/
- Role: k3s agent node

## Files:
- `k3s-agx-setup.sh` - AGX agent setup script (to be added)
- `README.md` - This documentation

## Usage:
```bash
# Run on AGX device to join cluster
./k3s-agx-setup.sh
```
EOF

# Create nano reference README (for completeness)
cat > /home/sanjay/containers/kubernetes/agent/nano/README.md << 'EOF'
# Kubernetes Nano Agent Setup

This directory would contain Nano-specific scripts and configurations.

## Nano Device Configuration:
- Server IP: 192.168.5.1 (Nano subnet access to tower)
- Node Name: nano
- Token Path: /export/vmstore/nano_home/containers/fastapi_nano/.token/
- Role: k3s agent node with GPU support

## Files:
- `k3s-nano-setup.sh` - Nano agent setup script (to be added)
- `README.md` - This documentation
EOF

# Create server reference
cat > /home/sanjay/containers/kubernetes/server/README.md << 'EOF'
# Server Components Reference (AGX)

This directory serves as a reference to server components that run on the tower.
The AGX device acts as an agent node and connects to these services.

## Server Components (on Tower):
- k3s server (control plane)
- PostgreSQL database
- pgAdmin interface  
- Docker registry

## AGX Access:
- Tower API: https://192.168.10.1:6443
- PostgreSQL: 192.168.10.1:5432
- pgAdmin: http://192.168.10.1:8080

## AGX Role:
- k3s agent node
- Workload execution
- Service consumption
EOF

# Set proper permissions
chown -R sanjay:sanjay /home/sanjay/containers/kubernetes 2>/dev/null || true
chmod 755 /home/sanjay/containers/kubernetes/agent/agx
chmod 755 /home/sanjay/containers/kubernetes/agent/nano  
chmod 755 /home/sanjay/containers/kubernetes/server

echo ""
echo "🎉 AGX Kubernetes directory structure created successfully!"
echo ""
echo "Directory structure on AGX:"
echo "/home/sanjay/containers/kubernetes/"
echo "├── agent/"
echo "│   ├── agx/              # AGX-specific agent setup"
echo "│   │   ├── README.md"
echo "│   │   └── (k3s-agx-setup.sh - to be added)"
echo "│   └── nano/             # Nano reference"
echo "│       └── README.md"
echo "└── server/               # Server components reference"
echo "    └── README.md"
echo ""
echo "Next steps on AGX:"
echo "1. Copy your working AGX agent script to agent/agx/k3s-agx-setup.sh"
echo "2. Share the working script with tower for sync"
echo "3. Test the AGX agent setup"