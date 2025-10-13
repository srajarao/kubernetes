# ==========================================
# COMMON INFRASTRUCTURE CONFIGURATION
# ==========================================

# NFS Configuration (shared across all nodes)
NFS_SERVER="10.1.10.150"      # NFS server IP
NFS_SHARE="/vmstore"          # NFS share path

# SSH Configuration
SSH_KEY_TYPE="rsa"            # rsa, ed25519
SSH_KEY_BITS="4096"           # for rsa keys

# User Configuration
DEFAULT_USER="sanjay"         # Default user for all nodes
KUBERNETES_DIR="/home/sanjay/kubernetes/agent"  # Standard directory

# ==========================================
# NODE CLUSTER CONFIGURATION
# ==========================================

# Node Types to Include in Cluster
# Options: tower, nano, agx, x86-worker, arm-worker
# Example: "tower,nano,agx" or "tower,x86-worker"
CLUSTER_NODES="tower,nano,agx"

# ==========================================
# NODE-SPECIFIC CONFIGURATIONS
# ==========================================

# Tower (Server) Configuration
TOWER_IP="10.1.10.150"
TOWER_ARCH="amd64"
TOWER_COMPONENTS="server,postgres,pgadmin,jupyter"  # Components to install
TOWER_BASE_IMAGE="ubuntu-minimal"  # Base image key from image-matrix.sh

# Jetson Nano Configuration
NANO_IP="10.1.10.181"
NANO_ARCH="arm64"
NANO_COMPONENTS="python,cuda,tensorrt,fastapi,gpu-monitoring"  # Components to install
NANO_BASE_IMAGE="l4t-minimal"  # Base image key from image-matrix.sh
NANO_IMAGE_NAME="fastapi_nano"
NANO_IMAGE_TAG="latest"
NANO_DOCKERFILE="agent/nano/dockerfile.nano.req"  # Will be auto-generated
NANO_REQUIREMENTS="agent/nano/requirements.nano.txt"  # Will be auto-generated

# Jetson AGX Configuration
AGX_IP="10.1.10.244"
AGX_ARCH="arm64"
AGX_COMPONENTS="python,cuda,tensorrt,pytorch,tensorflow,fastapi,gpu-monitoring,llm,rag"  # Components to install
AGX_BASE_IMAGE="l4t-minimal"  # Base image key from image-matrix.sh
AGX_IMAGE_NAME="fastapi_agx"
AGX_IMAGE_TAG="latest"
AGX_DOCKERFILE="agent/agx/dockerfile.agx.req"  # Will be auto-generated
AGX_REQUIREMENTS="agent/agx/requirements.agx.txt"  # Will be auto-generated

# ==========================================
# REGISTRY & BUILD CONFIGURATION
# ==========================================

REGISTRY_IP="10.1.10.150"
REGISTRY_PORT="5000"
REGISTRY_PROTOCOL="https"  # "http" or "https"
REGISTRY_URL="$REGISTRY_IP:$REGISTRY_PORT"

# Build Options
BUILD_MODE="selective"  # "all" or "selective" (only build for enabled nodes)
FORCE_REBUILD=false     # Force rebuild even if image exists

# ==========================================
# DATABASE CONFIGURATION
# ==========================================

POSTGRES_PASSWORD="postgres"
PGADMIN_PASSWORD="pgadmin"
PGADMIN_EMAIL="pgadmin@pgadmin.org"

# ==========================================
# DEBUG & LOGGING
# ==========================================

DEBUG=0  # 0=silent, 1=verbose, 2=debug

# ==========================================
# LEGACY COMPATIBILITY (will be deprecated)
# ==========================================

# Keep for backward compatibility during transition
INSTALL_SERVER=true
INSTALL_NANO_AGENT=true
INSTALL_AGX_AGENT=true