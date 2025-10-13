#!/bin/bash
# node-config.sh - Node Configuration Parser and Validator
# This file provides functions to parse and validate the new node configuration system

# ==========================================
# NODE CONFIGURATION FUNCTIONS
# ==========================================

# Source the image matrix
if [ -f "$SCRIPT_DIR/image-matrix.sh" ]; then
  source "$SCRIPT_DIR/image-matrix.sh"
else
  echo "WARNING: image-matrix.sh not found, using basic configuration"
fi

# Parse CLUSTER_NODES into an array
parse_cluster_nodes() {
    local nodes_string="$1"
    # Remove spaces and split by comma
    echo "$nodes_string" | tr -d ' ' | tr ',' '\n'
}

# Validate node configuration
validate_node_config() {
    local node_type="$1"

    case "$node_type" in
        "tower")
            if [ -z "$TOWER_IP" ]; then
                echo "ERROR: TOWER_IP not set for tower node"
                return 1
            fi
            ;;
        "nano")
            if [ -z "$NANO_IP" ] || [ -z "$NANO_IMAGE_NAME" ]; then
                echo "ERROR: NANO_IP or NANO_IMAGE_NAME not set for nano node"
                return 1
            fi
            ;;
        "agx")
            if [ -z "$AGX_IP" ] || [ -z "$AGX_IMAGE_NAME" ]; then
                echo "ERROR: AGX_IP or AGX_IMAGE_NAME not set for agx node"
                return 1
            fi
            ;;
        "x86-worker"|"arm-worker")
            echo "INFO: Generic worker node type '$node_type' - ensure IP and image are configured"
            ;;
        *)
            echo "WARNING: Unknown node type '$node_type'"
            ;;
    esac

    return 0
}

# Get node base image key (for matrix lookup)
get_node_base_image_key() {
    local node_type="$1"

    case "$node_type" in
        "tower") echo "$TOWER_BASE_IMAGE" ;;
        "nano") echo "$NANO_BASE_IMAGE" ;;
        "agx") echo "$AGX_BASE_IMAGE" ;;
        *) echo "ubuntu-minimal" ;;  # Default
    esac
}

# Get full base image path from key
get_node_base_image_path() {
    local node_type="$1"
    local base_key=$(get_node_base_image_key "$node_type")

    if [ -n "${BASE_IMAGES[$base_key]}" ]; then
        echo "${BASE_IMAGES[$base_key]}"
    else
        echo "ubuntu:22.04"  # Fallback
    fi
}

# Get recommended components for node type
get_node_recommended_components() {
    local node_type="$1"

    # Start with common components that ALL nodes need
    local components="infrastructure,networking,storage"

    # Add node-specific components
    case "$node_type" in
        "tower") components="$components,server,postgres,pgadmin,jupyter,database" ;;
        "nano") components="$components,python,cuda,tensorrt,fastapi,gpu-monitoring" ;;
        "agx") components="$components,python,cuda,tensorrt,pytorch,tensorflow,fastapi,gpu-monitoring,llm,rag" ;;
        "x86-gpu") components="$components,python,cuda,cudnn,pytorch,tensorflow,fastapi,gpu-monitoring,llm,rag" ;;
        "x86-cpu") components="$components,python,fastapi,database,monitoring,jupyter" ;;
        *) components="$components,python,fastapi" ;;  # Minimal default
    esac

    echo "$components"
}

# Validate component compatibility with base image
validate_component_compatibility() {
    local component="$1"
    local base_image_key="$2"

    if [ -n "${COMPONENT_COMPATIBILITY[$component]}" ]; then
        echo "${COMPONENT_COMPATIBILITY[$component]}" | grep -q "$base_image_key"
        return $?
    fi

    # If no compatibility defined, assume compatible
    return 0
}

# Get compatible components for a base image
get_compatible_components() {
    local base_image_key="$1"
    local compatible=""

    for component in "${!COMPONENT_COMPATIBILITY[@]}"; do
        if echo "${COMPONENT_COMPATIBILITY[$component]}" | grep -q "$base_image_key"; then
            compatible="${compatible:+$compatible,}$component"
        fi
    done

    echo "$compatible"
}

# Generate Dockerfile for node type
generate_node_dockerfile() {
    local node_type="$1"
    local base_image=$(get_node_base_image_path "$node_type")
    local components=$(get_node_components "$node_type")
    local arch=$(get_node_arch "$node_type")

    cat << EOF
# Auto-generated Dockerfile for $node_type node
# Architecture: $arch
# Base Image: $base_image
# Components: $components
# Generated: $(date)

FROM $base_image

ENV DEBIAN_FRONTEND=noninteractive \\
    PIP_NO_CACHE_DIR=1 \\
    PYTHONUNBUFFERED=1 \\
    VIRTUAL_ENV=/opt/venv \\
    PATH="/opt/venv/bin:\$PATH"

USER root

# Install system dependencies based on components
$(generate_system_deps "$components" "$arch")

$(generate_cusparselt_install "$base_image" "$node_type")

$(generate_common_infrastructure "$node_type")

# Setup Python virtual environment
$(generate_python_setup "$components")

# Install Python packages based on components
$(generate_python_deps "$components")

# Copy application code
COPY app/src/ /app/app/src/
COPY app/config/ /app/app/config/

# Copy auto-generated health checks
COPY app/src/health_checks.py /app/app/src/health_checks.py

# Create necessary directories
RUN mkdir -p /app/app/logs /app/app/data /mnt/vmstore

# Expose ports (SSH + application ports)
EXPOSE 22 8888 8000

# Create startup script
$(generate_startup_script "$node_type")

# Set the default command for the container
WORKDIR /app
CMD ["/usr/local/bin/start-node.sh"]
EOF
}

# Generate system dependencies installation
generate_system_deps() {
    local components="$1"
    local arch="$2"
    local sys_deps=""

    # Parse components
    IFS=',' read -ra COMPONENT_ARRAY <<< "$components"

    for component in "${COMPONENT_ARRAY[@]}"; do
        if [ -n "${COMPONENT_DEPS[$component]}" ]; then
            # Only include system packages, not Python packages
            case "$component" in
                python)
                    # Python system packages
                    sys_deps="${sys_deps:+$sys_deps }${COMPONENT_DEPS[$component]}"
                    ;;
                cuda|cudnn|tensorrt)
                    # Skip CUDA/TensorRT - already in L4T base images
                    continue
                    ;;
                infrastructure|networking|storage)
                    # Infrastructure system packages
                    sys_deps="${sys_deps:+$sys_deps }${COMPONENT_DEPS[$component]}"
                    ;;
                *)
                    # Skip Python packages (handled by pip)
                    continue
                    ;;
            esac
        fi
    done

    if [ -n "$sys_deps" ]; then
        cat << EOF
# Install system dependencies
RUN --mount=type=cache,target=/var/cache/apt \\
    apt-get update && \\
    apt-get install -y --no-install-recommends \\
        $sys_deps ca-certificates curl wget git build-essential && \\
    rm -rf /var/lib/apt/lists/*
EOF
    fi
}

# Generate cuSPARSELt installation for Jetson devices (mandatory)
generate_cusparselt_install() {
    local base_image="$1"
    local node_type="$2"
    
    # cuSPARSELt is mandatory for all Jetson devices (nano and agx)
    if [[ "$node_type" == "nano" || "$node_type" == "agx" ]]; then
        cat << 'EOF'
# --- Install cuSPARSELt (Mandatory for Jetson devices) ---
RUN wget https://developer.download.nvidia.com/compute/cusparselt/0.8.0/local_installers/cusparselt-local-tegra-repo-ubuntu2204-0.8.0_0.8.0-1_arm64.deb -O /tmp/cusparselt.deb && \
    dpkg -i /tmp/cusparselt.deb && \
    cp /var/cusparselt-local-tegra-repo-ubuntu2204-0.8.0/cusparselt-*-keyring.gpg /usr/share/keyrings/ && \
    apt-get update && \
    apt-get install -y --no-install-recommends cusparselt && \
    rm -f /tmp/cusparselt.deb && ldconfig
EOF
    fi
}

# Generate Python dependencies installation
generate_python_deps() {
    local components="$1"
    local deps=""

    # Build list of Python packages to install
    for component in $(echo "$components" | tr ',' ' '); do
        if [ -n "${COMPONENT_PIP_DEPS[$component]}" ]; then
            # Include pip packages for this component
            deps="$deps ${COMPONENT_PIP_DEPS[$component]}"
        fi
    done

    if [ -n "$deps" ]; then
        cat << EOF
# Install Python packages
RUN \$VIRTUAL_ENV/bin/pip install $deps
EOF
    fi
}

# Generate common infrastructure setup for all nodes
generate_common_infrastructure() {
    local node_type="$1"
    local node_ip=$(get_node_ip "$node_type")
    local node_name="$node_type"

    cat << EOF
# ==========================================
# COMMON INFRASTRUCTURE SETUP
# ==========================================

# Create standard directory structure
$(generate_directory_structure)

# Configure SSH for passwordless access
$(generate_ssh_setup)

# Configure networking and DNS
$(generate_network_config "$node_ip" "$node_name")

# Configure NFS storage
$(generate_nfs_config)

# Set common environment variables
$(generate_environment_vars "$node_ip" "$node_name")

# Configure user and permissions
$(generate_user_setup)
EOF
}

# Generate standard directory structure
generate_directory_structure() {
    cat << 'EOF'
# Create standard directory structure
RUN mkdir -p \
    /home/sanjay/kubernetes/agent \
    /mnt/vmstore \
    /app/logs \
    /app/data \
    /app/config \
    /app/models \
    /var/log/kubernetes \
    /root/.ssh && \
    chmod 755 /home/sanjay && \
    chmod 755 /home/sanjay/kubernetes && \
    chmod 755 /home/sanjay/kubernetes/agent
EOF
}

# Generate SSH setup for passwordless access
generate_ssh_setup() {
    cat << 'EOF'
# Configure SSH for passwordless access between nodes
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client openssh-server && \
    mkdir -p /etc/ssh && \
    echo "StrictHostKeyChecking no" >> /etc/ssh/ssh_config && \
    echo "UserKnownHostsFile /dev/null" >> /etc/ssh/ssh_config && \
    echo "LogLevel ERROR" >> /etc/ssh/ssh_config

# Generate SSH keys if they don't exist
RUN if [ ! -f /root/.ssh/id_rsa ]; then \
        ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -N ""; \
    fi

# Copy SSH keys from host if available (will be mounted at runtime)
RUN mkdir -p /host-ssh && \
    if [ -f /host-ssh/id_rsa ]; then cp /host-ssh/id_rsa* /root/.ssh/; fi && \
    if [ -f /host-ssh/authorized_keys ]; then cp /host-ssh/authorized_keys /root/.ssh/; fi
EOF
}

# Generate network configuration
generate_network_config() {
    local node_ip="$1"
    local node_name="$2"

    cat << EOF
# Configure networking and DNS resolution
RUN mkdir -p /usr/local/bin && \
    echo '#!/bin/bash' > /usr/local/bin/configure-network.sh && \
    echo 'echo "$node_ip $node_name" >> /etc/hosts' >> /usr/local/bin/configure-network.sh && \
    echo 'echo "127.0.0.1 localhost" >> /etc/hosts' >> /usr/local/bin/configure-network.sh && \
    echo 'if [ -f /host-config/cluster-hosts ]; then cat /host-config/cluster-hosts >> /etc/hosts; fi' >> /usr/local/bin/configure-network.sh && \
    chmod +x /usr/local/bin/configure-network.sh
EOF
}

# Generate NFS configuration
generate_nfs_config() {
    cat << 'EOF'
# Configure NFS client
RUN mkdir -p /mnt/vmstore && \
    echo "# NFS mount will be configured at runtime" > /etc/fstab.nfs

# NFS mount script
RUN echo '#!/bin/bash' > /usr/local/bin/mount-nfs.sh && \
    echo 'if [ -n "$NFS_SERVER" ] && [ -n "$NFS_SHARE" ]; then' >> /usr/local/bin/mount-nfs.sh && \
    echo '    mount -t nfs $NFS_SERVER:$NFS_SHARE /mnt/vmstore' >> /usr/local/bin/mount-nfs.sh && \
    echo 'fi' >> /usr/local/bin/mount-nfs.sh && \
    chmod +x /usr/local/bin/mount-nfs.sh
EOF
}

# Generate environment variables
generate_environment_vars() {
    local node_ip="$1"
    local node_name="$2"

    cat << EOF
# Set common environment variables
ENV NODE_IP=$node_ip \\
    NODE_NAME=$node_name \\
    HOME=/home/sanjay \\
    KUBERNETES_DIR=/home/sanjay/kubernetes/agent \\
    VMSTORE_DIR=/mnt/vmstore \\
    LOG_DIR=/app/logs \\
    DATA_DIR=/app/data \\
    CONFIG_DIR=/app/config
EOF
}

# Generate user setup
generate_user_setup() {
    cat << 'EOF'
# Configure user environment
RUN useradd -m -s /bin/bash sanjay || true && \
    usermod -aG sudo sanjay || true && \
    echo 'sanjay ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers && \
    mkdir -p /home/sanjay/.ssh && \
    chmod 700 /home/sanjay/.ssh && \
    chown -R sanjay:sanjay /home/sanjay

# Copy user SSH keys if available
USER sanjay
RUN mkdir -p /home/sanjay/kubernetes/agent && \
    mkdir -p /home/sanjay/.ssh

USER root
RUN if [ -f /host-ssh/id_rsa ]; then cp /host-ssh/id_rsa* /home/sanjay/.ssh/ && chown sanjay:sanjay /home/sanjay/.ssh/*; fi && \
    if [ -f /host-ssh/authorized_keys ]; then cp /host-ssh/authorized_keys /home/sanjay/.ssh/ && chown sanjay:sanjay /home/sanjay/.ssh/authorized_keys; fi
EOF
}

# Get node IP by type
get_node_ip() {
    local node_type="$1"

    case "$node_type" in
        "tower") echo "$TOWER_IP" ;;
        "nano") echo "$NANO_IP" ;;
        "agx") echo "$AGX_IP" ;;
        *) echo "" ;;
    esac
}

# Get node architecture by type
get_node_arch() {
    local node_type="$1"

    case "$node_type" in
        "tower") echo "$TOWER_ARCH" ;;
        "nano") echo "$NANO_ARCH" ;;
        "agx") echo "$AGX_ARCH" ;;
        *) echo "amd64" ;;  # Default to x86
    esac
}

# Get node components by type
get_node_components() {
    local node_type="$1"

    case "$node_type" in
        "tower") echo "$TOWER_COMPONENTS" ;;
        "nano") echo "$NANO_COMPONENTS" ;;
        "agx") echo "$AGX_COMPONENTS" ;;
        *) echo "" ;;
    esac
}

# Get node image name by type
get_node_image_name() {
    local node_type="$1"

    case "$node_type" in
        "tower") echo "$TOWER_IMAGE_NAME" ;;
        "nano") echo "$NANO_IMAGE_NAME" ;;
        "agx") echo "$AGX_IMAGE_NAME" ;;
        *) echo "fastapi_$node_type" ;;  # Default pattern
    esac
}

# Generate requirements.txt for node type
generate_node_requirements() {
    local node_type="$1"
    local components=$(get_node_components "$node_type")

    cat << EOF
# Auto-generated requirements.txt for $node_type node
# Components: $components
# Generated: $(date)

EOF

    # Add Python packages based on components
    for component in $(echo "$components" | tr ',' ' '); do
        if [ -n "${COMPONENT_PIP_DEPS[$component]}" ]; then
            # Output each pip package on a new line
            for pkg in ${COMPONENT_PIP_DEPS[$component]}; do
                echo "$pkg"
            done
        fi
    done
}

# Get node image details
get_node_image() {
    local node_type="$1"
    local detail="$2"  # name, tag, dockerfile, requirements

    case "$node_type" in
        "nano")
            case "$detail" in
                "name") echo "$NANO_IMAGE_NAME" ;;
                "tag") echo "$NANO_IMAGE_TAG" ;;
                "dockerfile") echo "$NANO_DOCKERFILE" ;;
                "requirements") echo "$NANO_REQUIREMENTS" ;;
            esac
            ;;
        "agx")
            case "$detail" in
                "name") echo "$AGX_IMAGE_NAME" ;;
                "tag") echo "$AGX_IMAGE_TAG" ;;
                "dockerfile") echo "$AGX_DOCKERFILE" ;;
                "requirements") echo "$AGX_REQUIREMENTS" ;;
            esac
            ;;
    esac
}

# Check if node type should be installed (for backward compatibility)
should_install_node() {
    local node_type="$1"

    # Check new configuration first
    if echo "$CLUSTER_NODES" | grep -q "$node_type"; then
        return 0
    fi

    # Fall back to legacy flags
    case "$node_type" in
        "tower") [ "$INSTALL_SERVER" = true ] ;;
        "nano") [ "$INSTALL_NANO_AGENT" = true ] ;;
        "agx") [ "$INSTALL_AGX_AGENT" = true ] ;;
        *) return 1 ;;
    esac
}

# Get full image path for a node
get_full_image_path() {
    local node_type="$1"
    local image_name=$(get_node_image "$node_type" "name")
    local image_tag=$(get_node_image "$node_type" "tag")

    if [ -n "$image_name" ] && [ -n "$image_tag" ]; then
        echo "$REGISTRY_URL/$image_name:$image_tag"
    else
        echo ""
    fi
}

# Validate entire cluster configuration
validate_cluster_config() {
    echo "🔍 Validating cluster configuration..."

    # Parse cluster nodes
    local nodes=$(parse_cluster_nodes "$CLUSTER_NODES")
    local valid=true

    for node in $nodes; do
        echo "  Checking node: $node"
        if ! validate_node_config "$node"; then
            valid=false
        fi

        # Validate component compatibility
        local base_key=$(get_node_base_image_key "$node")
        local components=$(get_node_components "$node")

        if [ -n "$base_key" ] && [ -n "$components" ]; then
            IFS=',' read -ra COMPONENT_ARRAY <<< "$components"
            for component in "${COMPONENT_ARRAY[@]}"; do
                if ! validate_component_compatibility "$component" "$base_key"; then
                    echo "  WARNING: Component '$component' may not be compatible with base image '$base_key'"
                fi
            done
        fi
    done

    if [ "$valid" = true ]; then
        echo "✅ Cluster configuration is valid"
        return 0
    else
        echo "❌ Cluster configuration has errors"
        return 1
    fi
}

# Display cluster summary
show_cluster_summary() {
    echo "📊 Cluster Configuration Summary"
    echo "=================================="
    echo "Nodes: $CLUSTER_NODES"
    echo ""

    local nodes=$(parse_cluster_nodes "$CLUSTER_NODES")

    for node in $nodes; do
        echo "Node: $node"
        echo "  IP: $(get_node_ip "$node")"
        echo "  Arch: $(get_node_arch "$node")"
        echo "  Base Image: $(get_node_base_image_key "$node") -> $(get_node_base_image_path "$node")"
        echo "  Components: $(get_node_components "$node")"

        local image_path=$(get_full_image_path "$node")
        if [ -n "$image_path" ]; then
            echo "  Final Image: $image_path"
        fi
        echo ""
    done

    echo "Registry: $REGISTRY_URL"
    echo "Build Mode: $BUILD_MODE"
    echo "Debug Level: $DEBUG"
}

# Generate startup script for the container
generate_startup_script() {
    local node_type="$1"
    local components=$(get_node_components "$node_type")
    
    # Set environment variables based on components
    local env_vars=""
    if ! echo "$components" | grep -q "database\|postgres"; then
        env_vars="${env_vars}export SKIP_DB_CHECK=true\n"
    fi
    if ! echo "$components" | grep -q "jupyter"; then
        env_vars="${env_vars}export SKIP_JUPYTER_CHECK=true\n"
    fi
    if ! echo "$components" | grep -q "pytorch\|tensorflow"; then
        env_vars="${env_vars}export SKIP_GPU_CHECKS=true\n"
    fi

    cat << EOF
# Create startup script
RUN echo '#!/bin/bash' > /usr/local/bin/start-node.sh && \
    echo 'set -e' >> /usr/local/bin/start-node.sh && \
    echo '' >> /usr/local/bin/start-node.sh && \
    echo '# Set environment variables based on components' >> /usr/local/bin/start-node.sh && \
    echo '$env_vars' >> /usr/local/bin/start-node.sh && \
    echo '' >> /usr/local/bin/start-node.sh && \
    echo '# Configure network' >> /usr/local/bin/start-node.sh && \
    echo '/usr/local/bin/configure-network.sh' >> /usr/local/bin/start-node.sh && \
    echo '' >> /usr/local/bin/start-node.sh && \
    echo '# Start SSH service' >> /usr/local/bin/start-node.sh && \
    echo 'service ssh start' >> /usr/local/bin/start-node.sh && \
    echo '' >> /usr/local/bin/start-node.sh && \
    echo '# Mount NFS if configured' >> /usr/local/bin/start-node.sh && \
    echo '/usr/local/bin/mount-nfs.sh' >> /usr/local/bin/start-node.sh && \
    echo '' >> /usr/local/bin/start-node.sh && \
    echo '# Start the application' >> /usr/local/bin/start-node.sh && \
    echo 'exec python3 /app/app/src/fastapi_app.py' >> /usr/local/bin/start-node.sh && \
    chmod +x /usr/local/bin/start-node.sh
EOF
}

# Generate requirements.txt for node type
generate_node_requirements() {
    local node_type="$1"
    local components=$(get_node_components "$node_type")

    cat << EOF
# Auto-generated requirements.txt for $node_type node
# Components: $components
# Generated: $(date)

EOF

    # Parse components and add their Python dependencies
    IFS=',' read -ra COMPONENT_ARRAY <<< "$components"

    for component in "${COMPONENT_ARRAY[@]}"; do
        if [ -n "${COMPONENT_PIP_DEPS[$component]}" ]; then
            # Add comment and dependencies
            echo "# $component dependencies"
            # Convert space-separated to line-separated
            echo "${COMPONENT_PIP_DEPS[$component]}" | tr ' ' '\n'
            echo ""
        fi
    done

# Generate health check endpoints for node type
generate_node_health_checks() {
    local node_type="$1"
    local components=$(get_node_components "$node_type")

    cat << EOF
# Auto-generated health check endpoints for $node_type node
# Components: $components
# Generated: $(date)

from fastapi import APIRouter, HTTPException
from typing import Dict, Any
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

EOF

    # Parse components and add health checks
    IFS=',' read -ra COMPONENT_ARRAY <<< "$components"

    for component in "${COMPONENT_ARRAY[@]}"; do
        case "$component" in
            "fastapi")
                cat << 'EOF'

@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """Basic application health check"""
    return {
        "status": "healthy",
        "service": "fastapi",
        "timestamp": "2025-01-01T00:00:00Z"  # Will be replaced with actual timestamp
    }

EOF
                ;;
            "database")
                cat << 'EOF'

@router.get("/health/db")
async def database_health_check() -> Dict[str, Any]:
    """Database connectivity health check"""
    try:
        # Add your database health check logic here
        # Example: check PostgreSQL connection
        return {
            "status": "healthy",
            "service": "database",
            "connection": "ok"
        }
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        raise HTTPException(status_code=503, detail="Database unavailable")

EOF
                ;;
            "gpu-monitoring")
                cat << 'EOF'

@router.get("/health/gpu")
async def gpu_health_check() -> Dict[str, Any]:
    """GPU availability and status check"""
    try:
        import subprocess
        result = subprocess.run(['nvidia-smi', '--query-gpu=name,memory.used,memory.total',
                               '--format=csv,noheader,nounits'],
                              capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            # Parse GPU info
            gpu_info = result.stdout.strip().split('\n')[0].split(', ')
            return {
                "status": "healthy",
                "service": "gpu",
                "gpu_name": gpu_info[0] if len(gpu_info) > 0 else "unknown",
                "memory_used_mb": int(gpu_info[1]) if len(gpu_info) > 1 else 0,
                "memory_total_mb": int(gpu_info[2]) if len(gpu_info) > 2 else 0
            }
        else:
            raise HTTPException(status_code=503, detail="GPU not available")
    except Exception as e:
        logger.error(f"GPU health check failed: {e}")
        raise HTTPException(status_code=503, detail="GPU check failed")

EOF
                ;;
            "llm")
                cat << 'EOF'

@router.get("/health/llm")
async def llm_health_check() -> Dict[str, Any]:
    """LLM model loading and inference check"""
    try:
        # Add your LLM health check logic here
        # Example: check if model is loaded and can do basic inference
        return {
            "status": "healthy",
            "service": "llm",
            "model_loaded": True,
            "inference_ready": True
        }
    except Exception as e:
        logger.error(f"LLM health check failed: {e}")
        raise HTTPException(status_code=503, detail="LLM service unavailable")

EOF
                ;;
            "rag")
                cat << 'EOF'

@router.get("/health/rag")
async def rag_health_check() -> Dict[str, Any]:
    """RAG system health check"""
    try:
        # Add your RAG health check logic here
        # Example: check vector database connectivity and embedding model
        return {
            "status": "healthy",
            "service": "rag",
            "vector_db": "connected",
            "embedding_model": "loaded"
        }
    except Exception as e:
        logger.error(f"RAG health check failed: {e}")
        raise HTTPException(status_code=503, detail="RAG service unavailable")

EOF
                ;;
            "jupyter")
                cat << 'EOF'

@router.get("/health/jupyter")
async def jupyter_health_check() -> Dict[str, Any]:
    """Jupyter server health check"""
    try:
        # Add your Jupyter health check logic here
        # Example: check if Jupyter server is running
        return {
            "status": "healthy",
            "service": "jupyter",
            "server_running": True
        }
    except Exception as e:
        logger.error(f"Jupyter health check failed: {e}")
        raise HTTPException(status_code=503, detail="Jupyter unavailable")

EOF
                ;;
            "monitoring")
                cat << 'EOF'

@router.get("/health/system")
async def system_health_check() -> Dict[str, Any]:
    """System monitoring health check"""
    try:
        import psutil
        return {
            "status": "healthy",
            "service": "system",
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent
        }
    except Exception as e:
        logger.error(f"System health check failed: {e}")
        raise HTTPException(status_code=503, detail="System monitoring failed")

EOF
                ;;
        esac
    done

    cat << 'EOF'

# Comprehensive health check combining all component checks
@router.get("/health/comprehensive")
async def comprehensive_health_check() -> Dict[str, Any]:
    """Comprehensive health check for all components"""
    results = {}
    overall_status = "healthy"

    try:
        # FastAPI basic check
        results["fastapi"] = (await health_check())["status"]
    except:
        results["fastapi"] = "unhealthy"
        overall_status = "unhealthy"

    # Add other component checks here based on what's enabled
EOF

    # Add component-specific checks to comprehensive health
    for component in "${COMPONENT_ARRAY[@]}"; do
        if [ "$component" != "fastapi" ]; then
            case "$component" in
                "database")
                    echo '    try:'
                    echo '        results["database"] = (await database_health_check())["status"]'
                    echo '    except:'
                    echo '        results["database"] = "unhealthy"'
                    echo '        overall_status = "unhealthy"'
                    ;;
                "gpu-monitoring")
                    echo '    try:'
                    echo '        results["gpu"] = (await gpu_health_check())["status"]'
                    echo '    except:'
                    echo '        results["gpu"] = "unhealthy"'
                    echo '        overall_status = "unhealthy"'
                    ;;
                "llm")
                    echo '    try:'
                    echo '        results["llm"] = (await llm_health_check())["status"]'
                    echo '    except:'
                    echo '        results["llm"] = "unhealthy"'
                    echo '        overall_status = "unhealthy"'
                    ;;
                "rag")
                    echo '    try:'
                    echo '        results["rag"] = (await rag_health_check())["status"]'
                    echo '    except:'
                    echo '        results["rag"] = "unhealthy"'
                    echo '        overall_status = "unhealthy"'
                    ;;
                "jupyter")
                    echo '    try:'
                    echo '        results["jupyter"] = (await jupyter_health_check())["status"]'
                    echo '    except:'
                    echo '        results["jupyter"] = "unhealthy"'
                    echo '        overall_status = "unhealthy"'
                    ;;
                "monitoring")
                    echo '    try:'
                    echo '        results["system"] = (await system_health_check())["status"]'
                    echo '    except:'
                    echo '        results["system"] = "unhealthy"'
                    echo '        overall_status = "unhealthy"'
                    ;;
            esac
        fi
    done

    cat << 'EOF'

    return {
        "status": overall_status,
        "components": results,
        "timestamp": "2025-01-01T00:00:00Z"  # Will be replaced with actual timestamp
    }
EOF
}
}

# Generate self-signed certificates for HTTPS registry
generate_registry_certificates() {
    local registry_ip="$1"
    local cert_dir="${2:-/etc/docker/certs.d/$registry_ip}"
    
    cat << EOF
# Generate self-signed certificates for HTTPS registry
RUN mkdir -p $cert_dir && \
    openssl req -newkey rsa:4096 -nodes -sha256 -keyout $cert_dir/registry.key -x509 -days 365 -out $cert_dir/registry.crt -subj "/C=US/ST=State/L=City/O=Organization/CN=$registry_ip" && \
    cp $cert_dir/registry.crt $cert_dir/ca.crt
EOF
}

# Generate registry configuration for HTTPS
generate_registry_config_https() {
    local registry_ip="$1"
    local registry_port="$2"
    local cert_dir="${3:-/etc/docker/certs.d/$registry_ip}"
    
    cat << EOF
# Configure registry for HTTPS
server:
  address: "0.0.0.0:5000"
  tls:
    certificate: "$cert_dir/registry.crt"
    key: "$cert_dir/registry.key"

storage:
  filesystem:
    rootdirectory: /var/lib/registry

http:
  addr: 0.0.0.0:5000
  tls:
    certificate: $cert_dir/registry.crt
    key: $cert_dir/registry.key
EOF
}

# Generate K3s registries.yaml configuration
generate_k3s_registry_config() {
    local registry_ip="$1"
    local registry_port="$2"
    local protocol="${3:-http}"
    
    if [[ "$protocol" == "https" ]]; then
        cat << EOF
mirrors:
  "$registry_ip:$registry_port":
    endpoint:
      - "https://$registry_ip:$registry_port"

configs:
  "$registry_ip:$registry_port":
    tls:
      ca_file: "/etc/docker/certs.d/$registry_ip/ca.crt"
EOF
    else
        cat << EOF
mirrors:
  "$registry_ip:$registry_port":
    endpoint:
      - "http://$registry_ip:$registry_port"

configs:
  "$registry_ip:$registry_port":
    tls:
      insecure_skip_verify: true
EOF
    fi
}

# Generate containerd hosts.toml configuration
generate_containerd_hosts_config() {
    local registry_ip="$1"
    local registry_port="$2"
    local protocol="${3:-http}"
    
    if [[ "$protocol" == "https" ]]; then
        cat << EOF
[host."https://$registry_ip:$registry_port"]
  capabilities = ["pull", "resolve", "push"]
  ca = "/etc/docker/certs.d/$registry_ip/ca.crt"
EOF
    else
        cat << EOF
[host."http://$registry_ip:$registry_port"]
  capabilities = ["pull", "resolve", "push"]
EOF
    fi
}