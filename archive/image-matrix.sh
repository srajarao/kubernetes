# Image-Component Matrix Configuration
# Defines which components are available and which base images support them

# ==========================================
# AVAILABLE BASE IMAGES
# ==========================================

# Base image definitions with their capabilities
declare -A BASE_IMAGES
BASE_IMAGES["l4t-minimal"]="nvcr.io/nvidia/l4t-jetpack:r36.4.0"      # CUDA, cuDNN, minimal Python
BASE_IMAGES["l4t-ml"]="nvcr.io/nvidia/l4t-ml:r36.4.0-py3"            # + PyTorch, TensorFlow
BASE_IMAGES["l4t-pytorch"]="nvcr.io/nvidia/l4t-pytorch:r36.4.0-py3"  # + PyTorch optimized
BASE_IMAGES["ubuntu-cuda"]="nvidia/cuda:12.2-base-ubuntu22.04"      # x86 CUDA base
BASE_IMAGES["ubuntu-minimal"]="ubuntu:22.04"                        # Minimal Ubuntu

# Architecture compatibility
declare -A BASE_IMAGE_ARCH
BASE_IMAGE_ARCH["l4t-minimal"]="arm64"
BASE_IMAGE_ARCH["l4t-ml"]="arm64"
BASE_IMAGE_ARCH["l4t-pytorch"]="arm64"
BASE_IMAGE_ARCH["ubuntu-cuda"]="amd64"
BASE_IMAGE_ARCH["ubuntu-minimal"]="amd64,arm64"

# ==========================================
# COMPONENT DEFINITIONS
# ==========================================

# Components that can be installed on nodes
declare -A COMPONENT_DEPS
COMPONENT_DEPS["python"]="python3.10 python3.10-venv python3-pip"
COMPONENT_DEPS["cuda"]="cuda-toolkit-12-2 libcudnn8"
COMPONENT_DEPS["cudnn"]="libcudnn8"
COMPONENT_DEPS["tensorrt"]="libnvinfer8 libnvinfer-plugin8"
COMPONENT_DEPS["pytorch"]="torch torchvision torchaudio"
COMPONENT_DEPS["tensorflow"]="tensorflow"
COMPONENT_DEPS["jupyter"]="jupyterlab notebook"
COMPONENT_DEPS["fastapi"]="fastapi uvicorn pydantic"
COMPONENT_DEPS["database"]="psycopg2-binary sqlalchemy"
COMPONENT_DEPS["monitoring"]="psutil prometheus-client"
COMPONENT_DEPS["gpu-monitoring"]="nvidia-ml-py"
COMPONENT_DEPS["llm"]="transformers accelerate"
COMPONENT_DEPS["rag"]="sentence-transformers faiss-cpu"

# Separate pip-only dependencies (for requirements.txt)
declare -A COMPONENT_PIP_DEPS
COMPONENT_PIP_DEPS["python"]=""  # No pip packages for python component
COMPONENT_PIP_DEPS["cuda"]=""    # System packages only
COMPONENT_PIP_DEPS["cudnn"]=""   # System packages only
COMPONENT_PIP_DEPS["tensorrt"]="" # System packages only
COMPONENT_PIP_DEPS["pytorch"]="torch torchvision torchaudio"
COMPONENT_PIP_DEPS["tensorflow"]="tensorflow"
COMPONENT_PIP_DEPS["jupyter"]="jupyterlab notebook"
COMPONENT_PIP_DEPS["fastapi"]="fastapi uvicorn pydantic psycopg2-binary python-dotenv python-multipart"
COMPONENT_PIP_DEPS["database"]="psycopg2-binary sqlalchemy"
COMPONENT_PIP_DEPS["monitoring"]="psutil prometheus-client"
COMPONENT_PIP_DEPS["gpu-monitoring"]="nvidia-ml-py"
COMPONENT_PIP_DEPS["llm"]="transformers accelerate"
COMPONENT_PIP_DEPS["rag"]="sentence-transformers faiss-cpu"

# Which base images support which components
declare -A COMPONENT_COMPATIBILITY
COMPONENT_COMPATIBILITY["python"]="l4t-minimal,l4t-ml,l4t-pytorch,ubuntu-cuda,ubuntu-minimal"
COMPONENT_COMPATIBILITY["cuda"]="l4t-minimal,l4t-ml,l4t-pytorch,ubuntu-cuda"
COMPONENT_COMPATIBILITY["cudnn"]="l4t-minimal,l4t-ml,l4t-pytorch,ubuntu-cuda"
COMPONENT_COMPATIBILITY["tensorrt"]="l4t-minimal,l4t-ml,l4t-pytorch"
COMPONENT_COMPATIBILITY["pytorch"]="l4t-ml,l4t-pytorch,ubuntu-cuda"
COMPONENT_COMPATIBILITY["tensorflow"]="l4t-ml,ubuntu-cuda"
COMPONENT_COMPATIBILITY["jupyter"]="l4t-minimal,l4t-ml,l4t-pytorch,ubuntu-cuda,ubuntu-minimal"
COMPONENT_COMPATIBILITY["fastapi"]="l4t-minimal,l4t-ml,l4t-pytorch,ubuntu-cuda,ubuntu-minimal"
COMPONENT_COMPATIBILITY["database"]="l4t-minimal,l4t-ml,l4t-pytorch,ubuntu-cuda,ubuntu-minimal"
COMPONENT_COMPATIBILITY["monitoring"]="l4t-minimal,l4t-ml,l4t-pytorch,ubuntu-cuda,ubuntu-minimal"
COMPONENT_COMPATIBILITY["gpu-monitoring"]="l4t-minimal,l4t-ml,l4t-pytorch,ubuntu-cuda"
COMPONENT_COMPATIBILITY["llm"]="l4t-ml,l4t-pytorch,ubuntu-cuda"
COMPONENT_COMPATIBILITY["rag"]="l4t-ml,l4t-pytorch,ubuntu-cuda,ubuntu-minimal"

# ==========================================
# NODE TYPE PRESETS
# ==========================================

# Predefined node configurations
declare -A NODE_TYPE_BASE
NODE_TYPE_BASE["nano"]="l4t-minimal"      # Nano: lightweight, GPU capable
NODE_TYPE_BASE["agx"]="l4t-ml"           # AGX: ML-capable with PyTorch/TF
NODE_TYPE_BASE["x86-gpu"]="ubuntu-cuda"  # x86 GPU workstation
NODE_TYPE_BASE["x86-cpu"]="ubuntu-minimal" # x86 CPU only
NODE_TYPE_BASE["tower"]="ubuntu-minimal"  # Server node

# Default components for each node type
declare -A NODE_TYPE_COMPONENTS
NODE_TYPE_COMPONENTS["nano"]="python,cuda,tensorrt,fastapi,gpu-monitoring"
NODE_TYPE_COMPONENTS["agx"]="python,cuda,tensorrt,pytorch,tensorflow,fastapi,gpu-monitoring,llm,rag"
NODE_TYPE_COMPONENTS["x86-gpu"]="python,cuda,cudnn,pytorch,tensorflow,fastapi,gpu-monitoring,llm,rag"
NODE_TYPE_COMPONENTS["x86-cpu"]="python,fastapi,database,monitoring,jupyter"
NODE_TYPE_COMPONENTS["tower"]="python,database,monitoring,jupyter"

# ==========================================
# BUILD OPTIMIZATION
# ==========================================

# Component installation order (dependencies first)
COMPONENT_INSTALL_ORDER=("python" "cuda" "cudnn" "tensorrt" "pytorch" "tensorflow" "database" "monitoring" "gpu-monitoring" "fastapi" "jupyter" "llm" "rag")

# Components that require special installation (not just pip)
SPECIAL_COMPONENTS=("cuda" "cudnn" "tensorrt")

# ==========================================
# COMMON INFRASTRUCTURE COMPONENTS
# ==========================================

# Components that ALL nodes must have
COMMON_COMPONENTS=("infrastructure" "networking" "storage")

# Infrastructure component dependencies (system level)
COMPONENT_DEPS["infrastructure"]="openssh-client openssh-server sudo curl wget git vim nano htop iotop"
COMPONENT_DEPS["networking"]="dnsutils net-tools iputils-ping traceroute nmap"
COMPONENT_DEPS["storage"]="nfs-common cifs-utils"

# Infrastructure component dependencies (Python level)
COMPONENT_DEPS["ssh-setup"]="paramiko"
COMPONENT_DEPS["nfs-client"]=""

# Common directory structure that all nodes should have
COMMON_DIRECTORIES=(
    "/home/sanjay/kubernetes/agent"
    "/mnt/vmstore"
    "/app/logs"
    "/app/data"
    "/app/config"
    "/app/models"
    "/var/log/kubernetes"
)

# Common environment variables
COMMON_ENV_VARS=(
    "NODE_IP"
    "NODE_NAME"
    "CLUSTER_NODES"
    "REGISTRY_URL"
    "NFS_SERVER"
    "NFS_SHARE"
)