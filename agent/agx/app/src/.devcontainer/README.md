# AGX DevContainer Setup

This devcontainer configuration provides a complete development environment for the AGX FastAPI application.

## Features

- **Jupyter Lab**: Pre-installed and configured for development
- **Python Environment**: Virtual environment with all required packages
- **VS Code Extensions**: Pre-configured for Python and Jupyter development
- **Port Forwarding**: Automatic forwarding of FastAPI (8000) and Jupyter (8888) ports
- **GPU Support**: Configured for NVIDIA Jetson AGX development

## Usage

1. **Open in VS Code**: Use "Remote-Containers: Open Folder Locally" or "Dev Containers: Reopen in Container"
2. **Development**: The container includes all dependencies and Jupyter Lab
3. **Testing**: Run health checks and FastAPI application within the container

## Included Packages

- Python 3.10 with virtual environment
- Jupyter Lab and Notebook
- FastAPI, Uvicorn, Pydantic
- PyTorch, TensorFlow, CUDA support
- All ML/AI libraries (transformers, scikit-learn, etc.)

## Health Checks

The devcontainer ensures Jupyter Lab is properly installed and available, eliminating the need to skip Jupyter checks in production deployments.