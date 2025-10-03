#!/bin/bash
# Quick Jupyter Lab deployment script

set -e

JUPYTER_DIR="/home/sanjay/containers/kubernetes/server/jupyter"

echo "🚀 Quick Jupyter Lab Setup for Kubernetes Cluster"
echo "================================================"

# Run the full setup
cd "$JUPYTER_DIR"
./setup-jupyter.sh

# Wait for deployment to be fully ready
echo "⏳ Waiting for Jupyter to be fully operational..."
sleep 30

# Copy demo notebook to NFS storage
echo "📁 Copying demo notebook to Jupyter workspace..."
sudo cp "$JUPYTER_DIR/cluster-demo.ipynb" /export/vmstore/jupyter/

# Set proper permissions
sudo chown -R 1000:1000 /export/vmstore/jupyter
sudo chmod -R 755 /export/vmstore/jupyter

echo ""
echo "✅ Jupyter Lab is ready!"
echo "🌍 External Access: http://192.168.10.1:30888"
echo "🔑 Token: jupyter-k8s-demo"
echo "📓 Demo Notebook: cluster-demo.ipynb (available in work directory)"
echo ""
echo "🎯 Quick Start:"
echo "  1. Open http://192.168.10.1:30888 in your browser"
echo "  2. Enter token: jupyter-k8s-demo"
echo "  3. Open cluster-demo.ipynb from the work directory"
echo "  4. Run all cells to see cluster capabilities"
echo ""