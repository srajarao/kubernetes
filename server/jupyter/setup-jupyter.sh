#!/bin/bash
# Jupyter Lab Setup Script for Kubernetes Cluster
# Sets up Jupyter with access to cluster resources and PostgreSQL

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JUPYTER_DIR="$SCRIPT_DIR"
SERVER_DIR="$(dirname "$SCRIPT_DIR")"
K8S_ROOT="$(dirname "$SERVER_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔬 Setting up Jupyter Lab for Kubernetes Cluster...${NC}"

# Create NFS directory for Jupyter storage
echo -e "${YELLOW}📁 Creating NFS storage directory...${NC}"
sudo mkdir -p /export/vmstore/jupyter
sudo chown -R 1000:1000 /export/vmstore/jupyter
sudo chmod 755 /export/vmstore/jupyter

# Create kubeconfig secret for cluster access
echo -e "${YELLOW}🔐 Creating kubeconfig secret...${NC}"
if kubectl get secret jupyter-kubeconfig >/dev/null 2>&1; then
    echo "  ✓ Secret already exists, updating..."
    kubectl delete secret jupyter-kubeconfig
fi

# Encode the kubeconfig file
KUBECONFIG_B64=$(base64 -w 0 ~/.kube/config)
kubectl create secret generic jupyter-kubeconfig --from-literal=config="$(echo $KUBECONFIG_B64 | base64 -d)"

# Deploy Jupyter Lab
echo -e "${YELLOW}🚀 Deploying Jupyter Lab...${NC}"
kubectl apply -f "$JUPYTER_DIR/jupyter-deployment.yaml"

# Wait for deployment to be ready
echo -e "${YELLOW}⏳ Waiting for Jupyter Lab to be ready...${NC}"
kubectl wait --for=condition=available --timeout=300s deployment/jupyter-lab

# Get service details
echo -e "${GREEN}✅ Jupyter Lab Setup Complete!${NC}"
echo -e "${BLUE}📊 Access Information:${NC}"

# Get the node IP (tower)
TOWER_IP=$(kubectl get node tower -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
EXTERNAL_IP="192.168.10.1"  # Tower's external IP

echo -e "  🌐 Internal Access: http://$TOWER_IP:30888"
echo -e "  🌍 External Access: http://$EXTERNAL_IP:30888"
echo -e "  🔑 Token: jupyter-k8s-demo"
echo -e "  📝 Password: (none - use token)"

echo -e "${BLUE}📁 Storage Locations:${NC}"
echo -e "  💾 Jupyter Files: /export/vmstore/jupyter (on tower)"
echo -e "  📊 Notebooks: /home/jovyan/work (in container)"

echo -e "${BLUE}🔗 Available Services:${NC}"
echo -e "  🐘 PostgreSQL: postgres-service:5432"
echo -e "  🎛️  pgAdmin: pgadmin-service:80"
echo -e "  🚀 FastAPI Nano: fastapi-nano-service:8000"

echo -e "${BLUE}📚 Pre-installed Libraries:${NC}"
echo -e "  • TensorFlow & Keras"
echo -e "  • PyTorch (via pip install torch)"
echo -e "  • Pandas, NumPy, Matplotlib"
echo -e "  • Scikit-learn"
echo -e "  • Jupyter Lab & Extensions"
echo -e "  • PostgreSQL connector (psycopg2)"

# Install additional packages
echo -e "${YELLOW}📦 Installing additional packages in Jupyter container...${NC}"
sleep 10  # Wait for container to be fully ready

kubectl exec deployment/jupyter-lab -- pip install \
    psycopg2-binary \
    pgvector \
    kubernetes \
    plotly \
    seaborn \
    requests \
    aiohttp

echo -e "${GREEN}🎉 Jupyter Lab is ready for use!${NC}"
echo -e "${BLUE}🔗 Open: http://$EXTERNAL_IP:30888${NC}"