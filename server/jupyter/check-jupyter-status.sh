#!/bin/bash
# Jupyter Lab Access Information and Status Check

echo "🔬 Jupyter Lab Status Check"
echo "=========================="
echo ""

# Check pod status
echo "📊 Pod Status:"
kubectl get pods -l app=jupyter-lab

echo ""
echo "🔗 Service Information:"
kubectl get service jupyter-service

echo ""
echo "🌍 Access Information:"
echo "  External URL: http://192.168.10.1:30888"
echo "  Token: jupyter-k8s-demo"
echo "  Password: (not required - use token)"

echo ""
echo "📁 Available Files:"
echo "  Demo Notebook: cluster-demo.ipynb"
echo "  NFS Storage: /export/vmstore/jupyter"

echo ""
echo "🔑 Database Credentials (for notebook):"
echo "  Host: postgres-service"
echo "  Port: 5432"
echo "  Database: vectordb"
echo "  Username: postgres"
echo "  Password: myscretpassword"

echo ""
echo "🚀 Quick Start:"
echo "  1. Open http://192.168.10.1:30888"
echo "  2. Enter token: jupyter-k8s-demo"
echo "  3. Open cluster-demo.ipynb from work directory"
echo "  4. Run cells to explore cluster capabilities"

echo ""
echo "📚 Available Libraries in Jupyter:"
echo "  • TensorFlow & Keras"
echo "  • PyTorch (installable)"
echo "  • Pandas, NumPy, Matplotlib, Seaborn"
echo "  • Scikit-learn"
echo "  • PostgreSQL connector (psycopg2)"
echo "  • Kubernetes Python client"
echo "  • Plotly for interactive plots"

# Test connectivity
echo ""
echo "🏥 Connectivity Tests:"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://192.168.10.1:30888)
if [ "$HTTP_STATUS" = "302" ] || [ "$HTTP_STATUS" = "200" ]; then
    echo "  ✅ Jupyter Lab: Accessible (HTTP $HTTP_STATUS)"
else
    echo "  ❌ Jupyter Lab: Not accessible (HTTP $HTTP_STATUS)"
fi

# Test database connection
if kubectl exec deployment/jupyter-lab -- python -c "import psycopg2; psycopg2.connect(host='postgres-service', user='postgres', password='myscretpassword', database='postgres')" 2>/dev/null; then
    echo "  ✅ PostgreSQL: Connection successful"
else
    echo "  ⚠️  PostgreSQL: Connection test failed"
fi

echo ""
echo "✨ Jupyter Lab is ready for data science and cluster exploration!"