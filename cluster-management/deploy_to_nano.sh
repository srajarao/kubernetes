#!/bin/bash

# Deploy Bootstrap Management Application to Nano
# This script moves the management application from tower to nano as a dedicated management node

set -e

echo "🚀 Deploying Bootstrap Management Application to Nano"
echo "=================================================="

NANO_IP="192.168.1.181"
REMOTE_DIR="/home/sanjay/containers/kubernetes/cluster-management"

echo "📋 Step 1: Creating remote directory on nano..."
ssh nano "mkdir -p $REMOTE_DIR"

echo "📦 Step 2: Copying application files to nano..."
scp bootstrap_app.py bootstrap_requirements.txt nano:$REMOTE_DIR/

echo "🐍 Step 3: Setting up Python virtual environment on nano..."
ssh nano "cd $REMOTE_DIR && python3 -m venv management_venv"

echo "📚 Step 4: Installing dependencies on nano..."
ssh nano "cd $REMOTE_DIR && source management_venv/bin/activate && pip install -r bootstrap_requirements.txt"

echo "🧪 Step 5: Testing application import on nano..."
ssh nano "cd $REMOTE_DIR && source management_venv/bin/activate && python -c 'from bootstrap_app import app; print(\"✅ App imported successfully on nano\")'"

echo "🌐 Step 6: Starting the management application on nano..."
ssh nano "cd $REMOTE_DIR && source management_venv/bin/activate && nohup uvicorn bootstrap_app:app --host 0.0.0.0 --port 8000 > server.log 2>&1 &"

echo "⏳ Step 7: Waiting for application to start..."
sleep 5

echo "🩺 Step 8: Testing application health..."
if curl -s --connect-timeout 10 http://$NANO_IP:8000/health > /dev/null; then
    echo "✅ Management application is running successfully on nano!"
    echo "🌐 Access it at: http://$NANO_IP:8000"
    echo "📊 Health check: http://$NANO_IP:8000/health"
    echo "ℹ️  API info: http://$NANO_IP:8000/api/info"
else
    echo "❌ Application failed to start. Check logs on nano:"
    echo "ssh nano 'cd $REMOTE_DIR && cat server.log'"
    exit 1
fi

echo ""
echo "🎉 Deployment Complete!"
echo "======================"
echo "Management application is now running on nano ($NANO_IP) as a dedicated management node"
echo "This provides proper separation between the management interface and the cluster nodes"