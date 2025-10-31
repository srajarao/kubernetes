#!/bin/bash

# Quick Deploy Script - Deploy changes from tower to nano
# Usage: ./quick_deploy.sh

echo "🚀 Quick Deploy to Nano Management Node"
echo "======================================="

NANO_IP="192.168.1.181"
REMOTE_DIR="/home/sanjay/containers/kubernetes/cluster-management"

echo "📦 Copying updated files to nano..."
scp bootstrap_app.py bootstrap_requirements.txt nano:$REMOTE_DIR/

echo "🔄 Restarting application on nano..."
ssh nano "pkill -f uvicorn; sleep 1"
ssh -f nano "cd $REMOTE_DIR && source management_venv/bin/activate && nohup uvicorn bootstrap_app:app --host 0.0.0.0 --port 8000 > server.log 2>&1 &"

echo "⏳ Waiting for restart..."
sleep 3

echo "🩺 Testing deployment..."
if curl -s --connect-timeout 5 http://$NANO_IP:8000/health > /dev/null; then
    echo "✅ Deployment successful!"
    echo "🌐 Access at: http://$NANO_IP:8000"
else
    echo "❌ Deployment failed. Check logs on nano:"
    echo "ssh nano 'cd $REMOTE_DIR && cat server.log'"
fi