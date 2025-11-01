#!/bin/bash
# Start script for cluster management application

cd /home/sanjay/containers/kubernetes/cluster-management

# Activate virtual environment
source management_venv/bin/activate

# Set environment variables
export ENABLE_HTTPS=true
export HTTPS_PORT=8443

# Start the application with nohup to ensure it keeps running
nohup python3 bootstrap_app.py > logs/server.log 2>&1 &

# Give it a moment to start
sleep 2

# Check if it's running
if pgrep -f "bootstrap_app.py" > /dev/null; then
    echo "✅ Cluster management application started successfully"
    echo "🌐 HTTPS URL: https://192.168.1.181:8443"
    echo "📊 Health check: curl -k https://192.168.1.181:8443/health"
else
    echo "❌ Failed to start cluster management application"
    echo "Check logs/server.log for details"
fi