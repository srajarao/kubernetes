#!/bin/bash

# Unified Deploy Script - Deploy/Move Bootstrap Management Application to Nano
# Usage: ./quick_deploy.sh [--full] [--help]
#   --full: Force full deployment (create venv, install deps)
#   --help: Show usage information

set -e

# Configuration
NANO_IP="192.168.1.181"
REMOTE_DIR="/home/sanjay/containers/kubernetes/cluster-management"
FORCE_FULL=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --full)
            FORCE_FULL=true
            shift
            ;;
        --help)
            echo "Usage: $0 [--full] [--help]"
            echo "  --full: Force full deployment (create venv, install deps)"
            echo "  --help: Show this help message"
            echo ""
            echo "Without --full: Quick update (assumes venv exists)"
            echo "With --full: Complete deployment (creates venv, installs deps)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo "🚀 Unified Deploy to Nano Management Node"
echo "========================================"

# Check if we need full deployment
if $FORCE_FULL || ! ssh nano "[ -d $REMOTE_DIR/management_venv ]" 2>/dev/null; then
    echo "🔧 Performing FULL DEPLOYMENT (initial setup)"
    echo "=============================================="

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

else
    echo "⚡ Performing QUICK UPDATE (incremental deployment)"
    echo "=================================================="

    echo "📦 Copying updated files to nano..."
    scp bootstrap_app.py bootstrap_requirements.txt nano:$REMOTE_DIR/
    scp -r ../server/utils nano:$REMOTE_DIR/../server/ 2>/dev/null || echo "⚠️  utils directory not found, skipping..."

    echo "🔄 Stopping existing application on nano..."
    ssh nano "pkill -f uvicorn; true" || true
    sleep 1
fi

echo "🌐 Starting the management application on nano..."
ssh -f nano "cd $REMOTE_DIR && source management_venv/bin/activate && nohup uvicorn bootstrap_app:app --host 0.0.0.0 --port 8000 > logs/server.log 2>&1"

echo "⏳ Waiting for application to start..."
sleep 5

echo "🩺 Testing application health..."
if curl -s --connect-timeout 10 http://$NANO_IP:8000/health > /dev/null; then
    echo "✅ Management application is running successfully on nano!"
    echo "🌐 Access it at: http://$NANO_IP:8000"
    echo "📊 Health check: http://$NANO_IP:8000/health"
    echo "ℹ️  API info: http://$NANO_IP:8000/api/info"
else
    echo "❌ Application failed to start. Check logs on nano:"
    echo "ssh nano 'cd $REMOTE_DIR && cat logs/server.log'"
    exit 1
fi

echo ""
echo "🎉 Deployment Complete!"
echo "======================"
echo "Management application is now running on nano ($NANO_IP) as a dedicated management node"
echo "This provides proper separation between the management interface and the cluster nodes"
echo ""
echo "🌐 **ACCESS URLS:**"
echo "=================="
echo "📱 Main Application: http://$NANO_IP:8000"
echo "💚 Health Check:     http://$NANO_IP:8000/health"
echo "📋 API Information:  http://$NANO_IP:8000/api/info"
echo ""
echo "🔗 Quick Access: curl http://$NANO_IP:8000/health"