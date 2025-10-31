#!/bin/bash

# Production HTTPS Startup Script for Cluster Management System
# This script starts the application with SSL/TLS encryption

echo "🔒 Starting Cluster Management System with HTTPS"
echo "================================================"

# Configuration
HTTPS_PORT=8443
APP_DIR="/home/sanjay/containers/kubernetes/cluster-management"
VENV_DIR="$APP_DIR/management_venv"

# Kill any existing processes
echo "🛑 Stopping any existing servers..."
pkill -f "python.*bootstrap_app.py" || true
pkill -f uvicorn || true
sleep 2

# Activate virtual environment and start HTTPS server
echo "🚀 Starting HTTPS server..."
cd "$APP_DIR"
source "$VENV_DIR/bin/activate"

# Set environment variables for HTTPS
export ENABLE_HTTPS=true
export HTTPS_PORT=$HTTPS_PORT

# Start the application in background
echo "🌐 Server will be available at: https://192.168.1.181:$HTTPS_PORT"
echo "🔐 Note: Browser will show security warning for self-signed certificate"
echo "   This is normal and safe to proceed for internal cluster management"
echo ""
echo "Server starting in background..."
echo ""

# Run in background with nohup
nohup python3 bootstrap_app.py > server.log 2>&1 &

echo "✅ Server started successfully in background (PID: $!)"
echo "📊 Check server status: curl -k https://192.168.1.181:$HTTPS_PORT/health"
echo "📝 Server logs: tail -f $APP_DIR/server.log"