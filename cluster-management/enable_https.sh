#!/bin/bash

# Enable HTTPS for Cluster Management System
# This script configures SSL certificates and restarts the application with HTTPS

echo "🔒 Enabling HTTPS for Cluster Management System"
echo "=============================================="

# Set environment variable to enable HTTPS
export ENABLE_HTTPS=true
export HTTPS_PORT=8443

echo "✅ HTTPS enabled with the following configuration:"
echo "   - HTTPS Port: 8443"
echo "   - SSL Certificates will be auto-generated"
echo "   - Access URL: https://192.168.1.181:8443"

echo ""
echo "🚀 Starting application with HTTPS..."
echo "Note: You may see browser warnings about self-signed certificates"
echo "      This is normal for development/testing environments"
echo ""

# Kill any existing processes
pkill -f "python.*bootstrap_app.py" || true
pkill -f uvicorn || true

# Start the application with HTTPS enabled
cd /home/sanjay/containers/kubernetes/cluster-management
source management_venv/bin/activate
ENABLE_HTTPS=true HTTPS_PORT=8443 python bootstrap_app.py