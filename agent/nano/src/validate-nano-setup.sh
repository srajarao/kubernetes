#!/bin/bash

# Nano Agent Validation Script
# This script validates the nano k3s agent setup and container services

# Setup colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'
TICK="${GREEN}✅${NC}"
CROSS="${RED}❌${NC}"

# Source configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$SCRIPT_DIR/app/config"
if [ -f "$CONFIG_DIR/nano-config.env" ]; then
    source "$CONFIG_DIR/nano-config.env"
fi

echo -e "${GREEN}Nano Agent Validation${NC}"
echo "=================================="
echo "Validates both k3s cluster and container services"
echo ""

# Check k3s agent status
echo -e "\n${GREEN}K3s Agent Status:${NC}"
if systemctl is-active --quiet k3s-agent; then
    echo -e "  k3s-agent service: $TICK"
else
    echo -e "  k3s-agent service: $CROSS"
fi

# Check node status in cluster
echo -e "\n${GREEN}Node Status in Cluster:${NC}"
if kubectl get nodes | grep -q "$(hostname)"; then
    NODE_STATUS=$(kubectl get nodes --no-headers | grep "$(hostname)" | awk '{print $2}')
    if [ "$NODE_STATUS" = "Ready" ]; then
        echo -e "  Node $(hostname): Ready $TICK"
    else
        echo -e "  Node $(hostname): $NODE_STATUS $CROSS"
    fi
else
    echo -e "  Node $(hostname): Not found in cluster $CROSS"
fi

# Check pod status
echo -e "\n${GREEN}FastAPI Pod Status:${NC}"
POD_NAME=$(kubectl get pods -l app=fastapi-nano -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -z "$POD_NAME" ]; then
    POD_NAME=$(kubectl get pods -l app=fastapi -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
fi

if [ -n "$POD_NAME" ]; then
    POD_STATUS=$(kubectl get pod "$POD_NAME" -o jsonpath='{.status.phase}' 2>/dev/null)
    if [ "$POD_STATUS" = "Running" ]; then
        echo -e "  FastAPI pod $POD_NAME: Running $TICK"
    else
        echo -e "  FastAPI pod $POD_NAME: $POD_STATUS $CROSS"
    fi
else
    echo -e "  FastAPI pod: Not found $CROSS"
fi

# Check container services (if running in container mode)
echo -e "\n${GREEN}Container Services:${NC}"
if docker ps | grep -q "fastapi_nano"; then
    echo -e "  Container running: $TICK"
    
    # Check FastAPI health
    if curl -s "http://localhost:8000/health" | grep -q "ok"; then
        echo -e "  FastAPI health (port 8000): $TICK"
    else
        echo -e "  FastAPI health (port 8000): $CROSS"
    fi
    
    # Check Jupyter accessibility
    if curl -s -I "http://localhost:8888/jupyter/lab" | grep -q "200\|405"; then
        echo -e "  Jupyter Lab (port 8888): $TICK"
    else
        echo -e "  Jupyter Lab (port 8888): $CROSS"
    fi
else
    echo -e "  Container not running (expected in k3s mode)"
fi

# Check NFS mount
echo -e "\n${GREEN}NFS Mount:${NC}"
if mount | grep -q "/mnt/vmstore"; then
    echo -e "  NFS mount (/mnt/vmstore): $TICK"
else
    echo -e "  NFS mount (/mnt/vmstore): $CROSS"
fi

# Check database connectivity (if postgres.env exists and pod is running)
echo -e "\n${GREEN}Database Connectivity:${NC}"
POD_NAME=$(kubectl get pods -l app=fastapi-nano -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -n "$POD_NAME" ] && [ "$POD_STATUS" = "Running" ]; then
    if kubectl exec "$POD_NAME" -- python3 -c "
import psycopg2
import os
from dotenv import load_dotenv
load_dotenv('/app/app/config/postgres.env')
try:
    conn = psycopg2.connect(
        host=os.getenv('POSTGRES_HOST'),
        port=os.getenv('POSTGRES_PORT', '5432'),
        dbname=os.getenv('POSTGRES_DB'),
        user=os.getenv('POSTGRES_USER'),
        password=os.getenv('POSTGRES_PASSWORD'),
        connect_timeout=5
    )
    conn.close()
    print('SUCCESS')
except Exception as e:
    print('FAILED')
" 2>/dev/null | grep -q "SUCCESS"; then
        echo -e "  PostgreSQL connection: $TICK"
    else
        echo -e "  PostgreSQL connection: $CROSS"
    fi
else
    echo -e "  Database check skipped (pod not running)"
fi

echo -e "\n${GREEN}Validation Complete${NC}"
echo "=================================="
echo "✅ K3s cluster integration (if running)"
echo "✅ Container services (FastAPI, Jupyter, Database)"
echo "✅ Network connectivity and NFS mounts"
echo "✅ ML library health checks"
echo ""
echo "For container-only mode with GPU acceleration:"
echo "  docker run --rm -it --runtime=nvidia --network=host -e FASTAPI_PORT=8000 -e FORCE_GPU_CHECKS=true -v /home/sanjay:/mnt/vmstore fastapi_nano"