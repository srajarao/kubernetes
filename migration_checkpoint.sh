#!/bin/bash

# Migration Checkpoint Script
# Run at various stages during the 10.1.10.x → 192.168.1.x migration

set -e

echo "🔍 K3s Cluster Migration Checkpoint"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check node connectivity
check_node_connectivity() {
    local node_ip="$1"
    local node_name="$2"

    echo -n "Testing $node_name ($node_ip): "
    if ping -c 1 -W 2 "$node_ip" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Reachable${NC}"
        return 0
    else
        echo -e "${RED}❌ Unreachable${NC}"
        return 1
    fi
}

# Function to check SSH connectivity
check_ssh_connectivity() {
    local node_ip="$1"
    local node_name="$2"

    echo -n "SSH to $node_name ($node_ip): "
    if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o LogLevel=ERROR "$node_ip" "echo 'SSH OK'" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Connected${NC}"
        return 0
    else
        echo -e "${RED}❌ Failed${NC}"
        return 1
    fi
}

# Function to check K3s node status
check_k3s_node() {
    local node_name="$1"

    echo -n "K3s node $node_name: "
    if kubectl get nodes | grep -q "$node_name.*Ready"; then
        echo -e "${GREEN}✅ Ready${NC}"
        return 0
    else
        echo -e "${RED}❌ Not Ready${NC}"
        return 1
    fi
}

# Function to check service health
check_service_health() {
    local service_url="$1"
    local service_name="$2"

    echo -n "$service_name health: "
    if curl -s --max-time 5 "$service_url" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Healthy${NC}"
        return 0
    else
        echo -e "${RED}❌ Unhealthy${NC}"
        return 1
    fi
}

echo ""
echo "🌐 NETWORK CONNECTIVITY CHECK"
echo "-----------------------------"

# Check all nodes
check_node_connectivity "192.168.1.150" "Tower"
check_node_connectivity "192.168.1.181" "Nano"
check_node_connectivity "192.168.1.244" "AGX"
check_node_connectivity "192.168.1.201" "Spark1"
check_node_connectivity "192.168.1.202" "Spark2"

echo ""
echo "🔐 SSH CONNECTIVITY CHECK"
echo "------------------------"

# Check SSH to all nodes (assuming user 'sanjay')
check_ssh_connectivity "sanjay@192.168.1.150" "Tower"
check_ssh_connectivity "sanjay@192.168.1.181" "Nano"
check_ssh_connectivity "sanjay@192.168.1.244" "AGX"
check_ssh_connectivity "sanjay@192.168.1.201" "Spark1"
check_ssh_connectivity "sanjay@192.168.1.202" "Spark2"

echo ""
echo "☸️  KUBERNETES CLUSTER STATUS"
echo "----------------------------"

# Check kubectl access
echo -n "kubectl access: "
if kubectl get nodes >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Available${NC}"

    # Check individual nodes
    check_k3s_node "tower"
    check_k3s_node "nano"
    check_k3s_node "agx"
    check_k3s_node "spark1"
    check_k3s_node "spark2"

    echo ""
    echo "Pod Status Summary:"
    kubectl get pods -A --no-headers | awk '{print $4}' | sort | uniq -c | while read count status; do
        if [ "$status" = "Running" ]; then
            echo -e "${GREEN}✅ $count pods $status${NC}"
        elif [ "$status" = "Pending" ]; then
            echo -e "${YELLOW}⏳ $count pods $status${NC}"
        else
            echo -e "${RED}❌ $count pods $status${NC}"
        fi
    done

else
    echo -e "${RED}❌ kubectl not accessible${NC}"
fi

echo ""
echo "🔧 SERVICE HEALTH CHECKS"
echo "-----------------------"

# Check FastAPI services
check_service_health "http://192.168.1.181:30002/health" "Nano FastAPI"
check_service_health "http://192.168.1.244:30002/health" "AGX FastAPI"
check_service_health "http://192.168.1.201:30002/health" "Spark1 FastAPI"
check_service_health "http://192.168.1.202:30002/health" "Spark2 FastAPI"

# Check other services
check_service_health "http://192.168.1.150:30080" "pgAdmin"
check_service_health "http://192.168.1.150:30500/v2/" "Docker Registry"

echo ""
echo "💾 STORAGE & BACKUP CHECK"
echo "------------------------"

# Check NFS mounts
echo -n "NFS mounts: "
if mount | grep -q "vmstore"; then
    echo -e "${GREEN}✅ Mounted${NC}"
else
    echo -e "${RED}❌ Not mounted${NC}"
fi

# Check backup directories
echo -n "Backup directories: "
if [ -d "/home/sanjay/containers" ] && [ -d "/vmstore" ]; then
    echo -e "${GREEN}✅ Available${NC}"
else
    echo -e "${RED}❌ Missing${NC}"
fi

echo ""
echo "📊 SYSTEM RESOURCES"
echo "------------------"

# Show basic resource usage
echo "Node Resource Usage:"
kubectl top nodes 2>/dev/null || echo "kubectl top not available"

echo ""
echo "🎯 MIGRATION STATUS SUMMARY"
echo "=========================="

# Count successful checks
TOTAL_CHECKS=15  # Approximate count
SUCCESSFUL=$(grep -c "✅" /tmp/checkpoint_output 2>/dev/null || echo "0")

echo "Migration appears to be $([ $SUCCESSFUL -gt 10 ] && echo "SUCCESSFUL" || echo "IN PROGRESS/ISSUES DETECTED")"
echo "Run this script again after each major phase to track progress."

echo ""
echo "📝 Next Steps:"
echo "- If all checks pass: Proceed to next migration phase"
echo "- If issues found: Address them before continuing"
echo "- Document any failures for troubleshooting"