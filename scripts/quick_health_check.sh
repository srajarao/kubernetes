#!/bin/bash

# Quick Cluster Health Check
# Performs a one-time comprehensive health check

set -e

echo "🔍 Performing Quick Cluster Health Check..."
echo "=========================================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_nodes() {
    echo -n "📊 Nodes: "
    local ready_nodes=$(kubectl get nodes --no-headers 2>/dev/null | grep -c " Ready" || echo "0")
    local total_nodes=$(kubectl get nodes --no-headers 2>/dev/null | wc -l || echo "0")

    if [ "$ready_nodes" -eq "$total_nodes" ] && [ "$total_nodes" -gt 0 ]; then
        echo -e "${GREEN}✅ $ready_nodes/$total_nodes nodes ready${NC}"
        return 0
    else
        echo -e "${RED}❌ $ready_nodes/$total_nodes nodes ready${NC}"
        return 1
    fi
}

check_pods() {
    echo -n "🐳 Pods: "
    local running_pods=$(kubectl get pods -A --no-headers 2>/dev/null | grep -c "Running\|Completed" || echo "0")
    local total_pods=$(kubectl get pods -A --no-headers 2>/dev/null | wc -l || echo "0")

    if [ "$running_pods" -eq "$total_pods" ] && [ "$total_pods" -gt 0 ]; then
        echo -e "${GREEN}✅ $running_pods/$total_pods pods healthy${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠️  $running_pods/$total_pods pods healthy${NC}"
        return 1
    fi
}

check_services() {
    echo -n "🌐 Services: "
    local services=$(kubectl get svc -A --no-headers 2>/dev/null | wc -l || echo "0")

    if [ "$services" -gt 0 ]; then
        echo -e "${GREEN}✅ $services services available${NC}"
        return 0
    else
        echo -e "${RED}❌ No services found${NC}"
        return 1
    fi
}

check_gpu() {
    echo -n "🎮 GPU: "
    local gpu_nodes=$(kubectl describe nodes 2>/dev/null | grep -c "nvidia.com/gpu:" || echo "0")

    if [ "$gpu_nodes" -gt 0 ]; then
        echo -e "${GREEN}✅ GPU support available on $gpu_nodes nodes${NC}"
        return 0
    else
        echo -e "${YELLOW}ℹ️  No GPU nodes detected${NC}"
        return 0
    fi
}

check_api() {
    echo -n "🔗 API Server: "
    if kubectl cluster-info >/dev/null 2>&1; then
        echo -e "${GREEN}✅ API server accessible${NC}"
        return 0
    else
        echo -e "${RED}❌ API server not accessible${NC}"
        return 1
    fi
}

# Run all checks
failed_checks=0

check_api || ((failed_checks++))
check_nodes || ((failed_checks++))
check_pods || ((failed_checks++))
check_services || ((failed_checks++))
check_gpu

echo ""
echo "=========================================="

if [ $failed_checks -eq 0 ]; then
    echo -e "${GREEN}🎉 All critical checks passed! Cluster is healthy.${NC}"
    exit 0
else
    echo -e "${RED}⚠️  $failed_checks checks failed. Review output above.${NC}"
    exit 1
fi