#!/bin/bash
# AGX Agent Validation Script
# Run this to validate AGX agent setup and cluster connectivity

source "$(dirname "$0")/agx-config.env"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
TICK="${GREEN}✅${NC}"
CROSS="${RED}❌${NC}"

function print_result() {
    if [ "$1" -eq 0 ]; then
        echo -e "$2 $TICK"
    else
        echo -e "$2 $CROSS"
    fi
}

echo -e "\n${GREEN}AGX Agent Validation${NC}"
echo -e "Node: $NODE_NAME"
echo -e "Tower: $TOWER_SERVER_IP"

echo -e "\n${GREEN}Network Connectivity${NC}"
ping -c 1 $TOWER_SERVER_IP >/dev/null 2>&1
print_result $? "  Tower reachable ($TOWER_SERVER_IP)"

timeout 5 bash -c "echo > /dev/tcp/$TOWER_SERVER_IP/$TOWER_API_PORT" 2>/dev/null
print_result $? "  k3s API server reachable ($TOWER_SERVER_IP:$TOWER_API_PORT)"

echo -e "\n${GREEN}k3s Agent Status${NC}"
sudo systemctl is-active --quiet k3s-agent
print_result $? "  k3s agent service running"

sudo systemctl is-enabled --quiet k3s-agent
print_result $? "  k3s agent service enabled"

echo -e "\n${GREEN}Cluster Membership${NC}"
kubectl get nodes >/dev/null 2>&1
print_result $? "  kubectl connectivity"

kubectl get nodes | grep -q "$NODE_NAME"
print_result $? "  Node $NODE_NAME in cluster"

NODE_STATUS=$(kubectl get node "$NODE_NAME" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)
if [ "$NODE_STATUS" = "True" ]; then
    print_result 0 "  Node $NODE_NAME is Ready"
else
    print_result 1 "  Node $NODE_NAME not Ready (Status: $NODE_STATUS)"
fi

echo -e "\n${GREEN}Container Runtime${NC}"
docker info >/dev/null 2>&1
print_result $? "  Docker running"

docker images | grep -q "localhost:5000"
print_result $? "  Registry images available"

echo -e "\n${GREEN}Storage Access${NC}"
[ -d "$REGISTRY_PATH" ]
print_result $? "  Shared registry accessible"

[ -f "$TOKEN_PATH" ]
print_result $? "  Token file accessible"

[ -f "$KUBECONFIG_PATH" ]
print_result $? "  Kubeconfig accessible"

echo -e "\n${GREEN}Service Access${NC}"
timeout 3 bash -c "echo > /dev/tcp/192.168.10.1/5432" 2>/dev/null
print_result $? "  PostgreSQL accessible"

timeout 3 bash -c "echo > /dev/tcp/192.168.10.1/8080" 2>/dev/null
print_result $? "  pgAdmin accessible"

echo -e "\n${GREEN}Cluster Overview${NC}"
kubectl get nodes -o wide 2>/dev/null || echo "Unable to get cluster nodes"
echo ""
kubectl get pods --all-namespaces -o wide | grep "$NODE_NAME" 2>/dev/null || echo "No pods running on this node"