#!/bin/bash

# Comprehensive K3s Agent Validation Script
# Tests all aspects of k3s agent setup and connectivity

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Timestamp function
get_timestamp() {
    date '+%H:%M:%S'
}

# Configuration
TOWER_IP="192.168.5.1"
AGX_IP="192.168.10.11"
NANO_IP="192.168.5.21"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  K3s Agent Comprehensive Validation${NC}"
echo -e "${BLUE}========================================${NC}"

# Detect device type
if ip addr show | grep -q "$AGX_IP"; then
    DEVICE_TYPE="AGX"
    DEVICE_IP="$AGX_IP"
    OTHER_DEVICE_IP="$NANO_IP"
    OTHER_DEVICE_NAME="Nano"
elif ip addr show | grep -q "$NANO_IP"; then
    DEVICE_TYPE="Nano"
    DEVICE_IP="$NANO_IP"
    OTHER_DEVICE_IP="$AGX_IP"
    OTHER_DEVICE_NAME="AGX"
else
    echo -e "${RED}ERROR: Cannot detect device type (not AGX or Nano)${NC}"
    exit 1
fi

echo -e "${GREEN}Detected device: $DEVICE_TYPE ($DEVICE_IP)${NC}"
echo ""

# Test functions
test_network_connectivity() {
    echo -e "${YELLOW}Testing Network Connectivity...${NC}"

    # Test connection to Tower
    if ping -c 3 -W 2 "$TOWER_IP" >/dev/null 2>&1; then
        echo -e "  ✅ Tower connectivity ($TOWER_IP)"
    else
        echo -e "  ❌ Tower connectivity failed ($TOWER_IP)"
        return 1
    fi

    # Test connection to other device
    if ping -c 3 -W 2 "$OTHER_DEVICE_IP" >/dev/null 2>&1; then
        echo -e "  ✅ $OTHER_DEVICE_NAME connectivity ($OTHER_DEVICE_IP)"
    else
        echo -e "  ❌ $OTHER_DEVICE_NAME connectivity failed ($OTHER_DEVICE_IP)"
        return 1
    fi

    # Test internet connectivity
    if ping -c 3 -W 2 8.8.8.8 >/dev/null 2>&1; then
        echo -e "  ✅ Internet connectivity"
    else
        echo -e "  ❌ Internet connectivity failed"
        return 1
    fi

    return 0
}

test_k3s_service() {
    echo -e "${YELLOW}Testing K3s Service...${NC}"

    # Check if k3s-agent service exists
    if systemctl is-enabled k3s-agent >/dev/null 2>&1; then
        echo -e "  ✅ k3s-agent service is enabled"
    else
        echo -e "  ❌ k3s-agent service not enabled"
        return 1
    fi

    # Check if service is running
    if systemctl is-active k3s-agent >/dev/null 2>&1; then
        echo -e "  ✅ k3s-agent service is running"
    else
        echo -e "  ❌ k3s-agent service not running"
        return 1
    fi

    # Check k3s agent process
    if pgrep -f "k3s agent" >/dev/null; then
        echo -e "  ✅ k3s agent process is running"
    else
        echo -e "  ❌ k3s agent process not found"
        return 1
    fi

    return 0
}

test_kubernetes_connectivity() {
    echo -e "${YELLOW}Testing Kubernetes Connectivity...${NC}"

    # Check kubectl access
    if command -v kubectl >/dev/null 2>&1; then
        echo -e "  ✅ kubectl is available"
    else
        echo -e "  ❌ kubectl not found"
        return 1
    fi

    # Test cluster access
    if kubectl cluster-info >/dev/null 2>&1; then
        echo -e "  ✅ Kubernetes cluster accessible"
    else
        echo -e "  ❌ Cannot access Kubernetes cluster"
        return 1
    fi

    # Check node status
    NODE_STATUS=$(kubectl get nodes -o jsonpath="{.items[?(@.status.addresses[0].address=='$DEVICE_IP')].status.conditions[?(@.type=='Ready')].status}")
    if [ "$NODE_STATUS" = "True" ]; then
        echo -e "  ✅ This node ($DEVICE_IP) is Ready in cluster"
    else
        echo -e "  ❌ This node ($DEVICE_IP) is not Ready in cluster"
        return 1
    fi

    # Check pod status
    READY_PODS=$(kubectl get pods -A --field-selector=status.phase=Running --no-headers | wc -l)
    if [ "$READY_PODS" -gt 0 ]; then
        echo -e "  ✅ $READY_PODS pods are running in cluster"
    else
        echo -e "  ⚠️  No running pods found (may be normal for fresh setup)"
    fi

    return 0
}

test_docker_registry() {
    echo -e "${YELLOW}Testing Docker Registry...${NC}"

    # Check Docker service
    if systemctl is-active docker >/dev/null 2>&1; then
        echo -e "  ✅ Docker service is running"
    else
        echo -e "  ❌ Docker service not running"
        return 1
    fi

    # Test registry connectivity
    if curl -k "https://$TOWER_IP:5000/v2/" >/dev/null 2>&1; then
        echo -e "  ✅ Docker registry accessible at $TOWER_IP:5000"
    else
        echo -e "  ❌ Docker registry not accessible at $TOWER_IP:5000"
        return 1
    fi

    # Check insecure registry config
    if [ -f /etc/docker/daemon.json ]; then
        if grep -q "$TOWER_IP:5000" /etc/docker/daemon.json; then
            echo -e "  ✅ Docker insecure registry configured"
        else
            echo -e "  ❌ Docker insecure registry not configured"
            return 1
        fi
    else
        echo -e "  ❌ Docker daemon.json not found"
        return 1
    fi

    return 0
}

test_nfs_mounts() {
    echo -e "${YELLOW}Testing NFS Mounts...${NC}"

    # Check vmstore mount
    if mount | grep -q "/mnt/vmstore"; then
        echo -e "  ✅ NFS mount /mnt/vmstore is active"
    else
        echo -e "  ❌ NFS mount /mnt/vmstore not found"
        return 1
    fi

    # Test mount accessibility
    if [ -d "/mnt/vmstore" ] && [ -r "/mnt/vmstore" ]; then
        echo -e "  ✅ NFS mount is accessible"
    else
        echo -e "  ❌ NFS mount not accessible"
        return 1
    fi

    return 0
}

test_routing_tables() {
    echo -e "${YELLOW}Testing Routing Tables...${NC}"

    # Check routes
    if ip route show | grep -q "192.168.5.0/24"; then
        echo -e "  ✅ Route to Nano subnet (192.168.5.0/24) exists"
    else
        echo -e "  ❌ Route to Nano subnet missing"
        return 1
    fi

    if ip route show | grep -q "192.168.10.0/24"; then
        echo -e "  ✅ Route to AGX subnet (192.168.10.0/24) exists"
    else
        echo -e "  ❌ Route to AGX subnet missing"
        return 1
    fi

    return 0
}

test_iptables_rules() {
    echo -e "${YELLOW}Testing iptables Rules...${NC}"

    # Check FORWARD rules for inter-device communication
    if sudo iptables -L FORWARD -n | grep -q "192.168.5.0/24.*ACCEPT"; then
        echo -e "  ✅ iptables rule for Nano subnet traffic exists"
    else
        echo -e "  ❌ iptables rule for Nano subnet traffic missing"
        return 1
    fi

    if sudo iptables -L FORWARD -n | grep -q "192.168.10.0/24.*ACCEPT"; then
        echo -e "  ✅ iptables rule for AGX subnet traffic exists"
    else
        echo -e "  ❌ iptables rule for AGX subnet traffic missing"
        return 1
    fi

    return 0
}

# Run all tests
FAILED_TESTS=()

run_test() {
    local test_name="$1"
    local test_func="$2"
    local start_time=$(get_timestamp)

    echo -e "${BLUE}----------------------------------------${NC}"
    echo -e "${YELLOW}[$start_time] Starting: $test_name${NC}"

    if $test_func; then
        local end_time=$(get_timestamp)
        echo -e "${GREEN}[$end_time] ✅ $test_name PASSED${NC}"
        return 0
    else
        local end_time=$(get_timestamp)
        echo -e "${RED}[$end_time] ❌ $test_name FAILED${NC}"
        FAILED_TESTS+=("$test_name")
        return 1
    fi
}

# Execute tests
run_test "Network Connectivity" test_network_connectivity
run_test "K3s Service Status" test_k3s_service
run_test "Kubernetes Connectivity" test_kubernetes_connectivity
run_test "Docker Registry" test_docker_registry
run_test "NFS Mounts" test_nfs_mounts
run_test "Routing Tables" test_routing_tables
run_test "iptables Rules" test_iptables_rules

# Summary
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}              VALIDATION SUMMARY${NC}"
echo -e "${BLUE}========================================${NC}"

if [ ${#FAILED_TESTS[@]} -eq 0 ]; then
    local end_timestamp=$(get_timestamp)
    echo -e "${GREEN}[$end_timestamp] 🎉 ALL TESTS PASSED! K3s agent setup is working flawlessly.${NC}"
    echo ""
    echo -e "${GREEN}Your $DEVICE_TYPE k3s agent is properly configured and connected to the cluster.${NC}"
    exit 0
else
    local end_timestamp=$(get_timestamp)
    echo -e "${RED}[$end_timestamp] ❌ ${#FAILED_TESTS[@]} test(s) failed:${NC}"
    for test in "${FAILED_TESTS[@]}"; do
        echo -e "  - $test"
    done
    echo ""
    echo -e "${YELLOW}💡 Troubleshooting tips:${NC}"
    echo "  - Run cleanup script first: ./cleanup-$DEVICE_TYPE.sh"
    echo "  - Re-run network setup: ./setup-${DEVICE_TYPE,,}-network.sh"
    echo "  - Then re-run k3s setup: ./k3s-${DEVICE_TYPE,,}-agent-setup.sh"
    echo "  - Check logs: journalctl -u k3s-agent -f"
    exit 1
fi