#!/bin/bash

clear

# Source configuration
# NOTE: Ensure k3s-config.sh exists and contains TOWER_IP, NANO_IP, AGX_IP, REGISTRY_IP, etc.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/k3s-config.sh" ]; then
  source "$SCRIPT_DIR/k3s-config.sh"
else
  echo "ERROR: k3s-config.sh not found in $SCRIPT_DIR"
  exit 1
fi

# Pre-flight validation
echo "🔍 Running pre-flight checks..."
if ! [[ "$TOWER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "❌ ERROR: TOWER_IP ($TOWER_IP) is not a valid IP address"
  exit 1
fi
if ! [[ "$NANO_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "❌ ERROR: NANO_IP ($NANO_IP) is not a valid IP address"
  exit 1
fi
if ! [[ "$AGX_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "❌ ERROR: AGX_IP ($AGX_IP) is not a valid IP address"
  exit 1
fi
echo "✅ Configuration validation passed"

# Network Interface Verification
echo "🔍 Verifying network interface configuration..."
echo "   Checking if IP addresses are properly assigned to interfaces..."

# Check for NetworkManager vs systemd-networkd renderer conflicts
echo "   🔍 Checking for network renderer conflicts..."
INTERFACE_STATE=$(networkctl 2>/dev/null | grep -E "(eno1|enp1s0f1)" | awk '{print $4}' || echo "unknown")
if [ "$INTERFACE_STATE" = "configuring" ]; then
    echo "   ❌ CRITICAL: Network interface is stuck in 'configuring' state"
    echo "   💡 This indicates a NetworkManager/systemd-networkd renderer conflict"
    echo "   🔧 Fix: Run 'sudo nmcli device set enp1s0f1 managed no' then 'sudo netplan apply'"
    echo "   📋 Current netplan renderers:"
    grep -r "renderer:" /etc/netplan/ 2>/dev/null | head -3 || echo "      No netplan files found"
    read -p "   Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "   ❌ Setup aborted by user due to network renderer conflict"
        exit 1
    fi
elif [ "$INTERFACE_STATE" = "configured" ]; then
    echo "   ✅ Network interface properly configured"
else
    echo "   ⚠️  Network interface state: $INTERFACE_STATE (monitoring...)"
fi

# Function to check if IP is assigned to an interface
check_ip_assignment() {
    local ip=$1
    local expected_iface=$2
    local description=$3

    if ip addr show | grep -q "$ip"; then
        echo "   ✅ $description: $ip is assigned"
        return 0
    else
        echo "   ❌ $description: $ip is NOT assigned to any interface"
        echo "   🔍 Current IP assignments:"
        ip addr show | grep "inet " | grep -v "127.0.0.1" | awk '{print "      " $2 " on " $NF}'
        return 1
    fi
}

# Check Tower IP assignment
if ! check_ip_assignment "$TOWER_IP" "enp1s0f1" "Tower IP"; then
    echo "   ⚠️  WARNING: Tower IP not found. This may cause network connectivity issues."
    echo "   💡 Ensure network interfaces are properly configured before proceeding."
    echo "   🔧 Run network setup scripts if needed:"
    echo "      - For Tower: Check /etc/netplan/50-dedicated-networks.yaml"
    echo "      - Verify with: ip addr show"
    read -p "   Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "   ❌ Setup aborted by user"
        exit 1
    fi
fi

echo "✅ Network interface verification completed"

# DNS and Hostname Resolution Verification
echo "🔍 Verifying DNS and hostname resolution..."
echo "   Testing connectivity to all cluster nodes..."

# Function to test hostname resolution and ping
test_node_connectivity() {
    local ip=$1
    local hostname=$2
    local description=$3

    echo "   Testing $description ($ip)..."
    
    # Test ping
    if ping -c 2 -W 2 "$ip" >/dev/null 2>&1; then
        echo "      ✅ Ping to $ip successful"
    else
        echo "      ❌ Cannot ping $ip"
        return 1
    fi
    
    # Test hostname resolution (if hostname is provided)
    if [ -n "$hostname" ]; then
        if getent hosts "$hostname" >/dev/null 2>&1; then
            echo "      ✅ Hostname '$hostname' resolves correctly"
        else
            echo "      ⚠️  Hostname '$hostname' does not resolve (may be normal if no DNS configured)"
        fi
    fi
    
    return 0
}

# Test connectivity to all nodes
connectivity_ok=true

if ! test_node_connectivity "$TOWER_IP" "tower" "Tower server"; then
    connectivity_ok=false
fi

if ! test_node_connectivity "$AGX_IP" "agx" "AGX node"; then
    connectivity_ok=false
fi

if ! test_node_connectivity "$NANO_IP" "nano" "Nano node"; then
    connectivity_ok=false
fi

if [ "$connectivity_ok" = true ]; then
    echo "   ✅ All cluster nodes are reachable"
else
    echo "   ⚠️  Some nodes are not reachable. This may cause deployment issues."
    echo "   💡 Check network cables, IP configurations, and firewall settings."
    read -p "   Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "   ❌ Setup aborted due to connectivity issues"
        exit 1
    fi
fi

echo "✅ DNS and hostname resolution verification completed"

# Routing Table Verification
echo "🔍 Verifying routing table configuration..."
echo "   Checking for routing issues that could cause connectivity problems..."

# Check for default route
if ! ip route show | grep -q "^default"; then
    echo "   ❌ WARNING: No default route found!"
    echo "   💡 This could prevent internet access and external connectivity."
else
    echo "   ✅ Default route exists"
fi

# Check for local subnet route
if ! ip route show | grep -q "10.1.10.0/24"; then
    echo "   ❌ WARNING: No route to local subnet 10.1.10.0/24!"
    echo "   💡 This will prevent communication with other cluster nodes."
else
    echo "   ✅ Local subnet route exists"
fi

# Check for multiple default routes (warning if metrics are equal)
default_routes=$(ip route show | grep "^default" | wc -l)
if [ "$default_routes" -gt 1 ]; then
    echo "   ⚠️  Multiple default routes detected ($default_routes total)"
    echo "   📋 Default routes:"
    ip route show | grep "^default" | sed 's/^/      /'
    echo "   💡 This is normal for multi-interface machines, but ensure wired interface has lower metric."
else
    echo "   ✅ Single default route"
fi

echo "✅ Routing table verification completed"

# K3s Configuration Verification
echo "🔍 Verifying K3s agent configurations..."
echo "   Checking that agents are configured with correct server URL..."

# Function to check K3s agent configuration
check_agent_config() {
    local node=$1
    local expected_ip=$2
    
    echo "   Checking $node configuration..."
    
    # Check if agent service exists and has correct server URL
    ssh "$node" "sudo cat /etc/systemd/system/k3s-agent.service.env 2>/dev/null | grep K3S_URL" | grep -q "$TOWER_IP" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "      ✅ $node configured with correct server URL: https://$TOWER_IP:6443"
    else
        echo "      ❌ $node server URL configuration issue"
        echo "      Expected: https://$TOWER_IP:6443"
        ssh "$node" "sudo cat /etc/systemd/system/k3s-agent.service.env 2>/dev/null | grep K3S_URL || echo '      No K3S_URL found'" 2>/dev/null
        return 1
    fi
    
    # Check if agent has correct node IP
    ssh "$node" "sudo cat /etc/systemd/system/k3s-agent.service 2>/dev/null | grep -A 5 'ExecStart.*agent' | grep -q '$expected_ip'" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "      ✅ $node configured with correct node IP: $expected_ip"
    else
        echo "      ⚠️  $node node IP configuration may need verification"
    fi
    
    return 0
}

# Check agent configurations
agent_config_ok=true

if ! check_agent_config "agx" "$AGX_IP"; then
    agent_config_ok=false
fi

if ! check_agent_config "nano" "$NANO_IP"; then
    agent_config_ok=false
fi

if [ "$agent_config_ok" = true ]; then
    echo "   ✅ All K3s agent configurations verified"
else
    echo "   ⚠️  Some agent configurations may have issues"
    read -p "   Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "   ❌ Setup aborted due to agent configuration issues"
        exit 1
    fi
fi

echo "✅ K3s configuration verification completed"
