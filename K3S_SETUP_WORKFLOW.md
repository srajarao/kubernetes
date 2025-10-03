# K3s Agent Setup & Validation Workflow

## Overview
This document outlines the complete workflow for setting up k3s agents with built-in fixes and comprehensive validation.

## Critical Principle: Fixes Must Be In Scripts
**All fixes must be implemented in the setup scripts themselves** - not applied manually. This ensures:
- Fixes are permanent and repeatable
- No manual intervention needed during installation
- Consistent results across multiple deployments
- Easy troubleshooting and maintenance

## Setup Sequence (With Built-in Fixes)

### Phase 1: Network Foundation (Run on Correct Devices)
```bash
# On Tower
cd /home/sanjay/containers/kubernetes
./network/1-setup_tower_network.sh

# On AGX (after Tower network is ready)
./network/2-setup_agx_network.sh

# On Nano (after Tower network is ready)
./network/3-setup_nano_network.sh

# Back on Tower
./network/4-setup_tower_routing.sh
```

### Phase 2: Kubernetes Setup (With Built-in Network Fixes)
```bash
# On Tower
./server/k8s-setup-validate.sh

# On AGX (scripts now include network restoration)
./agent/agx/k3s-agx-agent-setup.sh

# On Nano (scripts now include network restoration)
./agent/nano/k3s-nano-agent-setup.sh
```

## Built-in Fixes in Scripts

### Network Connectivity Fixes
Both AGX and Nano scripts now automatically:
- **Restore routes** after k3s installation (k3s modifies iptables/routes)
- **Add iptables rules** for inter-device communication
- **Ensure connectivity** between AGX↔Nano subnets via Tower

### Example: Nano Script Fixes
```bash
# After k3s installation, script automatically runs:
sudo ip route add 192.168.10.0/24 via $TOWER_IP dev $NANO_IFACE metric 100
sudo iptables -I FORWARD -s $NANO_IP -d 192.168.10.0/24 -j ACCEPT
```

## Validation Workflow (Run After Installation)

### Step 1: Run Comprehensive Validation
```bash
# On each agent after setup
cd /home/sanjay/containers/kubernetes
./validate-k3s-agent.sh
```

### Step 2: Check Results
The validation script tests:
- ✅ Network connectivity (Tower, other device, internet)
- ✅ K3s service status and processes
- ✅ Kubernetes cluster access and node readiness
- ✅ Docker registry connectivity
- ✅ NFS mounts accessibility
- ✅ Routing tables correctness
- ✅ iptables rules for inter-device traffic

### Step 3: If Validation Fails
```bash
# Clean up and retry
./agent/nano/cleanup-nano.sh  # or cleanup-agx.sh
# Re-run network setup
./network/3-setup_nano_network.sh
# Re-run k3s setup (with built-in fixes)
./agent/nano/k3s-nano-agent-setup.sh
# Re-validate
./validate-k3s-agent.sh
```

## Success Criteria
- **All validation tests pass** (7/7 tests)
- **No manual fixes needed** during installation
- **Connectivity maintained** after k3s setup
- **Cluster fully operational** with all nodes ready

## Troubleshooting Matrix

| Issue | Symptom | Built-in Fix | Manual Override |
|-------|---------|--------------|----------------|
| Routes lost after k3s | Can't reach other subnet | Script restores routes | `ip route add` |
| iptables blocks traffic | Ping fails between devices | Script adds FORWARD rules | `iptables -I` |
| Service not starting | k3s-agent fails | Script handles dependencies | `systemctl restart` |
| Registry not accessible | Docker pull fails | Script configures daemon.json | Edit `/etc/docker/daemon.json` |

## Weekly Testing Plan

### Monday: Clean Setup Test
1. Run cleanup scripts on all devices
2. Execute full setup sequence
3. Run validation - expect 100% pass rate
4. Document any issues for script improvement

### Wednesday: Recovery Test
1. Simulate failure (disconnect network, stop services)
2. Test automatic recovery via scripts
3. Validate restored functionality

### Friday: Stress Test
1. Deploy sample workloads
2. Test under load
3. Verify stability over time

## Key Improvements Made

1. **Permanent Route Restoration**: Added `ip route` commands in scripts
2. **iptables Rule Management**: Built-in firewall rule addition
3. **Comprehensive Validation**: Automated testing of all components
4. **Error Recovery**: Scripts handle common failure modes
5. **Documentation**: Clear workflow with success criteria

This approach ensures k3s agents work flawlessly every time without manual intervention.