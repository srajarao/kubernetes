#!/bin/bash

# K3s Node Auto-Recovery Script
# Monitors cluster nodes and automatically recovers failed agents

RECOVERY_LOG="/home/sanjay/containers/kubernetes/node_recovery.log"
KUBECONFIG="/home/sanjay/.kube/config"

# Node configuration
declare -A NODES=(
    ["nano"]="192.168.1.181"
    ["agx"]="192.168.1.244"
    ["spark1"]="192.168.1.201"
    ["spark2"]="192.168.1.202"
)

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - RECOVERY: $*" >> "$RECOVERY_LOG"
    echo "$*"
}

check_node_health() {
    local node_name="$1"
    local node_ip="$2"

    log "Checking health of node $node_name ($node_ip)"

    # Check if node is reachable via ping (with timeout)
    if ! timeout 5 ping -c 1 -W 2 "$node_ip" >/dev/null 2>&1; then
        log "❌ Node $node_name is not reachable via ping"
        return 1
    fi

    # Check if node is Ready in Kubernetes
    local node_status=$(timeout 10 kubectl get nodes "$node_name" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)
    if [ "$node_status" != "True" ]; then
        log "❌ Node $node_name is not Ready in Kubernetes (status: $node_status)"
        return 1
    fi

    # Check SSH connectivity (with timeout)
    if ! timeout 5 ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes "$node_name" "echo 'SSH OK'" >/dev/null 2>&1; then
        log "❌ Cannot SSH to node $node_name"
        return 1
    fi

    log "✅ Node $node_name is healthy"
    return 0
}

recover_node() {
    local node_name="$1"
    local node_ip="$2"

    log "Attempting to recover node $node_name"

    # Try to restart K3s agent via SSH (with timeout)
    if timeout 30 ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$node_name" "sudo systemctl restart k3s-agent" 2>/dev/null; then
        log "✅ Successfully restarted K3s agent on $node_name"

        # Wait for node to become ready (with shorter waits)
        local attempts=0
        while [ $attempts -lt 6 ]; do  # Wait up to 1 minute
            sleep 10
            local node_status=$(timeout 5 kubectl get nodes "$node_name" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)
            if [ "$node_status" = "True" ]; then
                log "✅ Node $node_name has recovered and is Ready"
                return 0
            fi
            ((attempts++))
        done

        log "❌ Node $node_name failed to become Ready after recovery attempt"
        return 1
    else
        log "❌ Failed to restart K3s agent on $node_name"
        return 1
    fi
}

check_and_recover_all_nodes() {
    log "Starting node health check and recovery cycle"

    local recovery_needed=false

    for node_name in "${!NODES[@]}"; do
        local node_ip="${NODES[$node_name]}"

        if ! check_node_health "$node_name" "$node_ip"; then
            log "🔧 Recovery needed for node $node_name"
            recovery_needed=true

            if recover_node "$node_name" "$node_ip"; then
                log "🎉 Successfully recovered node $node_name"
            else
                log "💥 Failed to recover node $node_name - manual intervention required"
            fi
        fi
    done

    if [ "$recovery_needed" = false ]; then
        log "✅ All nodes are healthy - no recovery needed"
    fi
}

# Ensure kubectl is available
export KUBECONFIG="$KUBECONFIG"
export PATH="/snap/bin:$PATH"

# Main execution
log "=== Node Auto-Recovery Script Started ==="
check_and_recover_all_nodes
log "=== Node Auto-Recovery Script Completed ==="