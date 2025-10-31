#!/bin/bash

# Comprehensive Cluster Health Monitor
# Monitors all critical infrastructure components

MONITOR_LOG="/home/sanjay/containers/kubernetes/health_monitor.log"
ALERT_LOG="/home/sanjay/containers/kubernetes/health_alerts.log"
HEALTH_CHECK_INTERVAL=60  # Check every minute
ALERT_THRESHOLD=3  # Alert after 3 consecutive failures

# Initialize counters
k3s_failures=0
node_failures=0
service_failures=0
storage_failures=0

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - HEALTH: $*" >> "$MONITOR_LOG"
}

alert() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ALERT: $message" >> "$ALERT_LOG"
    log "ALERT: $message"

    # Send desktop notification if available
    if command -v notify-send >/dev/null 2>&1; then
        notify-send "K3s Health Alert" "$message" --icon=dialog-warning
    fi
}

check_k3s_cluster() {
    log "Checking K3s cluster status..."

    # Check if kubectl is accessible
    if ! kubectl cluster-info >/dev/null 2>&1; then
        ((k3s_failures++))
        log "K3s API server not accessible (failure $k3s_failures/$ALERT_THRESHOLD)"
        if [ $k3s_failures -ge $ALERT_THRESHOLD ]; then
            alert "K3s cluster is not accessible - API server may be down"
            k3s_failures=0
        fi
        return 1
    fi

    k3s_failures=0
    log "K3s cluster is accessible"
    return 0
}

check_nodes() {
    log "Checking cluster nodes..."

    local unhealthy_nodes=$(kubectl get nodes --no-headers | grep -v " Ready" | wc -l)
    local total_nodes=$(kubectl get nodes --no-headers | wc -l)

    if [ "$unhealthy_nodes" -gt 0 ]; then
        ((node_failures++))
        log "Found $unhealthy_nodes unhealthy nodes out of $total_nodes (failure $node_failures/$ALERT_THRESHOLD)"
        if [ $node_failures -ge $ALERT_THRESHOLD ]; then
            alert "Cluster has $unhealthy_nodes unhealthy nodes out of $total_nodes total"
            node_failures=0
        fi
        return 1
    fi

    node_failures=0
    log "All $total_nodes nodes are healthy"
    return 0
}

check_services() {
    log "Checking critical services..."

    local failed_services=0

    # Check PostgreSQL (use actual labels from your cluster)
    if kubectl get pods -l app=postgres-db --no-headers 2>/dev/null | grep -q "Running"; then
        log "PostgreSQL service is running"
    else
        log "PostgreSQL service check: No pods found with label app=postgres-db"
    fi

    # Check registry (use actual labels from your cluster)
    if kubectl get pods -l app=registry --no-headers 2>/dev/null | grep -q "Running"; then
        log "Docker registry is running"
    else
        log "Docker registry check: No pods found with label app=registry"
    fi

    # Check pgAdmin (use actual labels from your cluster)
    if kubectl get pods -l app=pgadmin --no-headers 2>/dev/null | grep -q "Running"; then
        log "pgAdmin is running"
    else
        log "pgAdmin check: No pods found with label app=pgadmin"
    fi

    # Check actual running services
    local running_services=$(kubectl get pods -A --no-headers 2>/dev/null | grep "Running" | wc -l)
    local total_services=$(kubectl get pods -A --no-headers 2>/dev/null | wc -l)

    log "Services status: $running_services/$total_services pods are running"

    if [ "$running_services" -lt "$total_services" ]; then
        ((service_failures++))
        log "$((total_services - running_services)) services are not running (failure $service_failures/$ALERT_THRESHOLD)"
        if [ $service_failures -ge $ALERT_THRESHOLD ]; then
            alert "$((total_services - running_services)) services are failing"
            service_failures=0
        fi
        return 1
    fi

    service_failures=0
    log "All services are running"
    return 0
}

check_storage() {
    log "Checking storage health..."

    # Check NFS mount points on nodes
    local mount_issues=0

    # Check tower NFS exports
    if ! ssh tower "exportfs -v" >/dev/null 2>&1; then
        log "NFS exports on tower are not accessible"
        ((mount_issues++))
    fi

    if [ $mount_issues -gt 0 ]; then
        ((storage_failures++))
        log "Storage issues detected (failure $storage_failures/$ALERT_THRESHOLD)"
        if [ $storage_failures -ge $ALERT_THRESHOLD ]; then
            alert "Storage system has issues - NFS mounts may be failing"
            storage_failures=0
        fi
        return 1
    fi

    storage_failures=0
    log "Storage system is healthy"
    return 0
}

check_gpu_nodes() {
    log "Checking GPU-enabled nodes..."

    # Check if any nodes have GPU capacity
    local gpu_nodes=$(kubectl get nodes --no-headers 2>/dev/null | awk '{print $1}' | xargs -I {} kubectl describe node {} 2>/dev/null | grep -c "nvidia.com/gpu:" || echo "0")

    if [ "$gpu_nodes" -gt 0 ]; then
        log "Found $gpu_nodes GPU-enabled nodes"

        # Check NVIDIA device plugin (look for actual running pods)
        local plugin_pods=$(kubectl get pods -n kube-system --no-headers 2>/dev/null | grep -c "nvidia-device-plugin" || echo "0")
        if [ "$plugin_pods" -gt 0 ]; then
            log "NVIDIA device plugin pods are running"
            return 0
        else
            log "No NVIDIA device plugin pods found"
            return 1
        fi
    else
        log "No GPU-enabled nodes found"
        return 0  # Not an error if no GPU nodes exist
    fi
}
        fi
    else
        log "No GPU-enabled nodes detected"
    fi

    return 0
}

generate_report() {
    log "Generating health report..."

    local report_file="/home/sanjay/containers/kubernetes/health_report_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "=== K3s Cluster Health Report ==="
        echo "Generated: $(date)"
        echo ""

        echo "=== Cluster Overview ==="
        kubectl get nodes -o wide
        echo ""

        echo "=== Pod Status ==="
        kubectl get pods -A --field-selector=status.phase!=Running 2>/dev/null || echo "All pods are running"
        echo ""

        echo "=== Resource Usage ==="
        kubectl top nodes 2>/dev/null || echo "Metrics server not available"
        echo ""

        echo "=== Storage Status ==="
        kubectl get pv,pvc -A 2>/dev/null || echo "No persistent volumes found"
        echo ""

        echo "=== Recent Alerts ==="
        tail -10 "$ALERT_LOG" 2>/dev/null || echo "No recent alerts"
        echo ""

    } > "$report_file"

    log "Health report saved to $report_file"
}

main() {
    log "Starting comprehensive health monitoring..."

    # Test kubectl access first
    if ! kubectl cluster-info >/dev/null 2>&1; then
        log "ERROR: Cannot access Kubernetes API"
        exit 1
    fi

    while true; do
        local issues_found=0

        check_k3s_cluster || ((issues_found++))
        check_nodes || ((issues_found++))
        check_services || ((issues_found++))
        check_storage || ((issues_found++))
        check_gpu_nodes || ((issues_found++))

        if [ $issues_found -eq 0 ]; then
            log "All health checks passed"
        else
            log "Found $issues_found health issues"
        fi

        # Generate weekly report
        if [ $(date +%u) -eq 7 ] && [ $(date +%H) -eq 12 ] && [ $(date +%M) -lt 5 ]; then
            generate_report
        fi

        # Check for non-running pods (but don't fail if jq isn't available)
        local non_running_pods=$(kubectl get pods -A -o json 2>/dev/null | jq -r '.items[] | select(.status.phase != "Running") | "\(.metadata.name): \(.status.phase)"' 2>/dev/null || echo "")
        if [ -n "$non_running_pods" ]; then
            log "Found non-running pods: $non_running_pods"
        fi

        sleep $HEALTH_CHECK_INTERVAL
    done
}

# Handle script termination
trap 'log "Health monitoring stopped"' EXIT

main "$@"