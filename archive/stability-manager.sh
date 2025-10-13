#!/bin/bash
# K3s Environment Stability Manager
# Provides monitoring, health checks, and recovery for the K3s cluster

set -e

# Configuration
KUBECONFIG="/etc/rancher/k3s/k3s.yaml"
TOWER_IP="10.1.10.150"
NANO_IP="10.1.10.181"
AGX_IP="10.1.10.244"
LOG_FILE="/home/sanjay/containers/kubernetes/stability.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    # Always write to log file
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" >> "$LOG_FILE"
    # Only output to console if not in quiet mode
    if [ "${QUIET_MODE:-false}" = false ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - $*"
    fi
}

success() {
    echo -e "${GREEN}✅ $1${NC}" >> "$LOG_FILE"
    if [ "${QUIET_MODE:-false}" = false ]; then
        echo -e "${GREEN}✅ $1${NC}"
    fi
}

error() {
    echo -e "${RED}❌ $1${NC}" >> "$LOG_FILE"
    if [ "${QUIET_MODE:-false}" = false ]; then
        echo -e "${RED}❌ $1${NC}"
    fi
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}" >> "$LOG_FILE"
    if [ "${QUIET_MODE:-false}" = false ]; then
        echo -e "${YELLOW}⚠️  $1${NC}"
    fi
}

info() {
    echo -e "${BLUE}ℹ️  $1${NC}" >> "$LOG_FILE"
    if [ "${QUIET_MODE:-false}" = false ]; then
        echo -e "${BLUE}ℹ️  $1${NC}"
    fi
}

# Health check functions
check_nodes() {
    if [ "${QUIET_MODE:-false}" = false ]; then
        log "Checking cluster nodes..."
    fi
    if sudo kubectl --kubeconfig="$KUBECONFIG" get nodes >/dev/null 2>&1; then
        NODE_COUNT=$(sudo kubectl --kubeconfig="$KUBECONFIG" get nodes --no-headers | wc -l)
        READY_NODES=$(sudo kubectl --kubeconfig="$KUBECONFIG" get nodes --no-headers | grep -c " Ready")
        if [ "${QUIET_MODE:-false}" = false ]; then
            success "Nodes: $READY_NODES/$NODE_COUNT ready"
        fi
        return 0
    else
        if [ "${QUIET_MODE:-false}" = false ]; then
            error "Cannot connect to cluster"
        fi
        return 1
    fi
}

check_pods() {
    if [ "${QUIET_MODE:-false}" = false ]; then
        log "Checking application pods..."
    fi
    local failed_pods=0

    # Check each expected pod
    for pod in "fastapi-nano" "postgres-db" "pgadmin"; do
        if sudo kubectl --kubeconfig="$KUBECONFIG" get pods -l app="$pod" --no-headers 2>/dev/null | grep -q "Running"; then
            if [ "${QUIET_MODE:-false}" = false ]; then
                success "$pod: Running"
            fi
        else
            if [ "${QUIET_MODE:-false}" = false ]; then
                error "$pod: Not running or missing"
            fi
            ((failed_pods++))
        fi
    done

    return $failed_pods
}

check_services() {
    if [ "${QUIET_MODE:-false}" = false ]; then
        log "Checking service accessibility..."
    fi

    # FastAPI health check
    if curl -s -f http://"$TOWER_IP":30002/health >/dev/null 2>&1; then
        if [ "${QUIET_MODE:-false}" = false ]; then
            success "FastAPI: Accessible"
        fi
    else
        if [ "${QUIET_MODE:-false}" = false ]; then
            error "FastAPI: Not accessible"
        fi
        return 1
    fi

    # pgAdmin accessibility
    if curl -s -I http://"$TOWER_IP":30080 2>/dev/null | grep -q "302\|200"; then
        if [ "${QUIET_MODE:-false}" = false ]; then
            success "pgAdmin: Accessible"
        fi
    else
        if [ "${QUIET_MODE:-false}" = false ]; then
            error "pgAdmin: Not accessible"
        fi
        return 1
    fi

    return 0
}

# Recovery functions
restart_failed_pods() {
    log "Attempting to restart failed pods..."
    sudo kubectl --kubeconfig="$KUBECONFIG" delete pods --field-selector=status.phase!=Running --ignore-not-found=true
    sleep 10
}

redeploy_applications() {
    log "Redeploying applications..."
    cd /home/sanjay/containers/kubernetes

    # Clean up old deployments
    sudo kubectl --kubeconfig="$KUBECONFIG" delete deployment --all -n default --ignore-not-found=true
    sudo kubectl --kubeconfig="$KUBECONFIG" delete pods --all --force --grace-period=0 -n default --ignore-not-found=true
    sleep 5

    # Redeploy applications
    sed "s/localhost:5000/$TOWER_IP:5000/g" server/postgres/postgres-db-deployment.yaml | sed "s/\$POSTGRES_PASSWORD/postgres/g" | sudo kubectl --kubeconfig="$KUBECONFIG" apply -f -
    sudo kubectl --kubeconfig="$KUBECONFIG" apply -f server/postgres-pgadmin-nodeport-services.yaml

    sed "s/localhost:5000/$TOWER_IP:5000/g" server/pgadmin/pgadmin-deployment.yaml | sudo kubectl --kubeconfig="$KUBECONFIG" apply -f -

    # Deploy FastAPI
    sudo kubectl --kubeconfig="$KUBECONFIG" apply -f fastapi-deployment-full.yaml
}

# Main functions
health_check() {
    # Check if quiet mode is requested (for automation script integration)
    if [ "${1:-}" = "quiet" ]; then
        QUIET_MODE=true
    else
        QUIET_MODE=false
    fi

    # Export QUIET_MODE immediately so all functions can see it
    export QUIET_MODE

    local issues=0

    if ! check_nodes; then ((issues++)); fi
    if ! check_pods; then ((issues++)); fi
    if ! check_services; then ((issues++)); fi

    if [ $issues -eq 0 ]; then
        return 0
    else
        return 1
    fi
}

auto_recover() {
    log "=== AUTO RECOVERY ATTEMPT ==="

    if ! health_check; then
        warning "Issues detected, attempting recovery..."

        restart_failed_pods
        sleep 10

        if ! health_check; then
            warning "Pod restart insufficient, redeploying applications..."
            redeploy_applications
            sleep 30

            if health_check; then
                success "Recovery successful!"
            else
                error "Recovery failed. Manual intervention required."
                return 1
            fi
        fi
    fi

    return 0
}

backup_environment() {
    log "=== ENVIRONMENT BACKUP ==="
    local backup_dir="/home/sanjay/containers/kubernetes/backup/$(date +%Y%m%d_%H%M%S)"

    mkdir -p "$backup_dir"

    # Backup configurations
    cp k3s-config.sh "$backup_dir/"
    cp -r server/ "$backup_dir/"

    # Backup current state
    sudo kubectl --kubeconfig="$KUBECONFIG" get all -o yaml > "$backup_dir/cluster-state.yaml"
    sudo kubectl --kubeconfig="$KUBECONFIG" get pods -o wide > "$backup_dir/pods-status.txt"

    success "Environment backed up to: $backup_dir"
    echo "$backup_dir"
}

show_status() {
    echo "=== K3s ENVIRONMENT STATUS ==="
    echo "Date: $(date)"
    echo ""

    echo "CLUSTER NODES:"
    sudo kubectl --kubeconfig="$KUBECONFIG" get nodes -o wide 2>/dev/null || echo "Cannot connect to cluster"
    echo ""

    echo "APPLICATION PODS:"
    sudo kubectl --kubeconfig="$KUBECONFIG" get pods -o wide 2>/dev/null || echo "Cannot get pod status"
    echo ""

    echo "SERVICE ACCESSIBILITY:"
    echo "FastAPI:  http://$TOWER_IP:30002/health"
    echo "pgAdmin:  http://$TOWER_IP:30080"
    echo "PostgreSQL: $TOWER_IP:30432"
    echo ""

    echo "QUICK TESTS:"
    if curl -s -f http://"$TOWER_IP":30002/health >/dev/null 2>&1; then
        echo "✅ FastAPI: OK"
    else
        echo "❌ FastAPI: FAIL"
    fi

    if curl -s -I http://"$TOWER_IP":30080 2>/dev/null | grep -q "302\|200"; then
        echo "✅ pgAdmin: OK"
    else
        echo "❌ pgAdmin: FAIL"
    fi
}

# Main menu
case "${1:-status}" in
    "check"|"health")
        health_check
        ;;
    "recover"|"fix")
        auto_recover
        ;;
    "backup")
        backup_environment
        ;;
    "status")
        show_status
        ;;
    "monitor")
        echo "Starting continuous monitoring (Ctrl+C to stop)..."
        while true; do
            clear
            show_status
            echo ""
            echo "Next check in 30 seconds... (Ctrl+C to stop)"
            sleep 30
        done
        ;;
    *)
        echo "Usage: $0 {status|check|recover|backup|monitor}"
        echo ""
        echo "Commands:"
        echo "  status   - Show current environment status"
        echo "  check    - Run health checks"
        echo "  recover  - Attempt automatic recovery"
        echo "  backup   - Create environment backup"
        echo "  monitor  - Continuous monitoring mode"
        exit 1
        ;;
esac