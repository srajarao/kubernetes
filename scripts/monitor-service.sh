#!/bin/bash
# Background Environment Monitor
# Runs continuous health checks and alerts on issues

MONITOR_LOG="/home/sanjay/containers/kubernetes/monitor.log"
STABILITY_SCRIPT="/home/sanjay/containers/kubernetes/stability-manager.sh"
ALERT_THRESHOLD=3  # Alert after 3 consecutive failures

consecutive_failures=0

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - MONITOR: $*" >> "$MONITOR_LOG"
}

alert() {
    local message="$1"
    log "ALERT: $message"

    # Send desktop notification if available
    if command -v notify-send >/dev/null 2>&1; then
        notify-send "K3s Environment Alert" "$message" --icon=dialog-warning
    fi

    # Could add email alerts here in the future
}

while true; do
    if "$STABILITY_SCRIPT" check >> "$MONITOR_LOG" 2>&1; then
        # Environment is healthy
        consecutive_failures=0
        log "Environment healthy"
    else
        # Environment has issues
        ((consecutive_failures++))
        log "Health check failed ($consecutive_failures/$ALERT_THRESHOLD)"

        if [ $consecutive_failures -ge $ALERT_THRESHOLD ]; then
            alert "Environment unstable for $consecutive_failures checks. Auto-recovery recommended."
            consecutive_failures=0  # Reset counter after alert
        fi
    fi

    # Check every 5 minutes
    sleep 300
done