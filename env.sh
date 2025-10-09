#!/bin/bash
# Quick Environment Manager
# Simple commands for stable environment management

STABILITY_SCRIPT="/home/sanjay/containers/kubernetes/stability-manager.sh"
AUTOMATION_SCRIPT="/home/sanjay/containers/kubernetes/k3s-setup-automation.sh"

case "${1:-help}" in
    "status")
        "$STABILITY_SCRIPT" status
        ;;
    "check")
        "$STABILITY_SCRIPT" check
        ;;
    "fix")
        echo "Attempting to fix environment issues..."
        "$STABILITY_SCRIPT" recover
        ;;
    "backup")
        echo "Creating environment backup..."
        "$STABILITY_SCRIPT" backup
        ;;
    "reset")
        echo "⚠️  WARNING: This will reset the entire environment!"
        read -p "Are you sure? (yes/no): " confirm
        if [ "$confirm" = "yes" ]; then
            echo "Resetting environment..."
            "$AUTOMATION_SCRIPT"
        else
            echo "Reset cancelled."
        fi
        ;;
    "monitor")
        echo "Starting background monitoring..."
        nohup "$STABILITY_SCRIPT" monitor &
        echo "Monitor started. Use 'pkill -f monitor' to stop."
        ;;
    "stop-monitor")
        pkill -f "stability-manager.sh monitor"
        echo "Monitor stopped."
        ;;
    "help"|*)
        echo "K3s Environment Quick Manager"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  status       - Show current environment status"
        echo "  check        - Run health checks"
        echo "  fix          - Attempt automatic recovery"
        echo "  backup       - Create environment backup"
        echo "  reset        - Full environment reset (WARNING: destructive)"
        echo "  monitor      - Start background monitoring"
        echo "  stop-monitor - Stop background monitoring"
        echo "  help         - Show this help"
        echo ""
        echo "Examples:"
        echo "  $0 status    # Quick status overview"
        echo "  $0 check     # Health check"
        echo "  $0 fix       # Auto-recover issues"
        ;;
esac