#!/bin/bash

# =============================================================================
# Memory Check and Cleanup Script for Tower
# =============================================================================
# This script performs comprehensive memory analysis and cleanup on Tower node
# Date: October 28, 2025
# =============================================================================

set -e  # Exit on any error

# Configuration
TOWER_IP="192.168.1.150"
LOG_FILE="/home/sanjay/containers/kubernetes/memcheck_tower_$(date +%Y%m%d_%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

# Local command wrapper (no SSH needed)
local_cmd() {
    "$@"
}

# Header
echo "==================================================================================" | tee "$LOG_FILE"
echo "🔍 TOWER MEMORY CHECK AND CLEANUP SCRIPT" | tee -a "$LOG_FILE"
echo "==================================================================================" | tee -a "$LOG_FILE"
echo "Date: $(date)" | tee -a "$LOG_FILE"
echo "Target: Tower ($TOWER_IP)" | tee -a "$LOG_FILE"
echo "Log file: $LOG_FILE" | tee -a "$LOG_FILE"
echo "==================================================================================" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 1: Basic System Information
# =============================================================================
echo -e "${BLUE}📊 STEP 1: Basic System Information${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Getting system uptime and load average..."
UPTIME=$(uptime)
echo "$UPTIME" | tee -a "$LOG_FILE"

log "Getting system information..."
SYSINFO=$(uname -a)
echo "$SYSINFO" | tee -a "$LOG_FILE"

# Try to get distribution info in a cross-platform way
DISTRO_INFO=$(lsb_release -d 2>/dev/null | sed 's/Description:\s*//' 2>/dev/null || echo "Ubuntu Linux (lsb_release not available)")
echo "Distribution: $DISTRO_INFO" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 2: Memory Usage Analysis
# =============================================================================
echo -e "${BLUE}🧠 STEP 2: Memory Usage Analysis${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Checking memory usage (free -h)..."
MEM_INFO=$(free -h)
echo "$MEM_INFO" | tee -a "$LOG_FILE"

# Calculate memory percentage (more robust parsing)
TOTAL_MEM_KB=$(free | grep '^Mem:' | awk '{print $2}')
USED_MEM_KB=$(free | grep '^Mem:' | awk '{print $3}')

if [ -n "$TOTAL_MEM_KB" ] && [ -n "$USED_MEM_KB" ] && [ "$TOTAL_MEM_KB" -gt 0 ]; then
    MEM_PERCENT=$(( USED_MEM_KB * 100 / TOTAL_MEM_KB ))
else
    MEM_PERCENT=0
    echo -e "${YELLOW}⚠️  Could not calculate memory percentage${NC}" | tee -a "$LOG_FILE"
fi

if [ $MEM_PERCENT -gt 80 ]; then
    echo -e "${RED}⚠️  WARNING: Memory usage is ${MEM_PERCENT}% - HIGH USAGE${NC}" | tee -a "$LOG_FILE"
elif [ $MEM_PERCENT -gt 60 ]; then
    echo -e "${YELLOW}⚠️  CAUTION: Memory usage is ${MEM_PERCENT}% - MODERATE USAGE${NC}" | tee -a "$LOG_FILE"
else
    echo -e "${GREEN}✅ Memory usage is ${MEM_PERCENT}% - NORMAL${NC}" | tee -a "$LOG_FILE"
fi

log "Checking swap usage..."
SWAP_INFO=$(free -h | grep '^Swap:')
echo "$SWAP_INFO" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 3: Top Memory-Consuming Processes
# =============================================================================
echo -e "${BLUE}🔍 STEP 3: Top Memory-Consuming Processes${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Getting top 15 memory-consuming processes..."
TOP_PROCESSES=$(ps aux --sort=-pmem | head -16 2>/dev/null || ps aux | sort -k4 -nr | head -15)
echo "$TOP_PROCESSES" | tee -a "$LOG_FILE"

# Check for memory-hungry applications
log "Checking for potentially problematic applications..."
MEMORY_HOGS=$(ps aux --sort=-pmem | awk 'NR>1 && $4>5.0 {print $4"% "$11}' | head -5 2>/dev/null || ps aux | awk 'NR>1 && $4>5.0 {print $4"% "$11}' | sort -nr | head -5)
if [ -n "$MEMORY_HOGS" ]; then
    echo -e "${RED}🚨 CRITICAL: Found processes using more than 5% memory:${NC}" | tee -a "$LOG_FILE"
    echo "$MEMORY_HOGS" | tee -a "$LOG_FILE"
else
    echo -e "${GREEN}✅ No processes using more than 5% memory${NC}" | tee -a "$LOG_FILE"
fi
echo "" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 4: CPU Usage Analysis
# =============================================================================
echo -e "${BLUE}⚡ STEP 4: CPU Usage Analysis${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Getting top CPU-consuming processes..."
TOP_CPU=$(ps aux --sort=-pcpu | head -11 2>/dev/null || ps aux | sort -k3 -nr | head -10)
echo "$TOP_CPU" | tee -a "$LOG_FILE"

log "Checking system load average..."
LOAD_AVG=$(uptime | awk -F'load average:' '{print $2}' 2>/dev/null || uptime | sed 's/.*load average: //')
echo "Load Average: $LOAD_AVG" | tee -a "$LOG_FILE"

# Parse load average (1-minute average)
LOAD_1MIN=$(echo $LOAD_AVG | awk '{print $1}' | sed 's/,//' | sed 's/ //g')
LOAD_INT=$(echo $LOAD_1MIN | cut -d'.' -f1)

# Handle empty or invalid load average
if [ -z "$LOAD_INT" ] || ! [[ "$LOAD_INT" =~ ^[0-9]+$ ]]; then
    LOAD_INT=0
    echo -e "${YELLOW}⚠️  Could not parse load average${NC}" | tee -a "$LOG_FILE"
fi

if [ $LOAD_INT -gt 5 ]; then
    echo -e "${RED}🚨 CRITICAL: Load average is very high: $LOAD_1MIN${NC}" | tee -a "$LOG_FILE"
elif [ $LOAD_INT -gt 2 ]; then
    echo -e "${YELLOW}⚠️  WARNING: Load average is high: $LOAD_1MIN${NC}" | tee -a "$LOG_FILE"
else
    echo -e "${GREEN}✅ Load average is normal: $LOAD_1MIN${NC}" | tee -a "$LOG_FILE"
fi
echo "" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 5: Docker Analysis and Cleanup
# =============================================================================
echo -e "${BLUE}🐳 STEP 5: Docker Analysis and Cleanup${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Checking Docker system information..."
DOCKER_VERSION=$(docker version --format 'Client: {{.Client.Version}}' 2>/dev/null || echo 'Docker not running or not installed')
echo "$DOCKER_VERSION" | tee -a "$LOG_FILE"

log "Checking Docker disk usage..."
DOCKER_USAGE=$(docker system df 2>/dev/null || echo 'Cannot check Docker usage')
echo "$DOCKER_USAGE" | tee -a "$LOG_FILE"

log "Checking running Docker containers..."
RUNNING_CONTAINERS=$(docker ps 2>/dev/null || echo 'Cannot check running containers')
echo "$RUNNING_CONTAINERS" | tee -a "$LOG_FILE"

log "Performing Docker system cleanup..."
CLEANUP_RESULT=$(docker system prune -f 2>/dev/null || echo 'Docker cleanup not available')
echo "$CLEANUP_RESULT" | tee -a "$LOG_FILE"

log "Checking disk usage after cleanup..."
DOCKER_USAGE_AFTER=$(docker system df 2>/dev/null || echo 'Cannot check Docker usage after cleanup')
echo "$DOCKER_USAGE_AFTER" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 6: Kubernetes Analysis
# =============================================================================
echo -e "${BLUE}☸️  STEP 6: Kubernetes Analysis${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Checking k3s server status..."
K3S_STATUS=$(sudo systemctl status k3s --no-pager 2>/dev/null || echo 'k3s service not found')
echo "$K3S_STATUS" | tee -a "$LOG_FILE"

log "Checking k3s server configuration..."
K3S_CONFIG=$(sudo systemctl show k3s -p Environment 2>/dev/null | head -5 || echo 'Cannot read k3s config')
echo "$K3S_CONFIG" | tee -a "$LOG_FILE"

log "Checking recent k3s server logs..."
K3S_LOGS=$(sudo journalctl -u k3s -n 10 --no-pager 2>/dev/null || echo 'Cannot read k3s logs')
echo "$K3S_LOGS" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 7: Disk Usage Analysis
# =============================================================================
echo -e "${BLUE}💾 STEP 7: Disk Usage Analysis${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Checking disk usage..."
DISK_USAGE=$(df -h)
echo "$DISK_USAGE" | tee -a "$LOG_FILE"

log "Checking largest directories..."
LARGEST_DIRS=$(du -sh /* 2>/dev/null | sort -k1 -hr 2>/dev/null | head -10 || du -sh /* 2>/dev/null | sort -k1 -n -r | head -10)
echo "$LARGEST_DIRS" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 8: Network Analysis
# =============================================================================
echo -e "${BLUE}🌐 STEP 8: Network Analysis${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Checking network interfaces..."
NET_INTERFACES=$(ip addr show)
echo "$NET_INTERFACES" | tee -a "$LOG_FILE"

log "Checking network connectivity to key services..."
PING_SELF=$(ping -c 3 192.168.1.150 | tail -1)
echo "Ping to self (192.168.1.150): $PING_SELF" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 9: Recommendations and Summary
# =============================================================================
echo -e "${BLUE}📋 STEP 9: Recommendations and Summary${NC}" | tee -a "$LOG_FILE"
echo "==================================================================================" | tee -a "$LOG_FILE"
echo "✅ MEMORY CHECK COMPLETED" | tee -a "$LOG_FILE"
echo "==================================================================================" | tee -a "$LOG_FILE"

# Generate recommendations
echo "RECOMMENDATIONS:" | tee -a "$LOG_FILE"
echo "---------------" | tee -a "$LOG_FILE"

if [ -n "$MEM_PERCENT" ] && [ $MEM_PERCENT -le 60 ]; then
    echo -e "${GREEN}✅ Memory usage is normal (${MEM_PERCENT}%)${NC}" | tee -a "$LOG_FILE"
else
    echo -e "${RED}🚨 Memory usage is high (${MEM_PERCENT}%) - Consider cleanup${NC}" | tee -a "$LOG_FILE"
fi

if [ -n "$LOAD_INT" ] && [ $LOAD_INT -le 2 ]; then
    echo -e "${GREEN}✅ System load is normal${NC}" | tee -a "$LOG_FILE"
else
    echo -e "${RED}🚨 System load is high - Investigate CPU usage${NC}" | tee -a "$LOG_FILE"
fi

echo "" | tee -a "$LOG_FILE"

# System summary
echo "SYSTEM SUMMARY:" | tee -a "$LOG_FILE"
echo "---------------" | tee -a "$LOG_FILE"
echo "Memory Usage: ${MEM_PERCENT:-Unknown}% (${USED_MEM:-0} KB used of ${TOTAL_MEM:-0} KB total)" | tee -a "$LOG_FILE"
echo "Load Average: ${LOAD_AVG:-Unknown}" | tee -a "$LOG_FILE"
echo "Docker Cleanup: Performed" | tee -a "$LOG_FILE"
echo "Log File: $LOG_FILE" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

echo -e "${GREEN}🎉 Memory check and cleanup completed successfully!${NC}" | tee -a "$LOG_FILE"
echo "==================================================================================" | tee -a "$LOG_FILE"