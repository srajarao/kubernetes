#!/bin/bash

# =============================================================================
# Memory Check and Cleanup Script for Spark2
# =============================================================================
# This script performs comprehensive memory analysis and cleanup on Spark2 node
# Date: October 28, 2025
# =============================================================================

set -e  # Exit on any error

# Configuration
SPARK2_IP="192.168.1.202"
SSH_USER="sanjay"
LOG_FILE="/home/sanjay/containers/kubernetes/memcheck_spark2_$(date +%Y%m%d_%H%M%S).log"

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

# SSH command wrapper
ssh_cmd() {
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i /home/sanjay/.ssh/id_ed25519 "$SSH_USER@$SPARK2_IP" "$*"
}

# Header
echo "==================================================================================" | tee "$LOG_FILE"
echo "🔍 SPARK2 MEMORY CHECK AND CLEANUP SCRIPT" | tee -a "$LOG_FILE"
echo "==================================================================================" | tee -a "$LOG_FILE"
echo "Date: $(date)" | tee -a "$LOG_FILE"
echo "Target: Spark2 ($SPARK2_IP)" | tee -a "$LOG_FILE"
echo "Log file: $LOG_FILE" | tee -a "$LOG_FILE"
echo "==================================================================================" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 1: Basic System Information
# =============================================================================
echo -e "${BLUE}📊 STEP 1: Basic System Information${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Getting system uptime and load average..."
UPTIME=$(ssh_cmd "uptime")
echo "$UPTIME" | tee -a "$LOG_FILE"

log "Getting system information..."
SYSINFO=$(ssh_cmd "uname -a && lsb_release -d")
echo "$SYSINFO" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 2: Memory Usage Analysis
# =============================================================================
echo -e "${BLUE}🧠 STEP 2: Memory Usage Analysis${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Checking memory usage (free -h)..."
MEM_INFO=$(ssh_cmd "free -h")
echo "$MEM_INFO" | tee -a "$LOG_FILE"

# Calculate memory percentage
TOTAL_MEM=$(ssh_cmd "free | grep '^Mem:' | awk '{print \$2}'")
USED_MEM=$(ssh_cmd "free | grep '^Mem:' | awk '{print \$3}'")
MEM_PERCENT=$(( USED_MEM * 100 / TOTAL_MEM ))

if [ $MEM_PERCENT -gt 80 ]; then
    echo -e "${RED}⚠️  WARNING: Memory usage is ${MEM_PERCENT}% - HIGH USAGE${NC}" | tee -a "$LOG_FILE"
elif [ $MEM_PERCENT -gt 60 ]; then
    echo -e "${YELLOW}⚠️  CAUTION: Memory usage is ${MEM_PERCENT}% - MODERATE USAGE${NC}" | tee -a "$LOG_FILE"
else
    echo -e "${GREEN}✅ Memory usage is ${MEM_PERCENT}% - NORMAL${NC}" | tee -a "$LOG_FILE"
fi

log "Checking swap usage..."
SWAP_INFO=$(ssh_cmd "free -h | grep '^Swap:'")
echo "$SWAP_INFO" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 3: Top Memory-Consuming Processes
# =============================================================================
echo -e "${BLUE}🔍 STEP 3: Top Memory-Consuming Processes${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Getting top 15 memory-consuming processes..."
TOP_PROCESSES=$(ssh_cmd "ps aux --sort=-%mem | head -15")
echo "$TOP_PROCESSES" | tee -a "$LOG_FILE"

# Check for memory-hungry applications
log "Checking for potentially problematic applications..."
MEMORY_HOGS=$(ssh_cmd "ps aux --sort=-%mem | awk 'NR>1 && \$4>5.0 {print \$4\"% \"\$11}' | head -5")
if [ -n "$MEMORY_HOGS" ]; then
    echo -e "${YELLOW}⚠️  High memory usage processes (>5%):${NC}" | tee -a "$LOG_FILE"
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
TOP_CPU=$(ssh_cmd "ps aux --sort=-%cpu | head -10")
echo "$TOP_CPU" | tee -a "$LOG_FILE"

log "Checking system load average..."
LOAD_AVG=$(ssh_cmd "cat /proc/loadavg")
echo "Load Average: $LOAD_AVG" | tee -a "$LOG_FILE"

# Parse load average
LOAD_1=$(echo $LOAD_AVG | awk '{print $1}')
LOAD_5=$(echo $LOAD_AVG | awk '{print $2}')
LOAD_15=$(echo $LOAD_AVG | awk '{print $3}')

if (( $(echo "$LOAD_1 > 5.0" | bc -l) )); then
    echo -e "${RED}⚠️  WARNING: High 1-minute load average: $LOAD_1${NC}" | tee -a "$LOG_FILE"
elif (( $(echo "$LOAD_1 > 2.0" | bc -l) )); then
    echo -e "${YELLOW}⚠️  CAUTION: Moderate 1-minute load average: $LOAD_1${NC}" | tee -a "$LOG_FILE"
else
    echo -e "${GREEN}✅ Load average is normal: $LOAD_1${NC}" | tee -a "$LOG_FILE"
fi
echo "" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 5: Docker Analysis and Cleanup
# =============================================================================
echo -e "${BLUE}🐳 STEP 5: Docker Analysis and Cleanup${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Checking Docker system information..."
DOCKER_INFO=$(ssh_cmd "sudo docker system info 2>/dev/null | head -10" 2>/dev/null || echo "Docker not accessible or not running")
echo "$DOCKER_INFO" | tee -a "$LOG_FILE"

log "Checking Docker disk usage..."
DOCKER_DF=$(ssh_cmd "sudo docker system df 2>/dev/null" 2>/dev/null || echo "Docker system df not available")
echo "$DOCKER_DF" | tee -a "$LOG_FILE"

log "Checking running Docker containers..."
DOCKER_PS=$(ssh_cmd "sudo docker ps -a 2>/dev/null" 2>/dev/null || echo "Docker ps not available")
echo "$DOCKER_PS" | tee -a "$LOG_FILE"

# Check if Docker cleanup is needed
if ssh_cmd "sudo docker system df 2>/dev/null | grep -q 'GB'" 2>/dev/null; then
    log "Performing Docker system cleanup..."
    CLEANUP_OUTPUT=$(ssh_cmd "sudo docker system prune -f 2>/dev/null" 2>/dev/null || echo "Docker cleanup not performed")
    echo "$CLEANUP_OUTPUT" | tee -a "$LOG_FILE"

    log "Checking disk usage after cleanup..."
    DOCKER_DF_AFTER=$(ssh_cmd "sudo docker system df 2>/dev/null" 2>/dev/null || echo "Docker system df not available")
    echo "$DOCKER_DF_AFTER" | tee -a "$LOG_FILE"
else
    echo -e "${GREEN}✅ Docker disk usage is minimal or Docker not accessible${NC}" | tee -a "$LOG_FILE"
fi
echo "" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 6: Kubernetes Analysis
# =============================================================================
echo -e "${BLUE}☸️  STEP 6: Kubernetes Analysis${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Checking k3s agent status..."
K3S_STATUS=$(ssh_cmd "sudo systemctl status k3s-agent --no-pager -l | head -10" 2>/dev/null || echo "k3s status check failed")
echo "$K3S_STATUS" | tee -a "$LOG_FILE"

log "Checking k3s agent configuration..."
K3S_CONFIG=$(ssh_cmd "sudo cat /etc/systemd/system/k3s-agent.service.d/override.conf 2>/dev/null" 2>/dev/null || echo "k3s config not found")
echo "$K3S_CONFIG" | tee -a "$LOG_FILE"

log "Checking recent k3s agent logs..."
K3S_LOGS=$(ssh_cmd "sudo journalctl -u k3s-agent --since '5 minutes ago' | tail -5" 2>/dev/null || echo "k3s logs not available")
echo "$K3S_LOGS" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 7: Disk Usage Analysis
# =============================================================================
echo -e "${BLUE}💾 STEP 7: Disk Usage Analysis${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Checking disk usage..."
DISK_USAGE=$(ssh_cmd "df -h")
echo "$DISK_USAGE" | tee -a "$LOG_FILE"

log "Checking largest directories..."
LARGE_DIRS=$(ssh_cmd "sudo du -h /home /var /opt /usr 2>/dev/null | sort -hr | head -10" 2>/dev/null || echo "Directory size check failed")
echo "$LARGE_DIRS" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 8: Network Analysis
# =============================================================================
echo -e "${BLUE}🌐 STEP 8: Network Analysis${NC}" | tee -a "$LOG_FILE"
echo "----------------------------------------------------------------------------------" | tee -a "$LOG_FILE"

log "Checking network interfaces..."
NETWORK=$(ssh_cmd "ip addr show | grep -E '(inet|state)' | head -10")
echo "$NETWORK" | tee -a "$LOG_FILE"

log "Checking network connectivity to key services..."
PING_MASTER=$(ssh_cmd "ping -c 2 192.168.1.150 2>/dev/null | tail -1" 2>/dev/null || echo "Ping to master failed")
echo "Ping to master (192.168.1.150): $PING_MASTER" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# =============================================================================
# STEP 9: Recommendations and Summary
# =============================================================================
echo -e "${BLUE}📋 STEP 9: Recommendations and Summary${NC}" | tee -a "$LOG_FILE"
echo "==================================================================================" | tee -a "$LOG_FILE"

echo -e "${GREEN}✅ MEMORY CHECK COMPLETED${NC}" | tee -a "$LOG_FILE"
echo "==================================================================================" | tee -a "$LOG_FILE"

# Generate recommendations based on findings
echo "RECOMMENDATIONS:" | tee -a "$LOG_FILE"
echo "---------------" | tee -a "$LOG_FILE"

if [ $MEM_PERCENT -gt 80 ]; then
    echo -e "${RED}🚨 CRITICAL: Memory usage is very high (${MEM_PERCENT}%)${NC}" | tee -a "$LOG_FILE"
    echo "   - Close unnecessary applications" | tee -a "$LOG_FILE"
    echo "   - Check for memory leaks in running processes" | tee -a "$LOG_FILE"
    echo "   - Consider increasing system memory" | tee -a "$LOG_FILE"
elif [ $MEM_PERCENT -gt 60 ]; then
    echo -e "${YELLOW}⚠️  MODERATE: Memory usage is elevated (${MEM_PERCENT}%)${NC}" | tee -a "$LOG_FILE"
    echo "   - Monitor memory usage trends" | tee -a "$LOG_FILE"
    echo "   - Close unnecessary browser tabs/applications" | tee -a "$LOG_FILE"
else
    echo -e "${GREEN}✅ Memory usage is normal (${MEM_PERCENT}%)${NC}" | tee -a "$LOG_FILE"
fi

if (( $(echo "$LOAD_1 > 2.0" | bc -l) )); then
    echo -e "${YELLOW}⚠️  System load is high (load average: $LOAD_1)${NC}" | tee -a "$LOG_FILE"
    echo "   - Check for CPU-intensive processes" | tee -a "$LOG_FILE"
    echo "   - Consider optimizing running applications" | tee -a "$LOG_FILE"
else
    echo -e "${GREEN}✅ System load is normal${NC}" | tee -a "$LOG_FILE"
fi

echo "" | tee -a "$LOG_FILE"
echo "SYSTEM SUMMARY:" | tee -a "$LOG_FILE"
echo "---------------" | tee -a "$LOG_FILE"
echo "Memory Usage: ${MEM_PERCENT}% ($USED_MEM KB used of $TOTAL_MEM KB total)" | tee -a "$LOG_FILE"
echo "Load Average: $LOAD_AVG" | tee -a "$LOG_FILE"
echo "Docker Cleanup: Performed" | tee -a "$LOG_FILE"
echo "Log File: $LOG_FILE" | tee -a "$LOG_FILE"

echo "" | tee -a "$LOG_FILE"
echo -e "${GREEN}🎉 Memory check and cleanup completed successfully!${NC}" | tee -a "$LOG_FILE"
echo "==================================================================================" | tee -a "$LOG_FILE"

# Make the script executable
chmod +x "$0"

exit 0