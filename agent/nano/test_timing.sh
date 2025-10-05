#!/bin/bash

# Test script to demonstrate single-line timing updates
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo "Testing single-line timing updates..."
echo -e -n "${YELLOW}  🚀 Starting pod... 00:00${NC}"

PHASE="starting"
PHASE_START_TIME=$(date +%s)
LAST_ELAPSED_STR=""

for i in {1..10}; do
    sleep 3  # Simulate 3-second intervals
    
    # Update elapsed time display every 30 seconds (every 3 iterations since we check every 10s)
    if [ $((i % 1)) -eq 0 ]; then  # Changed to every iteration for demo
        CURRENT_TIME=$(date +%s)
        ELAPSED=$((CURRENT_TIME - PHASE_START_TIME))
        ELAPSED_MIN=$((ELAPSED / 60))
        ELAPSED_SEC=$((ELAPSED % 60))
        ELAPSED_STR=$(printf "%02d:%02d" $ELAPSED_MIN $ELAPSED_SEC)
        
        # Only print if timing has actually changed
        if [ "$ELAPSED_STR" != "$LAST_ELAPSED_STR" ]; then
            echo -e -n "\r${YELLOW}  🚀 Starting pod... ${ELAPSED_STR}${NC}"
            LAST_ELAPSED_STR="$ELAPSED_STR"
        fi
    fi
done

# Simulate phase completion
echo -e "\r${GREEN}  🚀 Starting pod... 00:30 ✅${NC}"
echo -e "${BLUE}  📥 Downloading image... 00:00${NC}"

echo "Demo complete!"
