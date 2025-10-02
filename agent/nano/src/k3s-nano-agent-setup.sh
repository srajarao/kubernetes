#!/bin/bash

# K3s Agent Setup Script for Nano
# Based on proven working AGX setup with nano-specific configurations
# This script sets up Nano as a k3s agent connected to the tower server

clear

# Setup colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'
TICK="${GREEN}✅${NC}"
CROSS="${RED}❌${NC}"

echo -e "${GREEN}Starting nano agent setup...${NC}\n"

# Source configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$(cd "$SCRIPT_DIR/../config" && pwd)"
NANO_ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
if [ -f "$CONFIG_DIR/nano-config.env" ]; then
    source "$CONFIG_DIR/nano-config.env"
    echo -e "${GREEN}Configuration loaded from nano-config.env${NC}"
    echo -e "  Tower IP: ${TOWER_IP}"
    echo -e "  Nano IP: ${NANO_IP}"
    echo -e "  Token Directory: ${TOKEN_DIR}"
    echo -e "  Project Directory: ${PROJECT_DIR}"
    echo -e "  Image Directory: ${IMAGE_DIR}"
fi

# Directories - will be overridden by nano-config.env if present
TOKEN_DIR="${TOKEN_DIR:-/mnt/vmstore/nano_home/containers/fastapi_nano/.token}"  # Nano: Read Token from server
PROJECT_DIR="${PROJECT_DIR:-/home/sanjay/containers/fastapi_nano}"              # Nano: Main project directory
IMAGE_DIR="${IMAGE_DIR:-/mnt/vmstore/nano_home/containers/fastapi_nano}"        # Nano: Save build images for server
TOWER_IP="${TOWER_IP:-192.168.5.1}"                                            # Tower server IP
NANO_IP="${NANO_IP:-192.168.5.21}"                                            # Nano device IP

# Debug flag - can be overridden by environment variable
DEBUG=${DEBUG:-0}

function debug_msg() {
    if [ "$DEBUG" -eq 1 ]; then
        echo -e "${GREEN}[DEBUG] $1${NC}"
    fi
}

function print_result() {
    local timestamp=$(date +"%H:%M:%S")
    if [ "$1" -eq 0 ]; then
        echo -e "[$timestamp] $2 $TICK"
        debug_msg "$2 succeeded"
    else
        echo -e "[$timestamp] $2 $CROSS"
        debug_msg "$2 failed"
    fi
}

function print_section() {
    local timestamp=$(date +"%H:%M:%S")
    echo -e "${GREEN}\n[$timestamp] == $1 ==${NC}"
}

function cleanup_k3s_agent_installation() {
    debug_msg "Running cleanup_k3s_agent_installation"
    print_section "Cleanup k3s Agent Installation"

    # Define the kubeconfig path for reliable kubectl access during cleanup
    KUBECONFIG_PATH="/home/sanjay/k3s.yaml"
    debug_msg "KUBECONFIG_PATH set to $KUBECONFIG_PATH"

    # Step 1: Quick deployment cleanup if kubectl is available (optional, will be cleaned anyway)
    if [ -f "$KUBECONFIG_PATH" ] && command -v kubectl >/dev/null 2>&1; then
        debug_msg "Quick deployment cleanup before uninstall"
        timeout 10s kubectl --kubeconfig="$KUBECONFIG_PATH" delete deployment fastapi-nano --ignore-not-found >/dev/null 2>&1
        print_result $? "  Quick deployment cleanup attempted"
    else
        debug_msg "Kubeconfig not found or kubectl not available, skipping pre-cleanup"
        print_result 0 "  No kubeconfig found, skipping pre-cleanup"
    fi

    # Step 2: Uninstall k3s agent first (this will clean up ALL pods automatically)
    debug_msg "Checking for k3s-agent-uninstall.sh"
    if [ -f "/usr/local/bin/k3s-agent-uninstall.sh" ]; then
        debug_msg "Found k3s-agent-uninstall.sh, running official uninstall"
        if [ "$DEBUG" -eq 1 ]; then
            echo -e "  Found k3s agent uninstall script, running official uninstall..."
            sudo /usr/local/bin/k3s-agent-uninstall.sh
        else
            sudo /usr/local/bin/k3s-agent-uninstall.sh >/dev/null 2>&1
        fi
        print_result $? "  Uninstalled k3s agent (all pods automatically cleaned)"
    else
        debug_msg "No k3s-agent-uninstall.sh found, performing manual cleanup"
        print_result 0 "  No official uninstall script found, performing manual cleanup"
    fi
    
    # Manual k3s agent cleanup (whether official script ran or not)
    debug_msg "Performing comprehensive k3s agent cleanup"
    echo -e "${GREEN}  Performing comprehensive k3s agent cleanup...${NC}"
    
    # Stop k3s-agent service
    if systemctl is-active --quiet k3s-agent 2>/dev/null; then
        debug_msg "Stopping k3s-agent service"
        sudo systemctl stop k3s-agent >/dev/null 2>&1
        print_result $? "  Stopped k3s-agent service"
    else
        print_result 0 "  k3s-agent service not running"
    fi
    
    # Disable k3s-agent service
    if systemctl is-enabled --quiet k3s-agent 2>/dev/null; then
        debug_msg "Disabling k3s-agent service"
        sudo systemctl disable k3s-agent >/dev/null 2>&1
        print_result $? "  Disabled k3s-agent service"
    else
        print_result 0 "  k3s-agent service not enabled"
    fi
    
    # Remove k3s binaries and files
    debug_msg "Removing k3s binaries and configuration files"
    sudo rm -f /usr/local/bin/k3s >/dev/null 2>&1
    sudo rm -f /usr/local/bin/kubectl >/dev/null 2>&1
    sudo rm -f /usr/local/bin/crictl >/dev/null 2>&1
    sudo rm -f /usr/local/bin/ctr >/dev/null 2>&1
    sudo rm -rf /etc/rancher/k3s >/dev/null 2>&1
    sudo rm -rf /var/lib/rancher/k3s >/dev/null 2>&1
    sudo rm -f /etc/systemd/system/k3s-agent.service >/dev/null 2>&1
    print_result 0 "  Removed k3s binaries and configuration files"
    
    # Reload systemd daemon
    debug_msg "Reloading systemd daemon"
    sudo systemctl daemon-reload >/dev/null 2>&1
    print_result $? "  Reloaded systemd daemon"
    
    # Remove stale kubeconfig files
    debug_msg "Removing stale kubeconfig files"
    rm -f /home/sanjay/k3s.yaml >/dev/null 2>&1
    rm -f ~/.kube/config >/dev/null 2>&1
    print_result $? "  Removed stale kubeconfig files"
}


function remove_dangling_docker_images() {
    debug_msg "Running remove_dangling_docker_images"
    echo -e "${GREEN}\n== Remove Dangling Docker Images ==${NC}"
    sudo docker image prune -f >/dev/null 2>&1
    print_result $? "  Removed dangling Docker images"
}

function get_file_mtime() {
    local file="$1"
    if [ -f "$file" ]; then
        # Try Linux stat first
        if stat -c %Y "$file" 2>/dev/null; then
            return 0
        # Try macOS stat
        elif stat -f %m "$file" 2>/dev/null; then
            return 0
        else
            echo "0"
            return 1
        fi
    else
        echo "0"
        return 1
    fi
}

function build_and_save_fastapi_image() {
    debug_msg "Running build_and_save_fastapi_image"
    print_section "Build and Save FastAPI Image"
    
    if [ ! -f "$NANO_ROOT_DIR/dockerfile.nano.req" ]; then
        debug_msg "Dockerfile not found"
        print_result 1 "  dockerfile.nano.req not found in $NANO_ROOT_DIR (skipping build)"
        return 1
    fi

    TAR_FILE="$IMAGE_DIR/fastapi_nano.tar"
    IMAGE_BUILT=false
    IMAGE_FROM_CACHE=false

    # Step 1: Check if Docker image exists
    if docker images fastapi_nano:latest | grep -q fastapi_nano; then
        debug_msg "Docker image already exists"
        print_result 0 "  fastapi_nano:latest image already available in Docker"
        IMAGE_FROM_CACHE=true
    else
        # Step 2: Docker image doesn't exist, check if we can build it
        debug_msg "Docker image not found, checking if build needed"
        DOCKERFILE_MTIME=$(get_file_mtime "$NANO_ROOT_DIR/dockerfile.nano.req")
        
        # Try to load from tar cache first if available and newer
        if [ -f "$TAR_FILE" ]; then
            TAR_MTIME=$(get_file_mtime "$TAR_FILE")
            if [ "$DOCKERFILE_MTIME" -le "$TAR_MTIME" ] 2>/dev/null; then
                debug_msg "Loading from tar cache"
                print_result 0 "  Loading fastapi_nano image from tar cache"
                docker load -i "$TAR_FILE" >/dev/null 2>&1
                if [ $? -eq 0 ]; then
                    print_result 0 "  Loaded fastapi_nano image from cache"
                    IMAGE_FROM_CACHE=true
                else
                    print_result 1 "  Failed to load from cache, will build"
                fi
            fi
        fi
        
        # If not loaded from cache, build the image
        if [ "$IMAGE_FROM_CACHE" = false ]; then
            debug_msg "Building image from Dockerfile"
            print_result 0 "  Building fastapi_nano image from Dockerfile"
            BUILD_OUTPUT=$(DOCKER_BUILDKIT=1 docker build -f "$NANO_ROOT_DIR/dockerfile.nano.req" -t fastapi_nano:latest "$NANO_ROOT_DIR" 2>&1)
            
            if echo "$BUILD_OUTPUT" | grep -q "Successfully built"; then
                if echo "$BUILD_OUTPUT" | grep -q "Using cache"; then
                    print_result 0 "  Built fastapi_nano:latest image (using Docker cache)"
                else
                    print_result 0 "  Built fastapi_nano:latest image from scratch"
                fi
                IMAGE_BUILT=true
            else
                print_result 1 "  Failed to build fastapi_nano:latest image"
                echo "$BUILD_OUTPUT"
                return 1
            fi
        fi
    fi

    # Step 3: Save tar image if needed
    if [ "$IMAGE_BUILT" = true ]; then
        # Image was built, save tar
        debug_msg "Saving newly built image to tar"
        mkdir -p "$IMAGE_DIR"
        docker save -o "$TAR_FILE" fastapi_nano:latest >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            chmod 644 "$TAR_FILE"
            print_result 0 "  Saved fastapi_nano image to tar backup"
        else
            print_result 1 "  Failed to save image to tar backup"
        fi
    elif [ "$IMAGE_FROM_CACHE" = true ] && [ ! -f "$TAR_FILE" ]; then
        # Image from cache but no tar exists, save tar
        debug_msg "Saving cached image to tar (tar missing)"
        mkdir -p "$IMAGE_DIR"
        docker save -o "$TAR_FILE" fastapi_nano:latest >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            chmod 644 "$TAR_FILE"
            print_result 0 "  Saved cached image to tar backup"
        else
            print_result 1 "  Failed to save cached image to tar"
        fi
    else
        print_result 0 "  Tar backup already exists, no save needed"
    fi

    # Step 4: Handle local registry upload
    if [ "$IMAGE_BUILT" = true ]; then
        # Image was built, push to registry
        debug_msg "Pushing newly built image to registry"
        docker tag fastapi_nano:latest ${TOWER_IP}:5000/fastapi_nano:latest
        print_result $? "  Tagged image for local registry"
        docker push ${TOWER_IP}:5000/fastapi_nano:latest >/dev/null 2>&1
        print_result $? "  Pushed new image to local registry ${TOWER_IP}:5000"
    else
        # Image not built, check if registry has it
        debug_msg "Checking if registry has image"
        if curl -s "http://${TOWER_IP}:5000/v2/fastapi_nano/manifests/latest" >/dev/null 2>&1; then
            print_result 0 "  Image already available in local registry"
        else
            # Registry doesn't have it, push from local
            debug_msg "Registry missing image, pushing from local"
            docker tag fastapi_nano:latest ${TOWER_IP}:5000/fastapi_nano:latest
            print_result $? "  Tagged image for local registry"
            docker push ${TOWER_IP}:5000/fastapi_nano:latest >/dev/null 2>&1
            print_result $? "  Pushed cached image to local registry ${TOWER_IP}:5000"
        fi
    fi
}

function check_certificate_trust() {
    debug_msg "Running check_certificate_trust"
    echo -e "\n${GREEN}Certificate Trust Checks${NC}"
    TOKEN_CERT="$TOKEN_DIR/server-ca.crt"
    debug_msg "TOKEN_CERT: $TOKEN_CERT"
    if [ -f "$TOKEN_CERT" ]; then
        debug_msg "Server CA cert found"
        print_result 0 "  Server CA cert found at $TOKEN_CERT"
    else
        debug_msg "Server CA cert not found"
        print_result 1 "  Server CA cert not found at $TOKEN_CERT"
    fi
    if [ "$DEBUG" -eq 1 ]; then
        debug_msg "Checking kubeconfig server entry"
        grep server ~/.kube/config >/dev/null 2>&1
        print_result $? "  kubeconfig server entry present"
        debug_msg "Testing API server certificate"
        openssl s_client -connect ${TOWER_IP}:6443 -showcerts </dev/null >/dev/null 2>&1
        print_result $? "  API server certificate presented"
    fi
}

function install_k3s_agent_with_token() {
    debug_msg "Running install_k3s_agent_with_token"
    print_section "Install k3s Agent with Token"
    TOKEN_FILE="$TOKEN_DIR/node-token"
    if [ -f "$TOKEN_FILE" ]; then
        # Ensure token file is readable
        if [ ! -r "$TOKEN_FILE" ]; then
            sudo chmod 644 "$TOKEN_FILE"
        fi
        if [ -r "$TOKEN_FILE" ]; then
            K3S_TOKEN=$(cat "$TOKEN_FILE")
        else
            K3S_TOKEN=$(sudo cat "$TOKEN_FILE")
        fi
        # Use server CA cert for agent trust
        TOKEN_CERT="$TOKEN_DIR/server-ca.crt"
        # Configure Insecure Registry via registries.yaml
        REGISTRY_IP="${TOWER_IP}:5000"
        print_section "Configure Insecure Registry (registries.yaml)"
        # 1. Create configuration directory
        sudo mkdir -p /etc/rancher/k3s/
        print_result $? "  Created /etc/rancher/k3s/ directory"
        # 2. Write registries.yaml to force HTTP for the local registry
        sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
mirrors:
    "$REGISTRY_IP":
        endpoint:
            - "http://$REGISTRY_IP"
        insecure: true
EOF
        print_result $? "  Created /etc/rancher/k3s/registries.yaml for HTTP registry access"
        # 3. Configure Docker daemon for insecure registry
        local docker_start=$(date +"%H:%M:%S")
        echo -e "${GREEN}[$docker_start]   Configuring Docker daemon for insecure registry...${NC}"
        if ! command -v jq >/dev/null 2>&1; then
            if [ "$DEBUG" -eq 1 ]; then
                echo -e "${YELLOW}  jq not found, installing...${NC}"
            fi
            sudo apt-get update && sudo apt-get install -y jq >/dev/null 2>&1
            print_result $? "  Installed jq"
        fi
        if [ -f /etc/docker/daemon.json ] && command -v jq >/dev/null 2>&1; then
            sudo jq 'if .["insecure-registries"] then .["insecure-registries"] += ["'${TOWER_IP}':5000"] | .["insecure-registries"] |= unique else . + {"insecure-registries": ["'${TOWER_IP}':5000"]} end' /etc/docker/daemon.json | sudo tee /etc/docker/daemon.json.tmp > /dev/null
            sudo mv /etc/docker/daemon.json.tmp /etc/docker/daemon.json
        else
            echo -e "${YELLOW}  jq not available or daemon.json missing, overwriting daemon.json...${NC}"
            echo '{"insecure-registries": ["'${TOWER_IP}':5000"]}' | sudo tee /etc/docker/daemon.json > /dev/null
        fi
        print_result $? "  Updated /etc/docker/daemon.json for insecure registry"
        if [ "$DEBUG" -eq 1 ]; then
            echo -e "${GREEN}  Current /etc/docker/daemon.json:${NC}"
            sudo cat /etc/docker/daemon.json
        fi
        sudo systemctl restart docker
        print_result $? "  Restarted Docker service"
        # Install k3s agent
        if [ -f "$TOKEN_CERT" ]; then
            local install_start=$(date +"%H:%M:%S")
            echo -e "${GREEN}[$install_start]   Installing k3s agent (this may take several minutes)...${NC}"
            K3S_URL="https://${TOWER_IP}:6443"
            NODE_IP="$NANO_IP"
            # Debug info
            if [ "$DEBUG" -eq 1 ]; then
                echo -e "\n${GREEN}== DEBUG: k3s agent install info ==${NC}"
                echo "  K3S_URL: $K3S_URL"
                echo "  K3S_TOKEN: (token hidden)"
                echo "  K3S_CA_FILE: $TOKEN_CERT"
                echo "  Node IP: $NODE_IP"
                echo "  Registry Configured At: /etc/rancher/k3s/registries.yaml"
                echo "  Install command: sudo curl -sfL https://get.k3s.io | K3S_URL=\"$K3S_URL\" K3S_TOKEN=\"$K3S_TOKEN\" K3S_CA_FILE=\"$TOKEN_CERT\" sh -s - agent --node-ip \"$NODE_IP\""
                echo -e "${GREEN}== Running k3s agent install... ==${NC}"
            fi
            # Execute install command
            if [ "$DEBUG" -eq 1 ]; then
                sudo curl -sfL https://get.k3s.io | K3S_URL="$K3S_URL" K3S_TOKEN="$K3S_TOKEN" K3S_CA_FILE="$TOKEN_CERT" sh -s - agent --node-ip "$NODE_IP"
            else
                sudo curl -sfL https://get.k3s.io | K3S_URL="$K3S_URL" K3S_TOKEN="$K3S_TOKEN" K3S_CA_FILE="$TOKEN_CERT" sh -s - agent --node-ip "$NODE_IP" >/dev/null 2>&1
            fi
            INSTALL_STATUS=$?
            print_result $INSTALL_STATUS "  Installed k3s-agent using token and CA cert"
            if [ $INSTALL_STATUS -ne 0 ]; then
                echo -e "${RED}ERROR: k3s agent install failed. Check above output for details.${NC}"
            else
                # Restart the service to load registries.yaml
                sudo systemctl restart k3s-agent
                print_result $? "  Restarted k3s-agent service to load registries.yaml"
            fi
        else
            print_result 1 "  Server CA cert not found at $TOKEN_CERT (cannot join cluster)"
            echo -e "${RED}ERROR: Server CA certificate missing. Agent cannot join cluster securely. Halting setup.${NC}"
            exit 2
        fi
        # Always copy latest kubeconfig to a known path for this script
        if [ -f "$TOKEN_DIR/k3s.yaml" ]; then
            mkdir -p "$(dirname "$KUBECONFIG_PATH")"
            cp "$TOKEN_DIR/k3s.yaml" "$KUBECONFIG_PATH"
            chmod 600 "$KUBECONFIG_PATH"
            print_result $? "  Updated kubeconfig at $KUBECONFIG_PATH"
            
            # Set k3s.yaml as default kubeconfig with safety checks
            debug_msg "Setting up default kubeconfig with validation"
            mkdir -p ~/.kube
            
            # Copy the k3s config to default location
            cp "$KUBECONFIG_PATH" ~/.kube/config
            chmod 600 ~/.kube/config
            COPY_STATUS=$?
            
            # Validate the copied config
            if [ $COPY_STATUS -eq 0 ] && [ -f ~/.kube/config ]; then
                # Check if the server URL is correct
                SERVER_URL=$(grep "server:" ~/.kube/config | head -1 | awk '{print $2}')
                debug_msg "Validating server URL: $SERVER_URL"
                
                if [[ "$SERVER_URL" == "https://${TOWER_IP}:6443" ]]; then
                    print_result 0 "  Set k3s kubeconfig as default (~/.kube/config)"
                    debug_msg "Server URL validation passed: $SERVER_URL"
                    
                    # Test kubectl connectivity with default config
                    debug_msg "Testing kubectl connectivity with default config"
                    if timeout 10s kubectl get nodes --request-timeout=5s >/dev/null 2>&1; then
                        print_result 0 "  Validated kubectl connectivity with default config"
                        CONFIG_VALID=true
                    else
                        print_result 1 "  Default config connectivity test failed"
                        CONFIG_VALID=false
                    fi
                else
                    print_result 1 "  Invalid server URL in default config: $SERVER_URL (expected: https://${TOWER_IP}:6443)"
                    CONFIG_VALID=false
                fi
            else
                print_result 1 "  Failed to copy k3s kubeconfig to default location"
                CONFIG_VALID=false
            fi
            
            # Set KUBECONFIG environment variable for current session
            export KUBECONFIG="$KUBECONFIG_PATH"
            print_result $? "  Set KUBECONFIG environment variable for current session"
            
            # Final validation message
            if [ "$CONFIG_VALID" = true ]; then
                debug_msg "Default kubeconfig setup completed successfully"
                print_result 0 "  Default kubeconfig validation: PASSED"
            else
                debug_msg "Default kubeconfig setup failed validation"
                print_result 1 "  Default kubeconfig validation: FAILED (use --kubeconfig=$KUBECONFIG_PATH)"
            fi
        else
            print_result 1 "  $TOKEN_DIR/k3s.yaml not found after install"
            echo -e "${RED}ERROR: Kubeconfig not found. Agent may not have joined the cluster. Halting setup.${NC}"
            exit 2
        fi
        # Import the FastAPI image into containerd ONLY if registry pull fails
        # Check if the image is available from registry first
        debug_msg "Checking if containerd already has the image"
        if sudo k3s ctr images list | grep -q "${TOWER_IP}:5000/fastapi_nano"; then
            debug_msg "Image already available in containerd, skipping import"
            print_result 0 "  FastAPI image already available in containerd"
        else
            debug_msg "Image not in containerd, checking registry availability"
            if curl -s "http://${TOWER_IP}:5000/v2/fastapi_nano/manifests/latest" >/dev/null 2>&1; then
                debug_msg "Image available in registry, k3s will pull automatically"
                print_result 0 "  FastAPI image available in registry (k3s will auto-pull)"
            elif [ -f "$IMAGE_DIR/fastapi_nano.tar" ]; then
                debug_msg "Registry unavailable, importing from tar backup"
                sudo k3s ctr images import "$IMAGE_DIR/fastapi_nano.tar" >/dev/null 2>&1
                print_result $? "  Imported fastapi_nano image into containerd from backup tar"
            else
                print_result 1 "  FastAPI image not available (no registry or tar backup)"
            fi
        fi
        # Note: Nano devices typically don't have NVIDIA GPUs
        echo -e "${GREEN}\n== Nano Device Notes ==${NC}"
        print_result 0 "  Nano setup complete (no GPU plugins needed)"
    else
        print_result 1 "  Token file not found at $TOKEN_FILE (skipping k3s-agent install)"
    fi
}

function apply_fastapi_deployment_yaml() {
    debug_msg "Running apply_fastapi_deployment_yaml"
    echo -e "${GREEN}\n== Apply FastAPI Deployment YAML ==${NC}"
    DEPLOYMENT_YAML="$CONFIG_DIR/start-fastapi-nano.yaml"
    debug_msg "DEPLOYMENT_YAML set to $DEPLOYMENT_YAML"
    if [ -f "$DEPLOYMENT_YAML" ]; then
        debug_msg "Deployment YAML found, applying with kubectl"
        timeout 30s kubectl --kubeconfig="$KUBECONFIG_PATH" apply -f "$DEPLOYMENT_YAML" >/dev/null 2>&1
        print_result $? "  Applied FastAPI deployment YAML: $DEPLOYMENT_YAML"
    else
        debug_msg "Deployment YAML not found, trying generic fastapi deployment"
        DEPLOYMENT_YAML="$CONFIG_DIR/start-fastapi.yaml"
        if [ -f "$DEPLOYMENT_YAML" ]; then
            timeout 30s kubectl --kubeconfig="$KUBECONFIG_PATH" apply -f "$DEPLOYMENT_YAML" >/dev/null 2>&1
            print_result $? "  Applied generic FastAPI deployment YAML: $DEPLOYMENT_YAML"
        else
            print_result 1 "  No deployment YAML found (skipping apply)"
        fi
    fi
}

function verify_node_ready() {
    debug_msg "Running verify_node_ready"
    echo -e "${GREEN}\n== Verify Node Ready Status ==${NC}"
    NODE_NAME=$(hostname)
    debug_msg "NODE_NAME set to $NODE_NAME"
    for i in {1..12}; do
        debug_msg "Checking node status, attempt $i"
        NODE_STATUS=$(timeout 10s kubectl --kubeconfig="$KUBECONFIG_PATH" get nodes --no-headers | grep "$NODE_NAME" | awk '{print $2}')
        debug_msg "NODE_STATUS: $NODE_STATUS"
        if [ "$NODE_STATUS" = "Ready" ]; then
            print_result 0 "  Node $NODE_NAME is Ready in the cluster"
            break
        fi
        sleep 5
    done
    if [ "$NODE_STATUS" != "Ready" ]; then
        debug_msg "Node not ready after 12 attempts"
        print_result 1 "  Node $NODE_NAME is not Ready (status: $NODE_STATUS)"
        timeout 10s kubectl --kubeconfig="$KUBECONFIG_PATH" describe node "$NODE_NAME"
    fi
}

function check_fastapi_pod_status() {
    debug_msg "Running check_fastapi_pod_status"
    echo -e "${GREEN}\n== Check FastAPI Pod Status ==${NC}"
    POD_NAME=$(timeout 10s kubectl --kubeconfig="$KUBECONFIG_PATH" get pods -l app=fastapi-nano -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    debug_msg "POD_NAME: $POD_NAME"
    if [ -z "$POD_NAME" ]; then
        debug_msg "No FastAPI nano pod found, trying generic fastapi"
        POD_NAME=$(timeout 10s kubectl --kubeconfig="$KUBECONFIG_PATH" get pods -l app=fastapi -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
        debug_msg "Generic POD_NAME: $POD_NAME"
    fi
    if [ -z "$POD_NAME" ]; then
        debug_msg "No FastAPI pod found"
        print_result 1 "  No FastAPI pod found after deployment"
    else
        STATUS=""
        MAX_RETRIES=18
        RETRY_COUNT=0
        while [ "$STATUS" != "Running" ] && [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
            debug_msg "Checking pod status, attempt $((RETRY_COUNT+1))"
            STATUS=$(timeout 5s kubectl --kubeconfig="$KUBECONFIG_PATH" get pod "$POD_NAME" -o jsonpath='{.status.phase}' 2>/dev/null)
            debug_msg "Pod status: $STATUS"
            if [ "$STATUS" == "Pending" ]; then
                REASON=$(timeout 5s kubectl --kubeconfig="$KUBECONFIG_PATH" get pod "$POD_NAME" -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null)
                debug_msg "Pending reason: $REASON"
                if [ "$REASON" == "ImagePullBackOff" ] || [ "$REASON" == "ErrImagePull" ]; then
                    echo -e "${RED}  Image Pull is failing, describing pod...${NC}"
                    timeout 10s kubectl --kubeconfig="$KUBECONFIG_PATH" describe pod "$POD_NAME"
                    print_result 1 "  FastAPI pod $POD_NAME is stuck in image pull error."
                    return
                fi
            fi
            if [ "$STATUS" = "Running" ]; then
                print_result 0 "  FastAPI pod $POD_NAME is Running"
                break
            fi
            echo -e "  Waiting for pod $POD_NAME to run... ($STATUS) (Retry: $((RETRY_COUNT+1))/$MAX_RETRIES)"
            sleep 3
            RETRY_COUNT=$((RETRY_COUNT+1))
        done
        if [ "$STATUS" != "Running" ]; then
            debug_msg "Pod not running after $MAX_RETRIES attempts"
            print_result 1 "  FastAPI pod $POD_NAME is not Running (status: $STATUS) after $((MAX_RETRIES * 3)) seconds."
            timeout 10s kubectl --kubeconfig="$KUBECONFIG_PATH" describe pod "$POD_NAME"
        fi
    fi
}

# Main execution
debug_msg "Starting main execution"
echo "Starting main execution..."
debug_msg "Calling cleanup_k3s_agent_installation"
cleanup_k3s_agent_installation
echo -e "${GREEN}===============================================${NC}"
debug_msg "Calling remove_dangling_docker_images"
remove_dangling_docker_images
echo -e "${GREEN}===============================================${NC}"
debug_msg "Calling build_and_save_fastapi_image"
build_and_save_fastapi_image
echo -e "${GREEN}===============================================${NC}"
debug_msg "Calling check_certificate_trust"
check_certificate_trust
echo -e "${GREEN}===============================================${NC}"
debug_msg "Calling install_k3s_agent_with_token"
install_k3s_agent_with_token
echo -e "${GREEN}===============================================${NC}"
debug_msg "Calling apply_fastapi_deployment_yaml"
apply_fastapi_deployment_yaml
echo -e "${GREEN}===============================================${NC}"
debug_msg "Calling verify_node_ready"
verify_node_ready
echo -e "${GREEN}===============================================${NC}"
debug_msg "Calling check_fastapi_pod_status"
check_fastapi_pod_status
debug_msg "Script completed"
echo -e "  ${YELLOW}Script completed${NC}"