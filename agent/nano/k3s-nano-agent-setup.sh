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
if [ -f "$SCRIPT_DIR/nano-config.env" ]; then
    source "$SCRIPT_DIR/nano-config.env"
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
    if [ "$1" -eq 0 ]; then
        echo -e "$2 $TICK"
        debug_msg "$2 succeeded"
    else
        echo -e "$2 $CROSS"
        debug_msg "$2 failed"
    fi
}

function cleanup_k3s_agent_installation() {
    debug_msg "Running cleanup_k3s_agent_installation"
    echo -e "${GREEN}\n== Cleanup k3s Agent Installation ==${NC}"

    # Define the kubeconfig path for reliable kubectl access during cleanup
    KUBECONFIG_PATH="/home/sanjay/k3s.yaml"
    debug_msg "KUBECONFIG_PATH set to $KUBECONFIG_PATH"

    # Forcefully delete existing Kubernetes resources
    if [ -f "$KUBECONFIG_PATH" ] && command -v kubectl >/dev/null 2>&1; then
        debug_msg "Kubeconfig found and kubectl available, proceeding with cleanup"
        if [ "$DEBUG" -eq 1 ]; then
            echo -e "  Attempting forceful cleanup of old 'fastapi-nano' resources... $TICK"
        fi
        # Delete the Deployment and Service (ignore if not found)
        debug_msg "Deleting deployment fastapi-nano"
        timeout 30s KUBECONFIG="$KUBECONFIG_PATH" kubectl delete deployment fastapi-nano --ignore-not-found >/dev/null 2>&1
        print_result $? "  Cleaned up K8s Deployment/Service/RS/Pods"
    else
        debug_msg "Kubeconfig not found or kubectl not available, skipping cleanup"
        print_result 0 "  No kubeconfig or kubectl found, skipping cleanup"
    fi

    # Check for the k3s uninstall script and run it if it exists
    debug_msg "Checking for k3s-agent-uninstall.sh"
    if [ -f "/usr/local/bin/k3s-agent-uninstall.sh" ]; then
        debug_msg "Found k3s-agent-uninstall.sh, running cleanup"
        if [ "$DEBUG" -eq 1 ]; then
            echo -e "  Found k3s agent uninstall script, running cleanup..."
        fi
        sudo /usr/local/bin/k3s-agent-uninstall.sh >/dev/null 2>&1
        print_result $? "  Uninstalled existing k3s agent"
    else
        debug_msg "No k3s-agent-uninstall.sh found"
        print_result 0 "  No k3s agent uninstall script found (initial setup or clean system)"
    fi
    # Remove stale kubeconfig
    debug_msg "Removing stale kubeconfig"
    rm -f /home/sanjay/k3s.yaml >/dev/null 2>&1
    print_result $? "  Removed stale /home/sanjay/k3s.yaml"
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
    echo -e "${GREEN}\n== Build and Save FastAPI Image ==${NC}"
    if [ -f "$SCRIPT_DIR/dockerfile.nano.req" ]; then
        debug_msg "Dockerfile found, checking timestamps"
        DOCKERFILE_MTIME=$(get_file_mtime "$SCRIPT_DIR/dockerfile.nano.req")
        TAR_FILE="$IMAGE_DIR/fastapi_nano.tar"
        BUILT_IMAGE=false
        # Check if we can skip build by using existing tar
        if [ -f "$TAR_FILE" ]; then
            TAR_MTIME=$(get_file_mtime "$TAR_FILE")
            if [ "$DOCKERFILE_MTIME" -le "$TAR_MTIME" ] 2>/dev/null; then
                debug_msg "Using cached image"
                print_result 0 "  Using cached fastapi_nano image (Dockerfile unchanged)"
                docker load -i "$TAR_FILE" >/dev/null 2>&1
                LOAD_STATUS=$?
                if [ $LOAD_STATUS -eq 0 ]; then
                    print_result 0 "  Loaded fastapi_nano image from cache"
                else
                    print_result 1 "  Failed to load cached image, will rebuild"
                    BUILT_IMAGE=true
                fi
            else
                debug_msg "Dockerfile changed, rebuilding"
                print_result 0 "  Dockerfile changed, rebuilding image"
                BUILT_IMAGE=true
            fi
        else
            debug_msg "No cached tar found, building"
            BUILT_IMAGE=true
        fi
        # Build if not loaded from cache or load failed
        if ! docker images fastapi_nano:latest | grep -q fastapi_nano; then
            debug_msg "Building image from Dockerfile"
            BUILD_OUTPUT=$(DOCKER_BUILDKIT=1 docker build -f "$SCRIPT_DIR/dockerfile.nano.req" -t fastapi_nano:latest "$SCRIPT_DIR" 2>&1)
            # Check if build was successful
            if echo "$BUILD_OUTPUT" | grep -q "Successfully built"; then
                # Check if cache was used
                if echo "$BUILD_OUTPUT" | grep -q "Using cache"; then
                    print_result 0 "  Built fastapi_nano:latest image from cache"
                else
                    print_result 0 "  Built fastapi_nano:latest image from scratch"
                fi
                BUILT_IMAGE=true
            else
                # Build failed
                debug_msg "Build failed"
                print_result 1 "  Failed to build fastapi_nano:latest image"
                echo "$BUILD_OUTPUT"  # Show build errors
                return 1
            fi
        else
            debug_msg "Image already available"
            print_result 0 "  fastapi_nano:latest image already available"
        fi
        # Tag and push to local registry only if we built/rebuild the image
        if [ "$BUILT_IMAGE" = true ]; then
            debug_msg "Tagging image for registry"
            docker tag fastapi_nano:latest ${TOWER_IP}:5000/fastapi_nano:latest
            print_result $? "  Tagged image for local registry"
            debug_msg "Pushing image to registry"
            docker push ${TOWER_IP}:5000/fastapi_nano:latest
            PUSH_STATUS=$?
            print_result $PUSH_STATUS "  Pushed image to local registry ${TOWER_IP}:5000"
        fi
        
        # Save to tar as backup only if we built/re-built the image or tar doesn't exist
        if [ "$BUILT_IMAGE" = true ] || [ ! -f "$TAR_FILE" ]; then
            if docker images fastapi_nano:latest | grep -q fastapi_nano; then
                debug_msg "Saving image to tar as backup"
                mkdir -p "$IMAGE_DIR"  # Ensure directory exists
                docker save -o "$TAR_FILE" fastapi_nano:latest >/dev/null 2>&1
                SAVE_STATUS=$?
                if [ $SAVE_STATUS -eq 0 ]; then
                    chmod 644 "$TAR_FILE"  # Make readable by all
                    print_result 0 "  Saved fastapi_nano image to $TAR_FILE (backup)"
                    print_result 0 "  Backup tar file ready for containerd import if needed"
                else
                    print_result $SAVE_STATUS "  Saved fastapi_nano image to $TAR_FILE (backup)"
                fi
            fi
        else
            debug_msg "Using existing tar backup, no save needed"
            if [ -f "$TAR_FILE" ]; then
                print_result 0 "  Using existing tar backup (no save needed)"
            fi
        fi
    else
        debug_msg "Dockerfile not found"
        print_result 1 "  dockerfile.nano.req not found in $SCRIPT_DIR (skipping build)"
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
    echo -e "${GREEN}\n== Install k3s Agent with Token ==${NC}"
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
        echo -e "${GREEN}\n== Configure Insecure Registry (registries.yaml) ==${NC}"
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
        echo -e "${GREEN}  Configuring Docker daemon for insecure registry...${NC}"
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
            echo -e "${GREEN}  Installing k3s agent (this may take several minutes)...${NC}"
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
        else
            print_result 1 "  $TOKEN_DIR/k3s.yaml not found after install"
            echo -e "${RED}ERROR: Kubeconfig not found. Agent may not have joined the cluster. Halting setup.${NC}"
            exit 2
        fi
        # Import the FastAPI image into containerd ONLY if registry pull fails
        # Check if the image is available from registry first
        if sudo k3s ctr images list | grep -q "${TOWER_IP}:5000/fastapi_nano"; then
            debug_msg "Image already available from registry, skipping tar import"
            print_result 0 "  FastAPI image available from registry (tar import not needed)"
        elif [ -f "$IMAGE_DIR/fastapi_nano.tar" ]; then
            debug_msg "Registry image not found, importing from tar backup"
            sudo k3s ctr images import "$IMAGE_DIR/fastapi_nano.tar" >/dev/null 2>&1
            print_result $? "  Imported fastapi_nano image into containerd from backup tar"
        else
            print_result 0 "  fastapi_nano.tar not found (registry method should work)"
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
    DEPLOYMENT_YAML="$SCRIPT_DIR/start-fastapi-nano.yaml"
    debug_msg "DEPLOYMENT_YAML set to $DEPLOYMENT_YAML"
    if [ -f "$DEPLOYMENT_YAML" ]; then
        debug_msg "Deployment YAML found, applying with kubectl"
        timeout 30s kubectl --kubeconfig="$KUBECONFIG_PATH" apply -f "$DEPLOYMENT_YAML" >/dev/null 2>&1
        print_result $? "  Applied FastAPI deployment YAML: $DEPLOYMENT_YAML"
    else
        debug_msg "Deployment YAML not found, trying generic fastapi deployment"
        DEPLOYMENT_YAML="$SCRIPT_DIR/start-fastapi.yaml"
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