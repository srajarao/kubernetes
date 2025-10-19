#!/bin/bash

# K3s Agent Setup Script for SPARK1
# Integrated from proven working setup_fastapi_spark1.sh with new architecture
# This script sets up SPARK1 as a k3s agent connected to the tower server

clear

# Setup colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'
TICK="${GREEN}✅${NC}"
CROSS="${RED}❌${NC}"

echo -e "${GREEN}Starting k3s Agent Setup...${NC}\n"

# Source configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/spark1-config.env" ]; then
    source "$SCRIPT_DIR/spark1-config.env"
    echo -e "${GREEN}Configuration loaded from spark1-config.env${NC}"
    echo -e "  Tower IP: ${TOWER_IP}"
    echo -e "  SPARK1 IP: ${SPARK1_IP}"
    echo -e "  Token Directory: ${TOKEN_DIR}"
    echo -e "  Project Directory: ${PROJECT_DIR}"
    echo -e "  Image Directory: ${IMAGE_DIR}"
fi

# Debug flag - can be overridden by environment variable
DEBUG=${DEBUG:-0}

function debug_msg() {
    if [ "$DEBUG" -eq 1 ]; then
        echo -e "${GREEN}[DEBUG] $1${NC}"
    fi
}

function print_result() {
    local timestamp=$(date '+%H:%M:%S')
    if [ "$1" -eq 0 ]; then
        echo -e "[$timestamp] $2 $TICK"
        debug_msg "$2 succeeded"
    else
        echo -e "[$timestamp] $2 $CROSS"
        debug_msg "$2 failed"
    fi
}

# Directories - will be overridden by spark1-config.env if present
TOKEN_DIR="${TOKEN_DIR:-/mnt/vmstore/spark1_home/containers/fastapi/.token}"  # SPARK1: Read Token from server
PROJECT_DIR="${PROJECT_DIR:-/home/sanjay/containers/fastapi}"              # SPARK1: Main project directory
IMAGE_DIR="${IMAGE_DIR:-/mnt/vmstore/spark1_home/containers/fastapi}"         # SPARK1: Save build images for server
TOWER_IP="${TOWER_IP:-192.168.10.1}"                                      # Tower server IP
SPARK1_IP="${SPARK1_IP:-10.1.10.201}"                                        # SPARK1 device IP

function cleanup_k3s_agent_installation() {
    debug_msg "Running cleanup_k3s_agent_installation"
    echo -e "${GREEN}\n== Cleanup k3s Agent Installation ==${NC}"

    # Define the kubeconfig path for reliable kubectl access during cleanup
    KUBECONFIG_PATH="/home/sanjay/k3s.yaml"
    debug_msg "KUBECONFIG_PATH set to $KUBECONFIG_PATH"

    # Check for the k3s uninstall script and run it FIRST
    debug_msg "Checking for k3s-agent-uninstall.sh"
    if [ -f "/usr/local/bin/k3s-agent-uninstall.sh" ]; then
        debug_msg "Found k3s-agent-uninstall.sh, running cleanup first"

        # CRITICAL: Delete pods running on THIS node only, especially GPU-using ones, to free resources
        debug_msg "Deleting pods on spark1 node before k3s uninstall to free GPU resources"
        if [ -f "$KUBECONFIG_PATH" ] && kubectl --kubeconfig="$KUBECONFIG_PATH" get pods >/dev/null 2>&1; then
            echo -e "  Deleting pods on spark1 node to free GPU resources..."
            # Only delete pods scheduled on the spark1 node
            kubectl --kubeconfig="$KUBECONFIG_PATH" delete pods -l kubernetes.io/hostname=spark1 --force --grace-period=0 >/dev/null 2>&1
            print_result $? "  Deleted pods on spark1 node (GPU resources freed)"
            # Give pods time to terminate
            sleep 5
        else
            debug_msg "No valid kubeconfig found, skipping pod deletion"
        fi

        if [ "$DEBUG" -eq 1 ]; then
            echo -e "  Found k3s agent uninstall script, running cleanup..."
        fi
        sudo /usr/local/bin/k3s-agent-uninstall.sh >/dev/null 2>&1
        print_result $? "  Uninstalled existing k3s agent"
    else
        debug_msg "No k3s-agent-uninstall.sh found"
        print_result 0 "  No k3s agent uninstall script found (initial setup or clean system)"
    fi

    # Remove stale kubeconfig immediately after k3s uninstall
    debug_msg "Removing stale kubeconfig"
    rm -f /home/sanjay/k3s.yaml >/dev/null 2>&1
    print_result $? "  Removed stale /home/sanjay/k3s.yaml"

    # Skip kubectl cleanup since k3s uninstall removes all resources
    debug_msg "Skipping kubectl cleanup - k3s uninstall removes all resources"
    print_result 0 "  Skipped kubectl cleanup (handled by k3s uninstall)"
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
            
            # Fix internet connectivity for k3s download
            echo -e "${GREEN}  Configuring internet connectivity for k3s download...${NC}"
            # Save current default route for restoration
            DEFAULT_ROUTE_VIA_TOWER=$(ip route show | grep "default via ${TOWER_IP}")
            if [ -n "$DEFAULT_ROUTE_VIA_TOWER" ]; then
                debug_msg "Temporarily removing default route via tower for internet access"
                sudo ip route del default via ${TOWER_IP} dev eno1 2>/dev/null || true
                print_result $? "  Configured internet access via wireless interface"
            else
                debug_msg "Default route via tower not found, continuing"
                print_result 0 "  Internet connectivity already available"
            fi
            
            K3S_URL="https://${TOWER_IP}:6443"
            NODE_IP="$SPARK1_IP"
            # --- START DEBUG INFO ---
            if [ "$DEBUG" -eq 1 ]; then
                echo -e "\n${GREEN}== DEBUG: k3s agent install info ==${NC}"
                echo "  K3S_URL: $K3S_URL"
                echo "  K3S_TOKEN: (token hidden)"
                echo "  K3S_CA_FILE: $TOKEN_CERT"
                echo "  Node IP: $NODE_IP"
                echo "  Registry Configured At: /etc/rancher/k3s/registries.yaml"
                # Updated Install command no longer uses K3S_AGENT_ARGS
                echo "  Install command: sudo curl -sfL https://get.k3s.io | K3S_URL=\"$K3S_URL\" K3S_TOKEN=\"$K3S_TOKEN\" K3S_CA_FILE=\"$TOKEN_CERT\" sh -s - agent --node-ip \"$NODE_IP\""
                echo -e "${GREEN}== Running k3s agent install... ==${NC}"
            fi
            # --- END DEBUG INFO ---
            # Execute install command (WITHOUT K3S_AGENT_ARGS)
            if [ "$DEBUG" -eq 1 ]; then
                sudo curl -sfL https://get.k3s.io | K3S_URL="$K3S_URL" K3S_TOKEN="$K3S_TOKEN" K3S_CA_FILE="$TOKEN_CERT" sh -s - agent --node-ip "$NODE_IP"
            else
                sudo curl -sfL https://get.k3s.io | K3S_URL="$K3S_URL" K3S_TOKEN="$K3S_TOKEN" K3S_CA_FILE="$TOKEN_CERT" sh -s - agent --node-ip "$NODE_IP" >/dev/null 2>&1
            fi
            INSTALL_STATUS=$?
            
            # Restore default route via tower for local cluster communication
            if [ -n "$DEFAULT_ROUTE_VIA_TOWER" ]; then
                debug_msg "Restoring default route via tower"
                sudo ip route add default via ${TOWER_IP} dev eno1 metric 100 2>/dev/null || true
                print_result $? "  Restored tower route for cluster communication"
            fi
            
            print_result $INSTALL_STATUS "  Installed k3s-agent using token and CA cert"
            if [ $INSTALL_STATUS -ne 0 ]; then
                echo -e "${RED}ERROR: k3s agent install failed. Check above output for details.${NC}"
            else
                # Restart the service to load registries.yaml
                sudo systemctl restart k3s-agent
                print_result $? "  Restarted k3s-agent service to load registries.yaml"
                
                # Ensure route to Nano subnet persists after k3s networking setup
                echo -e "${GREEN}  Ensuring route to Nano subnet (192.168.5.0/24) via Tower...${NC}"
                if ! ip route show | grep -q "192.168.5.0/24 via $TOWER_IP"; then
                    sudo ip route add 192.168.5.0/24 via $TOWER_IP dev $SPARK1_IFACE metric 100
                    print_result $? "  Route to Nano subnet added"
                else
                    echo -e "${GREEN}  Route to Nano subnet already exists${NC}"
                    print_result 0 "  Route to Nano subnet verified"
                fi
                
                # Add iptables rule to allow traffic to Nano subnet (if not already allowed)
                if ! sudo iptables -C FORWARD -s $SPARK1_IP -d 192.168.5.0/24 -j ACCEPT 2>/dev/null; then
                    sudo iptables -I FORWARD -s $SPARK1_IP -d 192.168.5.0/24 -j ACCEPT
                    print_result $? "  Added iptables rule for Nano traffic"
                else
                    print_result 0 "  iptables rule for Nano traffic already exists"
                fi
            fi
        else
            print_result 1 "  Server CA cert not found at $TOKEN_CERT (cannot join cluster)"
            echo -e "${RED}ERROR: Server CA certificate missing. Agent cannot join cluster securely. Halting setup.${NC}"
            exit 2
        fi
        # Always copy latest kubeconfig to ~/.kube/config and set permissions
        if [ -f "$TOKEN_DIR/k3s.yaml" ]; then
            mkdir -p "$HOME/.kube"
            cp "$TOKEN_DIR/k3s.yaml" "$HOME/.kube/config"
            chmod 600 "$HOME/.kube/config"
            print_result $? "  Updated kubeconfig at $HOME/.kube/config"
        else
            print_result 1 "  $TOKEN_DIR/k3s.yaml not found after install"
            echo -e "${RED}ERROR: Kubeconfig not found. Agent may not have joined the cluster. Halting setup.${NC}"
            exit 2
        fi
        # Import the FastAPI image into containerd ONLY if registry pull fails
        # Check if the image is available from registry first
        if sudo k3s ctr images list | grep -q "${TOWER_IP}:5000/fastapi_spark1"; then
            debug_msg "Image already available from registry, skipping tar import"
            print_result 0 "  FastAPI image available from registry (tar import not needed)"
        elif [ -f "$IMAGE_DIR/fastapi_spark1.tar" ]; then
            debug_msg "Registry image not found, importing from tar backup"
            sudo k3s ctr images import "$IMAGE_DIR/fastapi_spark1.tar" >/dev/null 2>&1
            print_result $? "  Imported fastapi_spark1 image into containerd from backup tar"
        else
            print_result 0 "  fastapi_spark1.tar not found (registry method should work)"
        fi
        # Install Nvidia container toolkit for GPU support
        echo -e "${GREEN}\n== Install NVIDIA Device Plugin ==${NC}"
        # Note: You may need to wait for the k3s-agent service to fully start before this kubectl command works reliably.
        timeout 30s kubectl apply -f https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.14.5/nvidia-device-plugin.yml >/dev/null 2>&1
        print_result $? "  NVIDIA device plugin applied to cluster"
    else
        print_result 1 "  Token file not found at $TOKEN_FILE (skipping k3s-agent install)"
    fi
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
    if [ -f "$PROJECT_DIR/dockerfile.online.req" ]; then
        debug_msg "Dockerfile found, checking timestamps"
        DOCKERFILE_MTIME=$(get_file_mtime "$PROJECT_DIR/dockerfile.online.req")
        TAR_FILE="$IMAGE_DIR/fastapi_spark1.tar"
        BUILT_IMAGE=false
        # Check if we can skip build by using existing tar
        if [ -f "$TAR_FILE" ]; then
            TAR_MTIME=$(get_file_mtime "$TAR_FILE")
            if [ "$DOCKERFILE_MTIME" -le "$TAR_MTIME" ] 2>/dev/null; then
                debug_msg "Using cached image"
                print_result 0 "  Using cached fastapi_spark1 image (Dockerfile unchanged)"
                docker load -i "$TAR_FILE" >/dev/null 2>&1
                LOAD_STATUS=$?
                if [ $LOAD_STATUS -eq 0 ]; then
                    print_result 0 "  Loaded fastapi_spark1 image from cache"
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
        if ! docker images fastapi-spark1:latest | grep -q fastapi-spark1; then
            debug_msg "Building image from Dockerfile"
            BUILD_OUTPUT=$(DOCKER_BUILDKIT=1 docker build -f "$PROJECT_DIR/dockerfile.online.req" -t fastapi-spark1:latest "$PROJECT_DIR" 2>&1)
            # Check if build was successful
            if echo "$BUILD_OUTPUT" | grep -q "Successfully built"; then
                # Check if cache was used
                if echo "$BUILD_OUTPUT" | grep -q "Using cache"; then
                    print_result 0 "  Built fastapi-spark1:latest image from cache"
                else
                    print_result 0 "  Built fastapi-spark1:latest image from scratch"
                fi
                BUILT_IMAGE=true
            else
                # Build failed
                debug_msg "Build failed"
                print_result 1 "  Failed to build fastapi-spark1:latest image"
                echo "$BUILD_OUTPUT"  # Show build errors
                return 1
            fi
        else
            debug_msg "Image already available"
            print_result 0 "  fastapi-spark1:latest image already available"
        fi
        # Tag and push to local registry only if we built/rebuild the image
        if [ "$BUILT_IMAGE" = true ]; then
            debug_msg "Tagging image for registry"
            docker tag fastapi-spark1:latest ${TOWER_IP}:5000/fastapi-spark1:latest
            print_result $? "  Tagged image for local registry"
            debug_msg "Pushing image to registry"
            docker push ${TOWER_IP}:5000/fastapi-spark1:latest
            PUSH_STATUS=$?
            print_result $PUSH_STATUS "  Pushed image to local registry ${TOWER_IP}:5000"
        fi
        
        # Save to tar as backup only if we built/re-built the image or tar doesn't exist
        if [ "$BUILT_IMAGE" = true ] || [ ! -f "$TAR_FILE" ]; then
            if docker images fastapi-spark1:latest | grep -q fastapi-spark1; then
                debug_msg "Saving image to tar as backup"
                mkdir -p "$IMAGE_DIR"  # Ensure directory exists
                docker save -o "$TAR_FILE" fastapi-spark1:latest >/dev/null 2>&1
                SAVE_STATUS=$?
                if [ $SAVE_STATUS -eq 0 ]; then
                    chmod 644 "$TAR_FILE"  # Make readable by all
                    print_result 0 "  Saved fastapi_spark1 image to $TAR_FILE (backup)"
                    print_result 0 "  Backup tar file ready for containerd import if needed"
                else
                    print_result $SAVE_STATUS "  Saved fastapi_spark1 image to $TAR_FILE (backup)"
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
        print_result 1 "  dockerfile.online.req not found in $PROJECT_DIR (skipping build)"
    fi
}

function apply_fastapi_deployment_yaml() {
    debug_msg "Running apply_fastapi_deployment_yaml"
    echo -e "${GREEN}\n== Apply FastAPI Deployment YAML ==${NC}"
    DEPLOYMENT_YAML="$SCRIPT_DIR/start-fastapi.yaml"
    debug_msg "DEPLOYMENT_YAML set to $DEPLOYMENT_YAML"
    if [ -f "$DEPLOYMENT_YAML" ]; then
        debug_msg "Deployment YAML found, applying with kubectl"
        timeout 30s kubectl apply -f "$DEPLOYMENT_YAML" >/dev/null 2>&1
        print_result $? "  Applied FastAPI deployment YAML: $DEPLOYMENT_YAML"
    else
        debug_msg "Deployment YAML not found"
        print_result 1 "  Deployment YAML not found at $DEPLOYMENT_YAML (skipping apply)"
    fi
}

function verify_node_ready() {
    debug_msg "Running verify_node_ready"
    echo -e "${GREEN}\n== Verify Node Ready Status ==${NC}"
    NODE_NAME=$(hostname)
    debug_msg "NODE_NAME set to $NODE_NAME"
    for i in {1..12}; do
        debug_msg "Checking node status, attempt $i"
        NODE_STATUS=$(timeout 10s kubectl get nodes --no-headers | grep "$NODE_NAME" | awk '{print $2}')
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
        timeout 10s kubectl describe node "$NODE_NAME"
    fi
}

function check_fastapi_pod_status() {
    debug_msg "Running check_fastapi_pod_status"
    echo -e "${GREEN}\n== Check FastAPI Pod Status ==${NC}"
    POD_NAME=$(timeout 10s kubectl get pods -l app=fastapi-spark1 -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    debug_msg "POD_NAME: $POD_NAME"
    if [ -z "$POD_NAME" ]; then
        debug_msg "No FastAPI pod found"
        print_result 1 "  No FastAPI pod found after deployment"
    else
        STATUS=""
        MAX_RETRIES=18
        RETRY_COUNT=0
        while [ "$STATUS" != "Running" ] && [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
            debug_msg "Checking pod status, attempt $((RETRY_COUNT+1))"
            STATUS=$(timeout 5s kubectl get pod "$POD_NAME" -o jsonpath='{.status.phase}' 2>/dev/null)
            debug_msg "Pod status: $STATUS"
            if [ "$STATUS" == "Pending" ]; then
                REASON=$(timeout 5s kubectl get pod "$POD_NAME" -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null)
                debug_msg "Pending reason: $REASON"
                if [ "$REASON" == "ImagePullBackOff" ] || [ "$REASON" == "ErrImagePull" ]; then
                    echo -e "${RED}  Image Pull is failing, describing pod...${NC}"
                    timeout 10s kubectl describe pod "$POD_NAME"
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
            timeout 10s kubectl describe pod "$POD_NAME"
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
