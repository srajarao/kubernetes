#!/bin/bash
clear
echo -e "${GREEN}Starting nano FastAPI agent setup...${NC}\n"
# Setup colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'
TICK="${GREEN}✅${NC}"
CROSS="${RED}❌${NC}"

# Debug flag
DEBUG=0

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


# Directories
TOKEN_DIR="/mnt/vmstore/nano_home/containers/fastapi_nano/.token"  # Read Token from server
PROJECT_DIR="/home/sanjay/containers/fastapi_nano"                # Main project directory
IMAGE_DIR="/mnt/vmstore/nano_home/containers/fastapi_nano"         # Save build images for server


function cleanup_k3s_agent_installation() {
    debug_msg "Running cleanup_k3s_agent_installation"
    echo -e "${GREEN}\n== Cleanup k3s Agent Installation ==${NC}"

    # Define the kubeconfig path for reliable kubectl access during cleanup
    KUBECONFIG_PATH="/home/sanjay/k3s.yaml"

    # --- NEW: Forcefully delete existing Kubernetes resources ---
    if [ -f "$KUBECONFIG_PATH" ] && command -v kubectl >/dev/null 2>&1; then
        echo -e "  Attempting forceful cleanup of old 'fastapi-nano' resources... $TICK"
        
        # 1. Delete the Deployment and Service (ignore if not found)
        KUBECONFIG="$KUBECONFIG_PATH" kubectl delete deployment fastapi-nano --ignore-not-found >/dev/null 2>&1
        KUBECONFIG="$KUBECONFIG_PATH" kubectl delete service fastapi-nano-service --ignore-not-found >/dev/null 2>&1
        
        # 2. Force delete any lingering ReplicaSets that may accumulate
        KUBECONFIG="$KUBECONFIG_PATH" kubectl delete rs -l app=fastapi-nano --ignore-not-found >/dev/null 2>&1
        
        # 3. Force delete any lingering Pods that may hold GPU resources
        # The --force --grace-period=0 is critical for cleaning up stuck Pods
        KUBECONFIG="$KUBECONFIG_PATH" kubectl delete pod -l app=fastapi-nano --ignore-not-found --force --grace-period=0 >/dev/null 2>&1
        print_result $? "  Cleaned up K8s Deployment/Service/RS/Pods"
    fi
    # -----------------------------------------------------------

    # Check for the k3s uninstall script and run it if it exists
    if [ -f "/usr/local/bin/k3s-agent-uninstall.sh" ]; then
        echo -e "  Found k3s agent uninstall script, running cleanup..."
        sudo /usr/local/bin/k3s-agent-uninstall.sh >/dev/null 2>&1
        print_result $? "  Uninstalled existing k3s agent"
    else
        print_result 0 "  No k3s agent uninstall script found (initial setup or clean system)"
    fi
    # Removed stale /home/sanjay/k3s.yaml
    rm -f /home/sanjay/k3s.yaml >/dev/null 2>&1
    print_result $? "  Removed stale /home/sanjay/k3s.yaml"
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
        
        # FIX: Implement reliable Insecure Registry configuration via registries.yaml
        REGISTRY_IP="192.168.5.1:5000"
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
        # Do NOT restart k3s-agent here, as it may not be installed yet

        if [ -f "$TOKEN_CERT" ]; then
            K3S_URL="https://192.168.5.1:6443"
            
            # --- START DEBUG INFO ---
            echo -e "\n${GREEN}== DEBUG: k3s agent install info ==${NC}"
            echo "  K3S_URL: $K3S_URL"
            echo "  K3S_TOKEN: (token hidden)"
            echo "  K3S_CA_FILE: $TOKEN_CERT"
            NODE_IP="192.168.5.21"
            echo "  Node IP: $NODE_IP"
            echo "  Registry Configured At: /etc/rancher/k3s/registries.yaml"
            
            # Updated Install command no longer uses K3S_AGENT_ARGS
            echo "  Install command: sudo curl -sfL https://get.k3s.io | K3S_URL=\"$K3S_URL\" K3S_TOKEN=\"$K3S_TOKEN\" K3S_CA_FILE=\"$TOKEN_CERT\" sh -s - agent --node-ip \"$NODE_IP\""
            echo -e "${GREEN}== Running k3s agent install... ==${NC}"
            # --- END DEBUG INFO ---
            
            # Execute install command (WITHOUT K3S_AGENT_ARGS)
            sudo curl -sfL https://get.k3s.io | K3S_URL="$K3S_URL" K3S_TOKEN="$K3S_TOKEN" K3S_CA_FILE="$TOKEN_CERT" sh -s - agent --node-ip "$NODE_IP"
            INSTALL_STATUS=$?
            print_result $INSTALL_STATUS "  Installed k3s-agent using token and CA cert"
            if [ $INSTALL_STATUS -ne 0 ]; then
                echo -e "${RED}ERROR: k3s agent install failed. Check above output for details.${NC}"
            else
                # 3. IMPORTANT: Restart the service to load registries.yaml
                sudo systemctl restart k3s-agent
                print_result $? "  Restarted k3s-agent service to load registries.yaml"
            fi
        else
            print_result 1 "  Server CA cert not found at $TOKEN_CERT (cannot join cluster)"
            echo -e "${RED}ERROR: Server CA certificate missing. Agent cannot join cluster securely. Halting setup.${NC}"
            exit 2
        fi
        
        # Copy kubeconfig to user home for stable permissions
        if [ -f "/mnt/vmstore/nano_home/containers/fastapi_nano/.token/k3s.yaml" ]; then
            cp /mnt/vmstore/nano_home/containers/fastapi_nano/.token/k3s.yaml "$HOME/k3s.yaml"
            print_result $? "  Copied kubeconfig to $HOME/k3s.yaml"
            chmod 600 "$HOME/k3s.yaml"
            print_result $? "  Set permissions on $HOME/k3s.yaml"
            
            # Set as default kubeconfig for kubectl
            mkdir -p "$HOME/.kube"
            cp "$HOME/k3s.yaml" "$HOME/.kube/config"
            print_result $? "  Set as default kubeconfig at $HOME/.kube/config"
        else
            print_result 1 "  /mnt/vmstore/nano_home/containers/fastapi_nano/.token/k3s.yaml not found after install"
            echo -e "${RED}ERROR: Kubeconfig not found. Agent may not have joined the cluster. Halting setup.${NC}"
            exit 2
        fi
        
        # Import the FastAPI image into containerd
        if [ -f "$IMAGE_DIR/fastapi_nano.tar" ]; then
            sudo k3s ctr images import "$IMAGE_DIR/fastapi_nano.tar"
            print_result $? "  Imported fastapi_nano image into containerd"
        else
            print_result 1 "  fastapi_nano.tar not found at $IMAGE_DIR (skipping import)"
        fi
        
        # Install Nvidia container toolkit for GPU support
        echo -e "${GREEN}\n== Install NVIDIA Device Plugin ==${NC}"
        # Note: You may need to wait for the k3s-agent service to fully start before this kubectl command works reliably.
        kubectl apply -f https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.14.5/nvidia-device-plugin.yml >/dev/null 2>&1
        print_result $? "  NVIDIA device plugin applied to cluster"
    else
        print_result 1 "  Token file not found at $TOKEN_FILE (no k3s found)"
        echo -e "${YELLOW}INFO: No k3s installation found. Cleaning up and exiting.${NC}"
        exit 0
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
    if [ -f "$PROJECT_DIR/dockerfile.fastapi_nano" ]; then
        DOCKERFILE_MTIME=$(get_file_mtime "$PROJECT_DIR/dockerfile.fastapi_nano")
        TAR_FILE="$IMAGE_DIR/fastapi_nano.tar"
        BUILT_IMAGE=false
        
        # Check if we can skip build by using existing tar
        if [ -f "$TAR_FILE" ]; then
            TAR_MTIME=$(get_file_mtime "$TAR_FILE")
            if [ "$DOCKERFILE_MTIME" -le "$TAR_MTIME" ] 2>/dev/null; then
                print_result 0 "  Using cached fastapi_nano image (Dockerfile unchanged)"
                # Load from existing tar
                docker load -i "$TAR_FILE" >/dev/null 2>&1
                LOAD_STATUS=$?
                if [ $LOAD_STATUS -eq 0 ]; then
                    print_result 0 "  Loaded fastapi_nano image from cache"
                else
                    print_result 1 "  Failed to load cached image, will rebuild"
                    BUILT_IMAGE=true
                fi
            else
                print_result 0 "  Dockerfile changed, rebuilding image"
                BUILT_IMAGE=true
            fi
        else
            BUILT_IMAGE=true
        fi
        
        # Build if not loaded from cache or load failed
        if ! docker images fastapi_nano:latest | grep -q fastapi_nano; then
            # Build image and capture output to check for cache usage
            BUILD_OUTPUT=$(DOCKER_BUILDKIT=1 docker build -f "$PROJECT_DIR/dockerfile.fastapi_nano" -t fastapi_nano:latest "$PROJECT_DIR" 2>&1)
            
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
                print_result 1 "  Failed to build fastapi_nano:latest image"
                echo "$BUILD_OUTPUT"  # Show build errors
                return 1
            fi
        else
            print_result 0 "  fastapi_nano:latest image already available"
        fi
        
        # Tag and push to local registry only if we built/rebuild the image
        if [ "$BUILT_IMAGE" = true ]; then
            docker tag fastapi_nano:latest 192.168.5.1:5000/fastapi_nano:latest
            print_result $? "  Tagged image for local registry"
            docker push 192.168.5.1:5000/fastapi_nano:latest
            PUSH_STATUS=$?
            print_result $PUSH_STATUS "  Pushed image to local registry 192.168.5.1:5000"
            
            # Save to tar only if push was successful and we built/loaded
            if [ $PUSH_STATUS -eq 0 ] && [ ! -f "$TAR_FILE" -o "$DOCKERFILE_MTIME" -gt "$TAR_MTIME" ] 2>/dev/null; then
                sudo docker save -o "$TAR_FILE" fastapi_nano:latest >/dev/null 2>&1
                print_result $? "  Saved fastapi_nano image to $TAR_FILE"
            fi
        else
            print_result 0 "  Skipping push - using cached image from registry"
        fi
    else
        print_result 1 "  dockerfile.fastapi_nano not found in $PROJECT_DIR (skipping build)"
    fi
}

function apply_fastapi_deployment_yaml() {
    debug_msg "Running apply_fastapi_deployment_yaml"
    echo -e "${GREEN}\n== Apply FastAPI Deployment YAML ==${NC}"
    DEPLOYMENT_YAML="$PROJECT_DIR/start-fastapi_nano.yaml"
    if [ -f "$DEPLOYMENT_YAML" ]; then
        kubectl apply -f "$DEPLOYMENT_YAML" >/dev/null 2>&1
        print_result $? "  Applied FastAPI deployment YAML: $DEPLOYMENT_YAML"
    else
        print_result 1 "  Deployment YAML not found at $DEPLOYMENT_YAML (skipping apply)"
    fi
}

function verify_node_ready() {
    debug_msg "Running verify_node_ready"
    echo -e "${GREEN}\n== Verify Node Ready Status ==${NC}"
    NODE_NAME=$(hostname)
    for i in {1..12}; do
        NODE_STATUS=$(kubectl get nodes --no-headers | grep "$NODE_NAME" | awk '{print $2}')
        if [ "$NODE_STATUS" = "Ready" ]; then
            print_result 0 "  Node $NODE_NAME is Ready in the cluster"
            break
        fi
        sleep 5
    done
    if [ "$NODE_STATUS" != "Ready" ]; then
        print_result 1 "  Node $NODE_NAME is not Ready (status: $NODE_STATUS)"
        kubectl describe node "$NODE_NAME"
    fi
}

# Locate and replace the existing check_fastapi_pod_status function (e.g., around line 250)

function check_fastapi_pod_status() {
    debug_msg "Running check_fastapi_pod_status"
    echo -e "${GREEN}\n== Check FastAPI Pod Status ==${NC}"
    POD_NAME=$(kubectl get pods -l app=fastapi-nano -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [ -z "$POD_NAME" ]; then
        print_result 1 "  No FastAPI pod found after deployment"
    else
        STATUS=""
        # Increase the wait time to 3 minutes (18 iterations of 10 seconds)
        MAX_RETRIES=18
        RETRY_COUNT=0
        
        while [ "$STATUS" != "Running" ] && [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
            STATUS=$(kubectl get pod "$POD_NAME" -o jsonpath='{.status.phase}' 2>/dev/null)
            
            # Check for specific failure reasons during pull/create
            if [ "$STATUS" == "Pending" ]; then
                REASON=$(kubectl get pod "$POD_NAME" -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null)
                if [ "$REASON" == "ImagePullBackOff" ] || [ "$REASON" == "ErrImagePull" ]; then
                    echo -e "${RED}  Image Pull is failing, describing pod...${NC}"
                    kubectl describe pod "$POD_NAME"
                    print_result 1 "  FastAPI pod $POD_NAME is stuck in image pull error."
                    return # Exit the function on persistent pull failure
                fi
            fi
            
            if [ "$STATUS" = "Running" ]; then
                print_result 0 "  FastAPI pod $POD_NAME is Running"
                break
            fi
            
            echo -e "  Waiting for pod $POD_NAME to run... ($STATUS) (Retry: $((RETRY_COUNT+1))/$MAX_RETRIES)"
            sleep 3 # Reduced delay to 3 seconds per retry
            RETRY_COUNT=$((RETRY_COUNT+1))
        done
        
        if [ "$STATUS" != "Running" ]; then
            print_result 1 "  FastAPI pod $POD_NAME is not Running (status: $STATUS) after $((MAX_RETRIES * 3)) seconds."
            # Show final, detailed status
            kubectl describe pod "$POD_NAME"
        fi
    fi
}

# Steps to check certificate trust
function check_certificate_trust() {
    debug_msg "Running check_certificate_trust"
    echo -e "\n${GREEN}Certificate Trust Checks${NC}"
    # Check if server CA cert has arrived in token folder
    TOKEN_CERT="$TOKEN_DIR/server-ca.crt"
    if [ -f "$TOKEN_CERT" ]; then
        print_result 0 "  Server CA cert found at $TOKEN_CERT"
    else
        print_result 1 "  Server CA cert not found at $TOKEN_CERT"
    fi
    grep server ~/.kube/config >/dev/null 2>&1
    print_result $? "  kubeconfig server entry present"
    openssl s_client -connect 192.168.5.1:6443 -showcerts </dev/null >/dev/null 2>&1
    print_result $? "  API server certificate presented"
}





# Main execution
echo "Starting main execution..."
cleanup_k3s_agent_installation
echo -e "${GREEN}===============================================${NC}"
remove_dangling_docker_images
echo -e "${GREEN}===============================================${NC}"
build_and_save_fastapi_image
echo -e "${GREEN}===============================================${NC}"
check_certificate_trust
echo -e "${GREEN}===============================================${NC}"
install_k3s_agent_with_token
echo -e "${GREEN}===============================================${NC}"
apply_fastapi_deployment_yaml
echo -e "${GREEN}===============================================${NC}"
verify_node_ready
echo -e "${GREEN}===============================================${NC}"
check_fastapi_pod_status
echo -e "  ${YELLOW}Script completed${NC}"
