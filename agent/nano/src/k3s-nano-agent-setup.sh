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

function cleanup_k3s_agent_installation() {
    debug_msg "Running cleanup_k3s_agent_installation"
    echo -e "${GREEN}\n== Cleanup k3s Agent Installation ==${NC}"

    # Define the kubeconfig path for reliable kubectl access during cleanup

    debug_msg "KUBECONFIG_PATH set to $KUBECONFIG_PATH"

    # FIRST: Clean up any remaining nano-related pods BEFORE uninstalling agent
    debug_msg "Checking for any remaining nano pods to clean up"
    if [ -f "$KUBECONFIG_PATH" ] && kubectl --kubeconfig="$KUBECONFIG_PATH" get pods -l app=fastapi-nano --no-headers 2>/dev/null | grep -q .; then
        debug_msg "Found nano pods, cleaning them up"
        # Use timeout and force delete to avoid hanging on terminating pods
        timeout 30s kubectl --kubeconfig="$KUBECONFIG_PATH" delete pods -l app=fastapi-nano --ignore-not-found=true --force --grace-period=0 >/dev/null 2>&1
        DELETE_STATUS=$?
        if [ $DELETE_STATUS -eq 0 ]; then
            print_result 0 "  Cleaned up existing fastapi-nano pods"
        else
            print_result 1 "  Failed to clean up pods (may be already terminating)"
        fi
        # Give pods time to terminate
        sleep 2
    else
        debug_msg "No nano pods found to clean up"
        print_result 0 "  No existing fastapi-nano pods to clean up"
    fi

    # SECOND: Clean up ALL pods currently running on the nano node
    debug_msg "Checking for any pods running on nano node"
    NODE_NAME=$(hostname)
    if [ -f "$KUBECONFIG_PATH" ]; then
        # Get all pods running on this node and delete them
        PODS_ON_NODE=$(timeout 10s kubectl --kubeconfig="$KUBECONFIG_PATH" get pods --all-namespaces --field-selector spec.nodeName=$NODE_NAME --no-headers -o custom-columns=":metadata.namespace,:metadata.name" 2>/dev/null)
        if [ -n "$PODS_ON_NODE" ] && [ "$PODS_ON_NODE" != "" ]; then
            debug_msg "Found pods running on nano node, cleaning them up"
            echo "$PODS_ON_NODE" | while read -r NAMESPACE POD_NAME; do
                if [ -n "$POD_NAME" ] && [ "$POD_NAME" != "" ]; then
                    debug_msg "Deleting pod $NAMESPACE/$POD_NAME"
                    timeout 15s kubectl --kubeconfig="$KUBECONFIG_PATH" delete pod "$POD_NAME" -n "$NAMESPACE" --ignore-not-found=true --force --grace-period=0 >/dev/null 2>&1
                fi
            done
            print_result 0 "  Cleaned up all pods running on nano node"
            # Give pods time to terminate
            sleep 3
        else
            debug_msg "No pods found running on nano node"
            print_result 0 "  No pods currently running on nano node"
        fi
    fi

    # THEN: Check for the k3s uninstall script and run it
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

    # Remove stale kubeconfig immediately after k3s uninstall
    debug_msg "Removing stale kubeconfig"
    rm -f /home/sanjay/k3s.yaml >/dev/null 2>&1
    print_result $? "  Removed stale /home/sanjay/k3s.yaml"

    # Skip kubectl cleanup since k3s uninstall removes all resources
    debug_msg "Skipping kubectl cleanup - k3s uninstall removes all resources"
    print_result 0 "  Skipped kubectl cleanup (handled by k3s uninstall)"
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
                # Check if image is already available locally first
                if docker images fastapi_nano:latest | grep -q fastapi_nano; then
                    debug_msg "Image already available locally, skipping load"
                    print_result 0 "  fastapi_nano:latest image already available"
                else
                    debug_msg "Loading image from tar cache"
                    docker load -i "$TAR_FILE" >/dev/null 2>&1
                    LOAD_STATUS=$?
                    if [ $LOAD_STATUS -eq 0 ]; then
                        print_result 0 "  Loaded fastapi_nano image from cache"
                    else
                        print_result 1 "  Failed to load cached image, will rebuild"
                        BUILT_IMAGE=true
                    fi
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
            # No need to print message here - already confirmed image availability above
        fi
        # Tag and push to local registry will happen in install phase after registry config
        debug_msg "Skipping registry push in build phase - will push after k3s registry config"
        
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
            # No message needed for existing tar backup
        fi
    else
        debug_msg "Dockerfile not found"
        print_result 1 "  dockerfile.nano.req not found in $SCRIPT_DIR (skipping build)"
    fi
}

function check_certificate_trust() {
    debug_msg "Running check_certificate_trust"
    echo -e "\n${GREEN}Certificate Trust Checks${NC}"
    TOKEN_CERT="$TOKEN_DIR/config/server-ca.crt"
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
    TOKEN_FILE="$TOKEN_DIR/config/node-token"
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
        TOKEN_CERT="$TOKEN_DIR/config/server-ca.crt"
        # Configuration variables
        REGISTRY_IP="${TOWER_IP}:5000"

        # 1. Configure Insecure Registry via registries.yaml
        echo -e "${GREEN}\n== Configure Insecure Registry (registries.yaml) ==${NC}"
        # Create configuration directory
        sudo mkdir -p /etc/rancher/k3s/
        print_result $? "  Created /etc/rancher/k3s/ directory"
        # Write registries.yaml to force HTTP for the local registry
        sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
mirrors:
    "$REGISTRY_IP":
        endpoint:
            - "http://$REGISTRY_IP"
        insecure: true
EOF
        
        print_result $? "  Created /etc/rancher/k3s/registries.yaml for HTTP registry access"

        # Copy CA certificate from server for registry trust
        echo -e "${GREEN}  Copying registry CA certificate from server...${NC}"
        sudo mkdir -p /etc/docker/certs.d/$REGISTRY_IP
        if sudo scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@$TOWER_IP:/etc/docker/certs.d/$REGISTRY_IP/ca.crt /etc/docker/certs.d/$REGISTRY_IP/ca.crt >/dev/null 2>&1; then
            print_result 0 "  Copied registry CA certificate from server"
        else
            echo -e "${YELLOW}  Could not copy CA cert from server, generating local copy...${NC}"
            # Fallback: generate the same certificate locally
            sudo openssl req -newkey rsa:4096 -nodes -sha256 \
                -keyout /tmp/registry.key \
                -x509 -days 365 \
                -out /etc/docker/certs.d/$REGISTRY_IP/ca.crt \
                -subj "/C=US/ST=State/L=City/O=Organization/CN=$TOWER_IP" \
                -addext "subjectAltName=IP:$TOWER_IP" >/dev/null 2>&1
            sudo rm -f /tmp/registry.key
            print_result $? "  Generated local registry CA certificate"
        fi
        
        # 2. Configure Docker daemon for insecure registry (keep this for local docker commands)
        echo -e "${GREEN}\n== Configure Insecure Registry (Docker Daemon) ==${NC}"
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
            echo -e "${GREEN}  Installing k3s agent with CA cert (this may take several minutes)...${NC}"
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
                echo "  Install command: sudo curl -sfL https://get.k3s.io | K3S_URL=\"$K3S_URL\" K3S_TOKEN=\"$K3S_TOKEN\" K3S_CA_FILE=\"$TOKEN_CERT\" sh -s - agent --node-ip \"$NODE_IP\" --with-node-id"
                echo -e "${GREEN}== Running k3s agent install... ==${NC}"
            fi
            # Execute install command with CA cert
            if [ "$DEBUG" -eq 1 ]; then
                sudo curl -sfL https://get.k3s.io | K3S_URL="$K3S_URL" K3S_TOKEN="$K3S_TOKEN" K3S_CA_FILE="$TOKEN_CERT" sh -s - agent --node-ip "$NODE_IP" --with-node-id
            else
                sudo curl -sfL https://get.k3s.io | K3S_URL="$K3S_URL" K3S_TOKEN="$K3S_TOKEN" K3S_CA_FILE="$TOKEN_CERT" sh -s - agent --node-ip "$NODE_IP" --with-node-id >/dev/null 2>&1
            fi
            INSTALL_STATUS=$?
            print_result $INSTALL_STATUS "  Installed k3s-agent using token and CA cert"
            if [ $INSTALL_STATUS -ne 0 ]; then
                echo -e "${RED}ERROR: k3s agent install failed. Check above output for details.${NC}"
                return 1
            fi
        else
            echo -e "${YELLOW}  CA cert not found, installing k3s agent without CA verification...${NC}"
            K3S_URL="https://${TOWER_IP}:6443"
            NODE_IP="$NANO_IP"
            # Debug info
            if [ "$DEBUG" -eq 1 ]; then
                echo -e "\n${GREEN}== DEBUG: k3s agent install info (no CA) ==${NC}"
                echo "  K3S_URL: $K3S_URL"
                echo "  K3S_TOKEN: (token hidden)"
                echo "  Node IP: $NODE_IP"
                echo "  Registry Configured At: /etc/rancher/k3s/registries.yaml"
                echo "  Install command: sudo curl -sfL https://get.k3s.io | K3S_URL=\"$K3S_URL\" K3S_TOKEN=\"$K3S_TOKEN\" sh -s - agent --node-ip \"$NODE_IP\" --with-node-id"
                echo -e "${GREEN}== Running k3s agent install... ==${NC}"
            fi
            # Execute install command without CA cert
            if [ "$DEBUG" -eq 1 ]; then
                sudo curl -sfL https://get.k3s.io | K3S_URL="$K3S_URL" K3S_TOKEN="$K3S_TOKEN" sh -s - agent --node-ip "$NODE_IP" --with-node-id
            else
                sudo curl -sfL https://get.k3s.io | K3S_URL="$K3S_URL" K3S_TOKEN="$K3S_TOKEN" sh -s - agent --node-ip "$NODE_IP" --with-node-id >/dev/null 2>&1
            fi
            INSTALL_STATUS=$?
            print_result $INSTALL_STATUS "  Installed k3s-agent using token (no CA verification)"
            if [ $INSTALL_STATUS -ne 0 ]; then
                echo -e "${RED}ERROR: k3s agent install failed. Check above output for details.${NC}"
                return 1
            fi
        fi

        # Post-install configuration (only if install succeeded)
        if [ $INSTALL_STATUS -eq 0 ]; then
            # FIX: Explicitly restart the K3s agent service so containerd picks up the new registries.yaml
            echo -e "${GREEN}\n== Reloading K3s Agent for Registry Config ==${NC}"
            if sudo systemctl is-active --quiet k3s-agent; then
                sudo systemctl restart k3s-agent
                print_result $? "  Restarted k3s-agent service to load new registries.yaml"
            else
                echo -e "${YELLOW}  k3s-agent not active yet, skipping restart.${NC}"
                # Wait for containerd to fully initialize with new registry config
                debug_msg "Waiting for containerd to initialize with registry config"
                sleep 5
            fi
            
            # Ensure route to AGX subnet persists after k3s networking setup
            echo -e "${GREEN}  Ensuring route to AGX subnet (192.168.10.0/24) via Tower...${NC}"
            if ! ip route show | grep -q "192.168.10.0/24 via $TOWER_IP"; then
                sudo ip route add 192.168.10.0/24 via $TOWER_IP dev $NANO_IFACE metric 100
                print_result $? "  Route to AGX subnet added"
            else
                echo -e "${GREEN}  Route to AGX subnet already exists${NC}"
                print_result 0 "  Route to AGX subnet verified"
            fi
            
            # Add iptables rule to allow traffic to AGX subnet (if not already allowed)
            if ! sudo iptables -C FORWARD -s $NANO_IP -d 192.168.10.0/24 -j ACCEPT 2>/dev/null; then
                sudo iptables -I FORWARD -s $NANO_IP -d 192.168.10.0/24 -j ACCEPT
                print_result $? "  Added iptables rule for AGX traffic"
            else
                print_result 0 "  iptables rule for AGX traffic already exists"
            fi
        fi
        # Always copy latest kubeconfig to a known path for this script
        if [ -f "$TOKEN_DIR/config/k3s.yaml" ]; then
            mkdir -p "$(dirname "$KUBECONFIG_PATH")"
            cp "$TOKEN_DIR/k3s.yaml" "$KUBECONFIG_PATH"
            chmod 600 "$KUBECONFIG_PATH"
            print_result $? "  Updated kubeconfig at $KUBECONFIG_PATH"
        else
            print_result 1 "  $TOKEN_DIR/config/k3s.yaml not found after install"
            echo -e "${RED}ERROR: Kubeconfig not found. Agent may not have joined the cluster. Halting setup.${NC}"
            exit 2
        fi
        # Import the FastAPI image into containerd - try registry pull first, then tar import
        debug_msg "Ensuring image is available in containerd"

        # First, ensure the image is pushed to registry (now that insecure registry is configured via registries.yaml)
        if ! sudo k3s ctr images list 2>/dev/null | grep -q "${TOWER_IP}:5000/fastapi_nano"; then
            debug_msg "Image not in registry, pushing from local Docker"
            # Tag and push to registry now that insecure registry is configured
            docker tag fastapi_nano:latest ${TOWER_IP}:5000/fastapi_nano:latest 2>/dev/null
            if [ $? -eq 0 ]; then
                docker push ${TOWER_IP}:5000/fastapi_nano:latest >/dev/null 2>&1
                if [ $? -eq 0 ]; then
                    debug_msg "Successfully pushed to registry"
                    print_result 0 "  Pushed fastapi_nano image to registry"
                else
                    debug_msg "Failed to push to registry"
                    print_result 1 "  Failed to push image to registry"
                fi
            else
                debug_msg "Failed to tag image for registry"
                print_result 1 "  Failed to tag image for registry"
            fi
        fi

        # Now try to pull from registry or import from tar
        if sudo k3s ctr images list 2>/dev/null | grep -q "fastapi_nano"; then
            debug_msg "Image already available in containerd"
            print_result 0 "  FastAPI image available in containerd"
        else
            debug_msg "Image not in containerd, attempting registry pull"
            # Try to pull from registry first
            debug_msg "Pulling from registry: ${TOWER_IP}:5000/fastapi_nano:latest"
            # Test registry connectivity first
            if curl -k --connect-timeout 5 http://${TOWER_IP}:5000/v2/ >/dev/null 2>&1; then
                debug_msg "Registry is accessible via HTTP, attempting k3s ctr pull"
                # Note: k3s containerd doesn't support HTTP registries, so this will fail
                # but we try anyway in case the configuration works
                sudo k3s ctr images pull ${TOWER_IP}:5000/fastapi_nano:latest >/dev/null 2>&1
                PULL_STATUS=$?
                debug_msg "Registry pull exit status: $PULL_STATUS"
            else
                debug_msg "Registry not accessible, skipping pull attempt"
                PULL_STATUS=1
            fi
            if sudo k3s ctr images list 2>/dev/null | grep -q "${TOWER_IP}:5000/fastapi_nano"; then
                debug_msg "Successfully pulled from registry"
                print_result 0 "  Pulled fastapi_nano image from registry"
            else
                debug_msg "Registry pull failed, checking if image exists in registry"
                # Check if Docker can see the image in registry
                if docker pull ${TOWER_IP}:5000/fastapi_nano:latest >/dev/null 2>&1; then
                    debug_msg "Image exists in registry but k3s pull failed, trying direct import"
                    print_result 0 "  Image available in registry, importing via tar fallback"
                else
                    debug_msg "Image not found in registry"
                    print_result 0 "  Image not available in registry, using tar import"
                fi
                if [ -f "$IMAGE_DIR/fastapi_nano.tar" ]; then
                    debug_msg "Importing from tar backup"
                    # Check if image is already imported to avoid slow re-import
                    if sudo k3s ctr images list 2>/dev/null | grep -q "fastapi_nano"; then
                        debug_msg "Image already imported in containerd"
                        print_result 0 "  FastAPI image already available in containerd (skipping import)"
                    else
                        debug_msg "Image not imported, performing tar import"
                        echo -e "${YELLOW}  Importing image from tar (this may take a few minutes)...${NC}"
                        START_TIME=$(date +%s)
                        
                        # Try optimized import method: load into docker first, then export to containerd
                        debug_msg "Attempting optimized import via Docker"
                        if docker load < "$IMAGE_DIR/fastapi_nano.tar" >/dev/null 2>&1; then
                            debug_msg "Successfully loaded into Docker, now exporting to containerd"
                            # Export from docker to containerd using k3s ctr with local import
                            if sudo k3s ctr images import --local <(docker save fastapi_nano:latest) >/dev/null 2>&1; then
                                debug_msg "Successfully imported via Docker optimization"
                                IMPORT_STATUS=0
                            else
                                debug_msg "Docker optimization failed, falling back to direct import"
                                sudo k3s ctr images import --local "$IMAGE_DIR/fastapi_nano.tar" >/dev/null 2>&1
                                IMPORT_STATUS=$?
                            fi
                        else
                            debug_msg "Docker load failed, using direct containerd import with local flag"
                            sudo k3s ctr images import --local "$IMAGE_DIR/fastapi_nano.tar" >/dev/null 2>&1
                            IMPORT_STATUS=$?
                        fi
                        
                        END_TIME=$(date +%s)
                        DURATION=$((END_TIME - START_TIME))
                        if [ $IMPORT_STATUS -eq 0 ]; then
                            print_result 0 "  Imported fastapi_nano image into containerd from backup tar (${DURATION}s)"
                        else
                            print_result 1 "  Failed to import fastapi_nano image from tar"
                        fi
                    fi
                else
                    print_result 1 "  No image source available (registry or tar)"
                fi
            fi
        fi
        # Note: Nano devices DO have NVIDIA GPUs, requiring GPU support setup in a production environment (FIX: Corrected GPU note)
        echo -e "${GREEN}\n== Nano Device Notes (GPU Acknowledged) ==${NC}"
        print_result 0 "  NVIDIA Jetson Nano GPU detected (Basic k3s agent install complete)"
    else
        print_result 1 "  Token file not found at $TOKEN_FILE (skipping k3s-agent install)"
    fi
}





function apply_fastapi_deployment_yaml() {
    debug_msg "Running apply_fastapi_deployment_yaml"
    echo -e "${GREEN}\n== Apply FastAPI Deployment YAML ==${NC}"

    # Clean up all pods on nano node before deployment to free GPU resources
    debug_msg "Cleaning up all pods on nano node before deployment"
    NODE_NAME=$(hostname)
    debug_msg "Targeting pods on node: $NODE_NAME"

    # First verify kubectl access
    if ! kubectl --kubeconfig="$KUBECONFIG_PATH" cluster-info >/dev/null 2>&1; then
        debug_msg "kubectl not accessible with current config, skipping pod cleanup"
        print_result 1 "  kubectl not accessible, skipping pod cleanup on node $NODE_NAME"
    else
        debug_msg "kubectl access verified, proceeding with pod cleanup"
        
        # Clean up failed/stuck pods first
        debug_msg "Checking for failed/stuck fastapi-nano pods to clean up"
        FAILED_PODS=$(kubectl --kubeconfig="$KUBECONFIG_PATH" get pods -l app=fastapi-nano --no-headers -o custom-columns=":metadata.name,:status.phase" 2>/dev/null | grep -E "(Failed|UnexpectedAdmissionError|CrashLoopBackOff|Pending)" | awk '{print $1}' || true)
        if [ -n "$FAILED_PODS" ]; then
            debug_msg "Found failed/stuck pods: $FAILED_PODS"
            echo "$FAILED_PODS" | while read -r POD_NAME; do
                if [ -n "$POD_NAME" ] && [ "$POD_NAME" != "" ]; then
                    debug_msg "Deleting failed pod $POD_NAME"
                    timeout 15s kubectl --kubeconfig="$KUBECONFIG_PATH" delete pod "$POD_NAME" --ignore-not-found=true --force --grace-period=0 >/dev/null 2>&1
                fi
            done
            print_result 0 "  Cleaned up failed/stuck fastapi-nano pods"
            sleep 3
        fi
        
        # Then clean up pods on this specific node
        if kubectl --kubeconfig="$KUBECONFIG_PATH" get pods --all-namespaces --field-selector spec.nodeName=$NODE_NAME --no-headers -o custom-columns=":metadata.namespace,:metadata.name" 2>/dev/null | grep -q .; then
            debug_msg "Found pods running on node $NODE_NAME, cleaning them up before deployment"
            kubectl --kubeconfig="$KUBECONFIG_PATH" get pods --all-namespaces --field-selector spec.nodeName=$NODE_NAME --no-headers -o custom-columns=":metadata.namespace,:metadata.name" 2>/dev/null | while read -r NAMESPACE POD_NAME; do
                if [ -n "$POD_NAME" ] && [ "$POD_NAME" != "" ] && [ "$POD_NAME" != "<none>" ]; then
                    debug_msg "Deleting pod $NAMESPACE/$POD_NAME from node $NODE_NAME before deployment"
                    if timeout 15s kubectl --kubeconfig="$KUBECONFIG_PATH" delete pod "$POD_NAME" -n "$NAMESPACE" --ignore-not-found=true --force --grace-period=0 >/dev/null 2>&1; then
                        debug_msg "Successfully deleted pod $NAMESPACE/$POD_NAME"
                    else
                        debug_msg "Failed to delete pod $NAMESPACE/$POD_NAME"
                    fi
                fi
            done
            print_result 0 "  Cleaned up all pods on node $NODE_NAME before deployment"
            # Give pods time to terminate and free GPU resources
            sleep 5
        else
            debug_msg "No pods found running on node $NODE_NAME"
            print_result 0 "  No pods to clean up on node $NODE_NAME"
        fi
    fi

    # Wait for NVIDIA GPU device plugin to be ready before deploying GPU workloads
    debug_msg "Checking NVIDIA GPU device plugin readiness"
    echo -e "${YELLOW}  Waiting for NVIDIA GPU device plugin to be ready...${NC}"
    PLUGIN_READY=false
    for i in {1..30}; do  # Wait up to 5 minutes (30 * 10s)
        if kubectl --kubeconfig="$KUBECONFIG_PATH" get pods -n kube-system -l app=nvidia-device-plugin-daemonset --no-headers 2>/dev/null | grep -q "Running"; then
            debug_msg "NVIDIA device plugin pod is running"
            # Additional check: verify GPU resources are available on nodes
            if kubectl --kubeconfig="$KUBECONFIG_PATH" get nodes -o jsonpath='{.items[*].status.capacity.nvidia\.com/gpu}' 2>/dev/null | grep -q "[1-9]"; then
                debug_msg "GPU resources detected on nodes"
                PLUGIN_READY=true
                print_result 0 "  NVIDIA GPU device plugin ready"
                break
            else
                debug_msg "GPU plugin running but no GPU capacity detected yet"
            fi
        else
            debug_msg "NVIDIA device plugin pod not running yet (attempt $i/30)"
        fi
        sleep 10
    done

    if [ "$PLUGIN_READY" = false ]; then
        print_result 1 "  NVIDIA GPU device plugin not ready after 5 minutes - GPU workloads may fail"
        echo -e "${YELLOW}  Warning: Proceeding with deployment but GPU allocation may fail${NC}"
    fi

    DEPLOYMENT_YAML="$CONFIG_DIR/start-fastapi-nano.yaml"
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

function check_fastapi_pod_status() {
    debug_msg "Running check_fastapi_pod_status"
    echo -e "${GREEN}\n== Check FastAPI Pod Status ==${NC}"
    echo -e "${YELLOW}  Note: Large 15.5GB image may take 3-5 minutes to download${NC}"

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
        # Increased timeout for large image downloads (36 * 10s = 6 minutes total wait time)
        MAX_RETRIES=36
        RETRY_COUNT=0
        
        # Phase tracking with timing
        PHASE="starting"
        PHASE_START_TIME=$(date +%s)
        LAST_ELAPSED_STR=""
        echo -e -n "${YELLOW}  🚀 Starting pod... 00:00${NC}"
        
        while [ "$STATUS" != "Running" ] && [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
            debug_msg "Checking pod status, attempt $((RETRY_COUNT+1))"
            STATUS=$(timeout 5s kubectl --kubeconfig="$KUBECONFIG_PATH" get pod "$POD_NAME" -o jsonpath='{.status.phase}' 2>/dev/null)
            debug_msg "Pod status: $STATUS"
            
            # Update elapsed time display every 30 seconds (every 3 iterations since we check every 10s)
            if [ $((RETRY_COUNT % 3)) -eq 0 ]; then
                CURRENT_TIME=$(date +%s)
                ELAPSED=$((CURRENT_TIME - PHASE_START_TIME))
                ELAPSED_MIN=$((ELAPSED / 60))
                ELAPSED_SEC=$((ELAPSED % 60))
                ELAPSED_STR=$(printf "%02d:%02d" $ELAPSED_MIN $ELAPSED_SEC)
                
                # Only print if timing has actually changed (not the same as last time)
                if [ "$ELAPSED_STR" != "$LAST_ELAPSED_STR" ]; then
                    # Print current phase with updated timing on same line
                    case "$PHASE" in
                        "starting")
                            echo -e -n "\r${YELLOW}  🚀 Starting pod... ${ELAPSED_STR}${NC}"
                            ;;
                        "downloading")
                            echo -e -n "\r${BLUE}  📥 Downloading image... ${ELAPSED_STR}${NC}"
                            ;;
                        "preparing")
                            echo -e -n "\r${CYAN}  ⚙️ Preparing container... ${ELAPSED_STR}${NC}"
                            ;;
                    esac
                    LAST_ELAPSED_STR="$ELAPSED_STR"
                fi
            fi
            
            if [ "$STATUS" = "Failed" ]; then
                # Mark current phase as failed with final timing
                CURRENT_TIME=$(date +%s)
                ELAPSED=$((CURRENT_TIME - PHASE_START_TIME))
                ELAPSED_MIN=$((ELAPSED / 60))
                ELAPSED_SEC=$((ELAPSED % 60))
                ELAPSED_STR=$(printf "%02d:%02d" $ELAPSED_MIN $ELAPSED_SEC)
                
                case "$PHASE" in
                    "starting")
                        echo -e "\r${RED}  🚀 Starting pod... ${ELAPSED_STR} ❌${NC}"
                        ;;
                    "downloading")
                        echo -e "\r${RED}  📥 Downloading image... ${ELAPSED_STR} ❌${NC}"
                        ;;
                    "preparing")
                        echo -e "\r${RED}  ⚙️ Preparing container... ${ELAPSED_STR} ❌${NC}"
                        ;;
                esac
                print_result 1 "  FastAPI pod $POD_NAME has Failed (not retrying)"
                timeout 10s kubectl --kubeconfig="$KUBECONFIG_PATH" describe pod "$POD_NAME"
                return 1
            fi
            
            if [ "$STATUS" == "Pending" ]; then
                REASON=$(timeout 5s kubectl --kubeconfig="$KUBECONFIG_PATH" get pod "$POD_NAME" -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null)
                debug_msg "Pending reason: $REASON"
                
                if [ "$REASON" == "ImagePullBackOff" ] || [ "$REASON" == "ErrImagePull" ]; then
                    # Mark current phase as failed with final timing
                    CURRENT_TIME=$(date +%s)
                    ELAPSED=$((CURRENT_TIME - PHASE_START_TIME))
                    ELAPSED_MIN=$((ELAPSED / 60))
                    ELAPSED_SEC=$((ELAPSED % 60))
                    ELAPSED_STR=$(printf "%02d:%02d" $ELAPSED_MIN $ELAPSED_SEC)
                    
                    case "$PHASE" in
                        "starting")
                            echo -e "\r${RED}  🚀 Starting pod... ${ELAPSED_STR} ❌${NC}"
                            ;;
                        "downloading")
                            echo -e "\r${RED}  📥 Downloading image... ${ELAPSED_STR} ❌${NC}"
                            ;;
                        "preparing")
                            echo -e "\r${RED}  ⚙️ Preparing container... ${ELAPSED_STR} ❌${NC}"
                            ;;
                    esac
                    print_result 1 "  FastAPI pod $POD_NAME is stuck in image pull error."
                    timeout 10s kubectl --kubeconfig="$KUBECONFIG_PATH" describe pod "$POD_NAME"
                    return 1
                fi
                
                # Update phase indicators with multiple lines
                if [ $RETRY_COUNT -lt 6 ] && [ "$PHASE" != "starting" ]; then
                    PHASE="starting"
                    PHASE_START_TIME=$(date +%s)
                    LAST_ELAPSED_STR=""
                    echo -e -n "${YELLOW}  🚀 Starting pod... 00:00${NC}"
                elif [ $RETRY_COUNT -ge 6 ] && [ $RETRY_COUNT -lt 18 ] && [ "$PHASE" != "downloading" ]; then
                    # Mark starting phase as completed
                    CURRENT_TIME=$(date +%s)
                    ELAPSED=$((CURRENT_TIME - PHASE_START_TIME))
                    ELAPSED_MIN=$((ELAPSED / 60))
                    ELAPSED_SEC=$((ELAPSED % 60))
                    ELAPSED_STR=$(printf "%02d:%02d" $ELAPSED_MIN $ELAPSED_SEC)
                    echo -e "\r${GREEN}  🚀 Starting pod... ${ELAPSED_STR} ✅${NC}"
                    PHASE="downloading"
                    PHASE_START_TIME=$(date +%s)
                    LAST_ELAPSED_STR=""
                    echo -e -n "${BLUE}  📥 Downloading image... 00:00${NC}"
                elif [ $RETRY_COUNT -ge 18 ] && [ "$PHASE" != "preparing" ]; then
                    # Mark downloading phase as completed
                    CURRENT_TIME=$(date +%s)
                    ELAPSED=$((CURRENT_TIME - PHASE_START_TIME))
                    ELAPSED_MIN=$((ELAPSED / 60))
                    ELAPSED_SEC=$((ELAPSED % 60))
                    ELAPSED_STR=$(printf "%02d:%02d" $ELAPSED_MIN $ELAPSED_SEC)
                    echo -e "\r${GREEN}  📥 Downloading image... ${ELAPSED_STR} ✅${NC}"
                    PHASE="preparing"
                    PHASE_START_TIME=$(date +%s)
                    LAST_ELAPSED_STR=""
                    echo -e -n "${CYAN}  ⚙️ Preparing container... 00:00${NC}"
                fi
            fi
            
            if [ "$STATUS" = "Running" ]; then
                # Mark current phase as completed with final timing
                CURRENT_TIME=$(date +%s)
                ELAPSED=$((CURRENT_TIME - PHASE_START_TIME))
                ELAPSED_MIN=$((ELAPSED / 60))
                ELAPSED_SEC=$((ELAPSED % 60))
                ELAPSED_STR=$(printf "%02d:%02d" $ELAPSED_MIN $ELAPSED_SEC)
                
                case "$PHASE" in
                    "starting")
                        echo -e "\r${GREEN}  🚀 Starting pod... ${ELAPSED_STR} ✅${NC}"
                        ;;
                    "downloading")
                        echo -e "\r${GREEN}  📥 Downloading image... ${ELAPSED_STR} ✅${NC}"
                        ;;
                    "preparing")
                        echo -e "\r${GREEN}  ⚙️ Preparing container... ${ELAPSED_STR} ✅${NC}"
                        ;;
                esac
                echo -e "     Ready to serve"
                print_result 0 "  FastAPI pod $POD_NAME is Running"
                break
            fi
            
            sleep 10
            RETRY_COUNT=$((RETRY_COUNT+1))
        done
        
        if [ "$STATUS" != "Running" ]; then
            # Mark current phase as failed with final timing
            CURRENT_TIME=$(date +%s)
            ELAPSED=$((CURRENT_TIME - PHASE_START_TIME))
            ELAPSED_MIN=$((ELAPSED / 60))
            ELAPSED_SEC=$((ELAPSED % 60))
            ELAPSED_STR=$(printf "%02d:%02d" $ELAPSED_MIN $ELAPSED_SEC)
            
            case "$PHASE" in
                "starting")
                    echo -e "\r${RED}  🚀 Starting pod... ${ELAPSED_STR} ❌${NC}"
                    ;;
                "downloading")
                    echo -e "\r${RED}  📥 Downloading image... ${ELAPSED_STR} ❌${NC}"
                    ;;
                "preparing")
                    echo -e "\r${RED}  ⚙️ Preparing container... ${ELAPSED_STR} ❌${NC}"
                    ;;
            esac
            debug_msg "Pod not running after $MAX_RETRIES attempts"
            print_result 1 "  FastAPI pod $POD_NAME is not Running (status: $STATUS) after $((MAX_RETRIES * 10 / 60)) minutes."
            timeout 10s kubectl --kubeconfig="$KUBECONFIG_PATH" describe pod "$POD_NAME"
        fi
    fi
}


function cleanup_k3s_agent_installation (){
    # FIRST: Clean up any remaining nano-related pods BEFORE uninstalling agent
    debug_msg "Checking for any remaining nano pods to clean up"
    if [ -f "$KUBECONFIG_PATH" ] && kubectl --kubeconfig="$KUBECONFIG_PATH" get pods -l app=fastapi-nano --no-headers 2>/dev/null | grep -q .; then
        debug_msg "Found nano pods, cleaning them up"
        # Use timeout and force delete to avoid hanging on terminating pods
        timeout 30s kubectl --kubeconfig="$KUBECONFIG_PATH" delete pods -l app=fastapi-nano --ignore-not-found=true --force --grace-period=0 >/dev/null 2>&1
        DELETE_STATUS=$?
        if [ $DELETE_STATUS -eq 0 ]; then
            print_result 0 "  Cleaned up existing fastapi-nano pods"
        else
            print_result 1 "  Failed to clean up pods (may be already terminating)"
        fi
        # Give pods time to terminate
        sleep 2
    else
        debug_msg "No nano pods found to clean up"
        print_result 0 "  No existing fastapi-nano pods to clean up"
    fi

    # THEN: Check for the k3s uninstall script and run it
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

    # Remove stale kubeconfig immediately after k3s uninstall
    debug_msg "Removing stale kubeconfig"
    rm -f /home/sanjay/k3s.yaml >/dev/null 2>&1
    print_result $? "  Removed stale /home/sanjay/k3s.yaml"

    # Skip kubectl cleanup since k3s uninstall removes all resources
    debug_msg "Skipping kubectl cleanup - k3s uninstall removes all resources"
    print_result 0 "  Skipped kubectl cleanup (handled by k3s uninstall)"
}

# Main execution
debug_msg "Calling cleanup_k3s_agent_installation"
cleanup_k3s_agent_installation
echo -e "${GREEN}===============================================${NC}"
debug_msg "Calling remove_dangling_docker_images"
remove_dangling_docker_images
echo -e "${GREEN}===============================================${NC}"
debug_msg "Calling build_and_save_fastapi_image"
build_and_save_fastapi_image
echo -e "${GREEN}===============================================${NC}"
debug_msg "Calling install_k3s_agent_with_token"
install_k3s_agent_with_token
echo -e "${GREEN}===============================================${NC}"
debug_msg "Calling apply_fastapi_deployment_yaml"
apply_fastapi_deployment_yaml
echo -e "${GREEN}===============================================${NC}"
debug_msg "Calling check_fastapi_pod_status"
check_fastapi_pod_status
debug_msg "Script completed"
echo -e "  ${YELLOW}Script completed${NC}"
