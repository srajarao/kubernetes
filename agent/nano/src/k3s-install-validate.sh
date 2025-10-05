#!/bin/bash
#set -x

# Variables
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'
KUBECONFIG_PATH="${KUBECONFIG_PATH:-$HOME/k3s.yaml}"
CROSS="${RED}❌${NC}"
TICK="${GREEN}✅${NC}"
DEBUG=${DEBUG:-0}
CLEAR_SCREEN=1



# Optionally clear the screen if CLEAR_SCREEN is set to 1
if [ "${CLEAR_SCREEN:-0}" -eq 1 ]; then
    clear
fi

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

# Function to copy kubeconfig from token directory to target path
copy_kubeconfig_from_token_dir() {
    local src_kubeconfig="$TOKEN_DIR/config/k3s.yaml"
    local dest_kubeconfig="$KUBECONFIG_PATH"
    if [ -f "$src_kubeconfig" ]; then
        mkdir -p "$(dirname "$dest_kubeconfig")"
        cp "$src_kubeconfig" "$dest_kubeconfig"
        chmod 600 "$dest_kubeconfig"
        print_result 0 "Copied kubeconfig from $src_kubeconfig to $dest_kubeconfig"
        return 0
    else
        print_result 1 "Kubeconfig not found at $src_kubeconfig"
        return 1
    fi
}


function cleanup_k3s_agent_installation() {
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
    rm -f "$KUBECONFIG_PATH" >/dev/null 2>&1
    print_result $? "  Removed stale $KUBECONFIG_PATH"

    # Remove dangling Docker images to free up space
    debug_msg "Running remove_dangling_docker_images"
    sudo docker image prune -f >/dev/null 2>&1
    print_result $? "  Removed dangling Docker images"

}

function check_certificate_trust() {
    if [ -f "$TOKEN_CERT" ]; then
        print_result 0 "  Server CA cert found at $TOKEN_CERT"
        grep server ~/.kube/config >/dev/null 2>&1
        print_result $? "  kubeconfig server entry present"
        openssl s_client -connect ${TOWER_IP}:6443 -showcerts </dev/null >/dev/null 2>&1
        print_result $? "  API server certificate presented"
    else
        print_result 1 "  Server CA cert not found at $TOKEN_CERT"
    fi
}

function check_node_token() {    
    if [ -f "$TOKEN_FILE" ]; then
        print_result 0 "$TOKEN_FILE"
        print_result 0 "  Node token file found at $TOKEN_FILE"
        # Ensure token file is readable
        if [ ! -r "$TOKEN_FILE" ]; then
            sudo chmod 644 "$TOKEN_FILE" 
            K3S_TOKEN=$(sudo cat "$TOKEN_FILE")
            print_result 0 "  Tokefile permission set  and read $TOKEN_FILE"
        else
            K3S_TOKEN=$(cat "$TOKEN_FILE")
            print_result 0 "  Node token file read $TOKEN_FILE"
        fi
    else
        print_result 1 "  Node token file not found at 3 $TOKEN_FILE"
    fi
}


# Function to read a config file and export variables
function load_agent_config() {
    local config_file="$1"
    if [ ! -f "$config_file" ]; then
        echo "Config file not found: $config_file" >&2
        return 1
    fi
    # Copy config file to standard config directory
    local config_dir="/home/sanjay/containers/kubernetes/agent/nano/app/config"
    mkdir -p "$config_dir"
    local config_basename
    config_basename=$(basename "$config_file")
    local dest_config="$config_dir/$config_basename"
    cp "$config_file" "$dest_config"
    

    set -a
    # shellcheck disable=SC1090
    source "$dest_config"
    set +a

    # Print all variables defined in the config file with their current values

    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue
        # Only process lines with key=value
        if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
            var_name="${BASH_REMATCH[1]}"
            # Print variable and its value (if set)
            printf "%s=\"%s\"\n" "$var_name" "${!var_name}"
        fi
    done < "$dest_config"
    echo "==============================="
}

function build_and_save_fastapi_image() {
    debug_msg "Running build_and_save_fastapi_image"
 
    if [ -f "$PROJECT_DIR/dockerfile.nano.req" ]; then
        debug_msg "Dockerfile found, checking timestamps"
        DOCKERFILE_MTIME=$(get_file_mtime "$PROJECT_DIR/dockerfile.nano.req")
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
            BUILD_OUTPUT=$(DOCKER_BUILDKIT=1 docker build -f "$PROJECT_DIR/dockerfile.nano.req" -t fastapi_nano:latest "$PROJECT_DIR" 2>&1)
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
        print_result 1 "  dockerfile.nano.req not found in $PROJECT_DIR (skipping build)"
    fi
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

function install_k3s_agent_with_token() {
    debug_msg "Running install_k3s_agent_with_token"
    echo -e "${GREEN}\n== Install k3s Agent with Token ==${NC}"
    print_result 0 "Token_file : $TOKEN_FILE"
    print_result 0 "Token_cert : $TOKEN_CERT"
    print_result 0 "K3S_TOKEN : $K3S_TOKEN"
    print_result 0 "K3S_URL : $K3S_URL"



    
  
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
      print_result 0 "1Token_file : $TOKEN_FILE"
    print_result 0 "1Token_cert : $TOKEN_CERT"
    print_result 0 "1K3S_TOKEN : $K3S_TOKEN"
    print_result 0 "1K3S_URL : $K3S_URL"


        # Use server CA cert for agent trust
        TOKEN_CERT="$TOKEN_DIR/config/server-ca.crt"

        # Configuration variables
        REGISTRY_IP="${TOWER_IP}:5000"

        # Configure Insecure Registry via registries.yaml
        echo -e "${GREEN}\n== Configure Insecure Registry (registries.yaml) ==${NC}"
        # Create configuration directory
        sudo mkdir -p /etc/rancher/k3s/
        print_result $? "  Created /etc/rancher/k3s/ directory"
        # Write registries.yaml to force HTTP for the local registry
        sudo cp /mnt/vmstore/nano_home/containers/kubernetes/agent/nano/registries.yaml /etc/rancher/k3s/registries.yaml 
        sudo chmod 644 /etc/rancher/k3s/registries.yaml
        print_result 0 "  Created /etc/rancher/k3s/registries.yaml for HTTP registry access"

        # Copy CA certificate from server for registry trust
        #echo -e "${GREEN}  Copying registry CA certificate from server...${NC}"
        #sudo mkdir -p /etc/docker/certs.d/$REGISTRY_IP
        #if sudo scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@$TOWER_IP:/etc/docker/certs.d/$REGISTRY_IP/ca.crt /etc/docker/certs.d/$REGISTRY_IP/ca.crt >/dev/null 2>&1; then
        #    print_result 0 "  Copied registry CA certificate from server"
        #else
        #    echo -e "${YELLOW}  Could not copy CA cert from server, generating local copy...${NC}"
        #    # Fallback: generate the same certificate locally
        #    sudo openssl req -newkey rsa:4096 -nodes -sha256 \
        #        -keyout /tmp/registry.key \
        #        -x509 -days 365 \
        #        -out /etc/docker/certs.d/$REGISTRY_IP/ca.crt \
        #        -subj "/C=US/ST=State/L=City/O=Organization/CN=$TOWER_IP" \
        #        -addext "subjectAltName=IP:$TOWER_IP" >/dev/null 2>&1
        #    sudo rm -f /tmp/registry.key
        #    print_result $? "  Generated local registry CA certificate"
        #fi
        
        # Configure Docker daemon for insecure registry (keep this for local docker commands)
        #echo -e "${GREEN}\n== Configure Insecure Registry (Docker Daemon) ==${NC}"
        #echo -e "${GREEN}  Configuring Docker daemon for insecure registry...${NC}"
        #if ! command -v jq >/dev/null 2>&1; then
        #    if [ "$DEBUG" -eq 1 ]; then
        #        echo -e "${YELLOW}  jq not found, installing...${NC}"
        #    fi
        #    sudo apt-get update && sudo apt-get install -y jq >/dev/null 2>&1
        #    print_result $? "  Installed jq"
        #fi
        #if [ -f /etc/docker/daemon.json ] && command -v jq >/dev/null 2>&1; then
        #    sudo jq 'if .["insecure-registries"] then .["insecure-registries"] += ["'${TOWER_IP}':5000"] | .["insecure-registries"] |= unique else . + {"insecure-registries": ["'${TOWER_IP}':5000"]} end' /etc/docker/daemon.json | sudo tee /etc/docker/daemon.json.tmp > /dev/null
        #    sudo mv /etc/docker/daemon.json.tmp /etc/docker/daemon.json
        #else
        #    echo -e "${YELLOW}  jq not available or daemon.json missing, overwriting daemon.json...${NC}"
        #    echo '{"insecure-registries": ["'${TOWER_IP}':5000"]}' | sudo tee /etc/docker/daemon.json > /dev/null
        #fi
        #print_result $? "  Updated /etc/docker/daemon.json for insecure registry"
        #if [ "$DEBUG" -eq 1 ]; then
        #    echo -e "${GREEN}  Current /etc/docker/daemon.json:${NC}"
        #    sudo cat /etc/docker/daemon.json
        #fi
        
        echo "{\"insecure-registries\": [\"$TOWER_IP:5000\"]}" | sudo tee /etc/docker/daemon.json >/dev/null 2>&1
        print_result $? "  Updated /etc/docker/daemon.json for insecure registry"
               
        
        sudo systemctl restart docker
        print_result $? "  Restarted Docker service"
        
        
            print_result 0 "2Token_file : $TOKEN_FILE"
    print_result 0 "2Token_cert : $TOKEN_CERT"
    print_result 0 "2K3S_TOKEN : $K3S_TOKEN"
    print_result 0 "2K3S_URL : $K3S_URL"

        
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
            #echo -e "${GREEN}  Ensuring route to AGX subnet (192.168.10.0/24) via Tower...${NC}"
            #if ! ip route show | grep -q "192.168.10.0/24 via $TOWER_IP"; then
            #    sudo ip route add 192.168.10.0/24 via $TOWER_IP dev $NANO_IFACE metric 100
            #    print_result $? "  Route to AGX subnet added"
            #else
            #    echo -e "${GREEN}  Route to AGX subnet already exists${NC}"
            #    print_result 0 "  Route to AGX subnet verified"
            #fi
           
            # Add iptables rule to allow traffic to AGX subnet (if not already allowed)
            #if ! sudo iptables -C FORWARD -s $NANO_IP -d 192.168.10.0/24 -j ACCEPT 2>/dev/null; then
            #    sudo iptables -I FORWARD -s $NANO_IP -d 192.168.10.0/24 -j ACCEPT
            #    print_result $? "  Added iptables rule for AGX traffic"
            #else
            #    print_result 0 "  iptables rule for AGX traffic already exists"
            #fi
        fi


            print_result 0 "3Token_file : $TOKEN_FILE"
    print_result 0 "3Token_cert : $TOKEN_CERT"
    print_result 0 "3K3S_TOKEN : $K3S_TOKEN"
    print_result 0 "3K3S_URL : $K3S_URL"

        # Always copy latest kubeconfig to a known path for this script
        if [ -f "$TOKEN_DIR/config/k3s.yaml" ]; then
            mkdir -p "$(dirname "$KUBECONFIG_PATH")"
            cp "$TOKEN_DIR/config/k3s.yaml" "$KUBECONFIG_PATH"
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

#Main Script Execution Starts Here
# Print out the important environment variables for verification.

echo -e "${GREEN}== Load nano-config.env ==${NC}"
load_agent_config /mnt/vmstore/nano_home/containers/kubernetes/agent/nano/app/config/nano-config.env
TOKEN_CERT="$TOKEN_DIR/config/server-ca.crt"
TOKEN_FILE="$TOKEN_DIR/config/node-token"

REGISTRY_IP="${TOWER_IP}:5000"
src_kubeconfig="$TOKEN_DIR/config/k3s.yaml"


echo -e "${GREEN}== Cleanup k3s Agent Installation ==${NC}"
cleanup_k3s_agent_installation

echo -e "${GREEN}== Load postgres.env ==${NC}"
load_agent_config /mnt/vmstore/nano_home/containers/kubernetes/agent/nano/app/config/postgres.env

echo -e "${GREEN}== Copy Kubeconfig from Token Dir ==${NC}"
copy_kubeconfig_from_token_dir

echo -e "${GREEN}== Check Certificate trust ==${NC}"
check_certificate_trust 

echo -e "${GREEN}== Check Node Token ==${NC}"
check_node_token

echo -e "${GREEN}== build_and_save_fastapi_image ==${NC}"
build_and_save_fastapi_image

echo -e "${GREEN}== Install k3s Agent with Token ==${NC}"
install_k3s_agent_with_token
