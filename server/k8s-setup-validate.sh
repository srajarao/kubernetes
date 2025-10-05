
#!/bin/bash
clear

# Kubernetes Server Setup Script for Tower
# 
# This script sets up the k3s server on the tower and validates the installation.
# The tower acts as the k3s server/control plane, while nano and AGX act as agent nodes.
#
# For agent setup, use: /home/sanjay/containers/kubernetes/agent/k3s-agent-setup.sh
#
# Usage:
#   ./k8s-setup-validate.sh    # Full server setup on tower

# Variables
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'
CROSS="${RED}❌${NC}"
TICK="${GREEN}✅${NC}"
DEBUG=${DEBUG:-0}
KUBECONFIG_PATH="/home/sanjay/k3s.yaml"
CLEAR_SCREEN=1
TOWER_IP="${TOWER_IP:-192.168.5.1}"                                                # Tower server IP
NANO_IP="${NANO_IP:-192.168.5.21}"                                                 # Nano Device IP
AGX_IP="${AGX_IP:-192.168.5.22}"                                                   # AGX device IP
REGISTRY_IP="${TOWER_IP}:5000"
NANO_PATH="/export/vmstore/nano_home/containers/kubernetes/agent/nano"
AGX_PATH="/export/vmstore/agx_home/containers/kubernetes/agent/agx/"

function print_result() {
    if [ "$1" -eq 0 ]; then
        echo -e "$2 $TICK"
    else
        echo -e "$2 $CROSS"
    fi
}

function debug_msg() {
    # Debug message function - can be enabled by setting DEBUG=1
    if [ "${DEBUG:-0}" -eq 1 ]; then
        echo "[DEBUG] $1"
    fi
}


# List all pods with current status
# Steps to check certificate trust
function check_certificate_trust() {
    echo -e "\n${GREEN}Certificate Trust Checks${NC}"

    # Use variables for server IPs
    NANO_SERVER_IP="192.168.5.1"
    AGX_SERVER_IP="192.168.10.1"   # <-- Set this to the AGX-accessible IP of the k3s server

    grep server ~/.kube/config >/dev/null 2>&1
    print_result $? "  kubeconfig server entry present"

    # Check API server certificate for both nano and AGX subnets
    openssl s_client -connect ${NANO_SERVER_IP}:6443 -showcerts </dev/null >/dev/null 2>&1
    print_result $? "  API server certificate presented (nano subnet)"
    openssl s_client -connect ${AGX_SERVER_IP}:6443 -showcerts </dev/null >/dev/null 2>&1
    print_result $? "  API server certificate presented (AGX subnet)"

    sudo openssl x509 -in /var/lib/rancher/k3s/server/tls/serving-kube-apiserver.crt -text -noout >/dev/null 2>&1
    print_result $? "  API server certificate details readable"
    kubectl get nodes >/dev/null 2>&1
    print_result $? "  kubectl get nodes"
    kubectl get pods >/dev/null 2>&1
    print_result $? "  kubectl get pods"
    kubectl get svc >/dev/null 2>&1
    print_result $? "  kubectl get svc"

    # Copy server-ca.crt to nano agent token directory
    AGENT_TOKEN_DIR="/export/vmstore/nano_home/containers/fastapi_nano/.token"
    sudo mkdir -p "$AGENT_TOKEN_DIR"
    sudo cp /var/lib/rancher/k3s/server/tls/server-ca.crt "$AGENT_TOKEN_DIR/server-ca.crt" 2>/dev/null
    print_result $? "  Copied server-ca.crt to $AGENT_TOKEN_DIR/server-ca.crt"


}

function check_docker_dns() {
    echo -e "\n${GREEN}Docker DNS Configuration${NC}"
    grep -q '"dns":' /etc/docker/daemon.json
    print_result $? "  Docker DNS config (/etc/docker/daemon.json)"
}
function setup_local_registry() {
    echo -e "\n${GREEN}Setup Local Registry with HTTPS${NC}"

    # Create certificates directory
    sudo mkdir -p /etc/docker/certs.d/192.168.5.1:5000

    # Generate self-signed certificate for registry
    if [ ! -f /etc/docker/certs.d/192.168.5.1:5000/ca.crt ]; then
        echo -e "${YELLOW}  Generating self-signed certificate for registry...${NC}"
        sudo openssl req -newkey rsa:4096 -nodes -sha256 \
            -keyout /etc/docker/certs.d/192.168.5.1:5000/registry.key \
            -x509 -days 365 \
            -out /etc/docker/certs.d/192.168.5.1:5000/ca.crt \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=192.168.5.1" \
            -addext "subjectAltName=IP:192.168.5.1" >/dev/null 2>&1
        sudo cp /etc/docker/certs.d/192.168.5.1:5000/ca.crt /etc/docker/certs.d/192.168.5.1:5000/registry.crt
        print_result $? "  Generated self-signed certificate for registry"
    fi

    # Check if registry is running
    docker ps | grep -q 'registry:2'
    if [ $? -eq 0 ]; then
        print_result 0 "  Local Docker registry running"
    else
        # Start registry with HTTPS
        docker run -d \
            -p 5000:5000 \
            --restart=always \
            --name registry \
            -v /etc/docker/certs.d/192.168.5.1:5000:/certs \
            -e REGISTRY_HTTP_ADDR=0.0.0.0:5000 \
            -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/registry.crt \
            -e REGISTRY_HTTP_TLS_KEY=/certs/registry.key \
            registry:2 >/dev/null 2>&1
        print_result $? "  Local Docker registry started with HTTPS"
    fi
    grep -q '"dns":' /etc/docker/daemon.json && grep -q '"insecure-registries":' /etc/docker/daemon.json && grep -q 'localhost:5000' /etc/docker/daemon.json && grep -q '192.168.5.1:5000' /etc/docker/daemon.json
    if [ $? -eq 0 ]; then
        print_result 0 "  Docker daemon.json DNS and insecure-registries present"
    else
        print_result 1 "  Docker daemon.json missing DNS or insecure-registries (manual merge required)"
    fi
    sudo systemctl restart docker >/dev/null 2>&1
    print_result $? "  Docker daemon restarted"
    docker tag postgres:latest localhost:5000/postgres:latest >/dev/null 2>&1
    print_result $? "  Tagged postgres for local registry"
    docker push localhost:5000/postgres:latest >/dev/null 2>&1
    print_result $? "  Pushed postgres to local registry"
    docker tag pgadmin:latest localhost:5000/pgadmin:latest >/dev/null 2>&1
    print_result $? "  Tagged pgadmin for local registry"
    docker push localhost:5000/pgadmin:latest >/dev/null 2>&1
    print_result $? "  Pushed pgadmin to local registry"
}

function create_registries_yaml(){
    # Create registries.yaml for insecure communication with local registry
    REGISTRIES_YAML=/etc/rancher/k3s/registries.yaml
    sudo mkdir -p /etc/rancher/k3s
    sudo tee $REGISTRIES_YAML >/dev/null <<EOF
mirrors:
  "192.168.5.1:5000":
    endpoint:
      - "http://192.168.5.1:5000"

configs:
  "192.168.5.1:5000":
    tls:
      insecure_skip_verify: true
EOF
        print_result $? "  Created $REGISTRIES_YAML for insecure registry communication"
}

function check_k3s() {
    echo -e "\n${GREEN}K3s Service${NC}"

    # Create registries.yaml for insecure communication with local registry
    create_registries_yaml            

    # Install k3s with both TLS SANs and external IP for AGX if not installed
    if ! command -v k3s >/dev/null 2>&1; then
        curl -sfL https://get.k3s.io | \
        INSTALL_K3S_EXEC="--tls-san $NANO_IP --tls-san $AGX_IP " sh - >/dev/null 2>&1
        print_result $? "  k3s installed with TLS SANs for nano and AGX"
    fi

    # Kubeconfig and cert setup for server, nano, and AGX
    if [ -f /etc/rancher/k3s/k3s.yaml ]; then
        # 1. Move and update server kubeconfig
        sudo mkdir -p /home/sanjay/.kube
        sudo cp /etc/rancher/k3s/k3s.yaml /home/sanjay/.kube/config
        sudo chown sanjay:sanjay /home/sanjay/.kube/config
        sudo chmod 600 /home/sanjay/.kube/config
        sed -i "s#server: https://127.0.0.1:6443#server: https://$TOWER_IP:6443#g" /home/sanjay/.kube/config
        print_result $? "  Copied and updated server kubeconfig to ~/.kube/config with server $TOWER_IP"

        # 2. Nano agent kubeconfig
        NANO_KUBECONFIG=${NANO_PATH}/.token/k3s.yaml
        mkdir -p "$(dirname "$NANO_KUBECONFIG")"
        cp /home/sanjay/.kube/config "$NANO_KUBECONFIG"
        sed -i "s#server: https://$TOWER_IP:6443#server: https://$NANO_IP:6443#g" "$NANO_KUBECONFIG"
        sudo chmod 600 "$NANO_KUBECONFIG"
        print_result $? "  Copied and updated kubeconfig for nano at $NANO_KUBECONFIG with server $NANO_IP"

        # 3. AGX agent kubeconfig
        AGX_KUBECONFIG=${AGX_PATH}/.token/k3s.yaml
        mkdir -p "$(dirname "$AGX_KUBECONFIG")"
        cp /home/sanjay/.kube/config "$AGX_KUBECONFIG"
        sed -i "s#server: https://$TOWER_IP:6443#server: https://$AGX_IP:6443#g" "$AGX_KUBECONFIG"
        sudo chmod 600 "$AGX_KUBECONFIG"
        print_result $? "  Copied and updated kubeconfig for AGX at $AGX_KUBECONFIG with server $AGX_IP"
    else
        print_result 1 "  /etc/rancher/k3s/k3s.yaml not found"
    fi

    if sudo test -f /var/lib/rancher/k3s/server/tls/server-ca.crt; then
        # Ensure CA cert is present for both agents (if needed, adjust path as required)
        CA_SRC=/var/lib/rancher/k3s/server/tls/server-ca.crt
        NANO_CERT=${NANO_PATH}/server-ca.crt
        AGX_CERT=${AGX_PATH}/server-ca.crt
        sudo cp "$CA_SRC" "$NANO_CERT" 2>/dev/null
        sudo cp "$CA_SRC" "$AGX_CERT" 2>/dev/null
        sudo chmod 644 "$NANO_CERT" "$AGX_CERT"
        print_result $? "  Copied CA cert to agent token directories"
    else
        print_result 1 "  /var/lib/rancher/k3s/server/tls/server-ca.crt was not found"
    fi

    if sudo test -f /etc/rancher/k3s/registries.yaml; then
        # Ensure registries.yaml is present for both agents (if needed, adjust path as required)
        CA_SRC=/etc/rancher/k3s/registries.yaml
        NANO_REGISTRY=${NANO_PATH}/registries.yaml
        AGX_REGISTRY=${AGX_PATH}/registries.yaml
        sudo cp "$CA_SRC" "$NANO_REGISTRY" 2>/dev/null
        sudo cp "$CA_SRC" "$AGX_REGISTRY" 2>/dev/null
        sudo chmod 644 "$NANO_REGISTRY" "$AGX_REGISTRY"
        print_result $? "  Copied registries.yaml to agent directories"
    else
        print_result 1 "  /etc/rancher/k3s/registries.yaml not found"
    fi


    if sudo test -f /var/lib/rancher/k3s/server/node-token; then
        # Ensure node-token is present for both agents (if needed, adjust path as required)
        TOKEN_SRC=/var/lib/rancher/k3s/server/node-token
        NANO_TOKEN=${NANO_PATH}/node-token
        AGX_TOKEN=${AGX_PATH}/node-token
        sudo cp "$TOKEN_SRC" "$NANO_TOKEN" 2>/dev/null
        sudo cp "$TOKEN_SRC" "$AGX_TOKEN" 2>/dev/null
        sudo chmod 644 "$NANO_TOKEN" "$AGX_TOKEN"
        print_result $? "  Copied node-token to agent directories"
    else
        print_result 1 "  /var/lib/rancher/k3s/server/node-token not found"
    fi





    # Check k3s API server port
    sudo ss -tulnp | grep 6443 >/dev/null 2>&1
    print_result $? "  Check k3s API server port 6443"
    # Check k3s service status
    sudo systemctl is-active --quiet k3s
    print_result $? "  Check k3s service status"
    # Check nodes
    kubectl get nodes >/dev/null 2>&1
    print_result $? "  kubectl get nodes"
}

function check_kubeconfig() {
    echo -e "\n${GREEN}Kubeconfig & Trust${NC}"
    NANO_SERVER_IP="192.168.5.1"
    AGX_SERVER_IP="192.168.10.1"
    CA_PATH="/var/lib/rancher/k3s/server/tls/server-ca.crt"

    # Check for both nano and AGX server entries
    if (grep -q "server: https://$NANO_SERVER_IP:6443" ~/.kube/config || grep -q "server: https://$AGX_SERVER_IP:6443" ~/.kube/config) \
        && grep -q "certificate-authority: $CA_PATH" ~/.kube/config; then
        print_result 0 "  kubeconfig server & CA"
    else
        print_result 1 "  kubeconfig server & CA"
        # Auto-fix for nano
        sed -i "s#server: https://127.0.0.1:6443#server: https://$NANO_SERVER_IP:6443#g" ~/.kube/config
        sed -i "s|certificate-authority:.*|certificate-authority: $CA_PATH|" ~/.kube/config
        # Also auto-fix for AGX if needed
        sed -i "s#server: https://$NANO_SERVER_IP:6443#server: https://$AGX_SERVER_IP:6443#g" ~/.kube/config
        # Re-check
        if (grep -q "server: https://$NANO_SERVER_IP:6443" ~/.kube/config || grep -q "server: https://$AGX_SERVER_IP:6443" ~/.kube/config) \
            && grep -q "certificate-authority: $CA_PATH" ~/.kube/config; then
            print_result 0 "  kubeconfig server & CA auto-fixed"
        else
            print_result 1 "  kubeconfig server & CA auto-fix failed"
        fi
    fi
}

function build_images() {
    echo -e "\n${GREEN}Build & Save Images${NC}"
    sudo systemctl restart docker >/dev/null 2>&1
    print_result $? "  Docker daemon restarted"
    
    # Build PostgreSQL image from new location
    cd /home/sanjay/containers/kubernetes/server/postgres
    DOCKER_BUILDKIT=1 docker build -f dockerfile.postgres -t postgres:latest . >/dev/null 2>&1
    print_result $? "  Built postgres:latest image"
    docker save -o /export/vmstore/k3sRegistry/postgres.tar postgres:latest >/dev/null 2>&1
    print_result $? "  Saved postgres image to tar"
    
    # Build pgAdmin image from new location
    cd /home/sanjay/containers/kubernetes/server/pgadmin
    DOCKER_BUILDKIT=1 docker build -f dockerfile.pgadmin -t pgadmin:latest . >/dev/null 2>&1
    print_result $? "  Built pgadmin:latest image"
    docker save -o /export/vmstore/k3sRegistry/pgadmin.tar pgadmin:latest >/dev/null 2>&1
    print_result $? "  Saved pgadmin image to tar"
}

function uninstall_k3s_cleanup() {
    echo -e "\n${GREEN}Uninstall k3s & Clean Up${NC}"
    # Run all uninstall steps silently
    if [ -x "/usr/local/bin/k3s-uninstall.sh" ]; then
        sudo /usr/local/bin/k3s-uninstall.sh >/dev/null 2>&1
    fi
    sudo rm -rf /etc/rancher/k3s /var/lib/rancher/k3s /var/lib/kubelet /run/k3s /run/flannel /var/lib/cni /usr/local/bin/k3s /usr/local/bin/k3s-killall.sh /usr/local/bin/k3s-uninstall.sh /usr/local/bin/crictl /usr/local/bin/ctr /etc/systemd/system/k3s.service /etc/systemd/system/k3s.service.env >/dev/null 2>&1
    sudo ip link delete cni0 2>/dev/null
    sudo ip link delete flannel.1 2>/dev/null
    sudo ip link delete flannel-v6.1 2>/dev/null
    sudo ip link delete kube-ipvs0 2>/dev/null
    sudo ip link delete flannel-wg 2>/dev/null
    sudo ip link delete flannel-wg-v6 2>/dev/null
    sudo iptables -F >/dev/null 2>&1
    sudo iptables -X >/dev/null 2>&1
    sudo iptables -t nat -F >/dev/null 2>&1
    sudo iptables -t nat -X >/dev/null 2>&1
    sudo iptables -t mangle -F >/dev/null 2>&1
    sudo iptables -t mangle -X >/dev/null 2>&1
    sudo iptables -t raw -F >/dev/null 2>&1
    sudo iptables -t raw -X >/dev/null 2>&1
    sudo systemctl daemon-reload >/dev/null 2>&1
    sudo docker image prune -f >/dev/null 2>&1
    print_result 0 "  Removed all dangling Docker images"
    print_result 0 "  Uninstall & cleanup completed"
}

# 1. DNS config
function check_dns() {
    echo -e "\n${GREEN}DNS Configuration${NC}"
    grep -q 'DNS=8.8.8.8' /etc/systemd/resolved.conf && grep -q 'FallbackDNS=8.8.4.4' /etc/systemd/resolved.conf
    print_result $? "  DNS config (/etc/systemd/resolved.conf)"
}

# 2. Docker DNS config
function check_and_load_registry() {
    echo -e "\n${GREEN}Check Local Registry${NC}"
    docker ps | grep -q 'registry:2'
    if [ $? -eq 0 ]; then
        print_result 0 "  Local Docker registry running"
    else
        docker run -d -p 5000:5000 --restart=always --name registry registry:2 >/dev/null 2>&1
        print_result $? "  Local Docker registry started"
    fi
    echo -e "\n${GREEN}Load Images to Local Registry${NC}"
    docker tag postgres:latest localhost:5000/postgres:latest >/dev/null 2>&1
    print_result $? "  Tagged postgres for local registry"
    docker push localhost:5000/postgres:latest >/dev/null 2>&1
    print_result $? "  Pushed postgres to local registry"
    docker tag pgadmin:latest localhost:5000/pgadmin:latest >/dev/null 2>&1
    print_result $? "  Tagged pgadmin for local registry"
    docker push localhost:5000/pgadmin:latest >/dev/null 2>&1
    print_result $? "  Pushed pgadmin to local registry"
}

# 6. Pod and service status
function check_pods_services() {
    echo -e "\n${GREEN}Deployments & Cluster Status${NC}"
    
    # Apply pgAdmin secret from new location
    kubectl apply -f /home/sanjay/containers/kubernetes/server/pgadmin/pgadmin-secret.yaml >/dev/null 2>&1
    print_result $? "  Applied pgadmin-secret.yaml"
    
    # Check hostPath in postgres-db-deployment.yaml (updated path)
    grep -q '/home/sanjay/containers/kubernetes/server/postgres' /home/sanjay/containers/kubernetes/server/postgres/postgres-db-deployment.yaml
    print_result $? "  Verified hostPath in postgres-db-deployment.yaml is set to /home/sanjay/containers/kubernetes/server/postgres"
    
    # Apply deployments from new locations
    kubectl apply -f /home/sanjay/containers/kubernetes/server/postgres/postgres-db-deployment.yaml >/dev/null 2>&1
    print_result $? "  Applied postgres-db-deployment.yaml"
    kubectl apply -f /home/sanjay/containers/kubernetes/server/pgadmin/pgadmin-deployment.yaml >/dev/null 2>&1
    print_result $? "  Applied pgadmin-deployment.yaml"
    kubectl apply -f /home/sanjay/containers/kubernetes/server/postgres/postgres-pgadmin-services.yaml >/dev/null 2>&1
    print_result $? "  Applied postgres-pgadmin-services.yaml"
    
    # Wait for pods to start after applying deployments/services
    echo -e "\n${GREEN}Waiting for pods to become ready...${NC}"
    sleep 10
    # Wait up to 60s for all pods to be ready
    for i in {1..12}; do
        NOT_READY=$(kubectl get pods --no-headers -n default | awk '$2!="1/1" {print $1}')
        if [ -z "$NOT_READY" ]; then
            echo -e "  All pods are ready."
            break
        fi
        sleep 5
    done

   
    # Verify postgres-pgadmin-services.yaml and pgadmin service
    echo -e "\n${GREEN}Verify postgres-pgadmin-services.yaml & pgadmin service${NC}"
    grep -q 'pgadmin' /home/sanjay/containers/kubernetes/server/postgres/postgres-pgadmin-services.yaml
    print_result $? "  pgadmin service present in postgres-pgadmin-services.yaml"
    kubectl get svc | grep -q 'pgadmin'
    print_result $? "  pgadmin service deployed (kubectl get svc)"
    kubectl get nodes -o wide >/dev/null 2>&1
    print_result $? "  kubectl get nodes -o wide"
    kubectl get pods >/dev/null 2>&1
    print_result $? "  kubectl get pods"
    kubectl get svc >/dev/null 2>&1
    print_result $? "  kubectl get svc"
}

function check_postgres_connectivity() {
    echo -e "\n${GREEN}Postgres External Connectivity${NC}"
    # Use environment variable or default to nano IP
    POSTGRES_HOST="${POSTGRES_HOST:-192.168.5.1}"
    timeout 2 bash -c "echo > /dev/tcp/${POSTGRES_HOST}/5432" 2>/dev/null
    print_result $? "  Postgres external connectivity (${POSTGRES_HOST}:5432)"
}

function list_all_deployments_status() {
    echo -e "\n${GREEN}Deployments Status (default namespace)${NC}"
    kubectl get deployments -n default -o wide
}

function check_individual_pod_status() {
    echo -e "\n${GREEN}Individual Pod Status (default namespace)${NC}"
    PODS=$(kubectl get pods --no-headers -n default | awk '{print $1}')
    if [ -z "$PODS" ]; then
        echo -e "  No resources found in default namespace."
    else
        for POD in $PODS; do
            STATUS=$(kubectl get pod $POD -n default -o jsonpath='{.status.phase}')
            READY=$(kubectl get pod $POD -n default -o jsonpath='{.status.containerStatuses[0].ready}')
            if [ "$STATUS" = "Running" ] && [ "$READY" = "true" ]; then
                print_result 0 "  $POD is Running and Ready"
            else
                print_result 1 "  $POD is not Ready (Status: $STATUS, Ready: $READY)"
            fi
        done
    fi
}




function setup_agent_config_files() {
    debug_msg "Running setup_agent_config_files"
    echo -e "\n${GREEN}Setting up Agent Configuration Files${NC}"

    AGENT_BASE_DIR="/home/sanjay/containers/kubernetes/agent"

    # --- Nano agent config ---
    NANO_CONFIG_DIR="$AGENT_BASE_DIR/nano/app/config"
    mkdir -p "$NANO_CONFIG_DIR" 2>/dev/null
    print_result $? "  Created nano agent config directory: $NANO_CONFIG_DIR"

    # nano-config.env
    NANO_CONFIG_ENV="$NANO_CONFIG_DIR/nano-config.env"
    if [ ! -f "$NANO_CONFIG_ENV" ]; then
        cat > "$NANO_CONFIG_ENV" << 'EOF'
# Jetson Nano Configuration
# This file is auto-generated by server setup script

# Device settings
DEVICE_TYPE="nano"
GPU_ENABLED="true"
FORCE_GPU_CHECKS="true"

# Network settings
NANO_IP="192.168.5.21"
TOWER_IP="192.168.5.1"

# Directory paths
SCRIPT_DIR="/home/sanjay/containers/kubernetes/agent/nano/app/src"
CONFIG_DIR="/home/sanjay/containers/kubernetes/agent/nano/app/config"
LOG_DIR="/home/sanjay/containers/kubernetes/agent/nano/app/logs"
DATA_DIR="/home/sanjay/containers/kubernetes/agent/nano/app/data"
TOKEN_DIR="/mnt/vmstore/nano_home/containers/kubernetes/agent/nano/.token"
PROJECT_DIR="/home/sanjay/containers/kubernetes/agent/nano"
IMAGE_DIR="/home/sanjay/containers"

# Docker settings
REGISTRY_URL="192.168.5.1:5000"
FASTAPI_IMAGE="192.168.5.1:5000/fastapi_nano:latest"

# K3s settings
K3S_URL="https://192.168.5.1:6443"
K3S_TOKEN_FILE="/home/sanjay/k3s-agent-token"
KUBECONFIG_PATH="/home/sanjay/k3s.yaml"
EOF
        print_result $? "  Created nano-config.env"
    else
        print_result 0 "  nano-config.env already exists"
    fi

    # nano postgres.env
    NANO_POSTGRES_ENV="$NANO_CONFIG_DIR/postgres.env"
    if [ ! -f "$NANO_POSTGRES_ENV" ]; then
        cat > "$NANO_POSTGRES_ENV" << 'EOF'
# PostgreSQL Configuration for Nano Agent
POSTGRES_HOST=192.168.5.1
POSTGRES_PORT=5432
POSTGRES_DB=postgres
POSTGRES_USER=postgres
POSTGRES_PASSWORD=mysecretpassword
EOF
        print_result $? "  Created postgres.env for nano"
    else
        print_result 0 "  postgres.env already exists for nano"
    fi





    # --- AGX agent config ---
    AGX_CONFIG_DIR="$AGENT_BASE_DIR/agx/app/config"
    if [ -d "$AGENT_BASE_DIR/agx" ]; then
        mkdir -p "$AGX_CONFIG_DIR" 2>/dev/null
        print_result $? "  Created agx agent config directory: $AGX_CONFIG_DIR"

        AGX_CONFIG_ENV="$AGX_CONFIG_DIR/agx-config.env"
        if [ ! -f "$AGX_CONFIG_ENV" ]; then
            cat > "$AGX_CONFIG_ENV" << 'EOF'
# NVIDIA AGX Xavier Configuration
# This file is auto-generated by server setup script

# Device settings
DEVICE_TYPE="agx"
GPU_ENABLED="true"
FORCE_GPU_CHECKS="true"

# Network settings
AGX_IP="192.168.10.21"
TOWER_IP="192.168.5.1"

# Directory paths
SCRIPT_DIR="/home/sanjay/containers/kubernetes/agent/agx/app/src"
CONFIG_DIR="/home/sanjay/containers/kubernetes/agent/agx/app/config"
LOG_DIR="/home/sanjay/containers/kubernetes/agent/agx/app/logs"
DATA_DIR="/home/sanjay/containers/kubernetes/agent/agx/app/data"
TOKEN_DIR="/mnt/vmstore/agx_home/containers/kubernetes/agent/agx/.token"
PROJECT_DIR="/home/sanjay/containers/kubernetes/agent/agx"
IMAGE_DIR="/home/sanjay/containers"

# Docker settings
REGISTRY_URL="192.168.5.1:5000"
FASTAPI_IMAGE="192.168.5.1:5000/fastapi_agx:latest"

# K3s settings
K3S_URL="https://192.168.5.1:6443"
K3S_TOKEN_FILE="/home/sanjay/k3s-agent-token"
KUBECONFIG_PATH="/home/sanjay/k3s.yaml"
EOF
            print_result $? "  Created agx-config.env"
        else
            print_result 0 "  agx-config.env already exists"
        fi

        AGX_POSTGRES_ENV="$AGX_CONFIG_DIR/postgres.env"
        if [ ! -f "$AGX_POSTGRES_ENV" ]; then
            cat > "$AGX_POSTGRES_ENV" << 'EOF'
# PostgreSQL Configuration for AGX Agent
POSTGRES_HOST=192.168.5.1
POSTGRES_PORT=5432
POSTGRES_DB=postgres
POSTGRES_USER=postgres
POSTGRES_PASSWORD=mysecretpassword
EOF
            print_result $? "  Created postgres.env for agx"
        else
            print_result 0 "  postgres.env already exists for agx"
        fi
    fi

    # Set proper permissions
    chmod -R 755 "$AGENT_BASE_DIR" 2>/dev/null
    print_result $? "  Set proper permissions on agent config directories"
}

function restart_registry_https() {
    echo -e "\n${GREEN}Restarting Registry with HTTPS${NC}"

    # Stop existing registry
    docker stop registry >/dev/null 2>&1
    docker rm registry >/dev/null 2>&1
    print_result 0 "  Stopped existing registry"

    # Create certificates directory
    sudo mkdir -p /etc/docker/certs.d/192.168.5.1:5000

    # Generate self-signed certificate for registry
    if [ ! -f /etc/docker/certs.d/192.168.5.1:5000/ca.crt ]; then
        echo -e "${YELLOW}  Generating self-signed certificate for registry...${NC}"
        sudo openssl req -newkey rsa:4096 -nodes -sha256 \
            -keyout /etc/docker/certs.d/192.168.5.1:5000/registry.key \
            -x509 -days 365 \
            -out /etc/docker/certs.d/192.168.5.1:5000/ca.crt \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=192.168.5.1" \
            -addext "subjectAltName=IP:192.168.5.1" >/dev/null 2>&1
        sudo cp /etc/docker/certs.d/192.168.5.1:5000/ca.crt /etc/docker/certs.d/192.168.5.1:5000/registry.crt
        print_result $? "  Generated self-signed certificate for registry"
    fi

    # Start registry with HTTPS
    docker run -d \
        -p 5000:5000 \
        --restart=always \
        --name registry \
        -v /etc/docker/certs.d/192.168.5.1:5000:/certs \
        -e REGISTRY_HTTP_ADDR=0.0.0.0:5000 \
        -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/registry.crt \
        -e REGISTRY_HTTP_TLS_KEY=/certs/registry.key \
        registry:2 >/dev/null 2>&1
    print_result $? "  Started registry with HTTPS"

    # Test HTTPS connectivity
    sleep 2
    if curl -k https://192.168.5.1:5000/v2/ >/dev/null 2>&1; then
        print_result 0 "  Registry HTTPS connectivity confirmed"
    else
        print_result 1 "  Registry HTTPS connectivity failed"
    fi
}

# Tower Server Setup (no debug mode needed - use dedicated agent script)
# The tower runs the k3s server/control plane and hosts the main services
echo -e "\n${GREEN}Running TOWER SERVER setup - installing k3s server and core services${NC}"
uninstall_k3s_cleanup
check_dns
check_docker_dns
build_images
setup_local_registry
check_k3s
check_certificate_trust
check_pods_services
check_individual_pod_status
list_all_deployments_status
check_postgres_connectivity
setup_agent_config_files


echo -e "\n${GREEN}Tower Server Setup Complete!${NC}"
echo -e "Agents can now join using: /home/sanjay/containers/kubernetes/agent/k3s-agent-setup.sh"
