
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

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color
TICK="${GREEN}✅${NC}"
CROSS="${RED}❌${NC}"

function print_result() {
    if [ "$1" -eq 0 ]; then
        echo -e "$2 $TICK"
    else
        echo -e "$2 $CROSS"
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

    # Copy server-ca.crt to AGX agent token directory
    AGENT_TOKEN_DIR="/export/vmstore/agx_home/containers/fastapi/.token"
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
    echo -e "\n${GREEN}Setup Local Registry${NC}"
    docker ps | grep -q 'registry:2'
    if [ $? -eq 0 ]; then
        print_result 0 "  Local Docker registry running"
    else
        docker run -d -p 5000:5000 --restart=always --name registry registry:2 >/dev/null 2>&1
        print_result $? "  Local Docker registry started"
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

function check_k3s() {
    echo -e "\n${GREEN}K3s Service${NC}"

    # Define both nano and AGX accessible IPs
    NANO_SERVER_IP="192.168.5.1"
    AGX_SERVER_IP="192.168.10.1"   # <-- Set this to the AGX-accessible IP of the k3s server

    # Install k3s with both TLS SANs and external IP for AGX if not installed
    if ! command -v k3s >/dev/null 2>&1; then
        curl -sfL https://get.k3s.io | \
        INSTALL_K3S_EXEC="--tls-san $NANO_SERVER_IP --tls-san $AGX_SERVER_IP --node-external-ip $AGX_SERVER_IP" sh - >/dev/null 2>&1
        print_result $? "  k3s installed with TLS SANs for nano and AGX, and external IP for AGX"
    fi

    # Kubeconfig Setup
    if [ -f /etc/rancher/k3s/k3s.yaml ]; then
        sudo cp /etc/rancher/k3s/k3s.yaml /home/sanjay/.kube/config
        print_result $? "  Copied k3s cluster config to ~/.kube/config"
        sudo chown sanjay:sanjay /home/sanjay/.kube/config
        sudo chmod 600 /home/sanjay/.kube/config
        # Set server address for nano (default)
        sed -i "s#server: https://127.0.0.1:6443#server: https://$NANO_SERVER_IP:6443#g" /home/sanjay/.kube/config
        print_result $? "  Update API server address to $NANO_SERVER_IP:6443 in kubeconfig"
        export KUBECONFIG=$HOME/.kube/config
        source ~/.bashrc
        # Copy for nano agent
        cp /home/sanjay/.kube/config /export/vmstore/nano_home/containers/fastapi_nano/.token/k3s.yaml
        sudo chmod 777 /export/vmstore/nano_home/containers/fastapi_nano/.token -R
        # Also create a kubeconfig for AGX with AGX IP as server
        sed "s#server: https://$NANO_SERVER_IP:6443#server: https://$AGX_SERVER_IP:6443#g" /home/sanjay/.kube/config > /export/vmstore/agx_home/containers/fastapi/.token/k3s.yaml
        sudo chmod 777 /export/vmstore/agx_home/containers/fastapi/.token -R
        print_result 0 "  Copied and updated kubeconfig for AGX with server $AGX_SERVER_IP"
    else
        print_result 1 "  /etc/rancher/k3s/k3s.yaml not found"
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

# 8. Wireless DNS check

function check_wireless_dns() {
    echo -e "\n${GREEN}Wireless DNS Override: Quarks HQ${NC}"
    nmcli connection show "Quarks HQ" >/dev/null 2>&1
    print_result $? "  nmcli connection show (Quarks HQ)"

    nmcli connection modify "Quarks HQ" ipv4.dns "8.8.8.8,1.1.1.1" >/dev/null 2>&1
    print_result $? "  nmcli connection modify 'Quarks HQ' ipv4.dns"

    nmcli connection modify "Quarks HQ" ipv4.ignore-auto-dns yes >/dev/null 2>&1
    print_result $? "  nmcli connection modify 'Quarks HQ' ipv4.ignore-auto-dns"

    nmcli connection down "Quarks HQ" >/dev/null 2>&1
    print_result $? "  nmcli connection down 'Quarks HQ'"

    nmcli connection up "Quarks HQ" >/dev/null 2>&1
    print_result $? "  nmcli connection up 'Quarks HQ'"
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

function export_token() {
    echo -e "\n${GREEN}Exporting k3s Server Tokens for Agent Nodes${NC}"
    
    # Export k3s server node-token for nano agent to join the cluster
    AGENT_TOKEN_DIR="/export/vmstore/nano_home/containers/fastapi_nano/.token"
    AGENT_TOKEN_PATH="$AGENT_TOKEN_DIR/node-token"
    mkdir -p "$AGENT_TOKEN_DIR"
    sudo chown -R "$USER:$USER" "$AGENT_TOKEN_DIR"
    if sudo test -f /var/lib/rancher/k3s/server/node-token; then
        sudo cp /var/lib/rancher/k3s/server/node-token "$AGENT_TOKEN_PATH" 2>/dev/null
        print_result $? "  Exported k3s server node-token for nano agent to $AGENT_TOKEN_PATH"
    else
        print_result 1 "  k3s server node-token not found"
    fi

    # Export k3s server node-token for AGX agent to join the cluster
    AGENT_TOKEN_DIR="/export/vmstore/agx_home/containers/fastapi/.token"
    AGENT_TOKEN_PATH="$AGENT_TOKEN_DIR/node-token"
    mkdir -p "$AGENT_TOKEN_DIR"
    sudo chown -R "$USER:$USER" "$AGENT_TOKEN_DIR"
    if sudo test -f /var/lib/rancher/k3s/server/node-token; then
        sudo cp /var/lib/rancher/k3s/server/node-token "$AGENT_TOKEN_PATH" 2>/dev/null
        print_result $? "  Exported k3s server node-token for AGX agent to $AGENT_TOKEN_PATH"
    else
        print_result 1 "  k3s server node-token not found"
    fi
    
}




# Tower Server Setup (no debug mode needed - use dedicated agent script)
# The tower runs the k3s server/control plane and hosts the main services
echo -e "\n${GREEN}Running TOWER SERVER setup - installing k3s server and core services${NC}"
uninstall_k3s_cleanup
check_dns
check_docker_dns
check_wireless_dns
build_images
setup_local_registry
check_k3s
check_certificate_trust
check_pods_services
check_individual_pod_status
list_all_deployments_status
check_postgres_connectivity
export_token

echo -e "\n${GREEN}Tower Server Setup Complete!${NC}"
echo -e "Agents can now join using: /home/sanjay/containers/kubernetes/agent/k3s-agent-setup.sh"
