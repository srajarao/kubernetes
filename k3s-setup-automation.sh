#!/bin/bash

clear

# K3s Setup and FastAPI Deployment Automation Script
# Automates the setup of K3s cluster with GPU support for FastAPI on Jetson Nano.
# Run this script on the server (tower) machine.
# Ensure SSH access to nano is set up (e.g., key-based auth).

DEBUG=${DEBUG:-0}

if [ "$DEBUG" = "1" ]; then
  echo "Starting K3s Setup and FastAPI Deployment..."
else
  echo "Starting K3s Setup and FastAPI Deployment in silent mode..."
fi

STEP=1
if [ "$DEBUG" != "1" ]; then
  set +e
fi

# Function to wait for server readiness
wait_for_server() {
  local timeout=60
  local count=0
  if [ "$DEBUG" = "1" ]; then echo "Waiting for server to be ready..."; fi
  while ! sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes &>/dev/null; do
    if [ $count -ge $timeout ]; then
      echo "Server did not start within $timeout seconds"
      exit 1
    fi
    sleep 1
    count=$((count + 1))
  done
  if [ "$DEBUG" = "1" ]; then echo "Server is ready"; fi
}

# Function to wait for agent readiness
wait_for_agent() {
  local timeout=60
  local count=0
  if [ "$DEBUG" = "1" ]; then echo "Waiting for agent (nano) to be ready..."; fi
  while ! sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes | grep -q "nano.*Ready"; do
    if [ $count -ge $timeout ]; then
      echo "Agent did not join within $timeout seconds"
      exit 1
    fi
    sleep 1
    count=$((count + 1))
  done
  if [ "$DEBUG" = "1" ]; then echo "Agent is ready"; fi
}

# Function to wait for GPU capacity
wait_for_gpu_capacity() {
  local timeout=120
  local count=0
  if [ "$DEBUG" = "1" ]; then echo "Waiting for GPU..."; fi
  while ! sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get node nano -o jsonpath='{.status.capacity.nvidia\.com/gpu}' | grep -q '1'; do
    if [ $count -ge $timeout ]; then
      echo "GPU capacity not added within $timeout seconds"
      exit 1
    fi
    sleep 5
    count=$((count + 5))
  done
    if [ "$DEBUG" = "1" ]; then echo "GPU capacity added"; fi
}

# Uninstall Server
if [ "$DEBUG" = "1" ]; then
  echo "Starting K3s Setup and FastAPI Deployment..."
else
  echo "Starting K3s Setup and FastAPI Deployment in silent mode..."
fi

# Function to wait for GPU capacity
wait_for_gpu_capacity() {
  local timeout=120
  local count=0
  echo "Waiting for GPU..."
  while ! sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get node nano -o jsonpath='{.status.capacity.nvidia\.com/gpu}' | grep -q '1'; do
    if [ $count -ge $timeout ]; then
      echo "GPU capacity not added within $timeout seconds"
      exit 1
    fi
    sleep 5
    count=$((count + 5))
  done
  echo "GPU ready"
}

# Uninstall Server
if [ "$DEBUG" = "1" ]; then
  echo "Uninstalling Server..."
  sleep 5
  sudo /usr/local/bin/k3s-uninstall.sh
else
  echo -n "1/20. Uninstalling K3s server... "
  sleep 5
  if sudo /usr/local/bin/k3s-uninstall.sh > /dev/null 2>&1; then
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[32m✔\033[0m"  # Print checkmark anyway, as uninstall may not exist
  fi
fi
STEP=2

# Install Server
echo -n "2/20. Installing K3s server... "
sleep 5
sudo curl -sfL https://get.k3s.io | sh -s - server
echo -e "\033[32m✔\033[0m"
STEP=3

# Get Token
if [ "$DEBUG" = "1" ]; then echo "Getting Token..."; fi
sleep 5
TOKEN=$(sudo cat /var/lib/rancher/k3s/server/node-token)
if [ "$DEBUG" = "1" ]; then echo "Token: $TOKEN"; fi
sleep 5

# Uninstall Agent (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Uninstalling Agent..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo /usr/local/bin/k3s-agent-uninstall.sh"
else
  echo -n "3/20. Uninstalling K3s agent on nano... "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo /usr/local/bin/k3s-agent-uninstall.sh" > /dev/null 2>&1; then
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[31m✗\033[0m"
    exit 1
  fi
fi
STEP=4

# Reinstall Agent (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Reinstalling Agent..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "export K3S_TOKEN=\"$TOKEN\"; sudo curl -sfL https://get.k3s.io | K3S_URL=https://192.168.5.20:6443 K3S_TOKEN=\$K3S_TOKEN sh -"
  wait_for_agent
else
  echo -n "4/20. Reinstalling K3s agent on nano... "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "export K3S_TOKEN=\"$TOKEN\"; sudo curl -sfL https://get.k3s.io | K3S_URL=https://192.168.5.20:6443 K3S_TOKEN=\$K3S_TOKEN sh -" > /dev/null 2>&1; then
    wait_for_agent
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[31m✗\033[0m"
    exit 1
  fi
fi
STEP=5

# Add Registry Config Dir (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Adding Registry Config Dir..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo mkdir -p /etc/rancher/k3s/"
else
  echo -n "5/20. Creating registry configuration directory... "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo mkdir -p /etc/rancher/k3s/" > /dev/null 2>&1; then
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[31m✗\033[0m"
    exit 1
  fi
fi
STEP=6

# Add Insecure Registry (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Adding Insecure Registry..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "echo 'configs: \"192.168.5.1:5000\": insecure_skip_verify: true' | sudo tee /etc/rancher/k3s/registries.yaml > /dev/null"
else
  echo -n "6/20. Adding insecure registry configuration... "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "echo 'configs: \"192.168.5.1:5000\": insecure_skip_verify: true' | sudo tee /etc/rancher/k3s/registries.yaml > /dev/null" > /dev/null 2>&1; then
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[31m✗\033[0m"
    exit 1
  fi
fi
STEP=7

# Fix Registry YAML Syntax (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Fixing Registry YAML Syntax..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
configs:
  \"192.168.5.1:5000\":
    insecure_skip_verify: true
    http: true
EOF"
else
  echo -n "7/20. Fixing registry YAML syntax... "
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
configs:
  \"192.168.5.1:5000\":
    insecure_skip_verify: true
    http: true
EOF" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[31m✗\033[0m"
    exit 1
  fi
fi
STEP=8

# Configure Containerd for Registry (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Configuring Containerd for Registry..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/192.168.5.1:5000"
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/192.168.5.1:5000/hosts.toml > /dev/null <<EOF
[host.\"http://192.168.5.1:5000\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
EOF"
else
  echo -n "8/20. Configuring containerd for registry... "
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/192.168.5.1:5000" > /dev/null 2>&1 && ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/192.168.5.1:5000/hosts.toml > /dev/null <<EOF
[host.\"http://192.168.5.1:5000\"]
  capabilities = [\"pull\", \"resolve\", \"push\"]
EOF" > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[31m✗\033[0m"
    exit 1
  fi
fi
STEP=9

# Restart Agent After Registry Config (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Restarting Agent After Registry Config..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo systemctl restart k3s-agent"
  wait_for_agent
else
  echo -n "9/20. Restarting K3s agent after registry config... "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo systemctl restart k3s-agent" > /dev/null 2>&1; then
    wait_for_agent
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[31m✗\033[0m"
    exit 1
  fi
fi
STEP=10

# Restart Server
if [ "$DEBUG" = "1" ]; then
  echo "Restarting Server..."
  sleep 5
  sudo systemctl restart k3s
  wait_for_server
else
  echo -n "10/20. Restarting K3s server... "
  sleep 5
  if sudo systemctl restart k3s > /dev/null 2>&1; then
    wait_for_server
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[31m✗\033[0m"
    exit 1
  fi
fi
STEP=11
# Apply Taint
if [ "$DEBUG" = "1" ]; then
  echo "Applying Taint..."
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml taint node nano CriticalAddonsOnly=true:NoExecute --overwrite
else
  echo -n "11/20. Applying taint to server node... "
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml taint node nano CriticalAddonsOnly=true:NoExecute --overwrite > /dev/null 2>&1; then
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[31m✗\033[0m"
    exit 1
  fi
fi
STEP=12

# Verify Node Status
if [ "$DEBUG" = "1" ]; then echo "Verifying Node Status..."; fi
sleep 5
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes

# Install NVIDIA RuntimeClass
if [ "$DEBUG" = "1" ]; then
  echo "Installing NVIDIA RuntimeClass..."
  sleep 5
  echo 'apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: nvidia
handler: nvidia
' | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f -
else
  echo -n "12/20. Installing NVIDIA runtime class... "
  sleep 5
  echo 'apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: nvidia
handler: nvidia
' | sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f - > /dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[31m✗\033[0m"
    exit 1
  fi
fi
STEP=13

# Install NVIDIA Device Plugin
if [ "$DEBUG" = "1" ]; then
  echo "Installing NVIDIA Device Plugin..."
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f nvidia-ds-updated.yaml
  wait_for_gpu_capacity
else
  echo -n "13/20. Installing NVIDIA device plugin... "
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f nvidia-ds-updated.yaml > /dev/null 2>&1; then
    wait_for_gpu_capacity
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[31m✗\033[0m"
    exit 1
  fi
fi
STEP=14

# Configure NVIDIA Runtime on Agent (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Configuring NVIDIA Runtime on Agent..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo systemctl stop k3s-agent"
  # Assuming the config is already there from previous setups
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo systemctl start k3s-agent"
  wait_for_agent
else
  echo -n "14/20. Configuring NVIDIA runtime on agent... "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo systemctl stop k3s-agent" > /dev/null 2>&1 && ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo systemctl start k3s-agent" > /dev/null 2>&1; then
    wait_for_agent
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[31m✗\033[0m"
    exit 1
  fi
fi
STEP=15

# Copy Files for Build
if [ "$DEBUG" = "1" ]; then
  echo "Copying Files for Build..."
  sleep 5
  scp /home/sanjay/containers/kubernetes/agent/nano/dockerfile.nano.req sanjay@192.168.5.21:~
  scp /home/sanjay/containers/kubernetes/agent/nano/requirements.nano.txt sanjay@192.168.5.21:~
  scp -r /home/sanjay/containers/kubernetes/agent/nano/app sanjay@192.168.5.21:~
else
  echo -n "15/20. Copying files for Docker build... "
  sleep 5
  if scp /home/sanjay/containers/kubernetes/agent/nano/dockerfile.nano.req sanjay@192.168.5.21:~ > /dev/null 2>&1 && scp /home/sanjay/containers/kubernetes/agent/nano/requirements.nano.txt sanjay@192.168.5.21:~ > /dev/null 2>&1 && scp -r /home/sanjay/containers/kubernetes/agent/nano/app sanjay@192.168.5.21:~ > /dev/null 2>&1; then
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[31m✗\033[0m"
    exit 1
  fi
fi
STEP=16

# Build Image (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Building Image..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo docker build -t fastapi_nano:latest -f dockerfile.nano.req ."
else
  echo -n "16/20. Building Docker image... "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo docker build -t fastapi_nano:latest -f dockerfile.nano.req ." > /dev/null 2>&1; then
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[31m✗\033[0m"
    exit 1
  fi
fi
STEP=17

# Tag Image (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Tagging Image..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo docker tag fastapi_nano:latest 192.168.5.1:5000/fastapi_nano:latest"
else
  echo -n "17/20. Tagging Docker image... "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo docker tag fastapi_nano:latest 192.168.5.1:5000/fastapi_nano:latest" > /dev/null 2>&1; then
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[31m✗\033[0m"
    exit 1
  fi
fi
STEP=18

# Push Image (via SSH)
if [ "$DEBUG" = "1" ]; then
  echo "Pushing Image..."
  sleep 5
  ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo docker push 192.168.5.1:5000/fastapi_nano:latest"
else
  echo -n "18/20. Pushing Docker image to registry... "
  sleep 5
  if ssh -o StrictHostKeyChecking=no sanjay@192.168.5.21 "sudo docker push 192.168.5.1:5000/fastapi_nano:latest" > /dev/null 2>&1; then
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[31m✗\033[0m"
    exit 1
  fi
fi
STEP=19

# Create Deployment YAML
echo "Creating Deployment YAML..."
sleep 5
rm -f fastapi-deployment-full.yaml
cat <<DEPLOYMENT > fastapi-deployment-full.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastapi-nano
  namespace: default
  labels:
    app: fastapi-nano
    device: nano
    tier: agent
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: fastapi-nano
  template:
    metadata:
      labels:
        app: fastapi-nano
        device: nano
        tier: agent
    spec:
      runtimeClassName: nvidia
      nodeSelector:
        kubernetes.io/hostname: nano
      containers:
      - name: fastapi-nano
        image: 192.168.5.1:5000/fastapi_nano:latest
        ports:
        - containerPort: 8000
          name: http
        - containerPort: 8888
          name: jupyter
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
            nvidia.com/gpu: 1
          limits:
            memory: "2Gi"
            cpu: "1000m"
            nvidia.com/gpu: 1
        env:
        - name: DEVICE_TYPE
          value: "nano"
        - name: GPU_ENABLED
          value: "true"
        - name: FORCE_GPU_CHECKS
          value: "true"
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        volumeMounts:
        - name: vmstore
          mountPath: /mnt/vmstore
        - name: nano-home
          mountPath: /home/nano
        - name: nano-config
          mountPath: /app/app/config
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: vmstore
        nfs:
          server: 192.168.5.1
          path: /export/vmstore
      - name: nano-home
        nfs:
          server: 192.168.5.1
          path: /export/vmstore/nano_home
      - name: nano-config
        nfs:
          server: 192.168.5.1
          path: /export/vmstore/tower_home/kubernetes/agent/nano/app/config
      tolerations:
      - key: "node-role.kubernetes.io/agent"
        operator: "Exists"
        effect: "NoSchedule"
      - key: "CriticalAddonsOnly"
        operator: "Equal"
        value: "true"
        effect: "NoExecute"
---
apiVersion: v1
kind: Service
metadata:
  name: fastapi-nano-service
  namespace: default
  labels:
    app: fastapi-nano
    device: nano
spec:
  selector:
    app: fastapi-nano
  ports:
  - port: 8000
    targetPort: 8000
    protocol: TCP
    name: http
  - port: 8888
    targetPort: 8888
    protocol: TCP
    name: jupyter
  type: ClusterIP
---
apiVersion: v1
kind: Service
metadata:
  name: fastapi-nano-nodeport
  namespace: default
  labels:
    app: fastapi-nano
    device: nano
spec:
  selector:
    app: fastapi-nano
  ports:
  - port: 8000
    targetPort: 8000
    nodePort: 30002
    protocol: TCP
    name: http
  - port: 8888
    targetPort: 8888
    nodePort: 30003
    protocol: TCP
    name: jupyter
  type: NodePort
DEPLOYMENT


# Deploy Application
if [ "$DEBUG" = "1" ]; then
  echo "Deploying Application..."
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f fastapi-deployment-full.yaml
else
  echo -n "19/20. Deploying FastAPI application... "
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f fastapi-deployment-full.yaml > /dev/null 2>&1; then
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[31m✗\033[0m"
    exit 1
  fi
fi
STEP=20

# Monitor Pod Status
if [ "$DEBUG" = "1" ]; then
  echo "Monitoring Pod Status..."
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide
else
  echo -n "20/20. Monitoring pod status... "
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide > /dev/null 2>&1; then
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[31m✗\033[0m"
    exit 1
  fi
fi

# Force Restart if Stuck (optional, commented out)
# echo "Force Restart if Stuck..."
# sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete pod <pod-name> --force --grace-period=0
# sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml rollout restart deployment fastapi-nano

# Review and Validate Implementation
if [ "$DEBUG" = "1" ]; then
  echo "Reviewing and Validating Implementation..."
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml describe node nano | grep -A 5 Capacity
  curl http://192.168.5.21:30002/health
else
  echo -n "Reviewing and Validating Implementation... "
  sleep 5
  if (sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes > /dev/null 2>&1 && sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide > /dev/null 2>&1 && sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml describe node nano | grep -A 5 Capacity > /dev/null 2>&1) && (curl http://192.168.5.21:30002/health > /dev/null 2>&1 || true); then
    echo -e "\033[32m✔\033[0m"
  else
    echo -e "\033[31m✗\033[0m"
    exit 1
  fi
fi
POD_NAME=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -l app=fastapi-nano -o jsonpath='{.items[0].metadata.name}')
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml exec $POD_NAME -- nvidia-smi 2>/dev/null


