# K3s Setup and FastAPI Deployment Guide with GPU Support

This guide provides a comprehensive step-by-step process to set up a K3s cluster with GPU support for deploying a FastAPI application on a Jetson Nano device. It includes troubleshooting and validation steps specific to Jetson hardware.

## 1. Uninstall Server
**Node:** {s}  
**Command:**
```bash
sudo /usr/local/bin/k3s-uninstall.sh
```
**Notes:** Clears all server data.

--------------------------------------------------------------------------------

## 2. Install Server
**Node:** {s}  
**Command:**
```bash
sudo curl -sfL https://get.k3s.io | sh -s - server
```
**Notes:** Installs a clean K3s Server.

--------------------------------------------------------------------------------

## 3. Get Token
**Node:** {s}  
**Command:**
```bash
sudo cat /var/lib/rancher/k3s/server/node-token
```
**Notes:** Fetches the new token for the Agent join. (Example: K1082767438a0c1247511c44dbc26fa4f5fb58ff5eb971b7d9ce31acba98cf96841::server:94ab84631ab403dda08afec268c27324)

--------------------------------------------------------------------------------

## 4. Uninstall Agent
**Node:** {a}  
**Command:**
```bash
sudo /usr/local/bin/k3s-agent-uninstall.sh
```
**Notes:** Clears agent data.

--------------------------------------------------------------------------------

## 5. Reinstall Agent
**Node:** {a}  
**Command:**
```bash
export K3S_TOKEN="K1082767438a0c1247511c44dbc26fa4f5fb58ff5eb971b7d9ce31acba98cf96841::server:94ab84631ab403dda08afec268c27324"
sudo curl -sfL https://get.k3s.io | K3S_URL=https://192.168.5.1:6443 K3S_TOKEN=$K3S_TOKEN INSTALL_K3S_EXEC="--disable-servicelb" sh -
```
**Notes:** Re-joins the Agent to the Server. (Use the IP and Token from step 3).

--------------------------------------------------------------------------------

## 6. Add Registry Config Dir
**Node:** {a}  
**Command:**
```bash
sudo mkdir -p /etc/rancher/k3s/
```
**Notes:** Directory for the registry config.

--------------------------------------------------------------------------------

## 7. Add Insecure Registry
**Node:** {a}  
**Command:**
```bash
echo 'configs: "192.168.5.1:5000": insecure_skip_verify: true' | sudo tee /etc/rancher/k3s/registries.yaml > /dev/null
```
**Notes:** Allows pulling images from your local registry.

--------------------------------------------------------------------------------

## 8. Fix Registry YAML Syntax
**Node:** {a}  
**Command:**
```bash
sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
configs:
  "192.168.5.1:5000":
    insecure_skip_verify: true
    http: true
EOF
```
**Notes:** Correct the YAML syntax and add HTTP support for the registry.

--------------------------------------------------------------------------------

## 9. Configure Containerd for Registry
**Node:** {a}  
**Command:**
```bash
sudo mkdir -p /var/lib/rancher/k3s/agent/etc/containerd/certs.d/192.168.5.1:5000
sudo tee /var/lib/rancher/k3s/agent/etc/containerd/certs.d/192.168.5.1:5000/hosts.toml > /dev/null <<EOF
[host."http://192.168.5.1:5000"]
  capabilities = ["pull", "resolve", "push"]
EOF
```
**Notes:** Manually configure containerd for HTTP registry access.

--------------------------------------------------------------------------------

## 10. Restart Agent After Registry Config
**Node:** {a}  
**Command:**
```bash
sudo systemctl restart k3s-agent
```
**Notes:** Restart the agent to apply registry and containerd changes.

--------------------------------------------------------------------------------

## 11. Restart Server
**Node:** {s}  
**Command:**
```bash
sudo systemctl restart k3s
```
**Notes:** Stabilizes API server connections after the agent joins.

--------------------------------------------------------------------------------

## 12. Apply Taint
**Node:** {s}  
**Command:**
```bash
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml taint node nano CriticalAddonsOnly=true:NoExecute
```
**Notes:** Fixes the NotReady issue by blocking the Load Balancer pod on the Agent.

--------------------------------------------------------------------------------

## 13. Verify Node Status
**Node:** {s}  
**Command:**
```bash
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes
```
**Notes:** Check for: nano and tower STATUS=Ready.

--------------------------------------------------------------------------------

## 14. Install NVIDIA RuntimeClass
**Node:** {s}  
**Command:**
```bash
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f - <<EOF
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: nvidia
handler: nvidia
EOF
```
**Notes:** Create RuntimeClass for NVIDIA GPU workloads.

--------------------------------------------------------------------------------

## 15. Install NVIDIA Device Plugin
**Node:** {s}  
**Command:**
```bash
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.14.1/nvidia-device-plugin.yml
```
**Notes:** Install device plugin to advertise GPU resources (may not work on Jetson).

--------------------------------------------------------------------------------

## 16. Manually Add GPU Capacity to Nano Node
**Node:** {s}  
**Command:**
```bash
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml edit node nano
# In the editor, add under status.capacity: nvidia.com/gpu: 1
# And under status.allocatable: nvidia.com/gpu: 1
# Save and exit
```
**Notes:** Manually add GPU resources to the nano node since the device plugin may not detect Jetson GPU.

--------------------------------------------------------------------------------

## 17. Configure NVIDIA Runtime on Agent
**Node:** {a}  
**Command:**
```bash
sudo systemctl stop k3s-agent
# Ensure /var/lib/rancher/k3s/agent/etc/containerd/config.toml has the NVIDIA runtime section
sudo systemctl start k3s-agent
```
**Notes:** Ensure NVIDIA container runtime is configured in containerd.

--------------------------------------------------------------------------------

## 18. Build Image
**Node:** {a}  
**Command:**
```bash
sudo docker build -t fastapi_nano:latest -f dockerfile.nano.req .
```
**Notes:** Builds the application image locally.

--------------------------------------------------------------------------------

## 19. Tag Image
**Node:** {a}  
**Command:**
```bash
sudo docker tag fastapi_nano:latest 192.168.5.1:5000/fastapi_nano:latest
```
**Notes:** Tags the image with the registry address.

--------------------------------------------------------------------------------

## 20. Push Image
**Node:** {a}  
**Command:**
```bash
sudo docker push 192.168.5.1:5000/fastapi_nano:latest
```
**Notes:** Pushes the image to your private registry.

--------------------------------------------------------------------------------

## 21. Create Deployment YAML
**Node:** {s}  
**Command:**
```bash
sudo tee fastapi-deployment-full.yaml > /dev/null <<EOF
[Full YAML with GPU requests and tolerations]
EOF
```
**Notes:** Creates the manifest file with GPU requests and tolerations.

--------------------------------------------------------------------------------

## 22. Deploy Application
**Node:** {s}  
**Command:**
```bash
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f fastapi-deployment-full.yaml
```
**Notes:** Starts the deployment.

--------------------------------------------------------------------------------

## 23. Monitor Pod Status
**Node:** {s}  
**Command:**
```bash
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide
```
**Notes:** Check if the pod is running on the nano node.

--------------------------------------------------------------------------------

## 24. Force Restart if Stuck
**Node:** {s}  
**Command:**
```bash
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml delete pod <pod-name> --force --grace-period=0
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml rollout restart deployment fastapi-nano
```
**Notes:** If pod is stuck terminating or pulling, force delete and restart.

--------------------------------------------------------------------------------

## 25. Review and Validate Implementation
**Node:** {s}  
**Command:**
```bash
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml describe node nano | grep -A 5 Capacity
curl http://192.168.5.21:30002/health
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml exec -it <pod-name> -- nvidia-smi
```
**Notes:** Review nodes are Ready, pod is Running on nano, GPU capacity is listed, app health endpoint responds, and GPU is detected inside the pod. Access FastAPI at http://192.168.5.21:30002

--------------------------------------------------------------------------------

## 26. Access FastAPI Endpoint
**Node:** {s}  
**Command:**
```bash
curl http://192.168.5.21:30002
```
**Notes:** Access the running FastAPI application on the nano node.

--------------------------------------------------------------------------------

## 27. Access Jupyter Endpoint
**Node:** {s}  
**Command:**
```bash
# Open in browser: http://192.168.5.21:30003
```
**Notes:** Access the Jupyter notebook interface on the nano node.

--------------------------------------------------------------------------------

## 28. Access FastAPI Endpoints
**Node:** {s}  
**Command:**
```bash
# Main application: http://192.168.5.21:30002
# Health check: curl http://192.168.5.21:30002/health
# Readiness check: curl http://192.168.5.21:30002/ready
```
**Notes:** Access the FastAPI application and its health endpoints on the nano node.

--------------------------------------------------------------------------------