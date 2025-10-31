# Script Executor - K3s Pod Deployment Architecture

## 🏗️ **Yes! Container as K3s Pod with WebSocket Hosting**

You're absolutely correct. The architecture would be:

## **🏛️ Deployment Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                    K3s Cluster                              │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐    │
│  │                 Worker Nodes                        │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │    │
│  │  │   spark1    │  │   spark2    │  │    nano     │  │    │
│  │  │  (Agent)    │  │  (Agent)    │  │  (Agent)    │  │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                Control Plane                         │    │
│  │  ┌─────────────────────────────────────────────────┐ │    │
│  │  │                tower (Server)                    │ │    │
│  │  │  ┌─────────────────────────────────────────────┐ │ │    │
│  │  │  │        script-executor POD                  │ │ │    │
│  │  │  │  ┌─────────────────────────────────────────┐ │ │ │    │
│  │  │  │  │ 🌐 WebSocket Server (Port 8000)        │ │ │ │    │
│  │  │  │  │  • FastAPI Application                  │ │ │ │    │
│  │  │  │  │  • REST APIs                            │ │ │ │    │
│  │  │  │  │  • WebSocket Handlers                   │ │ │ │    │
│  │  │  │  │  • Script Execution Engine              │ │ │ │    │
│  │  │  │  └─────────────────────────────────────────┘ │ │ │    │
│  │  │  │                                             │ │ │    │
│  │  │  │  📁 Volume Mount:                           │ │ │    │
│  │  │  │     /home/sanjay/containers/kubernetes      │ │ │    │
│  │  │  └─────────────────────────────────────────────┘ │ │ │    │
│  │  └─────────────────────────────────────────────────┘ │ │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## **🔗 How the Pod Connects to K3s**

### **1. Kubernetes Service Integration**
```yaml
apiVersion: v1
kind: Service
metadata:
  name: script-executor-service
spec:
  selector:
    app: script-executor
  ports:
  - port: 80
    targetPort: 8000  # Container port
  type: ClusterIP      # Internal cluster access
```

### **2. Ingress for External Access**
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: script-executor-ingress
spec:
  rules:
  - host: script-executor.your-domain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: script-executor-service
            port:
              number: 80
```

### **3. Volume Mount for Script Access**
```yaml
spec:
  containers:
  - name: script-executor
    volumeMounts:
    - name: scripts-volume
      mountPath: /home/sanjay/containers/kubernetes
      readOnly: true
  volumes:
  - name: scripts-volume
    hostPath:
      path: /home/sanjay/containers/kubernetes
      type: Directory
```

## **🌐 WebSocket Communication Flow**

### **Client → Pod Communication:**
```
User Browser → Ingress → Service → Pod (Port 8000)
                    ↓
            WebSocket Connection
                    ↓
        Real-time Script Output
```

### **Script Execution Flow:**
```
1. User selects scripts in web UI
2. Browser sends WebSocket message to pod
3. Pod executes scripts on host filesystem
4. Pod streams output back via WebSocket
5. Browser displays real-time results
```

## **🔒 Security & Access Model**

### **Pod Security Context:**
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  capabilities:
    drop:
    - ALL
```

### **Network Policies:**
- Pod can only access necessary cluster resources
- External access controlled via ingress
- Internal communication secured

### **RBAC Integration:**
- Pod service account with minimal permissions
- Access to Kubernetes API for cluster information
- Script execution limited to allowed directories

## **📊 Resource Requirements**

### **Pod Resources:**
```yaml
resources:
  requests:
    memory: "128Mi"
    cpu: "100m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

### **Storage Access:**
- Read-only access to script directories
- No write permissions to host filesystem
- Secure execution environment

## **🔄 Pod Lifecycle**

### **Startup Process:**
```
1. Pod scheduled on tower node
2. Container starts with script-executor image
3. FastAPI application initializes
4. Volume mounts provide script access
5. WebSocket server starts on port 8000
6. Health checks pass
7. Service becomes available
```

### **Runtime Operations:**
- Handles HTTP requests for script discovery
- Manages WebSocket connections for execution
- Executes scripts in isolated subprocesses
- Streams output in real-time
- Monitors resource usage

### **Scaling & Reliability:**
- Can be scaled to multiple replicas
- Load balancer distributes requests
- Automatic restart on failures
- Rolling updates for zero downtime

## **🌟 Benefits of Pod Deployment**

### **Integration Advantages:**
- **Native K3s Citizen**: Runs as first-class cluster component
- **Service Discovery**: Automatic service registration
- **Load Balancing**: Built-in traffic distribution
- **Monitoring**: Integrated with cluster monitoring

### **Operational Benefits:**
- **High Availability**: Survives node failures
- **Auto-healing**: Automatic pod restarts
- **Resource Management**: Controlled by Kubernetes
- **Security**: Pod security policies apply

### **Development Benefits:**
- **Consistent Environment**: Same runtime everywhere
- **Easy Updates**: Rolling deployments
- **Configuration Management**: ConfigMaps and Secrets
- **Logging**: Centralized log aggregation

## **🚀 Deployment Reality Check**

**Yes, this is exactly how it would work!** The script-executor application runs as a pod in your K3s cluster, hosting the WebSocket server that powers the real-time web interface.

The pod would be:
- ✅ **Linked to your K3s cluster** as a managed workload
- ✅ **Accessible via Kubernetes services and ingress**
- ✅ **Isolated and secure** with proper resource limits
- ✅ **Integrated with your existing scripts** via volume mounts

This architecture makes the script executor a **native part of your cluster infrastructure**! 🏗️

**Does this deployment model make sense for your use case?** The pod would essentially become your cluster's script execution and management control plane! 🎯</content>
<parameter name="filePath">/home/sanjay/containers/kubernetes/pod-deployment-architecture.md