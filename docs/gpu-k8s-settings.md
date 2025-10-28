# Kubernetes GPU Job Configuration Settings

This document outlines the key YAML settings used in `fastapi-deployment-spark2.yaml` to configure a Job with GPU access on Jetson hardware, avoiding Kubernetes GPU resource management.

## 1. Settings Determining Job vs Deployment

- **apiVersion**: `batch/v1` (for Job) vs `apps/v1` (for Deployment)
- **kind**: `Job` (runs to completion, no persistent pods) vs `Deployment` (manages long-running pods with replicas)

Example:
```yaml
apiVersion: batch/v1
kind: Job
```

## 2. Settings Determining No Retry

- **backoffLimit**: `0` (no retries on failure; Job fails immediately)
- **restartPolicy**: `Never` (container doesn't restart within the pod)

Example:
```yaml
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
```

## 3. Settings Removal Needed for No GPU Management

Remove `nvidia.com/gpu` from `resources.requests` and `resources.limits` to bypass Kubernetes GPU resource allocation (which fails on Jetson). Instead, use privileged mounts.

Removed section:
```yaml
# Remove this:
resources:
  requests:
    nvidia.com/gpu: 1
  limits:
    nvidia.com/gpu: 1
```

## 4. Settings Needed for Privileged Access

- **securityContext.privileged**: `true` (allows container to access host devices and perform privileged operations)

Example:
```yaml
securityContext:
  privileged: true
```

## 5. Settings Needed for Privileged Mounts

- **runtimeClassName**: `nvidia` (uses NVIDIA container runtime for GPU support)
- **volumes**: HostPath mounts for GPU device files
- **volumeMounts**: Mount the host GPU devices into the container
- **securityContext.privileged**: `true` (required for accessing host devices)

Example:
```yaml
spec:
  runtimeClassName: nvidia
  containers:
  - securityContext:
      privileged: true
    volumeMounts:
    - name: nvidia-dev
      mountPath: /dev/nvidia0
    # ... other mounts
  volumes:
  - name: nvidia-dev
    hostPath:
      path: /dev/nvidia0
  # ... other volumes
```

These settings enable direct GPU access via host mounts on Jetson, bypassing the NVIDIA device plugin's resource management.

## 6. Important: Avoid Mounting Host Libraries

**Do not mount host CUDA libraries** (e.g., `/usr/lib/aarch64-linux-gnu`) as this can cause conflicts with the container's CUDA runtime, preventing TensorFlow from detecting GPUs.

**Problem**: Mounting host libraries overrides container libraries, causing version mismatches.
**Solution**: Remove library mounts and let the container use its own compatible CUDA libraries.
**Result**: TensorFlow detects GPUs correctly while maintaining device access via privileged mounts.

Example of what to avoid:
```yaml
# DO NOT include this mount:
volumes:
- name: nvidia-lib
  hostPath:
    path: /usr/lib/aarch64-linux-gnu
volumeMounts:
- name: nvidia-lib
  mountPath: /usr/lib/aarch64-linux-gnu
```

## 7. Hardware Resource Verification

Before deploying GPU workloads, verify the actual hardware resources on the target node:

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null sanjay@192.168.1.202 "echo '=== CPU Information ===' && nproc && echo && echo '=== Memory Information ===' && free -h && echo && echo '=== GPU Information ===' && nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits"
```

Expected output for spark2 node:
```
=== CPU Information ===
20

=== Memory Information ===
               total        used        free      shared  buff/cache   available
Mem:           119Gi       4.3Gi        80Gi        33Mi        35Gi       115Gi
Swap:           15Gi       449Mi        15Gi

=== GPU Information ===
NVIDIA GB10, [N/A]
```

Use these values to set appropriate `resources.limits` and `resources.requests` in your Job YAML.

## 8. Tests Required to Confirm Access to All Resources

After deploying the Job, run these commands to verify resource access:

### Pod Status
```bash
kubectl get pods -l app=fastapi-spark2
```
- Should show `1/1 Running`

### GPU Device Access
```bash
kubectl exec <pod-name> -- ls -la /dev/ | grep nvidia
```
- Should list: `nvidia0`, `nvidiactl`, `nvidia-uvm`, `nvidia-modeset`, `nvidia-uvm-tools`, `nvidia-caps`

### GPU Functionality
```bash
kubectl exec <pod-name> -- nvidia-smi
```
- Should display GPU info (e.g., NVIDIA GB10, driver version, CUDA version)

### CUDA Access via PyTorch
```bash
kubectl exec <pod-name> -- python3 -c "import torch; print('CUDA available:', torch.cuda.is_available()); print('CUDA version:', torch.version.cuda); print('GPU count:', torch.cuda.device_count()); print('GPU name:', torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'None')"
```
- Should show CUDA available: True, CUDA version 13.0, GPU count 1, GPU name NVIDIA GB10

### TensorFlow CUDA Build Check
```bash
kubectl exec <pod-name> -- python3 -c "import tensorflow as tf; print('TF built with CUDA:', tf.test.is_built_with_cuda()); print('TF GPU available:', tf.test.is_gpu_available(cuda_only=False))"
```
- Should show TF built with CUDA: True, TF GPU available: True

### TensorFlow GPU Access
```bash
kubectl exec <pod-name> -- python3 -c "import tensorflow as tf; print('GPUs:', len(tf.config.list_physical_devices('GPU')))"
```
- Should return `GPUs: 1` (confirms TensorFlow can detect and use the GPU)

### TensorFlow GPU Matrix Multiplication Test
```bash
kubectl exec <pod-name> -- python3 -c "
import tensorflow as tf
print('TensorFlow version:', tf.__version__)
print('Available GPUs:', len(tf.config.list_physical_devices('GPU')))

# Test matrix multiplication on GPU
with tf.device('/GPU:0'):
    print('Performing matrix multiplication on GPU...')
    a = tf.random.normal([2000, 2000])
    b = tf.random.normal([2000, 2000])
    c = tf.matmul(a, b)
    result = c.numpy()  # Force computation
    print('Matrix multiplication completed successfully!')
    print('Result shape:', result.shape)
    print('Sample value:', result[0, 0])
"
```
- Should show TensorFlow version, 1 GPU available, successful matrix multiplication on GPU, result shape (2000, 2000), and a sample value.

### PyTorch GPU Access
```bash
kubectl exec <pod-name> -- python3 -c "import torch; print('CUDA available:', torch.cuda.is_available())"
```
- Should return `CUDA available: True` (confirms PyTorch can access CUDA)

### PyTorch CUDA Matrix Multiplication Test
```bash
kubectl exec <pod-name> -- python3 -c "
import torch
print('PyTorch CUDA available:', torch.cuda.is_available())
if torch.cuda.is_available():
    device = torch.device('cuda')
    print('Performing matrix multiplication on GPU...')
    a = torch.randn(2000, 2000).to(device)
    b = torch.randn(2000, 2000).to(device)
    c = torch.matmul(a, b)
    result = c.cpu()
    print('Matrix multiplication completed successfully!')
    print('Result shape:', result.shape)
    print('Sample value:', result[0, 0].item())
else:
    print('CUDA not available')
"
```
- Should show PyTorch CUDA available: True, successful matrix multiplication on GPU, result shape torch.Size([2000, 2000]), and a sample value.

### TensorRT Functionality Test
```bash
kubectl exec <pod-name> -- python3 -c "
import tensorrt as trt
print('TensorRT version:', trt.__version__)
print('Testing basic TensorRT functionality...')

# Create logger
logger = trt.Logger(trt.Logger.INFO)

# Create builder
builder = trt.Builder(logger)
print('Builder created successfully')

# Check available platforms
print('GPU architectures supported:', builder.platform_has_tf32 if hasattr(builder, 'platform_has_tf32') else 'N/A')
print('Fast FP16 supported:', builder.platform_has_fast_fp16 if hasattr(builder, 'platform_has_fast_fp16') else 'N/A')
print('Fast INT8 supported:', builder.platform_has_fast_int8 if hasattr(builder, 'platform_has_fast_int8') else 'N/A')

# Create network
network = builder.create_network()
print('Network created successfully')

# Create config
config = builder.create_builder_config()
print('Builder config created successfully')

print('TensorRT basic functionality test passed!')
"
```
- Should show TensorRT version (e.g., 10.8.0.43), successful creation of builder/network/config, and GPU capabilities (TF32/FP16/INT8 support). Note: Convolution operations may fail on CC 12.1 GPUs due to shader generation limitations.

### FastAPI Application Test
```bash
kubectl exec <pod-name> -- curl -s http://localhost:8000/health
```
- Should return JSON with `"status": "healthy"`, `"gpu_enabled": "true"`, etc.

```bash
kubectl exec <pod-name> -- curl -s http://localhost:8000/test
```
- Should return JSON with `"message": "AGX FastAPI server is running"`, device info, etc.

### TensorRT Functionality Test
```bash
# Run the comprehensive TensorRT test integrated into spark2_app.py
kubectl exec <pod-name> -- python3 /app/spark2_app.py  # Will run during health checks
```
The TensorRT check in `spark2_app.py` now includes comprehensive validation that tests:
- Core functionality (Builder/Network/Config creation)
- Working operations (Identity, ReLU layers)
- GPU capability detection (TF32, FP16, INT8 support)
- Known limitations (Convolution operations on CC 12.1)

**Expected Results:**
- ✅ TensorRT Status: FUNCTIONAL with limitations
- ✅ Working operations: Identity, ReLU
- ✅ GPU capabilities detected: TF32, Fast FP16, Fast INT8
- ⚠️ Convolution operations limited (expected on CC 12.1)

### CPU Access
```bash
kubectl exec <pod-name> -- grep -c processor /proc/cpuinfo
```
- Should return `20` (or expected CPU count)

### NFS Mount Access
```bash
kubectl exec <pod-name> -- ls -la /workspace/vmstore
kubectl exec <pod-name> -- ls -la /workspace/spark2_home
kubectl exec <pod-name> -- ls -la /workspace/config
```
- Should list files/directories from NFS shares

### Privileged Access Confirmation
```bash
kubectl exec <pod-name> -- whoami
```
- Should be `root` (due to privileged mode)

Replace `<pod-name>` with the actual pod name (e.g., `fastapi-spark2-kz2f7`).

## 7. Command Setting for Pod Behavior

- **command**: `["sleep", "infinity"]` (keeps the pod running indefinitely without executing the app, allowing GPU access testing)
- To run the actual app, change to your app's startup command (e.g., `["python", "app.py"]`)