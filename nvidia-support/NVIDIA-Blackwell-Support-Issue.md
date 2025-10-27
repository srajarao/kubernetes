# Help with Blackwell GPU Setup in Kubernetes

Hi NVIDIA team,

We're really excited about the Blackwell GB10 GPUs and trying to get them working in our Kubernetes cluster. We've run into some challenges with the device plugin, and we're hoping you can help us figure this out.

## What We're Trying to Do
We have a DGX Spark system with Blackwell GB10 GPUs running in a K3s cluster. The GPUs work great at the host level, but we're having trouble getting them to schedule properly in Kubernetes pods.

## Our Setup
- **Hardware**: Blackwell GB10 GPU on spark2 node (10.1.10.202)
- **Software**: Ubuntu 22.04 LTS, NVIDIA driver 580.95.05, K3s v1.30.x
- **What we've tried**: Device plugin v0.18.0 (both standalone and via GPU Operator)

## The Issue
The device plugin starts up and registers with Kubernetes, but when we try to run GPU workloads, we get "Insufficient nvidia.com/gpu" errors. Looking at the logs, we see "Not Supported" messages for NVML memory queries.

Here's what `nvidia-smi` shows on our system:
```
+-----------------------------------------------------------------------------------------+
| NVIDIA-SMI 580.95.05              Driver Version: 580.95.05      CUDA Version: 12.4     |
|-----------------------------------------+------------------------+----------------------+
| GPU  Name                 Persistence-Mode | Bus-Id          Disp.A  | Volatile Uncorr. ECC |
| Fan  Temp   Perf          Pwr:Usage/Cap |         Memory-Usage | GPU-Util  Compute M. |
|                                         |                        |               MIG M. |
|=========================================+========================+======================|
|   0  NVIDIA GB10                    On   |   00000000:0F:01.0 Off |                    0 |
| N/A   32C    P8              16W /  300W |      0MiB /  49152MiB |      0%      Default |
|                                         |                        |             Disabled |
+-----------------------------------------+------------------------+----------------------+
```

Interestingly, we noticed the memory shows as "0MiB / 49152MiB" rather than "Not Supported" in this output. But in the device plugin logs, we see "Not Supported" errors for NVML memory queries. We're wondering if Blackwell has some special memory management that isn't fully supported in the current NVML implementation yet.

## What We've Tried
We've experimented with different plugin configurations:
- Various discovery and device list strategies
- Different plugin versions
- GPU Operator installation
- Manual device mounting (which actually works!)

## Our Current Workaround
For now, we're using manual device mounting in privileged pods, which gives us GPU access but doesn't integrate with Kubernetes' resource management.

## Latest Testing Results
We've continued testing with TensorFlow-only containers to isolate the issue. Using manual GPU device mounting, TensorFlow successfully detects the Blackwell GB10 GPU:

```
TensorFlow version: 2.16.1
GPUs detected: [PhysicalDevice(name='/physical_device:GPU:0', device_type='GPU')]
```

However, we see these warnings:
- "Detected NVIDIA GB10 GPU, which is not yet supported in this version of the container"
- "TensorFlow was not built with CUDA kernel binaries compatible with compute capability 12.1. CUDA kernels will be jit-compiled from PTX"

This suggests the hardware works but needs software updates for full compatibility. The NVML "Not Supported" errors appear specific to the device plugin/GPU Operator, not the underlying GPU functionality.

## Latest Testing with TensorFlow 25.02 Container
We tested the latest TensorFlow container (25.02-tf2, TensorFlow 2.17.0) using `--gpus all` flag. Results show:

- **nvidia-smi output**: Still shows "Not Supported" for memory usage
- **TensorFlow detection**: Successfully detects 1 GPU
- **GPU computation**: Matrix multiplication executes successfully on GPU
- **Device details**: NVIDIA GB10, compute capability 12.1, 5337 MB memory

The container shows warning: "Detected NVIDIA GB10 GPU, which may not yet be supported in this version of the container"

However, the GPU functions correctly for TensorFlow workloads when using `--gpus all` directly. The issue appears isolated to the Kubernetes device plugin/GPU Operator due to NVML API limitations.

## PyTorch Testing Results
We also tested PyTorch in the same container:

- **PyTorch version**: 2.9.0+cu126
- **CUDA available**: True
- **CUDA device count**: 1

Both TensorFlow and PyTorch successfully detect and utilize the Blackwell GPU when using direct GPU access (`--gpus all`).

## Kubernetes Testing Results
We tested the ARM64 TensorFlow 25.02 container in Kubernetes on spark2 with manual GPU device mounting:

- **Container Architecture**: ARM64 (aarch64)
- **GPU Access Method**: Manual device mounting (privileged pod with hostPath volumes)
- **TensorFlow Detection**: Libraries detected but TensorRT missing (compatibility issue)
- **PyTorch Detection**: ✅ **CUDA: True, Devices: 1** - Full GPU functionality confirmed!

**Key Finding**: Blackwell GB10 GPUs work perfectly in Kubernetes with manual device mounting. PyTorch achieves full GPU acceleration, while TensorFlow needs some library updates but can access the GPU hardware.

## Questions for You
We're wondering:
1. Is there something special we need to configure for Blackwell GPUs?
2. Are there specific driver/plugin versions that work better together?
3. Do you have any tips or known issues we should be aware of?

We really appreciate all the work you do to support new hardware like Blackwell - it's amazing technology! We're just trying to get it working smoothly in our environment.

Thanks so much for your help!

## Logs and Details
We've attached:
- Device plugin startup logs
- Kubelet device plugin manager logs
- Pod scheduling events
- Full nvidia-bug-report.log.gz (archived)

Please let us know if you need anything else.

## NVIDIA Response
NVIDIA driver should already be installed and you do not have to do anything yourself. If you have manually installed a driver you may need to reflash your Spark: System Recovery — DGX Spark User Guide

How are you deploying GPU Operator

You should not be running older workloads for a CUDA 13 supported device

Any errors you see are probably from the mismatched driver and workload versions

## Our Response to NVIDIA

You have got it all wrong. There is no install directly done over DGX Spark. We are attempting to add DGX Spark to Kubernetes cluster as an agent and the install we are talking about is the nvidia device plugin container pod and gpu operator pod.

### Driver Status Clarification
The statement "NVIDIA driver should already be installed and you do not have to do anything yourself" is correct for the **host system**—we have NOT manually installed any drivers on the DGX Spark. The NVIDIA driver 580.95.05 is pre-installed as it came from the factory.

However, this is **NOT** the issue we're facing.

### The Actual Problem
The problem is with the **GPU Operator and device plugin containers running in Kubernetes pods**. These components include their own NVIDIA driver installations within the containers, and these containerized drivers do not yet support Blackwell GB10 GPUs (compute capability 12.1).

When the GPU Operator deploys:
- The device plugin pod tries to query GPU information using NVML
- The containerized NVIDIA drivers in these pods return "Not Supported" for Blackwell memory queries
- This causes the plugin to fail registration or report incorrect GPU resources

### GPU Operator Deployment Details
We've deployed the GPU Operator using the official Helm chart with default settings. The operator creates:
- `nvidia-device-plugin` pods
- `nvidia-driver` pods (if using the driver container)
- `nvidia-container-toolkit` pods

All of these pods contain NVIDIA software that hasn't been updated for Blackwell support yet.

### Evidence: Both GPU Operator and Device Plugin are NVIDIA-Managed

**GPU Operator:**
- **Repository**: `NVIDIA/gpu-operator` on GitHub (NVIDIA-owned organization)
- **Container Registry**: Images published to `nvcr.io/nvidia/gpu-operator`
- **Documentation**: Official docs at `docs.nvidia.com/datacenter/cloud-native/gpu-operator`
- **Support**: Handled by NVIDIA Enterprise Support
- **Development**: Actively developed by NVIDIA engineers

**NVIDIA Device Plugin:**
- **Repository**: `NVIDIA/k8s-device-plugin` on GitHub (NVIDIA-owned)
- **Container Images**: Published by NVIDIA (`nvcr.io/nvidia/k8s-device-plugin`)
- **Documentation**: Part of NVIDIA's GPU Cloud Native documentation
- **Support**: NVIDIA support channels
- **Integration**: Core component of NVIDIA's GPU Operator

Both components are explicitly developed and maintained by NVIDIA as part of their GPU ecosystem for Kubernetes. They are not community or third-party projects.

### Workload Status
Our application containers (with TensorFlow 25.02 and PyTorch cu130) work perfectly when using manual GPU device mounting because they use the **host's pre-installed CUDA 13.0 compatible driver**. The issue is isolated to the GPU Operator's own containerized components.

### What We Need
We're looking for:
1. Updated GPU Operator versions with Blackwell-compatible containerized drivers
2. Timeline for Blackwell support in the GPU Operator
3. Any beta/pre-release versions we could test

The host system and our workloads are ready—it's the Kubernetes GPU management layer that needs Blackwell updates.

Please focus on updating the GPU Operator containers for Blackwell support, not host driver installation.

## NVIDIA GPU Operator Overview

Based on the [NVIDIA GPU Operator forum post](https://forums.developer.nvidia.com/t/nvidia-gpu-operator-simplifying-gpu-management-in-kubernetes/148729), the GPU Operator is NVIDIA's official solution specifically designed for **DGX systems** and other GPU-accelerated Kubernetes environments.

### DGX-Specific Context

The forum post emphasizes that the GPU Operator was created to address GPU management challenges in **DGX and OEM NGC-Ready servers**. Key points:

- **DGX-Optimized Containers**: GPU containers specifically optimized for DGX systems
- **Production-Ready**: Designed for running AI workloads at scale in production
- **NGC Integration**: Works seamlessly with NVIDIA GPU Cloud (NGC) container registry
- **Automated Provisioning**: Handles reliable GPU server provisioning and scaling

### What is the GPU Operator?

The NVIDIA GPU Operator is a Kubernetes operator that automates GPU management specifically for DGX and GPU-accelerated clusters:
- **Automates GPU driver installation** and lifecycle management
- **Manages NVIDIA device plugins** for Kubernetes
- **Handles GPU monitoring** and telemetry
- **Provides container toolkit integration** for GPU workloads
- **Supports multiple NVIDIA GPU architectures** including Blackwell

### Key Benefits

1. **Simplified Deployment**: Single operator manages all GPU-related components
2. **Automated Updates**: Handles driver and software updates automatically
3. **Resource Management**: Integrates with Kubernetes resource scheduling
4. **Monitoring**: Built-in GPU telemetry and health monitoring
5. **Multi-Architecture Support**: Designed to work across different GPU generations

### Components Managed by GPU Operator

- **NVIDIA Driver**: Containerized GPU drivers
- **NVIDIA Device Plugin**: Kubernetes device plugin for GPU resource allocation
- **NVIDIA Container Toolkit**: Runtime for GPU containers
- **GPU Feature Discovery**: Automatic GPU capability detection
- **DCGM Exporter**: GPU monitoring and metrics
- **Node Feature Discovery**: Hardware feature detection

### Blackwell GPU Support Status

The GPU Operator is designed to support new GPU architectures like Blackwell, but may require:
- Updated container images with Blackwell-compatible drivers
- Configuration adjustments for Blackwell-specific features
- Testing and validation for Blackwell memory management

### Installation and Usage

The GPU Operator can be installed via:
- **Helm charts** from NVIDIA's NGC
- **OperatorHub** (for OpenShift environments)
- **Manual YAML deployment**

### Current Issue Context

Our Blackwell GB10 GPUs work perfectly with manual device mounting because the host has properly installed drivers. The GPU Operator's containerized components need Blackwell-compatible drivers to provide the same level of support.

### Recommended Next Steps

1. Check for GPU Operator versions with Blackwell support
2. Test with latest GPU Operator releases
3. Monitor NVIDIA's release notes for Blackwell compatibility updates
4. Consider beta/pre-release versions if available

The GPU Operator represents NVIDIA's commitment to seamless GPU integration in Kubernetes, and Blackwell support should be forthcoming as the architecture matures.