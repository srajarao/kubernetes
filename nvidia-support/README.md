# NVIDIA Blackwell GPU Support Files

This folder contains all diagnostic files and documentation for the NVIDIA device plugin compatibility issue with Blackwell GB10 GPU.

## Files Included

### Documentation
- `NVIDIA-Blackwell-Support-Issue.md` - Detailed issue report for NVIDIA support

### Log Files
- `nvidia-device-plugin-full.log` - Complete device plugin startup logs
- `kubelet-device-plugin-logs.txt` - K3s agent logs related to device plugin
- `node-spark2-describe.txt` - Full node description with GPU capacity info
- `nvidia-smi-output.txt` - Host nvidia-smi output
- `pod-gpu-test-events.txt` - Pod scheduling failure events
- `system-info.txt` - System and GPU information

### Configuration Files
- `manual-gpu-pod.yaml` - Working manual GPU pod configuration
- `gpu-test.yaml` - Test pod that fails with GPU requests (archived)

### Archive
- `nvidia-blackwell-support-files.tar.gz` - Compressed archive of all files (572KB)

## How to Use

1. **Forum Post**: Copy `NVIDIA-Blackwell-Support-Issue.md` content to NVIDIA developer forums
2. **Support Ticket**: Attach `nvidia-blackwell-support-files.tar.gz` to NVIDIA Enterprise Support ticket
3. **Reference**: Mention device plugin v0.18.0, Blackwell GB10 GPU, driver 580.95.05

## Issue Summary
- NVIDIA device plugin registers but fails GPU allocation due to NVML "Not Supported" errors
- Blackwell GB10 GPU works with nvidia-smi but not with Kubernetes device plugin
- Manual device mounting provides workaround but bypasses standard GPU scheduling

## Contact Information
Please submit to:
- NVIDIA Developer Forums: https://forums.developer.nvidia.com/
- NVIDIA Enterprise Support: https://www.nvidia.com/en-us/support/enterprise/