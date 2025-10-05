#!/usr/bin/env python3
"""
FastAPI Application for Jetson Nano
CPU-only optimized for limited resources
"""

import os
import platform
import psutil
from datetime import datetime
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import uvicorn

# Create FastAPI app
app = FastAPI(
    title="FastAPI Nano Agent",
    description="Jetson Nano CPU-only FastAPI service for Kubernetes cluster",
    version="1.0.0"
)

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "FastAPI Nano Agent",
        "device": "jetson-nano",
        "status": "running",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health_check():
    """Health check endpoint for Kubernetes"""
    try:
        # Basic system checks
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return {
            "status": "healthy",
            "device": "nano",
            "timestamp": datetime.now().isoformat(),
            "system": {
                "memory_percent": memory.percent,
                "disk_percent": disk.percent,
                "cpu_count": psutil.cpu_count(),
                "architecture": platform.machine()
            }
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Health check failed: {str(e)}")

@app.get("/ready")
async def readiness_check():
    """Readiness check endpoint for Kubernetes"""
    try:
        # Check if essential services are ready
        memory = psutil.virtual_memory()
        
        # Fail if memory usage is too high (>90%)
        if memory.percent > 90:
            raise HTTPException(status_code=503, detail="Memory usage too high")
            
        return {
            "status": "ready",
            "device": "nano",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Readiness check failed: {str(e)}")

@app.get("/info")
async def system_info():
    """Detailed system information"""
    try:
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        cpu_percent = psutil.cpu_percent(interval=1)
        
        return {
            "device": {
                "type": "jetson-nano",
                "architecture": platform.machine(),
                "platform": platform.platform(),
                "python_version": platform.python_version()
            },
            "resources": {
                "cpu": {
                    "count": psutil.cpu_count(),
                    "usage_percent": cpu_percent
                },
                "memory": {
                    "total_gb": round(memory.total / (1024**3), 2),
                    "available_gb": round(memory.available / (1024**3), 2),
                    "usage_percent": memory.percent
                },
                "disk": {
                    "total_gb": round(disk.total / (1024**3), 2),
                    "free_gb": round(disk.free / (1024**3), 2),
                    "usage_percent": disk.percent
                }
            },
            "gpu": {
                "enabled": True,
                "type": "NVIDIA Jetson Nano/Orin GPU",
                "cuda_available": True,
                "memory_info": "Shared with system memory (4GB total)"
            },
            "kubernetes": {
                "node_name": os.getenv("NODE_NAME", "unknown"),
                "pod_name": os.getenv("HOSTNAME", "unknown")
            },
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get system info: {str(e)}")

@app.get("/metrics")
async def metrics():
    """Prometheus-style metrics endpoint"""
    try:
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        cpu_percent = psutil.cpu_percent(interval=1)
        
        metrics = f"""# HELP nano_memory_usage_percent Memory usage percentage
# TYPE nano_memory_usage_percent gauge
nano_memory_usage_percent {memory.percent}

# HELP nano_disk_usage_percent Disk usage percentage  
# TYPE nano_disk_usage_percent gauge
nano_disk_usage_percent {disk.percent}

# HELP nano_cpu_usage_percent CPU usage percentage
# TYPE nano_cpu_usage_percent gauge
nano_cpu_usage_percent {cpu_percent}

# HELP nano_memory_total_bytes Total memory in bytes
# TYPE nano_memory_total_bytes gauge
nano_memory_total_bytes {memory.total}

# HELP nano_disk_total_bytes Total disk space in bytes
# TYPE nano_disk_total_bytes gauge
nano_disk_total_bytes {disk.total}
"""
        return JSONResponse(content=metrics, media_type="text/plain")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get metrics: {str(e)}")

if __name__ == "__main__":
    # Get configuration from environment variables
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    workers = int(os.getenv("WORKERS", "1"))  # Single worker for nano
    
    print(f"Starting FastAPI Nano Agent on {host}:{port}")
    print(f"Device: Jetson Nano (CPU-only)")
    print(f"Workers: {workers}")
    
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        workers=workers,
        log_level="info",
        access_log=True
    )