# Auto-generated health check endpoints for agx node
# Components: python,cuda,tensorrt,pytorch,tensorflow,fastapi,gpu-monitoring,llm,rag
# Generated: Sat 11 Oct 2025 04:12:12 PM PDT

from fastapi import APIRouter, HTTPException
from typing import Dict, Any
import logging

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """Basic application health check"""
    return {
        "status": "healthy",
        "service": "fastapi",
        "timestamp": "2025-01-01T00:00:00Z"  # Will be replaced with actual timestamp
    }


@router.get("/health/gpu")
async def gpu_health_check() -> Dict[str, Any]:
    """GPU availability and status check"""
    try:
        import subprocess
        result = subprocess.run(['nvidia-smi', '--query-gpu=name,memory.used,memory.total',
                               '--format=csv,noheader,nounits'],
                              capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            # Parse GPU info
            gpu_info = result.stdout.strip().split('\n')[0].split(', ')
            return {
                "status": "healthy",
                "service": "gpu",
                "gpu_name": gpu_info[0] if len(gpu_info) > 0 else "unknown",
                "memory_used_mb": int(gpu_info[1]) if len(gpu_info) > 1 else 0,
                "memory_total_mb": int(gpu_info[2]) if len(gpu_info) > 2 else 0
            }
        else:
            raise HTTPException(status_code=503, detail="GPU not available")
    except Exception as e:
        logger.error(f"GPU health check failed: {e}")
        raise HTTPException(status_code=503, detail="GPU check failed")


@router.get("/health/llm")
async def llm_health_check() -> Dict[str, Any]:
    """LLM model loading and inference check"""
    try:
        # Add your LLM health check logic here
        # Example: check if model is loaded and can do basic inference
        return {
            "status": "healthy",
            "service": "llm",
            "model_loaded": True,
            "inference_ready": True
        }
    except Exception as e:
        logger.error(f"LLM health check failed: {e}")
        raise HTTPException(status_code=503, detail="LLM service unavailable")


@router.get("/health/rag")
async def rag_health_check() -> Dict[str, Any]:
    """RAG system health check"""
    try:
        # Add your RAG health check logic here
        # Example: check vector database connectivity and embedding model
        return {
            "status": "healthy",
            "service": "rag",
            "vector_db": "connected",
            "embedding_model": "loaded"
        }
    except Exception as e:
        logger.error(f"RAG health check failed: {e}")
        raise HTTPException(status_code=503, detail="RAG service unavailable")


# Comprehensive health check combining all component checks
@router.get("/health/comprehensive")
async def comprehensive_health_check() -> Dict[str, Any]:
    """Comprehensive health check for all components"""
    results = {}
    overall_status = "healthy"

    try:
        # FastAPI basic check
        results["fastapi"] = (await health_check())["status"]
    except:
        results["fastapi"] = "unhealthy"
        overall_status = "unhealthy"

    # Add other component checks here based on what's enabled
    try:
        results["gpu"] = (await gpu_health_check())["status"]
    except:
        results["gpu"] = "unhealthy"
        overall_status = "unhealthy"
    try:
        results["llm"] = (await llm_health_check())["status"]
    except:
        results["llm"] = "unhealthy"
        overall_status = "unhealthy"
    try:
        results["rag"] = (await rag_health_check())["status"]
    except:
        results["rag"] = "unhealthy"
        overall_status = "unhealthy"

    return {
        "status": overall_status,
        "components": results,
        "timestamp": "2025-01-01T00:00:00Z"  # Will be replaced with actual timestamp
    }
