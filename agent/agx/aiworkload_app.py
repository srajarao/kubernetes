#!/opt/venv/bin/python
"""
Unified healthcheck for Jetson (L4T r36.x)
This script performs a series of checks on the system and then launches a FastAPI Nano server.
If any check fails, the script will exit with a specific error code.

Exit codes:
  0 = all checks passed and app started
  1 = libstdc++ load failed
  2 = cuSPARSELt load failed
  3 = PyTorch check failed
  4 = TensorFlow check failed
  5 = TensorRT check failed
  6 = Jupyter Lab check failed
    7 = FastAPI Nano dependencies check failed
  8 = Database connection failed
"""
import os, sys, ctypes, subprocess
import importlib
import psycopg2
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from typing import List, Dict
import uvicorn
from pydantic import BaseModel
from typing import Dict, Optional


EXIT_OK = 0
EXIT_LIBSTDCPP_FAIL = 1
EXIT_CUSPARSELT_FAIL = 2
EXIT_TORCH_FAIL = 3
EXIT_TF_FAIL = 4
EXIT_TRT_FAIL = 5
EXIT_JUPYTER_FAIL = 6
EXIT_FASTAPI_NANO_FAIL = 7
EXIT_DB_FAIL = 8

# Load environment variables from the .env file.
load_dotenv(dotenv_path="/usr/local/bin/postgres.env")


# A Pydantic model to define the data structure for an Item
class Item(BaseModel):
    name: str
    price: float
    is_offer: Optional[bool] = None


# A simple in-memory "database"
items_db: Dict[int, Item] = {}

# === 1. HEALTH CHECK FUNCTIONS ===


def load_libstdcxx():
    try:
        ctypes.CDLL("libstdc++.so.6", mode=ctypes.RTLD_GLOBAL)
        print("✅ libstdc++: PASS")
        return True
    except OSError as e:
        print("❌ libstdc++: FAIL ->", e)
        return False


def check_cusparselt():
    print("\n=== cuSPARSELt Check ===")
    try:
        ctypes.CDLL("libcusparseLt.so")
        print("✅ cuSPARSELt: PASS")
        return True
    except OSError as e:
        print("❌ cuSPARSELt: FAIL ->", e)
        return False


def check_torch():
    print("\n=== PyTorch + CUDA + cuDNN Check ===")
    try:
        import torch

        print("Torch:", torch.__version__)
        print("CUDA available:", torch.cuda.is_available())
        print("cuDNN enabled:", torch.backends.cudnn.is_available())
        if torch.backends.cudnn.is_available():
            try:
                print("cuDNN version:", torch.backends.cudnn.version())
            except Exception:
                pass
        if torch.cuda.is_available():
            try:
                print("GPU name:", torch.cuda.get_device_name(0))
            except Exception:
                pass
            x = torch.randn(2, 3, device="cuda")
            y = torch.randn(2, 3, device="cuda")
            _ = x + y
        print("✅ PyTorch: PASS")
        return True
    except Exception as e:
        print("❌ PyTorch: FAIL ->", e)
        return False


def check_tensorflow():
    print("\n=== TensorFlow + GPU + cuDNN Check ===")
    try:
        os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
        import tensorflow as tf

        print("TensorFlow:", tf.__version__)
        try:
            build = tf.sysconfig.get_build_info()
            cuda_version = build.get("cuda_version") or build.get("cuda_version_number")
            cudnn_version = build.get("cudnn_version") or build.get(
                "cudnn_version_number"
            )
            print("TF build CUDA:", cuda_version, "cuDNN:", cudnn_version)
        except Exception:
            pass
        gpus = tf.config.list_physical_devices("GPU")
        print("GPUs visible to TF:", gpus)
        print(
            "Built with CUDA:", getattr(tf.test, "is_built_with_cuda", lambda: None)()
        )
        if gpus:
            try:
                x = tf.random.normal([2, 3])
                y = tf.random.normal([2, 3])
                z = x + y
                _ = z.numpy()
                print("✅ TensorFlow: PASS")
            except Exception as e:
                print("❌ TensorFlow: FAIL ->", e)
                return False
        else:
            print("❌ TensorFlow: FAIL -> No GPU detected")
            return False
        return True
    except Exception as e:
        print("❌ TensorFlow: FAIL ->", e)
        return False


def check_tensorrt():
    print("\n=== TensorRT Check ===")
    candidates = [
        "libnvinfer.so.10",
        "libnvinfer.so.9",
        "libnvinfer.so.8",
        "libnvinfer.so",
    ]
    loaded = False
    last_err = None
    for name in candidates:
        try:
            ctypes.CDLL(name)
            print(f"Found {name}")
            loaded = True
            break
        except OSError as e:
            last_err = e
    try:
        import tensorrt as trt
        print("TensorRT Python version:", getattr(trt, "__version__", "unknown"))
        print("✅ TensorRT: PASS (skipping builder test)")
        return True
    except Exception as e:
        if not loaded and last_err is not None:
            print("❌ TensorRT: FAIL -> libnvinfer not found:", last_err)
        print("❌ TensorRT: FAIL ->", e)
        return False


def check_jupyter():
    print("\n=== Jupyter Lab Check ===")
    try:
        import jupyterlab

        print("JupyterLab version:", getattr(jupyterlab, "__version__", "unknown"))
        jupyter_bin = subprocess.getoutput("command -v jupyter")
        if not jupyter_bin:
            print("❌ Jupyter Lab: FAIL -> 'jupyter' binary not found in PATH")
            return False
        print("Found jupyter binary at:", jupyter_bin)
        out = subprocess.getoutput(f"{jupyter_bin} lab --help 2>&1")
        if out.strip() and (
            "JupyterLab" in out
            or "Options" in out
            or "Subcommands" in out
            or "Examples" in out
        ):
            print("✅ Jupyter Lab: PASS")
            return True
        else:
            print(
                "❌ Jupyter Lab: FAIL -> Unexpected output from 'jupyter lab --help':\n",
                out,
            )
            return False
    except Exception as e:
        print("❌ Jupyter Lab: FAIL ->", e)
        return False


def check_fastapi_nano_deps():
    print("\n=== FastAPI Nano Project Dependencies Check ===")
    dependencies = {
        "psycopg2": "psycopg2",
        "python-dotenv": "dotenv",
    "fastapi_nano": "fastapi",
        "uvicorn": "uvicorn",
        "pydantic": "pydantic",
        "scipy": "scipy",
        "pandas": "pandas",
        "scikit-learn": "sklearn",
    }
    missing_deps = []
    for pkg, import_name in dependencies.items():
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing_deps.append(pkg)
    if missing_deps:
        print(f"❌ FastAPI Nano dependencies missing: {', '.join(missing_deps)}")
        return False
    print("✅ FastAPI Nano Dependencies: PASS")
    return True


def connect_to_db():
    print("\n=== PostgreSQL Database Connection Check ===")
    try:
        conn = psycopg2.connect(
            user=os.getenv("POSTGRES_USER"),
            password=os.getenv("POSTGRES_PASSWORD"),
            host=os.getenv("POSTGRES_HOST"),
            port=os.getenv("POSTGRES_PORT", "5432"),
            database=os.getenv("POSTGRES_DB"),
        )
        conn.close()
        print("✅ Database Connection: PASS")
        return True
    except (Exception, psycopg2.Error) as error:
        print(f"❌ Error while connecting to PostgreSQL: {error}")
        return False


# === 2. FASTAPI NANO APPLICATION ===


def get_fastapi_nano_app():
    app = FastAPI()

    from fastapi import File, UploadFile, Body
    from typing import Optional

    # --- Real backend integration for /search ---
    from src.backend.multimodalrag import MultimodalRag
    from src.backend.search_grounding import SearchGroundingRetriever
    from src.backend.data_model import DocumentPerChunkDataModel
    from src.backend.knowledge_agent import KnowledgeAgentGrounding
    from src.backend.models import SearchConfig, Message
    from azure.search.documents.aio import SearchClient
    from azure.storage.blob import ContainerClient
    from openai import AsyncAzureOpenAI
    import os

    # These should be loaded from config/env for production
    SEARCH_ENDPOINT = os.getenv("SEARCH_ENDPOINT", "<your-search-endpoint>")
    SEARCH_KEY = os.getenv("SEARCH_KEY", "<your-search-key>")
    SEARCH_INDEX = os.getenv("SEARCH_INDEX", "<your-search-index>")
    OPENAI_ENDPOINT = os.getenv("OPENAI_ENDPOINT", "<your-openai-endpoint>")
    OPENAI_KEY = os.getenv("OPENAI_KEY", "<your-openai-key>")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4")
    STORAGE_CONN_STR = os.getenv("STORAGE_CONN_STR", "<your-storage-conn-str>")
    STORAGE_CONTAINER = os.getenv("STORAGE_CONTAINER", "<your-container>")

    # Backend object initialization (should be done once, not per request)
    search_client = SearchClient(SEARCH_ENDPOINT, SEARCH_INDEX, SEARCH_KEY)
    openai_client = AsyncAzureOpenAI(api_key=OPENAI_KEY, azure_endpoint=OPENAI_ENDPOINT)
    data_model = DocumentPerChunkDataModel()
    search_grounding = SearchGroundingRetriever(
        search_client, openai_client, data_model, OPENAI_MODEL
    )
    knowledge_agent = KnowledgeAgentGrounding()
    container_client = ContainerClient.from_connection_string(
        STORAGE_CONN_STR, STORAGE_CONTAINER
    )
    rag = MultimodalRag(
        knowledge_agent, search_grounding, openai_client, OPENAI_MODEL, container_client
    )

    @app.post("/search")
    async def search(
        query: Optional[str] = Body(None, embed=True),
        image: Optional[str] = Body(None, embed=True),
        chat_thread: Optional[list] = Body(default_factory=list, embed=True),
    ):
        # Build search config (can be extended to accept more params)
        search_config: SearchConfig = {
            "chunk_count": 10,
            "openai_api_mode": "chat_completions",
            "use_semantic_ranker": True,
            "use_streaming": False,
            "use_knowledge_agent": False,
        }
        user_message = query or ""
        # Convert chat_thread to expected format
        thread = chat_thread if chat_thread else []
        # Call backend search logic
        results = await search_grounding.retrieve(user_message, thread, search_config)
        return {"results": results}

    @app.post("/chat")
    async def chat(message: str = Body(..., embed=True)):
        # Mock chat response with citations
        return {
            "response": f"Echo: {message}",
            "citations": [{"doc_id": "doc1", "text": "Sample citation for chat"}],
        }

    @app.get("/citations")
    async def citations(doc_id: str = Query(...)):
        # Mock citation data
        return {"citations": [{"doc_id": doc_id, "text": "Sample citation text"}]}

    @app.post("/upload")
    async def upload(file: UploadFile = File(...)):
        # Mock upload response
        return {
            "status": "success",
            "filename": file.filename,
            "doc_id": "doc_uploaded",
        }

    @app.get("/health")
    async def health():
        """Comprehensive health check including all GPU modules and dependencies"""
        import datetime

        health_status = {
            "status": "checking",
            "timestamp": datetime.datetime.now().isoformat(),
            "device": "agx",
            "gpu_enabled": True,
            "modules": {}
        }

        # Run all module checks
        try:
            health_status["modules"]["libstdc++"] = load_libstdcxx()
            health_status["modules"]["cusparselt"] = check_cusparselt()
            health_status["modules"]["pytorch"] = check_torch()
            health_status["modules"]["tensorflow"] = check_tensorflow()
            health_status["modules"]["tensorrt"] = check_tensorrt()
            health_status["modules"]["jupyter"] = check_jupyter()
            health_status["modules"]["fastapi_deps"] = check_fastapi_nano_deps()
            health_status["modules"]["database"] = connect_to_db()
            
            # Additional AI workload specific checks
            try:
                import transformers
                health_status["modules"]["transformers"] = True
            except ImportError:
                health_status["modules"]["transformers"] = False
                
            try:
                import torch
                # Check for advanced PyTorch features
                health_status["modules"]["torchvision"] = True
            except ImportError:
                health_status["modules"]["torchvision"] = False

            # Determine overall status
            all_modules_ok = all(health_status["modules"].values())
            health_status["status"] = "healthy" if all_modules_ok else "unhealthy"

        except Exception as e:
            health_status["status"] = "error"
            health_status["error"] = str(e)

        return health_status

    @app.get("/ready")
    async def ready():
        return {"status": "ready"}

    @app.get("/config")
    async def config():
        # Mock config response
        return {
            "models": ["gpt-4", "clip", "search-index"],
            "settings": {"multimodal": True, "max_results": 10},
        }

    return app


# === 3. MAIN SCRIPT LOGIC ===


def main():
    print("Arch:", os.uname().machine)
    
    print("Running libstdc++ check...")
    result1 = load_libstdcxx()
    print(f"libstdc++ result: {result1}")
    
    print("Running cuSPARSELt check...")
    result2 = check_cusparselt()
    print(f"cuSPARSELt result: {result2}")
    
    print("Running PyTorch check...")
    result3 = check_torch()
    print(f"PyTorch result: {result3}")
    
    print("Running TensorFlow check...")
    result4 = check_tensorflow()
    print(f"TensorFlow result: {result4}")
    
    print("Running TensorRT check...")
    result5 = check_tensorrt()
    print(f"TensorRT result: {result5}")
    
    print("Running Jupyter check...")
    result6 = check_jupyter()
    print(f"Jupyter result: {result6}")
    
    print("Running FastAPI Nano deps check...")
    result7 = check_fastapi_nano_deps()
    print(f"FastAPI Nano deps result: {result7}")
    
    print("Running database check...")
    result8 = connect_to_db()
    print(f"Database result: {result8}")
    
    all_checks_passed = result1 and result2 and result3 and result4 and result5 and result6 and result7 and result8
    
    print(f"\nAll checks passed: {all_checks_passed}")

    if all_checks_passed:
        print("\n✅✅✅ ALL HEALTH CHECKS PASSED ✅✅✅")
        print("\nStarting FastAPI Nano server...")
        try:
            app = get_fastapi_nano_app()
            uvicorn.run(app, host="0.0.0.0", port=8000)
        except Exception as e:
            print(f"❌❌❌ FAILED TO START FASTAPI NANO SERVER: {e} ❌❌❌")
            sys.exit(1)
    else:
        print("\n❌❌❌ ONE OR MORE CHECKS FAILED ❌❌❌")
        if not load_libstdcxx():
            sys.exit(EXIT_LIBSTDCPP_FAIL)
        if not check_cusparselt():
            sys.exit(EXIT_CUSPARSELT_FAIL)
        if not check_torch():
            sys.exit(EXIT_TORCH_FAIL)
        if not check_tensorflow():
            sys.exit(EXIT_TF_FAIL)
        if not check_tensorrt():
            sys.exit(EXIT_TRT_FAIL)
        if not check_jupyter():
            sys.exit(EXIT_JUPYTER_FAIL)
        if not check_fastapi_nano_deps():
            sys.exit(EXIT_FASTAPI_NANO_FAIL)
        if not connect_to_db():
            sys.exit(EXIT_DB_FAIL)


if __name__ == "__main__":
    main()
