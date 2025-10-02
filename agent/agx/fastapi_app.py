#!/opt/venv/bin/python
"""
Unified healthcheck for Jetson (L4T r36.x)
This script performs a series of checks on the system and then launches a FastAPI server.
If any check fails, the script will exit with a specific error code.

Exit codes:
0 = all checks passed and app started
1 = libstdc++ load failed
2 = cuSPARSELt load failed
3 = PyTorch check failed
4 = TensorFlow check failed
5 = TensorRT check failed
6 = Jupyter Lab check failed
7 = FastAPI dependencies check failed
8 = Database connection failed
"""
import os
import sys
import ctypes
import subprocess
import importlib
import psycopg2
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi import Body, File, UploadFile
from pydantic import BaseModel
from typing import List, Dict, Optional


EXIT_OK = 0
EXIT_LIBSTDCPP_FAIL = 1
EXIT_CUSPARSELT_FAIL = 2
EXIT_TORCH_FAIL = 3
EXIT_TF_FAIL = 4
EXIT_TRT_FAIL = 5
EXIT_JUPYTER_FAIL = 6
EXIT_FASTAPI_FAIL = 7
EXIT_DB_FAIL = 8
EXIT_TRANSFORMERS_FAIL = 9

# Load environment variables from the .env file.
load_dotenv(dotenv_path="/workspace/postgres.env")

# === 1. HEALTH CHECK FUNCTIONS ===
##1 - LOAD LIBRARY CHECKS ---
def load_libstdcxx():
    try:
        ctypes.CDLL("libstdc++.so.6", mode=ctypes.RTLD_GLOBAL)
        print("✅ libstdc++: PASS")
        return True
    except OSError as e:
        print("❌ libstdc++: FAIL ->", e)
        return False

##2 - CUSPARSELT CHECK ---
def check_cusparselt():
    print("\n=== cuSPARSELt Check ===")
    try:
        ctypes.CDLL("libcusparseLt.so")
        print("✅ cuSPARSELt: PASS")
        return True
    except OSError as e:
        print("❌ cuSPARSELt: FAIL ->", e)
        return False

##3 - TORCH CHECK ---
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

##4 - TENSORFLOW CHECK ---
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

##5 - TENSORRT CHECK ---
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
        logger = trt.Logger(trt.Logger.ERROR)
        builder = trt.Builder(logger)
        try:
            flag = trt.NetworkDefinitionCreationFlag.EXPLICIT_BATCH
            network = builder.create_network(flag)
        except Exception:
            network = builder.create_network()
        print("✅ TensorRT: PASS")
        return True
    except Exception as e:
        if not loaded and last_err is not None:
            print("❌ TensorRT: FAIL -> libnvinfer not found:", last_err)
        print("❌ TensorRT: FAIL ->", e)
        return False

##6 - JUPYTER LAB CHECK ---
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

##7 - FASTAPI DEPENDENCIES CHECK ---
def check_fastapi_deps():
    print("\n=== FastAPI Project Dependencies Check ===")
    dependencies = {
        "psycopg2": "psycopg2",
        "python-dotenv": "dotenv",
        "fastapi": "fastapi",
        "uvicorn": "uvicorn",
        "pydantic": "pydantic",
        "scipy": "scipy",
        "pandas": "pandas",
        "scikit-learn": "sklearn",
    }
    missing_deps = []
    for pkg, import_name in dependencies.items():
        try:
            print (f"Checking import for {pkg}...")
            importlib.import_module(import_name)
        except ImportError:
            missing_deps.append(pkg)
    if missing_deps:
        print(f"❌ FastAPI dependencies missing: {', '.join(missing_deps)}")
        return False        
    print("✅ FastAPI Dependencies: PASS")
    return True

##8 - POSTGRESQL CONNECTION CHECK ---
def connect_to_db():
    print("\n=== PostgreSQL Database Connection Check ===")
    try:
        conn = psycopg2.connect(
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            host=os.getenv("DB_HOST"),
            port=os.getenv("DB_PORT"),
            database=os.getenv("DB_NAME"),
        )
        conn.close()
        print(f"DB_HOST: {os.getenv('DB_HOST')} ")
        print(f"DB_PORT: {os.getenv('DB_PORT')} ")
        print(f"DB_USER: {os.getenv('DB_USER')} ")
        print(f"DB_NAME: {os.getenv('DB_NAME')} ")
        print("✅ Database Connection: PASS")   
        return True
    except (Exception, psycopg2.Error) as error:
        print(f"❌ Error while connecting to PostgreSQL: {error}")
        return False


## -9 - TRANSFORMERS CHECK ---
def check_transformers():
    print("\n=== Transformers Library Check ===")
    try:
        import transformers
        print(f"Transformers version: {transformers.__version__}")
        print("✅ Transformers: PASS")
        return True
    except ImportError as e:
        print(f"❌ Transformers: FAIL -> {e}")
        return False
    return True


# === 2. FASTAPI APPLICATION ===

def get_fastapi_app():
    app = FastAPI()
    from transformers import AutoTokenizer, AutoModel
    import torch
    import numpy as np

    MODEL_NAME = os.getenv("TRANSFORMERS_MODEL", "distilbert-base-uncased")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModel.from_pretrained(MODEL_NAME)

    def embed_query(query: str):
        inputs = tokenizer(query, return_tensors="pt")
        with torch.no_grad():
            outputs = model(**inputs)
            hidden = outputs.last_hidden_state[0]
            embedding = hidden.mean(dim=0).cpu().numpy()
        return embedding

    def search_postgres(query_embedding, top_k=5):
        conn = psycopg2.connect(
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            host=os.getenv("DB_HOST"),
            port=os.getenv("DB_PORT"),
            database=os.getenv("DB_NAME"),
        )
        cur = conn.cursor()
        sql = """
            SELECT id, title, content, embedding
            FROM documents
            ORDER BY embedding <-> %s
            LIMIT %s;
        """
        cur.execute(sql, (list(query_embedding), top_k))
        results = cur.fetchall()
        cur.close()
        conn.close()
        return results
    ##----------------------------------------------------------------------------
    from fastapi import Body, File, UploadFile
    @app.post("/search")
    async def search(
        query: Optional[str] = Body(None, embed=True),
        image: Optional[str] = Body(None, embed=True),
        chat_thread: Optional[list] = Body(default_factory=list, embed=True),
    ):
        if not query:
            return {"results": [], "error": "Query required"}
        query_embedding = embed_query(query)
        top_docs = search_postgres(query_embedding, top_k=5)
        results = [
            {
                "id": doc[0],
                "title": doc[1],
                "content": doc[2],
                "citations": [],  # Extend as needed
                "context": doc[2],
            }
            for doc in top_docs
        ]
        return {"results": results}
    ##----------------------------------------------------------------------------
    @app.post("/chat")
    async def chat(message: str = Body(..., embed=True)):
        # Mock chat response with citations
        return {
            "response": f"Echo: {message}",
            "citations": [{"doc_id": "doc1", "text": "Sample citation for chat"}],
        }
    ##----------------------------------------------------------------------------  
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
    ##----------------------------------------------------------------------------
    @app.get("/health")
    async def health():
        return {"status": "ok"}
    ##----------------------------------------------------------------------------
    @app.get("/config")
    async def config():
        # Mock config response
        return {
            "models": ["gpt-4", "clip", "search-index"],
            "settings": {"multimodal": True, "max_results": 10},
        }

    ##----------------------------------------------------------------------------
    @app.get("/health")
    async def health():
        return {"status": "ok"}
    ##----------------------------------------------------------------------------
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
    all_checks_passed = (
        load_libstdcxx()                      ##1 - LOAD LIBRARY CHECKS ---
        and check_cusparselt()                ##2 - CUSPARSELT CHECK ---
        and check_torch()                     ##3 - TORCH CHECK ---
        # and check_tensorflow()                ##4 - TENSORFLOW CHECK ---  # Temporarily disabled
        # and check_tensorrt()                  ##5 - TENSORRT CHECK ---  # Temporarily disabled
        and check_jupyter()                   ##6 - JUPYTER CHECK ---
        and check_fastapi_deps()              ##7 - FASTAPI DEPS CHECK ---
        and connect_to_db()                   ##8 - POSTGRESQL CONNECTION CHECK ---
        and check_transformers()              ##9 - TRANSFORMERS CHECK --- 
        
    )

    if all_checks_passed:
        print("\n✅✅✅ ALL HEALTH CHECKS PASSED ✅✅✅")
        print("\nStarting FastAPI server...")
        try:
            app = get_fastapi_app()
            uvicorn.run(app, host="0.0.0.0", port=8000)
        except Exception as e:
            print(f"❌❌❌ FAILED TO START FASTAPI SERVER: {e} ❌❌❌")
            sys.exit(EXIT_OK)
    else:
        print("\n❌❌❌ ONE OR MORE CHECKS FAILED ❌❌❌")
        if not load_libstdcxx():
            sys.exit(EXIT_LIBSTDCPP_FAIL)
        if not check_cusparselt():
            sys.exit(EXIT_CUSPARSELT_FAIL)
        if not check_torch():
            sys.exit(EXIT_TORCH_FAIL)
        # if not check_tensorflow():
        #     sys.exit(EXIT_TF_FAIL)
        # if not check_tensorrt():
        #     sys.exit(EXIT_TRT_FAIL)
        if not check_jupyter():
            sys.exit(EXIT_JUPYTER_FAIL)
        if not check_fastapi_deps():
            sys.exit(EXIT_FASTAPI_FAIL)
        if not check_transformers():
            sys.exit(EXIT_TRANSFORMERS_FAIL)
        if not connect_to_db():
            sys.exit(EXIT_DB_FAIL)


if __name__ == "__main__":
    main()
