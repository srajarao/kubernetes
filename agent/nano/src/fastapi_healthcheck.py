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
from fastapi import FastAPI, HTTPException
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

# Load environment variables from the postgres.env file in the workspace root.
load_dotenv(dotenv_path='postgres.env')

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
            cudnn_version = build.get("cudnn_version") or build.get("cudnn_version_number")
            print("TF build CUDA:", cuda_version, "cuDNN:", cudnn_version)
        except Exception:
            pass
        gpus = tf.config.list_physical_devices("GPU")
        print("GPUs visible to TF:", gpus)
        print("Built with CUDA:", getattr(tf.test, "is_built_with_cuda", lambda: None)())
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
    candidates = ["libnvinfer.so.10", "libnvinfer.so.9", "libnvinfer.so.8", "libnvinfer.so"]
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
            "JupyterLab" in out or
            "Options" in out or
            "Subcommands" in out or
            "Examples" in out
        ):
            print("✅ Jupyter Lab: PASS")
            return True
        else:
            print("❌ Jupyter Lab: FAIL -> Unexpected output from 'jupyter lab --help':\n", out)
            return False
    except Exception as e:
        print("❌ Jupyter Lab: FAIL ->", e)
        return False

def check_fastapi_nano_deps():
    print("\n=== FastAPI Nano Project Dependencies Check ===")
    dependencies = {
        "psycopg2": "psycopg2", "python-dotenv": "dotenv",
    "fastapi_nano": "fastapi", "uvicorn": "uvicorn",
        "pydantic": "pydantic", "scipy": "scipy",
        "pandas": "pandas", "scikit-learn": "sklearn"
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
    print("POSTGRES_USER:", os.getenv("POSTGRES_USER"))
    print("POSTGRES_HOST:", os.getenv("POSTGRES_HOST"))
    print("POSTGRES_DB:", os.getenv("POSTGRES_DB"))
    try:
        conn = psycopg2.connect(
            user=os.getenv("POSTGRES_USER"),
            password=os.getenv("POSTGRES_PASSWORD"),
            host=os.getenv("POSTGRES_HOST"),
            port=os.getenv("POSTGRES_PORT", "5432"),
            database=os.getenv("POSTGRES_DB")
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


    @app.get("/")
    async def root():
        return {"message": "Hello from FastAPI Nano!"}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/items/{item_id}")
    def read_item(item_id: int):
        if item_id not in items_db:
            raise HTTPException(status_code=404, detail="Item not found")
        return items_db[item_id]

    @app.post("/items/")
    def create_item(item_id: int, item: Item):
        if item_id in items_db:
            raise HTTPException(status_code=400, detail="Item with this ID already exists")
        items_db[item_id] = item
        return {"message": "Item created successfully", "item": item}

    # --- New /search endpoint ---
    from fastapi import Body
    from typing import Optional

    @app.post("/search")
    async def search(query: Optional[str] = Body(None, embed=True), image: Optional[str] = Body(None, embed=True), chat_thread: Optional[list] = Body(default_factory=list, embed=True)):
        # Only text search implemented for local demo
        conn = psycopg2.connect(
            user=os.getenv("POSTGRES_USER"),
            password=os.getenv("POSTGRES_PASSWORD"),
            host=os.getenv("POSTGRES_HOST"),
            port=os.getenv("POSTGRES_PORT", "5432"),
            database=os.getenv("POSTGRES_DB")
        )
        cur = conn.cursor()
        # Search for documents matching query in title or content
        cur.execute(
            "SELECT id, title, content, file_path, doc_type, created_at FROM documents WHERE content ILIKE %s OR title ILIKE %s",
            (f"%{query}%", f"%{query}%")
        )
        results = cur.fetchall()
        cur.close()
        conn.close()
        # Format results to match Azure demo response
        return {"results": [
            {
                "id": r[0],
                "title": r[1],
                "content": r[2],
                "file_path": r[3],
                "doc_type": r[4],
                "created_at": r[5].isoformat() if r[5] else None
            } for r in results
        ]}

    return app

# === 3. MAIN SCRIPT LOGIC ===

def main():
    print("Arch:", os.uname().machine)
    all_checks_passed = (
        load_libstdcxx() and
        check_cusparselt() and
        check_torch() and
        check_tensorflow() and
        check_tensorrt() and
        check_jupyter() and
    check_fastapi_nano_deps() and
        connect_to_db()
    )

    if all_checks_passed:
        print("\n✅✅✅ ALL HEALTH CHECKS PASSED ✅✅✅")
        print("\nStarting FastAPI Nano server...")
        try:
            app = get_fastapi_nano_app()
            uvicorn.run(app, host="0.0.0.0", port=8000)
        except Exception as e:
            print(f"❌❌❌ FAILED TO START FASTAPI NANO SERVER: {e} ❌❌❌")
            sys.exit(EXIT_OK)
    else:
        print("\n❌❌❌ ONE OR MORE CHECKS FAILED ❌❌❌")
        if not load_libstdcxx(): sys.exit(EXIT_LIBSTDCPP_FAIL)
        if not check_cusparselt(): sys.exit(EXIT_CUSPARSELT_FAIL)
        if not check_torch(): sys.exit(EXIT_TORCH_FAIL)
        if not check_tensorflow(): sys.exit(EXIT_TF_FAIL)
        if not check_tensorrt(): sys.exit(EXIT_TRT_FAIL)
        if not check_jupyter(): sys.exit(EXIT_JUPYTER_FAIL)
        if not check_fastapi_nano_deps(): sys.exit(EXIT_FASTAPI_NANO_FAIL)
        if not connect_to_db(): sys.exit(EXIT_DB_FAIL)

if __name__ == "__main__":
    main()
