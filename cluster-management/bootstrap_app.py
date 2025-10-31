"""
Basic Hello World Web Server - Bootstrap Starting Point
A minimal FastAPI application to demonstrate native Python web serving
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os
import pathlib
from typing import List, Dict, Any, Optional
import stat
import subprocess
import asyncio
from datetime import datetime, timedelta
import json
import docker
import hashlib
import secrets
import logging
from logging.handlers import RotatingFileHandler
import ipaddress
import shutil
from jose import JWTError, jwt
from pydantic import BaseModel

app = FastAPI(
    title="Script Executor Bootstrap",
    description="Basic web server for cluster management bootstrap",
    version="0.1.0"
)

# Audit logging configuration
AUDIT_LOG_FILE = "audit.log"
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)

# Create rotating file handler for audit logs
audit_handler = RotatingFileHandler(
    AUDIT_LOG_FILE,
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
audit_formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
audit_handler.setFormatter(audit_formatter)
audit_logger.addHandler(audit_handler)

def log_audit_event(event_type: str, username: str, action: str, resource: str = None,
                   details: Dict[str, Any] = None, ip_address: str = None, user_agent: str = None):
    """Log an audit event"""
    audit_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "username": username,
        "action": action,
        "resource": resource,
        "details": details or {},
        "ip_address": ip_address,
        "user_agent": user_agent
    }
    audit_logger.info(json.dumps(audit_data))

def get_client_info(request):
    """Extract client information from request"""
    client_host = getattr(request.client, 'host', None) if hasattr(request, 'client') else None
    user_agent = request.headers.get('user-agent', None)
    return client_host, user_agent

# SSL/HTTPS Configuration
SSL_CERT_FILE = "ssl/cert.pem"
SSL_KEY_FILE = "ssl/key.pem"

def generate_ssl_certificates():
    """Generate self-signed SSL certificates for HTTPS"""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    import datetime

    # Create SSL directory if it doesn't exist
    ssl_dir = pathlib.Path("ssl")
    ssl_dir.mkdir(exist_ok=True)

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Generate certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Kubernetes Cluster Management"),
        x509.NameAttribute(NameOID.COMMON_NAME, "cluster-management.local"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("cluster-management.local"),
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            x509.IPAddress(ipaddress.IPv4Address("192.168.1.181")),  # nano IP
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())

    # Write certificate and private key to files
    with open(SSL_CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(SSL_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

# Authentication configuration
SECRET_KEY = "your-secret-key-change-in-production"  # TODO: Move to environment variable
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Simple password hashing using hashlib + salt
def hash_password(password: str) -> str:
    """Hash a password with salt"""
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hashed}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    try:
        salt, hash_value = hashed_password.split(":", 1)
        computed = hashlib.sha256((salt + plain_password).encode()).hexdigest()
        return secrets.compare_digest(computed, hash_value)
    except:
        return False

security = HTTPBearer()

# User models
class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None
    role: str = "viewer"  # viewer, operator, admin

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

# In-memory user database (TODO: Replace with proper database)
fake_users_db = {
    "admin": {
        "username": "admin",
        "full_name": "Cluster Administrator",
        "email": "admin@cluster.local",
        "password": "admin123",  # Plain text for now - will be hashed at runtime
        "disabled": False,
        "role": "admin"
    },
    "operator": {
        "username": "operator",
        "full_name": "Cluster Operator",
        "email": "operator@cluster.local",
        "password": "operator123",
        "disabled": False,
        "role": "operator"
    },
    "viewer": {
        "username": "viewer",
        "full_name": "Cluster Viewer",
        "email": "viewer@cluster.local",
        "password": "viewer123",
        "disabled": False,
        "role": "viewer"
    }
}

# Hash passwords at startup
for user in fake_users_db.values():
    if "password" in user:
        user["hashed_password"] = hash_password(user["password"])
        del user["password"]

# Docker client - lazy initialization
docker_client = None
docker_available = None

# Authentication functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    try:
        salt, hash_value = hashed_password.split(":", 1)
        computed = hashlib.sha256((salt + plain_password).encode()).hexdigest()
        return secrets.compare_digest(computed, hash_value)
    except:
        return False

def get_password_hash(password):
    """Hash a password"""
    return hash_password(password)

def get_user(db, username: str):
    """Get user from database"""
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db, username: str, password: str):
    """Authenticate a user"""
    # TEMPORARY: Allow blank username and password for testing
    if username == "" and password == "":
        # Return a default admin user for blank credentials
        return User(
            username="admin",
            email="admin@cluster.local",
            full_name="Cluster Administrator",
            disabled=False,
            role="admin",
            hashed_password="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6fYzYXeUe"  # dummy hash
        )

    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current authenticated user"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    """Get current active user"""
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def get_docker_client():
    """Get Docker status by testing CLI access"""
    global docker_client, docker_available
    
    if docker_available is None:
        try:
            # Test Docker CLI access
            result = subprocess.run(
                ['docker', 'version', '--format', 'json'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                docker_available = True
                docker_client = "cli"  # Marker that CLI works
                print("Docker CLI access confirmed")
            else:
                raise Exception(f"Docker CLI failed: {result.stderr}")
                
        except Exception as e:
            print(f"Docker CLI test failed: {e}")
            docker_client = None
            docker_available = False
    
    return docker_client if docker_available else None

def discover_scripts(base_path: str = "/home/sanjay/containers/kubernetes") -> Dict[str, Any]:
    """
    Discover all shell scripts in the kubernetes directory structure.
    Returns organized script catalog with metadata.
    """
    scripts = []
    base_path_obj = pathlib.Path(base_path)
    
    # Find all .sh files
    for script_path in base_path_obj.rglob("*.sh"):
        try:
            # Skip certain directories
            if any(skip in str(script_path) for skip in ['pgadmin/data', '__pycache__', '.git']):
                continue
                
            # Get file stats
            stat_info = script_path.stat()
            
            # Check if executable
            is_executable = bool(stat_info.st_mode & stat.S_IXUSR)
            
            # Get relative path
            relative_path = script_path.relative_to(base_path_obj)
            
            # Categorize by directory
            path_parts = relative_path.parts
            category = path_parts[0] if len(path_parts) > 0 else "root"
            
            # Get file size and modification time
            size = stat_info.st_size
            mtime = stat_info.st_mtime
            
            script_info = {
                "name": script_path.name,
                "path": str(relative_path),
                "full_path": str(script_path),
                "category": category,
                "size": size,
                "executable": is_executable,
                "last_modified": mtime,
                "directory": str(script_path.parent)
            }
            
            scripts.append(script_info)
            
        except (OSError, PermissionError):
            # Skip files we can't access
            continue
    
    # Organize by category
    categories = {}
    for script in scripts:
        cat = script["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(script)
    
    # Sort scripts within each category by name
    for cat_scripts in categories.values():
        cat_scripts.sort(key=lambda x: x["name"])
    
    return {
        "total_scripts": len(scripts),
        "categories": categories,
        "scripts": scripts
    }

async def execute_script(script_path: str, timeout: int = 30) -> Dict[str, Any]:
    """
    Execute a script and capture its output.
    Returns execution results with stdout, stderr, return code, and timing.
    """
    start_time = datetime.now()
    
    try:
        # Check if script exists and is executable
        if not os.path.exists(script_path):
            return {
                "success": False,
                "error": f"Script not found: {script_path}",
                "script_path": script_path
            }
        
        if not os.access(script_path, os.X_OK):
            return {
                "success": False,
                "error": f"Script is not executable: {script_path}",
                "script_path": script_path
            }
        
        # Execute the script
        process = await asyncio.create_subprocess_exec(
            script_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=os.path.dirname(script_path)
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            return {
                "success": False,
                "error": f"Script execution timed out after {timeout} seconds",
                "script_path": script_path,
                "timeout": timeout
            }
        
        end_time = datetime.now()
        execution_time = (end_time - start_time).total_seconds()
        
        return {
            "success": True,
            "script_path": script_path,
            "return_code": process.returncode,
            "stdout": stdout.decode('utf-8', errors='replace'),
            "stderr": stderr.decode('utf-8', errors='replace'),
            "execution_time": execution_time,
            "timestamp": end_time.isoformat()
        }
        
    except Exception as e:
        end_time = datetime.now()
        execution_time = (end_time - start_time).total_seconds()
        
        return {
            "success": False,
            "error": str(e),
            "script_path": script_path,
            "execution_time": execution_time
        }

# Docker-related functions
def get_docker_info() -> Dict[str, Any]:
    """
    Get Docker system information and status.
    """
    if not get_docker_client():
        return {
            "available": False,
            "error": "Docker client not available"
        }
    
    try:
        # Get Docker version
        version_result = subprocess.run(
            ['docker', 'version', '--format', '{{.Server.Version}}'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Get system info
        info_result = subprocess.run(
            ['docker', 'system', 'info', '--format', '{{.Containers}}|{{.ContainersRunning}}|{{.Images}}'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if version_result.returncode == 0 and info_result.returncode == 0:
            containers_total, containers_running, images = info_result.stdout.strip().split('|')
            return {
                "available": True,
                "version": {"ApiVersion": "N/A", "Version": version_result.stdout.strip()},
                "info": {
                    "containers": int(containers_total),
                    "containers_running": int(containers_running),
                    "containers_paused": 0,  # Not easily available via CLI
                    "containers_stopped": int(containers_total) - int(containers_running),
                    "images": int(images),
                    "docker_root_dir": "N/A",
                    "server_version": version_result.stdout.strip()
                }
            }
        else:
            raise Exception("Docker CLI commands failed")
            
    except Exception as e:
        return {
            "available": False,
            "error": str(e)
        }

def list_docker_images() -> Dict[str, Any]:
    """
    List all Docker images on the system.
    """
    if not get_docker_client():
        return {"available": False, "error": "Docker client not available"}
    
    try:
        result = subprocess.run(
            ['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}|{{.ID}}|{{.Size}}'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            images = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.split('|')
                    if len(parts) >= 3:
                        repo_tag = parts[0]
                        image_id = parts[1]
                        size = parts[2]
                        images.append({
                            "repo_tags": [repo_tag],
                            "id": image_id,
                            "size": size
                        })
            
            return {
                "available": True,
                "images": images,
                "count": len(images)
            }
        else:
            raise Exception(f"Docker images command failed: {result.stderr}")
            
    except Exception as e:
        return {
            "available": False,
            "error": str(e)
        }

def list_docker_containers() -> Dict[str, Any]:
    """
    List all Docker containers (running and stopped).
    """
    if not get_docker_client():
        return {"available": False, "error": "Docker client not available"}
    
    try:
        result = subprocess.run(
            ['docker', 'ps', '-a', '--format', '{{.Names}}|{{.Image}}|{{.Status}}|{{.ID}}'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            containers = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.split('|')
                    if len(parts) >= 4:
                        containers.append({
                            "name": parts[0],
                            "image": parts[1],
                            "status": parts[2],
                            "id": parts[3]
                        })
            
            return {
                "available": True,
                "containers": containers,
                "count": len(containers)
            }
        else:
            raise Exception(f"Docker ps command failed: {result.stderr}")
            
    except Exception as e:
        return {
            "available": False,
            "error": str(e)
        }

async def build_docker_image(dockerfile_path: str, tag: str, build_context: str = None) -> Dict[str, Any]:
    """
    Build a Docker image from a Dockerfile using CLI.
    Returns build results.
    """
    if not get_docker_client():
        return {
            "success": False,
            "error": "Docker client not available"
        }
    
    start_time = datetime.now()
    
    try:
        # Determine build context
        if build_context is None:
            build_context = os.path.dirname(dockerfile_path)
        
        # Validate paths
        if not os.path.exists(dockerfile_path):
            return {
                "success": False,
                "error": f"Dockerfile not found: {dockerfile_path}"
            }
        
        if not os.path.exists(build_context):
            return {
                "success": False,
                "error": f"Build context not found: {build_context}"
            }
        
        # Run docker build
        cmd = [
            'docker', 'build',
            '-f', dockerfile_path,
            '-t', tag,
            build_context
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minutes timeout
        )
        
        end_time = datetime.now()
        execution_time = (end_time - start_time).total_seconds()
        
        if result.returncode == 0:
            return {
                "success": True,
                "image_id": "N/A",  # Would need to parse from output
                "tag": tag,
                "build_logs": result.stdout,
                "execution_time": execution_time,
                "timestamp": end_time.isoformat()
            }
        else:
            return {
                "success": False,
                "error": result.stderr,
                "execution_time": execution_time
            }
        
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Build timed out",
            "execution_time": 300
        }
    except Exception as e:
        end_time = datetime.now()
        execution_time = (end_time - start_time).total_seconds()
        
        return {
            "success": False,
            "error": str(e),
            "execution_time": execution_time
        }

# Cluster management functions
def get_cluster_node_info() -> Dict[str, Any]:
    """
    Get information about all cluster nodes from the main README.
    This provides a static view of the cluster configuration.
    """
    nodes = {
        "control_plane": {
            "name": "Tower",
            "ip": "192.168.1.150",
            "role": "Control Plane, Registry, Storage",
            "gpu_support": "None",
            "status": "online",
            "services": ["Docker Registry", "PostgreSQL", "pgAdmin", "NFS Server"]
        },
        "gpu_workers": [
            {
                "name": "Nano",
                "ip": "192.168.1.181",
                "role": "GPU Worker Node",
                "gpu_support": "Jetson Nano GPU",
                "status": "online",
                "services": ["FastAPI App", "Jupyter Lab", "GPU Runtime", "NVIDIA GPU"]
            },
            {
                "name": "AGX",
                "ip": "192.168.1.244",
                "role": "GPU Worker Node",
                "gpu_support": "AGX Orin GPU",
                "status": "online",
                "services": ["FastAPI App", "Jupyter Lab", "GPU Runtime", "NVIDIA GPU"]
            },
            {
                "name": "DGX-Spark-1",
                "ip": "192.168.1.201",
                "role": "GPU Worker Node",
                "gpu_support": "Blackwell GB10",
                "status": "online",
                "services": ["K3s Agent", "GPU Operator", "Blackwell GB10", "TensorFlow/PyTorch"]
            },
            {
                "name": "DGX-Spark-2",
                "ip": "192.168.1.202",
                "role": "GPU Worker Node",
                "gpu_support": "Blackwell GB10",
                "status": "online",
                "services": ["K3s Agent", "GPU Operator", "Blackwell GB10", "TensorFlow/PyTorch"]
            }
        ],
        "network_gateways": [
            {
                "name": "Krithi",
                "ip": "192.168.1.100",
                "role": "VPN Gateway & Network Access",
                "gpu_support": "None",
                "status": "online",
                "services": ["OpenVPN Server", "Network Access", "NFS Client", "Host Resolution"]
            }
        ]
    }
    
    return {
        "cluster_name": "K3s Multi-Node AI Cluster",
        "total_nodes": 6,
        "nodes": nodes,
        "network_topology": "Comcast Business Router → ER605 Router → 10G Unifi Switch",
        "last_updated": datetime.now().isoformat()
    }

async def check_cluster_status() -> Dict[str, Any]:
    """
    Check real-time status of cluster nodes by attempting connections.
    """
    nodes = get_cluster_node_info()
    status_results = {}
    
    for category, node_list in nodes["nodes"].items():
        if isinstance(node_list, list):
            for node in node_list:
                node_name = node["name"].lower()
                node_ip = node["ip"]
                
                # Ping check
                ping_success = await ping_node(node_ip)
                
                # Basic connectivity check (if ping succeeds, try SSH)
                ssh_success = False
                if ping_success:
                    ssh_success = await check_ssh_connectivity(node_ip)
                
                status_results[node_name] = {
                    "name": node["name"],
                    "ip": node_ip,
                    "pingable": ping_success,
                    "ssh_accessible": ssh_success,
                    "configured_status": node["status"],
                    "last_checked": datetime.now().isoformat()
                }
        else:
            # Single node (control plane)
            node = node_list
            node_name = node["name"].lower()
            node_ip = node["ip"]
            
            ping_success = await ping_node(node_ip)
            ssh_success = False
            if ping_success:
                ssh_success = await check_ssh_connectivity(node_ip)
            
            status_results[node_name] = {
                "name": node["name"],
                "ip": node_ip,
                "pingable": ping_success,
                "ssh_accessible": ssh_success,
                "configured_status": node["status"],
                "last_checked": datetime.now().isoformat()
            }
    
    return {
        "cluster_status": status_results,
        "summary": {
            "total_nodes": len(status_results),
            "pingable_nodes": sum(1 for s in status_results.values() if s["pingable"]),
            "ssh_accessible_nodes": sum(1 for s in status_results.values() if s["ssh_accessible"]),
            "timestamp": datetime.now().isoformat()
        }
    }

async def ping_node(ip: str) -> bool:
    """
    Ping a node to check basic connectivity.
    """
    try:
        result = await asyncio.create_subprocess_exec(
            'ping', '-c', '1', '-W', '2', ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await result.wait()
        return result.returncode == 0
    except Exception:
        return False

async def check_ssh_connectivity(ip: str) -> bool:
    """
    Check if SSH connection is possible to the node.
    """
    try:
        result = await asyncio.create_subprocess_exec(
            'ssh', '-o', 'ConnectTimeout=3', '-o', 'StrictHostKeyChecking=no', 
            '-o', 'UserKnownHostsFile=/dev/null', f'sanjay@{ip}', 'echo "test"',
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await result.wait()
        return result.returncode == 0
    except Exception:
        return False

async def ping_nodes(node_names: List[str]) -> Dict[str, Any]:
    """
    Ping multiple nodes and return detailed results.
    """
    nodes_info = get_cluster_node_info()
    results = {}
    
    for node_name in node_names:
        node_name_lower = node_name.lower()
        
        # Find node IP
        node_ip = None
        for category, node_list in nodes_info["nodes"].items():
            if isinstance(node_list, list):
                for node in node_list:
                    if node["name"].lower() == node_name_lower:
                        node_ip = node["ip"]
                        break
            else:
                if node_list["name"].lower() == node_name_lower:
                    node_ip = node_list["ip"]
                    break
        
        if node_ip:
            ping_success = await ping_node(node_ip)
            results[node_name] = {
                "ip": node_ip,
                "pingable": ping_success,
                "timestamp": datetime.now().isoformat()
            }
        else:
            results[node_name] = {
                "error": f"Node '{node_name}' not found in cluster configuration",
                "timestamp": datetime.now().isoformat()
            }
    
    return {
        "ping_results": results,
        "summary": {
            "requested_nodes": len(node_names),
            "successful_pings": sum(1 for r in results.values() if r.get("pingable", False)),
            "timestamp": datetime.now().isoformat()
        }
    }

# Docker API endpoints
@app.get("/api/docker/info")
async def docker_info():
    """
    Get Docker system information and status.
    """
    return get_docker_info()

@app.get("/api/docker/images")
async def docker_images():
    """
    List all Docker images.
    """
    return list_docker_images()

@app.get("/api/docker/containers")
async def docker_containers():
    """
    List all Docker containers.
    """
    return list_docker_containers()

@app.post("/api/docker/build")
async def docker_build(request: dict):
    """
    Build a Docker image from a Dockerfile.
    Expected JSON: {"dockerfile_path": "/path/to/Dockerfile", "tag": "image:tag", "build_context": "/path/to/context"}
    """
    dockerfile_path = request.get("dockerfile_path")
    tag = request.get("tag")
    build_context = request.get("build_context")
    
    if not dockerfile_path or not tag:
        return {
            "success": False,
            "error": "dockerfile_path and tag are required"
        }
    
    return await build_docker_image(dockerfile_path, tag, build_context)

# Cluster API endpoints
@app.get("/api/cluster/nodes")
async def get_cluster_nodes():
    """
    Get information about all cluster nodes.
    """
    return get_cluster_node_info()

@app.get("/api/cluster/status")
async def get_cluster_status(request: Request, current_user: User = Depends(get_current_active_user)):
    """
    Get real-time status of all cluster nodes.
    """
    # Log cluster status access
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="CLUSTER_OPERATION",
        username=current_user.username,
        action="STATUS_CHECK",
        resource="cluster",
        details={"user_role": current_user.role},
        ip_address=client_host,
        user_agent=user_agent
    )

    return await check_cluster_status()

@app.post("/api/cluster/ping")
async def ping_cluster_nodes(request: dict):
    """
    Ping specified nodes to check connectivity.
    Expected JSON: {"nodes": ["node1", "node2", ...]}
    """
    nodes = request.get("nodes", [])
    if not nodes:
        return {"error": "No nodes specified"}
    
    return await ping_nodes(nodes)

@app.get("/api/cluster/resources")
async def get_cluster_resources(request: Request, current_user: User = Depends(get_current_active_user)):
    """
    Get resource usage (CPU, memory, disk) for all cluster nodes.
    """
    # Log resource monitoring access
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="RESOURCE_MONITORING",
        username=current_user.username,
        action="VIEW_RESOURCES",
        resource="cluster",
        details={"user_role": current_user.role},
        ip_address=client_host,
        user_agent=user_agent
    )

    return await get_cluster_resource_usage()

@app.get("/api/cluster/resources/{node_name}")
async def get_node_resources(node_name: str, request: Request, current_user: User = Depends(get_current_active_user)):
    """
    Get detailed resource usage for a specific node.
    """
    # Log resource monitoring access
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="RESOURCE_MONITORING",
        username=current_user.username,
        action="VIEW_NODE_RESOURCES",
        resource=node_name,
        details={"user_role": current_user.role},
        ip_address=client_host,
        user_agent=user_agent
    )

    return await get_node_resource_usage(node_name)

async def get_cluster_resource_usage():
    """Get resource usage for all cluster nodes"""
    nodes = get_cluster_node_info()
    resource_data = {}

    for node_name, node_info in nodes.items():
        if node_info.get("pingable", False) and node_info.get("ssh_accessible", False):
            try:
                resource_data[node_name] = await get_node_resource_usage(node_name)
            except Exception as e:
                resource_data[node_name] = {
                    "error": f"Failed to get resources: {str(e)}",
                    "timestamp": datetime.utcnow().isoformat()
                }
        else:
            resource_data[node_name] = {
                "status": "unreachable",
                "timestamp": datetime.utcnow().isoformat()
            }

    return {
        "cluster_resources": resource_data,
        "timestamp": datetime.utcnow().isoformat()
    }

async def get_node_resource_usage(node_name: str):
    """Get detailed resource usage for a specific node via SSH"""
    node_info = get_cluster_node_info().get(node_name)
    if not node_info:
        return {"error": f"Node {node_name} not found"}

    if not node_info.get("ssh_accessible", False):
        return {"error": f"Node {node_name} is not SSH accessible"}

    try:
        # SSH command to get system resource usage
        ssh_cmd = [
            "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
            f"sanjay@{node_info['ip']}",
            """
            echo "=== CPU Usage ===" &&
            top -bn1 | grep "Cpu(s)" | awk '{for(i=1;i<=NF;i++) if($i ~ /id/) {sub(/%/, "", $(i-1)); print 100-$(i-1)"%"; exit}}' &&
            echo "=== Memory Usage ===" &&
            free | grep Mem | awk '{printf "%.2f%%\\n", $3/$2 * 100.0}' &&
            echo "=== Disk Usage ===" &&
            df / | tail -1 | awk '{print $5}' &&
            echo "=== Load Average ===" &&
            uptime | awk -F'load average:' '{ print $2 }' | sed 's/^ *//'
            """
        ]

        result = await asyncio.create_subprocess_exec(
            *ssh_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await result.communicate()

        if result.returncode == 0:
            output = stdout.decode().strip().split('\n')
            return {
                "cpu_usage": output[1] if len(output) > 1 else "N/A",
                "memory_usage": output[3] if len(output) > 3 else "N/A",
                "disk_usage": output[5] if len(output) > 5 else "N/A",
                "load_average": output[7] if len(output) > 7 else "N/A",
                "timestamp": datetime.utcnow().isoformat(),
                "status": "success"
            }
        else:
            return {
                "error": f"SSH command failed: {stderr.decode()}",
                "timestamp": datetime.utcnow().isoformat(),
                "status": "error"
            }
    except Exception as e:
        return {
            "error": f"Failed to get resource usage: {str(e)}",
            "timestamp": datetime.utcnow().isoformat(),
            "status": "error"
        }

@app.get("/api/logs/audit")
async def get_audit_logs(request: Request, current_user: User = Depends(get_current_active_user), limit: int = 100, offset: int = 0):
    """
    Get audit logs with pagination.
    Only admin users can access audit logs.
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required for audit logs")

    # Log audit log access
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="AUDIT_LOG_ACCESS",
        username=current_user.username,
        action="VIEW_AUDIT_LOGS",
        resource="audit_logs",
        details={"limit": limit, "offset": offset, "user_role": current_user.role},
        ip_address=client_host,
        user_agent=user_agent
    )

    try:
        if not os.path.exists(AUDIT_LOG_FILE):
            return {"logs": [], "total": 0, "limit": limit, "offset": offset}

        with open(AUDIT_LOG_FILE, 'r') as f:
            lines = f.readlines()

        # Parse JSON log entries
        logs = []
        for line in reversed(lines):  # Most recent first
            try:
                log_entry = json.loads(line.strip())
                logs.append(log_entry)
            except json.JSONDecodeError:
                continue

        # Apply pagination
        total_logs = len(logs)
        start_idx = offset
        end_idx = offset + limit
        paginated_logs = logs[start_idx:end_idx]

        return {
            "logs": paginated_logs,
            "total": total_logs,
            "limit": limit,
            "offset": offset,
            "has_more": end_idx < total_logs
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read audit logs: {str(e)}")

@app.get("/api/logs/system")
async def get_system_logs(request: Request, current_user: User = Depends(get_current_active_user), lines: int = 100):
    """
    Get recent system logs from the server.
    Requires operator or admin role.
    """
    if current_user.role not in ["operator", "admin"]:
        raise HTTPException(status_code=403, detail="Operator or admin access required")

    # Log system log access
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="SYSTEM_LOG_ACCESS",
        username=current_user.username,
        action="VIEW_SYSTEM_LOGS",
        resource="system_logs",
        details={"lines": lines, "user_role": current_user.role},
        ip_address=client_host,
        user_agent=user_agent
    )

    try:
        # Get system logs using journalctl or syslog
        result = await asyncio.create_subprocess_exec(
            "journalctl", "-n", str(lines), "--no-pager",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await result.communicate()

        if result.returncode == 0:
            log_lines = stdout.decode().strip().split('\n')
            return {
                "logs": log_lines,
                "total_lines": len(log_lines),
                "requested_lines": lines,
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            # Fallback to syslog if journalctl fails
            result = await asyncio.create_subprocess_exec(
                "tail", "-n", str(lines), "/var/log/syslog",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()

            if result.returncode == 0:
                log_lines = stdout.decode().strip().split('\n')
                return {
                    "logs": log_lines,
                    "total_lines": len(log_lines),
                    "requested_lines": lines,
                    "source": "syslog",
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                return {
                    "error": "Unable to access system logs",
                    "details": stderr.decode(),
                    "timestamp": datetime.utcnow().isoformat()
                }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read system logs: {str(e)}")

@app.post("/api/backup/create")
async def create_backup(request: Request, current_user: User = Depends(get_current_active_user), backup_type: str = "full"):
    """
    Create a backup of cluster configurations and data.
    Requires admin role.
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required for backups")

    # Log backup creation attempt
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="BACKUP_OPERATION",
        username=current_user.username,
        action="CREATE_BACKUP",
        resource="cluster_backup",
        details={"backup_type": backup_type, "user_role": current_user.role},
        ip_address=client_host,
        user_agent=user_agent
    )

    try:
        backup_id = f"backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        backup_dir = f"backups/{backup_id}"
        pathlib.Path(backup_dir).mkdir(parents=True, exist_ok=True)

        backup_info = {
            "backup_id": backup_id,
            "backup_type": backup_type,
            "created_by": current_user.username,
            "created_at": datetime.utcnow().isoformat(),
            "status": "in_progress",
            "files": []
        }

        # Backup configurations
        config_files = [
            "bootstrap_app.py",
            "bootstrap_requirements.txt",
            "README.md",
            "audit.log"
        ]

        for config_file in config_files:
            if os.path.exists(config_file):
                shutil.copy2(config_file, f"{backup_dir}/")
                backup_info["files"].append(config_file)

        # Backup cluster configurations if they exist
        cluster_config_dir = "/home/sanjay/containers/kubernetes"
        cluster_configs = [
            "server.log",
            "migration_checkpoint.sh"
        ]

        for config in cluster_configs:
            config_path = os.path.join(cluster_config_dir, config)
            if os.path.exists(config_path):
                shutil.copy2(config_path, f"{backup_dir}/")
                backup_info["files"].append(config)

        # Create backup manifest
        with open(f"{backup_dir}/backup_manifest.json", 'w') as f:
            json.dump(backup_info, f, indent=2)

        backup_info["status"] = "completed"

        # Update manifest with final status
        with open(f"{backup_dir}/backup_manifest.json", 'w') as f:
            json.dump(backup_info, f, indent=2)

        return {
            "backup_id": backup_id,
            "status": "completed",
            "files_backed_up": len(backup_info["files"]),
            "backup_path": backup_dir,
            "created_at": backup_info["created_at"]
        }

    except Exception as e:
        # Log backup failure
        log_audit_event(
            event_type="BACKUP_OPERATION",
            username=current_user.username,
            action="BACKUP_FAILED",
            resource="cluster_backup",
            details={"error": str(e), "backup_type": backup_type},
            ip_address=client_host,
            user_agent=user_agent
        )
        raise HTTPException(status_code=500, detail=f"Backup creation failed: {str(e)}")

@app.get("/api/backup/list")
async def list_backups(request: Request, current_user: User = Depends(get_current_active_user)):
    """
    List all available backups.
    Requires admin role.
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required for backup management")

    # Log backup list access
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="BACKUP_OPERATION",
        username=current_user.username,
        action="LIST_BACKUPS",
        resource="backup_list",
        details={"user_role": current_user.role},
        ip_address=client_host,
        user_agent=user_agent
    )

    try:
        backups_dir = pathlib.Path("backups")
        if not backups_dir.exists():
            return {"backups": [], "total": 0}

        backups = []
        for backup_dir in backups_dir.iterdir():
            if backup_dir.is_dir():
                manifest_path = backup_dir / "backup_manifest.json"
                if manifest_path.exists():
                    with open(manifest_path, 'r') as f:
                        backup_info = json.load(f)
                        backups.append(backup_info)

        # Sort by creation date (newest first)
        backups.sort(key=lambda x: x.get("created_at", ""), reverse=True)

        return {
            "backups": backups,
            "total": len(backups)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list backups: {str(e)}")

@app.post("/api/backup/restore/{backup_id}")
async def restore_backup(backup_id: str, request: Request, current_user: User = Depends(get_current_active_user)):
    """
    Restore from a backup.
    Requires admin role.
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required for backup restoration")

    # Log backup restoration attempt
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="BACKUP_OPERATION",
        username=current_user.username,
        action="RESTORE_BACKUP",
        resource=backup_id,
        details={"user_role": current_user.role},
        ip_address=client_host,
        user_agent=user_agent
    )

    try:
        backup_dir = f"backups/{backup_id}"
        manifest_path = f"{backup_dir}/backup_manifest.json"

        if not os.path.exists(manifest_path):
            raise HTTPException(status_code=404, detail=f"Backup {backup_id} not found")

        with open(manifest_path, 'r') as f:
            backup_info = json.load(f)

        # Create restore manifest
        restore_info = {
            "backup_id": backup_id,
            "restored_by": current_user.username,
            "restored_at": datetime.utcnow().isoformat(),
            "status": "in_progress",
            "files_restored": []
        }

        # Restore files
        for file_path in backup_info.get("files", []):
            backup_file = f"{backup_dir}/{file_path}"
            if os.path.exists(backup_file):
                # Create backup of current file before restoring
                if os.path.exists(file_path):
                    backup_current = f"{file_path}.backup_before_restore"
                    shutil.copy2(file_path, backup_current)

                shutil.copy2(backup_file, file_path)
                restore_info["files_restored"].append(file_path)

        restore_info["status"] = "completed"

        # Save restore manifest
        restore_manifest_path = f"{backup_dir}/restore_manifest.json"
        with open(restore_manifest_path, 'w') as f:
            json.dump(restore_info, f, indent=2)

        return {
            "backup_id": backup_id,
            "status": "completed",
            "files_restored": len(restore_info["files_restored"]),
            "restored_at": restore_info["restored_at"]
        }

    except Exception as e:
        # Log restore failure
        log_audit_event(
            event_type="BACKUP_OPERATION",
            username=current_user.username,
            action="RESTORE_FAILED",
            resource=backup_id,
            details={"error": str(e)},
            ip_address=client_host,
            user_agent=user_agent
        )
        raise HTTPException(status_code=500, detail=f"Backup restoration failed: {str(e)}")

# Deployment Workflow Models
class DeploymentTemplate(BaseModel):
    name: str
    description: str
    template_type: str  # "docker", "kubernetes", "script"
    parameters: Dict[str, Any]
    steps: List[Dict[str, Any]]
    created_by: str
    created_at: str

class DeploymentWorkflow(BaseModel):
    template_name: str
    parameters: Dict[str, Any]
    target_nodes: List[str]
    scheduled_time: Optional[str] = None
    status: str = "pending"
    created_by: str
    created_at: str

# In-memory storage for deployment templates and workflows
deployment_templates = {}
deployment_workflows = {}

@app.post("/api/deployments/templates")
async def create_deployment_template(
    template: DeploymentTemplate,
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """
    Create a new deployment template.
    Requires operator or admin role.
    """
    if current_user.role not in ["operator", "admin"]:
        raise HTTPException(status_code=403, detail="Operator or admin access required")

    # Log template creation
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="DEPLOYMENT_OPERATION",
        username=current_user.username,
        action="CREATE_TEMPLATE",
        resource=template.name,
        details={"template_type": template.template_type, "user_role": current_user.role},
        ip_address=client_host,
        user_agent=user_agent
    )

    template_dict = template.dict()
    template_dict["created_by"] = current_user.username
    template_dict["created_at"] = datetime.utcnow().isoformat()

    deployment_templates[template.name] = template_dict

    return {"message": f"Template '{template.name}' created successfully", "template": template_dict}

@app.get("/api/deployments/templates")
async def list_deployment_templates(request: Request, current_user: User = Depends(get_current_active_user)):
    """
    List all deployment templates.
    """
    # Log template list access
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="DEPLOYMENT_OPERATION",
        username=current_user.username,
        action="LIST_TEMPLATES",
        resource="deployment_templates",
        details={"user_role": current_user.role},
        ip_address=client_host,
        user_agent=user_agent
    )

    return {"templates": list(deployment_templates.values()), "total": len(deployment_templates)}

@app.post("/api/deployments/workflows")
async def create_deployment_workflow(
    workflow: DeploymentWorkflow,
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """
    Create a new deployment workflow.
    Requires operator or admin role.
    """
    if current_user.role not in ["operator", "admin"]:
        raise HTTPException(status_code=403, detail="Operator or admin access required")

    # Validate template exists
    if workflow.template_name not in deployment_templates:
        raise HTTPException(status_code=404, detail=f"Template '{workflow.template_name}' not found")

    # Log workflow creation
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="DEPLOYMENT_OPERATION",
        username=current_user.username,
        action="CREATE_WORKFLOW",
        resource=f"workflow_{workflow.template_name}",
        details={
            "template_name": workflow.template_name,
            "target_nodes": workflow.target_nodes,
            "user_role": current_user.role
        },
        ip_address=client_host,
        user_agent=user_agent
    )

    workflow_id = f"workflow_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}"
    workflow_dict = workflow.dict()
    workflow_dict["workflow_id"] = workflow_id
    workflow_dict["created_by"] = current_user.username
    workflow_dict["created_at"] = datetime.utcnow().isoformat()

    deployment_workflows[workflow_id] = workflow_dict

    return {"message": f"Workflow '{workflow_id}' created successfully", "workflow": workflow_dict}

@app.get("/api/deployments/workflows")
async def list_deployment_workflows(request: Request, current_user: User = Depends(get_current_active_user)):
    """
    List all deployment workflows.
    """
    # Log workflow list access
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="DEPLOYMENT_OPERATION",
        username=current_user.username,
        action="LIST_WORKFLOWS",
        resource="deployment_workflows",
        details={"user_role": current_user.role},
        ip_address=client_host,
        user_agent=user_agent
    )

    return {"workflows": list(deployment_workflows.values()), "total": len(deployment_workflows)}

@app.post("/api/deployments/workflows/{workflow_id}/execute")
async def execute_deployment_workflow(
    workflow_id: str,
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """
    Execute a deployment workflow.
    Requires operator or admin role.
    """
    if current_user.role not in ["operator", "admin"]:
        raise HTTPException(status_code=403, detail="Operator or admin access required")

    if workflow_id not in deployment_workflows:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found")

    workflow = deployment_workflows[workflow_id]

    # Log workflow execution
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="DEPLOYMENT_OPERATION",
        username=current_user.username,
        action="EXECUTE_WORKFLOW",
        resource=workflow_id,
        details={
            "template_name": workflow["template_name"],
            "target_nodes": workflow["target_nodes"],
            "user_role": current_user.role
        },
        ip_address=client_host,
        user_agent=user_agent
    )

    # Update workflow status
    workflow["status"] = "executing"
    workflow["executed_by"] = current_user.username
    workflow["executed_at"] = datetime.utcnow().isoformat()

    # Here you would implement the actual deployment logic
    # For now, we'll simulate execution
    try:
        # Simulate deployment steps
        template = deployment_templates[workflow["template_name"]]
        execution_results = []

        for step in template["steps"]:
            step_result = {
                "step": step["name"],
                "status": "completed",
                "timestamp": datetime.utcnow().isoformat()
            }
            execution_results.append(step_result)

        workflow["status"] = "completed"
        workflow["execution_results"] = execution_results
        workflow["completed_at"] = datetime.utcnow().isoformat()

        return {
            "workflow_id": workflow_id,
            "status": "completed",
            "execution_results": execution_results,
            "completed_at": workflow["completed_at"]
        }

    except Exception as e:
        workflow["status"] = "failed"
        workflow["error"] = str(e)
        workflow["failed_at"] = datetime.utcnow().isoformat()

        raise HTTPException(status_code=500, detail=f"Workflow execution failed: {str(e)}")

# Advanced Cluster Operations Models
class ScalingPolicy(BaseModel):
    name: str
    metric: str  # cpu, memory, custom
    threshold: float
    scale_up_action: str
    scale_down_action: str
    cooldown_period: int = 300  # seconds
    enabled: bool = True

class HealthCheck(BaseModel):
    name: str
    type: str  # http, tcp, command, kubernetes
    target: str
    interval: int = 30  # seconds
    timeout: int = 10   # seconds
    retries: int = 3
    enabled: bool = True

# In-memory storage for advanced operations
scaling_policies = {}
health_checks = {}

@app.post("/api/cluster/scaling/policies")
async def create_scaling_policy(
    policy: ScalingPolicy,
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """
    Create a scaling policy for auto-scaling operations.
    Requires admin role.
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required for scaling policies")

    # Log scaling policy creation
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="SCALING_OPERATION",
        username=current_user.username,
        action="CREATE_SCALING_POLICY",
        resource=policy.name,
        details={"metric": policy.metric, "threshold": policy.threshold, "user_role": current_user.role},
        ip_address=client_host,
        user_agent=user_agent
    )

    policy_dict = policy.dict()
    policy_dict["created_by"] = current_user.username
    policy_dict["created_at"] = datetime.utcnow().isoformat()
    policy_dict["last_triggered"] = None

    scaling_policies[policy.name] = policy_dict

    return {"message": f"Scaling policy '{policy.name}' created successfully", "policy": policy_dict}

@app.get("/api/cluster/scaling/policies")
async def list_scaling_policies(request: Request, current_user: User = Depends(get_current_active_user)):
    """
    List all scaling policies.
    Requires admin role.
    """
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    # Log scaling policies access
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="SCALING_OPERATION",
        username=current_user.username,
        action="LIST_SCALING_POLICIES",
        resource="scaling_policies",
        details={"user_role": current_user.role},
        ip_address=client_host,
        user_agent=user_agent
    )

    return {"policies": list(scaling_policies.values()), "total": len(scaling_policies)}

@app.post("/api/cluster/health/checks")
async def create_health_check(
    check: HealthCheck,
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """
    Create a health check for monitoring services.
    Requires operator or admin role.
    """
    if current_user.role not in ["operator", "admin"]:
        raise HTTPException(status_code=403, detail="Operator or admin access required")

    # Log health check creation
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="HEALTH_CHECK_OPERATION",
        username=current_user.username,
        action="CREATE_HEALTH_CHECK",
        resource=check.name,
        details={"type": check.type, "target": check.target, "user_role": current_user.role},
        ip_address=client_host,
        user_agent=user_agent
    )

    check_dict = check.dict()
    check_dict["created_by"] = current_user.username
    check_dict["created_at"] = datetime.utcnow().isoformat()
    check_dict["last_check"] = None
    check_dict["status"] = "unknown"

    health_checks[check.name] = check_dict

    return {"message": f"Health check '{check.name}' created successfully", "check": check_dict}

@app.get("/api/cluster/health/checks")
async def list_health_checks(request: Request, current_user: User = Depends(get_current_active_user)):
    """
    List all health checks with their current status.
    """
    # Log health checks access
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="HEALTH_CHECK_OPERATION",
        username=current_user.username,
        action="LIST_HEALTH_CHECKS",
        resource="health_checks",
        details={"user_role": current_user.role},
        ip_address=client_host,
        user_agent=user_agent
    )

    return {"checks": list(health_checks.values()), "total": len(health_checks)}

@app.post("/api/cluster/health/checks/{check_name}/run")
async def run_health_check(
    check_name: str,
    request: Request,
    current_user: User = Depends(get_current_active_user)
):
    """
    Manually run a specific health check.
    """
    if check_name not in health_checks:
        raise HTTPException(status_code=404, detail=f"Health check '{check_name}' not found")

    check = health_checks[check_name]

    # Log health check execution
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="HEALTH_CHECK_OPERATION",
        username=current_user.username,
        action="RUN_HEALTH_CHECK",
        resource=check_name,
        details={"type": check["type"], "target": check["target"], "user_role": current_user.role},
        ip_address=client_host,
        user_agent=user_agent
    )

    # Simulate health check execution
    try:
        # Here you would implement actual health check logic
        # For now, we'll simulate based on check type
        if check["type"] == "http":
            # Simulate HTTP health check
            import random
            success = random.choice([True, True, True, False])  # 75% success rate
        elif check["type"] == "tcp":
            # Simulate TCP connection check
            success = random.choice([True, True, False])  # 66% success rate
        else:
            success = random.choice([True, False])  # 50% success rate

        check["last_check"] = datetime.utcnow().isoformat()
        check["status"] = "healthy" if success else "unhealthy"

        return {
            "check_name": check_name,
            "status": check["status"],
            "last_check": check["last_check"],
            "details": f"Health check completed for {check['target']}"
        }

    except Exception as e:
        check["status"] = "error"
        check["last_check"] = datetime.utcnow().isoformat()

        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")

@app.get("/api/cluster/health/status")
async def get_cluster_health_status(request: Request, current_user: User = Depends(get_current_active_user)):
    """
    Get overall cluster health status based on all health checks.
    """
    # Log health status access
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="HEALTH_CHECK_OPERATION",
        username=current_user.username,
        action="GET_HEALTH_STATUS",
        resource="cluster_health",
        details={"user_role": current_user.role},
        ip_address=client_host,
        user_agent=user_agent
    )

    total_checks = len(health_checks)
    healthy_checks = sum(1 for check in health_checks.values() if check.get("status") == "healthy")
    unhealthy_checks = sum(1 for check in health_checks.values() if check.get("status") == "unhealthy")

    overall_status = "healthy"
    if unhealthy_checks > 0:
        overall_status = "degraded"
    if unhealthy_checks > total_checks / 2:
        overall_status = "critical"

    return {
        "overall_status": overall_status,
        "total_checks": total_checks,
        "healthy_checks": healthy_checks,
        "unhealthy_checks": unhealthy_checks,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.websocket("/ws/docker/build")
async def websocket_docker_build(websocket: WebSocket):
    """
    WebSocket endpoint for Docker image building with real-time output.
    """
    await websocket.accept()
    
    try:
        # Wait for build request
        data = await websocket.receive_json()
        dockerfile_path = data.get("dockerfile_path")
        tag = data.get("tag", "custom:latest")
        build_context = data.get("build_context")
        
        if not dockerfile_path:
            await websocket.send_json({
                "type": "error",
                "message": "dockerfile_path is required"
            })
            return
        
        # Validate Docker availability
        if not get_docker_client():
            await websocket.send_json({
                "type": "error",
                "message": "Docker client not available"
            })
            return
        
        # Send start message
        await websocket.send_json({
            "type": "start",
            "message": f"Starting Docker build for {tag}",
            "timestamp": datetime.now().isoformat()
        })
        
        start_time = datetime.now()
        
        try:
            # Determine build context
            if build_context is None:
                build_context = os.path.dirname(dockerfile_path)
            
            # Validate paths
            if not os.path.exists(dockerfile_path):
                await websocket.send_json({
                    "type": "error",
                    "message": f"Dockerfile not found: {dockerfile_path}"
                })
                return
            
            if not os.path.exists(build_context):
                await websocket.send_json({
                    "type": "error",
                    "message": f"Build context not found: {build_context}"
                })
                return
            
            # Run docker build with real-time output
            cmd = [
                'docker', 'build',
                '-f', dockerfile_path,
                '-t', tag,
                build_context
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,  # Combine stdout and stderr
                cwd=build_context
            )
            
            # Stream output in real-time
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                
                line_text = line.decode('utf-8', errors='replace').rstrip()
                if line_text:  # Only send non-empty lines
                    await websocket.send_json({
                        "type": "log",
                        "data": line_text,
                        "timestamp": datetime.now().isoformat()
                    })
            
            # Wait for process to complete
            return_code = await process.wait()
            execution_time = (datetime.now() - start_time).total_seconds()
            
            if return_code == 0:
                await websocket.send_json({
                    "type": "complete",
                    "success": True,
                    "tag": tag,
                    "execution_time": execution_time,
                    "timestamp": datetime.now().isoformat()
                })
            else:
                await websocket.send_json({
                    "type": "error",
                    "message": f"Build failed with return code {return_code}",
                    "execution_time": execution_time
                })
            
        except asyncio.TimeoutError:
            await websocket.send_json({
                "type": "error",
                "message": f"Build timed out after {timeout} seconds"
            })
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            await websocket.send_json({
                "type": "error",
                "message": f"Build failed: {str(e)}",
                "execution_time": execution_time
            })
            
    except WebSocketDisconnect:
        print("Docker build WebSocket client disconnected")
    except Exception as e:
        try:
            await websocket.send_json({
                "type": "error",
                "message": f"WebSocket error: {str(e)}"
            })
        except:
            pass

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the interactive cluster management interface"""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cluster Management - Nano</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                border-radius: 15px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                overflow: hidden;
            }
            .header {
                background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
                color: white;
                padding: 30px;
                text-align: center;
            }
            .header h1 {
                margin: 0;
                font-size: 2.5em;
                font-weight: 300;
            }
            .header p {
                margin: 10px 0 0 0;
                opacity: 0.9;
                font-size: 1.1em;
            }
            .nav {
                background: #f8fafc;
                padding: 20px;
                border-bottom: 1px solid #e2e8f0;
            }
            .nav-tabs {
                display: flex;
                justify-content: center;
                gap: 10px;
                margin: 0;
                padding: 0;
                list-style: none;
                flex-wrap: wrap;
            }
            .nav-tab {
                padding: 12px 24px;
                background: white;
                border: 2px solid #e2e8f0;
                border-radius: 8px;
                cursor: pointer;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                font-weight: 500;
                position: relative;
                overflow: hidden;
            }
            .nav-tab::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
                transition: left 0.5s;
            }
            .nav-tab:hover::before {
                left: 100%;
            }
            .nav-tab.active {
                background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
                color: white;
                border-color: #4f46e5;
                box-shadow: 0 4px 12px rgba(79, 70, 229, 0.3);
                transform: translateY(-2px);
            }
            .nav-tab:hover {
                border-color: #4f46e5;
                transform: translateY(-2px);
                box-shadow: 0 4px 12px rgba(79, 70, 229, 0.2);
            }
            .content {
                padding: 30px;
            }
            .tab-content {
                display: none;
                padding: 20px;
                animation: fadeIn 0.5s ease-in-out;
            }
            .tab-content.active {
                display: block;
            }
            @keyframes fadeIn {
                from {
                    opacity: 0;
                    transform: translateY(20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }
            .stat-card {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 20px;
                border-radius: 10px;
                text-align: center;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
                overflow: hidden;
            }
            .stat-card::before {
                content: '';
                position: absolute;
                top: 0;
                left: -100%;
                width: 100%;
                height: 100%;
                background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
                transition: left 0.6s;
            }
            .stat-card:hover::before {
                left: 100%;
            }
            .stat-card:hover {
                transform: translateY(-8px) scale(1.02);
                box-shadow: 0 12px 25px rgba(0,0,0,0.2);
            }
            .stat-card h3 {
                margin: 0 0 10px 0;
                font-size: 2em;
                font-weight: 300;
            }
            .stat-card p {
                margin: 0;
                opacity: 0.9;
            }
            .script-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }
            .script-card {
                border: 1px solid #e2e8f0;
                border-radius: 10px;
                padding: 20px;
                transition: all 0.3s ease;
            }
            .script-card:hover {
                box-shadow: 0 10px 25px rgba(0,0,0,0.1);
                transform: translateY(-5px);
            }
            .script-card h4 {
                margin: 0 0 10px 0;
                color: #1f2937;
            }
            .script-card .meta {
                font-size: 0.9em;
                color: #6b7280;
                margin: 5px 0;
            }
            .script-card .actions {
                margin-top: 15px;
            }
            .btn {
                padding: 8px 16px;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-size: 0.9em;
                transition: all 0.3s ease;
                margin-right: 10px;
                text-align: center;
            }
            .btn-primary {
                background: #4f46e5;
                color: white;
            }
            .btn-primary:hover {
                background: #3730a3;
            }
            .btn-success {
                background: #10b981;
                color: white;
            }
            .btn-success:hover {
                background: #059669;
            }
            .execution-result {
                background: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                padding: 20px;
                margin: 20px 0;
                font-family: 'Courier New', monospace;
                white-space: pre-wrap;
                max-height: 400px;
                overflow-y: auto;
            }
            .status-indicator {
                display: inline-block;
                width: 12px;
                height: 12px;
                border-radius: 50%;
                margin-right: 8px;
            }
            .status-online {
                background: #10b981;
            }
            .phase-indicator {
                display: inline-flex;
                align-items: center;
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 0.8em;
                font-weight: 500;
                margin-left: 10px;
            }
            .phase-current {
                background: #fef3c7;
                color: #d97706;
            }
            .phase-completed {
                background: #d1fae5;
                color: #065f46;
            }
        }

        /* Login Modal Styles */
        .login-modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 1000;
        }
        .login-container {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.3);
            width: 400px;
            max-width: 90%;
        }
        .login-container h2 {
            margin: 0 0 10px 0;
            color: #1f2937;
            text-align: center;
        }
        .login-container p {
            text-align: center;
            color: #6b7280;
            margin-bottom: 20px;
        }
        .form-group {
            margin-bottom: 15px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
            color: #374151;
        }
        .form-group input {
            width: 100%;
            padding: 10px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-size: 16px;
            box-sizing: border-box;
        }
        .form-group input:focus {
            outline: none;
            border-color: #4f46e5;
        }
        .error-message {
            color: #dc2626;
            background: #fef2f2;
            padding: 10px;
            border-radius: 5px;
            margin-top: 15px;
            text-align: center;
        }
        .login-info {
            margin-top: 20px;
            padding: 15px;
            background: #f8fafc;
            border-radius: 8px;
            font-size: 14px;
        }
        .login-info h4 {
            margin: 0 0 10px 0;
            color: #374151;
        }
        .login-info ul {
            margin: 0;
            padding-left: 20px;
        }
        .login-info li {
            margin-bottom: 5px;
        }

        /* Node Tree Styles */
        .node-tree {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            font-size: 0.9em;
        }
        .tree-node {
            display: flex;
            align-items: center;
            padding: 8px 12px;
            margin: 2px 0;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s ease;
            border: 1px solid transparent;
        }
        .tree-node:hover {
            background: #f3f4f6;
            border-color: #e5e7eb;
        }
        .tree-node.server-node {
            background: #eff6ff;
            border-color: #3b82f6;
            font-weight: bold;
        }
        .tree-node.server-node:hover {
            background: #dbeafe;
        }
        .tree-node.control-plane-node {
            background: #fef3c7;
            border-color: #f59e0b;
        }
        .tree-node.gpu-nodes, .tree-node.network-nodes {
            background: #f0fdf4;
            border-color: #10b981;
            font-weight: 500;
        }
        .tree-node.gpu-worker-node {
            background: #ecfdf5;
            border-color: #6ee7b7;
            margin-left: 20px;
        }
        .tree-node.network-node {
            background: #f0f9ff;
            border-color: #7dd3fc;
            margin-left: 20px;
        }
        .node-checkbox {
            margin-right: 8px;
            cursor: pointer;
            transform: scale(1.1);
        }
        .tree-icon {
            margin-right: 8px;
            font-size: 1.1em;
        }
        .tree-label {
            flex: 1;
            font-weight: 500;
        }
        .tree-details {
            color: #6b7280;
            font-size: 0.85em;
            margin-left: 8px;
        }
        .tree-count {
            color: #6b7280;
            font-size: 0.8em;
            font-weight: normal;
        }
        .tree-children {
            margin-left: 20px;
            border-left: 2px solid #e5e7eb;
            padding-left: 10px;
        }
        .tree-children.collapsed {
            display: none;
        }
        .node-status {
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: 500;
            margin-left: 8px;
        }
        .status-online {
            background: #d1fae5;
            color: #065f46;
        }
        .status-offline {
            background: #f3f4f6;
            color: #6b7280;
        }
        .status-error {
            background: #fee2e2;
            color: #991b1b;
        }
        </style>
    </head>
    <body>
        <!-- Login Modal -->
        <div id="login-modal" class="login-modal">
            <div class="login-container">
                <h2>🔐 Cluster Management Login</h2>
                <p>Access the cluster management system</p>
                <form id="login-form">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
                <div id="login-error" class="error-message" style="display: none;"></div>
                <div class="login-info">
                    <h4>Demo Accounts:</h4>
                    <ul>
                        <li><strong>admin</strong> / admin123 (Full access)</li>
                        <li><strong>operator</strong> / operator123 (Limited operations)</li>
                        <li><strong>viewer</strong> / viewer123 (Read-only)</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="container" id="main-container" style="display: none;">
            <div class="header">
                <h1>🚀 Cluster Management</h1>
                <p>Dedicated Management Node on Nano <span class="phase-indicator phase-current">Phase 7: Security & Authentication</span></p>
                <div style="margin-top: 15px;">
                    <span class="status-indicator status-online"></span>
                    <strong>Status:</strong> Online | <strong>Host:</strong> nano (192.168.1.181) | <strong>Port:</strong> 8000
                </div>
            </div>

            <nav class="nav">
                <ul class="nav-tabs">
                    <li class="nav-tab active" onclick="showTab('overview')">Overview</li>
                    <li class="nav-tab" onclick="showTab('cluster')">Cluster</li>
                    <li class="nav-tab" onclick="showTab('resources')">Resources</li>
                    <li class="nav-tab" onclick="showTab('scripts')">Scripts</li>
                    <li class="nav-tab" onclick="showTab('execute')">Execute</li>
                    <li class="nav-tab" onclick="showTab('containers')">Containers</li>
                    <li class="nav-tab" onclick="showTab('logs')">Logs</li>
                    <li class="nav-tab" onclick="showTab('backups')">Backups</li>
                    <li class="nav-tab" onclick="showTab('deployments')">Deployments</li>
                    <li class="nav-tab" onclick="showTab('operations')">Operations</li>
                    <li class="nav-tab" onclick="showTab('api')">API</li>
                </ul>
            </nav>

            <div class="content">
                <!-- Overview Tab -->
                <div id="overview" class="tab-content active">
                    <h2>📊 System Overview</h2>
                    
                    <div class="stats-grid" id="stats-grid">
                        <!-- Stats will be loaded dynamically -->
                        <div class="stat-card">
                            <h3 id="total-scripts">--</h3>
                            <p>Scripts Discovered</p>
                        </div>
                        <div class="stat-card">
                            <h3 id="categories-count">--</h3>
                            <p>Categories</p>
                        </div>
                        <div class="stat-card">
                            <h3 id="executable-scripts">--</h3>
                            <p>Executable Scripts</p>
                        </div>
                        <div class="stat-card">
                            <h3 id="api-endpoints">13</h3>
                            <p>API Endpoints</p>
                        </div>
                    </div>

                    <h3>🎯 Phase Progress</h3>
                    <div style="background: #f8fafc; padding: 20px; border-radius: 10px; margin: 20px 0;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                            <span><strong>Phase 1:</strong> Bootstrap Web Server</span>
                            <span style="color: #10b981;">✅ Complete</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                            <span><strong>Phase 2:</strong> Script Discovery</span>
                            <span style="color: #10b981;">✅ Complete</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                            <span><strong>Phase 3:</strong> Script Execution</span>
                            <span style="color: #10b981;">✅ Complete</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                            <span><strong>Phase 4:</strong> WebSocket Streaming</span>
                            <span style="color: #10b981;">✅ Complete</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                            <span><strong>Phase 5:</strong> Container Building</span>
                            <span style="color: #10b981;">✅ Complete</span>
                        </div>
                        <div style="display: flex; justify-content: space-between;">
                            <span><strong>Phase 6:</strong> Full Cluster UI</span>
                            <span style="color: #10b981;">✅ Complete</span>
                        </div>
                    </div>
                </div>

                <!-- Cluster Tab -->
                <div id="cluster" class="tab-content">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px;">
                        <div style="flex: 1;">
                            <!-- Node Summary Section - Top Left -->
                            <div style="background: #f8fafc; padding: 20px; border-radius: 10px; display: flex; flex-direction: column;">
                                <h3>� Node Summary</h3>
                                <div id="node-summary" style="flex: 1; min-height: 300px;">
                                    <p>Loading node information...</p>
                                </div>
                            </div>
                        </div>
                        <div style="flex: 1; margin-left: 20px;">
                            <!-- Cluster Overview and Status - Single Panel -->
                            <div style="background: #f8fafc; padding: 20px; border-radius: 10px; display: flex; flex-direction: column; height: 100%;">
                                <!-- Cluster Overview Title with Refresh Button -->
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                                    <h2 style="margin: 0; text-align: left;">🌳 Cluster Overview</h2>
                                    <button class="btn btn-primary" onclick="console.log('Button clicked'); loadClusterData()" style="font-size: 0.8em; padding: 6px 12px; cursor: pointer; z-index: 10;">🔄 Refresh All</button>
                                </div>
                                
                                <!-- Status Section -->
                                <h3>📈 Status</h3>
                                <div id="cluster-status" style="flex: 1;">
                                    <p>Loading cluster status...</p>
                                </div>
                                
                                <!-- Ping Test Section -->
                                <div style="margin-top: 20px; padding-top: 15px; border-top: 1px solid #e2e8f0;">
                                    <h3>🏓 Network Testing</h3>
                                    <p>Test connectivity to selected nodes in the cluster tree.</p>
                                    <button class="btn btn-success" onclick="pingSelectedNodes()" style="font-size: 0.9em; padding: 8px 16px;">🏓 Ping Selected Nodes</button>
                                    <div id="ping-status" style="margin-top: 10px; font-size: 0.9em;"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Cluster Tree - Full Width -->
                    <div style="background: #f8fafc; padding: 20px; border-radius: 10px; margin-top: 20px;">
                        <h3>🌳 Cluster Tree</h3>
                        <div id="cluster-tree" style="font-family: 'Courier New', monospace; background: #1f2937; color: #e5e7eb; padding: 15px; border-radius: 5px; min-height: 300px;">
                            <div id="tree-content">
                                Loading cluster tree...
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Scripts Tab -->
                <div id="scripts" class="tab-content">
                    <h2>📂 Script Library</h2>
                    <div id="scripts-container">
                        <p>Loading scripts...</p>
                    </div>
                </div>

                <!-- Execute Tab -->
                <div id="execute" class="tab-content">
                    <h2>▶️ Script Execution</h2>
                    
                    <div style="background: #f8fafc; padding: 20px; border-radius: 10px; margin: 20px 0;">
                        <h3>Test Execution Framework</h3>
                        <p>Run a safe test script to verify the execution system works:</p>
                        <button class="btn btn-primary" onclick="testExecution()">🧪 Run Test Script</button>
                        <div id="test-result" style="margin-top: 15px;"></div>
                    </div>

                    <div style="background: #fef3c7; padding: 20px; border-radius: 10px; margin: 20px 0; border-left: 4px solid #d97706;">
                        <h3>⚠️ Real Script Execution</h3>
                        <p><strong>Coming Soon:</strong> Interactive script selection and execution with real-time output streaming.</p>
                        <p>Currently available via API endpoints for programmatic access.</p>
                    </div>

                    <div style="background: #ecfdf5; padding: 20px; border-radius: 10px; margin: 20px 0; border-left: 4px solid #10b981;">
                        <h3>🚀 Live Script Execution (WebSocket)</h3>
                        <p><strong>Real-time execution with live output streaming!</strong></p>
                        <div style="margin: 15px 0;">
                            <select id="script-selector" style="padding: 8px; border-radius: 5px; border: 1px solid #d1d5db; min-width: 300px;">
                                <option value="">Select a script to execute...</option>
                            </select>
                            <button class="btn btn-success" onclick="executeScriptRealtime()" style="margin-left: 10px;">▶️ Execute Live</button>
                        </div>
                        <div id="execution-output" style="background: #1f2937; color: #e5e7eb; padding: 15px; border-radius: 5px; font-family: 'Courier New', monospace; min-height: 200px; max-height: 400px; overflow-y: auto; display: none;">
                            <div id="output-content"></div>
                        </div>
                    </div>
                </div>

                <!-- Containers Tab -->
                <div id="containers" class="tab-content">
                    <h2>🐳 Docker Containers</h2>
                    
                    <div style="background: #f8fafc; padding: 20px; border-radius: 10px; margin: 20px 0;">
                        <h3>Docker System Status</h3>
                        <div id="docker-status">
                            <p>Checking Docker status...</p>
                        </div>
                    </div>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0;">
                        <div style="background: #f8fafc; padding: 20px; border-radius: 10px;">
                            <h3>📦 Docker Images</h3>
                            <div id="docker-images">
                                <p>Loading images...</p>
                            </div>
                        </div>
                        
                        <div style="background: #f8fafc; padding: 20px; border-radius: 10px;">
                            <h3>🚢 Docker Containers</h3>
                            <div id="docker-containers">
                                <p>Loading containers...</p>
                            </div>
                        </div>
                    </div>

                    <div style="background: #ecfdf5; padding: 20px; border-radius: 10px; margin: 20px 0; border-left: 4px solid #10b981;">
                        <h3>🏗️ Build Docker Image</h3>
                        <p><strong>Build custom Docker images from Dockerfiles!</strong></p>
                        <div style="margin: 15px 0;">
                            <input type="text" id="dockerfile-path" placeholder="/path/to/Dockerfile" style="padding: 8px; border-radius: 5px; border: 1px solid #d1d5db; min-width: 300px; margin-right: 10px;">
                            <input type="text" id="image-tag" placeholder="myimage:latest" style="padding: 8px; border-radius: 5px; border: 1px solid #d1d5db; min-width: 200px; margin-right: 10px;">
                            <button class="btn btn-success" onclick="buildDockerImage()">🏗️ Build Image</button>
                        </div>
                        <div id="build-output" style="background: #1f2937; color: #e5e7eb; padding: 15px; border-radius: 5px; font-family: 'Courier New', monospace; min-height: 200px; max-height: 400px; overflow-y: auto; display: none; margin-top: 15px;">
                            <div id="build-content"></div>
                        </div>
                    </div>
                </div>

                <!-- Resources Tab -->
                <div id="resources" class="tab-content">
                    <h2>📊 Resource Monitoring</h2>

                    <div style="background: #f8fafc; padding: 20px; border-radius: 10px; margin: 20px 0;">
                        <h3>Cluster Resource Usage</h3>
                        <p>Real-time monitoring of CPU, memory, and disk usage across all cluster nodes.</p>
                        <button class="btn btn-primary" onclick="loadResourceUsage()">🔄 Refresh Resources</button>
                        <div id="resource-status" style="margin-top: 15px;"></div>
                    </div>

                    <div class="stats-grid" id="resource-stats">
                        <!-- Resource stats will be loaded dynamically -->
                    </div>
                </div>

                <!-- Logs Tab -->
                <div id="logs" class="tab-content">
                    <h2>📋 System Logs</h2>

                    <div style="display: grid; grid-template-columns: 1fr 2fr; gap: 20px; margin: 20px 0;">
                        <div style="background: #f8fafc; padding: 20px; border-radius: 10px;">
                            <h3>Audit Logs</h3>
                            <p>Security and access logs for all system operations.</p>
                            <button class="btn btn-primary" onclick="loadAuditLogs()">📋 View Audit Logs</button>
                            <button class="btn btn-success" onclick="searchAuditLogs()">🔍 Search Logs</button>
                            <div id="audit-logs-status" style="margin-top: 15px;"></div>
                        </div>

                        <div style="background: #f8fafc; padding: 20px; border-radius: 10px;">
                            <h3>System Logs</h3>
                            <p>Recent system logs from the management server.</p>
                            <button class="btn btn-primary" onclick="loadSystemLogs()">📋 View System Logs</button>
                            <div id="system-logs-status" style="margin-top: 15px;"></div>
                        </div>
                    </div>

                    <div id="logs-content" style="background: #1f2937; color: #e5e7eb; padding: 20px; border-radius: 10px; font-family: 'Courier New', monospace; max-height: 500px; overflow-y: auto; display: none;">
                        <div id="logs-output"></div>
                    </div>
                </div>

                <!-- Backups Tab -->
                <div id="backups" class="tab-content">
                    <h2>💾 Backup Management</h2>

                    <div style="background: #f8fafc; padding: 20px; border-radius: 10px; margin: 20px 0;">
                        <h3>Cluster Backups</h3>
                        <p>Create and manage backups of cluster configurations and data.</p>
                        <button class="btn btn-success" onclick="createBackup()">➕ Create Backup</button>
                        <button class="btn btn-primary" onclick="listBackups()">📋 List Backups</button>
                        <div id="backup-status" style="margin-top: 15px;"></div>
                    </div>

                    <div id="backups-list" style="display: none;">
                        <h3>Available Backups</h3>
                        <div id="backups-content" class="script-grid">
                            <!-- Backups will be loaded dynamically -->
                        </div>
                    </div>
                </div>

                <!-- Deployments Tab -->
                <div id="deployments" class="tab-content">
                    <h2>🚀 Deployment Workflows</h2>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0;">
                        <div style="background: #f8fafc; padding: 20px; border-radius: 10px;">
                            <h3>Deployment Templates</h3>
                            <p>Manage reusable deployment templates for common operations.</p>
                            <button class="btn btn-primary" onclick="listDeploymentTemplates()">📋 View Templates</button>
                            <div id="templates-status" style="margin-top: 15px;"></div>
                        </div>

                        <div style="background: #f8fafc; padding: 20px; border-radius: 10px;">
                            <h3>Workflows</h3>
                            <p>Create and execute automated deployment workflows.</p>
                            <button class="btn btn-success" onclick="listDeploymentWorkflows()">📋 View Workflows</button>
                            <button class="btn btn-warning" onclick="createDeploymentWorkflow()">➕ New Workflow</button>
                            <div id="workflows-status" style="margin-top: 15px;"></div>
                        </div>
                    </div>

                    <div id="deployments-content" style="display: none;">
                        <div id="deployments-output"></div>
                    </div>
                </div>

                <!-- Operations Tab -->
                <div id="operations" class="tab-content">
                    <h2>⚙️ Advanced Operations</h2>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0;">
                        <div style="background: #f8fafc; padding: 20px; border-radius: 10px;">
                            <h3>Auto-Scaling Policies</h3>
                            <p>Configure automatic scaling based on resource metrics.</p>
                            <button class="btn btn-primary" onclick="listScalingPolicies()">📋 View Policies</button>
                            <button class="btn btn-success" onclick="createScalingPolicy()">➕ New Policy</button>
                            <div id="scaling-status" style="margin-top: 15px;"></div>
                        </div>

                        <div style="background: #f8fafc; padding: 20px; border-radius: 10px;">
                            <h3>Health Checks</h3>
                            <p>Monitor service health and cluster status.</p>
                            <button class="btn btn-primary" onclick="listHealthChecks()">📋 View Checks</button>
                            <button class="btn btn-success" onclick="createHealthCheck()">➕ New Check</button>
                            <div id="health-status" style="margin-top: 15px;"></div>
                        </div>
                    </div>

                    <div style="background: #f8fafc; padding: 20px; border-radius: 10px; margin: 20px 0;">
                        <h3>Cluster Health Overview</h3>
                        <p>Real-time health status of the entire cluster.</p>
                        <button class="btn btn-primary" onclick="getClusterHealth()">🔄 Check Health</button>
                        <div id="cluster-health-status" style="margin-top: 15px;"></div>
                    </div>

                    <div id="operations-content" style="display: none;">
                        <div id="operations-output"></div>
                    </div>
                </div>

                <!-- API Tab -->
                <div id="api" class="tab-content">
                    <h2>🔌 API Endpoints</h2>
                    
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px;">
                        <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px;">
                            <h3>� Discovery Endpoints</h3>
                            <ul style="margin: 0; padding-left: 20px;">
                                <li><code>GET /api/scripts</code> - All scripts by category</li>
                                <li><code>GET /api/scripts/stats</code> - Statistics</li>
                                <li><code>GET /api/scripts/{category}</code> - Category scripts</li>
                            </ul>
                        </div>
                        
                        <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px;">
                            <h3>🚀 Execution Endpoints</h3>
                            <ul style="margin: 0; padding-left: 20px;">
                                <li><code>POST /api/scripts/execute</code> - Execute script (batch mode)</li>
                                <li><code>GET /api/scripts/execute/test</code> - Test execution framework</li>
                                <li><code>WebSocket /ws/execute</code> - <strong>Real-time execution with live streaming</strong></li>
                            </ul>
                        </div>
                        
                        <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px;">
                            <h3>🩺 System Endpoints</h3>
                            <ul style="margin: 0; padding-left: 20px;">
                                <li><code>GET /health</code> - Health check</li>
                                <li><code>GET /api/info</code> - System info</li>
                            </ul>
                        </div>
                        
                        <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px;">
                            <h3>🐳 Docker Endpoints</h3>
                            <ul style="margin: 0; padding-left: 20px;">
                                <li><code>GET /api/docker/info</code> - Docker system info</li>
                                <li><code>GET /api/docker/images</code> - List Docker images</li>
                                <li><code>GET /api/docker/containers</code> - List Docker containers</li>
                                <li><code>POST /api/docker/build</code> - Build Docker image</li>
                                <li><code>WebSocket /ws/docker/build</code> - <strong>Real-time Docker build</strong></li>
                            </ul>
                        </div>
                        
                        <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px;">
                            <h3>🌳 Cluster Endpoints</h3>
                            <ul style="margin: 0; padding-left: 20px;">
                                <li><code>GET /api/cluster/nodes</code> - Cluster node information</li>
                                <li><code>GET /api/cluster/status</code> - Real-time node status</li>
                                <li><code>POST /api/cluster/ping</code> - Ping selected nodes</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
            // Authentication state management
            let currentUser = null;
            let accessToken = null;

            // Check authentication on page load
            document.addEventListener('DOMContentLoaded', function() {
                const token = localStorage.getItem('access_token');
                if (token) {
                    accessToken = token;
                    validateToken();
                } else {
                    showLoginModal();
                }
            });

            // Authentication functions
            async function login(username, password) {
                try {
                    const response = await fetch('/api/auth/login', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            username: username,
                            password: password
                        })
                    });

                    if (response.ok) {
                        const data = await response.json();
                        accessToken = data.access_token;
                        localStorage.setItem('access_token', accessToken);
                        await validateToken();
                        hideLoginModal();
                        showMainInterface();
                    } else {
                        const error = await response.json();
                        showLoginError(error.detail || 'Login failed');
                    }
                } catch (error) {
                    showLoginError('Network error. Please try again.');
                }
            }

            async function validateToken() {
                if (!accessToken) return false;

                try {
                    const response = await fetch('/api/auth/me', {
                        headers: {
                            'Authorization': `Bearer ${accessToken}`
                        }
                    });

                    if (response.ok) {
                        currentUser = await response.json();
                        updateUserInterface();
                        return true;
                    } else {
                        logout();
                        return false;
                    }
                } catch (error) {
                    logout();
                    return false;
                }
            }

            function logout() {
                currentUser = null;
                accessToken = null;
                localStorage.removeItem('access_token');
                showLoginModal();
                hideMainInterface();
            }

            function showLoginModal() {
                document.getElementById('login-modal').style.display = 'flex';
            }

            function hideLoginModal() {
                document.getElementById('login-modal').style.display = 'none';
            }

            function showMainInterface() {
                document.getElementById('main-container').style.display = 'block';
                // Load initial data
                loadStats();
                loadScriptsForSelector();
            }

            function hideMainInterface() {
                document.getElementById('main-container').style.display = 'none';
            }

            function showLoginError(message) {
                const errorDiv = document.getElementById('login-error');
                errorDiv.textContent = message;
                errorDiv.style.display = 'block';
            }

            function updateUserInterface() {
                if (currentUser) {
                    // Update header with user info
                    const header = document.querySelector('.header');
                    let userInfo = header.querySelector('.user-info');
                    if (!userInfo) {
                        userInfo = document.createElement('div');
                        userInfo.className = 'user-info';
                        header.appendChild(userInfo);
                    }
                    userInfo.innerHTML = `
                        <div style="margin-top: 10px; text-align: center;">
                            <span>👤 ${currentUser.full_name || currentUser.username} (${currentUser.role})</span>
                            <button onclick="logout()" style="margin-left: 10px; padding: 4px 8px; background: #dc2626; color: white; border: none; border-radius: 4px; cursor: pointer;">Logout</button>
                        </div>
                    `;
                }
            }

            // Login form handler
            document.getElementById('login-form').addEventListener('submit', function(e) {
                e.preventDefault();
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                login(username, password);
            });

            // Tab switching functionality
            async function loadClusterData() {
                try {
                    await loadNodeSummary();
                    await loadClusterTree();
                } catch (error) {
                    console.error('Failed to load cluster data:', error);
                }
            }

            function showTab(tabName) {
                // Hide all tabs
                const tabs = document.querySelectorAll('.tab-content');
                tabs.forEach(tab => tab.classList.remove('active'));
                
                // Remove active class from all nav tabs
                const navTabs = document.querySelectorAll('.nav-tab');
                navTabs.forEach(tab => tab.classList.remove('active'));
                
                // Show selected tab
                document.getElementById(tabName).classList.add('active');
                event.target.classList.add('active');
                
                // Load data for specific tabs
                if (tabName === 'overview') {
                    loadStats();
                } else if (tabName === 'scripts') {
                    loadScripts();
                } else if (tabName === 'cluster') {
                    loadClusterData();
                }
            }

            // Helper function for authenticated API calls
            async function authenticatedFetch(url, options = {}) {
                const headers = {
                    'Content-Type': 'application/json',
                    ...options.headers
                };

                if (accessToken) {
                    headers['Authorization'] = `Bearer ${accessToken}`;
                }

                return fetch(url, {
                    ...options,
                    headers
                });
            }

            // Load statistics
            async function loadStats() {
                try {
                    const response = await authenticatedFetch('/api/scripts/stats');
                    const data = await response.json();
                    
                    document.getElementById('total-scripts').textContent = data.total_scripts;
                    document.getElementById('categories-count').textContent = data.categories_count;
                    
                    let executableCount = 0;
                    Object.values(data.categories).forEach(cat => {
                        executableCount += cat.executable_scripts;
                    });
                    document.getElementById('executable-scripts').textContent = executableCount;
                } catch (error) {
                    console.error('Failed to load stats:', error);
                }
            }

            // Load scripts
            async function loadScripts() {
                try {
                    const response = await authenticatedFetch('/api/scripts');
                    const data = await response.json();
                    
                    let html = '';
                    Object.entries(data.categories).forEach(([category, scripts]) => {
                        html += `<h3>📁 ${category.toUpperCase()} (${scripts.length} scripts)</h3>`;
                        html += '<div class="script-grid">';
                        
                        scripts.forEach(script => {
                            const executableIcon = script.executable ? '✅' : '❌';
                            const size = (script.size / 1024).toFixed(1) + ' KB';
                            
                            html += `
                                <div class="script-card">
                                    <h4>${script.name}</h4>
                                    <div class="meta">📍 ${script.directory}</div>
                                    <div class="meta">📏 ${size} | ${executableIcon} Executable</div>
                                    <div class="actions">
                                        <button class="btn btn-primary" onclick="viewScript('${script.full_path}')">👁️ View</button>
                                        ${script.executable ? `<button class="btn btn-success" onclick="executeScript('${script.name}', '${category}')">▶️ Execute</button>` : ''}
                                    </div>
                                </div>
                            `;
                        });
                        
                        html += '</div>';
                    });
                    
                    document.getElementById('scripts-container').innerHTML = html;
                } catch (error) {
                    console.error('Failed to load scripts:', error);
                    document.getElementById('scripts-container').innerHTML = '<p>Error loading scripts</p>';
                }
            }

            // Test execution
            async function testExecution() {
                const button = event.target;
                const resultDiv = document.getElementById('test-result');
                
                button.disabled = true;
                button.textContent = '⏳ Running...';
                resultDiv.innerHTML = '<p>Executing test script...</p>';
                
                try {
                    const response = await fetch('/api/scripts/execute/test');
                    const data = await response.json();
                    
                    if (data.test_result === 'success') {
                        resultDiv.innerHTML = `
                            <div class="execution-result">
✅ Test Successful!
📝 Return Code: ${data.execution_result.return_code}
⏱️ Execution Time: ${data.execution_result.execution_time.toFixed(2)}s

📤 Output:
${data.execution_result.stdout}
                            </div>
                        `;
                    } else {
                        resultDiv.innerHTML = `<div style="color: red;">❌ Test Failed: ${data.error}</div>`;
                    }
                } catch (error) {
                    resultDiv.innerHTML = `<div style="color: red;">❌ Error: ${error.message}</div>`;
                }
                
                button.disabled = false;
                button.textContent = '🧪 Run Test Script';
            }

            // Load scripts for selector
            async function loadScriptsForSelector() {
                try {
                    const response = await fetch('/api/scripts');
                    const data = await response.json();
                    
                    const selector = document.getElementById('script-selector');
                    selector.innerHTML = '<option value="">Select a script to execute...</option>';
                    
                    Object.entries(data.categories).forEach(([category, scripts]) => {
                        const optgroup = document.createElement('optgroup');
                        optgroup.label = category.toUpperCase();
                        
                        scripts.forEach(script => {
                            if (script.executable) {
                                const option = document.createElement('option');
                                option.value = script.full_path;
                                option.textContent = `${script.name} (${(script.size/1024).toFixed(1)} KB)`;
                                optgroup.appendChild(option);
                            }
                        });
                        
                        if (optgroup.children.length > 0) {
                            selector.appendChild(optgroup);
                        }
                    });
                } catch (error) {
                    console.error('Failed to load scripts for selector:', error);
                }
            }

            // Execute script with real-time WebSocket output
            async function executeScriptRealtime() {
                const scriptPath = document.getElementById('script-selector').value;
                if (!scriptPath) {
                    alert('Please select a script to execute');
                    return;
                }
                
                const outputDiv = document.getElementById('execution-output');
                const outputContent = document.getElementById('output-content');
                
                // Clear previous output and show container
                outputContent.innerHTML = '';
                outputDiv.style.display = 'block';
                
                // Scroll to output
                outputDiv.scrollIntoView({ behavior: 'smooth' });
                
                try {
                    const ws = new WebSocket(`ws://${window.location.host}/ws/execute`);
                    
                    ws.onopen = function(event) {
                        console.log('WebSocket connected');
                        // Send execution request
                        ws.send(JSON.stringify({
                            script_path: scriptPath,
                            timeout: 30
                        }));
                    };
                    
                    ws.onmessage = function(event) {
                        const data = JSON.parse(event.data);
                        
                        if (data.type === 'start') {
                            outputContent.innerHTML += `<div style="color: #10b981;">▶️ ${data.message}</div>`;
                        } else if (data.type === 'stdout') {
                            outputContent.innerHTML += `<div style="color: #e5e7eb;">${data.data}</div>`;
                        } else if (data.type === 'stderr') {
                            outputContent.innerHTML += `<div style="color: #f87171;">${data.data}</div>`;
                        } else if (data.type === 'complete') {
                            const status = data.return_code === 0 ? '✅ Success' : '❌ Failed';
                            outputContent.innerHTML += `<div style="color: #10b981; margin-top: 10px;">${status} (Return code: ${data.return_code}, Time: ${data.execution_time.toFixed(2)}s)</div>`;
                        } else if (data.type === 'error') {
                            outputContent.innerHTML += `<div style="color: #f87171;">❌ ${data.message}</div>`;
                        }
                        
                        // Auto-scroll to bottom
                        outputDiv.scrollTop = outputDiv.scrollHeight;
                    };
                    
                    ws.onclose = function(event) {
                        console.log('WebSocket closed');
                        outputContent.innerHTML += `<div style="color: #6b7280; margin-top: 10px;">--- Execution finished ---</div>`;
                    };
                    
                    ws.onerror = function(error) {
                        console.error('WebSocket error:', error);
                        outputContent.innerHTML += `<div style="color: #f87171;">❌ WebSocket connection failed</div>`;
                    };
                    
                } catch (error) {
                    outputContent.innerHTML += `<div style="color: #f87171;">❌ Failed to connect: ${error.message}</div>`;
                }
            }

            // Placeholder functions
            function viewScript(path) {
                alert(`View script: ${path}\\n\\nFeature coming soon!`);
            }
            
            function executeScript(name, category) {
                alert(`Execute script: ${name} from ${category}\\n\\nFeature coming soon with real-time output!`);
            }

            // Load initial data
            document.addEventListener('DOMContentLoaded', function() {
                loadStats();
                loadScriptsForSelector();
            });

            // Docker functions
            async function loadDockerStatus() {
                try {
                    const response = await fetch('/api/docker/info');
                    const data = await response.json();
                    
                    const statusDiv = document.getElementById('docker-status');
                    if (data.available) {
                        statusDiv.innerHTML = `
                            <div style="color: #10b981;">✅ Docker Available</div>
                            <p><strong>Version:</strong> ${data.info.server_version}</p>
                            <p><strong>Containers:</strong> ${data.info.containers} total, ${data.info.containers_running} running</p>
                            <p><strong>Images:</strong> ${data.info.images}</p>
                        `;
                    } else {
                        statusDiv.innerHTML = `<div style="color: #f87171;">❌ Docker Not Available: ${data.error}</div>`;
                    }
                } catch (error) {
                    document.getElementById('docker-status').innerHTML = `<div style="color: #f87171;">❌ Error loading Docker status</div>`;
                }
            }

            async function loadDockerImages() {
                try {
                    const response = await fetch('/api/docker/images');
                    const data = await response.json();
                    
                    const imagesDiv = document.getElementById('docker-images');
                    if (data.available && data.images.length > 0) {
                        let html = '<div style="max-height: 300px; overflow-y: auto;">';
                        data.images.forEach(image => {
                            const size = (image.size / (1024 * 1024)).toFixed(2) + ' MB';
                            const tags = image.tags.length > 0 ? image.tags.join(', ') : image.repo_tags[0];
                            html += `
                                <div style="border: 1px solid #e2e8f0; border-radius: 5px; padding: 10px; margin: 5px 0;">
                                    <strong>${tags}</strong><br>
                                    <small>ID: ${image.id.substring(7, 19)} | Size: ${size}</small>
                                </div>
                            `;
                        });
                        html += '</div>';
                        imagesDiv.innerHTML = html;
                    } else {
                        imagesDiv.innerHTML = '<p>No Docker images found</p>';
                    }
                } catch (error) {
                    document.getElementById('docker-images').innerHTML = '<p>Error loading images</p>';
                }
            }

            async function loadDockerContainers() {
                try {
                    const response = await fetch('/api/docker/containers');
                    const data = await response.json();
                    
                    const containersDiv = document.getElementById('docker-containers');
                    if (data.available && data.containers.length > 0) {
                        let html = '<div style="max-height: 300px; overflow-y: auto;">';
                        data.containers.forEach(container => {
                            const statusColor = container.status.includes('Up') ? '#10b981' : '#6b7280';
                            html += `
                                <div style="border: 1px solid #e2e8f0; border-radius: 5px; padding: 10px; margin: 5px 0;">
                                    <strong>${container.name}</strong><br>
                                    <small>Image: ${container.image} | <span style="color: ${statusColor};">${container.status}</span></small>
                                </div>
                            `;
                        });
                        html += '</div>';
                        containersDiv.innerHTML = html;
                    } else {
                        containersDiv.innerHTML = '<p>No Docker containers found</p>';
                    }
                } catch (error) {
                    document.getElementById('docker-containers').innerHTML = '<p>Error loading containers</p>';
                }
            }

            async function buildDockerImage() {
                const dockerfilePath = document.getElementById('dockerfile-path').value;
                const imageTag = document.getElementById('image-tag').value;
                
                if (!dockerfilePath || !imageTag) {
                    alert('Please provide both Dockerfile path and image tag');
                    return;
                }
                
                const outputDiv = document.getElementById('build-output');
                const outputContent = document.getElementById('build-content');
                
                // Clear previous output and show container
                outputContent.innerHTML = '';
                outputDiv.style.display = 'block';
                
                // Scroll to output
                outputDiv.scrollIntoView({ behavior: 'smooth' });
                
                try {
                    const ws = new WebSocket(`ws://${window.location.host}/ws/docker/build`);
                    
                    ws.onopen = function(event) {
                        console.log('Docker build WebSocket connected');
                        // Send build request
                        ws.send(JSON.stringify({
                            dockerfile_path: dockerfilePath,
                            tag: imageTag
                        }));
                    };
                    
                    ws.onmessage = function(event) {
                        const data = JSON.parse(event.data);
                        
                        if (data.type === 'start') {
                            outputContent.innerHTML += `<div style="color: #10b981;">🏗️ ${data.message}</div>`;
                        } else if (data.type === 'log') {
                            outputContent.innerHTML += `<div style="color: #e5e7eb;">${data.data}</div>`;
                        } else if (data.type === 'status') {
                            outputContent.innerHTML += `<div style="color: #6b7280;">${data.data}</div>`;
                        } else if (data.type === 'error') {
                            outputContent.innerHTML += `<div style="color: #f87171;">❌ ${data.data}</div>`;
                        } else if (data.type === 'complete') {
                            const time = data.execution_time.toFixed(2);
                            outputContent.innerHTML += `<div style="color: #10b981; margin-top: 10px;">✅ Build Complete! Image: ${data.tag} (ID: ${data.image_id.substring(7, 19)}, Time: ${time}s)</div>`;
                            // Refresh images list
                            loadDockerImages();
                        }
                        
                        // Auto-scroll to bottom
                        outputDiv.scrollTop = outputDiv.scrollHeight;
                    };
                    
                    ws.onclose = function(event) {
                        console.log('Docker build WebSocket closed');
                        outputContent.innerHTML += `<div style="color: #6b7280; margin-top: 10px;">--- Build finished ---</div>`;
                    };
                    
                    ws.onerror = function(error) {
                        console.error('Docker build WebSocket error:', error);
                        outputContent.innerHTML += `<div style="color: #f87171;">❌ WebSocket connection failed</div>`;
                    };
                    
                } catch (error) {
                    outputContent.innerHTML += `<div style="color: #f87171;">❌ Failed to connect: ${error.message}</div>`;
                }
            }

            // Update showTab function to load Docker data
            const originalShowTab = window.showTab;
            window.showTab = function(tabName) {
                originalShowTab(tabName);
                
                if (tabName === 'containers') {
                    loadDockerStatus();
                    loadDockerImages();
                    loadDockerContainers();
                }
            };

            // Cluster management functions
            async function loadClusterData() {
                console.log('loadClusterData called');
                
                // Add loading state to button
                const refreshBtn = event.target.closest('button');
                if (refreshBtn) {
                    refreshBtn.disabled = true;
                    refreshBtn.textContent = '🔄 Loading...';
                }
                
                try {
                    await loadClusterStatus();
                    await loadNodeSummary();
                    await loadClusterTree();
                } catch (error) {
                    console.error('Error in loadClusterData:', error);
                } finally {
                    // Reset button state
                    if (refreshBtn) {
                        refreshBtn.disabled = false;
                        refreshBtn.textContent = '🔄 Refresh All';
                    }
                }
            }

            async function loadClusterStatus() {
                try {
                    // Check if user is authenticated
                    if (!accessToken) {
                        document.getElementById('cluster-status').innerHTML = '<div style="color: #f59e0b;">⚠️ Please log in to view cluster status</div>';
                        return;
                    }
                    
                    const response = await fetch('/api/cluster/status', {
                        headers: {
                            'Authorization': `Bearer ${accessToken}`
                        }
                    });
                    
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    
                    const data = await response.json();
                    
                    const statusDiv = document.getElementById('cluster-status');
                    const summary = data.summary;
                    
                    statusDiv.innerHTML = `
                        <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                            <div style="text-align: center;">
                                <div style="font-size: 2em; font-weight: bold; color: #4f46e5;">${summary.total_nodes}</div>
                                <div>Total Nodes</div>
                            </div>
                            <div style="text-align: center;">
                                <div style="font-size: 2em; font-weight: bold; color: #10b981;">${summary.pingable_nodes}</div>
                                <div>Pingable</div>
                            </div>
                            <div style="text-align: center;">
                                <div style="font-size: 2em; font-weight: bold; color: #f59e0b;">${summary.ssh_accessible_nodes}</div>
                                <div>SSH Accessible</div>
                            </div>
                        </div>
                        <div style="margin-top: 10px; font-size: 0.9em; color: #6b7280;">
                            Last updated: ${new Date(summary.timestamp).toLocaleString()}
                        </div>
                    `;
                } catch (error) {
                    console.error('Error loading cluster status:', error);
                    document.getElementById('cluster-status').innerHTML = '<div style="color: #f87171;">❌ Error loading cluster status<br><small>' + error.message + '</small></div>';
                }
            }

            async function loadNodeSummary() {
                try {
                    const response = await fetch('/api/cluster/nodes');
                    const data = await response.json();
                    
                    const summaryDiv = document.getElementById('node-summary');
                    let html = `
                        <div class="node-tree">
                            <div class="tree-node server-node" onclick="toggleTreeNode(this)">
                                <input type="checkbox" class="node-checkbox" onchange="handleCheckboxChange(this)">
                                <span class="tree-icon">🖥️</span>
                                <span class="tree-label">Server</span>
                                <span class="tree-count">(${data.nodes.gpu_workers.length + data.nodes.network_gateways.length + 1} nodes)</span>
                            </div>
                            <div class="tree-children">
                                <!-- Control Plane -->
                                <div class="tree-node control-plane-node">
                                    <input type="checkbox" class="node-checkbox" onchange="handleCheckboxChange(this)">
                                    <span class="tree-icon">🎛️</span>
                                    <span class="tree-label">${data.nodes.control_plane.name}</span>
                                    <span class="tree-details">(${data.nodes.control_plane.ip}) - ${data.nodes.control_plane.role}</span>
                                    <div class="node-status status-${data.nodes.control_plane.status.toLowerCase()}">${data.nodes.control_plane.status}</div>
                                </div>
                                
                                <!-- GPU Workers -->
                                <div class="tree-node gpu-nodes" onclick="toggleTreeNode(this)">
                                    <input type="checkbox" class="node-checkbox" onchange="handleCheckboxChange(this)">
                                    <span class="tree-icon">🔽</span>
                                    <span class="tree-label">GPU Worker Nodes</span>
                                    <span class="tree-count">(${data.nodes.gpu_workers.length})</span>
                                </div>
                                <div class="tree-children">
                                    ${data.nodes.gpu_workers.map(node => `
                                        <div class="tree-node gpu-worker-node">
                                            <input type="checkbox" class="node-checkbox" onchange="handleCheckboxChange(this)">
                                            <span class="tree-icon">${node.gpu_support.includes('Blackwell') ? '🚀' : '🎮'}</span>
                                            <span class="tree-label">${node.name}</span>
                                            <span class="tree-details">(${node.ip}) - ${node.gpu_support}</span>
                                            <div class="node-status status-${node.status.toLowerCase()}">${node.status}</div>
                                        </div>
                                    `).join('')}
                                </div>
                                
                                <!-- Network Gateways -->
                                <div class="tree-node network-nodes" onclick="toggleTreeNode(this)">
                                    <input type="checkbox" class="node-checkbox" onchange="handleCheckboxChange(this)">
                                    <span class="tree-icon">🔽</span>
                                    <span class="tree-label">Network Gateways</span>
                                    <span class="tree-count">(${data.nodes.network_gateways.length})</span>
                                </div>
                                <div class="tree-children">
                                    ${data.nodes.network_gateways.map(node => `
                                        <div class="tree-node network-node">
                                            <input type="checkbox" class="node-checkbox" onchange="handleCheckboxChange(this)">
                                            <span class="tree-icon">🔐</span>
                                            <span class="tree-label">${node.name}</span>
                                            <span class="tree-details">(${node.ip}) - VPN Gateway</span>
                                            <div class="node-status status-${node.status.toLowerCase()}">${node.status}</div>
                                        </div>
                                    `).join('')}
                                </div>
                            </div>
                        </div>
                    `;
                    
                    summaryDiv.innerHTML = html;
                } catch (error) {
                    console.error('Error loading node summary:', error);
                    document.getElementById('node-summary').innerHTML = '<div style="color: #f87171;">❌ Error loading node summary<br><small>' + error.message + '</small></div>';
                }
            }

            function toggleTreeNode(element) {
                const children = element.nextElementSibling;
                if (children && children.classList.contains('tree-children')) {
                    const isCollapsed = children.classList.contains('collapsed');
                    children.classList.toggle('collapsed');
                    // Update expand/collapse indicator
                    const icon = element.querySelector('.tree-icon');
                    if (icon) {
                        icon.textContent = isCollapsed ? '▶️' : '🔽';
                    }
                }
            }

            function handleCheckboxChange(checkbox) {
                const treeNode = checkbox.closest('.tree-node');
                const isChecked = checkbox.checked;

                // If this is a parent node, update all children
                if (treeNode.classList.contains('server-node') ||
                    treeNode.classList.contains('gpu-nodes') ||
                    treeNode.classList.contains('network-nodes')) {

                    const childrenContainer = treeNode.nextElementSibling;
                    if (childrenContainer && childrenContainer.classList.contains('tree-children')) {
                        const childCheckboxes = childrenContainer.querySelectorAll('.node-checkbox');
                        childCheckboxes.forEach(childCheckbox => {
                            childCheckbox.checked = isChecked;
                        });
                    }
                }

                // Update parent checkbox based on children state
                updateParentCheckbox(treeNode);
            }

            function updateParentCheckbox(childNode) {
                // Find the parent container
                const parentContainer = childNode.closest('.tree-children');
                if (!parentContainer) return;

                const parentNode = parentContainer.previousElementSibling;
                if (!parentNode || !parentNode.classList.contains('tree-node')) return;

                const parentCheckbox = parentNode.querySelector('.node-checkbox');
                if (!parentCheckbox) return;

                // Check if all siblings are checked
                const siblingCheckboxes = parentContainer.querySelectorAll('.node-checkbox');
                const allChecked = Array.from(siblingCheckboxes).every(cb => cb.checked);
                const someChecked = Array.from(siblingCheckboxes).some(cb => cb.checked);

                parentCheckbox.checked = allChecked;
                parentCheckbox.indeterminate = someChecked && !allChecked;

                // Recursively update grandparent
                updateParentCheckbox(parentNode);
            }

            async function loadClusterTree() {
                try {
                    const response = await fetch('/api/cluster/nodes');
                    const data = await response.json();
                    
                    const treeDiv = document.getElementById('tree-content');
                    // Keep terminal area clean for live info - tree structure is shown in the left panel
                    treeDiv.textContent = `🌐 ${data.cluster_name} - ${data.nodes.gpu_workers.length + data.nodes.network_gateways.length + 1} nodes online\n\nReady for live operations and monitoring...`;
                } catch (error) {
                    document.getElementById('tree-content').textContent = 'Error loading cluster info';
                }
            }

            // Ping test functions
            function getSelectedNodes() {
                const selectedNodes = [];
                const checkboxes = document.querySelectorAll('.node-checkbox:checked');
                
                checkboxes.forEach(checkbox => {
                    const treeNode = checkbox.closest('.tree-node');
                    const nodeLabel = treeNode.querySelector('.tree-label');
                    
                    if (nodeLabel) {
                        let nodeName = nodeLabel.textContent.trim();
                        
                        // Skip parent nodes (Server, GPU Worker Nodes, Network Gateways)
                        if (nodeName === 'Server' || nodeName === 'GPU Worker Nodes' || nodeName === 'Network Gateways') {
                            return;
                        }
                        
                        // Use the node name directly (this matches the cluster configuration)
                        selectedNodes.push(nodeName);
                    }
                });
                
                return selectedNodes;
            }

            async function pingSelectedNodes() {
                const selectedNodes = getSelectedNodes();
                const pingStatusDiv = document.getElementById('ping-status');
                const treeContentDiv = document.getElementById('tree-content');
                
                if (selectedNodes.length === 0) {
                    pingStatusDiv.innerHTML = '<div style="color: #f59e0b;">⚠️ Please select at least one node to ping</div>';
                    return;
                }
                
                pingStatusDiv.innerHTML = '<div style="color: #3b82f6;">🏓 Pinging selected nodes...</div>';
                treeContentDiv.textContent = `🏓 Starting ping test for ${selectedNodes.length} node(s)...\n\n`;
                
                try {
                    const response = await fetch('/api/cluster/ping', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${accessToken}`
                        },
                        body: JSON.stringify({ nodes: selectedNodes })
                    });
                    
                    const data = await response.json();
                    
                    if (data.error) {
                        pingStatusDiv.innerHTML = `<div style="color: #f87171;">❌ Error: ${data.error}</div>`;
                        treeContentDiv.textContent += `❌ Error: ${data.error}\n`;
                        return;
                    }
                    
                    pingStatusDiv.innerHTML = `<div style="color: #10b981;">✅ Ping test completed for ${selectedNodes.length} node(s)</div>`;
                    
                    // Display results in terminal
                    let resultsText = `🏓 Ping Test Results (${new Date().toLocaleString()})\n`;
                    resultsText += `═`.repeat(50) + `\n\n`;
                    
                    Object.entries(data.ping_results).forEach(([node, result]) => {
                        const status = result.pingable ? '✅ REACHABLE' : '❌ UNREACHABLE';
                        const ip = result.ip ? ` (${result.ip})` : '';
                        resultsText += `${status} ${node}${ip}\n`;
                    });
                    
                    resultsText += `\n📊 Summary: ${data.summary.successful_pings}/${data.summary.requested_nodes} nodes reachable\n\n`;
                    resultsText += `Ready for next operation...\n`;
                    
                    treeContentDiv.textContent = resultsText;
                    
                } catch (error) {
                    pingStatusDiv.innerHTML = '<div style="color: #f87171;">❌ Error performing ping test</div>';
                    treeContentDiv.textContent += `❌ Error: ${error.message}\n`;
                }
            }

            // Resource monitoring functions
            async function loadResourceUsage() {
                try {
                    const response = await fetch('/api/cluster/resources', {
                        headers: {
                            'Authorization': `Bearer ${accessToken}`
                        }
                    });
                    const data = await response.json();

                    const statusDiv = document.getElementById('resource-status');
                    const statsDiv = document.getElementById('resource-stats');

                    if (data.cluster_resources) {
                        statusDiv.innerHTML = '<div style="color: #10b981;">✅ Resources loaded successfully</div>';

                        let statsHtml = '';
                        Object.entries(data.cluster_resources).forEach(([node, resources]) => {
                            const cpu = resources.cpu_usage || 'N/A';
                            const memory = resources.memory_usage || 'N/A';
                            const disk = resources.disk_usage || 'N/A';

                            statsHtml += `
                                <div class="stat-card">
                                    <h3>${node}</h3>
                                    <p><strong>CPU:</strong> ${cpu}</p>
                                    <p><strong>Memory:</strong> ${memory}</p>
                                    <p><strong>Disk:</strong> ${disk}</p>
                                </div>
                            `;
                        });
                        statsDiv.innerHTML = statsHtml;
                    } else {
                        statusDiv.innerHTML = '<div style="color: #f87171;">❌ Failed to load resources</div>';
                    }
                } catch (error) {
                    document.getElementById('resource-status').innerHTML = '<div style="color: #f87171;">Error loading resources</div>';
                }
            }

            // Log management functions
            async function loadAuditLogs() {
                try {
                    const response = await fetch('/api/logs/audit', {
                        headers: {
                            'Authorization': `Bearer ${accessToken}`
                        }
                    });
                    const data = await response.json();

                    const statusDiv = document.getElementById('audit-logs-status');
                    const logsDiv = document.getElementById('logs-content');
                    const outputDiv = document.getElementById('logs-output');

                    if (data.logs && data.logs.length > 0) {
                        statusDiv.innerHTML = `<div style="color: #10b981;">✅ Loaded ${data.logs.length} audit log entries</div>`;

                        let logsHtml = '<h3>Audit Logs</h3>';
                        data.logs.forEach(log => {
                            const timestamp = new Date(log.timestamp).toLocaleString();
                            logsHtml += `<div style="margin-bottom: 10px; padding: 10px; background: #374151; border-radius: 5px;">
                                <div><strong>${timestamp}</strong> - ${log.event_type} - ${log.action}</div>
                                <div style="color: #9ca3af;">User: ${log.username} | Resource: ${log.resource || 'N/A'}</div>
                                ${log.details ? `<div style="color: #d1d5db; font-size: 0.9em;">Details: ${JSON.stringify(log.details)}</div>` : ''}
                            </div>`;
                        });

                        outputDiv.innerHTML = logsHtml;
                        logsDiv.style.display = 'block';
                    } else {
                        statusDiv.innerHTML = '<div style="color: #6b7280;">No audit logs found</div>';
                    }
                } catch (error) {
                    document.getElementById('audit-logs-status').innerHTML = '<div style="color: #f87171;">Error loading audit logs</div>';
                }
            }

            async function loadSystemLogs() {
                try {
                    const response = await fetch('/api/logs/system', {
                        headers: {
                            'Authorization': `Bearer ${accessToken}`
                        }
                    });
                    const data = await response.json();

                    const statusDiv = document.getElementById('system-logs-status');
                    const logsDiv = document.getElementById('logs-content');
                    const outputDiv = document.getElementById('logs-output');

                    if (data.logs && data.logs.length > 0) {
                        statusDiv.innerHTML = `<div style="color: #10b981;">✅ Loaded ${data.logs.length} system log lines</div>`;

                        let logsHtml = '<h3>System Logs</h3><pre style="background: #111827; padding: 15px; border-radius: 5px; overflow-x: auto;">';
                        logsHtml += data.logs.join('\\n');
                        logsHtml += '</pre>';

                        outputDiv.innerHTML = logsHtml;
                        logsDiv.style.display = 'block';
                    } else {
                        statusDiv.innerHTML = '<div style="color: #6b7280;">No system logs available</div>';
                    }
                } catch (error) {
                    document.getElementById('system-logs-status').innerHTML = '<div style="color: #f87171;">Error loading system logs</div>';
                }
            }

            // Backup management functions
            async function createBackup() {
                if (!confirm('Create a new backup of cluster configurations?')) return;

                try {
                    const response = await fetch('/api/backup/create', {
                        method: 'POST',
                        headers: {
                            'Authorization': `Bearer ${accessToken}`
                        }
                    });
                    const data = await response.json();

                    const statusDiv = document.getElementById('backup-status');
                    if (data.backup_id) {
                        statusDiv.innerHTML = `<div style="color: #10b981;">✅ Backup created successfully: ${data.backup_id}</div>
                            <div style="margin-top: 10px;">
                                <strong>Files backed up:</strong> ${data.files_backed_up}<br>
                                <strong>Created at:</strong> ${new Date(data.created_at).toLocaleString()}
                            </div>`;
                        // Refresh backups list
                        setTimeout(() => listBackups(), 1000);
                    } else {
                        statusDiv.innerHTML = '<div style="color: #f87171;">❌ Failed to create backup</div>';
                    }
                } catch (error) {
                    document.getElementById('backup-status').innerHTML = '<div style="color: #f87171;">Error creating backup</div>';
                }
            }

            async function listBackups() {
                try {
                    const response = await fetch('/api/backup/list', {
                        headers: {
                            'Authorization': `Bearer ${accessToken}`
                        }
                    });
                    const data = await response.json();

                    const listDiv = document.getElementById('backups-list');
                    const contentDiv = document.getElementById('backups-content');

                    if (data.backups && data.backups.length > 0) {
                        listDiv.style.display = 'block';

                        let backupsHtml = '';
                        data.backups.forEach(backup => {
                            const created = new Date(backup.created_at).toLocaleString();
                            backupsHtml += `
                                <div class="script-card">
                                    <h4>${backup.backup_id}</h4>
                                    <div class="meta">Created: ${created}</div>
                                    <div class="meta">By: ${backup.created_by}</div>
                                    <div class="meta">Files: ${backup.files ? backup.files.length : 'N/A'}</div>
                                    <div class="actions">
                                        <button class="btn btn-success" onclick="restoreBackup('${backup.backup_id}')">Restore</button>
                                    </div>
                                </div>
                            `;
                        });
                        contentDiv.innerHTML = backupsHtml;
                    } else {
                        listDiv.style.display = 'none';
                        contentDiv.innerHTML = '<p>No backups found</p>';
                    }
                } catch (error) {
                    document.getElementById('backups-list').style.display = 'none';
                }
            }

            async function restoreBackup(backupId) {
                if (!confirm(`Restore from backup ${backupId}? This will overwrite current configurations.`)) return;

                try {
                    const response = await fetch(`/api/backup/restore/${backupId}`, {
                        method: 'POST',
                        headers: {
                            'Authorization': `Bearer ${accessToken}`
                        }
                    });
                    const data = await response.json();

                    alert(`Backup ${backupId} restored successfully!\\nFiles restored: ${data.files_restored}`);
                } catch (error) {
                    alert('Failed to restore backup');
                }
            }

            // Deployment workflow functions
            async function listDeploymentTemplates() {
                try {
                    const response = await fetch('/api/deployments/templates', {
                        headers: {
                            'Authorization': `Bearer ${accessToken}`
                        }
                    });
                    const data = await response.json();

                    const statusDiv = document.getElementById('templates-status');
                    const contentDiv = document.getElementById('deployments-content');
                    const outputDiv = document.getElementById('deployments-output');

                    if (data.templates && data.templates.length > 0) {
                        statusDiv.innerHTML = `<div style="color: #10b981;">✅ Loaded ${data.templates.length} templates</div>`;

                        let templatesHtml = '<h3>Deployment Templates</h3>';
                        data.templates.forEach(template => {
                            templatesHtml += `
                                <div class="script-card">
                                    <h4>${template.name}</h4>
                                    <p>${template.description}</p>
                                    <div class="meta">Type: ${template.template_type}</div>
                                    <div class="meta">Created by: ${template.created_by}</div>
                                </div>
                            `;
                        });

                        outputDiv.innerHTML = templatesHtml;
                        contentDiv.style.display = 'block';
                    } else {
                        statusDiv.innerHTML = '<div style="color: #6b7280;">No templates found</div>';
                    }
                } catch (error) {
                    document.getElementById('templates-status').innerHTML = '<div style="color: #f87171;">Error loading templates</div>';
                }
            }

            async function listDeploymentWorkflows() {
                try {
                    const response = await fetch('/api/deployments/workflows', {
                        headers: {
                            'Authorization': `Bearer ${accessToken}`
                        }
                    });
                    const data = await response.json();

                    const statusDiv = document.getElementById('workflows-status');
                    const contentDiv = document.getElementById('deployments-content');
                    const outputDiv = document.getElementById('deployments-output');

                    if (data.workflows && data.workflows.length > 0) {
                        statusDiv.innerHTML = `<div style="color: #10b981;">✅ Loaded ${data.workflows.length} workflows</div>`;

                        let workflowsHtml = '<h3>Deployment Workflows</h3>';
                        data.workflows.forEach(workflow => {
                            const statusColor = workflow.status === 'completed' ? '#10b981' :
                                              workflow.status === 'failed' ? '#f87171' : '#f59e0b';
                            workflowsHtml += `
                                <div class="script-card">
                                    <h4>${workflow.workflow_id}</h4>
                                    <p>Template: ${workflow.template_name}</p>
                                    <div class="meta">Status: <span style="color: ${statusColor};">${workflow.status}</span></div>
                                    <div class="meta">Created by: ${workflow.created_by}</div>
                                    <div class="actions">
                                        <button class="btn btn-success" onclick="executeWorkflow('${workflow.workflow_id}')">Execute</button>
                                    </div>
                                </div>
                            `;
                        });

                        outputDiv.innerHTML = workflowsHtml;
                        contentDiv.style.display = 'block';
                    } else {
                        statusDiv.innerHTML = '<div style="color: #6b7280;">No workflows found</div>';
                    }
                } catch (error) {
                    document.getElementById('workflows-status').innerHTML = '<div style="color: #f87171;">Error loading workflows</div>';
                }
            }

            async function executeWorkflow(workflowId) {
                if (!confirm(`Execute workflow ${workflowId}?`)) return;

                try {
                    const response = await fetch(`/api/deployments/workflows/${workflowId}/execute`, {
                        method: 'POST',
                        headers: {
                            'Authorization': `Bearer ${accessToken}`
                        }
                    });
                    const data = await response.json();

                    alert(`Workflow ${workflowId} executed successfully!\\nStatus: ${data.status}`);
                    // Refresh workflows list
                    setTimeout(() => listDeploymentWorkflows(), 1000);
                } catch (error) {
                    alert('Failed to execute workflow');
                }
            }

            // Update showTab function to load data for new tabs
            const originalShowTab2 = window.showTab;
            window.showTab = function(tabName) {
                originalShowTab2(tabName);

                if (tabName === 'resources') {
                    loadResourceUsage();
                } else if (tabName === 'logs') {
                    // Logs are loaded on demand
                } else if (tabName === 'backups') {
                    listBackups();
                } else if (tabName === 'deployments') {
                    // Deployment data loaded on demand
                } else if (tabName === 'operations') {
                    getClusterHealth();
                }
            };

            // Advanced operations functions
            async function listScalingPolicies() {
                try {
                    const response = await fetch('/api/cluster/scaling/policies', {
                        headers: {
                            'Authorization': `Bearer ${accessToken}`
                        }
                    });
                    const data = await response.json();

                    const statusDiv = document.getElementById('scaling-status');
                    const contentDiv = document.getElementById('operations-content');
                    const outputDiv = document.getElementById('operations-output');

                    if (data.policies && data.policies.length > 0) {
                        statusDiv.innerHTML = `<div style="color: #10b981;">✅ Loaded ${data.policies.length} scaling policies</div>`;

                        let policiesHtml = '<h3>Auto-Scaling Policies</h3>';
                        data.policies.forEach(policy => {
                            const enabled = policy.enabled ? '✅ Enabled' : '❌ Disabled';
                            policiesHtml += `
                                <div class="script-card">
                                    <h4>${policy.name}</h4>
                                    <p>Metric: ${policy.metric} | Threshold: ${policy.threshold}</p>
                                    <div class="meta">Status: ${enabled}</div>
                                    <div class="meta">Cooldown: ${policy.cooldown_period}s</div>
                                    <div class="meta">Created by: ${policy.created_by}</div>
                                </div>
                            `;
                        });

                        outputDiv.innerHTML = policiesHtml;
                        contentDiv.style.display = 'block';
                    } else {
                        statusDiv.innerHTML = '<div style="color: #6b7280;">No scaling policies configured</div>';
                    }
                } catch (error) {
                    document.getElementById('scaling-status').innerHTML = '<div style="color: #f87171;">Error loading scaling policies</div>';
                }
            }

            async function listHealthChecks() {
                try {
                    const response = await fetch('/api/cluster/health/checks', {
                        headers: {
                            'Authorization': `Bearer ${accessToken}`
                        }
                    });
                    const data = await response.json();

                    const statusDiv = document.getElementById('health-status');
                    const contentDiv = document.getElementById('operations-content');
                    const outputDiv = document.getElementById('operations-output');

                    if (data.checks && data.checks.length > 0) {
                        statusDiv.innerHTML = `<div style="color: #10b981;">✅ Loaded ${data.checks.length} health checks</div>`;

                        let checksHtml = '<h3>Health Checks</h3>';
                        data.checks.forEach(check => {
                            const statusColor = check.status === 'healthy' ? '#10b981' :
                                              check.status === 'unhealthy' ? '#f87171' : '#6b7280';
                            const enabled = check.enabled ? '✅ Enabled' : '❌ Disabled';
                            checksHtml += `
                                <div class="script-card">
                                    <h4>${check.name}</h4>
                                    <p>Type: ${check.type} | Target: ${check.target}</p>
                                    <div class="meta">Status: <span style="color: ${statusColor};">${check.status || 'unknown'}</span></div>
                                    <div class="meta">Enabled: ${enabled}</div>
                                    <div class="meta">Interval: ${check.interval}s</div>
                                    <div class="actions">
                                        <button class="btn btn-success" onclick="runHealthCheck('${check.name}')">Run Check</button>
                                    </div>
                                </div>
                            `;
                        });

                        outputDiv.innerHTML = checksHtml;
                        contentDiv.style.display = 'block';
                    } else {
                        statusDiv.innerHTML = '<div style="color: #6b7280;">No health checks configured</div>';
                    }
                } catch (error) {
                    document.getElementById('health-status').innerHTML = '<div style="color: #f87171;">Error loading health checks</div>';
                }
            }

            async function getClusterHealth() {
                try {
                    const response = await fetch('/api/cluster/health/status', {
                        headers: {
                            'Authorization': `Bearer ${accessToken}`
                        }
                    });
                    const data = await response.json();

                    const statusDiv = document.getElementById('cluster-health-status');

                    const statusColor = data.overall_status === 'healthy' ? '#10b981' :
                                      data.overall_status === 'degraded' ? '#f59e0b' : '#f87171';

                    statusDiv.innerHTML = `
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <div style="color: ${statusColor}; font-size: 1.2em; font-weight: bold;">
                                ${data.overall_status.toUpperCase()}
                            </div>
                            <div style="color: #6b7280;">
                                ${data.healthy_checks}/${data.total_checks} checks healthy
                            </div>
                        </div>
                        <div style="margin-top: 10px; font-size: 0.9em; color: #6b7280;">
                            Last updated: ${new Date(data.timestamp).toLocaleString()}
                        </div>
                    `;
                } catch (error) {
                    document.getElementById('cluster-health-status').innerHTML = '<div style="color: #f87171;">Error loading cluster health</div>';
                }
            }

            async function runHealthCheck(checkName) {
                try {
                    const response = await fetch(`/api/cluster/health/checks/${checkName}/run`, {
                        method: 'POST',
                        headers: {
                            'Authorization': `Bearer ${accessToken}`
                        }
                    });
                    const data = await response.json();

                    alert(`Health check ${checkName} completed!\\nStatus: ${data.status}`);
                    // Refresh health checks list
                    setTimeout(() => listHealthChecks(), 1000);
                } catch (error) {
                    alert('Failed to run health check');
                }
            }

            // Placeholder functions for creating new items
            function createScalingPolicy() {
                alert('Scaling policy creation UI coming soon!\\n\\nThis will allow you to:\\n- Set CPU/memory thresholds\\n- Configure scale-up/down actions\\n- Set cooldown periods');
            }

            function createHealthCheck() {
                alert('Health check creation UI coming soon!\\n\\nThis will allow you to:\\n- Configure HTTP/TCP checks\\n- Set check intervals\\n- Define retry policies');
            }

            function createDeploymentWorkflow() {
                alert('Deployment workflow creation UI coming soon!\\n\\nThis will allow you to:\\n- Select deployment templates\\n- Configure target nodes\\n- Set execution parameters');
            }

            function searchAuditLogs() {
                alert('Audit log search UI coming soon!\\n\\nThis will allow you to:\\n- Filter by user, event type, action\\n- Search by date range\\n- Export filtered results');
            }
        </script>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.get("/health")
async def health_check():
    """Basic health check endpoint"""
    return {"status": "healthy", "phase": "bootstrap", "server": "native-python"}

# Authentication endpoints
@app.post("/api/auth/login", response_model=Token)
async def login_for_access_token(form_data: LoginRequest, request: Request):
    """Login endpoint - returns JWT access token"""
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        # Log failed login attempt
        client_host, user_agent = get_client_info(request)
        log_audit_event(
            event_type="AUTHENTICATION",
            username=form_data.username,
            action="LOGIN_FAILED",
            details={"reason": "Invalid credentials"},
            ip_address=client_host,
            user_agent=user_agent
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Log successful login
    client_host, user_agent = get_client_info(request)
    log_audit_event(
        event_type="AUTHENTICATION",
        username=user.username,
        action="LOGIN_SUCCESS",
        details={"role": user.role},
        ip_address=client_host,
        user_agent=user_agent
    )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/auth/logout")
async def logout():
    """Logout endpoint - client should discard token"""
    return {"message": "Successfully logged out"}

@app.get("/api/auth/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    """Get current user information"""
    return current_user

@app.get("/api/auth/users")
async def get_users(current_user: User = Depends(get_current_active_user)):
    """Get all users (admin only)"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    users = []
    for username, user_data in fake_users_db.items():
        users.append({
            "username": user_data["username"],
            "full_name": user_data["full_name"],
            "email": user_data["email"],
            "role": user_data["role"],
            "disabled": user_data["disabled"]
        })
    return {"users": users}

@app.get("/api/info")
async def api_info():
    """API information endpoint"""
    return {
        "name": "Script Executor Bootstrap",
        "version": "0.1.0",
        "phase": "script_execution",
        "capabilities": [
            "web_server",
            "health_check",
            "api_endpoints",
            "script_discovery",
            "script_execution"
        ],
        "next_phase": "websocket_integration"
    }

@app.get("/api/scripts")
async def get_scripts():
    """Get all discovered scripts organized by category"""
    return discover_scripts()

@app.get("/api/scripts/stats")
async def get_script_stats():
    """Get statistics about discovered scripts"""
    all_scripts = discover_scripts()
    
    stats = {
        "total_scripts": all_scripts["total_scripts"],
        "categories_count": len(all_scripts["categories"]),
        "categories": {}
    }
    
    for cat, scripts in all_scripts["categories"].items():
        executable_count = sum(1 for s in scripts if s["executable"])
        total_size = sum(s["size"] for s in scripts)
        
        stats["categories"][cat] = {
            "total_scripts": len(scripts),
            "executable_scripts": executable_count,
            "total_size_bytes": total_size
        }
    
    return stats

@app.get("/api/scripts/{category}")
async def get_scripts_by_category(category: str):
    """Get scripts for a specific category"""
    all_scripts = discover_scripts()
    if category in all_scripts["categories"]:
        return {
            "category": category,
            "scripts": all_scripts["categories"][category],
            "count": len(all_scripts["categories"][category])
        }
    return {"error": f"Category '{category}' not found", "available_categories": list(all_scripts["categories"].keys())}

@app.post("/api/scripts/execute")
async def execute_script_endpoint(request: Dict[str, Any], req: Request, current_user: User = Depends(get_current_active_user)):
    """
    Execute a script by path or name.
    Request body: {"script_path": "/path/to/script.sh"} or {"script_name": "script.sh", "category": "agent"}
    """
    script_path = request.get("script_path")
    script_name = request.get("script_name")
    category = request.get("category")
    timeout = request.get("timeout", 30)

    if script_path:
        # Direct path execution
        full_path = os.path.join("/home/sanjay/containers/kubernetes", script_path.lstrip("/"))
    elif script_name and category:
        # Find script by name and category
        all_scripts = discover_scripts()
        if category in all_scripts["categories"]:
            for script in all_scripts["categories"][category]:
                if script["name"] == script_name:
                    full_path = script["full_path"]
                    break
            else:
                return {"error": f"Script '{script_name}' not found in category '{category}'"}
        else:
            return {"error": f"Category '{category}' not found"}
    else:
        return {"error": "Must provide either 'script_path' or both 'script_name' and 'category'"}

    # Log script execution attempt
    client_host, user_agent = get_client_info(req)
    log_audit_event(
        event_type="SCRIPT_EXECUTION",
        username=current_user.username,
        action="EXECUTE_SCRIPT",
        resource=full_path,
        details={
            "script_name": script_name,
            "category": category,
            "timeout": timeout,
            "user_role": current_user.role
        },
        ip_address=client_host,
        user_agent=user_agent
    )

    # Execute the script
    result = await execute_script(full_path, timeout)
    return result

@app.get("/api/scripts/execute/test")
async def test_script_execution():
    """
    Test script execution with a safe command (echo hello).
    This is for testing the execution framework without running actual scripts.
    """
    try:
        # Create a simple test script
        test_script = "/tmp/test_script.sh"
        with open(test_script, 'w') as f:
            f.write("#!/bin/bash\necho 'Hello from test script!'\necho 'Current date: $(date)'\necho 'Working directory: $(pwd)'\n")
        os.chmod(test_script, 0o755)
        
        # Execute the test script
        result = await execute_script(test_script, timeout=10)
        
        # Clean up
        os.remove(test_script)
        
        return {
            "test_result": "success",
            "message": "Script execution framework is working!",
            "execution_result": result
        }
        
    except Exception as e:
        return {
            "test_result": "failed",
            "error": str(e)
        }

@app.websocket("/ws/execute")
async def websocket_execute(websocket: WebSocket):
    """
    WebSocket endpoint for real-time script execution.
    Streams output as the script runs.
    """
    await websocket.accept()
    
    try:
        # Wait for execution request
        data = await websocket.receive_json()
        script_path = data.get("script_path")
        timeout = data.get("timeout", 30)
        
        if not script_path:
            await websocket.send_json({
                "type": "error",
                "message": "No script_path provided"
            })
            return
        
        # Validate script exists and is executable
        if not os.path.exists(script_path):
            await websocket.send_json({
                "type": "error",
                "message": f"Script not found: {script_path}"
            })
            return
        
        if not os.access(script_path, os.X_OK):
            await websocket.send_json({
                "type": "error",
                "message": f"Script is not executable: {script_path}"
            })
            return
        
        # Send start message
        await websocket.send_json({
            "type": "start",
            "message": f"Starting execution of {script_path}",
            "timestamp": datetime.now().isoformat()
        })
        
        # Execute script with real-time output streaming
        start_time = datetime.now()
        
        try:
            process = await asyncio.create_subprocess_exec(
                script_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=os.path.dirname(script_path)
            )
            
            # Stream stdout in real-time
            async def stream_output(stream, stream_type):
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    
                    line_text = line.decode('utf-8', errors='replace').rstrip()
                    if line_text:  # Only send non-empty lines
                        await websocket.send_json({
                            "type": stream_type,
                            "data": line_text,
                            "timestamp": datetime.now().isoformat()
                        })
            
            # Start streaming tasks
            stdout_task = asyncio.create_task(stream_output(process.stdout, "stdout"))
            stderr_task = asyncio.create_task(stream_output(process.stderr, "stderr"))
            
            # Wait for process to complete or timeout
            try:
                return_code = await asyncio.wait_for(process.wait(), timeout=timeout)
                execution_time = (datetime.now() - start_time).total_seconds()
                
                # Wait for output streaming to complete
                await asyncio.gather(stdout_task, stderr_task)
                
                # Send completion message
                await websocket.send_json({
                    "type": "complete",
                    "return_code": return_code,
                    "execution_time": execution_time,
                    "timestamp": datetime.now().isoformat()
                })
                
            except asyncio.TimeoutError:
                process.kill()
                await websocket.send_json({
                    "type": "error",
                    "message": f"Script execution timed out after {timeout} seconds"
                })
                
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            await websocket.send_json({
                "type": "error",
                "message": f"Execution failed: {str(e)}",
                "execution_time": execution_time
            })
            
    except WebSocketDisconnect:
        print("WebSocket client disconnected")
    except Exception as e:
        try:
            await websocket.send_json({
                "type": "error",
                "message": f"WebSocket error: {str(e)}"
            })
        except:
            pass  # Client may have disconnected

# HTTPS Startup Logic
if __name__ == "__main__":
    import uvicorn
    import sys

    # Generate SSL certificates if HTTPS is enabled
    https_enabled = os.getenv("ENABLE_HTTPS", "false").lower() == "true"

    if https_enabled:
        print("🔒 Generating SSL certificates for HTTPS...")
        try:
            generate_ssl_certificates()
            print("✅ SSL certificates generated successfully")
            print(f"📄 Certificate: {SSL_CERT_FILE}")
            print(f"🔑 Private Key: {SSL_KEY_FILE}")

            # Start HTTPS server
            uvicorn.run(
                "bootstrap_app:app",
                host="0.0.0.0",
                port=int(os.getenv("HTTPS_PORT", "8443")),
                ssl_certfile=SSL_CERT_FILE,
                ssl_keyfile=SSL_KEY_FILE,
                reload=False
            )
        except Exception as e:
            print(f"❌ Failed to generate SSL certificates: {e}")
            print("🌐 Starting HTTP server instead...")
            https_enabled = False

    if not https_enabled:
        # Start HTTP server
        port = int(os.getenv("HTTP_PORT", "8000"))
        print(f"🌐 Starting HTTP server on port {port}...")
        uvicorn.run(
            "bootstrap_app:app",
            host="0.0.0.0",
            port=port,
            reload=False
        )

