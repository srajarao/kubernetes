# AI Environment Documentation

## Hardware Inventory

| Name    | Type                    | Hostname/IP(s)           |
|---------|-------------------------|--------------------------|
| nano    | Jetson (non Orin)       | 10.1.10.181              |
| agx     | Jetson AGX Orin         | 10.1.10.244              |
| tower   | Ubuntu Desktop (Server) | 10.1.10.150              |
| spark1  | NVIDIA DGX Spark        | 10.1.10.201 / 192.168.1.201 |
| spark2  | NVIDIA DGX Spark        | 10.1.10.202 / 198.168.1.202 |

---

## Directory Structure Overview

- `agent/` - Contains subfolders for each node (agx, nano, spark1, spark2) with deployment scripts, configs, and apps.
- `archive/` - Backup scripts, old configs, and health checks.
- `docs/` - Documentation and project plans.
- `images/` - Built images and configs for containerization.
- `rag/` - Reference and deployment files for RAG (Retrieval-Augmented Generation) workflows.
- `scripts/` - Utility scripts for environment setup, monitoring, and validation.
- `server/` - Server-side deployment scripts, configs, and Docker requirements.

---

## Main Components & Services

- **FastAPI**: REST API services (see `agent/agx/fastapi-deployment-agx.yaml`, `setup_fastapi_agx.sh`)
- **Jupyter**: Notebooks for experimentation (see `agent/agx/start-jupyter.sh`, `archive/cluster-demo.ipynb`)
- **Spark**: Distributed compute nodes (see `agent/spark1/`, `agent/spark2/`)
- **K3s/Kubernetes**: Lightweight Kubernetes for orchestration (see `k3s-config.sh`, `server/k3s-server.sh`)
- **Postgres/PGAdmin**: Database and admin UI (see `server/postgres-db-deployment.yaml`)

---

## Setup & Usage

1. **K3s Server Setup**
   - Run `server/k3s-server.sh` on the tower node to initialize the Kubernetes server.
2. **Agent Node Setup**
   - Use scripts in `agent/<node>/` (e.g., `k3s-agx-agent-setup.sh`, `k3s-nano.sh`) to join nodes to the cluster.
3. **Deploy FastAPI/Jupyter**
   - Use deployment YAMLs and setup scripts in `agent/agx/` and `server/`.
4. **Database Setup**
   - Deploy Postgres and PGAdmin using YAMLs in `server/`.
5. **Monitoring & Validation**
   - Use scripts in `scripts/` and `archive/` for health checks and validation.

---

## Key Configuration Files

- `.env` and `*.env` files for environment variables
- `requirements.*.txt` for Python dependencies
- `dockerfile.*` for container builds
- `*.yaml` for Kubernetes deployments

---

## Notes

- Refer to `README.md` and `PROJECT_PLAN.md` in each directory for more details.
- Update this documentation as the environment evolves.
