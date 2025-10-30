# 🚀 Network Migration Timeline: 10.1.10.x → 192.168.1.x
## ER605 Firewall Integration & VPN Setup
## Duration: 5:00 PM - 2:00 AM (9 hours)

---

## 📋 **PHASE 1: PREPARATION (5:00 PM - 6:00 PM)**

### 5:00 PM - 5:30 PM: Final Preparation
- [ ] **Backup current configurations**
  ```bash
  cd /home/sanjay/containers/kubernetes
  git status  # Ensure clean working directory
  git tag "pre-network-migration-$(date +%Y%m%d_%H%M)"
  ./backup_home.sh  # Full backup of current setup
  ```

- [ ] **Document current network state**
  ```bash
  # Record current IPs and connectivity
  kubectl get nodes -o wide
  kubectl get pods -o wide -A
  kubectl get services -o wide -A
  ```

- [ ] **Test current cluster functionality**
  - Verify FastAPI services are accessible
  - Test backup scripts
  - Confirm NFS mounts working

### 5:30 PM - 6:00 PM: ER605 Firewall Setup
- [ ] **Unbox and connect ER605**
  - Connect ER605 between switch and current router
  - Power on and access web interface (192.168.0.1 or similar)

- [ ] **Initial ER605 configuration**
  - Set admin password
  - Update firmware if needed
  - Configure LAN interface: `192.168.1.1/24`

---

## 📋 **PHASE 2: NETWORK RECONFIGURATION (6:00 PM - 8:00 PM)**

### 6:00 PM - 6:30 PM: Update Tower (Server Node)
- [ ] **Change Tower static IP**
  ```bash
  # Edit /etc/netplan/01-netcfg.yaml
  sudo netplan apply
  # IP: 192.168.1.150 → 192.168.1.150
  # Gateway: 192.168.1.1 → 192.168.1.1
  ```

- [ ] **Update K3s server configuration**
  ```bash
  sudo systemctl stop k3s
  # Update /etc/rancher/k3s/k3s.yaml if needed
  ```

- [ ] **Reconfigure NFS exports**
  ```bash
  sudo ./scripts/update-nfs-exports.sh
  sudo exportfs -ra
  ```

### 6:30 PM - 7:00 PM: Update AGX Node
- [ ] **SSH to AGX and change IP**
  ```bash
  ssh sanjay@192.168.1.244  # Will lose connection
  # On AGX: Update netplan, change to 192.168.1.244
  ```

- [ ] **Update AGX K3s agent**
  ```bash
  # On AGX: Update k3s-agent service configuration
  ```

### 7:00 PM - 7:30 PM: Update Nano Node
- [ ] **SSH to Nano and change IP**
  ```bash
  ssh sanjay@192.168.1.181
  # On Nano: Update to 192.168.1.181
  ```

- [ ] **Update Nano K3s agent**

### 7:30 PM - 8:00 PM: Update Spark Nodes
- [ ] **Update Spark1 (192.168.1.201 → 192.168.1.201)**
- [ ] **Update Spark2 (192.168.1.202 → 192.168.1.202)**

---

## 📋 **PHASE 3: CONFIGURATION UPDATES (8:00 PM - 9:30 PM)**

### 8:00 PM - 8:30 PM: Apply IP Changes to Codebase
- [x] **COMPLETED** All K3s setup scripts pre-verified clean of old IPs:
  - `server/k3s-server.sh` ✅
  - `agent/*/k3s-*.sh` ✅ 
  - All deployment YAML files ✅
- [ ] **Run IP update script** (if needed)
  ```bash
  cd /home/sanjay/containers/kubernetes
  ./update_ips.sh "10.1.10" "192.168.1"
  git diff  # Review changes
  git add .
  git commit -m "Network migration: 10.1.10.x → 192.168.1.x"
  ```

- [ ] **Sync changes to all nodes**
  ```bash
  # Push to git and pull on all nodes
  git push origin main
  ```

### 8:30 PM - 9:00 PM: Update Kubernetes Configurations
- [ ] **Restart K3s on all nodes**
  ```bash
  # On each node:
  sudo systemctl restart k3s-agent  # (or k3s for server)
  ```

- [ ] **Update deployments**
  ```bash
  kubectl apply -f agent/*/fastapi-deployment-*.yaml
  kubectl apply -f server/fastapi-deployment-full.yaml
  ```

### 9:00 PM - 9:30 PM: Update Supporting Services
- [ ] **Update PostgreSQL and pgAdmin**
  ```bash
  kubectl apply -f server/postgres-db-deployment.yaml
  kubectl apply -f server/pgadmin-deployment.yaml
  ```

- [ ] **Update Docker registry**
  ```bash
  kubectl apply -f server/registry-deployment.yaml
  ```

---

## 📋 **PHASE 4: FIREWALL & VPN CONFIGURATION (9:30 PM - 11:00 PM)**

### 9:30 PM - 10:00 PM: ER605 Firewall Configuration
- [ ] **Set up port forwarding**
  - Port 1194 (UDP) → VPN server
  - Port 80/443 → Web services if needed
  - Port 30002 → FastAPI services

- [ ] **Configure firewall rules**
  - Allow internal traffic
  - Block external access except VPN
  - Set up NAT rules

### 10:00 PM - 10:30 PM: OpenVPN Server Setup
- [ ] **Install OpenVPN on ER605**
  - Use ER605's built-in OpenVPN server
  - Configure certificates
  - Set up user accounts

- [ ] **Generate client configurations**
  - Create .ovpn files for remote access
  - Test VPN connectivity

### 10:30 PM - 11:00 PM: Security Hardening
- [ ] **Update firewall policies**
  - Enable intrusion detection
  - Set up access time restrictions
  - Configure logging

---

## 📋 **PHASE 5: TESTING & VALIDATION (11:00 PM - 1:00 AM)**

### 11:00 PM - 11:30 PM: Cluster Connectivity Tests
- [ ] **Verify node connectivity**
  ```bash
  kubectl get nodes
  kubectl get pods -A
  ```

- [ ] **Test FastAPI services**
  ```bash
  curl http://192.168.1.181:30002/health
  curl http://192.168.1.244:30002/health
  curl http://192.168.1.201:30002/health
  curl http://192.168.1.202:30002/health
  ```

### 11:30 PM - 12:00 AM: External Access Testing
- [ ] **Test VPN connection**
  - Connect from external network
  - Verify access to cluster services
  - Test port forwarding

- [ ] **Update external references**
  - Update any external DNS if applicable
  - Test remote monitoring tools

### 12:00 AM - 12:30 AM: Backup System Validation
- [ ] **Test backup scripts**
  ```bash
  ./backup_home.sh  # On each node
  ```

- [ ] **Verify NFS mounts**
  ```bash
  df -h | grep vmstore
  ```

### 12:30 AM - 1:00 AM: Performance & Monitoring
- [ ] **Monitor cluster health**
  ```bash
  kubectl top nodes
  kubectl top pods
  ```

- [ ] **Test GPU workloads**
  - Run GPU-intensive tasks
  - Monitor NVIDIA GPU usage

---

## 📋 **PHASE 6: CLEANUP & DOCUMENTATION (1:00 AM - 2:00 AM)**

### 1:00 AM - 1:30 AM: Final Validation
- [ ] **Run comprehensive tests**
  ```bash
  ./scripts/validate-k3s-agent.sh  # On each node
  ```

- [ ] **Update documentation**
  - Update IP addresses in README.md
  - Document new network topology
  - Update firewall rules documentation

### 1:30 AM - 2:00 AM: Backup & Sign-off
- [ ] **Final backup**
  ```bash
  ./backup_home.sh
  git add .
  git commit -m "Post-migration: Final updates and documentation"
  git push origin main
  ```

- [ ] **Create migration report**
  - Document any issues encountered
  - Note performance improvements
  - Update runbooks with new IPs

---

## 🚨 **EMERGENCY ROLLBACK PLAN**

If critical issues arise:

1. **Immediate rollback**: Change all devices back to 10.1.10.x IPs
2. **Git rollback**: `git reset --hard HEAD~1`
3. **K3s restart**: `sudo systemctl restart k3s*`
4. **Remove ER605**: Connect devices directly to original router

## 📞 **CRITICAL CHECKPOINTS**

- [ ] **6:00 PM**: All devices reachable on new IPs
- [ ] **8:00 PM**: Codebase updated and committed
- [ ] **9:00 PM**: Kubernetes services running
- [ ] **10:00 PM**: VPN server operational
- [ ] **11:00 PM**: External access confirmed
- [ ] **1:00 AM**: All tests passing

## 🛠️ **REQUIRED TOOLS & ACCESS**

- [ ] ER605 firewall unit
- [ ] SSH access to all nodes
- [ ] Admin access to ER605 web interface
- [ ] Git repository access
- [ ] kubectl access
- [ ] OpenVPN client for testing

---

**Total Duration: 9 hours | Critical Path: Network reconfiguration → Code updates → Service restart**