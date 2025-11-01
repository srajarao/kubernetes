# 🚀 Network Migration Checklist: 10.1.10.x → 192.168.1.x
**Date:** October 27, 2025 (Migration Completed: October 28, 2025)
**Time Window:** 5:00 PM - 2:00 AM (9 hours)
**Goal:** Migrate K3s cluster from 10.1.10.x to 192.168.1.x subnet with ER605 firewall
**Status:** ✅ MIGRATION COMPLETED - Infrastructure updated, IPs migrated, certificates regenerated, k3s server reinstalled, PostgreSQL & pgAdmin deployed, Nano & AGX agents rejoined with FastAPI

## 📋 Pre-Migration Preparation (30 minutes - 5:00 PM - 5:30 PM)

### ✅ Prerequisites Checklist
- [x] ER605 firewall purchased and ready
- [x] **Collect MAC addresses for ER605 DHCP reservations:**
  - ER605 device: [get from device label/sticker]
  - Nano: `ssh sanjay@192.168.1.181 "ip link show | grep ether"`
  - AGX: `ssh sanjay@192.168.1.244 "ip link show | grep ether"`
  - Spark1: `ssh sanjay@192.168.1.201 "ip link show | grep ether"`
  - Spark2: `ssh sanjay@192.168.1.202 "ip link show | grep ether"`
- [x] Backup current cluster state: `kubectl get all -A > cluster-backup-pre-migration.yaml`
- [x] Git repository clean: `git status` should show no uncommitted changes
- [x] All cluster nodes accessible via current IPs (now 192.168.1.x)
- [x] Current cluster services verified working:
  - [x] FastAPI services on all nodes
  - [x] PostgreSQL/pgAdmin accessible
  - [x] NFS storage mounted
  - [x] GPU workloads functioning

### ✅ Tools & Scripts Ready
- [x] IP update script created: `update_ips.sh`
- [x] Migration checklist printed/documented
- [x] Emergency rollback plan documented
- [x] Contact info for support if needed

### ✅ Script Pre-Testing (30 minutes)
- [x] **Test IP update script:** `./update_ips.sh --dry-run "10.1.10" "192.168.1" | head -20`
- [x] **Test NFS update scripts:** `./scripts/update-nfs-exports.sh --dry-run && ./scripts/update-nfs-fstab.sh --dry-run`
- [x] **Verify script backups work:** Test backup and restore procedures
- [x] **Validate all scripts have correct permissions:** `ls -la update_ips.sh scripts/*.sh`

### ✅ External Dependencies Check
- [x] **Check for external firewall rules:** Any corporate firewalls allowing access to 10.1.10.x IPs?
- [x] **VPN configurations:** Any existing VPNs or remote access tools using old IPs?
- [x] **Monitoring systems:** External monitoring pointing to 10.1.10.x addresses?
- [x] **DNS records:** Any external DNS pointing to cluster IPs?
- [x] **Backup destinations:** Off-site backups using 10.1.10.x addresses?

---

## 🕘 Phase 1: Firewall Setup (75 minutes - 5:30 PM - 6:45 PM)

### Comcast Gateway DHCP Reservations Update (15 minutes - 5:30 PM - 5:45 PM)
- [x] **5:35 PM** Access Comcast gateway admin portal at http://192.168.1.1
- [x] **5:40 PM** Navigate to DHCP reservations section
- [x] **5:45 PM** Update MAC address reservation for ER605 device:
  - ER605 (MAC: [get ER605 MAC address]): 10.1.10.2
- [x] **5:50 PM** Save DHCP reservation changes
- [x] **5:55 PM** Verify ER605 reservation is active (192.168.1.1 and 10.1.10.2 only)

### ER605 Firewall Configuration (35 minutes - 5:55 PM - 6:30 PM)
- [x] **6:00 PM** Connect ER605 between switch and Comcast gateway
- [x] **6:05 PM** Configure ER605 WAN interface with static IP 10.1.10.2
- [x] **6:10 PM** Set up 192.168.1.0/24 subnet on LAN interface
- [x] **6:15 PM** Configure DHCP server for 192.168.1.100-192.168.1.199 range
- [x] **6:20 PM** Set up DHCP reservations for cluster nodes:
  - Tower (MAC: [collected earlier]): 192.168.1.150
  - Nano (MAC: [collected earlier]): 192.168.1.181
  - AGX (MAC: [collected earlier]): 192.168.1.244
  - Spark1 (MAC: [collected earlier]): 192.168.1.201
  - Spark2 (MAC: [collected earlier]): 192.168.1.202
- [x] **6:25 PM** Set up port forwarding: External port 1194 → ER605 port 1194
- [x] **6:30 PM** Configure firewall rules for cluster communication
- [x] **6:35 PM** Test internet connectivity through firewall

### USW Flex XG Switch Configuration (10 minutes - 6:35 PM - 6:45 PM)
- [x] **6:40 PM** Connect USW Flex XG to ER605 LAN port (not WAN port)
- [x] **6:42 PM** Switch should automatically get IP from ER605 DHCP (192.168.1.x range)
- [x] **6:44 PM** Access switch web interface using assigned IP
- [x] **6:45 PM** Verify switch can reach ER605 gateway at 192.168.1.1

**⏰ Checkpoint 1:** Firewall and switch configured, internet accessible

---

## 🕙 Phase 2: Node IP Migration (100 minutes - 6:45 PM - 8:25 PM)

### Network Preparation (10 minutes - 6:45 PM - 6:55 PM)
- [x] **6:45 PM** Verify ER605 DHCP server is active and reservations are set
- [x] **6:50 PM** Confirm all nodes can reach ER605 at 10.1.10.2
- [x] **6:55 PM** Backup current network configurations on all nodes

### Tower Server Migration (15 minutes - 6:55 PM - 7:10 PM)
- [x] **7:00 PM** Update Tower netplan to use DHCP:
  ```bash
  sudo nano /etc/netplan/01-netcfg.yaml
  # Change from static IP to DHCP
  network:
    ethernets:
      eno1:  # or your interface name
        dhcp4: true
    version: 2
  ```
- [x] **7:05 PM** Apply netplan changes: `sudo netplan apply`
- [x] **7:10 PM** Reboot Tower: `sudo reboot`

### Nano Migration (15 minutes - 7:10 PM - 7:25 PM)
- [x] **7:15 PM** SSH to Nano (may need to use old IP temporarily)
- [x] **7:20 PM** Update Nano netplan to DHCP and apply
- [x] **7:25 PM** Reboot Nano

### AGX Migration (15 minutes - 7:25 PM - 7:40 PM)
- [x] **7:30 PM** SSH to AGX (may need to use old IP temporarily)
- [x] **7:35 PM** Update AGX netplan to DHCP and apply
- [x] **7:40 PM** Reboot AGX

### Spark Nodes Migration (30 minutes - 7:40 PM - 8:10 PM)
- [x] **7:45 PM** Update Spark1 netplan to DHCP and reboot
- [x] **7:55 PM** Update Spark2 netplan to DHCP and reboot
- [x] **8:05 PM** Wait for all nodes to come back online with new IPs

### Connectivity Verification (15 minutes - 8:10 PM - 8:25 PM)
- [x] **8:15 PM** Verify all nodes have correct new IPs:
  - Tower: 192.168.1.150
  - Nano: 192.168.1.181
  - AGX: 192.168.1.244
  - Spark1: 192.168.1.201
  - Spark2: 192.168.1.202
- [x] **8:20 PM** Test inter-node connectivity: `ping` between all nodes
- [x] **8:25 PM** Update local /etc/hosts file with new IPs

**⏰ Checkpoint 2:** All nodes migrated to new subnet, basic connectivity verified

---

## 🕚 Phase 2.5: Hostname Resolution Updates (30 minutes - 8:25 PM - 8:55 PM)

### Update /etc/hosts Files (30 minutes - 8:25 PM - 8:55 PM)
- [x] **8:30 PM** Update Tower /etc/hosts:
  ```bash
  sudo sed -i 's/10\.1\.10\.150/192.168.1.150/g' /etc/hosts
  sudo sed -i 's/10\.1\.10\.181/192.168.1.181/g' /etc/hosts
  sudo sed -i 's/10\.1\.10\.244/192.168.1.244/g' /etc/hosts
  sudo sed -i 's/10\.1\.10\.201/192.168.1.201/g' /etc/hosts
  sudo sed -i 's/10\.1\.10\.202/192.168.1.202/g' /etc/hosts
  ```
- [x] **8:35 PM** Update Nano /etc/hosts:
  ```bash
  ssh sanjay@192.168.1.181 "sudo sed -i 's/10\.1\.10\.150/192.168.1.150/g' /etc/hosts"
  ssh sanjay@192.168.1.181 "sudo sed -i 's/10\.1\.10\.181/192.168.1.181/g' /etc/hosts"
  ssh sanjay@192.168.1.181 "sudo sed -i 's/10\.1\.10\.244/192.168.1.244/g' /etc/hosts"
  ssh sanjay@192.168.1.181 "sudo sed -i 's/10\.1\.10\.201/192.168.1.201/g' /etc/hosts"
  ssh sanjay@192.168.1.181 "sudo sed -i 's/10\.1\.10\.202/192.168.1.202/g' /etc/hosts"
  ```
- [x] **8:40 PM** Update AGX /etc/hosts:
  ```bash
  ssh sanjay@192.168.1.244 "sudo sed -i 's/10\.1\.10\.150/192.168.1.150/g' /etc/hosts"
  ssh sanjay@192.168.1.244 "sudo sed -i 's/10\.1\.10\.181/192.168.1.181/g' /etc/hosts"
  ssh sanjay@192.168.1.244 "sudo sed -i 's/10\.1\.10\.244/192.168.1.244/g' /etc/hosts"
  ssh sanjay@192.168.1.244 "sudo sed -i 's/10\.1\.10\.201/192.168.1.201/g' /etc/hosts"
  ssh sanjay@192.168.1.244 "sudo sed -i 's/10\.1\.10\.202/192.168.1.202/g' /etc/hosts"
  ```
- [x] **8:45 PM** Update Spark1 /etc/hosts:
  ```bash
  ssh sanjay@192.168.1.201 "sudo sed -i 's/10\.1\.10\.150/192.168.1.150/g' /etc/hosts"
  ssh sanjay@192.168.1.201 "sudo sed -i 's/10\.1\.10\.181/192.168.1.181/g' /etc/hosts"
  ssh sanjay@192.168.1.201 "sudo sed -i 's/10\.1\.10\.244/192.168.1.244/g' /etc/hosts"
  ssh sanjay@192.168.1.201 "sudo sed -i 's/10\.1\.10\.201/192.168.1.201/g' /etc/hosts"
  ssh sanjay@192.168.1.201 "sudo sed -i 's/10\.1\.10\.202/192.168.1.202/g' /etc/hosts"
  ```
- [x] **8:50 PM** Update Spark2 /etc/hosts:
  ```bash
  ssh sanjay@192.168.1.202 "sudo sed -i 's/10\.1\.10\.150/192.168.1.150/g' /etc/hosts"
  ssh sanjay@192.168.1.202 "sudo sed -i 's/10\.1\.10\.181/192.168.1.181/g' /etc/hosts"
  ssh sanjay@192.168.1.202 "sudo sed -i 's/10\.1\.10\.244/192.168.1.244/g' /etc/hosts"
  ssh sanjay@192.168.1.202 "sudo sed -i 's/10\.1\.10\.201/192.168.1.201/g' /etc/hosts"
  ssh sanjay@192.168.1.202 "sudo sed -i 's/10\.1\.10\.202/192.168.1.202/g' /etc/hosts"
  ```
- [x] **8:55 PM** Verify hostname resolution on all nodes:
  ```bash
  # From Tower, test all nodes
  ping tower  # should resolve to 192.168.1.150
  ping nano   # should resolve to 192.168.1.181
  ping agx    # should resolve to 192.168.1.244
  ping spark1 # should resolve to 192.168.1.201
  ping spark2 # should resolve to 192.168.1.202
  ```

**⏰ Checkpoint 2.5:** Hostname resolution working on all nodes

---

**⏰ Checkpoint 2:** All nodes reachable on new IPs, basic connectivity verified

### Update /etc/hosts Files on All Nodes
**Required /etc/hosts entries for all nodes:**
```
192.168.1.150   tower
192.168.1.181   nano
192.168.1.244   agx
192.168.1.201   spark1
192.168.1.202   spark2
```

- [ ] **8:30 PM** Update Tower /etc/hosts:
  ```bash
  sudo sed -i 's/10\.1\.10\.150/192.168.1.150/g' /etc/hosts
  sudo sed -i 's/10\.1\.10\.181/192.168.1.181/g' /etc/hosts
  sudo sed -i 's/10\.1\.10\.244/192.168.1.244/g' /etc/hosts
  sudo sed -i 's/10\.1\.10\.201/192.168.1.201/g' /etc/hosts
  sudo sed -i 's/10\.1\.10\.202/192.168.1.202/g' /etc/hosts
  ```

- [ ] **8:35 PM** Update Nano /etc/hosts:
  ```bash
  ssh sanjay@192.168.1.181 "sudo sed -i 's/10\.1\.10\.150/192.168.1.150/g' /etc/hosts"
  ssh sanjay@192.168.1.181 "sudo sed -i 's/10\.1\.10\.181/192.168.1.181/g' /etc/hosts"
  ssh sanjay@192.168.1.181 "sudo sed -i 's/10\.1\.10\.244/192.168.1.244/g' /etc/hosts"
  ssh sanjay@192.168.1.181 "sudo sed -i 's/10\.1\.10\.201/192.168.1.201/g' /etc/hosts"
  ssh sanjay@192.168.1.181 "sudo sed -i 's/10\.1\.10\.202/192.168.1.202/g' /etc/hosts"
  ```

- [ ] **8:40 PM** Update AGX /etc/hosts:
  ```bash
  ssh sanjay@192.168.1.244 "sudo sed -i 's/10\.1\.10\.150/192.168.1.150/g' /etc/hosts"
  ssh sanjay@192.168.1.244 "sudo sed -i 's/10\.1\.10\.181/192.168.1.181/g' /etc/hosts"
  ssh sanjay@192.168.1.244 "sudo sed -i 's/10\.1\.10\.244/192.168.1.244/g' /etc/hosts"
  ssh sanjay@192.168.1.244 "sudo sed -i 's/10\.1\.10\.201/192.168.1.201/g' /etc/hosts"
  ssh sanjay@192.168.1.244 "sudo sed -i 's/10\.1\.10\.202/192.168.1.202/g' /etc/hosts"
  ```

- [ ] **8:45 PM** Update Spark1 /etc/hosts:
  ```bash
  ssh sanjay@192.168.1.201 "sudo sed -i 's/10\.1\.10\.150/192.168.1.150/g' /etc/hosts"
  ssh sanjay@192.168.1.201 "sudo sed -i 's/10\.1\.10\.181/192.168.1.181/g' /etc/hosts"
  ssh sanjay@192.168.1.201 "sudo sed -i 's/10\.1\.10\.244/192.168.1.244/g' /etc/hosts"
  ssh sanjay@192.168.1.201 "sudo sed -i 's/10\.1\.10\.201/192.168.1.201/g' /etc/hosts"
  ssh sanjay@192.168.1.201 "sudo sed -i 's/10\.1\.10\.202/192.168.1.202/g' /etc/hosts"
  ```

- [ ] **8:50 PM** Update Spark2 /etc/hosts:
  ```bash
  ssh sanjay@192.168.1.202 "sudo sed -i 's/10\.1\.10\.150/192.168.1.150/g' /etc/hosts"
  ssh sanjay@192.168.1.202 "sudo sed -i 's/10\.1\.10\.181/192.168.1.181/g' /etc/hosts"
  ssh sanjay@192.168.1.202 "sudo sed -i 's/10\.1\.10\.244/192.168.1.244/g' /etc/hosts"
  ssh sanjay@192.168.1.202 "sudo sed -i 's/10\.1\.10\.201/192.168.1.201/g' /etc/hosts"
  ssh sanjay@192.168.1.202 "sudo sed -i 's/10\.1\.10\.202/192.168.1.202/g' /etc/hosts"
  ```

- [ ] **8:55 PM** Verify hostname resolution on all nodes:
  ```bash
  # Test from Tower
  ping -c 1 nano && ping -c 1 agx && ping -c 1 spark1 && ping -c 1 spark2
  ```

**⏰ Checkpoint 2.5:** Hostname resolution working on all nodes

---

## 🕚 Phase 3: Configuration Updates (70 minutes - 8:55 PM - 10:05 PM)

### Repository Updates (20 minutes - 8:55 PM - 9:15 PM)
- [x] **9:00 PM** Run IP update script: `./update_ips.sh "10.1.10" "192.168.1"`
- [x] **9:05 PM** Review changes: `git diff`
- [x] **9:10 PM** Commit changes: `git add . && git commit -m "Network migration: 10.1.10.x → 192.168.1.x"`

### Manual Configuration Updates (40 minutes - 9:15 PM - 9:55 PM)
- [x] **9:20 PM** Update subnet references in config files:
  - [x] `agent/spark2/app/config/spark2-config.env`: SPARK2_SUBNET
  - [x] `agent/agx/agx-config.env`: AGX_SUBNET
  - [x] Network validation scripts
### NFS Server & Client Updates (25 minutes - 9:55 PM - 10:20 PM)

**NFS Server (Tower) - 10 minutes:**
- [x] **10:00 PM** Stop NFS services on Tower:
  ```bash
  sudo systemctl stop nfs-server
  sudo systemctl stop nfs-kernel-server
  ```
- [x] **10:02 PM** Update NFS exports configuration:
  ```bash
  sudo ./scripts/update-nfs-exports.sh
  cat /etc/exports  # Verify new IPs: 192.168.1.150, 192.168.1.181, 192.168.1.244, etc.
  ```
- [x] **10:05 PM** Export new NFS shares: `sudo exportfs -ra`
- [x] **10:07 PM** Restart NFS server: `sudo systemctl start nfs-server`

**NFS Clients (All Nodes) - 15 minutes:**
- [x] **10:10 PM** Update Nano NFS mounts:
  ```bash
  ssh sanjay@192.168.1.181 "sudo systemctl stop nfs-client.target"
  ssh sanjay@192.168.1.181 "sudo ./scripts/update-nfs-fstab.sh"
  ssh sanjay@192.168.1.181 "sudo mount -a"
  ssh sanjay@192.168.1.181 "sudo systemctl start nfs-client.target"
  ```
- [x] **10:13 PM** Update AGX NFS mounts:
  ```bash
  ssh sanjay@192.168.1.244 "sudo systemctl stop nfs-client.target"
  ssh sanjay@192.168.1.244 "sudo ./scripts/update-nfs-fstab.sh"
  ssh sanjay@192.168.1.244 "sudo mount -a"
  ssh sanjay@192.168.1.244 "sudo systemctl start nfs-client.target"
  ```
- [x] **10:16 PM** Update Spark1 NFS mounts:
  ```bash
  ssh sanjay@192.168.1.201 "sudo systemctl stop nfs-client.target"
  ssh sanjay@192.168.1.201 "sudo ./scripts/update-nfs-fstab.sh"
  ssh sanjay@192.168.1.201 "sudo mount -a"
  ssh sanjay@192.168.1.201 "sudo systemctl start nfs-client.target"
  ```
- [x] **10:19 PM** Update Spark2 NFS mounts:
  ```bash
  ssh sanjay@192.168.1.202 "sudo systemctl stop nfs-client.target"
  ssh sanjay@192.168.1.202 "sudo ./scripts/update-nfs-fstab.sh"
  ssh sanjay@192.168.1.202 "sudo mount -a"
  ssh sanjay@192.168.1.202 "sudo systemctl start nfs-client.target"
  ```

**NFS Verification - 5 minutes:**
- [x] **10:20 PM** Test NFS connectivity from all nodes:
  ```bash
  # From Tower, test all clients
  showmount -e localhost
  ssh sanjay@192.168.1.181 "df -h | grep nfs"
  ssh sanjay@192.168.1.244 "df -h | grep nfs"
  ssh sanjay@192.168.1.201 "df -h | grep nfs"
  ssh sanjay@192.168.1.202 "df -h | grep nfs"
  ```

**⏰ Checkpoint 3.1:** NFS services updated and mounts verified

### Kubernetes Deployment Updates (15 minutes - 10:20 PM - 10:35 PM)
- [x] **10:25 PM** Update FastAPI deployment YAMLs with new IPs:
  - `agent/nano/fastapi-deployment-full.yaml` - Update service IPs and node selectors
  - `agent/agx/fastapi-deployment-agx.yaml` - Update service IPs and node selectors  
  - `agent/spark1/fastapi-deployment-spark1.yaml` - Update service IPs and node selectors
  - `agent/spark2/fastapi-deployment-spark2.yaml` - Update service IPs and node selectors
- [x] **10:30 PM** Update PostgreSQL deployment: `server/postgres-db-deployment.yaml`
- [x] **10:32 PM** Update pgAdmin deployment: `server/pgadmin-deployment.yaml`
- [x] **10:35 PM** Update registry deployment: `server/registry-deployment.yaml`

### Setup Scripts Updates (15 minutes - 10:35 PM - 10:50 PM)
- [x] **COMPLETED** All K3s setup scripts verified clean of old IPs:
  - `server/k3s-server.sh` - ✅ Already uses correct 192.168.1.x IPs
  - `agent/nano/k3s-nano.sh` - ✅ Clean, uses correct IP variables
  - `agent/agx/k3s-agx.sh` - ✅ Updated start-fastapi-agx.yaml registry port
  - `agent/spark1/k3s-spark1.sh` - ✅ Clean, no 10.1.10 references found
  - `agent/spark2/k3s-spark2.sh` - ✅ Clean, no 10.1.10 references found
- [x] **COMPLETED** All deployment YAML files verified:
  - `agent/*/fastapi-deployment-*.yaml` - ✅ All use correct NFS server IP (192.168.1.150)
  - `server/postgres-db-deployment.yaml` - ✅ Uses correct IPs
  - `server/pgadmin-deployment.yaml` - ✅ Uses correct IPs
  - `server/registry-deployment.yaml` - ✅ Uses correct IPs
- [x] **COMPLETED** Network configuration scripts verified:
  - `scripts/update-nfs-exports.sh` - ✅ Uses correct export IPs
  - `scripts/update-nfs-fstab.sh` - ✅ Uses correct mount IPs
  - `scripts/update-docker-registry.sh` - ✅ Uses correct registry IPs

### Backup Configuration Updates (10 minutes - 10:50 PM - 11:00 PM)
- [x] **10:55 PM** Update backup scripts with new IPs:
  - `backup_home.sh` - Update target IPs
  - `scripts/restore_backup.sh` - Update source IPs
  - `scripts/update-all-nfs-fstab.sh` - Update NFS mount IPs
- [x] **10:57 PM** Update monitoring scripts: `scripts/monitor-service.sh`
- [x] **10:59 PM** Commit all configuration changes: `git add . && git commit -m "Network migration: 10.1.10.x → 192.168.1.x"`

**⏰ Checkpoint 3:** All configurations updated, repository committed

---

## 🕛 Phase 4: Cluster Reconfiguration (90 minutes - 11:00 PM - 12:30 AM)

### K3s Server Reinstallation (45 minutes - 11:00 PM - 11:45 PM)
**✅ COMPLETED - Server reinstalled via k3s-server.sh script**
- [x] **11:00 PM** Reinstall k3s server on Tower (completed via script)
- [x] **11:05 PM** Verify server installation: `sudo systemctl status k3s`
- [x] **11:10 PM** Check server logs: `sudo journalctl -u k3s -n 20`
- [x] **11:15 PM** Verify kubectl access: `kubectl get nodes` (shows Tower)
- [x] **11:20 PM** Update k3s config if needed: `/etc/rancher/k3s/config.yaml`
- [x] **11:25 PM** Get cluster join token: `sudo cat /var/lib/rancher/k3s/server/node-token`
- [x] **11:30 PM** Test basic cluster functionality

### Agent Nodes Rejoin (45 minutes - 11:30 PM - 12:15 AM)
- [x] **11:35 PM** Update Nano K3s agent config and restart (completed via k3s-nano.sh)
- [x] **11:45 PM** Update AGX K3s agent config and restart (completed via k3s-agx.sh):
  ```bash
  ssh sanjay@192.168.1.244 "sudo systemctl stop k3s-agent"
  # Update /etc/rancher/k3s/config.yaml if needed
  ssh sanjay@192.168.1.244 "sudo systemctl start k3s-agent"
  ```
- [ ] **11:55 PM** Update Spark1 K3s agent config and restart:
  ```bash
  ssh sanjay@192.168.1.201 "sudo systemctl stop k3s-agent"
  # Update /etc/rancher/k3s/config.yaml if needed
  ssh sanjay@192.168.1.201 "sudo systemctl start k3s-agent"
  ```
- [ ] **12:05 AM** Update Spark2 K3s agent config and restart:
  ```bash
  ssh sanjay@192.168.1.202 "sudo systemctl stop k3s-agent"
  # Update /etc/rancher/k3s/config.yaml if needed
  ssh sanjay@192.168.1.202 "sudo systemctl start k3s-agent"
  ```
- [ ] **12:12 PM** Wait for all agents to rejoin: `kubectl get nodes` (should show all nodes Ready)
- [ ] **12:15 PM** Verify cluster connectivity: `kubectl get pods -A`

### Services Restart (15 minutes - 12:15 AM - 12:30 AM)
- [x] **12:20 AM** Deploy PostgreSQL: `kubectl apply -f server/postgres-db-deployment.yaml` (completed via script)
- [x] **12:25 AM** Deploy pgAdmin: `kubectl apply -f server/pgadmin-deployment.yaml` (completed via script)
- [ ] **12:30 AM** Uncordon nodes: `kubectl uncordon <node>` (no nodes to uncordon yet)

**⏰ Checkpoint 4:** K3s cluster reformed, core services running

---

## 🕐 Phase 5: Application Deployment (60 minutes - 11:20 PM - 12:20 AM)

### FastAPI Services (40 minutes - 11:20 PM - 12:00 AM)
- [x] **11:25 PM** Deploy Nano FastAPI: `kubectl apply -f agent/nano/fastapi-deployment-full.yaml` (completed via k3s-nano.sh)
- [x] **11:35 PM** Deploy AGX FastAPI: `kubectl apply -f agent/agx/fastapi-deployment-agx.yaml` (completed via k3s-agx.sh)
- [ ] **11:45 PM** Deploy Spark1 FastAPI: `kubectl apply -f agent/spark1/fastapi-deployment-spark1.yaml`
- [ ] **11:55 PM** Deploy Spark2 FastAPI: `kubectl apply -f agent/spark2/fastapi-deployment-spark2.yaml`

### Service Validation (20 minutes - 12:00 AM - 12:20 AM)
- [ ] **12:05 AM** Check pod status: `kubectl get pods -A`
- [ ] **12:10 AM** Verify service endpoints accessible
- [ ] **12:15 AM** Test GPU workloads if applicable
- [ ] **12:20 AM** Run backup verification

**⏰ Checkpoint 5:** All applications deployed and accessible

---

## 🕑 Phase 6: VPN Setup & Testing (80 minutes - 12:20 AM - 1:40 AM)

### Comcast Router Port Forwarding (20 minutes - 12:20 AM - 12:40 AM)
- [ ] **12:20 AM** Connect to the existing 10.1.10.x subnet (ensure your device is still on the old network)
- [ ] **12:25 AM** Open web browser and navigate to http://192.168.1.1
- [ ] **12:30 AM** Login to Comcast Business Router web interface (use admin credentials)
- [ ] **12:35 AM** Navigate to Firewall > Port Forwarding (or Advanced > Port Forwarding)
- [ ] **12:40 AM** Add new port forwarding rule for OpenVPN:
  - **Rule Name**: K3s VPN Access
  - **Service Type**: UDP
  - **External Port Start**: 1194
  - **External Port End**: 1194
  - **Internal IP Address**: 10.1.10.2 (ER605 firewall IP)
  - **Internal Port Start**: 1194
  - **Internal Port End**: 1194
  - **Enable**: Checked
- [ ] **12:45 AM** Save the port forwarding rule
- [ ] **12:50 AM** Verify the rule appears in the active forwarding list
- [ ] **12:55 AM** Test external connectivity to port 1194 (optional - can use online port checker)
- [ ] **1:00 AM** Switch back to 192.168.1.x subnet for ER605 configuration

### OpenVPN Server Setup (40 minutes - 1:00 AM - 1:40 AM)
- [ ] **1:00 AM** Connect to the new 192.168.1.x subnet (ensure your device is on the new network)
- [ ] **1:05 AM** Open web browser and navigate to http://192.168.1.1
- [ ] **1:10 AM** Login to ER605 web interface (use admin credentials)
- [ ] **1:15 AM** Navigate to VPN > OpenVPN > Server tab
- [ ] **1:20 AM** Click "Enable" to activate OpenVPN Server
- [ ] **1:25 AM** Configure OpenVPN Server settings:
  - **Service Type**: Enable OpenVPN Server
  - **Protocol**: UDP
  - **Port**: 1194
  - **VPN Subnet**: 10.8.0.0/24
  - **Client IP Assignment**: Automatic
  - **Primary DNS**: 8.8.8.8 (Google DNS)
  - **Secondary DNS**: 1.1.1.1 (Cloudflare DNS)
- [ ] **1:30 AM** Click "Save" to apply OpenVPN server configuration
- [ ] **1:35 AM** Navigate to VPN > OpenVPN > Client tab
- [ ] **1:40 AM** Download the OpenVPN client configuration file (.ovpn)
- [ ] **1:45 AM** Install OpenVPN client on test device (if not already installed)
- [ ] **1:50 AM** Import the downloaded .ovpn configuration file
- [ ] **1:55 AM** Connect to VPN and verify connection status
- [ ] **2:00 AM** Test cluster access through VPN tunnel:
  - Ping cluster nodes: `ping 192.168.1.150` (Tower)
  - Access Kubernetes dashboard if available
  - Test SSH access to nodes through VPN
- [ ] **2:05 AM** Verify firewall rules allow VPN traffic (check ER605 logs if needed)
- [ ] **2:10 AM** Test port forwarding for external access (if configured)
- [ ] **2:15 AM** Disconnect VPN and verify local network access still works
- [ ] **2:20 AM** Reconnect VPN and confirm persistent access

### Final Testing (40 minutes - 2:20 AM - 3:00 AM)
- [ ] **2:25 AM** Test all FastAPI endpoints on new subnet:
  - Nano: http://192.168.1.181:30002
  - AGX: http://192.168.1.244:30003
  - Spark1: http://192.168.1.201:30004
  - Spark2: http://192.168.1.202:30005
- [ ] **2:30 AM** Verify PostgreSQL connectivity from all nodes
- [ ] **2:35 AM** Test NFS storage access and performance
- [ ] **2:40 AM** Run full backup cycle and verify integrity
- [ ] **2:45 AM** Performance testing of GPU workloads (if applicable)
- [ ] **2:50 AM** Final cluster health check: `kubectl get nodes && kubectl get pods -A`
- [ ] **2:55 AM** Migration complete - document any issues encountered

**⏰ Checkpoint 6:** VPN functional, all services tested and accessible

---

## 🕒 Phase 7: Cleanup & Documentation (45 minutes - 2:55 AM - 3:40 AM)

### Cleanup Tasks (20 minutes - 2:55 AM - 3:15 AM)
- [ ] **3:00 AM** Remove old IP references from documentation
- [ ] **3:05 AM** Update README with new network information
- [ ] **3:10 AM** Clean up temporary files and backups
- [ ] **3:15 AM** Update monitoring and alerting if applicable

### Documentation (25 minutes - 3:15 AM - 3:40 AM)
- [ ] **3:20 AM** Document new network topology
- [ ] **3:25 AM** Update runbooks with new IPs
- [ ] **3:30 AM** Create VPN access documentation
- [ ] **3:35 AM** Final git commit and push
- [ ] **3:40 AM** Migration officially complete

---

## 🚨 Emergency Rollback Plan

If migration fails at any point:

1. **Immediate Actions:**
   - Revert all nodes to original 10.1.10.x IPs
   - Remove ER605 firewall, reconnect directly to router
   - `git checkout -- .` to revert configuration changes
   - `kubectl apply -f cluster-backup-pre-migration.yaml`

2. **Contact Info:**
   - Emergency contact: [Your contact info]
   - Support resources: [Relevant links]

3. **Success Criteria:**
   - All nodes reachable on original IPs
   - K3s cluster functional
   - All services accessible

---

## ✅ Success Validation Checklist

- [ ] All nodes show Ready: `kubectl get nodes`
- [ ] All pods running: `kubectl get pods -A | grep -v Running` should return empty
- [ ] FastAPI services accessible on new IPs
- [ ] PostgreSQL/pgAdmin working
- [ ] NFS storage mounted correctly
- [ ] VPN connection established
- [ ] Backup scripts functional
- [ ] GPU workloads operational

**Final Checkpoint:** Migration complete by 2:20 AM

---

## 🔍 Post-Migration Validation (30 minutes - Next Day)

**⚠️ Important:** Perform these checks the day after migration to ensure stability.

### Network Connectivity Tests
- [ ] Verify all nodes reachable: `ping 192.168.1.150 && ping 192.168.1.181 && ping 192.168.1.244 && ping 192.168.1.201 && ping 192.168.1.202`
- [ ] Test inter-node communication: SSH between all nodes
- [ ] Verify DNS resolution: `nslookup nano`, `nslookup agx`, etc.

### Service Availability Tests
- [ ] K3s cluster health: `kubectl get nodes && kubectl get pods -A`
- [ ] FastAPI services: Access all endpoints from local network
- [ ] PostgreSQL: Connect via pgAdmin and run test queries
- [ ] NFS storage: Read/write operations from all nodes

### VPN Access Tests
- [ ] Connect via VPN from external network
- [ ] Access cluster services through VPN tunnel
- [ ] Test file transfers and remote management

### Performance Validation
- [ ] Run GPU workloads (if applicable)
- [ ] Monitor system resources during normal operation
- [ ] Verify backup scripts execute successfully

**✅ Migration Success:** All post-migration tests pass