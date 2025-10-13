# 🚀 Jetson Network Setup: High-Performance 10G + 1G Dual Network Configuration

This repository contains scripts to configure a high-performance, dual-network setup between a Tower (host server) and Jetson devices (AGX Orin and Nano), optimized for maximum NFS throughput and seamless development workflows.

## 🎯 What This System Provides

This repository contains scripts to configure a **high-performance, dual-network setup** between a Tower (host server) and Jetson devices (AGX Orin and Nano), optimized for maximum NFS throughput and seamless development workflows.

### ✅ Key Benefits
- **🚀 Maximum AGX Performance**: Dedicated 10G link for data-intensive AI/ML workloads
- **🔒 Nano Reliability**: Stable 1G connection without bandwidth interference
- **🛡️ Network Isolation**: Zero performance impact between devices
- **🌐 Internet Connectivity**: Preserved internet access for both devices via Tower NAT
- **💾 Unified Storage**: Both devices access the same NFS storage seamlessly
- **🔄 Optional Inter-Device Communication**: Nano ↔ AGX routing when needed
- **🛟 Enterprise Safety**: Automatic backups and restore capabilities
- **🔑 Passwordless SSH**: Seamless script execution across all devices

### 🏆 Performance Achieved
- **AGX Orin**: Up to 10 Gbps bandwidth to Tower with ultra-low latency
- **Jetson Nano**: Up to 1 Gbps dedicated bandwidth with preserved internet
- **Network Isolation**: No bandwidth sharing or interference between devices
- **NFS Performance**: Optimized for high-throughput data processing

## 🏗️ Network Architecture Overview

### The Problem We Solved
- **AGX Orin**: Needs maximum speed for AI inference, large datasets, video processing → **10G dedicated link**
- **Nano**: Needs stable, reliable connectivity for IoT/monitoring → **1G dedicated link**
- **Inter-device communication**: Optional routing through Tower without affecting performance

### Network Topology
```
                    TOWER (Ubuntu Host)
                    ├── 10G Port: enp1s0f0 (192.168.10.1)
                    └── 1G Port: eno2 (192.168.5.1)
                           │
            ┌──────────────┼──────────────┐
            │              │              │
    ┌───────▼────┐    ┌────▼────┐    ┌────▼────┐
    │ 10G Network│    │ ROUTING  │   │1G Network│
    │192.168.10.x│    │(Optional)│   │192.168.5.x│
    └───────┬────┘    └─────────┘    └────┬────┘
            │                              │
    ┌───────▼────┐                  ┌─────▼────┐
    │ AGX Orin   │                  │Jetson Nano│
    │ eno1       │                  │ eno1      │
    │192.168.10.11│                 │192.168.5.21│
    └────────────┘                  └───────────┘
```

## 📊 Network Configuration Details

| Device          | Interface  | Network         | IP Address    | Purpose                    |
|-----------------|------------|-----------------|---------------|----------------------------|
| **Tower**       | enp1s0f0   | 192.168.10.x/24 | 192.168.10.1  | 10G link to AGX            |
| **Tower**       | eno2       | 192.168.5.x/24  | 192.168.5.1   | 1G link to Nano            |
| **AGX Orin**    | eno1       | 192.168.10.x/24 | 192.168.10.11 | High-speed data processing |
| **Jetson Nano** | eno1       | 192.168.5.x/24  | 192.168.5.21  | Reliable connectivity      |

## 📋 Prerequisites

### Hardware Requirements
- **Tower**: Dual network interfaces (10G + 1G Ethernet ports)
- **AGX Orin**: 10G Ethernet capability (eno1 interface)
- **Jetson Nano**: 1G Ethernet interface (eno1 interface)
- **Cables**: Appropriate Ethernet cables for each link speed

### Software Requirements
- **Ubuntu/Linux** on all devices
- **netplan.io** for network configuration
- **nfs-common** for NFS client functionality
- **nfs-kernel-server** on Tower
- **iperf3** for performance testing (optional)
- **iptables-persistent** for firewall rule persistence (Tower)

### Before You Begin
- [ ] All devices are running Ubuntu/Linux
- [ ] Ethernet cables are connected between devices
- [ ] You have sudo access on all devices
- [ ] SSH access is available to all devices
- [ ] Backup any important configurations (scripts do this automatically)

## 🚀 Quick Start (5 Minutes)

For experienced users with passwordless SSH already configured:

```bash
# On Tower (Ubuntu Host)
cd /home/sanjay/containers/bridgenfs
./setup_ssh_keys.sh                           # Passwordless SSH setup
./setup_tower_network.sh                      # Dual interfaces + NFS
ssh agx "./setup_agx_network.sh"              # AGX 10G network
ssh nano "./setup_nano_network.sh"            # Nano 1G network
./setup_tower_internet_sharing_enhanced.sh    # NAT + routing + testing
```

**That's it!** Your high-performance network is ready. Skip to [Success Validation](#-success-validation) to verify.

## 📖 Detailed Deployment Instructions

### ⚡ Complete Execution Plan

**IMPORTANT**: Each script must be run on the correct device. Follow this exact sequence:

```bash
# ======================================
# PHASE 1: TOWER SETUP (Run on Tower)
# ======================================
cd /home/sanjay/containers/bridgenfs

# Step 0: SSH Key Setup - RECOMMENDED FIRST
./setup_ssh_keys.sh                           # Sets up passwordless SSH to devices

# Step 1: Tower Network Configuration
./setup_tower_network.sh                      # Configures dual interfaces + NFS

# ======================================
# PHASE 2: DEVICE SETUP
# ======================================

# Step 2: AGX Setup (Run on AGX Orin)
ssh agx  # or ssh 192.168.10.11
cd /home/sanjay/containers/bridgenfs
./setup_agx_network.sh                        # Configures 10G network + NFS mount

# Step 3: Nano Setup (Run on Jetson Nano)
ssh nano  # or ssh 192.168.5.21
cd /home/sanjay/containers/bridgenfs
./setup_nano_network.sh                       # Configures 1G network + preserves internet

# ======================================
# PHASE 3: TOWER FINALIZATION (Run on Tower)
# ======================================
# Return to Tower or open new Tower terminal
cd /home/sanjay/containers/bridgenfs

# Step 4: Internet Sharing + Routing
./setup_tower_internet_sharing_enhanced.sh    # NAT/routing + automatic device testing

# ======================================
# PHASE 4: OPTIONAL - Inter-device Communication
# ======================================

# Step 5: AGX Routing (OPTIONAL - only if AGX needs to reach Nano)
ssh agx
cd /home/sanjay/containers/bridgenfs
./setup_agx_routing.sh                        # Adds routes to reach Nano network
```

**⏱️ Total Setup Time**: ~15-20 minutes  
**🔧 Required Steps**: 0-4 (Step 5 is optional)  
**🔑 Passwordless SSH**: Step 0 eliminates all password prompts  
**🎯 Device-Specific**: Each script runs on its designated device

### 📋 What Each Step Does

| Step  | Script                           | Device | Purpose                                     | Prerequisites       |
|-------|----------------------------------|--------|---------------------------------------------|---------------------|
| **0** | `setup_ssh_keys.sh`              | Tower  | Passwordless SSH setup                      | None                |
| **1** | `setup_tower_network.sh`         | Tower  | Dual interfaces (10G + 1G) + NFS config     | Step 0 recommended  |
| **2** | `setup_agx_network.sh`           | AGX    | 10G network connection + NFS mount          | Step 1 complete     |
| **3** | `setup_nano_network.sh`          | Nano   | 1G network connection + internet preserved  | Step 1 complete     |
| **4** | `setup_tower_internet_sharing.sh`| Tower  | NAT/routing for internet + inter-device     | Steps 1-3 complete  |
| **5** | `setup_agx_routing.sh`           | AGX    | Routes to reach Nano network                | Step 4 complete     |

## 🔧 Script Reference

### Passwordless SSH Setup

#### 0. `setup_ssh_keys.sh` 🔑
**Purpose**: Configure passwordless SSH authentication
- Generates SSH key pair (ed25519) on Tower
- Copies public key to AGX and Nano devices
- Creates SSH config for easy access (ssh nano, ssh agx)
- Tests passwordless connectivity
- **Enables seamless script execution without password prompts**

### Core Network Setup Scripts

#### 1. `setup_tower_network.sh` 🏢
**Purpose**: Configure Tower as dual-network server
- Sets up 10G interface (enp1s0f0) with IP 192.168.10.1
- Sets up 1G interface (eno2) with IP 192.168.5.1
- Configures NFS server for both networks
- Tests connectivity to both Jetson devices

#### 2. `setup_agx_network.sh` ⚡
**Purpose**: Configure AGX Orin for maximum 10G performance
- Assigns static IP 192.168.10.11 to eno1 interface
- Mounts NFS share from Tower via 10G link
- Includes iperf3 speed testing for 10G validation
- Optimized for high-throughput data processing

#### 3. `setup_nano_network.sh` 🔗
**Purpose**: Configure Nano with preserved internet connectivity
- Assigns static IP 192.168.5.21 to eno1 interface
- Mounts NFS share from Tower via 1G link
- Preserves existing internet connection (WiFi)
- Includes connectivity validation and troubleshooting

### Advanced Configuration Scripts

#### 4. `setup_tower_internet_sharing.sh` 🌐
**Purpose**: Configure Tower as complete network gateway
- Enables IP forwarding and NAT rules for both networks
- Provides internet access to Nano and AGX through Tower
- Enables inter-device communication (Nano ↔ AGX)
- Makes firewall rules persistent across reboots
- **Replaces the old setup_tower_routing.sh**

#### 4b. `setup_tower_internet_sharing_enhanced.sh` 🌐⚡
**Purpose**: Enhanced version with passwordless SSH integration
- All features of the standard version
- Automatically tests connectivity to devices
- Uses SSH config aliases (nano, agx) when available
- Verifies internet access on remote devices
- Tests inter-device communication automatically

#### 5. `setup_agx_routing.sh` 🔄
**Purpose**: Add AGX routing to reach Nano network
- Updates AGX Netplan with route to 192.168.5.x network
- Routes Nano traffic through Tower (192.168.10.1)
- Maintains full 10G performance for Tower communication

### Backup and Recovery Scripts

#### 6. `restore_backup.sh` 🔄
**Purpose**: Restore configurations from automatic backups
- Lists all available backup directories with timestamps **on current device**
- Automatically detects backup type (SSH, network, firewall)
- Restores configurations to previous working state
- Provides guidance for post-restoration testing
- **Must be run on the same device that created the backup**
- **Use when scripts cause issues or you need to rollback**

## 🔄 Configuration Backup and Restore

**All scripts now automatically backup configurations before making changes!**

### View Available Backups (Device-Specific)
```bash
# Tower backups (SSH, firewall, Tower network) - run on Tower
./restore_backup.sh

# AGX backups (AGX network, routing) - run on AGX
ssh agx
cd /home/sanjay/containers/bridgenfs
./restore_backup.sh

# Nano backups (Nano network) - run on Nano
ssh nano
cd /home/sanjay/containers/bridgenfs
./restore_backup.sh
```

### Restore from Backup (Device-Specific)
```bash
# On Tower - restore Tower configurations
./restore_backup.sh /tmp/iptables_backup_20251001_173045
./restore_backup.sh ~/.ssh/backup_20251001_173045

# On AGX - restore AGX configurations
ssh agx
./restore_backup.sh /tmp/agx_netplan_backup_20251001_173045

# On Nano - restore Nano configurations
ssh nano
./restore_backup.sh /tmp/nano_netplan_backup_20251001_173045
```

**Backup locations by device**:
- **Tower**: SSH configs (`~/.ssh/backup_*/`), Firewall rules (`/tmp/iptables_backup_*/`), Tower network (`/tmp/netplan_backup_*/`)
- **AGX**: Network configs (`/tmp/agx_netplan_backup_*/`), Routing configs (`/tmp/agx_routing_backup_*/`)
- **Nano**: Network configs (`/tmp/nano_netplan_backup_*/`)

## 🔍 Troubleshooting

### ⚠️ Internet Connectivity Issues

**Common Problem**: Nano loses internet access after running network setup.

**Cause**: Some configurations may set Tower as default gateway without proper NAT.

**Solution**:
```bash
# On Tower - Enable internet sharing
./setup_tower_internet_sharing_enhanced.sh

# Or manually add NAT rules:
sudo iptables -t nat -A POSTROUTING -s 192.168.5.0/24 -o wlo1 -j MASQUERADE
sudo iptables -I FORWARD 1 -s 192.168.5.0/24 -j ACCEPT
sudo iptables -I FORWARD 2 -d 192.168.5.0/24 -j ACCEPT
```

**Prevention**: Use the current `setup_nano_network.sh` for new deployments.

### 🔄 Execution Order Issues

**Problem**: Scripts fail or network doesn't work properly.

**Common Causes**:
- Running scripts out of order
- Skipping required steps
- Not waiting for previous step to complete

**Solution**:
```bash
# Always follow this order:
# 1. Tower network setup FIRST
# 2. Device setups (AGX, Nano) SECOND
# 3. Tower internet sharing THIRD
# 4. Additional routing LAST (optional)

# If you ran steps out of order, reset and start over:
sudo netplan apply  # On each device
./setup_tower_network.sh  # Start from step 1
```

### 💾 Backup and Restore Issues

**Problem**: Need to restore configuration but unsure which device to use.

**Solution**: **Each device restores its own backups**
```bash
# Tower backups (SSH, firewall, Tower network) - restore on Tower
./restore_backup.sh

# AGX backups (AGX network, routing) - restore on AGX
ssh agx
./restore_backup.sh

# Nano backups (Nano network) - restore on Nano
ssh nano
./restore_backup.sh
```

**Remember**: Backups are stored locally on each device in `/tmp/` directories.

### Network Connectivity Issues
```bash
# Check interface status
ip addr show

# Test connectivity
ping 192.168.10.1  # From AGX to Tower
ping 192.168.5.1   # From Nano to Tower

# Check NFS mounts
df -h | grep vmstore

# Verify internet access
ping 8.8.8.8       # Test DNS and internet
```

### Performance Validation
```bash
# Test 10G speed (AGX)
iperf3 -c 192.168.10.1 -P 8 -t 10

# Test 1G speed (Nano)
iperf3 -c 192.168.5.1 -P 4 -t 10
```

### Routing Verification
```bash
# Check routing table
ip route show

# Test inter-device communication
ping 192.168.10.11  # From Nano to AGX
ping 192.168.5.21   # From AGX to Nano

# Check NAT/forwarding rules (on Tower)
sudo iptables -t nat -L -n | grep MASQUERADE
sudo iptables -L FORWARD -n | grep 192.168
```

### Firewall and NAT Issues
```bash
# Check if IP forwarding is enabled (on Tower)
cat /proc/sys/net/ipv4/ip_forward  # Should return 1

# View current NAT rules (on Tower)
sudo iptables -t nat -L POSTROUTING -n

# Check if rules are persistent
ls -la /etc/iptables/rules.v4

# Reload persistent rules if needed
sudo iptables-restore < /etc/iptables/rules.v4
```

## ⚡ Performance Characteristics

### 🏎️ AGX Orin (10G Network)
- **Bandwidth**: Up to 10 Gbps to Tower
- **Latency**: Ultra-low latency for real-time processing
- **Use Case**: AI inference, large dataset processing, video streaming
- **NFS Mount**: `/mnt/vmstore` via 10G link

### 🔒 Jetson Nano (1G Network)
- **Bandwidth**: Up to 1 Gbps to Tower
- **Stability**: Dedicated link prevents interference
- **Use Case**: IoT applications, monitoring, lightweight processing
- **NFS Mount**: `/mnt/vmstore` via 1G link

### 🌉 Inter-Device Communication
- **Path**: Nano → Tower (1G) → AGX (10G)
- **Performance Impact**: Zero impact on AGX-Tower 10G performance
- **Latency**: ~1-2ms additional hop through Tower
- **Bandwidth**: Limited by Nano's 1G interface

## 🛡️ Network Isolation & Security

### Traffic Separation
- **AGX traffic**: Flows directly over dedicated 10G link
- **Nano traffic**: Flows over dedicated 1G link
- **No bandwidth sharing**: Each device has dedicated network path
- **No interference**: High-speed AGX operations never affect Nano

### Routing Logic
```
AGX → Tower:     Direct 10G link (192.168.10.x network)
Nano → Tower:    Direct 1G link (192.168.5.x network)
AGX → Nano:      AGX → Tower → Nano (when routing enabled)
Nano → AGX:      Nano → Tower → AGX (when routing enabled)
```

## ✅ Success Validation

After successful deployment, you should see:

1. **Tower**: Both 192.168.10.1 and 192.168.5.1 IP addresses assigned
2. **AGX**: Can ping 192.168.10.1 and mount NFS via 10G
3. **Nano**: Can ping 192.168.5.1 and mount NFS via 1G
4. **Internet**: Both AGX and Nano can reach external sites (ping 8.8.8.8)
5. **NFS**: Both devices can access `/mnt/vmstore`
6. **Performance**: AGX achieves near 10G speeds, Nano achieves near 1G speeds
7. **Inter-device** (if enabled): Nano and AGX can ping each other
8. **NAT Rules**: Tower shows proper MASQUERADE rules for both networks
9. **Backups**: Each device has backup directories in `/tmp/` with timestamps
10. **Restore capability**: `./restore_backup.sh` lists available backups on each device

## 🚨 Important Notes

### Script Versions
- **Current scripts** are optimized for reliability and internet connectivity
- **Automatic backups** protect against configuration issues
- **All scripts are safe to re-run** with idempotent operations
- **Restore capability** available if rollback is needed
- **setup_nano_network.sh** is the current stable version
- **setup_tower_internet_sharing_enhanced.sh** provides comprehensive networking

### Internet Connectivity
- **Tower acts as NAT gateway** providing internet to both networks
- **Nano preserves WiFi internet** as backup connection
- **All devices maintain internet access** after configuration

### Firewall Rules
- **Persistent rules**: Automatically saved to `/etc/iptables/rules.v4`
- **Service dependency**: Requires `iptables-persistent` package
- **Rule verification**: Check with `sudo iptables -t nat -L -n`

---

*This setup provides enterprise-grade network performance while maintaining simplicity and reliability for your Jetson development environment.*
