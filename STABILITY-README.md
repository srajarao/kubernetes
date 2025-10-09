# K3s Environment Stability Guide

## 🎯 Mission: Stable Environment for Multi-Modal RAG Development

This guide provides tools and procedures to maintain a stable K3s environment so you can focus on your RAG project instead of infrastructure issues.

## 🚀 Quick Start

```bash
# Check environment status
./env.sh status

# Run health checks
./env.sh check

# Auto-fix issues
./env.sh fix

# Create backup before major changes
./env.sh backup
```

## 📊 Environment Status

**Current Services:**
- **FastAPI**: `http://10.1.10.150:30002` (GPU-enabled on Nano)
- **pgAdmin**: `http://10.1.10.150:30080` (Database admin)
- **PostgreSQL**: `10.1.10.150:30432` (with pgvector)

**Architecture:**
- **Tower**: x86_64 (Control plane, pgAdmin, PostgreSQL)
- **Nano**: ARM64 (GPU workloads, FastAPI)
- **AGX**: ARM64 (GPU workloads)

## 🛠️ Stability Tools

### Quick Commands (`env.sh`)

```bash
./env.sh status    # Overview of all services
./env.sh check     # Health verification
./env.sh fix       # Auto-recovery
./env.sh backup    # Create backup
./env.sh monitor   # Start background monitoring
```

### Advanced Tools (`stability-manager.sh`)

```bash
./stability-manager.sh status      # Detailed status
./stability-manager.sh check       # Comprehensive health check
./stability-manager.sh recover     # Advanced recovery
./stability-manager.sh backup      # Full backup
./stability-manager.sh monitor     # Continuous monitoring
```

## 🔄 Recovery Procedures

### Automatic Recovery
```bash
./env.sh fix
```
This will:
1. Restart failed pods
2. Redeploy applications if needed
3. Verify all services are accessible

### Manual Recovery
If auto-recovery fails:
```bash
# Full environment reset
./env.sh reset
```

## 📁 Backup Strategy

- **Automatic**: Create backup before any major changes
- **Location**: `backup/YYYYMMDD_HHMMSS/`
- **Contents**: Configurations, deployment files, cluster state

```bash
./env.sh backup
```

## 🔍 Monitoring

### Background Monitoring
```bash
# Start monitoring (runs every 5 minutes)
./env.sh monitor

# Stop monitoring
./env.sh stop-monitor
```

### Manual Checks
```bash
# Quick status
./env.sh status

# Detailed health check
./env.sh check
```

## 🚨 Troubleshooting

### Common Issues & Solutions

**Pods not running:**
```bash
./env.sh fix
```

**Services not accessible:**
```bash
./env.sh check  # Identify the issue
./env.sh fix    # Attempt recovery
```

**Architecture issues:**
- FastAPI → Nano (ARM64)
- pgAdmin/PostgreSQL → Tower (x86_64)

### Logs
- **Stability logs**: `stability.log`
- **Monitor logs**: `monitor.log`
- **Application logs**: `kubectl logs <pod-name>`

## 🎯 Development Workflow

1. **Start your session:**
   ```bash
   ./env.sh status  # Verify environment is stable
   ```

2. **During development:**
   ```bash
   ./env.sh check   # Quick health check if something seems off
   ```

3. **Before major changes:**
   ```bash
   ./env.sh backup  # Create safety backup
   ```

4. **If issues arise:**
   ```bash
   ./env.sh fix     # Auto-recovery
   ```

## 📞 Support

If the environment becomes unstable:

1. Run `./env.sh check` to diagnose
2. Try `./env.sh fix` for auto-recovery
3. Check logs in `stability.log`
4. As last resort: `./env.sh reset`

## 🎉 Focus on Your RAG Project!

With these stability tools, you can now focus on building your multi-modal RAG system instead of fighting infrastructure issues. The environment will automatically recover from most problems and alert you if manual intervention is needed.