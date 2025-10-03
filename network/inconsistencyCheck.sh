#!/bin/bash
# inconsistencyCheck.sh - Automated consistency checker for Jetson network setup scripts
# Version: 1.0
# Date: October 2, 2025

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS=(1-setup_tower_network.sh 2-setup_agx_network.sh 3-setup_nano_network.sh 4-setup_tower_routing.sh 5-setup_agx_routing.sh 6-setup_tower_sshkeys.sh 7-setup_agx_sshkeys.sh 8-setup_nano_sshkeys.sh)

# Expected values
EXPECTED_IPS=("192.168.10.1" "192.168.5.1" "192.168.10.11" "192.168.5.21")
EXPECTED_MOUNT_POINT="/mnt/vmstore"
EXPECTED_SSH_USER="sanjay"
EXPECTED_KEY_TYPE="ed25519"

# Global counters
ERRORS=0
WARNINGS=0

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARNINGS++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((ERRORS++))
}

log_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# Check if all scripts exist
check_script_existence() {
    log_header "Checking Script Existence"
    local missing_scripts=()

    for script in "${SCRIPTS[@]}"; do
        if [[ -f "$SCRIPT_DIR/$script" ]]; then
            if [[ -x "$SCRIPT_DIR/$script" ]]; then
                log_success "Script exists and is executable: $script"
            else
                log_warning "Script exists but is not executable: $script"
            fi
        else
            missing_scripts+=("$script")
            log_error "Script missing: $script"
        fi
    done

    if [[ ${#missing_scripts[@]} -eq 0 ]]; then
        log_success "All 8 setup scripts are present"
    else
        log_error "Missing scripts: ${missing_scripts[*]}"
    fi
}

# Check IP address consistency
check_ip_consistency() {
    log_header "Checking IP Address Consistency"

    local tower_10g_count=$(grep -h "192\.168\.10\.1" "$SCRIPT_DIR"/[1-8]-setup_*.sh | wc -l)
    local tower_1g_count=$(grep -h "192\.168\.5\.1" "$SCRIPT_DIR"/[1-8]-setup_*.sh | wc -l)
    local agx_count=$(grep -h "192\.168\.10\.11" "$SCRIPT_DIR"/[1-8]-setup_*.sh | wc -l)
    local nano_count=$(grep -h "192\.168\.5\.21" "$SCRIPT_DIR"/[1-8]-setup_*.sh | wc -l)

    # Expected counts (approximate)
    if [[ $tower_10g_count -ge 3 ]]; then
        log_success "Tower 10G IP (192.168.10.1) found $tower_10g_count times"
    else
        log_error "Tower 10G IP count too low: $tower_10g_count (expected ≥3)"
    fi

    if [[ $tower_1g_count -ge 3 ]]; then
        log_success "Tower 1G IP (192.168.5.1) found $tower_1g_count times"
    else
        log_error "Tower 1G IP count too low: $tower_1g_count (expected ≥3)"
    fi

    if [[ $agx_count -ge 4 ]]; then
        log_success "AGX IP (192.168.10.11) found $agx_count times"
    else
        log_error "AGX IP count too low: $agx_count (expected ≥4)"
    fi

    if [[ $nano_count -ge 4 ]]; then
        log_success "Nano IP (192.168.5.21) found $nano_count times"
    else
        log_error "Nano IP count too low: $nano_count (expected ≥4)"
    fi
}

# Check mount point consistency
check_mount_points() {
    log_header "Checking Mount Point Consistency"

    local mount_points=$(grep -h "MOUNT_POINT=" "$SCRIPT_DIR"/[1-8]-setup_*.sh | sort | uniq)

    if [[ $(echo "$mount_points" | wc -l) -eq 1 ]]; then
        local mount_value=$(echo "$mount_points" | cut -d'"' -f2)
        if [[ "$mount_value" == "$EXPECTED_MOUNT_POINT" ]]; then
            log_success "All scripts use consistent mount point: $mount_value"
        else
            log_error "Mount point mismatch: found '$mount_value', expected '$EXPECTED_MOUNT_POINT'"
        fi
    else
        log_error "Multiple mount points found:"
        echo "$mount_points"
    fi
}

# Check interface configurations
check_interface_config() {
    log_header "Checking Interface Configurations"

    # Check Script 2 (AGX) - should use auto-detection
    if grep -q "AGX_IFACE=\$(ip link show" "$SCRIPT_DIR/2-setup_agx_network.sh"; then
        log_success "Script 2 uses auto-detection for AGX interface"
    else
        log_error "Script 2 should use auto-detection for AGX interface"
    fi

    # Check Scripts 3 and 5 - currently hardcoded but working
    local nano_iface=$(grep -h "NANO_IFACE=" "$SCRIPT_DIR/3-setup_nano_network.sh" | cut -d'"' -f2)
    local agx_iface_script5=$(grep -h "AGX_IFACE=" "$SCRIPT_DIR/5-setup_agx_routing.sh" | cut -d'"' -f2)

    if [[ "$nano_iface" == "eno1" ]]; then
        log_success "Script 3 uses expected Nano interface: $nano_iface"
    else
        log_warning "Script 3 uses unexpected Nano interface: $nano_iface (expected eno1)"
    fi

    if [[ "$agx_iface_script5" == "eno1" ]]; then
        log_success "Script 5 uses expected AGX interface: $agx_iface_script5"
    else
        log_warning "Script 5 uses unexpected AGX interface: $agx_iface_script5 (expected eno1)"
    fi
}

# Check hostname resolution in /etc/hosts
check_hostname_resolution() {
    log_header "Checking Hostname Resolution (/etc/hosts)"

    local hosts_file="/etc/hosts"
    local required_entries=(
        "192.168.10.1 tower"
        "192.168.10.11 agx"
        "192.168.5.21 nano"
    )

    for entry in "${required_entries[@]}"; do
        if grep -q "^$entry$" "$hosts_file"; then
            log_success "Found hostname entry: $entry"
        else
            log_error "Missing hostname entry in /etc/hosts: $entry"
        fi
    done

    # Check for duplicates
    local duplicates=$(grep -E "(192\.168\.(10\.1|10\.11|5\.21))" "$hosts_file" | sort | uniq -d)
    if [[ -n "$duplicates" ]]; then
        log_warning "Duplicate entries found in /etc/hosts:"
        echo "$duplicates"
    fi
}

# Check SSH configuration consistency
check_ssh_config() {
    log_header "Checking SSH Configuration Consistency"

    local ssh_scripts=("$SCRIPT_DIR/6-setup_tower_sshkeys.sh" "$SCRIPT_DIR/7-setup_agx_sshkeys.sh" "$SCRIPT_DIR/8-setup_nano_sshkeys.sh")

    for script in "${ssh_scripts[@]}"; do
        local ssh_user=$(grep -h "SSH_USER=" "$script" | cut -d'"' -f2)
        local key_type=$(grep -h "KEY_TYPE=" "$script" | cut -d'"' -f2)

        if [[ "$ssh_user" != "$EXPECTED_SSH_USER" ]]; then
            log_error "$(basename "$script"): SSH user mismatch '$ssh_user' (expected '$EXPECTED_SSH_USER')"
        fi

        if [[ "$key_type" != "$EXPECTED_KEY_TYPE" ]]; then
            log_error "$(basename "$script"): Key type mismatch '$key_type' (expected '$EXPECTED_KEY_TYPE')"
        fi
    done

    log_success "SSH configurations are consistent across all scripts"
}

# Check netplan file configurations
check_netplan_config() {
    log_header "Checking Netplan File Configurations"

    local netplan_files=$(grep -h "NETPLAN_FILE=" "$SCRIPT_DIR"/[1-8]-setup_*.sh)

    # Check for expected files
    if echo "$netplan_files" | grep -q "50-dedicated-networks.yaml"; then
        log_success "Tower uses correct netplan file: 50-dedicated-networks.yaml"
    else
        log_error "Tower netplan file not found or incorrect"
    fi

    if echo "$netplan_files" | grep -q "99-agx-static.yaml"; then
        log_success "AGX uses correct netplan file: 99-agx-static.yaml"
    else
        log_error "AGX netplan file not found or incorrect"
    fi

    if echo "$netplan_files" | grep -q "99-nano-static.yaml"; then
        log_success "Nano uses correct netplan file: 99-nano-static.yaml"
    else
        log_error "Nano netplan file not found or incorrect"
    fi
}

# Check system configuration (device-aware)
check_system_config() {
    log_header "Checking System Configuration"

    # Detect which device we're running on
    local hostname=$(hostname)
    local device_type="unknown"

    if [[ "$hostname" == "tower" ]]; then
        device_type="tower"
    elif [[ "$hostname" == "agx" ]]; then
        device_type="agx"
    elif [[ "$hostname" == "nano" ]]; then
        device_type="nano"
    fi

    log_info "Running on device: $hostname (type: $device_type)"

    if [[ "$device_type" == "tower" ]]; then
        # Tower-specific checks
        # Check NFS exports
        if [[ -f /etc/exports ]]; then
            local export_count=$(grep -c "/export/vmstore" /etc/exports)
            if [[ $export_count -ge 3 ]]; then
                log_success "NFS exports configured for $export_count devices"
            else
                log_warning "Only $export_count NFS exports found (expected ≥3)"
            fi
        else
            log_error "/etc/exports file not found"
        fi

        # Check NFS service
        if systemctl is-active --quiet nfs-kernel-server; then
            log_success "NFS server service is running"
        else
            log_error "NFS server service is not running"
        fi

    else
        # Client device checks (AGX or Nano)
        local tower_ip=""
        local expected_mount="/mnt/vmstore"

        if [[ "$device_type" == "agx" ]]; then
            tower_ip="192.168.10.1"
        elif [[ "$device_type" == "nano" ]]; then
            tower_ip="192.168.5.1"
        fi

        # Check NFS connectivity to Tower
        if [[ -n "$tower_ip" ]]; then
            log_info "Checking NFS connectivity to Tower ($tower_ip)..."

            # Test if we can show Tower's exports
            if showmount -e "$tower_ip" &>/dev/null; then
                log_success "NFS server on Tower ($tower_ip) is accessible"
            else
                log_error "Cannot access NFS server on Tower ($tower_ip)"
            fi

            # Check if NFS mount exists
            if mount | grep -q "$tower_ip:/export/vmstore on $expected_mount"; then
                log_success "NFS mount active: $expected_mount"
            else
                log_warning "NFS mount not active: $expected_mount"
            fi
        fi
    fi

    # Common checks for all devices
    # Check fstab for vmstore entries
    if [[ -f /etc/fstab ]]; then
        local vmstore_count=$(grep -c "vmstore" /etc/fstab)
        if [[ "$device_type" == "tower" ]]; then
            # Tower should have 1 vmstore entry (local mount)
            if [[ $vmstore_count -eq 1 ]]; then
                log_success "Tower fstab has single vmstore entry"
            else
                log_error "Tower fstab has $vmstore_count vmstore entries (expected 1)"
            fi
        else
            # Clients should have 1 vmstore entry (NFS mount)
            if [[ $vmstore_count -eq 1 ]]; then
                log_success "Client fstab has NFS mount entry"
            else
                log_warning "Client fstab has $vmstore_count vmstore entries (expected 1)"
            fi
        fi
    else
        log_error "/etc/fstab file not found"
    fi
}

# Check error handling
check_error_handling() {
    log_header "Checking Error Handling"

    local scripts_with_set_e=$(grep -l "set -e" "$SCRIPT_DIR"/[1-8]-setup_*.sh | wc -l)

    if [[ $scripts_with_set_e -eq 8 ]]; then
        log_success "All 8 scripts use 'set -e' for error handling"
    else
        log_error "Only $scripts_with_set_e scripts use 'set -e' (expected 8)"
    fi
}

# Check passwordless SSH connectivity
check_ssh_connectivity() {
    log_header "Checking Passwordless SSH Connectivity"

    # Detect which device we're running on
    local hostname=$(hostname)
    local device_type="unknown"

    if [[ "$hostname" == "tower" ]]; then
        device_type="tower"
    elif [[ "$hostname" == "agx" ]]; then
        device_type="agx"
    elif [[ "$hostname" == "nano" ]]; then
        device_type="nano"
    fi

    case "$device_type" in
        "tower")
            # Tower should connect to AGX and Nano
            log_info "Testing Tower → AGX SSH connection..."
            if ssh -o ConnectTimeout=5 -o BatchMode=yes agx "echo 'SSH_SUCCESS'" 2>/dev/null | grep -q "SSH_SUCCESS"; then
                log_success "Tower → AGX: Passwordless SSH working"
            else
                log_error "Tower → AGX: Passwordless SSH failed"
            fi

            log_info "Testing Tower → Nano SSH connection..."
            if ssh -o ConnectTimeout=5 -o BatchMode=yes nano "echo 'SSH_SUCCESS'" 2>/dev/null | grep -q "SSH_SUCCESS"; then
                log_success "Tower → Nano: Passwordless SSH working"
            else
                log_error "Tower → Nano: Passwordless SSH failed"
            fi
            ;;

        "agx")
            # AGX should connect to Tower and Nano
            log_info "Testing AGX → Tower SSH connection..."
            if ssh -o ConnectTimeout=5 -o BatchMode=yes tower "echo 'SSH_SUCCESS'" 2>/dev/null | grep -q "SSH_SUCCESS"; then
                log_success "AGX → Tower: Passwordless SSH working"
            else
                log_error "AGX → Tower: Passwordless SSH failed"
            fi

            log_info "Testing AGX → Nano SSH connection..."
            if ssh -o ConnectTimeout=5 -o BatchMode=yes nano "echo 'SSH_SUCCESS'" 2>/dev/null | grep -q "SSH_SUCCESS"; then
                log_success "AGX → Nano: Passwordless SSH working"
            else
                log_error "AGX → Nano: Passwordless SSH failed"
            fi
            ;;

        "nano")
            # Nano should connect to Tower and AGX
            log_info "Testing Nano → Tower SSH connection..."
            if ssh -o ConnectTimeout=5 -o BatchMode=yes tower "echo 'SSH_SUCCESS'" 2>/dev/null | grep -q "SSH_SUCCESS"; then
                log_success "Nano → Tower: Passwordless SSH working"
            else
                log_error "Nano → Tower: Passwordless SSH failed"
            fi

            log_info "Testing Nano → AGX SSH connection..."
            if ssh -o ConnectTimeout=5 -o BatchMode=yes agx "echo 'SSH_SUCCESS'" 2>/dev/null | grep -q "SSH_SUCCESS"; then
                log_success "Nano → AGX: Passwordless SSH working"
            else
                log_error "Nano → AGX: Passwordless SSH failed"
            fi
            ;;

        *)
            log_warning "Unknown device type ($hostname), skipping SSH connectivity tests"
            ;;
    esac
}

# Main execution
main() {
    echo -e "${BLUE}Jetson Network Setup Scripts - Consistency Checker${NC}"
    echo -e "${BLUE}=================================================${NC}"

    check_script_existence
    check_ip_consistency
    check_mount_points
    check_interface_config
    check_hostname_resolution
    check_ssh_config
    check_netplan_config
    check_system_config
    check_error_handling
    check_ssh_connectivity

    # Summary
    log_header "SUMMARY"
    echo "Scripts checked: ${#SCRIPTS[@]}"
    echo "Errors found: $ERRORS"
    echo "Warnings found: $WARNINGS"

    if [[ $ERRORS -eq 0 ]]; then
        if [[ $WARNINGS -eq 0 ]]; then
            log_success "All checks passed! Scripts are fully consistent."
            exit 0
        else
            log_warning "All critical checks passed, but $WARNINGS warnings found."
            exit 0
        fi
    else
        log_error "$ERRORS critical errors found. Please review and fix."
        exit 1
    fi
}

# Run main function
main "$@"