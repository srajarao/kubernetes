#!/bin/bash

# Script to update IP addresses from 10.1.10.x to 192.168.1.x subnet
# Usage: ./update_ips.sh [--dry-run] [old_subnet] [new_subnet]
# Example: ./update_ips.sh --dry-run "10.1.10" "192.168.1"

set -e

DRY_RUN=false
if [ "$1" = "--dry-run" ]; then
    DRY_RUN=true
    shift
fi

OLD_SUBNET="${1:-10.1.10}"
NEW_SUBNET="${2:-192.168.1}"

echo "🔄 Updating IP addresses from ${OLD_SUBNET}.x to ${NEW_SUBNET}.x"
if [ "$DRY_RUN" = true ]; then
    echo "🧪 DRY RUN MODE - No files will be modified"
fi
echo "This will affect all files in the repository. Make sure to backup first!"
echo ""

# Function to update IP in a file
update_ip_in_file() {
    local file="$1"
    local old_ip="$2"
    local new_ip="$3"

    if grep -q "$old_ip" "$file"; then
        echo "Updating $file: $old_ip → $new_ip"
        if [ "$DRY_RUN" = false ]; then
            sed -i "s/$old_ip/$new_ip/g" "$file"
        fi
    fi
}

# Function to update subnet references
update_subnet_in_file() {
    local file="$1"
    local old_subnet="$2"
    local new_subnet="$3"

    if grep -q "$old_subnet" "$file"; then
        echo "Updating subnet in $file: $old_subnet → $new_subnet"
        if [ "$DRY_RUN" = false ]; then
            sed -i "s/$old_subnet/$new_subnet/g" "$file"
        fi
    fi
}

# List of specific IP mappings (old → new)
declare -A IP_MAPPING=(
    ["${OLD_SUBNET}.150"]="${NEW_SUBNET}.150"  # Tower
    ["${OLD_SUBNET}.181"]="${NEW_SUBNET}.181"  # Nano
    ["${OLD_SUBNET}.244"]="${NEW_SUBNET}.244"  # AGX
    ["${OLD_SUBNET}.201"]="${NEW_SUBNET}.201"  # Spark1
    ["${OLD_SUBNET}.202"]="${NEW_SUBNET}.202"  # Spark2
)

echo "📝 Updating specific IP addresses..."

# Update each specific IP
for old_ip in "${!IP_MAPPING[@]}"; do
    new_ip="${IP_MAPPING[$old_ip]}"
    echo "Mapping: $old_ip → $new_ip"

    # Find all files containing this IP and update them
    find . -type f -name "*.sh" -o -name "*.yaml" -o -name "*.yml" -o -name "*.env" -o -name "*.md" | \
    while read -r file; do
        update_ip_in_file "$file" "$old_ip" "$new_ip"
    done
done

# Update subnet references
echo ""
echo "📡 Updating subnet references..."
OLD_SUBNET_FULL="${OLD_SUBNET}.0/24"
NEW_SUBNET_FULL="${NEW_SUBNET}.0/24"

find . -type f -name "*.sh" -o -name "*.yaml" -o -name "*.yml" -o -name "*.env" -o -name "*.md" | \
while read -r file; do
    update_subnet_in_file "$file" "$OLD_SUBNET_FULL" "$NEW_SUBNET_FULL"
done

# Update gateway references
echo ""
echo "🌐 Updating gateway references..."
OLD_GATEWAY="${OLD_SUBNET}.1"
NEW_GATEWAY="${NEW_SUBNET}.1"

find . -type f -name "*.sh" -o -name "*.yaml" -o -name "*.yml" -o -name "*.env" -o -name "*.md" | \
while read -r file; do
    update_ip_in_file "$file" "$OLD_GATEWAY" "$NEW_GATEWAY"
done

echo ""
echo "🔍 Checking for any remaining old subnet references..."
REMAINING=$(grep -r "${OLD_SUBNET}" . --include="*.sh" --include="*.yaml" --include="*.yml" --include="*.env" --include="*.md" 2>/dev/null | wc -l)
if [ "$REMAINING" -gt 0 ]; then
    echo "⚠️  Found $REMAINING remaining references to ${OLD_SUBNET}.x subnet:"
    grep -r "${OLD_SUBNET}" . --include="*.sh" --include="*.yaml" --include="*.yml" --include="*.env" --include="*.md" 2>/dev/null
else
    echo "✅ No remaining references found!"
fi

echo ""
echo "📋 Summary of changes:"
echo "- Tower: ${OLD_SUBNET}.150 → ${NEW_SUBNET}.150"
echo "- Nano:  ${OLD_SUBNET}.181 → ${NEW_SUBNET}.181"
echo "- AGX:   ${OLD_SUBNET}.244 → ${NEW_SUBNET}.244"
echo "- Spark1: ${OLD_SUBNET}.201 → ${NEW_SUBNET}.201"
echo "- Spark2: ${OLD_SUBNET}.202 → ${NEW_SUBNET}.202"
echo "- Gateway: ${OLD_SUBNET}.1 → ${NEW_SUBNET}.1"
echo "- Subnet: ${OLD_SUBNET}.0/24 → ${NEW_SUBNET}.0/24"

echo ""
echo "🎯 Next steps:"
echo "1. Review the changes with 'git diff'"
echo "2. Test the configurations"
echo "3. Commit the changes"
echo "4. Update physical network configuration on devices"
echo "5. Reconfigure ER605 firewall and VPN"