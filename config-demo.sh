#!/bin/bash
# config-demo.sh - Demonstration of the new node configuration system
# This script shows how the parameterized configuration works

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🚀 K3s Node Configuration System Demo"
echo "======================================"

# Source the configuration
if [ -f "$SCRIPT_DIR/k3s-config.sh" ]; then
  source "$SCRIPT_DIR/k3s-config.sh"
else
  echo "❌ ERROR: k3s-config.sh not found"
  exit 1
fi

# Source node configuration functions
if [ -f "$SCRIPT_DIR/node-config.sh" ]; then
  source "$SCRIPT_DIR/node-config.sh"
else
  echo "❌ ERROR: node-config.sh not found"
  exit 1
fi

echo ""
echo "📋 Current Configuration:"
echo "-------------------------"
show_cluster_summary

echo ""
echo "🔧 Node-Specific Details:"
echo "------------------------"

# Parse cluster nodes
nodes=$(parse_cluster_nodes "$CLUSTER_NODES")

for node in $nodes; do
  echo "Node: $node"
  echo "  - Should install: $(should_install_node "$node" && echo '✅ Yes' || echo '❌ No')"
  echo "  - IP: $(get_node_ip "$node")"
  echo "  - Architecture: $(get_node_arch "$node")"
  echo "  - Components: $(get_node_components "$node")"

  # Show image details for agent nodes
  if [ "$node" != "tower" ]; then
    image_name=$(get_node_image "$node" "name")
    image_tag=$(get_node_image "$node" "tag")
    dockerfile=$(get_node_image "$node" "dockerfile")
    requirements=$(get_node_image "$node" "requirements")

    if [ -n "$image_name" ]; then
      echo "  - Image: $REGISTRY_URL/$image_name:$image_tag"
      echo "  - Dockerfile: $dockerfile"
      echo "  - Requirements: $requirements"
    fi
  fi
  echo ""
done

echo "💡 Configuration Benefits:"
echo "--------------------------"
echo "✅ Flexible node selection (add/remove nodes easily)"
echo "✅ Per-node image configuration"
echo "✅ Component-based architecture"
echo "✅ Architecture-aware (ARM64/AMD64 support)"
echo "✅ Easy to extend for new node types"
echo "✅ Backward compatible with existing flags"

echo ""
echo "🔄 Migration Path:"
echo "------------------"
echo "1. Update k3s-config.sh with new format"
echo "2. Test with config-demo.sh"
echo "3. Gradually migrate script logic to use new functions"
echo "4. Remove legacy flags once fully migrated"