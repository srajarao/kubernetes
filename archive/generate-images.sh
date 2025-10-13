#!/bin/bash
# generate-images.sh - Generate optimized Dockerfiles and requirements based on component matrix
# This script creates node-specific Dockerfiles and requirements files

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source configuration and functions
source "$SCRIPT_DIR/k3s-config.sh"
source "$SCRIPT_DIR/node-config.sh"

echo "🏗️  Generating Optimized Docker Images and Requirements"
echo "======================================================"

# Parse cluster nodes
nodes=$(parse_cluster_nodes "$CLUSTER_NODES")

for node in $nodes; do
    # Skip tower for now (server components handled separately)
    if [ "$node" = "tower" ]; then
        echo "⏭️  Skipping tower node (server components)"
        continue
    fi

    echo ""
    echo "🔧 Processing node: $node"

    # Get node configuration
    base_image=$(get_node_base_image_path "$node")
    components=$(get_node_components "$node")
    arch=$(get_node_arch "$node")
    dockerfile_path=$(get_node_image "$node" "dockerfile")
    requirements_path=$(get_node_image "$node" "requirements")

    if [ -z "$dockerfile_path" ] || [ -z "$requirements_path" ]; then
        echo "  ⚠️  Skipping $node - dockerfile/requirements paths not configured"
        continue
    fi

    echo "  📦 Base Image: $base_image"
    echo "  🧩 Components: $components"
    echo "  🏗️  Architecture: $arch"

    # Generate Dockerfile
    echo "  📝 Generating Dockerfile: $dockerfile_path"
    mkdir -p "$(dirname "$dockerfile_path")"

    generate_node_dockerfile "$node" > "$dockerfile_path"

    # Generate requirements file
    echo "  📋 Generating requirements: $requirements_path"
    mkdir -p "$(dirname "$requirements_path")"

    generate_node_requirements "$node" > "$requirements_path"

    # Generate health checks
    health_check_path="agent/$node/app/src/health_checks.py"
    echo "  🏥 Generating health checks: $health_check_path"
    mkdir -p "$(dirname "$health_check_path")"

    generate_node_health_checks "$node" > "$health_check_path"

    echo "  ✅ Generated files for $node"
done

echo ""
echo "🎉 Image generation complete!"
echo ""
echo "📋 Generated Files:"
for node in $nodes; do
    if [ "$node" != "tower" ]; then
        dockerfile=$(get_node_image "$node" "dockerfile")
        requirements=$(get_node_image "$node" "requirements")
        health_checks="agent/$node/app/src/health_checks.py"
        if [ -n "$dockerfile" ]; then
            echo "  $node: $dockerfile, $requirements, $health_checks"
        fi
    fi
done

echo ""
echo "🚀 Next Steps:"
echo "  1. Review generated Dockerfiles and requirements"
echo "  2. Test builds: docker build -f <dockerfile> ."
echo "  3. Update k3s-setup-automation.sh to use generated files"