#!/bin/bash
# Smart Docker build script for AGX
# Uses devcontainer-inspired approach with proper Jupyter installation
# Uses cache unless forced or when source files have changed significantly

set -e

IMAGE_NAME="spark1"
REGISTRY="10.1.10.150:30500"
TAG="latest"
FULL_IMAGE="${REGISTRY}/${IMAGE_NAME}:${TAG}"

# Check if --no-cache is forced
FORCE_CLEAN=false
if [[ "$1" == "--clean" ]] || [[ "$1" == "--no-cache" ]]; then
    FORCE_CLEAN=true
    echo "🔄 Forced clean build (--no-cache)"
fi

# Check for significant changes that require clean build
if [[ "$FORCE_CLEAN" == false ]]; then
    # Check if base image or major dependencies changed
    if ! docker images --format "table {{.Repository}}:{{.Tag}}" | grep -q "nvcr.io/nvidia/l4t-jetpack"; then
        echo "🆕 Base image not cached, performing clean build"
        FORCE_CLEAN=true
    fi
fi

# Build the image
echo "🏗️  Building ${FULL_IMAGE} (with CUDA PyTorch and pre-downloaded wheels)"
if [[ "$FORCE_CLEAN" == true ]]; then
    docker buildx build --platform linux/arm64 -f dockerfile.spark1.wheels -t ${IMAGE_NAME} --no-cache --load .
else
    docker buildx build --platform linux/arm64 -f dockerfile.spark1.wheels -t ${IMAGE_NAME} --load .
fi

# Tag and push
echo "📤 Pushing ${FULL_IMAGE}"
docker tag ${IMAGE_NAME} ${FULL_IMAGE}
docker push ${FULL_IMAGE}

echo "✅ Build complete: ${FULL_IMAGE}"
echo "🎯 Jupyter Lab is now pre-installed in the container image"
echo "🎮 GPU support: CUDA-enabled PyTorch installed (detects GPU at runtime)"

# Instructions for deployment
echo ""
echo "🚀 To deploy:"
echo "   kubectl apply -f fastapi-deployment-spark1.yaml"
echo "   kubectl delete pods -l app=fastapi-spark1  # Force restart"
echo ""
echo "💡 For clean rebuilds when troubleshooting:"
echo "   ./build.sh --clean"
echo ""
echo "🧪 For development with Jupyter:"
echo "   Use .devcontainer/devcontainer.json in VS Code"
