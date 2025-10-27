#!/bin/bash

# Script to download ARM64 wheels from spark2 and copy back to local wheels folder
# Usage: ./download_wheels.sh

set -e

SPARK2_HOST="spark2"
REMOTE_TMP="/tmp/wheels_download"
LOCAL_WHEELS_DIR="$(dirname "$0")"

echo "🚀 Downloading ARM64 wheels from $SPARK2_HOST..."

# Create remote temp directory
ssh "$SPARK2_HOST" "mkdir -p $REMOTE_TMP"

# Copy requirements file to spark2
scp "../requirements.spark2.txt" "$SPARK2_HOST:$REMOTE_TMP/"

# Download wheels on spark2
ssh "$SPARK2_HOST" "cd $REMOTE_TMP && pip download -r requirements.spark2.txt --only-binary=:all: -d ."

# Copy all wheels back
echo "📥 Copying wheels back to local folder..."
scp "$SPARK2_HOST:$REMOTE_TMP/*.whl" "$LOCAL_WHEELS_DIR/"

# Clean up remote temp directory
ssh "$SPARK2_HOST" "rm -rf $REMOTE_TMP"

echo "✅ Wheel download complete!"
echo "📦 Wheels saved to: $LOCAL_WHEELS_DIR"
ls -la "$LOCAL_WHEELS_DIR"/*.whl