#!/bin/bash
# Start FastAPI Nano pod only (no agent install/cleanup)

PROJECT_DIR="/home/sanjay/containers/fastapi_nano"
DEPLOYMENT_YAML="$PROJECT_DIR/start-fastapi_nano.yaml"

# Delete any existing FastAPI Nano deployment and pod to avoid duplicates
echo "Deleting any existing FastAPI Nano deployment and pod..."
kubectl delete deployment fastapi-nano --ignore-not-found
kubectl delete pod -l app=fastapi-nano --ignore-not-found --force --grace-period=0

# Apply the deployment
echo "Applying FastAPI deployment YAML..."
kubectl apply -f "$DEPLOYMENT_YAML"

echo "Checking FastAPI pod status..."
POD_NAME=$(kubectl get pods -l app=fastapi-nano -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
kubectl get pod "$POD_NAME"
kubectl describe pod "$POD_NAME"

echo "Done. FastAPI Nano pod should be running. Access Swagger at http://192.168.5.21:8000/docs"
