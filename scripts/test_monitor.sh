#!/bin/bash
echo "Test monitor starting..."
kubectl get nodes --no-headers | wc -l
echo "Test monitor completed successfully"
