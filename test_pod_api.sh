#!/bin/bash
# Test pod management API

echo "Testing pod management API..."

# First, get an access token (using blank credentials for testing)
TOKEN=$(curl -k -s -X POST "https://localhost:8443/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"","password":""}' | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
    echo "Failed to get access token"
    exit 1
fi

echo "Got access token: ${TOKEN:0:20}..."

# Test getting all pods
echo "Testing /api/cluster/pods..."
RESPONSE=$(curl -k -s -H "Authorization: Bearer $TOKEN" "https://localhost:8443/api/cluster/pods")
echo "Response: $RESPONSE"

# Test getting pods from default namespace
echo "Testing /api/cluster/pods?namespace=default..."
RESPONSE_NS=$(curl -k -s -H "Authorization: Bearer $TOKEN" "https://localhost:8443/api/cluster/pods?namespace=default")
echo "Response: $RESPONSE_NS"

echo "Pod management API test completed."