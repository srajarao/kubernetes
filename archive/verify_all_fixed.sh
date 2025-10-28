#!/bin/bash

# Comprehensive Pod Verification Script
# Tests all deployed services and endpoints

echo "🔍 COMPREHENSIVE POD VERIFICATION REPORT"
echo "=========================================="
echo ""

# Function to test HTTP endpoints
test_http_endpoint() {
    local name=$1
    local url=$2
    local expected_code=${3:-200}

    echo -n "Testing $name ($url)... "
    response=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)

    if [ "$response" = "$expected_code" ] || ([ "$expected_code" = "200|302" ] && ([ "$response" = "200" ] || [ "$response" = "302" ])); then
        echo "✅ PASS (HTTP $response)"
        return 0
    else
        echo "❌ FAIL (HTTP $response)"
        return 1
    fi
}

# Function to test database connectivity
test_db_connection() {
    local name=$1
    local host=$2
    local port=$3
    local db=$4
    local user=$5
    local password=$6

    echo -n "Testing $name (PostgreSQL $host:$port)... "
    if PGPASSWORD="$password" psql -h "$host" -p "$port" -U "$user" -d "$db" -c "SELECT 1;" >/dev/null 2>&1; then
        echo "✅ PASS"
        return 0
    else
        echo "❌ FAIL"
        return 1
    fi
}

echo "📦 POD STATUS:"
echo "--------------"
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide
echo ""

echo "🌐 SERVICE ENDPOINTS:"
echo "---------------------"

# Test PostgreSQL database connectivity (not HTTP)
test_db_connection "PostgreSQL Database" "192.168.1.150" "30432" "postgres" "postgres" "postgres"

# Test pgAdmin (302 redirect is normal - redirects to login)
test_http_endpoint "pgAdmin Web UI" "http://192.168.1.150:30080" "200|302"

# Test Nano FastAPI endpoints
test_http_endpoint "Nano FastAPI Health" "http://192.168.1.150:30002/health"
test_http_endpoint "Nano FastAPI Docs" "http://192.168.1.150:30002/docs"
test_http_endpoint "Nano Jupyter" "http://192.168.1.150:30003/jupyter" "200|302"

# Test AGX FastAPI endpoints
test_http_endpoint "AGX FastAPI Health" "http://192.168.1.150:30004/health"
test_http_endpoint "AGX FastAPI Status" "http://192.168.1.150:30004/status"
test_http_endpoint "AGX FastAPI Docs" "http://192.168.1.150:30004/docs"
test_http_endpoint "AGX Jupyter" "http://192.168.1.150:30005/jupyter" "200|302"

# Test Spark1 FastAPI endpoints
test_http_endpoint "Spark1 FastAPI Health" "http://192.168.1.150:30007/health"
test_http_endpoint "Spark1 FastAPI Docs" "http://192.168.1.150:30007/docs"
test_http_endpoint "Spark1 Jupyter" "http://192.168.1.150:30008/jupyter" "200|302"

# Note: AGX LLM API (port 30006) and Spark1 LLM API (port 30009) are not implemented yet
echo "Testing AGX LLM API (http://192.168.1.150:30006/docs)... ⚠️  SKIP (Not implemented)"
echo "Testing Spark1 LLM API (http://192.168.1.150:30009/docs)... ⚠️  SKIP (Not implemented)"

echo ""

echo "🔧 CLUSTER HEALTH:"
echo "------------------"
echo "Node Status:"
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes
echo ""

echo "Service Status:"
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get services
echo ""

echo "✅ VERIFICATION COMPLETE"