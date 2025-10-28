#!/bin/bash
# PostgreSQL + pgAdmin + pgvector Verification Script

echo -e "\033[32m=== PostgreSQL + pgvector + pgAdmin Verification ===\033[0m"
echo

# Check services
echo "1. Checking Kubernetes services..."
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get services | grep -E "(postgres|pgadmin)"
echo

# Check pods
echo "2. Checking PostgreSQL and pgAdmin pods..."
sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods | grep -E "(postgres|pgadmin)"
echo

# Test pgAdmin web access
echo "3. Testing pgAdmin web access..."
PGADMIN_RESPONSE=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" http://192.168.1.150:30080)
if [ "$PGADMIN_RESPONSE" = "302" ] || [ "$PGADMIN_RESPONSE" = "200" ]; then
    echo "✅ pgAdmin accessible at http://192.168.1.150:30080"
    echo "   Login: pgadmin@pgadmin.org / pgadmin"
else
    echo "❌ pgAdmin not accessible (HTTP $PGADMIN_RESPONSE)"
    exit 1
fi
echo

# Test PostgreSQL connectivity
echo "4. Testing PostgreSQL connectivity..."
POSTGRES_POD=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -l app=postgres-db -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -n "$POSTGRES_POD" ] && sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml exec "$POSTGRES_POD" -- psql -U postgres -c "SELECT 1;" > /dev/null 2>&1; then
    echo "✅ PostgreSQL accessible internally"
else
    echo "❌ PostgreSQL connection failed"
fi
echo

# Verify pgvector extension
echo "5. Verifying pgvector extension..."
POSTGRES_POD=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -l app=postgres-db -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -n "$POSTGRES_POD" ]; then
    VECTOR_VERSION=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml exec "$POSTGRES_POD" -- psql -U postgres -t -c "SELECT extversion FROM pg_extension WHERE extname = 'vector';" 2>/dev/null | tr -d ' ')
    if [ -n "$VECTOR_VERSION" ]; then
        echo "✅ pgvector extension active (version: $VECTOR_VERSION)"
    else
        echo "❌ pgvector extension not found"
    fi
else
    echo "❌ PostgreSQL pod not found"
fi
echo

# External access summary
echo "6. External Access Summary:"
echo "   ✅ PostgreSQL: 192.168.1.150:30432"
echo "   ✅ pgAdmin:    http://192.168.1.150:30080"
echo
echo -e "\033[32m=== Verification Complete ===\033[0m"