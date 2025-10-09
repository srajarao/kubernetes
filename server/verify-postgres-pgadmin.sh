#!/bin/bash
# PostgreSQL + pgAdmin + pgvector Verification Script

echo "=== PostgreSQL + pgvector + pgAdmin Verification ==="
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
PGADMIN_RESPONSE=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" http://10.1.10.150:30080)
if [ "$PGADMIN_RESPONSE" = "302" ] || [ "$PGADMIN_RESPONSE" = "200" ]; then
    echo "✅ pgAdmin accessible at http://10.1.10.150:30080"
    echo "   Login: pgadmin@pgadmin.org / pgadmin"
else
    echo "❌ pgAdmin not accessible (HTTP $PGADMIN_RESPONSE)"
    exit 1
fi
echo

# Test PostgreSQL connectivity
echo "4. Testing PostgreSQL connectivity..."
if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml exec deployment/postgres-db -- psql -U postgres -c "SELECT 1;" > /dev/null 2>&1; then
    echo "✅ PostgreSQL accessible internally"
else
    echo "❌ PostgreSQL connection failed"
fi
echo

# Verify pgvector extension
echo "5. Verifying pgvector extension..."
VECTOR_VERSION=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml exec deployment/postgres-db -- psql -U postgres -t -c "SELECT extversion FROM pg_extension WHERE extname = 'vector';" 2>/dev/null | tr -d ' ')
if [ -n "$VECTOR_VERSION" ]; then
    echo "✅ pgvector extension active (version: $VECTOR_VERSION)"
else
    echo "❌ pgvector extension not found"
fi
echo

# External access summary
echo "6. External Access Summary:"
echo "   PostgreSQL: 10.1.10.150:30432"
echo "   pgAdmin:    http://10.1.10.150:30080"
echo
echo "=== Verification Complete ==="