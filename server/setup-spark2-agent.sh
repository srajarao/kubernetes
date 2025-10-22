#!/bin/bash

echo "🚀 SPARK2 Agent Setup from Tower"
echo "================================="

# Configuration
SPARK2_IP="10.1.10.202"
SSH_USER="sanjay"
SSH_KEY="$HOME/.ssh/id_ed25519"
SSH_OPTS="-o StrictHostKeyChecking=no -o LogLevel=ERROR -i $SSH_KEY"
SSH_CMD="ssh $SSH_OPTS"
SCP_CMD="scp $SSH_OPTS"

echo ""
echo "Step 1: Copying agent setup script to SPARK2..."
if $SCP_CMD ../agent/spark2/k3s-spark2-agent-setup.sh $SSH_USER@$SPARK2_IP:~/; then
    echo "✅ Script copied successfully"
else
    echo "❌ Failed to copy script"
    exit 1
fi

echo ""
echo "Step 2: Running agent setup on SPARK2..."
echo "      (This may take several minutes...)"
if $SSH_CMD $SSH_USER@$SPARK2_IP "chmod +x k3s-spark2-agent-setup.sh && ./k3s-spark2-agent-setup.sh"; then
    echo "✅ Agent setup completed successfully"
else
    echo "❌ Agent setup failed"
    exit 1
fi

echo ""
echo "🎉 SPARK2 is now joined to the K3s cluster!"
echo ""
echo "Next steps:"
echo "1. Verify SPARK2 appears in cluster: kubectl get nodes"
echo "2. Deploy services to SPARK2: kubectl apply -f ../agent/spark2/fastapi-deployment-spark2.yaml"