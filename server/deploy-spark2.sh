#!/bin/bash

echo "Starting SPARK2 deployment..."

echo "Step 1: Copying agent setup script to SPARK2..."
scp -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 ../agent/spark2/k3s-spark2-agent-setup.sh sanjay@10.1.10.202:~/
if [ $? -eq 0 ]; then
    echo "✅ Script copied successfully"
else
    echo "❌ Failed to copy script"
    exit 1
fi

echo "Step 2: Running agent setup on SPARK2..."
ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i ~/.ssh/id_ed25519 sanjay@10.1.10.202 "chmod +x k3s-spark2-agent-setup.sh && ./k3s-spark2-agent-setup.sh"
if [ $? -eq 0 ]; then
    echo "✅ Agent setup completed"
else
    echo "❌ Agent setup failed"
    exit 1
fi

echo "🎉 SPARK2 deployment completed!"
