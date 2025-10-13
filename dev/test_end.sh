  STEP=$((26 + 3))
  echo -n "{s} [tower] [$TOWER_IP] 26/25. Deploying PgAdmin secret... "
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /home/sanjay/containers/kubernetes/server/pgadmin/pgadmin-secret.yaml > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
  STEP=$((27 + 3))
  echo -n "{s} [tower] [$TOWER_IP] 27/25. Deploying PgAdmin... "
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /home/sanjay/containers/kubernetes/server/pgadmin/pgadmin-deployment.yaml > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi

STEP=$((27 + 3))

# Apply NodePort services
if [ "$DEBUG" = "1" ]; then
  echo "Applying NodePort services..."
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /home/sanjay/containers/kubernetes/server/postgres-pgadmin-nodeport-services.yaml
else
  STEP=$((28 + 3))
  echo -n "{s} [tower] [$TOWER_IP] 28/25. Applying NodePort services... "
  sleep 5
  if sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml apply -f /home/sanjay/containers/kubernetes/server/postgres-pgadmin-nodeport-services.yaml > /dev/null 2>&1; then
    echo -e "\033[32m✅\033[0m"
  else
    echo -e "\033[31m❌\033[0m"
    exit 1
  fi
fi

# Final validation
if [ "$DEBUG" = "1" ]; then
  echo "Reviewing and Validating Implementation..."
  sleep 5
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get nodes
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -o wide
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml describe node nano | grep -A 5 Capacity
  curl http://$NANO_IP:30002/health
  curl http://$TOWER_IP:30080
  POD_NAME=$(sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods -l app=fastapi-nano -o jsonpath='{.items[0].metadata.name}')
  sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml exec $POD_NAME -- nvidia-smi 2>/dev/null
fi






