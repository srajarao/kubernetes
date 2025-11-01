import subprocess
import json
import os

print("Environment variables:")
for key in ['KUBECONFIG', 'HOME', 'PATH']:
    print(f"{key}: {os.environ.get(key)}")

try:
    print("Running kubectl get nodes...")
    result = subprocess.run(['kubectl', 'get', 'nodes', '-o', 'json'],
                          capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
    print(f'Return code: {result.returncode}')
    if result.returncode == 0:
        print("Success!")
        nodes_data = json.loads(result.stdout)
        node_count = len(nodes_data.get('items', []))
        print(f'Node count: {node_count}')
    else:
        print(f'Error: {result.stderr}')
except Exception as e:
    print(f'Exception: {e}')