import subprocess
import json

try:
    result = subprocess.run(['kubectl', 'get', 'nodes', '-o', 'json'], capture_output=True, text=True, timeout=10)
    print('kubectl return code:', result.returncode)
    if result.returncode == 0:
        nodes_data = json.loads(result.stdout)
        node_count = len(nodes_data.get('items', []))
        print('Node count:', node_count)

        pod_result = subprocess.run(['kubectl', 'get', 'pods', '--all-namespaces', '-o', 'json'], capture_output=True, text=True, timeout=10)
        pod_count = 0
        if pod_result.returncode == 0:
            pods_data = json.loads(pod_result.stdout)
            pod_count = len(pods_data.get('items', []))
        print('Pod count:', pod_count)

        data = {'status': 'Healthy', 'nodes': node_count, 'pods': pod_count}
        print('Data:', data)
    else:
        print('kubectl error:', result.stderr)
except Exception as e:
    print('Exception:', e)