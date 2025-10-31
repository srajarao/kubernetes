#!/usr/bin/env python3
import requests
import json
import sys
import os

# Add current directory to path
sys.path.insert(0, os.getcwd())

# Import the app to test directly
from bootstrap_app import app
from fastapi.testclient import TestClient

def test_network_api():
    client = TestClient(app)

    # Test GET /api/network/devices
    response = client.get('/api/network/devices')
    print(f"GET /api/network/devices - Status: {response.status_code}")

    if response.status_code == 200:
        data = response.json()
        print("✅ API working!")
        devices = data.get('devices', {})
        print(f"Found {len(devices)} devices:")

        for key, device in devices.items():
            print(f"  - {key}: {device.get('name', 'Unknown')} ({device.get('type', 'Unknown')}) - {device.get('ip', 'No IP')}")

        # Test device types
        device_types = data.get('device_types', {})
        print(f"Found {len(device_types)} device types:")
        for type_key, type_info in device_types.items():
            print(f"  - {type_key}: {type_info.get('name', 'Unknown')} {type_info.get('icon', '')}")

    else:
        print(f"❌ API error: {response.status_code}")
        print(response.text)

if __name__ == "__main__":
    test_network_api()