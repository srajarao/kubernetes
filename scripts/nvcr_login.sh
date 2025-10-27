#!/bin/bash
# This script logs into the NVIDIA Container Registry (nvcr.io)
# It is intended to be sourced or executed to authenticate the docker client.

# It is recommended to replace the API key with a more secure method of authentication in a production environment.
# For example, using a secret management tool.

# IMPORTANT: Replace YOUR_API_KEY_HERE with your actual NGC API key.
NGC_API_KEY="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"

if [ "$NGC_API_KEY" == "YOUR_API_KEY_HERE" ]; then
    echo "Please edit this script and replace YOUR_API_KEY_HERE with your NGC API key."
    exit 1
fi

echo "$NGC_API_KEY" | docker login nvcr.io --username '$oauthtoken' --password-stdin
