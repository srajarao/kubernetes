# K3s Installation Configuration
# Set to true to install the respective components

# Install K3s server on tower
INSTALL_SERVER=false

# Install K3s agent on nano
INSTALL_NANO_AGENT=true

# Install K3s agent on agx
INSTALL_AGX_AGENT=true

# IP addresses
TOWER_IP="10.1.10.150"
NANO_IP="192.168.10.1"
AGX_IP="10.1.10.244"

# Registry settings
REGISTRY_IP="10.1.10.150"
REGISTRY_PORT="5000"