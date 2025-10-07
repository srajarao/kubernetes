# K3s Installation Configuration
# Set to true to install the respective components

# Install K3s server on tower
INSTALL_SERVER=true

# Install K3s agent on nano
INSTALL_NANO_AGENT=true

# Install K3s agent on agx
INSTALL_AGX_AGENT=true

# IP addresses
TOWER_IP="192.168.10.1"
NANO_IP="192.168.5.21"
AGX_IP="192.168.10.11"

# Registry settings
REGISTRY_IP="192.168.10.1"
REGISTRY_PORT="5000"