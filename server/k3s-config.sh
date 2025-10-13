# k3s-config.sh

# K3s Installation Configuration
# Set to true to install the respective components

# Install K3s server on tower
INSTALL_SERVER=true # Set to true to allow server uninstall/install steps to run

# Install K3s agent on nano
INSTALL_NANO_AGENT=true

# Install K3s agent on agx
INSTALL_AGX_AGENT=true

# IP addresses
TOWER_IP="10.1.10.150"
NANO_IP="10.1.10.181"   # <-- Use the correct, reachable IP
AGX_IP="10.1.10.244"

# Registry settings
REGISTRY_IP="10.1.10.150"
REGISTRY_PORT="5000"

# Database Configuration
POSTGRES_PASSWORD="postgres"  # PostgreSQL admin password
PGADMIN_PASSWORD="pgadmin"          # pgAdmin default password
PGADMIN_EMAIL="pgadmin@pgadmin.org" # pgAdmin default email

# Debug mode (0 for silent, 1 for verbose)
DEBUG=0
