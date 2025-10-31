# Cluster Management Documentation

This directory contains comprehensive manual pages for the Cluster Management system.

## Directory Structure

```
man/
├── man_index.7          # Index of all manual pages
├── bootstrap_app.1      # Main application documentation
├── start_https.1        # HTTPS server setup
├── deploy_to_nano.1     # Remote deployment
├── k3s-server.1         # K3s server setup
├── k3s-agent-scripts.1  # Agent node configurations
├── utility-scripts.1    # System utilities
├── environment_variables.7  # Configuration reference
└── deployment_guide.7   # Complete deployment guide
```

## Accessing Documentation

### Web Interface
1. Start the cluster management application
2. Navigate to the **"📚 Wiki"** tab
3. Click on any documentation link to view the manual page

### Command Line
```bash
# View specific man page
man ./man/bootstrap_app.1

# Or set MANPATH
export MANPATH="$MANPATH:$(pwd)/man"
man bootstrap_app
```

### API Access
```bash
# Get man page content via API
curl -k https://localhost:8443/api/docs/man/bootstrap_app
```

## Manual Page Sections

- **Section 1**: User commands and applications
- **Section 7**: Miscellaneous information and reference

## Contributing

When adding new documentation:

1. Use standard man page formatting with groff/troff macros
2. Follow the naming convention: `name.section`
3. Update `man_index.7` with the new page
4. Test rendering: `man ./man/your_page.1`

## Key Documentation Areas

- **Deployment**: Complete setup instructions
- **Configuration**: Environment variables and settings
- **Operation**: Daily usage and maintenance
- **Troubleshooting**: Common issues and solutions
- **API Reference**: Programmatic access documentation

## Quick Start

1. **Deploy the system**: See `deployment_guide.7`
2. **Configure environment**: See `environment_variables.7`
3. **Set up K3s cluster**: See `k3s-server.1` and `k3s-agent-scripts.1`
4. **Start the application**: See `bootstrap_app.1` and `start_https.1`

For questions or issues, refer to the troubleshooting sections in each manual page.