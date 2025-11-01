#!/bin/bash

# Move existing CA certificate to ssl directory
# This moves the existing ca.crt to the ssl directory for proper organization

echo "� Moving CA Certificate to SSL Directory"
echo "========================================"

# Check if ca.crt exists in current directory
if [ ! -f "ca.crt" ]; then
    echo "❌ Error: ca.crt not found in current directory"
    exit 1
fi

# Check if ssl directory exists, create if not
if [ ! -d "ssl" ]; then
    echo "📁 Creating ssl directory..."
    mkdir -p ssl
fi

# Move ca.crt to ssl directory
echo "📁 Moving ca.crt to ssl directory..."
mv ca.crt ssl/ca.crt

echo ""
echo "✅ CA Certificate Moved Successfully!"
echo "===================================="
echo ""
echo "📄 CA Certificate: ssl/ca.crt"
echo ""
echo "🦊 Firefox Import Instructions:"
echo "1. Open Firefox Settings"
echo "2. Search for 'certificates'"
echo "3. Click 'View Certificates...'"
echo "4. Go to 'Authorities' tab"
echo "5. Click 'Import...'"
echo "6. Select 'ssl/ca.crt'"
echo "7. Check 'Trust this CA to identify websites'"
echo "8. Click 'OK'"
echo ""
echo "🌐 After importing, visit: https://192.168.1.181:8443/"
echo "   (No more security warnings!)"