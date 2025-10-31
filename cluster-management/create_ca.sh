#!/bin/bash

# Generate Certificate Authority and Sign Server Certificate
# This creates a proper CA that can be imported into browsers

echo "🔐 Creating Certificate Authority for Cluster Management"
echo "======================================================="

cd /home/sanjay/containers/kubernetes/cluster-management/ca

# Generate CA private key
echo "📝 Generating CA private key..."
openssl genrsa -out ca.key 2048

# Generate CA certificate
echo "📄 Generating CA certificate..."
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -out ca.crt \
  -subj "/C=US/ST=CA/L=San Francisco/O=Kubernetes Cluster Management CA/CN=Cluster Management Root CA"

# Generate server private key
echo "🔑 Generating server private key..."
openssl genrsa -out server.key 2048

# Generate certificate signing request (CSR)
echo "📋 Generating certificate signing request..."
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=CA/L=San Francisco/O=Kubernetes Cluster Management/CN=cluster-management.local"

# Create extensions file for SAN (Subject Alternative Name)
cat > server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = cluster-management.local
DNS.2 = localhost
IP.1 = 192.168.1.181
IP.2 = 127.0.0.1
EOF

# Sign the server certificate with our CA
echo "✍️  Signing server certificate with CA..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -sha256 \
  -extfile server.ext

# Copy certificates to ssl directory
echo "📁 Copying certificates to ssl directory..."
cp server.crt ../ssl/cert.pem
cp server.key ../ssl/key.pem
cp ca.crt ../ssl/ca.crt

echo ""
echo "✅ Certificate Authority Created Successfully!"
echo "=============================================="
echo ""
echo "📄 CA Certificate: ca/ca.crt (Import this into Firefox)"
echo "🔐 Server Certificate: ssl/cert.pem (Signed by our CA)"
echo "🔑 Server Key: ssl/key.pem"
echo ""
echo "🦊 Firefox Import Instructions:"
echo "1. Open Firefox Settings"
echo "2. Search for 'certificates'"
echo "3. Click 'View Certificates...'"
echo "4. Go to 'Authorities' tab"
echo "5. Click 'Import...'"
echo "6. Select 'ca/ca.crt'"
echo "7. Check 'Trust this CA to identify websites'"
echo "8. Click 'OK'"
echo ""
echo "🌐 After importing, visit: https://192.168.1.181:8443/"
echo "   (No more security warnings!)"