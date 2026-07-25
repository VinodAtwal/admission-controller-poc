#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

# Define directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
DEPLOY_DIR="${PROJECT_DIR}/deploy"

cd "${SCRIPT_DIR}"

echo "=== Generating TLS certificates for the Webhook ==="

# 1. Create a clean environment
rm -f ca.key ca.crt server.key server.csr server.crt server.conf

# 2. Generate CA Private Key and Certificate
echo "Generating CA..."
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -subj "/CN=Admission Controller CA" -days 365 -out ca.crt

# 3. Create OpenSSL configuration for server certificate with SAN
echo "Creating openssl config..."
cat <<EOF > server.conf
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
CN = secret-scanner-webhook-service.default.svc

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = secret-scanner-webhook-service
DNS.2 = secret-scanner-webhook-service.default
DNS.3 = secret-scanner-webhook-service.default.svc
DNS.4 = secret-scanner-webhook-service.default.svc.cluster.local
EOF

# 4. Generate Server Private Key and CSR
echo "Generating Server Key & CSR..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key -config server.conf -out server.csr

# 5. Sign Server CSR with CA
echo "Signing server certificate..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extensions v3_req -extfile server.conf

echo "=== Injecting CA Bundle into Kubernetes configurations ==="

# Get base64 encoded CA Bundle
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    CA_BUNDLE=$(cat ca.crt | base64 | tr -d '\n')
else
    # Linux / Git Bash / WS
    CA_BUNDLE=$(cat ca.crt | base64 -w0)
fi

# Reset configurations from templates if they contain actual base64 to avoid stacking replacements,
# or simply replace the placeholder. To make this script re-runnable, we check if CA_BUNDLE_PLACEHOLDER
# is still there. If not, we restore the original placeholder from git or just edit.
# A robust way is to make sure we have a clean copy, but since we are running locally,
# we can just use python to replace any old base64 or placeholder.
# Even simpler: we can keep the templates as mutating-webhook.yaml and validating-webhook.yaml
# and replace the placeholder. If the user reruns, they can reset with git checkout.

for file in "mutating-webhook.yaml" "validating-webhook.yaml"; do
    filepath="${DEPLOY_DIR}/${file}"
    if [ ! -f "${filepath}" ]; then
        echo "Error: ${filepath} not found"
        exit 1
    fi
    
    echo "Updating caBundle in ${file}..."
    
    # Use python for cross-platform in-place replacement
    python3 -c "
import sys
with open('${filepath}', 'r') as f:
    content = f.read()

# Replace either the placeholder or any previous 40+ char base64 string
import re
# Look for caBundle: followed by non-whitespace (either placeholder or base64)
new_content = re.sub(r'caBundle:\s*\S+', 'caBundle: ${CA_BUNDLE}', content)

with open('${filepath}', 'w') as f:
    f.write(new_content)
"
done

echo "=== Uploading certificates to Kubernetes as a Secret ==="
# Check if kubectl is available
if command -v kubectl &> /dev/null; then
    echo "Creating Kubernetes Secret: secret-scanner-webhook-certs..."
    kubectl delete secret secret-scanner-webhook-certs --ignore-not-found
    kubectl create secret tls secret-scanner-webhook-certs \
      --cert=server.crt \
      --key=server.key
    echo "Secret created successfully."
else
    echo "Warning: 'kubectl' command not found. Secret was not created."
    echo "Once kubectl is connected, you can run:"
    echo "  kubectl create secret tls secret-scanner-webhook-certs --cert=certs/server.crt --key=certs/server.key"
fi

echo "=== TLS Certificate Setup Complete ==="
