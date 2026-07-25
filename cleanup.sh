#!/usr/bin/env bash

# Color variables for nice formatting
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0;0m' # No Color

echo -e "${BLUE}===============================================${NC}"
echo -e "${BLUE}    Admission Controller Cleanup Script        ${NC}"
echo -e "${BLUE}===============================================${NC}"

# Check kubectl connectivity
if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}Warning: kubectl command not found. Skipping Kubernetes resource deletion.${NC}"
else
    if kubectl cluster-info &> /dev/null; then
        echo -e "${YELLOW}Deleting Kubernetes resources...${NC}"
        
        # Delete Webhook Configurations
        kubectl delete mutatingwebhookconfiguration secret-scanner-mutating-webhook --ignore-not-found
        kubectl delete validatingwebhookconfiguration secret-scanner-validating-webhook --ignore-not-found
        
        # Delete Service & Deployment
        kubectl delete service secret-scanner-webhook-service --ignore-not-found
        kubectl delete deployment secret-scanner-webhook --ignore-not-found
        
        # Delete Secret
        kubectl delete secret secret-scanner-webhook-certs --ignore-not-found
        
        # Delete Test Pods
        kubectl delete pod test-pod-safe --ignore-not-found
        kubectl delete pod test-pod-unsafe --ignore-not-found
        
        echo -e "${GREEN}Kubernetes resources deleted successfully.${NC}"
    else
        echo -e "${RED}Warning: Unable to connect to Kubernetes cluster. Skipping Kubernetes resource deletion.${NC}"
    fi
fi

# Clean up local cert files
echo -e "${YELLOW}Cleaning up local certificate files...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rm -f "${SCRIPT_DIR}/certs/ca.key" \
      "${SCRIPT_DIR}/certs/ca.crt" \
      "${SCRIPT_DIR}/certs/ca.srl" \
      "${SCRIPT_DIR}/certs/server.key" \
      "${SCRIPT_DIR}/certs/server.csr" \
      "${SCRIPT_DIR}/certs/server.crt" \
      "${SCRIPT_DIR}/certs/server.conf"

# Restore original placeholders in webhook files if needed
echo -e "${YELLOW}Restoring templates placeholders in deploy configs...${NC}"
DEPLOY_DIR="${SCRIPT_DIR}/deploy"
for file in "mutating-webhook.yaml" "validating-webhook.yaml"; do
    filepath="${DEPLOY_DIR}/${file}"
    if [ -f "${filepath}" ]; then
        python3 -c "
import sys
with open('${filepath}', 'r') as f:
    content = f.read()

import re
# Reset the caBundle to the placeholder
new_content = re.sub(r'caBundle:\s*\S+', 'caBundle: CA_BUNDLE_PLACEHOLDER', content)

with open('${filepath}', 'w') as f:
    f.write(new_content)
"
    fi
done

echo -e "\n${GREEN}===============================================${NC}"
echo -e "${GREEN}      Cleanup Completed Successfully!          ${NC}"
echo -e "${GREEN}===============================================${NC}"
