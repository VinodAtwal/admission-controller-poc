#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

# Color variables for nice formatting
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0;0m' # No Color

echo -e "${BLUE}===============================================${NC}"
echo -e "${BLUE}    Full Webhook Deployment Pipeline Started   ${NC}"
echo -e "${BLUE}===============================================${NC}"

# 1. Verification of environment
if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}Error: kubectl is not installed or not in PATH.${NC}"
    exit 1
fi

if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: docker is not installed or not running.${NC}"
    exit 1
fi

# Check K8s connection
if ! kubectl cluster-info &> /dev/null; then
    echo -e "${RED}Error: Cannot connect to Kubernetes cluster. Please start your cluster first.${NC}"
    exit 1
fi

# Detect Cluster type
CLUSTER_TYPE="generic"
NODE_NAME=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [[ "$NODE_NAME" == "docker-desktop" ]]; then
    CLUSTER_TYPE="docker-desktop"
    echo -e "${GREEN}Detected cluster type: Docker Desktop${NC}"
elif kubectl get nodes -o jsonpath='{.items[*].metadata.name}' | grep -q "minikube"; then
    CLUSTER_TYPE="minikube"
    echo -e "${GREEN}Detected cluster type: Minikube${NC}"
elif kubectl get nodes -o jsonpath='{.items[*].metadata.name}' | grep -q "kind-"; then
    CLUSTER_TYPE="kind"
    echo -e "${GREEN}Detected cluster type: Kind${NC}"
else
    echo -e "${YELLOW}Detected cluster type: Generic / External (${NODE_NAME})${NC}"
fi

# 2. Build Docker Image
IMAGE_NAME="secret-scanner-webhook:latest"
echo -e "\n${BLUE}[1/5] Building Docker Image: ${IMAGE_NAME}...${NC}"

if [[ "$CLUSTER_TYPE" == "minikube" ]]; then
    echo -e "${YELLOW}Configuring Docker environment for Minikube...${NC}"
    eval $(minikube docker-env)
fi

docker build -t ${IMAGE_NAME} .

# If Kind, we must load the image into the control plane
if [[ "$CLUSTER_TYPE" == "kind" ]]; then
    # Extract cluster name
    KIND_CLUSTER=$(kubectl config current-context | sed 's/kind-//')
    echo -e "${YELLOW}Loading image into Kind cluster '${KIND_CLUSTER}'...${NC}"
    kind load docker-image ${IMAGE_NAME} --name "${KIND_CLUSTER}"
fi

# 3. Generate TLS certificates and patch webhook configuration
echo -e "\n${BLUE}[2/5] Running TLS Certificate Setup...${NC}"
chmod +x certs/generate-certs.sh
./certs/generate-certs.sh

# 4. Deploying Webhook Components to Cluster
echo -e "\n${BLUE}[3/5] Deploying Webhook configurations to Kubernetes...${NC}"
kubectl apply -f deploy/deployment.yaml
kubectl apply -f deploy/service.yaml
kubectl apply -f deploy/mutating-webhook.yaml
kubectl apply -f deploy/validating-webhook.yaml

# 5. Wait for Webhook Deployment Rollout
echo -e "\n${BLUE}[4/5] Waiting for deployment rollout...${NC}"
kubectl rollout status deployment/secret-scanner-webhook --timeout=90s

# 6. Verify and Print Status
echo -e "\n${BLUE}[5/5] Deployment verification...${NC}"
PODS=$(kubectl get pods -l app=secret-scanner-webhook -o wide)
echo -e "${GREEN}Webhook Pod Status:${NC}"
echo "${PODS}"

echo -e "\n${GREEN}===============================================${NC}"
echo -e "${GREEN}      Deployment Completed Successfully!       ${NC}"
echo -e "${GREEN}===============================================${NC}"
echo -e "\nTo verify it works:"
echo -e "  1. Watch Webhook logs:  ${YELLOW}kubectl logs -l app=secret-scanner-webhook -f${NC}"
echo -e "  2. Test Mutation (Safe): ${YELLOW}kubectl apply -f deploy/test-pod-safe.yaml && kubectl get pod test-pod-safe --show-labels${NC}"
echo -e "  3. Test Block (Unsafe):   ${YELLOW}kubectl apply -f deploy/test-pod-unsafe.yaml${NC}"
echo -e "  4. Cleanup Test Pods:    ${YELLOW}kubectl delete pod test-pod-safe --ignore-not-found${NC}"
