#!/usr/bin/env bash
set -euo pipefail

LOCATION="${LOCATION:-eastus}"
PROJECT_NAME="${PROJECT_NAME:-rest-soap-labs}"
RESOURCE_GROUP="${RESOURCE_GROUP:-rg-${PROJECT_NAME}}"
ENVIRONMENT_NAME="${ENVIRONMENT_NAME:-cae-${PROJECT_NAME}}"
CONTAINER_APP_NAME="${CONTAINER_APP_NAME:-ca-${PROJECT_NAME}}"
ACR_NAME="${ACR_NAME:-restsoaplabs}"
IMAGE_NAME="${IMAGE_NAME:-${PROJECT_NAME}}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
IMAGE_URI="${ACR_NAME}.azurecr.io/${IMAGE_NAME}:${IMAGE_TAG}"
IMAGE_PLATFORM="${IMAGE_PLATFORM:-linux/amd64}"
MIN_REPLICAS="${MIN_REPLICAS:-1}"
MAX_REPLICAS="${MAX_REPLICAS:-1}"
CONTAINER_CPU="${CONTAINER_CPU:-2.0}"
CONTAINER_MEMORY="${CONTAINER_MEMORY:-4Gi}"

echo "Configuration:"
echo "  PROJECT_NAME=${PROJECT_NAME}"
echo "  RESOURCE_GROUP=${RESOURCE_GROUP}"
echo "  ENVIRONMENT_NAME=${ENVIRONMENT_NAME}"
echo "  CONTAINER_APP_NAME=${CONTAINER_APP_NAME}"
echo "  ACR_NAME=${ACR_NAME}"
echo "  IMAGE_URI=${IMAGE_URI}"
echo "  IMAGE_PLATFORM=${IMAGE_PLATFORM}"
echo "  MIN_REPLICAS=${MIN_REPLICAS}"
echo "  MAX_REPLICAS=${MAX_REPLICAS}"
echo "  CONTAINER_CPU=${CONTAINER_CPU}"
echo "  CONTAINER_MEMORY=${CONTAINER_MEMORY}"

az group create --name "${RESOURCE_GROUP}" --location "${LOCATION}" >/dev/null
az acr create --resource-group "${RESOURCE_GROUP}" --name "${ACR_NAME}" --sku Basic >/dev/null 2>&1 || true
az acr update --name "${ACR_NAME}" --admin-enabled true >/dev/null
az acr login --name "${ACR_NAME}"
ACR_USERNAME="$(az acr credential show --name "${ACR_NAME}" --query username -o tsv)"
ACR_PASSWORD="$(az acr credential show --name "${ACR_NAME}" --query passwords[0].value -o tsv)"

docker buildx inspect "${PROJECT_NAME}-builder" >/dev/null 2>&1 || \
  docker buildx create --name "${PROJECT_NAME}-builder" --use >/dev/null
docker buildx use "${PROJECT_NAME}-builder"
docker buildx build --platform "${IMAGE_PLATFORM}" -t "${IMAGE_URI}" --push .

az containerapp env create \
  --name "${ENVIRONMENT_NAME}" \
  --resource-group "${RESOURCE_GROUP}" \
  --location "${LOCATION}" >/dev/null 2>&1 || true

az containerapp create \
  --name "${CONTAINER_APP_NAME}" \
  --resource-group "${RESOURCE_GROUP}" \
  --environment "${ENVIRONMENT_NAME}" \
  --image "${IMAGE_URI}" \
  --target-port 8089 \
  --ingress external \
  --min-replicas "${MIN_REPLICAS}" \
  --max-replicas "${MAX_REPLICAS}" \
  --cpu "${CONTAINER_CPU}" \
  --memory "${CONTAINER_MEMORY}" \
  --registry-server "${ACR_NAME}.azurecr.io" \
  --registry-username "${ACR_USERNAME}" \
  --registry-password "${ACR_PASSWORD}" \
  --env-vars SOAP_DAST_HOST=0.0.0.0 SOAP_DAST_VULN_PORT=8089 SOAP_DAST_VULN_PUBLIC_PORT=443

VULN_FQDN="$(az containerapp show --name "${CONTAINER_APP_NAME}" --resource-group "${RESOURCE_GROUP}" --query properties.configuration.ingress.fqdn -o tsv)"

az containerapp update \
  --name "${CONTAINER_APP_NAME}" \
  --resource-group "${RESOURCE_GROUP}" \
  --min-replicas "${MIN_REPLICAS}" \
  --max-replicas "${MAX_REPLICAS}" \
  --cpu "${CONTAINER_CPU}" \
  --memory "${CONTAINER_MEMORY}" \
  --set-env-vars SOAP_DAST_HOST=0.0.0.0 SOAP_DAST_PORT=8089 SOAP_DAST_PUBLIC_HOST="${VULN_FQDN}" SOAP_DAST_PUBLIC_PORT=443 SOAP_DAST_DB_PATH=/data/rest_soap_labs.db >/dev/null

az containerapp ingress sticky-sessions set \
  --name "${CONTAINER_APP_NAME}" \
  --resource-group "${RESOURCE_GROUP}" \
  --affinity sticky >/dev/null

echo "Sticky sessions are enabled. SQLite uses /tmp by default; use an external database for true cross-replica persistence."

echo "App URL:"
echo "https://${VULN_FQDN}/soap?wsdl"
echo "REST Swagger:"
echo "https://${VULN_FQDN}/swagger/rest.json"
echo "XML/SOAP Swagger:"
echo "https://${VULN_FQDN}/swagger/xml.json"
