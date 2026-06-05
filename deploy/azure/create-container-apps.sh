#!/usr/bin/env bash
set -euo pipefail

LOCATION="${LOCATION:-eastus}"
RESOURCE_GROUP="${RESOURCE_GROUP:-rg-soap-dast-lab}"
ENVIRONMENT_NAME="${ENVIRONMENT_NAME:-cae-soap-dast-lab}"
ACR_NAME="${ACR_NAME:-REPLACE_WITH_UNIQUE_ACR_NAME}"
IMAGE_NAME="${IMAGE_NAME:-soap-dast-lab}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
IMAGE_URI="${ACR_NAME}.azurecr.io/${IMAGE_NAME}:${IMAGE_TAG}"
IMAGE_PLATFORM="${IMAGE_PLATFORM:-linux/amd64}"

az group create --name "${RESOURCE_GROUP}" --location "${LOCATION}" >/dev/null
az acr create --resource-group "${RESOURCE_GROUP}" --name "${ACR_NAME}" --sku Basic >/dev/null 2>&1 || true
az acr update --name "${ACR_NAME}" --admin-enabled true >/dev/null
az acr login --name "${ACR_NAME}"
ACR_USERNAME="$(az acr credential show --name "${ACR_NAME}" --query username -o tsv)"
ACR_PASSWORD="$(az acr credential show --name "${ACR_NAME}" --query passwords[0].value -o tsv)"

docker buildx inspect soap-dast-lab-builder >/dev/null 2>&1 || \
  docker buildx create --name soap-dast-lab-builder --use >/dev/null
docker buildx use soap-dast-lab-builder
docker buildx build --platform "${IMAGE_PLATFORM}" -t "${IMAGE_URI}" --push .

az containerapp env create \
  --name "${ENVIRONMENT_NAME}" \
  --resource-group "${RESOURCE_GROUP}" \
  --location "${LOCATION}" >/dev/null 2>&1 || true

az containerapp create \
  --name soap-dast-lab-vulnerable \
  --resource-group "${RESOURCE_GROUP}" \
  --environment "${ENVIRONMENT_NAME}" \
  --image "${IMAGE_URI}" \
  --target-port 8089 \
  --ingress external \
  --registry-server "${ACR_NAME}.azurecr.io" \
  --registry-username "${ACR_USERNAME}" \
  --registry-password "${ACR_PASSWORD}" \
  --env-vars APP_MODE=vulnerable SOAP_DAST_HOST=0.0.0.0 SOAP_DAST_VULN_PORT=8089 SOAP_DAST_VULN_PUBLIC_PORT=443

VULN_FQDN="$(az containerapp show --name soap-dast-lab-vulnerable --resource-group "${RESOURCE_GROUP}" --query properties.configuration.ingress.fqdn -o tsv)"

az containerapp update \
  --name soap-dast-lab-vulnerable \
  --resource-group "${RESOURCE_GROUP}" \
  --set-env-vars APP_MODE=vulnerable SOAP_DAST_HOST=0.0.0.0 SOAP_DAST_VULN_PORT=8089 SOAP_DAST_PUBLIC_HOST="${VULN_FQDN}" SOAP_DAST_VULN_PUBLIC_PORT=443 >/dev/null

echo "Vulnerable app URL:"
echo "https://${VULN_FQDN}/soap?wsdl"
echo "REST Swagger:"
echo "https://${VULN_FQDN}/swagger/rest.json"
echo "XML/SOAP Swagger:"
echo "https://${VULN_FQDN}/swagger/xml.json"
