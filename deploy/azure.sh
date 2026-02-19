#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   bash deploy/azure.sh <RESOURCE_GROUP> [LOCATION] [APP_NAME] [ENV_NAME]
# Example:
#   bash deploy/azure.sh rg-stealthops eastus stealthops stealthops-env

RESOURCE_GROUP="${1:-}"
LOCATION="${2:-eastus}"
APP_NAME="${3:-stealthops}"
ENV_NAME="${4:-stealthops-env}"

if [[ -z "${RESOURCE_GROUP}" ]]; then
  echo "error: resource group is required"
  echo "usage: bash deploy/azure.sh <RESOURCE_GROUP> [LOCATION] [APP_NAME] [ENV_NAME]"
  exit 1
fi

echo "==> Ensuring Azure Container Apps extension is installed"
az extension add --name containerapp --upgrade

echo "==> Registering providers (safe to run repeatedly)"
az provider register --namespace Microsoft.App --wait
az provider register --namespace Microsoft.OperationalInsights --wait

echo "==> Creating/updating resource group ${RESOURCE_GROUP}"
az group create --name "${RESOURCE_GROUP}" --location "${LOCATION}" >/dev/null

echo "==> Deploying Container App ${APP_NAME}"
az containerapp up \
  --name "${APP_NAME}" \
  --resource-group "${RESOURCE_GROUP}" \
  --location "${LOCATION}" \
  --environment "${ENV_NAME}" \
  --source . \
  --ingress external \
  --target-port 8080

echo "==> Done. App URL:"
az containerapp show \
  --name "${APP_NAME}" \
  --resource-group "${RESOURCE_GROUP}" \
  --query properties.configuration.ingress.fqdn \
  --output tsv

