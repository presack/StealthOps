#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   bash deploy/azure.sh <RESOURCE_GROUP> [LOCATION] [APP_NAME] [ENV_NAME] [options]
# Example:
#   bash deploy/azure.sh rg-stealthops eastus stealthops stealthops-env
#
# Options:
#   --deploy-mode <source|image|local>   default: source
#   --image <IMAGE_REF>                  required when --deploy-mode image
#   --acr-name <ACR_NAME>                required when --deploy-mode local
#   --image-tag <TAG>                    optional when --deploy-mode local
#   --registry-server <SERVER>           optional for private registry image deploy
#   --registry-username <USERNAME>       optional for private registry image deploy
#   --registry-password <PASSWORD>       optional for private registry image deploy

RESOURCE_GROUP="${1:-}"
LOCATION="${2:-eastus}"
APP_NAME="${3:-stealthops}"
ENV_NAME="${4:-stealthops-env}"
shift $(( $# >= 4 ? 4 : $# ))

if [[ -z "${RESOURCE_GROUP}" ]]; then
  echo "error: resource group is required"
  echo "usage: bash deploy/azure.sh <RESOURCE_GROUP> [LOCATION] [APP_NAME] [ENV_NAME] [options]"
  exit 1
fi

DEPLOY_MODE="source"
IMAGE_REF=""
ACR_NAME=""
IMAGE_TAG=""
REGISTRY_SERVER=""
REGISTRY_USERNAME=""
REGISTRY_PASSWORD=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deploy-mode)
      DEPLOY_MODE="${2:-}"
      shift 2
      ;;
    --image)
      IMAGE_REF="${2:-}"
      shift 2
      ;;
    --acr-name)
      ACR_NAME="${2:-}"
      shift 2
      ;;
    --image-tag)
      IMAGE_TAG="${2:-}"
      shift 2
      ;;
    --registry-server)
      REGISTRY_SERVER="${2:-}"
      shift 2
      ;;
    --registry-username)
      REGISTRY_USERNAME="${2:-}"
      shift 2
      ;;
    --registry-password)
      REGISTRY_PASSWORD="${2:-}"
      shift 2
      ;;
    *)
      echo "error: unknown option: $1"
      exit 1
      ;;
  esac
done

if [[ "${DEPLOY_MODE}" != "source" && "${DEPLOY_MODE}" != "image" && "${DEPLOY_MODE}" != "local" ]]; then
  echo "error: --deploy-mode must be one of: source, image, local"
  exit 1
fi

if [[ "${DEPLOY_MODE}" == "image" && -z "${IMAGE_REF}" ]]; then
  echo "error: --image is required when --deploy-mode image"
  exit 1
fi

if [[ "${DEPLOY_MODE}" == "local" && -z "${ACR_NAME}" ]]; then
  echo "error: --acr-name is required when --deploy-mode local"
  exit 1
fi

if [[ -n "${REGISTRY_SERVER}" || -n "${REGISTRY_USERNAME}" || -n "${REGISTRY_PASSWORD}" ]]; then
  if [[ -z "${REGISTRY_SERVER}" || -z "${REGISTRY_USERNAME}" || -z "${REGISTRY_PASSWORD}" ]]; then
    echo "error: --registry-server, --registry-username, and --registry-password must be provided together"
    exit 1
  fi
fi

echo "==> Ensuring Azure Container Apps extension is installed"
az extension add --name containerapp --upgrade

echo "==> Registering providers (safe to run repeatedly)"
az provider register --namespace Microsoft.App --wait
az provider register --namespace Microsoft.OperationalInsights --wait

echo "==> Creating/updating resource group ${RESOURCE_GROUP}"
az group create --name "${RESOURCE_GROUP}" --location "${LOCATION}" >/dev/null

if az containerapp env show --name "${ENV_NAME}" --resource-group "${RESOURCE_GROUP}" >/dev/null 2>&1; then
  echo "==> Container Apps environment exists: ${ENV_NAME}"
else
  echo "==> Creating Container Apps environment ${ENV_NAME}"
  az containerapp env create \
    --name "${ENV_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --location "${LOCATION}" >/dev/null
fi

IMAGE_TO_DEPLOY=""
if [[ "${DEPLOY_MODE}" == "source" ]]; then
  echo "==> Deploying Container App ${APP_NAME} from source (uses ACR Tasks)"
  az containerapp up \
    --name "${APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --location "${LOCATION}" \
    --environment "${ENV_NAME}" \
    --source . \
    --ingress external \
    --target-port 8080
else
  if [[ "${DEPLOY_MODE}" == "local" ]]; then
    if ! command -v docker >/dev/null 2>&1; then
      echo "error: docker CLI not found. Install Docker and retry."
      exit 1
    fi
    if [[ -z "${IMAGE_TAG}" ]]; then
      IMAGE_TAG="$(date +%Y%m%d%H%M%S)"
    fi

    echo "==> Ensuring ACR exists: ${ACR_NAME}"
    if az acr show --name "${ACR_NAME}" --resource-group "${RESOURCE_GROUP}" >/dev/null 2>&1; then
      :
    else
      az acr create \
        --name "${ACR_NAME}" \
        --resource-group "${RESOURCE_GROUP}" \
        --location "${LOCATION}" \
        --sku Basic \
        --admin-enabled true >/dev/null
    fi

    echo "==> Logging into ACR ${ACR_NAME}"
    az acr login --name "${ACR_NAME}"

    IMAGE_TO_DEPLOY="${ACR_NAME}.azurecr.io/${APP_NAME}:${IMAGE_TAG}"
    echo "==> Building image locally: ${IMAGE_TO_DEPLOY}"
    docker build -t "${IMAGE_TO_DEPLOY}" .
    echo "==> Pushing image: ${IMAGE_TO_DEPLOY}"
    docker push "${IMAGE_TO_DEPLOY}"

    REGISTRY_SERVER="${ACR_NAME}.azurecr.io"
    REGISTRY_USERNAME="$(az acr credential show --name "${ACR_NAME}" --query username --output tsv)"
    REGISTRY_PASSWORD="$(az acr credential show --name "${ACR_NAME}" --query passwords[0].value --output tsv)"
  else
    IMAGE_TO_DEPLOY="${IMAGE_REF}"
  fi

  if az containerapp show --name "${APP_NAME}" --resource-group "${RESOURCE_GROUP}" >/dev/null 2>&1; then
    echo "==> Updating existing Container App ${APP_NAME} with image ${IMAGE_TO_DEPLOY}"
    az containerapp update \
      --name "${APP_NAME}" \
      --resource-group "${RESOURCE_GROUP}" \
      --image "${IMAGE_TO_DEPLOY}" >/dev/null
  else
    echo "==> Creating Container App ${APP_NAME} with image ${IMAGE_TO_DEPLOY}"
    create_args=(
      --name "${APP_NAME}"
      --resource-group "${RESOURCE_GROUP}"
      --environment "${ENV_NAME}"
      --image "${IMAGE_TO_DEPLOY}"
      --ingress external
      --target-port 8080
    )
    if [[ -n "${REGISTRY_SERVER}" ]]; then
      create_args+=(--registry-server "${REGISTRY_SERVER}")
      create_args+=(--registry-username "${REGISTRY_USERNAME}")
      create_args+=(--registry-password "${REGISTRY_PASSWORD}")
    fi
    az containerapp create "${create_args[@]}" >/dev/null
  fi
fi

echo "==> Done. App URL:"
az containerapp show \
  --name "${APP_NAME}" \
  --resource-group "${RESOURCE_GROUP}" \
  --query properties.configuration.ingress.fqdn \
  --output tsv
