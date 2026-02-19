#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   bash deploy/gcp.sh <PROJECT_ID> [REGION] [SERVICE_NAME]
# Example:
#   bash deploy/gcp.sh my-gcp-project us-central1 stealthops

PROJECT_ID="${1:-}"
REGION="${2:-us-central1}"
SERVICE_NAME="${3:-stealthops}"
IMAGE="gcr.io/${PROJECT_ID}/${SERVICE_NAME}:latest"

if [[ -z "${PROJECT_ID}" ]]; then
  echo "error: project id is required"
  echo "usage: bash deploy/gcp.sh <PROJECT_ID> [REGION] [SERVICE_NAME]"
  exit 1
fi

echo "==> Setting gcloud project to ${PROJECT_ID}"
gcloud config set project "${PROJECT_ID}"

echo "==> Enabling required APIs"
gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com

echo "==> Building container image ${IMAGE}"
gcloud builds submit --tag "${IMAGE}" .

echo "==> Deploying Cloud Run service ${SERVICE_NAME} in ${REGION}"
gcloud run deploy "${SERVICE_NAME}" \
  --image "${IMAGE}" \
  --region "${REGION}" \
  --platform managed \
  --allow-unauthenticated \
  --port 8080 \
  --min-instances 0 \
  --max-instances 2

echo "==> Done. Service URL:"
gcloud run services describe "${SERVICE_NAME}" \
  --region "${REGION}" \
  --format='value(status.url)'

