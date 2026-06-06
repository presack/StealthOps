#!/usr/bin/env bash
# create-vm.sh — provision a GCP e2-small for a StealthOps training deployment
#
# Usage:
#   bash deploy/create-vm.sh <deployment-name> <project-id>
#
# Example:
#   bash deploy/create-vm.sh botswana my-gcp-project
#
# This script:
#   1. Creates an e2-small VM in africa-south1 (Johannesburg)
#   2. Opens firewall rules for HTTP and HTTPS
#   3. Prints the external IP and the exact next steps
#
# After running:
#   - Add DNS A record at Cloudflare:  <deployment>.stealthops.dev → <IP>
#   - Wait ~60s for DNS to propagate, then SSH in and run vm-setup.sh
#   - Tear down when done:  gcloud compute instances delete stealthops-<deployment>

set -euo pipefail

DEPLOYMENT="${1:-}"
PROJECT="${2:-}"

if [[ -z "$DEPLOYMENT" || -z "$PROJECT" ]]; then
    echo "usage: bash deploy/create-vm.sh <deployment-name> <project-id>"
    echo "  e.g. bash deploy/create-vm.sh botswana my-gcp-project"
    exit 1
fi

INSTANCE="stealthops-${DEPLOYMENT}"
ZONE="africa-south1-a"
REGION="africa-south1"
MACHINE="e2-small"
DISK_GB=20

echo "==> [1/3] Creating VM: $INSTANCE ($MACHINE, $ZONE)"
gcloud compute instances create "$INSTANCE" \
    --project="$PROJECT" \
    --zone="$ZONE" \
    --machine-type="$MACHINE" \
    --image-family=debian-12 \
    --image-project=debian-cloud \
    --boot-disk-size="${DISK_GB}GB" \
    --boot-disk-type=pd-standard \
    --tags=stealthops-web \
    --metadata=enable-oslogin=TRUE

echo "==> [2/3] Adding firewall rules (HTTP + HTTPS on tag stealthops-web)"
# Rules are idempotent — gcloud errors if already exists, redirect stderr
gcloud compute firewall-rules create stealthops-allow-http \
    --project="$PROJECT" \
    --allow=tcp:80 \
    --target-tags=stealthops-web \
    --description="StealthOps: allow HTTP for certbot challenge" \
    2>/dev/null || true

gcloud compute firewall-rules create stealthops-allow-https \
    --project="$PROJECT" \
    --allow=tcp:443 \
    --target-tags=stealthops-web \
    --description="StealthOps: allow HTTPS" \
    2>/dev/null || true

echo "==> [3/3] Fetching external IP"
EXTERNAL_IP=$(gcloud compute instances describe "$INSTANCE" \
    --project="$PROJECT" \
    --zone="$ZONE" \
    --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

FQDN="${DEPLOYMENT}.stealthops.dev"

echo ""
echo "==========================================================="
echo "  VM created: $INSTANCE"
echo "  External IP: $EXTERNAL_IP"
echo "==========================================================="
echo ""
echo "Next steps:"
echo ""
echo "  1. Add a DNS A record at Cloudflare:"
echo "       Name:    $DEPLOYMENT"
echo "       Type:    A"
echo "       Value:   $EXTERNAL_IP"
echo "       Proxy:   DNS only (grey cloud) — certbot needs direct TCP"
echo ""
echo "  2. Wait ~60 seconds for DNS to propagate, then verify:"
echo "       nslookup $FQDN"
echo ""
echo "  3. Push your repo and SSH into the VM:"
echo "       gcloud compute ssh $INSTANCE --project=$PROJECT --zone=$ZONE"
echo ""
echo "  4. On the VM, clone the repo and run:"
echo "       git clone https://github.com/presack/StealthOps.git"
echo "       cd StealthOps"
echo "       cp .env.example .env && nano .env   # fill in keys"
echo "       bash deploy/vm-setup.sh $FQDN you@example.com"
echo ""
echo "  5. To tear down when the event is complete:"
echo "       gcloud compute instances delete $INSTANCE --project=$PROJECT --zone=$ZONE"
