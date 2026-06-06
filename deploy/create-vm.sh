#!/usr/bin/env bash
# create-vm.sh — provision a GCP e2-small for a StealthOps training deployment
#
# Usage:
#   bash deploy/create-vm.sh <deployment-name> <project-id> [zone]
#
# Examples:
#   bash deploy/create-vm.sh us   my-gcp-project us-central1-a
#   bash deploy/create-vm.sh bw   my-gcp-project africa-south1-a
#
# Zone defaults to us-central1-a if omitted.
# Region is derived automatically from the zone (everything before the last -X).
#
# This script:
#   1. Creates an e2-small VM with an ephemeral IP in the requested zone
#   2. Opens firewall rules for HTTP and HTTPS (idempotent, safe to re-run)
#   3. Prints the external IP and the exact next steps
#
# After running:
#   - Add DNS A record at Cloudflare:  <name>.stealthops.dev → <IP>
#     Proxy: DNS only (grey cloud) while certbot runs, switch after if desired
#   - Wait ~60s for DNS to propagate, SSH in, run vm-setup.sh
#   - Tear down: gcloud compute instances delete stealthops-<name> --zone=<zone>
#   - Remove the DNS A record at Cloudflare (IP is ephemeral, won't be reused)

set -euo pipefail

DEPLOYMENT="${1:-}"
PROJECT="${2:-}"
ZONE="${3:-us-central1-a}"

if [[ -z "$DEPLOYMENT" || -z "$PROJECT" ]]; then
    echo "usage: bash deploy/create-vm.sh <deployment-name> <project-id> [zone]"
    echo "  e.g. bash deploy/create-vm.sh us  my-gcp-project us-central1-a"
    echo "       bash deploy/create-vm.sh bw  my-gcp-project africa-south1-a"
    exit 1
fi

# Derive region from zone: strip the trailing -<letter>
REGION="${ZONE%-*}"
INSTANCE="stealthops-${DEPLOYMENT}"
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
# Rules are project-wide and idempotent — safe to re-run across deployments
gcloud compute firewall-rules create stealthops-allow-http \
    --project="$PROJECT" \
    --allow=tcp:80 \
    --target-tags=stealthops-web \
    --description="StealthOps: allow HTTP for certbot ACME challenge" \
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
echo "  VM created:   $INSTANCE"
echo "  Zone:         $ZONE"
echo "  External IP:  $EXTERNAL_IP  (ephemeral — update DNS if VM restarts)"
echo "==========================================================="
echo ""
echo "Next steps:"
echo ""
echo "  1. Add a DNS A record at Cloudflare:"
echo "       Name:    $DEPLOYMENT"
echo "       Type:    A"
echo "       Value:   $EXTERNAL_IP"
echo "       Proxy:   DNS only (grey cloud) — certbot needs direct TCP on port 80"
echo ""
echo "  2. Wait ~60 seconds for DNS to propagate, then verify:"
echo "       nslookup $FQDN"
echo ""
echo "  3. SSH into the VM:"
echo "       gcloud compute ssh $INSTANCE --project=$PROJECT --zone=$ZONE"
echo ""
echo "  4. On the VM, clone the repo and run setup:"
echo "       git clone https://github.com/presack/StealthOps.git"
echo "       cd StealthOps"
echo "       cp .env.example .env && nano .env   # fill in keys + auth credentials"
echo "       bash deploy/vm-setup.sh $FQDN you@example.com"
echo ""
echo "  5. To tear down when done:"
echo "       gcloud compute instances delete $INSTANCE --project=$PROJECT --zone=$ZONE"
echo "       (then remove the DNS A record at Cloudflare)"
