#!/usr/bin/env bash
# vm-setup.sh — bootstrap a fresh GCP e2-small (Debian/Ubuntu) for StealthOps
#
# Usage:
#   bash deploy/vm-setup.sh <fqdn> <email>
#
# Example:
#   bash deploy/vm-setup.sh botswana.stealthops.dev you@example.com
#
# Prerequisites:
#   - DNS A record for <fqdn> already points to this VM's external IP
#   - Firewall allows inbound 80 and 443 (GCP: add rules or use --tags)
#   - .env file present in the repo root (copy from .env.example and fill in)
#
# The script is idempotent: safe to re-run if something fails partway through.

set -euo pipefail

FQDN="${1:-}"
EMAIL="${2:-}"

if [[ -z "$FQDN" || -z "$EMAIL" ]]; then
    echo "usage: bash deploy/vm-setup.sh <fqdn> <certbot-email>"
    echo "  e.g. bash deploy/vm-setup.sh botswana.stealthops.dev you@example.com"
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> [1/6] Installing system packages"
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg lsb-release \
    nginx certbot python3-certbot-nginx

echo "==> [2/6] Installing Docker"
if ! command -v docker &>/dev/null; then
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker "$USER"
    echo "     Docker installed. You may need to log out and back in for"
    echo "     group membership to take effect; using sudo docker for now."
fi

if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null 2>&1; then
    sudo apt-get install -y docker-compose-plugin
fi

echo "==> [3/6] Configuring nginx for $FQDN"
sudo sed "s/FQDN/$FQDN/g" "$REPO_ROOT/deploy/nginx.conf" \
    > /tmp/stealthops-nginx.conf
sudo cp /tmp/stealthops-nginx.conf /etc/nginx/sites-available/stealthops
sudo ln -sf /etc/nginx/sites-available/stealthops \
            /etc/nginx/sites-enabled/stealthops
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx

echo "==> [4/6] Issuing TLS certificate for $FQDN"
# Certbot will update /etc/nginx/sites-available/stealthops with the
# ssl_certificate directives and reload nginx automatically.
sudo certbot --nginx -d "$FQDN" --non-interactive --agree-tos \
    --email "$EMAIL" --redirect

echo "==> [5/6] Creating cache volume directory"
sudo mkdir -p /data/cache
sudo chown "$USER:$USER" /data/cache

echo "==> [6/6] Starting StealthOps container"
if [[ ! -f "$REPO_ROOT/.env" ]]; then
    echo "ERROR: $REPO_ROOT/.env not found."
    echo "  Copy .env.example to .env, fill in API keys and auth credentials,"
    echo "  then re-run this script."
    exit 1
fi

cd "$REPO_ROOT"
sudo docker compose pull 2>/dev/null || true
sudo docker compose up -d --build

echo ""
echo "==> Done. StealthOps is live at https://$FQDN"
echo "    Monitor logs:  sudo docker compose logs -f"
echo "    Stop:          sudo docker compose down"
echo "    Rebuild:       sudo docker compose up -d --build"
