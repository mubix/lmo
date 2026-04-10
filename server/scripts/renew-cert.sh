#!/usr/bin/env bash
# Manual certificate renewal + reload
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "run as root"; exit 1; }

DOMAIN="${1:-}"
if [[ -n "$DOMAIN" ]]; then
    certbot renew --cert-name "$DOMAIN" --force-renewal
else
    certbot renew --force-renewal
fi

# SIGHUP triggers cert reload without restart
kill -HUP "$(pidof letmeout)" 2>/dev/null || systemctl restart letmeout
echo "[+] certificate renewed, letmeout reloaded"
