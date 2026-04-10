#!/usr/bin/env bash
# setup.sh — Automated setup for an egress filter testing server
#
# Installs a single Go binary that replaces sslh + nginx/apache + separate
# Go services. One process handles all protocols.
#
# Usage:
#   sudo ./setup.sh yourdomain.com
#   sudo ./setup.sh --dns digitalocean --admin-port 62222 yourdomain.com
#   sudo ./setup.sh --dns cloudflare --admin-port 62222 --admin-ip 1.2.3.4 yourdomain.com

set -euo pipefail

# ---------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------
DNS_PLUGIN="manual"
IFACE=""
DOMAIN=""
PUBLIC_IP=""
EMAIL=""
ADMIN_PORT="62222"
ADMIN_SOURCE=""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# SERVER_DIR is the parent of scripts/ — contains main.go, configs/, systemd/
SERVER_DIR="$(dirname "$SCRIPT_DIR")"

usage() {
    cat <<EOF
Usage: sudo $0 [OPTIONS] DOMAIN

Options:
  --dns PLUGIN          certbot DNS plugin (digitalocean, cloudflare, route53, manual)
  --iface IFACE         network interface (auto-detected if omitted)
  --ip IP               public IP (auto-detected if omitted)
  --email EMAIL         Let's Encrypt notification email
  --admin-port PORT     SSH port for admin access (default: 62222)
  --admin-ip IP         restrict admin SSH to this source IP (recommended)
  -h, --help            show this help
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --dns)         DNS_PLUGIN="$2"; shift 2 ;;
        --iface)       IFACE="$2"; shift 2 ;;
        --ip)          PUBLIC_IP="$2"; shift 2 ;;
        --email)       EMAIL="$2"; shift 2 ;;
        --admin-port)  ADMIN_PORT="$2"; shift 2 ;;
        --admin-ip)    ADMIN_SOURCE="$2"; shift 2 ;;
        -h|--help)     usage ;;
        -*)            echo "Unknown: $1"; usage ;;
        *)             DOMAIN="$1"; shift ;;
    esac
done

[[ -z "$DOMAIN" ]] && { echo "Error: domain required"; usage; }
[[ $EUID -ne 0 ]] && { echo "Error: run as root"; exit 1; }

# ---------------------------------------------------------------
# Auto-detect interface and IP
# ---------------------------------------------------------------
if [[ -z "$IFACE" ]]; then
    IFACE=$(ip -o route get 8.8.8.8 2>/dev/null | awk '{print $5; exit}')
    [[ -z "$IFACE" ]] && IFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -1)
fi
if [[ -z "$PUBLIC_IP" ]]; then
    PUBLIC_IP=$(ip -o -4 addr show dev "$IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
    [[ -z "$PUBLIC_IP" ]] && PUBLIC_IP=$(curl -s4 --max-time 5 ifconfig.me)
fi

echo "============================================"
echo " letmeout setup"
echo " Domain:     $DOMAIN"
echo " Public IP:  $PUBLIC_IP"
echo " Interface:  $IFACE"
echo " DNS plugin: $DNS_PLUGIN"
echo " Admin SSH:  port $ADMIN_PORT${ADMIN_SOURCE:+ from $ADMIN_SOURCE}"
echo "============================================"
echo ""

# ---------------------------------------------------------------
# Step 1: Install dependencies
# ---------------------------------------------------------------
echo "[1/8] Installing packages..."
apt-get update -qq
apt-get install -y -qq golang-go certbot iptables-persistent openssh-server curl rsyslog logrotate

case "$DNS_PLUGIN" in
    digitalocean) apt-get install -y -qq python3-certbot-dns-digitalocean 2>/dev/null || pip3 install certbot-dns-digitalocean ;;
    cloudflare)   apt-get install -y -qq python3-certbot-dns-cloudflare 2>/dev/null || pip3 install certbot-dns-cloudflare ;;
    route53)      pip3 install certbot-dns-route53 ;;
    manual)       ;;
    *)            pip3 install "certbot-dns-$DNS_PLUGIN" 2>/dev/null || true ;;
esac
echo "[+] done"

# ---------------------------------------------------------------
# Step 2: Build the server binary
# ---------------------------------------------------------------
echo "[2/8] Building letmeout binary..."
mkdir -p /opt/letmeout
cp "$SERVER_DIR"/*.go "$SERVER_DIR"/go.mod /opt/letmeout/
(cd /opt/letmeout && go build -o letmeout .)
echo "[+] /opt/letmeout/letmeout built"

# ---------------------------------------------------------------
# Step 3: Configure admin SSH
# ---------------------------------------------------------------
echo "[3/8] Configuring admin SSH on port $ADMIN_PORT..."

# Ensure sshd listens on the admin port + key-only auth
cat > /etc/ssh/sshd_config.d/letmeout-admin.conf << SSHD
# Admin SSH access for letmeout server
Port $ADMIN_PORT
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin yes
UseDNS no
MaxAuthTries 3
MaxStartups 3:50:10
LoginGraceTime 10
SSHD

systemctl restart sshd
echo "[+] sshd listening on port $ADMIN_PORT"

# ---------------------------------------------------------------
# Step 4: Obtain wildcard TLS certificate
# ---------------------------------------------------------------
echo "[4/8] Obtaining wildcard TLS certificate..."

CERTBOT_ARGS=(certonly --non-interactive --agree-tos -d "$DOMAIN" -d "*.$DOMAIN")
[[ -n "$EMAIL" ]] && CERTBOT_ARGS+=(--email "$EMAIL") || CERTBOT_ARGS+=(--register-unsafely-without-email)

case "$DNS_PLUGIN" in
    digitalocean)
        CREDS="/root/do-certbot.ini"
        [[ ! -f "$CREDS" ]] && { echo "ERROR: create $CREDS with: dns_digitalocean_token = YOUR_TOKEN"; exit 1; }
        chmod 600 "$CREDS"
        CERTBOT_ARGS+=(--dns-digitalocean --dns-digitalocean-credentials "$CREDS" --dns-digitalocean-propagation-seconds 60)
        ;;
    cloudflare)
        CREDS="/etc/letsencrypt/cloudflare.ini"
        [[ ! -f "$CREDS" ]] && { echo "ERROR: create $CREDS with: dns_cloudflare_api_token = YOUR_TOKEN"; exit 1; }
        chmod 600 "$CREDS"
        CERTBOT_ARGS+=(--dns-cloudflare --dns-cloudflare-credentials "$CREDS" --dns-cloudflare-propagation-seconds 30)
        ;;
    route53)
        CERTBOT_ARGS+=(--dns-route53)
        ;;
    manual)
        CERTBOT_ARGS+=(--preferred-challenges dns --manual)
        echo "  Manual DNS challenge — certbot will ask you to create TXT records."
        ;;
esac

certbot "${CERTBOT_ARGS[@]}"
echo "[+] TLS certificate obtained"

# ---------------------------------------------------------------
# Step 5: Install systemd service
# ---------------------------------------------------------------
echo "[5/8] Installing systemd service..."

cat > /etc/default/letmeout << ENV
DOMAIN=$DOMAIN
PUBLIC_IP=$PUBLIC_IP
ENV

cp "$SERVER_DIR/systemd/letmeout.service" /etc/systemd/system/letmeout.service
systemctl daemon-reload
systemctl enable --now letmeout
echo "[+] letmeout service started"

# ---------------------------------------------------------------
# Step 6: Apply iptables rules
# ---------------------------------------------------------------
echo "[6/8] Applying iptables rules..."
echo ""
echo "  WARNING: This will redirect ALL inbound TCP/UDP to the letmeout binary."
echo "  Admin SSH will only be accessible on port $ADMIN_PORT${ADMIN_SOURCE:+ from $ADMIN_SOURCE}."
echo "  Make sure you can reconnect before proceeding!"
echo ""

bash "$SERVER_DIR/configs/iptables-rules.sh" "$PUBLIC_IP" "$ADMIN_PORT" "$ADMIN_SOURCE"

netfilter-persistent save 2>/dev/null || {
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
}
echo "[+] iptables rules applied and persisted"

# ---------------------------------------------------------------
# Step 7: Sysctl + logrotate
# ---------------------------------------------------------------
echo "[7/8] Applying sysctl tuning and logrotate..."
cp "$SERVER_DIR/configs/sysctl-network.conf" /etc/sysctl.d/99-letmeout.conf
sysctl --system > /dev/null 2>&1
cp "$SERVER_DIR/configs/logrotate-syslog.conf" /etc/logrotate.d/rsyslog
echo "[+] done"

# ---------------------------------------------------------------
# Step 8: Cert renewal cron
# ---------------------------------------------------------------
echo "[8/8] Setting up cert renewal..."

mkdir -p /etc/letsencrypt/renewal-hooks/post
cat > /etc/letsencrypt/renewal-hooks/post/reload-letmeout.sh << 'HOOK'
#!/bin/bash
# Send SIGHUP to reload TLS cert without restart
kill -HUP $(pidof letmeout) 2>/dev/null || systemctl restart letmeout
HOOK
chmod +x /etc/letsencrypt/renewal-hooks/post/reload-letmeout.sh

CRON_LINE="22 05,17 * * * certbot renew --quiet"
(crontab -l 2>/dev/null | grep -v certbot; echo "$CRON_LINE") | crontab -
echo "[+] cert renewal cron installed"

# ---------------------------------------------------------------
# Verify
# ---------------------------------------------------------------
echo ""
echo "[*] Verifying..."
PASS=0; FAIL=0

check() {
    if [[ "$2" == *"w00tw00t"* ]]; then
        echo "  [PASS] $1"; ((PASS++))
    else
        echo "  [FAIL] $1"; ((FAIL++))
    fi
}

check "HTTP" "$(curl -s --max-time 3 http://127.0.0.1:8080 2>/dev/null || echo '')"
check "HTTPS" "$(curl -sk --max-time 3 https://127.0.0.1:8443 2>/dev/null || echo '')"
check "Echo" "$(echo '' | nc -q1 -w2 127.0.0.1 9999 2>/dev/null || echo '')"

if systemctl is-active --quiet letmeout; then
    echo "  [PASS] letmeout service"; ((PASS++))
else
    echo "  [FAIL] letmeout service"; ((FAIL++))
fi

if iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "DNAT.*:80"; then
    echo "  [PASS] iptables DNAT"; ((PASS++))
else
    echo "  [FAIL] iptables DNAT"; ((FAIL++))
fi

echo ""
echo "============================================"
echo " Setup complete ($PASS passed, $FAIL failed)"
echo "============================================"
echo ""
echo " Admin SSH:    ssh -p $ADMIN_PORT root@$PUBLIC_IP"
echo ""
echo " Test from another machine:"
echo "   curl http://$DOMAIN:8888"
echo "   curl https://$DOMAIN:9999"
echo "   curl http://test.$DOMAIN:12345/any/path.php"
echo "   ssh $DOMAIN              # gets w00tw00t SSH banner"
echo "   nc $DOMAIN 31337         # gets w00tw00t|ECHO|..."
echo "   echo x | nc -u $DOMAIN 9999"
echo "   dig @$DOMAIN TXT test.com"
echo ""

[[ $FAIL -gt 0 ]] && exit 1 || exit 0
