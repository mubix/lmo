#!/usr/bin/env bash
# iptables NAT rules for egress filter testing
#
# Traffic flow:
#   TCP :25             → RETURN   → letmeout SMTP listener (server speaks first)
#   TCP :$ADMIN_PORT    → RETURN   → real sshd (admin access)
#   All other TCP       → DNAT :80 → letmeout main listener (protocol detection)
#   UDP :123            → RETURN   → system NTP
#   All other UDP       → DNAT :5353 → letmeout UDP listener
#
# Usage: sudo ./iptables-rules.sh PUBLIC_IP [ADMIN_PORT] [ADMIN_SOURCE_IP]

set -euo pipefail

PUBLIC_IP="${1:?Usage: $0 PUBLIC_IP [ADMIN_PORT] [ADMIN_SOURCE_IP]}"
ADMIN_PORT="${2:-}"
ADMIN_SOURCE="${3:-}"

echo "[*] Setting up iptables NAT rules for $PUBLIC_IP"

iptables -t nat -F PREROUTING
iptables -t nat -F OUTPUT

# --- TCP ---

# SMTP bypasses the main listener (SMTP is server-speaks-first,
# so protocol detection can't work — client sends nothing initially)
iptables -t nat -A PREROUTING -d "$PUBLIC_IP" -p tcp --dport 25 -j RETURN

# Admin SSH — direct access to real sshd, bypassing the main listener.
# Use source IP restriction if provided, otherwise just the port.
if [[ -n "$ADMIN_PORT" ]]; then
    if [[ -n "$ADMIN_SOURCE" ]]; then
        iptables -t nat -A PREROUTING -d "$PUBLIC_IP" -p tcp --dport "$ADMIN_PORT" -s "$ADMIN_SOURCE" -j RETURN
        echo "[*] Admin SSH: port $ADMIN_PORT from $ADMIN_SOURCE only"
    else
        iptables -t nat -A PREROUTING -d "$PUBLIC_IP" -p tcp --dport "$ADMIN_PORT" -j RETURN
        echo "[*] Admin SSH: port $ADMIN_PORT from any source"
    fi
fi

# Everything else → main TCP listener on port 80
iptables -t nat -A PREROUTING -d "$PUBLIC_IP" -p tcp -m state --state NEW -j DNAT --to-destination "$PUBLIC_IP":80

# --- UDP ---

# NTP passes through (server's own time sync)
iptables -t nat -A PREROUTING -d "$PUBLIC_IP" -p udp --dport 123 -j RETURN

# Everything else → UDP listener on port 5353
iptables -t nat -A PREROUTING -d "$PUBLIC_IP" -p udp -j DNAT --to-destination "$PUBLIC_IP":5353

# OUTPUT rule so local UDP testing works (e.g. dig @localhost)
iptables -t nat -A OUTPUT -d "$PUBLIC_IP" -p udp ! --dport 123 -j DNAT --to-destination "$PUBLIC_IP":5353

echo "[+] iptables rules applied"
echo "[*] Verify: iptables -t nat -L PREROUTING -n -v"
