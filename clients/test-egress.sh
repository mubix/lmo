#!/usr/bin/env bash
# test-egress.sh — Client-side egress filter testing
#
# Usage:
#   ./test-egress.sh yourdomain.com                    # Common ports (TCP)
#   ./test-egress.sh yourdomain.com 80 443 8080        # Specific ports
#   ./test-egress.sh yourdomain.com all                 # All 65535 TCP ports
#   ./test-egress.sh --udp yourdomain.com               # Common UDP ports
#   ./test-egress.sh --https yourdomain.com             # HTTPS mode

set -euo pipefail

TIMEOUT=2
USE_HTTPS=false
USE_UDP=false
VERIFY="w00tw00t"
DOMAIN=""
PORTS=()

COMMON_TCP=(
    20 21 22 23 25 53 80 110 135 139 143 161 389
    443 445 465 587 636 993 995
    1080 1433 1521 2049 3306 3389
    4443 5432 5900 5985 5986
    8000 8080 8443 8888 9090 9443
)
COMMON_UDP=(53 123 161 162 389 443 500 514 1194 4500 5353 8443)

usage() {
    echo "Usage: $0 [--https|--udp] [--timeout SEC] DOMAIN [PORTS...|all]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --https)   USE_HTTPS=true; shift ;;
        --udp)     USE_UDP=true; shift ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        -h|--help) usage ;;
        -*)        echo "Unknown: $1"; usage ;;
        *)
            if [[ -z "$DOMAIN" ]]; then DOMAIN="$1"
            elif [[ "$1" == "all" ]]; then PORTS=($(seq 1 65535))
            else PORTS+=("$1")
            fi
            shift ;;
    esac
done

[[ -z "$DOMAIN" ]] && { echo "Error: domain required"; usage; }

if [[ ${#PORTS[@]} -eq 0 ]]; then
    if $USE_UDP; then PORTS=("${COMMON_UDP[@]}"); else PORTS=("${COMMON_TCP[@]}"); fi
fi

OPEN=() CLOSED=()
TOTAL=${#PORTS[@]}
PROTO="http"; CURL_EXTRA=""
$USE_HTTPS && { PROTO="https"; CURL_EXTRA="-k"; }

echo "============================================"
echo " Egress Filter Test → $DOMAIN"
echo " Mode: $($USE_UDP && echo "UDP" || echo "$PROTO") | Ports: $TOTAL | Timeout: ${TIMEOUT}s"
echo "============================================"
echo ""

for PORT in "${PORTS[@]}"; do
    if $USE_UDP; then
        RESULT=$(echo "test" | nc -u -w "$TIMEOUT" "$DOMAIN" "$PORT" 2>/dev/null || echo "")
    else
        RESULT=$(curl -s --max-time "$TIMEOUT" --connect-timeout "$TIMEOUT" \
            $CURL_EXTRA "$PROTO://$DOMAIN:$PORT/" 2>/dev/null || echo "")
    fi

    if [[ "$RESULT" == *"$VERIFY"* ]]; then
        OPEN+=("$PORT")
        printf "  [OPEN]   %-5s → %s\n" "$PORT" "$VERIFY"
    else
        CLOSED+=("$PORT")
        [[ $TOTAL -le 50 ]] && printf "  [CLOSED] %-5s\n" "$PORT"
    fi
done

echo ""
echo "============================================"
echo " Open: ${#OPEN[@]} / $TOTAL"
echo "============================================"
[[ ${#OPEN[@]} -gt 0 ]] && echo " Ports: ${OPEN[*]}"

if [[ ${#OPEN[@]} -eq $TOTAL ]]; then
    echo " [!!!] ALL ports open — no egress filtering detected!"
elif [[ ${#OPEN[@]} -eq 0 ]]; then
    echo " [OK] All tested ports filtered"
else
    echo " [!!] Partial filtering — review open ports"
fi
echo ""
