# letmeoutofyour.net

A server that responds with `w00tw00t` on **every TCP and UDP port**, in **every protocol it can detect**. Built for Blue Teams to test egress filtering — if you can reach it and see `w00tw00t`, that port is open outbound.

**Live instance:** [letmeoutofyour.net](https://letmeoutofyour.net)

```
curl http://letmeoutofyour.net:8888                          → w00tw00t
curl https://letmeoutofyour.net:9999                         → w00tw00t
curl http://test.sub.letmeoutofyour.net:12345/any/path.php   → w00tw00t
ssh letmeoutofyour.net                                       → SSH-2.0-w00tw00t_letmeoutofyour.net
nc letmeoutofyour.net 31337                                  → 220 letmeoutofyour.net w00tw00t|...
ftp letmeoutofyour.net 21                                    → 220 letmeoutofyour.net w00tw00t|...
echo test | nc -u letmeoutofyour.net 9999                    → w00tw00t
dig @letmeoutofyour.net TXT anything.com                     → w00tw00t|DNS|letmeoutofyour.net
telnet letmeoutofyour.net 23                                 → 220 letmeoutofyour.net w00tw00t|...
```

## Architecture

One Go binary handles everything. No nginx, no Apache, no sslh, no sshd dependency.

```
                   ┌────────────────────────────────────────────┐
                   │              iptables NAT                  │
                   │                                            │
  TCP :25 ────────►│── RETURN ──────────────┐                   │
  TCP :ADMIN ─────►│── RETURN ──► real sshd │                   │
  All other TCP ──►│── DNAT :80 ──► letmeout ├── peek bytes ─┐  │
                   │                         │                │  │
                   │  0x16    → TLS handshake → HTTP 200 w00tw00t│
                   │  GET/POST → HTTP 200 w00tw00t              │
                   │  SSH-     → SSH-2.0-w00tw00t → close       │
                   │  (other)  → w00tw00t|ECHO|… → close        │
                   │  (nothing)→ 220 domain w00tw00t (FTP/SMTP) │
                   │                                            │
  UDP :123 ───────►│── RETURN (NTP) ─────────┐                  │
  All other UDP ──►│── DNAT :5353 ──► letmeout │                │
                   │                  ├─ DNS? → valid DNS reply  │
                   │                  └─ raw  → w00tw00t         │
                   └────────────────────────────────────────────┘
```

### Protocol Detection

The binary peeks at the first bytes of each TCP connection to determine the protocol:

| First Bytes | Detected As | Response | Speed |
|---|---|---|---|
| `0x16` | TLS/SSL | TLS handshake → HTTP 200 `w00tw00t` | **Instant** |
| `GET`, `POST`, etc. | HTTP | HTTP 200 `w00tw00t` | **Instant** |
| `SSH-` | SSH | `SSH-2.0-w00tw00t_domain` → close (no key exchange, no auth) | **Instant** |
| (anything else) | Unknown | `w00tw00t\|ECHO\|domain\|timestamp\|nonce` | **Instant** |
| (nothing for 300ms) | Server-speaks-first | `220 domain w00tw00t\|timestamp\|nonce` (valid FTP/SMTP greeting) | **300ms** |
| *(port 25 only)* | SMTP | `220 domain ESMTP w00tw00t\|SMTP\|...` | **Instant** |

For UDP, if the packet looks like a DNS query, it returns a valid DNS response (TXT record contains `w00tw00t|DNS|domain`). Otherwise it returns raw `w00tw00t`.

### Speed

**Clients that send data first (HTTP, HTTPS, SSH): response is instant.** Protocol detection takes microseconds — curl/wget/browsers get `w00tw00t` back in under a millisecond after connect.

**Clients that wait for a server greeting (FTP, telnet, nc, port scanners): 300ms delay.** The server waits briefly for client data, then sends a `220` multi-protocol greeting. At 500 parallel connections, scanning all 65,535 ports takes ~40 seconds worst case.

The peek timeout is configurable (`-peek-ms` flag) if you need to tune for your traffic patterns.

### Scale

The server is designed to handle internet-scale scanner traffic:

- **SO_REUSEPORT with one accept loop per CPU core** — the kernel load-balances new connections across multiple sockets, removing the single-accept-queue bottleneck. Scales linearly with core count.
- **Pre-computed HTTP and SSH responses** — no `fmt.Sprintf` in the hot path; handlers just `Write` a static byte slice.
- **Goroutine-per-connection with an atomic cap** (`-max-conns`, default 200000) — Go's scheduler handles millions of short-lived connections efficiently. Connections above the cap still get `w00tw00t\n` immediately.
- **Kernel tuning** (see `server/configs/sysctl-network.conf`) — bumps `somaxconn`, `tcp_max_syn_backlog`, and `nf_conntrack_max` so the kernel doesn't drop connections under burst load.

Flags for tuning:
```
-listeners N     # number of parallel accept loops (default: runtime.NumCPU())
-max-conns N     # max concurrent TCP connections (default: 200000)
-peek-ms N       # ms to wait for client data (default: 300)
```

### Why One Binary?

The original server ran sslh (protocol multiplexer) + Apache + three Go services + OpenSSH. This caused:

- **SSH brute force overload** — sslh detected SSH and forwarded to a real sshd, which burned CPU on key exchange for every brute forcer on the internet
- **Log explosion** — sslh logged every connection to syslog, filling disk at internet scale
- **Operational complexity** — five services to monitor and restart

The single binary fixes all three: SSH connections get a version string and an immediate close (nothing to brute force, microseconds per connection), logging is one stats line every 5 minutes, and there's one systemd unit to manage.

## Setup

### Prerequisites

- Linux server (Debian/Ubuntu) with a public IP
- A domain name you control
- Root access

### Step 1: DNS

Create two A records pointing to your server:

| Type | Name | Value |
|------|------|-------|
| A | `@` | `YOUR_SERVER_IP` |
| A | `*` | `YOUR_SERVER_IP` |

Verify:
```bash
dig +short yourdomain.com            # → your IP
dig +short anything.yourdomain.com   # → your IP
```

### Step 2: TLS Credentials

Wildcard certs require DNS-01 validation. Set up API credentials for your DNS provider before running setup.

**DigitalOcean:**
```bash
echo "dns_digitalocean_token = YOUR_DO_API_TOKEN" > /root/do-certbot.ini
chmod 600 /root/do-certbot.ini
```

**Cloudflare:**
```bash
mkdir -p /etc/letsencrypt
echo "dns_cloudflare_api_token = YOUR_TOKEN" > /etc/letsencrypt/cloudflare.ini
chmod 600 /etc/letsencrypt/cloudflare.ini
```

### Step 3: Run Setup

```bash
git clone https://github.com/mubix/letmeoutofyour.net.git
cd letmeoutofyour.net

# DigitalOcean DNS, admin SSH on port 62222 restricted to your IP
sudo ./server/scripts/setup.sh \
    --dns digitalocean \
    --admin-port 62222 \
    --admin-ip YOUR_HOME_IP \
    yourdomain.com
```

The setup script:
1. Installs Go and certbot
2. Builds the `letmeout` binary
3. Configures sshd on the admin port (key-only auth)
4. Obtains a wildcard TLS cert
5. Installs and starts the systemd service
6. Applies iptables rules (all TCP/UDP → letmeout)
7. Applies sysctl tuning + logrotate
8. Sets up cert auto-renewal (twice daily cron)

### Step 4: Verify

From another machine:
```bash
curl http://yourdomain.com:8888
curl https://yourdomain.com:9999
curl http://test.yourdomain.com:12345/any/path.php
ssh yourdomain.com
echo test | nc -u yourdomain.com 9999
dig @yourdomain.com TXT anything.com
```

Admin SSH:
```bash
ssh -p 62222 root@yourdomain.com
```

## Client-Side Testing Script

For Blue Teams testing their egress rules:

```bash
./clients/test-egress.sh yourdomain.com              # common ports
./clients/test-egress.sh yourdomain.com 80 443 8080   # specific ports
./clients/test-egress.sh yourdomain.com all            # all 65535 TCP
./clients/test-egress.sh --udp yourdomain.com          # common UDP ports
./clients/test-egress.sh --https yourdomain.com        # HTTPS mode
```

See **[clients/README.md](clients/README.md)** for the full list of clients known to work against this server.

Or use one of the more fully-featured clients that live in this repo:

- **`clients/lmo.py`** — the original threaded Python client (HTTP, HTTPS, SSH) from [github.com/mubix/lmo](https://github.com/mubix/lmo). Updated to work with the new single-binary server.
- **`clients/lmo-oob.py`** — out-of-band tester that confirms HTTP egress via a DNS lookup to a separate domain.

And one external Go tool that works great:

- **[sensepost/go-out](https://github.com/sensepost/go-out)** — SensePost's Go-based egress tester.

## File Layout

```
letmeoutofyour.net/
├── README.md                    # this file
├── LICENSE
│
├── server/                      # everything needed to build and run the server
│   ├── main.go                  # entry point, flags, TLS, signals, stats
│   ├── tcp.go                   # TCP: protocol detection + HTTP/TLS/SSH/SMTP/echo
│   ├── udp.go                   # UDP: DNS-aware + raw w00tw00t
│   ├── go.mod
│   ├── configs/
│   │   ├── iptables-rules.sh    # NAT rules (TCP→:80, UDP→:5353, admin RETURN)
│   │   ├── sysctl-network.conf  # kernel tuning for high connection volume
│   │   └── logrotate-syslog.conf
│   ├── systemd/
│   │   └── letmeout.service     # single hardened systemd unit
│   └── scripts/
│       ├── setup.sh             # full automated setup
│       └── renew-cert.sh        # manual cert renewal
│
└── clients/                     # client-side egress testing tools
    ├── README.md                # list of known clients + usage
    ├── lmo.py                   # original threaded Python client (HTTP/HTTPS/SSH)
    ├── lmo-oob.py               # OOB tester: HTTP egress confirmed via DNS lookup
    └── test-egress.sh           # minimal bash smoke tester
```

## How iptables Makes It Work

Five NAT rules redirect the entire port space to one binary:

```bash
# SMTP bypasses main listener (server must speak first)
iptables -t nat -A PREROUTING -d $IP -p tcp --dport 25 -j RETURN

# Admin SSH bypasses main listener (reaches real sshd)
iptables -t nat -A PREROUTING -d $IP -p tcp --dport 62222 -s $ADMIN_IP -j RETURN

# ALL other TCP → letmeout on port 80
iptables -t nat -A PREROUTING -d $IP -p tcp -m state --state NEW -j DNAT --to-destination $IP:80

# NTP passes through
iptables -t nat -A PREROUTING -d $IP -p udp --dport 123 -j RETURN

# ALL other UDP → letmeout on port 5353
iptables -t nat -A PREROUTING -d $IP -p udp -j DNAT --to-destination $IP:5353
```

## Maintenance

```bash
# Service status
systemctl status letmeout

# Live stats (logged every 5 minutes)
journalctl -u letmeout -f

# iptables rules
iptables -t nat -L PREROUTING -n -v

# Force cert renewal + reload
sudo ./server/scripts/renew-cert.sh yourdomain.com

# Reload TLS cert without restart (after certbot renewal)
systemctl reload letmeout    # sends SIGHUP
```

## Troubleshooting

| Problem | Fix |
|---|---|
| Locked out of SSH | Console/KVM, then `iptables -t nat -F` |
| Cert renewal fails | Check DNS API creds, `certbot renew --dry-run` |
| No response on a port | `iptables -t nat -L -n`, `systemctl status letmeout` |
| High memory | Service has MemoryMax=512M; `systemctl restart letmeout` |
| Need to update admin IP | Edit iptables RETURN rule, `netfilter-persistent save` |

## Origin & Related Tools

This server has been running in one form or another since **2012**. The original write-ups:

- **[Let Me Out Of Your Net — Intro](https://malicious.link/posts/2012/2012-08-10-let-me-out-of-your-net-intro/)** (2012-08-10) — the blog post that started it, explaining why a server that listens on every port with a verifiable response string is useful to Blue Teams testing egress rules.
- **[Let Me Out Of Your Net — Server Build](https://malicious.link/posts/2012/2012-08-11-let-me-out-of-your-net-server-build/)** (2012-08-11) — the original build-out post describing how the first version of the server was set up.

Client-side tools for testing egress filtering against this server (or your own instance) live under [`clients/`](clients/):

- **`clients/lmo.py`** — the threaded Python client from the original [github.com/mubix/lmo](https://github.com/mubix/lmo) repo (2020). HTTP, HTTPS, and SSH checks against a list of ports. Updated to use a raw-socket SSH banner check (the original paramiko-based host-key verification no longer applies to the new single-binary server).
- **`clients/lmo-oob.py`** — out-of-band tester that confirms HTTP egress by sending base32-encoded URL info as a DNS lookup to a separate wildcard domain. Proves both HTTP *and* DNS egress in one shot.
- **`clients/test-egress.sh`** — minimal bash smoke tester (no Python).
- **[sensepost/go-out](https://github.com/sensepost/go-out)** — external: SensePost's Go-based egress tester. Tested and works great against the new architecture.

## Credits

Created by [@mubix](https://github.com/mubix) (Rob Fuller).

## License

MIT
