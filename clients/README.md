# Clients

Client-side tools for testing egress filtering against a `letmeoutofyour.net` server (the live instance or your own).

The verification string is **`w00tw00t`** — any client that sees it in a response knows the connection succeeded end-to-end.

## In this directory

### `lmo.py`

The original `lmo` Python client, from [github.com/mubix/lmo](https://github.com/mubix/lmo) (2020). Threaded port scanner that tests HTTP, HTTPS, and SSH against a list of ports and prints which ones reach the server.

```bash
pip install requests
./lmo.py
```

Edit the top of the script to change `ports`, `domain`, or `threadcount`. Uncomment the `list(range(1, 65536))` line for a full sweep of all 65,535 ports.

**Changes from the original 2020 version:** the SSH check was rewritten to use a raw socket read of the SSH version banner instead of `paramiko` + hardcoded host-key verification. This is because the new single-binary server returns a version string containing `w00tw00t` and closes the connection — there's no real sshd and no key exchange to verify against. Dropping `paramiko` also removes a heavy dependency.

### `lmo-oob.py`

Out-of-band egress tester. For each port that returns `w00tw00t` over HTTP/HTTPS, it encodes the URL into base32 and sends a DNS query to a wildcard subdomain of `malicious.link`. This proves not just that HTTP egress works, but that **DNS egress also works** — useful for confirming two-stage exfil paths.

```bash
pip install requests
./lmo-oob.py
```

The script uses a random prefix on each run so DNS caching doesn't mask repeat tests. Example output in a network that only allows 80/443 outbound:

```
Testing: http://letmeoutofyour.net:80
w00tw00t
wtsvmufbpr.NB2HI4B2F4XWYZLUNVSW65LUN5THS33VOIXG4ZLUHI4DA-A-A-A.malicious.link
Testing: http://letmeoutofyour.net:445
Failed to connect
```

To point this at your own server, change `domain` (the letmeout instance) and `dns` (the wildcard domain you control for OOB confirmation) at the top of the script.

### `test-egress.sh`

A minimal bash client bundled with the repo for quick smoke testing. No Python needed — only `bash`, `curl`, and `nc`.

```bash
./test-egress.sh yourdomain.com                 # common ports
./test-egress.sh yourdomain.com 80 443 8080     # specific ports
./test-egress.sh yourdomain.com all             # all 65535 TCP
./test-egress.sh --udp yourdomain.com           # common UDP ports
./test-egress.sh --https yourdomain.com         # HTTPS mode
```

## External clients that work against this server

These aren't in the repo but are known to work against the current single-binary server:

- **[sensepost/go-out](https://github.com/sensepost/go-out)** — SensePost's Go-based egress tester. Tested and confirmed working against the new architecture, including the shorter peek timeout and multi-protocol `220` greeting behavior.

## Adding a client

If you write a new client (or find one that works and isn't listed), open a PR adding it to this README, or drop the client directly into this directory.

When in doubt about whether a client "works": if it can show you `w00tw00t` in any response from any port on a running server, it works.
