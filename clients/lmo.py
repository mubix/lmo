#!/usr/bin/env python3
# lmo.py — Let Me Out egress filter tester
#
# Tests HTTP, HTTPS, and SSH ports against a letmeoutofyour.net server
# (or your own instance). Any port that returns the string "w00tw00t"
# is egressing successfully.
#
# Dependencies: requests  (pip install requests)

import concurrent.futures
import random
import socket

import requests

# --- Configuration ---
ports = [80, 443, 445, 8080, 3389, 22, 21]
# ports = list(range(1, 65536))  # uncomment for a full sweep

domain = "letmeoutofyour.net"
verbose = False
printOpen = True
printClosed = True
threadcount = 100

VERIFY = "w00tw00t"

random.shuffle(ports)

# Silence InsecureRequestWarning — the server uses a real wildcard cert but
# we may test subdomains or IPs where the cert doesn't strictly match.
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


def vprint(status):
    if verbose:
        print(status)


def print_open(status):
    if printOpen:
        print("[+] " + status)


def print_closed(status):
    if printClosed:
        print("[-] " + status)


def check_web(base, domain, port):
    url = f"{base}{domain}:{port}"
    vprint(f"Testing: {url}")
    try:
        r = requests.get(url, timeout=2, verify=False)
        if VERIFY in r.text:
            print_open(f"Success! {url}")
        else:
            print_closed(f"No w00tw00t: {url}")
    except requests.exceptions.ConnectionError:
        print_closed(f"Failed! {url}")
    except requests.exceptions.Timeout:
        print_closed(f"Timeout! {url}")
    except requests.exceptions.RequestException as e:
        print_closed(f"Error! {url} ({type(e).__name__})")


def check_ssh(domain, port):
    # The letmeout server sends an SSH version string containing "w00tw00t"
    # and closes immediately — no key exchange, no auth. A raw socket read
    # of the banner is all we need, and it avoids the paramiko dependency
    # (the original lmo.py verified a hardcoded ed25519 host key, which no
    # longer exists on the new single-binary server).
    label = f"SSH to {domain}:{port}"
    vprint(f"Trying {label}")
    try:
        s = socket.create_connection((domain, port), timeout=2)
        s.sendall(b"SSH-2.0-lmo_client\r\n")
        banner = s.recv(512).decode("utf-8", errors="ignore")
        s.close()
        if VERIFY in banner:
            print_open(f"Success! {label}")
        else:
            print_closed(f"No w00tw00t: {label}")
    except (socket.timeout, ConnectionRefusedError, OSError):
        print_closed(f"Failed! {label}")


with concurrent.futures.ThreadPoolExecutor(threadcount) as executor:
    for port in ports:
        executor.submit(check_web, "http://", domain, port)
        executor.submit(check_web, "https://", domain, port)
        executor.submit(check_ssh, domain, port)
