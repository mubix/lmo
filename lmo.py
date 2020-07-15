#!/usr/bin/env python3
import requests
import socket
import random
import string
import concurrent.futures
from paramiko.client import SSHClient
import paramiko

# VARIABLES
ports = [80,443,445,8080,3389,22,21]
#ports = list(range(1,65536))

domain = "letmeoutofyour.net"
verbose = False
printOpen = True
printClosed = True

threadcount = 100

random.shuffle(ports)


# Verbosity - set to False above if you don't want output
def vprint(status):
  if verbose == True:
    print(status)

# Print open ports
def print_open(status):
  if printOpen == True:
    print("[+] " + status)

# Print closed ports
def print_closed(status):
  if printClosed == True:
    print("[-] " + status)


def check_web(base, domain, port):
  vprint("Testing: " + base + domain + ":" + str(port))
  try:
    r = requests.get(base + domain + ":" + str(port), timeout=1)
    result = r.text.strip()
    if result == "w00tw00t":
      print_open("Success! " + base + domain + ":" + str(port))
  except requests.exceptions.ConnectionError:
    print_closed("Failed! " + base + domain + ":" + str(port))

def check_ssh(domain, port):
  client = SSHClient()
  vprint("Trying SSH to " + domain + " Port: " + str(port))
  try:
    client.connect(domain, port, timeout=1)
  except paramiko.ssh_exception.SSHException:
    pass
  except socket.timeout:
    print_closed("Failed! SSH to " + domain + " Port: " + str(port))
    return
  key = client.get_transport().get_remote_server_key()
  if key.get_base64() == "AAAAC3NzaC1lZDI1NTE5AAAAIIrfkWLMzwGKRliVsJOjm5OJRJo6AZt7NsqAH8bk9tYc":
    print_open("Success! SSH to " + domain + " Port: " + str(port))

with concurrent.futures.ThreadPoolExecutor(threadcount) as executor:
  for port in ports:
    # Test HTTP
    base = "http://"
    executor.submit(check_web, base, domain, port)
    # Test HTTPS
    base = "https://"
    executor.submit(check_web, base, domain, port)
    # Test SSH
    executor.submit(check_ssh, domain, port)
