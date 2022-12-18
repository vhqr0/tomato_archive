#!/usr/bin/env python3
'''
Copy from https://github.com/trojan-gfw/trojan [/scripts/getcert.py].
'''

import socket
import ssl
import sys
import argparse
from urllib.parse import urlparse

parser = argparse.ArgumentParser()
parser.add_argument('-u', '--url', default='')
parser.add_argument('-H', '--hostname')
args = parser.parse_args()

url = urlparse('//' + args.url)
addr = url.hostname or 'localhost'
port = url.port or 443
hostname = args.hostname or addr

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection((addr, port)) as sock:
    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
        print(ssl.DER_cert_to_PEM_cert(ssock.getpeercert(True)), end='')
