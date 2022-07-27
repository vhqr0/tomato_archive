#!/usr/bin/env python3

import socket
import ssl
import threading
from hashlib import md5

from socks5 import Socks5, socks5_urlparse
from pipe import pipe_s


class SSocks5R(Socks5):

    def __init__(self, isock, pwd, spwd, saf, saddr, shost, tlsctx):
        super().__init__(isock, pwd)
        self.spwd = spwd
        self.saf = saf
        self.saddr = saddr
        self.shost = shost
        self.tlsctx = tlsctx

    def run(self):
        self.do_read_auth()
        self.do_connect_s()
        pipe_s(self.isock, self.osock)

    def do_connect_s(self):
        sock = socket.socket(self.saf, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
        sock.connect(self.saddr)
        self.osock = self.tlsctx.wrap_socket \
            (sock, server_hostname=self.shost)
        self.osock.sendall(self.spwd + self.isock.recv(4096))


class SSocks5(Socks5):

    def __init__(self, isock, pwd, tlsctx):
        super().__init__(isock, None)
        self.spwd = pwd
        self.tlsctx = tlsctx

    def isock_recvall(self, n):
        buf = b''
        while n:
            b = self.isock.recv(n)
            assert len(b) != 0
            n -= len(b)
            buf += b
        return buf

    def run(self):
        self.do_accept_s()
        self.do_read_req()
        self.do_exec_cmd()
        pipe_s(self.osock, self.isock)

    def do_accept_s(self):
        self.isock = self.tlsctx.wrap_socket(self.isock, server_side=True)
        assert self.isock_recvall(32) == self.spwd


class SSocks5RServer:

    def __init__(self, addr, pwd, spwd, saddr, shost, cafile, debug):
        af, _, _, _, addr = socket.getaddrinfo \
            (addr[0], addr[1], type=socket.SOCK_STREAM)[0]
        self.sock = socket.socket(af, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self.sock.bind(addr)
        self.pwd = pwd
        self.spwd = md5(spwd[0]).digest() + md5(spwd[1]).digest()
        self.saf, _, _, _, self.saddr = socket.getaddrinfo \
            (saddr[0], saddr[1], type=socket.SOCK_STREAM)[0]
        self.shost = shost
        self.tlsctx = ssl.create_default_context(cafile=cafile)
        self.debug = debug

    @staticmethod
    def ssocks5rrun(isock, pwd, spwd, saf, saddr, shost, tlsctx, debug):
        try:
            SSocks5R(isock, pwd, spwd, saf, saddr, shost, tlsctx).run()
        except Exception as e:
            if debug:
                print(f'{threading.get_native_id()}: {type(e)} {e}')

    def run(self):
        self.sock.listen()
        while True:
            conn, addr = self.sock.accept()
            conn.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
            threading.Thread(target=self.ssocks5rrun,
                             args=(conn, self.pwd, self.spwd, self.saf,
                                   self.saddr, self.shost, self.tlsctx,
                                   self.debug),
                             daemon=True).start()


class SSocks5Server:

    def __init__(self, addr, pwd, certfile, keyfile, debug):
        af, _, _, _, addr = socket.getaddrinfo \
            (addr[0], addr[1], type=socket.SOCK_STREAM)[0]
        self.sock = socket.socket(af, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self.sock.bind(addr)
        self.pwd = md5(pwd[0]).digest() + md5(pwd[1]).digest()
        self.tlsctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.tlsctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self.debug = debug

    @staticmethod
    def ssocks5run(isock, pwd, tlsctx, debug):
        try:
            SSocks5(isock, pwd, tlsctx).run()
        except Exception as e:
            if debug:
                print(f'{threading.get_native_id()}: {type(e)} {e}')

    def run(self):
        self.sock.listen()
        while True:
            conn, addr = self.sock.accept()
            conn.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
            threading.Thread(target=self.ssocks5run,
                             args=(conn, self.pwd, self.tlsctx, self.debug),
                             daemon=True).start()


if __name__ == '__main__':
    import argparse
    import signal
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true', default=False)
    parser.add_argument('-r', '--relay', action='store_true', default=False)
    parser.add_argument('-u', '--url', default='')
    parser.add_argument('-s', '--surl', default='')
    parser.add_argument('-H', '--host')
    parser.add_argument('-c', '--cert', default='cert.pem')
    parser.add_argument('-k', '--key', default='key.pem')
    args = parser.parse_args()
    debug = args.debug
    relay = args.relay
    addr, pwd = socks5_urlparse(args.url, ('localhost', 1080))
    saddr, spwd = socks5_urlparse(args.surl, ('localhost', 443))
    shost = args.host or saddr[0]
    certfile = args.cert
    keyfile = args.key
    assert spwd

    signal.signal(signal.SIGINT, lambda _no, _f: sys.exit(0))
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

    if relay:
        SSocks5RServer(addr, pwd, spwd, saddr, shost, certfile, debug).run()
    else:
        SSocks5Server(saddr, spwd, certfile, keyfile, debug).run()
