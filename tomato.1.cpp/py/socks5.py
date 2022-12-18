#!/usr/bin/env python3

import socket
import struct
import errno
import threading

from relay import relay

AUTH_NOAUTH = 0
AUTH_GSSAPI = 1
AUTH_PASSWORD = 2
AUTH_NOACCEPT = 0xff

PWD_SUCCESS = 0
PWD_FAILURE = 0xff

CMD_CONNECT = 1
CMD_BIND = 2
CMD_UDPASSOC = 3

ATYPE_IPV4 = 1
ATYPE_IPV6 = 4
ATYPE_DOMAIN = 3

REP_SUCCESS = 0
REP_GENERALFAILURE = 1
REP_CONNNOTALLOWED = 2
REP_NETUNREACH = 3
REP_HOSTUNREACH = 4
REP_CONNREFUSED = 5
REP_TIMEOUT = 6
REP_CMDNOTSUPPORT = 7
REP_ATYPENOTSUPPORT = 8


class Socks5Session:

    def __init__(self, isock, auth):
        self.isock = isock
        self.osock = None
        self.auth = auth
        self.cmd = -1
        self.atype = -1
        self.addr = ('', 0)

    def run(self):
        self.do_read_auth()
        self.do_read_req()
        self.do_exec_cmd()
        relay(self.isock, self.osock)

    def do_read_auth(self):
        buf = self.isock.recv(4096)
        nmeths = buf[1]
        ver, nmeths, meths = struct.unpack(f'!BB{nmeths}s', buf)
        assert ver == 5
        meths = tuple(meths)
        meth = AUTH_PASSWORD if self.auth else AUTH_NOAUTH
        if meth not in meths:
            meth = AUTH_NOACCEPT
        self.isock.sendall(struct.pack('!BB', 5, meth))
        assert meth != AUTH_NOACCEPT
        if meth == AUTH_PASSWORD:
            buf = self.isock.recv(4096)
            ulen = buf[1]
            plen = buf[2 + ulen]
            ver, ulen, uname, plen, passwd = struct.unpack(
                f'!BB{ulen}sB{plen}s', buf)
            assert ver == 1
            sts = PWD_SUCCESS if (uname, passwd) == self.auth else PWD_FAILURE
            self.isock.sendall(struct.pack('!BB', 1, sts))
            assert sts == PWD_SUCCESS

    def do_read_req(self):
        buf = self.isock.recv(4096)
        atype = buf[3]
        assert atype in (ATYPE_IPV4, ATYPE_IPV6, ATYPE_DOMAIN)
        if atype == ATYPE_IPV4:
            ver, cmd, rsv, atype, addr, port = struct.unpack('!BBBB4sH', buf)
            addr = socket.inet_ntop(socket.AF_INET, addr)
        elif atype == ATYPE_IPV6:
            ver, cmd, rsv, atype, addr, port = struct.unpack('!BBBB16sH', buf)
            addr = socket.inet_ntop(socket.AF_INET6, addr)
        else:
            alen = buf[4]
            ver, cmd, rsv, atype, alen, addr, port = struct.unpack(
                f'!BBBBB{alen}sH', buf)
            addr = addr.decode()
        assert ver == 5 and rsv == 0
        self.cmd = cmd
        self.atype = atype
        self.addr = (addr, port)

    def do_write_rep(self, rep):
        buf = b''
        if self.atype == ATYPE_IPV4:
            if rep == REP_SUCCESS:
                buf = struct.pack(
                    '!B4sH', ATYPE_IPV4,
                    socket.inet_pton(socket.AF_INET, self.addr[0]),
                    self.addr[1])
            else:
                buf = struct.pack('!B4sH', ATYPE_IPV4, b'\x00' * 4, 0)
        elif self.atype == ATYPE_IPV6:
            if rep == REP_SUCCESS:
                buf = struct.pack(
                    '!B16sH', ATYPE_IPV6,
                    socket.inet_pton(socket.AF_INET6, self.addr[0]),
                    self.addr[1])
            else:
                buf = struct.pack('!B16sH', ATYPE_IPV6, b'\x00' * 16, 0)
        else:
            buf = struct.pack('!B16sH', ATYPE_IPV6, b'\x00', 16, 0)
        self.isock.sendall(struct.pack('!BBB', 5, rep, 0) + buf)

    def do_exec_cmd(self):
        if self.cmd == CMD_CONNECT:
            self.do_connect()
        elif self.cmd == CMD_BIND:
            self.do_bind()
        else:
            self.do_write_rep(REP_CMDNOTSUPPORT)
            raise NotImplementedError(f'SOCKS5 CMD {self.cmd}')

    def do_resolve(self):
        if self.atype != ATYPE_DOMAIN:
            return
        af, _, _, _, addr = socket.getaddrinfo \
            (self.addr[0], self.addr[1], type=socket.SOCK_STREAM)[0]
        assert af in (socket.AF_INET, socket.AF_INET6)
        self.atype = ATYPE_IPV4 if af == socket.AF_INET else ATYPE_IPV6
        self.addr = addr

    def do_connect(self):
        print(f'{threading.get_native_id()}: '
              f'{self.isock.getpeername()[:2]} connect to {self.addr[:2]}')
        self.do_resolve()
        af = socket.AF_INET if self.atype == ATYPE_IPV4 else socket.AF_INET6
        self.osock = socket.socket(af, socket.SOCK_STREAM)
        self.osock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)

        try:
            self.osock.connect(self.addr)
        except OSError as e:
            rep = REP_GENERALFAILURE
            if e.errno == errno.ENETUNREACH:
                rep = REP_NETUNREACH
            elif e.errno == errno.EHOSTUNREACH:
                rep = REP_HOSTUNREACH
            elif e.errno == errno.ECONNREFUSED:
                rep = REP_CONNREFUSED
            elif e.errno == errno.ETIMEDOUT:
                rep = REP_TIMEOUT
            self.addr = self.osock.getsockname()
            self.do_write_rep(rep)
            raise e
        else:
            self.addr = self.osock.getsockname()
            self.do_write_rep(REP_SUCCESS)

    def do_bind(self):
        print(f'{threading.get_native_id()}: '
              f'{self.isock.getpeername()} bind to {self.addr}')
        self.do_resolve()
        af = socket.AF_INET if self.atype == ATYPE_IPV4 else socket.AF_INET6
        sock = socket.socket(af, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

        try:
            sock.bind(self.addr)
            sock.listen(1)
        except OSError as e:
            self.addr = sock.getsockname()
            self.do_write_rep(REP_GENERALFAILURE)
            raise e
        else:
            self.addr = sock.getsockname()
            self.do_write_rep(REP_SUCCESS)

        try:
            self.osock, self.addr = sock.accept()
            self.osock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
        except OSError as e:
            self.do_write_rep(REP_GENERALFAILURE)
            raise e
        else:
            self.do_write_rep(REP_SUCCESS)


class Socks5Server:

    def __init__(self, addr, auth, debug):
        af, _, _, _, addr = socket.getaddrinfo \
            (addr[0], addr[1], type=socket.SOCK_STREAM)[0]
        self.sock = socket.socket(af, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self.sock.bind(addr)
        self.auth = auth
        self.debug = debug

    @staticmethod
    def socks5run(isock, auth, debug):
        try:
            Socks5Session(isock, auth).run()
        except Exception as e:
            if debug:
                print(f'{threading.get_native_id()}: {type(e)} {e}')

    def run(self):
        self.sock.listen()
        while True:
            conn, addr = self.sock.accept()
            conn.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
            threading.Thread(target=self.socks5run,
                             args=(conn, self.auth, self.debug),
                             daemon=True).start()



if __name__ == '__main__':
    from urllib.parse import urlparse
    import argparse
    import signal
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('-u', '--url', default='')
    args = parser.parse_args()
    debug = args.debug
    url = urlparse('//' + args.url)
    addr = (url.hostname or 'localhost', url.port or 1080)
    auth = (url.username, url.password)
    if not (auth[0] and auth[1]):
        auth = None
    else:
        auth = (auth[0].encode(), auth[1].encode())

    signal.signal(signal.SIGINT, lambda _no, _f: sys.exit(0))
    Socks5Server(addr, auth, debug).run()
