#!/usr/bin/env python3

import socket
import struct
import errno
import threading

from pipe import pipe

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


class Socks5:

    def __init__(self, isock, pwd):
        self.isock = isock
        self.osock = None
        self.pwd = pwd
        self.cmd = -1
        self.atype = -1
        self.addr = ('', 0)

    def run(self):
        self.do_read_auth()
        self.do_read_req()
        self.do_exec_cmd()
        pipe(self.isock, self.osock)

    def isock_recvall(self, n):
        return self.isock.recv(n, socket.MSG_WAITALL)

    def do_read_auth(self):
        buf = self.isock_recvall(2)
        ver, nmeths = struct.unpack('!BB', buf)
        assert ver == 5 and nmeths != 0
        meths = tuple(self.isock_recvall(nmeths))
        meth = AUTH_PASSWORD if self.pwd else AUTH_NOAUTH
        if meth not in meths:
            meth = AUTH_NOACCEPT
        self.isock.sendall(struct.pack('!BB', 5, meth))
        assert meth != AUTH_NOACCEPT
        if meth == AUTH_PASSWORD:
            buf = self.isock_recvall(2)
            ver, ulen = struct.unpack('!BB', buf)
            assert ver == 1 and ulen != 0
            buf = self.isock_recvall(ulen + 1)
            uname, plen = struct.unpack(f'!{ulen}sB', buf)
            assert plen != 0
            passwd = self.isock_recvall(plen)
            sts = PWD_SUCCESS if (uname, passwd) == self.pwd else PWD_FAILURE
            self.isock.sendall(struct.pack('!BB', 1, sts))
            assert sts == PWD_SUCCESS

    def do_read_req(self):
        buf = self.isock_recvall(4)
        ver, cmd, rsv, atype = struct.unpack('!BBBB', buf)
        assert ver == 5 and rsv == 0 and \
            atype in (ATYPE_IPV4, ATYPE_IPV6, ATYPE_DOMAIN)
        self.cmd, self.atype = cmd, atype
        alen = 0
        if self.atype == ATYPE_IPV4:
            alen = 4
        elif self.atype == ATYPE_IPV6:
            alen = 16
        else:
            alen = self.isock_recvall(1)[0]
        buf = self.isock_recvall(alen + 2)
        addr = struct.unpack(f'!{alen}sH', buf)
        if self.atype == ATYPE_IPV4:
            self.addr = (socket.inet_ntop(socket.AF_INET, addr[0]), addr[1])
        elif self.atype == ATYPE_IPV6:
            self.addr = (socket.inet_ntop(socket.AF_INET6, addr[0]), addr[1])
        else:
            self.addr = addr

    def do_write_rep(self, rep):
        buf = b''
        if self.atype == ATYPE_IPV4:
            addr = socket.inet_pton(socket.AF_INET, self.addr[0])
            buf = struct.pack('!4sH', addr, self.addr[1])
        elif self.atype == ATYPE_IPV6:
            addr = socket.inet_pton(socket.AF_INET6, self.addr[0])
            buf = struct.pack('!16sH', addr, self.addr[1])
        else:
            alen = len(self.addr[0])
            buf = struct.pack(f'!B{alen}sH', alen, self.addr[0], self.addr[1])
        buf = struct.pack('!BBBB', 5, rep, 0, self.atype) + buf
        self.isock.sendall(buf)

    def do_exec_cmd(self):
        if self.cmd == CMD_CONNECT:
            self.do_connect()
        elif self.cmd == CMD_BIND:
            self.do_bind()
        else:
            self.do_write_rep(REP_CMDNOTSUPPORT)
            raise NotImplementedError(f'Socks5 CMD {self.cmd} not implemented')

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
              f'{self.isock.getpeername()} connect to {self.addr}')
        if self.atype == ATYPE_DOMAIN:
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
        if self.atype == ATYPE_DOMAIN:
            self.do_resolve()
        af = socket.AF_INET if self.atype == ATYPE_IPV4 else socket.AF_INET6
        sock = socket.socket(af, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        sock.bind(self.addr)

        try:
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

    def __init__(self, addr, pwd, debug):
        af, _, _, _, addr = socket.getaddrinfo \
            (addr[0], addr[1], type=socket.SOCK_STREAM)[0]
        self.sock = socket.socket(af, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self.sock.bind(addr)
        self.pwd = pwd
        self.debug = debug

    @staticmethod
    def socks5run(isock, pwd, debug):
        try:
            Socks5(isock, pwd).run()
        except Exception as e:
            if debug:
                print(f'{threading.get_native_id()}: {type(e)} {e}')

    def run(self):
        self.sock.listen()
        while True:
            conn, addr = self.sock.accept()
            conn.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
            threading.Thread(target=self.socks5run,
                             args=(conn, self.pwd, self.debug),
                             daemon=True).start()


from urllib.parse import urlparse


def socks5_urlparse(url, defaddr):
    url = urlparse('//' + url)
    addr = (url.hostname or defaddr[0], url.port or defaddr[1])
    pwd = None
    if url.username and url.password:
        pwd = (url.username.encode(), url.password.encode())
    return addr, pwd


if __name__ == '__main__':
    import argparse
    import signal
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true', default=False)
    parser.add_argument('-u', '--url', default='')
    args = parser.parse_args()
    debug = args.debug
    addr, pwd = socks5_urlparse(args.url, ('localhost', 1080))

    signal.signal(signal.SIGINT, lambda _no, _f: sys.exit(0))
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    Socks5Server(addr, pwd, debug).run()
