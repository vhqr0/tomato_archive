#!/usr/bin/env python3
'''
Simple python implementation of tomato.
'''

import asyncio
import socket
import ssl
import re
import struct
import hashlib
import binascii
import sqlite3

ATYPE_IPV4 = 1
ATYPE_IPV6 = 4
ATYPE_DOMAIN = 3

RULE_BLOCK = 1
RULE_PROXY = 2
RULE_DIRECT = 3

rules_db_conn = None
rules_db_cur = None
rules_cache = dict()
rules_default = RULE_PROXY


def rules_set_default(rule):
    global rules_default
    rules_default = rule


def rules_db_open(dbfile):
    global rules_db_conn, rules_db_cur
    rules_db_conn = sqlite3.connect(dbfile)
    rules_db_cur = rules_db_conn.cursor()


def rules_match(domain):
    if not rules_db_conn:
        return rules_default
    if domain in rules_cache:
        return rules_cache[domain]
    rules_db_cur.execute(f'select rule from data where domain={repr(domain)};')
    res = rules_db_cur.fetchone()
    if res:
        res = res[0]
    if not res:
        pos = domain.find('.')
        if pos > 0:
            res = rules_match(domain[pos + 1:])
    if not res:
        res = rules_default
    assert res in (RULE_BLOCK, RULE_PROXY, RULE_DIRECT)
    rules_cache[domain] = res
    return res


async def proxy(reader, writer):
    while True:
        buf = await reader.read(4096)
        if len(buf) == 0:
            if writer.can_write_eof():
                writer.write_eof()
            break
        else:
            writer.write(buf)
            await writer.drain()


async def socks5_unpack(buf, reader, writer):
    nmeths = buf[1]
    ver, nmeths, meths = struct.unpack(f'!BB{nmeths}s', buf)
    assert ver == 5 and 0 in meths
    writer.write(b'\x05\x00')
    await writer.drain()
    buf = await reader.read(4096)
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
    assert ver == 5 and cmd == 1 and rsv == 0
    writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
    await writer.drain()
    return addr, port


http_re1 = re.compile(r'^(\w+) [^ ]+ (HTTP/[^ \r\n]+)\r\n')
http_re2 = re.compile(
    r'\r\nHost: ([^ :\[\]\r\n]+|\[[:0-9a-fA-F]+\])(:([0-9]+))?\r\n')


async def http_unpack(buf, reader, writer):
    pos = buf.find(b'\r\n\r\n')
    assert pos > 0
    header = buf[:pos + 2].decode()
    rest = buf[pos + 4:]
    res1 = http_re1.search(header)
    res2 = http_re2.search(header)
    assert res1 and res2
    method = res1[1]
    version = res1[2]
    addr = res2[1]
    port = res2[3]
    addr = addr if addr[0] != '[' else addr[1:-1]
    port = int(port) if port else 80
    if method == 'CONNECT':
        writer.write(
            f'{version} 200 Connection Established\r\nConnection: close\r\n\r\n'
            .encode())
        await writer.drain()
    else:
        rest = '\r\n'.join(
            h for h in header.split('\r\n')
            if not h.startswith('Proxy-')).encode() + b'\r\n' + rest
    return addr, port, rest


async def socks5_or_http_unpack(reader, writer):
    buf = await reader.read(4096)
    if buf[0] == 5:
        addr, port = await socks5_unpack(buf, reader, writer)
        return addr, port, b''
    else:
        return await http_unpack(buf, reader, writer)


async def trojan_unpack(reader, writer, password):
    buf = await reader.read(4096)
    atype = buf[59]
    assert atype in (ATYPE_IPV4, ATYPE_IPV6, ATYPE_DOMAIN)
    if atype == ATYPE_IPV4:
        hlen = 68
        received_password, del1, cmd, atype, addr, port, del2 = struct.unpack(
            '!56s2sBB4sH2s', buf[:hlen])
        addr = socket.inet_ntop(socket.AF_INET, addr)
        rest = buf[hlen:]
    elif atype == ATYPE_IPV6:
        hlen = 80
        received_password, del1, cmd, atype, addr, port, del2 = struct.unpack(
            '!56s2sBB16sH2s', buf[:hlen])
        addr = socket.inet_ntop(socket.AF_INET6, addr)
        rest = buf[hlen:]
    else:
        alen = buf[60]
        hlen = alen + 65
        received_password, del1, cmd, atype, alen, addr, port, del2 = struct.unpack(
            f'!56s2sBBB{alen}sH2s', buf[:hlen])
        addr = addr.decode()
        rest = buf[hlen:]
    assert received_password == password and \
        del1 == b'\r\n' and cmd == 1 and del2 == b'\r\n'
    return addr, port, rest


def trojan_pack(password, addr, port, rest):
    addr = addr.encode()
    alen = len(addr)
    return struct.pack(f'!56s2sBBB{alen}sH2s', password, b'\r\n', 1,
                       ATYPE_DOMAIN, alen, addr, port, b'\r\n') + rest


async def socks5_connect(in_reader, in_writer, addr, port, rest):
    peername = in_writer.get_extra_info('peername')[:2]
    rule = rules_match(addr)
    if rule not in (RULE_PROXY, RULE_DIRECT):
        print(f'{peername} <=> {(addr, port)} [block]')
        in_writer.close()
        await in_writer.wait_closed()
        return
    else:
        print(f'{peername} <=> {(addr, port)} [proxy/direct]')
    out_reader, out_writer = await asyncio.open_connection(addr, port)
    if rest:
        out_writer.write(rest)
        await out_writer.drain()
    await asyncio.gather(proxy(in_reader, out_writer),
                         proxy(out_reader, in_writer))


async def trojan_connect(in_reader, in_writer, out_addr, out_port,
                         ssl_hostname, ssl_context, password, addr, port,
                         rest):
    peername = in_writer.get_extra_info('peername')[:2]
    rule = rules_match(addr)
    if rule not in (RULE_PROXY, RULE_DIRECT):
        print(f'{peername} <=> {(addr, port)} [block]')
        in_writer.close()
        await in_writer.wait_closed()
        return
    elif rule == RULE_PROXY:
        print(f'{peername} <=> {(addr, port)} [proxy]')
        out_reader, out_writer = await asyncio.open_connection(
            out_addr, out_port, server_hostname=ssl_hostname, ssl=ssl_context)
        rest = trojan_pack(password, addr, port, rest)
    elif rule == RULE_DIRECT:
        print(f'{peername} <=> {(addr, port)} [direct]')
        out_reader, out_writer = await asyncio.open_connection(addr, port)
    if rest:
        out_writer.write(rest)
        await out_writer.drain()
    await asyncio.gather(proxy(in_reader, out_writer),
                         proxy(out_reader, in_writer))


class socks5:

    def __init__(self, in_addr, in_port, debug):
        self.in_addr = in_addr
        self.in_port = in_port
        self.debug = debug

    def run(self):
        asyncio.run(self.start_server())

    async def start_server(self):
        server = await asyncio.start_server(self.open_connection,
                                            self.in_addr,
                                            self.in_port,
                                            reuse_address=True)
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        print(f'server start at {addrs}')
        async with server:
            await server.serve_forever()

    async def open_connection(self, in_reader, in_writer):
        try:
            addr, port, rest = await socks5_or_http_unpack(
                in_reader, in_writer)
            await socks5_connect(in_reader, in_writer, addr, port, rest)
        except:
            if self.debug:
                raise


class trojanc:

    def __init__(self, in_addr, in_port, out_addr, out_port, password,
                 ssl_hostname, ssl_cafile, debug):
        self.in_addr = in_addr
        self.in_port = in_port
        self.out_addr = out_addr
        self.out_port = out_port
        self.password = binascii.hexlify(
            hashlib.sha224(password.encode() if password else b'').digest())
        self.ssl_hostname = ssl_hostname or out_addr
        self.ssl_context = ssl.create_default_context(
            cafile=(ssl_cafile if ssl_cafile else None))
        self.debug = debug

    def run(self):
        asyncio.run(self.start_server())

    async def start_server(self):
        server = await asyncio.start_server(self.open_connection,
                                            self.in_addr,
                                            self.in_port,
                                            reuse_address=True)
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        print(f'server start at {addrs}')
        async with server:
            await server.serve_forever()

    async def open_connection(self, in_reader, in_writer):
        try:
            addr, port, rest = await socks5_or_http_unpack(
                in_reader, in_writer)
            await trojan_connect(in_reader, in_writer, self.out_addr,
                                 self.out_port, self.ssl_hostname,
                                 self.ssl_context, self.password, addr, port,
                                 rest)
        except:
            if self.debug:
                raise


class trojans:

    def __init__(self, in_addr, in_port, password, ssl_certfile, ssl_keyfile,
                 ssl_keypassword, debug):
        self.in_addr = in_addr
        self.in_port = in_port
        self.password = binascii.hexlify(
            hashlib.sha224(password.encode() if password else b'').digest())
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.load_cert_chain(
            certfile=ssl_certfile,
            keyfile=ssl_keyfile,
            password=(ssl_keypassword if ssl_keypassword else None))
        self.debug = debug

    def run(self):
        asyncio.run(self.start_server())

    async def start_server(self):
        server = await asyncio.start_server(self.open_connection,
                                            self.in_addr,
                                            self.in_port,
                                            reuse_address=True,
                                            ssl=self.ssl_context)
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        print(f'server start at {addrs}')
        async with server:
            await server.serve_forever()

    async def open_connection(self, in_reader, in_writer):
        try:
            addr, port, rest = await trojan_unpack(in_reader, in_writer,
                                                   self.password)
            await socks5_connect(in_reader, in_writer, addr, port, rest)
        except:
            if self.debug:
                raise


def main():
    import sys
    import signal
    import argparse
    from urllib.parse import urlparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('-c',
                        '--client',
                        action='store_const',
                        dest='mode',
                        const='client')
    parser.add_argument('-s',
                        '--server',
                        action='store_const',
                        dest='mode',
                        const='server')
    parser.add_argument('-i', '--inbound')
    parser.add_argument('-o', '--outbound')
    parser.add_argument('-p', '--password')
    parser.add_argument('-H', '--hostname')
    parser.add_argument('--ca', default='certs/cert.pem')
    parser.add_argument('--cert', default='certs/cert.pem')
    parser.add_argument('--key', default='certs/key.pem')
    parser.add_argument('--keypassword')
    parser.add_argument('--db')
    parser.add_argument('--block',
                        action='store_const',
                        dest='rule',
                        const=RULE_BLOCK)
    parser.add_argument('--proxy',
                        action='store_const',
                        dest='rule',
                        const=RULE_PROXY)
    parser.add_argument('--direct',
                        action='store_const',
                        dest='rule',
                        const=RULE_DIRECT)
    args = parser.parse_args()
    debug = args.debug
    mode = args.mode or 'socks5'
    inbound = urlparse('//' + (args.inbound or ''))
    outbound = urlparse('//' + (args.outbound or ''))
    password = args.password
    ssl_hostname = args.hostname
    ssl_cafile = args.ca
    ssl_certfile = args.cert
    ssl_keyfile = args.key
    ssl_keypassword = args.keypassword
    rules_db_file = args.db
    rules_default_rule = args.rule

    signal.signal(signal.SIGINT, lambda _no, _f: sys.exit(0))
    if rules_db_file:
        rules_db_open(rules_db_file)
    if rules_default_rule:
        rules_set_default(rules_default_rule)
    if mode == 'socks5':
        socks5(inbound.hostname or 'localhost', inbound.port or 1080,
               debug).run()
    elif mode == 'client':
        trojanc(inbound.hostname or 'localhost', inbound.port or 1080,
                outbound.hostname or 'localhost', outbound.port or 443,
                password, ssl_hostname, ssl_cafile, debug).run()
    elif mode == 'server':
        trojans(inbound.hostname or 'localhost', inbound.port or 443, password,
                ssl_certfile, ssl_keyfile, ssl_keypassword, debug).run()


if __name__ == '__main__':
    main()
