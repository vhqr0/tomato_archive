#!/usr/bin/env python3
'''
Reverse proxy bypassing NAT, support auto reconnection.
'''

import asyncio
import time
import hashlib


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


class connector:

    def __init__(self, in_addr, in_port, out_addr, out_port, password,
                 timewait, debug):
        self.in_addr = in_addr
        self.in_port = in_port
        self.out_addr = out_addr
        self.out_port = out_port
        self.password = password.encode() if password else b''
        self.timewait = timewait
        self.debug = debug

    def run(self):
        asyncio.run(self.start_server())

    async def start_server(self):
        while True:
            print('open connection...')
            err = None
            try:
                peername, in_reader, in_writer, out_reader, out_writer = \
                    await self.open_connection()
            except Exception as e:
                err = e
            if err:
                print(f'open connection raise: {err}')
                print('restart timewait...')
                await asyncio.sleep(self.timewait)
                print('restart...')
            else:
                print(f'accept from {peername}')
                asyncio.create_task(
                    self.proxy(in_reader, in_writer, out_reader, out_writer))

    async def open_connection(self):
        ts = int.to_bytes(int(time.time()), 4, 'big')
        tag = ts + hashlib.sha224(self.password + ts).digest()
        in_reader, in_writer = await asyncio.open_connection(
            self.in_addr, self.in_port)
        in_writer.write(tag)
        await in_writer.drain()
        peername = await in_reader.readuntil(b'\r\n')
        peername = peername[:-2].decode()
        out_reader, out_writer = await asyncio.open_connection(
            self.out_addr, self.out_port)
        return peername, in_reader, in_writer, out_reader, out_writer

    async def proxy(self, in_reader, in_writer, out_reader, out_writer):
        try:
            await asyncio.gather(proxy(in_reader, out_writer),
                                 proxy(out_reader, in_writer))
        except:
            if self.debug:
                raise


class acceptor:

    def __init__(self, in_addr, in_port, out_addr, out_port, password, debug):
        self.in_addr = in_addr
        self.in_port = in_port
        self.out_addr = out_addr
        self.out_port = out_port
        self.password = password.encode() if password else b''
        self.debug = debug

    def run(self):
        asyncio.run(self.start_server())

    async def start_server(self):
        self.connections = asyncio.Queue()
        await asyncio.gather(self.start_server_in(), self.start_server_out())

    async def start_server_in(self):
        server = await asyncio.start_server(self.do_accept_in, self.in_addr,
                                            self.in_port)
        async with server:
            await server.serve_forever()

    async def start_server_out(self):
        server = await asyncio.start_server(self.do_accept_out, self.out_addr,
                                            self.out_port)
        async with server:
            await server.serve_forever()

    async def do_accept_in(self, in_reader, in_writer):
        peername = in_writer.get_extra_info('peername')
        peername = f'{peername[0]}:{peername[1]}'
        print(f'accept from {peername}')
        self.connections.put_nowait((in_reader, in_writer, peername))

    async def do_accept_out(self, out_reader, out_writer):
        try:
            tag = await out_reader.readexactly(32)
            ts = int.from_bytes(tag[:4], 'big')
            assert abs(ts - (int(time.time()) & 0xffffffff)) < 5 and \
                hashlib.sha224(self.password + tag[:4]).digest() == tag[4:]
            peername = out_writer.get_extra_info('peername')
            print(f'accept connector {peername[0]}:{peername[1]}...')
            in_reader, in_writer, peername = await self.connections.get()
            self.connections.task_done()
            print(f'connector get {peername}')
            if out_reader.at_eof():
                print('connector reset...')
                self.connections.put_nowait((in_reader, in_writer, peername))
                return
            out_writer.write(peername.encode() + b'\r\n')
            await out_writer.drain()
            await asyncio.gather(proxy(in_reader, out_writer),
                                 proxy(out_reader, in_writer))
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
                        '--connector',
                        action='store_const',
                        dest='mode',
                        const='connector')
    parser.add_argument('-a',
                        '--acceptor',
                        action='store_const',
                        dest='mode',
                        const='acceptor')
    parser.add_argument('-i', '--inbound')
    parser.add_argument('-o', '--outbound')
    parser.add_argument('-p', '--password')
    parser.add_argument('-t', '--timewait', type=int, default=15)
    args = parser.parse_args()
    debug = args.debug
    mode = args.mode or 'connector'
    inbound = urlparse('//' + (args.inbound or ''))
    outbound = urlparse('//' + (args.outbound or ''))
    password = args.password
    timewait = args.timewait

    signal.signal(signal.SIGINT, lambda _no, _f: sys.exit(0))
    if mode == 'connector':
        connector(inbound.hostname or 'localhost', inbound.port or 1022,
                  outbound.hostname or 'localhost', outbound.port or 22,
                  password, timewait, debug).run()
    elif mode == 'acceptor':
        acceptor(inbound.hostname or 'localhost', inbound.port or 2222,
                 outbound.hostname or 'localhost', outbound.port or 1022,
                 password, debug).run()


if __name__ == '__main__':
    main()
