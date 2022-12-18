#!/usr/bin/env python3
'''
Forward traffic between two endpoints with different address family or TCP/TLS.
'''

import asyncio
import ssl


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


class forwarder:

    def __init__(self, in_addr, in_port, out_addr, out_port, in_ssl, out_ssl,
                 ssl_hostname, ssl_cafile, ssl_certfile, ssl_keyfile,
                 ssl_keypassword, debug):
        self.in_addr = in_addr
        self.in_port = in_port
        self.out_addr = out_addr
        self.out_port = out_port
        self.ssl_hostname = ssl_hostname
        self.in_ssl = None
        self.out_ssl = None
        if in_ssl:
            assert ssl_certfile and ssl_keyfile
            self.in_ssl = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.in_ssl.load_cert_chain(
                certfile=ssl_certfile,
                keyfile=ssl_keyfile,
                password=(ssl_keypassword if ssl_keypassword else None))
        if out_ssl:
            self.out_ssl = ssl.create_default_context(
                cafile=(ssl_cafile if ssl_cafile else None))
        self.debug = debug

    def run(self):
        asyncio.run(self.start_server())

    async def start_server(self):
        server = await asyncio.start_server(self.open_connection,
                                            self.in_addr,
                                            self.in_port,
                                            reuse_address=True,
                                            ssl=self.in_ssl)
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        print(f'server start at {addrs}')
        async with server:
            await server.serve_forever()

    async def open_connection(self, in_reader, in_writer):
        try:
            peername = in_writer.get_extra_info('peername')
            print(f'accept from {peername}')
            out_reader, out_writer = await asyncio.open_connection(
                self.out_addr,
                self.out_port,
                server_hostname=self.ssl_hostname,
                ssl=self.out_ssl)
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
    parser.add_argument('-m', '--mode', default='r2r')
    parser.add_argument('-i', '--inbound')
    parser.add_argument('-o', '--outbound')
    parser.add_argument('-H', '--hostname')
    parser.add_argument('--ca', default='certs/cert.pem')
    parser.add_argument('--cert', default='certs/cert.pem')
    parser.add_argument('--key', default='certs/key.pem')
    parser.add_argument('--keypassword')
    args = parser.parse_args()
    debug = args.debug
    mode = args.mode
    in_ssl = mode in ('t2r', 't2t')
    out_ssl = mode in ('r2t', 't2t')
    inbound = urlparse('//' + (args.inbound or ''))
    in_addr = inbound.hostname or 'localhost'
    in_port = inbound.port or 8080
    outbound = urlparse('//' + (args.outbound or ''))
    out_addr = outbound.hostname or 'localhost'
    out_port = outbound.port or 80
    ssl_hostname = args.hostname
    ssl_cafile = args.ca
    ssl_certfile = args.cert
    ssl_keyfile = args.key
    ssl_keypassword = args.keypassword

    signal.signal(signal.SIGINT, lambda _no, _f: sys.exit(0))
    forwarder(in_addr, in_port, out_addr, out_port, in_ssl, out_ssl,
              ssl_hostname, ssl_cafile, ssl_certfile, ssl_keyfile,
              ssl_keypassword, debug).run()


if __name__ == '__main__':
    main()
