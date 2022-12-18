#!/usr/bin/env python3
'''
End-to-End UDP forwarder.
'''

import asyncio
import time


class udp_forward_in_session(asyncio.DatagramProtocol):

    def __init__(self, queue):
        self.queue = queue

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.queue.put_nowait((addr, data))


class udp_forward_out_session(asyncio.DatagramProtocol):

    def __init__(self, in_addr, out_addr, queue):
        self.ts = time.time
        self.in_addr = in_addr
        self.out_addr = out_addr
        self.queue = queue

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if addr != self.out_addr:
            return
        self.ts = time.time()
        self.queue.put_nowait((self.in_addr, data))

    def send(self, data):
        self.ts = time.time()
        self.transport.sendto(data, self.out_addr)


class udp_forwarder:

    def __init__(self, in_addr, out_addr, clear_internal):
        self.in_addr = in_addr
        self.out_addr = out_addr
        self.clear_internal = clear_internal
        self.out_sessions = dict()

    def run(self):
        asyncio.run(self.start_server())

    async def start_server(self):
        self.in_queue = asyncio.Queue()
        self.out_queue = asyncio.Queue()
        _, in_session = await asyncio.get_running_loop(
        ).create_datagram_endpoint(
            lambda: udp_forward_in_session(self.in_queue),
            local_addr=self.in_addr)
        self.in_session = in_session
        asyncio.create_task(self.in_recv())
        asyncio.create_task(self.out_recv())
        while True:
            await asyncio.sleep(self.clear_internal)
            self.out_sessions_clear()

    async def in_recv(self):
        while True:
            addr, data = await self.in_queue.get()
            self.in_queue.task_done()
            if addr in self.out_sessions:
                print(f'{addr} => remote')
                self.out_sessions[addr].send(data)
            else:
                print(f'new session: {addr}')
                _, out_session = await asyncio.get_running_loop(
                ).create_datagram_endpoint(lambda: udp_forward_out_session(
                    addr, self.out_addr, self.out_queue),
                                           remote_addr=self.out_addr)
                self.out_sessions[addr] = out_session
                out_session.send(data)

    async def out_recv(self):
        while True:
            addr, data = await self.out_queue.get()
            self.out_queue.task_done()
            print(f'remote => {addr}')
            self.in_session.transport.sendto(data, addr)

    def out_sessions_clear(self):
        ts = time.time()
        for addr, out_session in list(self.out_sessions.items()):
            if abs(out_session.ts - ts) > self.clear_internal:
                print(f'clear session: {out_session.in_addr}')
                out_session.transport.close()
                del self.out_sessions[addr]


def main():
    import sys
    import signal
    import argparse
    from urllib.parse import urlparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--inbound')
    parser.add_argument('-o', '--outbound')
    parser.add_argument('-I', '--internal', type=int, default=60)
    args = parser.parse_args()
    inbound = urlparse('//' + (args.inbound or ''))
    in_addr = (inbound.hostname or '0.0.0.0', inbound.port or 53)
    outbound = urlparse('//' + (args.outbound or ''))
    out_addr = (outbound.hostname or '127.0.0.1', outbound.port or 53)
    internal = args.internal

    signal.signal(signal.SIGINT, lambda _no, _f: sys.exit(0))
    udp_forwarder(in_addr, out_addr, internal).run()


if __name__ == '__main__':
    main()
