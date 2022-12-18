#!/usr/bin/env python3
"""
add tunnel:
	ip tuntap add dev tun0 mode tun
	ip l set tun0 up
	ip a add 10.0.1.2/24 dev tun0
	ip r add x.x.x.x via y.y.y.y dev ens33 # connect to vpn y.y.y.y via prev gw x.x.x.x
	ip r add default via 10.0.1.1/24 dev tun0 # set peer of tun as new gw

add tunnel (router):
	ip tuntap add dev tun0 mode tun
	ip l set tun0 up
	ip a add 10.0.1.1/24 dev tun0
	echo 1 > /proc/sys/net/ipv4/ip_forward
	iptables -t nat -A POSTROUTING -s 10.0.1.0/24 -o ens33 -j MASQUERADE
"""

import platform
import os
import fcntl
import array
import struct
import select
import socket
import scapy.all as sp

TUNSETIFF = 0x400454ca

IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
IFF_PERSIST = 0x0800

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86dd

ARCH = platform.architecture()[0]
assert ARCH in ('32bit', '64bit')

IFREQSIZE = 40 if ARCH == '64bit' else 32
IFNAMSIZE = 16


def tun_open(dev, flags):
    ifr = array.array('B', bytes(IFREQSIZE))
    if dev:
        ifrn = array.array('B', dev.encode()[:15])
        ifr[:len(ifrn)] = ifrn
    if flags:
        ifr[16:18] = array.array('B', struct.pack('@H', flags))
    fd = os.open('/dev/net/tun', os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    dev = ifr[:16].tobytes()
    dev = dev[:dev.find(b'\x00')].decode()
    return fd, dev


def show(buf, addr=None):
    seq, ptype = struct.unpack('!HH', buf[:4])
    verb = f'recv from {addr}' if addr else 'read'
    if ptype == ETH_P_IP:
        print(f'{verb} ipv4: {seq} {sp.IP(buf[4:]).summary()}')
    elif ptype == ETH_P_IPV6:
        print(f'{verb} ipv6: {seq} {sp.IPv6(buf[4:]).summary()}')
    else:
        print(f'{verb} unknown: {seq}, {ptype}')


def vpn(fd, local_addr, peer_addr, *, family=socket.AF_INET, debug=False):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind(local_addr)
    while True:
        rfds, _, _ = select.select([fd, sock], [], [])
        if fd in rfds:
            buf = os.read(fd, 4096)
            if debug:
                show(buf)
            sock.sendto(buf, peer_addr)
        if sock in rfds:
            buf, addr = sock.recvfrom(4096)
            if debug:
                show(buf, addr)
            os.write(fd, buf)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('-i', '--iface', default='tun0')
    parser.add_argument('local_addr')
    parser.add_argument('local_port')
    parser.add_argument('peer_addr')
    parser.add_argument('peer_port')
    args = parser.parse_args()
    fd, dev = tun_open(args.iface, IFF_TUN)
    print(f'attached to {dev}')
    vpn(fd, (args.local_addr, int(args.local_port)),
        (args.peer_addr, int(args.peer_port)),
        debug=args.debug)
