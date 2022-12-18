#!/usr/bin/env python3

import ctypes

tomato = ctypes.cdll.LoadLibrary('./build/libtomato.so')

enc = lambda s: s.encode() if s else None

# forward #####################################################################

tomato.forward.restype = None
tomato.forward.argtypes = tuple(ctypes.c_char_p for _ in range(4))
forward = lambda laddr, raddr: \
    tomato.forward(laddr[0].encode(),
                   laddr[1].encode(),
                   raddr[0].encode(),
                   raddr[1].encode())

# tls2raw #####################################################################

tomato.tls2raw.restype = None
tomato.tls2raw.argtypes = tuple(ctypes.c_char_p for _ in range(7))
tls2raw = lambda laddr, raddr, certfile, keyfile, password: \
    tomato.tls2raw(laddr[0].encode(),
                   laddr[1].encode(),
                   raddr[0].encode(),
                   raddr[1].encode(),
                   certfile.encode(),
                   keyfile.encode(),
                   enc(password))

# raw2tls #####################################################################

tomato.raw2tls.restype = None
tomato.raw2tls.argtypes = tuple(ctypes.c_char_p for _ in range(6))
raw2tls = lambda laddr, raddr, hostname, cafile: \
    tomato.raw2tls(laddr[0].encode(),
                   laddr[1].encode(),
                   raddr[0].encode(),
                   raddr[1].encode(),
                   enc(hostname),
                   enc(cafile))

# socks5 ######################################################################

tomato.socks5.restype = None
tomato.socks5.argtypes = \
    tuple(ctypes.c_char_p for _ in range(4)) + (ctypes.c_int, )
socks5 = lambda addr, auth, strict: \
    tomato.socks5(addr[0].encode(),
                  addr[1].encode(),
                  enc(auth[0]),
                  enc(auth[1]),
                  strict)

# socks5s #####################################################################

tomato.socks5s.restype = None
tomato.socks5s.argtypes = \
    tuple(ctypes.c_char_p for _ in range(7)) + (ctypes.c_int, )
socks5s = lambda addr, auth, certfile, keyfile, password, strict: \
    tomato.socks5s(addr[0].encode(),
                   addr[1].encode(),
                   enc(auth[0]),
                   enc(auth[1]),
                   certfile.encode(),
                   keyfile.encode(),
                   enc(password),
                   strict)

# proxyrules ##################################################################

RULE_BLOCK = 1
RULE_PROXY = 2
RULE_DIRECT = 3

ruled = {'block': RULE_BLOCK, 'proxy': RULE_PROXY, 'direct': RULE_DIRECT}

tomato.set_default_rule.restype = None
tomato.set_default_rule.argtypes = (ctypes.c_int, )
set_default_rule = lambda rule: tomato.set_default_rule(ruled[rule])

tomato.add_ip_rule.restype = None
tomato.add_ip_rule.argtypes = (ctypes.c_char_p, ctypes.c_int)
add_ip_rule = lambda mmdb, rule: tomato.add_ip_rule(mmdb.encode(), ruled[rule])

tomato.add_domain_rule.restype = None
tomato.add_domain_rule.argtypes = (ctypes.c_char_p, ctypes.c_int)
add_domain_rule = lambda domain, rule: \
    tomato.add_domain_rule(domain.encode(), ruled[rule])

tomato.clear_rules.restype = None
tomato.clear_rules.argtypes = None
clear_rules = tomato.clear_rules


def add_rules(rulesfile):
    with open(rulesfile) as rf:
        set_default_rule(rf.readline()[:-1])
        for line in rf:
            cmd, arg, rule = line.split()
            if cmd == 'ip':
                add_ip_rule(arg, rule)
            elif cmd == 'domain':
                add_domain_rule(arg, rule)
            elif cmd == 'domains':
                with open(arg) as df:
                    for domain in df:
                        add_domain_rule(domain[:-1], rule)
            else:
                raise ValueError()


# socks5f #####################################################################

tomato.socks5f.restype = None
tomato.socks5f.argtypes = tuple(ctypes.c_char_p for _ in range(10))
socks5f = lambda laddr, lauth, raddr, rauth, hostname, cafile: \
    tomato.socks5f(laddr[0].encode(),
                   laddr[1].encode(),
                   enc(lauth[0]),
                   enc(lauth[1]),
                   raddr[0].encode(),
                   raddr[1].encode(),
                   enc(rauth[0]),
                   enc(rauth[1]),
                   enc(hostname),
                   enc(cafile))

# acceptor ####################################################################

tomato.acceptor.restype = None
tomato.acceptor.argtypes = tuple(ctypes.c_char_p for _ in range(9))
acceptor = lambda caddr, addr, auth, certfile, keyfile, password: \
    tomato.acceptor(caddr[0].encode(),
                    caddr[1].encode(),
                    addr[0].encode(),
                    addr[1].encode(),
                    enc(auth[0]),
                    enc(auth[1]),
                    certfile.encode(),
                    keyfile.encode(),
                    enc(password))

# connector ###################################################################

tomato.connector.restype = None
tomato.connector.argtypes = tuple(ctypes.c_char_p for _ in range(8))
connector = lambda aaddr, addr, auth, hostname, cafile: \
    tomato.connector(aaddr[0].encode(),
                     aaddr[1].encode(),
                     addr[0].encode(),
                     addr[1].encode(),
                     enc(auth[0]),
                     enc(auth[1]),
                     enc(hostname),
                     enc(cafile))

# main ########################################################################


def main():
    import signal
    import argparse
    from urllib.parse import urlparse

    signal.signal(signal.SIGINT, signal.SIG_DFL)

    parser = argparse.ArgumentParser()
    parser.add_argument('-i',
                        '--inbound',
                        default='',
                        help='Proxy inbound url.')
    parser.add_argument('-o',
                        '--outbound',
                        default='',
                        help='Proxy outbound url.')
    parser.add_argument('-c',
                        '--certfile',
                        default='certs/cert.pem',
                        help='TLS certfile. Default is certs/cert.pem.')
    parser.add_argument('-k',
                        '--keyfile',
                        default='certs/key.pem',
                        help='TLS keyfile. Default is certs/key.pem.')
    parser.add_argument('-C',
                        '--certdfl',
                        action='store_true',
                        help='Use system default certfiles to verify TLS.'
                        ' It\'s useful to specify an self-signed certfile.'
                        ' Only client side need this option.')
    parser.add_argument('-H',
                        '--hostname',
                        help='Hostname to verify TLS.'
                        ' Default is server side hostname in it\'s url.'
                        ' Only client side need this option.')
    parser.add_argument('-P',
                        '--password',
                        help='Password of keyfile if needed.')
    parser.add_argument(
        '-r',
        '--rulesfile',
        help='Socks5F rulesfile.'
        ' It\'s useful to bypass or block ips from a set of mmdb files.'
        ' It\'s useful to bypass or block domains from a set of txt files.')
    parser.add_argument('-s',
                        '--strict',
                        action='store_true',
                        help='Socks5 server only accept fold request.'
                        ' It\'s useful to prevent active detection.')
    args = parser.parse_args()
    iurl = urlparse(args.inbound)
    ourl = urlparse(args.outbound)
    strict = int(bool(args.strict))
    certfile = args.certfile
    keyfile = args.keyfile
    cafile = None if args.certdfl else certfile
    hostname = args.hostname
    password = args.password
    rulesfile = args.rulesfile

    addrpack = lambda url, dfl: \
        (url.hostname or dfl[0], str(url.port or dfl[1]))
    authpack = lambda url: \
        (url.username, url.password)

    scheme = (iurl.scheme, ourl.scheme)

    if scheme == ('raw', 'raw'):
        forward(addrpack(iurl, ('localhost', 8080)),
                addrpack(ourl, ('localhost', 80)))

    elif scheme == ('tls', 'raw'):
        tls2raw(addrpack(iurl, ('localhost', 443)),
                addrpack(ourl, ('localhost', 8080)), \
                certfile, keyfile, password)

    elif scheme == ('raw', 'tls'):
        raw2tls(addrpack(iurl, ('localhost', 8080)),
                addrpack(ourl, ('localhost', 443)), \
                hostname, cafile)

    elif scheme == ('socks5', ''):
        socks5(addrpack(iurl, ('localhost', 8080)), authpack(iurl), strict)

    elif scheme == ('socks5s', ''):
        socks5s(addrpack(iurl, ('localhost', 443)), authpack(iurl), \
                certfile, keyfile, password, strict)

    elif scheme == ('socks5', 'socks5s'):
        if rulesfile:
            add_rules(rulesfile)
        socks5f(addrpack(iurl, ('localhost', 8080)), authpack(iurl), \
                addrpack(ourl, ('localhost', 443)), authpack(ourl), \
                hostname, cafile)

    elif scheme == ('raw', 'connector'):
        acceptor(addrpack(ourl, ('localhost', 443)),
                 addrpack(iurl, ('localhost', 8080)), \
                 authpack(ourl), certfile, keyfile, password)

    elif scheme == ('acceptor', 'raw'):
        connector(addrpack(iurl, ('localhost', 443)),
                  addrpack(ourl, ('localhost', 80)), \
                  authpack(iurl), hostname, cafile)

    else:
        print('unknown protocol')


if __name__ == '__main__':
    main()
