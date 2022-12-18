import socket
import struct
import select
import errno


def relay(isock, osock):
    sd, sr, sw = 0, 1, 2
    ioctx = [isock, osock, sr, b'']
    oictx = [osock, isock, sr, b'']
    while ioctx[2] != sd or oictx[2] != sd:
        rfds, wfds = [], []
        for ctx in (ioctx, oictx):
            if ctx[2] == sr:
                rfds.append(ctx[0])
            elif ctx[2] == sw:
                wfds.append(ctx[1])
        rfds, wfds, _ = select.select(rfds, wfds, [])
        for ctx in (ioctx, oictx):
            if ctx[2] == sr and ctx[0] in rfds:
                buf = ctx[0].recv(4096, socket.MSG_DONTWAIT)
                if len(buf) == 0:
                    ctx[2] = sd
                    ctx[1].shutdown(socket.SHUT_WR)
                else:
                    ctx[2] = sw
                    ctx[3] = buf
            elif ctx[2] == sw and ctx[1] in wfds:
                try:
                    wlen = ctx[1].send \
                        (ctx[3], socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
                    if wlen == len(ctx[3]):
                        ctx[2] = sr
                        ctx[3] = b''
                    else:
                        ctx[3] = ctx[3][wlen:]
                except OSError as e:
                    if e.errno == errno.EPIPE:
                        isock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                         struct.pack('@ii', 1, 0))
                        osock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                         struct.pack('@ii', 1, 0))
                        ioctx[2], oictx[2] = sd, sd
                    else:
                        raise e
