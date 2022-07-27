import socket
import ssl
import struct
import select
import errno


def pipe(isock, osock):
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


def pipe_s(isock, osock):
    osock.setblocking(False)
    sd, sr, sw = 0, 1, 2
    ios, ois = sr, sr
    iob, oib = b'', b''
    while ios != sd or ois != sd:
        rfds, wfds = [], []
        if ios == sr:
            rfds.append(isock)
        elif ios == sw:
            wfds.append(osock)
        if ois == sr:
            rfds.append(osock)
        elif ois == sw:
            wfds.append(isock)
        rfds, wfds, _ = select.select(rfds, wfds, [])
        if ios == sr and isock in rfds:
            buf = isock.recv(4096, socket.MSG_DONTWAIT)
            if len(buf) == 0:
                ios = sd
                osock.shutdown(socket.SHUT_WR)
            else:
                ios = sw
                iob = buf
        elif ios == sw and osock in wfds:
            try:
                wlen = osock.send(iob)
                if wlen == len(iob):
                    ios = sr
                    iob = b''
                else:
                    iob = iob[wlen:]
            except ssl.SSLWantWriteError:
                pass
            except OSError as e:
                if e.errno == errno.EPIPE:
                    isock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                     struct.pack('@ii', 1, 0))
                    osock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                     struct.pack('@ii', 1, 0))
                    ios, ois = sd, sd
                else:
                    raise e
        if ois == sr and osock in rfds:
            try:
                buf = osock.recv(4096)
                if len(buf) == 0:
                    ois = sd
                    isock.shutdown(socket.SHUT_WR)
                else:
                    ois = sw
                    oib = buf
            except ssl.SSLWantReadError:
                pass
        elif ois == sw and isock in wfds:
            try:
                wlen = isock.send(oib, socket.MSG_DONTWAIT)
                if wlen == len(oib):
                    ois = sr
                    oib = b''
                else:
                    oib = oib[wlen:]
            except OSError as e:
                if e.errno == errno.EPIPE:
                    isock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                     struct.pack('@ii', 1, 0))
                    osock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                     struct.pack('@ii', 1, 0))
                    ios, ois = sd, sd
                else:
                    raise e
