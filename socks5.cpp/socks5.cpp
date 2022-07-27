#include "tcpp.hpp"
#include "tcppserver.hpp"

#include <string.h>

#include <sys/select.h>

#define SOCKS5_BUFSIZE 4096

#define STS_DONE 0
#define STS_READ 1
#define STS_WRITE 2

#define ATYPE_IPV4 1
#define ATYPE_IPV6 4
#define ATYPE_DOMAIN 3

typedef struct {
  Socket *isock, *osock;
  int status, n, cur;
  char buf[SOCKS5_BUFSIZE];
} PipeContext;

class Socks5 {
private:
  Socket &isock, osock;
  Address addr;

public:
  Socks5(Socket &isock);
  void run();
};

Socks5::Socks5(Socket &isock) : isock(isock), osock() {}

void Socks5::run() {
  int i, n, err, len, ver, cmd, rsv, atype, nfds;
  struct linger linger;
  fd_set rfds, wfds;
  PipeContext ctx[2];
  unsigned char buf[512];

  isock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1);

  n = isock.recv(buf, sizeof(buf));
  ver = buf[0];
  len = buf[1];
  ASSERT(n > 2 && ver == 5 && len != 0 && n == len + 2, "Invalid auth request");
  for (i = 2; i < n; i++)
    if (buf[i] == 0)
      break;
  ASSERT(i != n, "Invalid auth request");
  isock.sendall((void *)"\x05\x00", 2);

  n = isock.recv(buf, sizeof(buf));
  ver = buf[0];
  cmd = buf[1];
  rsv = buf[2];
  atype = buf[3];
  ASSERT(n > 4 && ver == 5 && cmd == 1 && rsv == 0, "Invalid request");
  ASSERT(atype == ATYPE_IPV4 || atype == ATYPE_IPV6 || atype == ATYPE_DOMAIN,
         "Invalid request");

  memset(&addr, 0, sizeof(addr));
  switch (atype) {
  case ATYPE_IPV4:
    ASSERT(n == 10, "Invalid request");
    addr.sin4.sin_family = AF_INET;
    memcpy(&addr.sin4.sin_addr, buf + 4, 4);
    memcpy(&addr.sin4.sin_port, buf + 8, 2);
    break;
  case ATYPE_IPV6:
    ASSERT(n == 22, "Invalid request");
    addr.sin6.sin6_family = AF_INET6;
    memcpy(&addr.sin6.sin6_addr, buf + 4, 16);
    memcpy(&addr.sin6.sin6_port, buf + 20, 2);
    break;
  case ATYPE_DOMAIN:
    len = buf[4];
    ASSERT(n == len + 7, "Invalid request");
    addr.sd.sd_family = AF_DOMAIN;
    memcpy(&addr.sd.sd_addr, buf + 5, len);
    memcpy(&addr.sd.sd_port, buf + len + 5, 2);
    break;
  }

  std::cout << "HANDLE:\t" + isock.getpeerstr() + "<=>" + addr.ntop() + "\n";

  addr.getaddrinfo();
  osock.open(addr);
  osock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1);
  osock.connect(addr);
  osock.getsockname(addr);

  buf[0] = 5;
  buf[1] = 0;
  buf[2] = 0;
  switch (addr.sa.sa_family) {
  case AF_INET:
    buf[3] = ATYPE_IPV4;
    memcpy(buf + 4, &addr.sin4.sin_addr, 4);
    memcpy(buf + 8, &addr.sin4.sin_port, 2);
    isock.sendall(buf, 10);
    break;
  case AF_INET6:
    buf[3] = ATYPE_IPV6;
    memcpy(buf + 4, &addr.sin6.sin6_addr, 16);
    memcpy(buf + 20, &addr.sin6.sin6_port, 2);
    isock.sendall(buf, 22);
    break;
  case AF_DOMAIN:
    len = strlen(addr.sd.sd_addr);
    buf[3] = ATYPE_DOMAIN;
    buf[4] = len;
    memcpy(buf + 5, addr.sd.sd_addr, len);
    memcpy(buf + 5 + len, &addr.sd.sd_port, 2);
    isock.sendall(buf, len + 7);
    break;
  }

  linger.l_onoff = 1;
  linger.l_linger = 0;
  ctx[0].isock = &isock;
  ctx[0].osock = &osock;
  ctx[0].status = STS_READ;
  ctx[1].isock = &osock;
  ctx[1].osock = &isock;
  ctx[1].status = STS_READ;
  nfds = isock.fd < osock.fd ? osock.fd + 1 : isock.fd + 1;

  while (ctx[0].status != STS_DONE || ctx[0].status != STS_DONE) {
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    for (int i = 0; i < 2; i++) {
      if (ctx[i].status == STS_READ)
        FD_SET(ctx[i].isock->fd, &rfds);
      else if (ctx[i].status == STS_WRITE)
        FD_SET(ctx[i].osock->fd, &wfds);
    }
  doselect:
    err = select(nfds, &rfds, &wfds, NULL, NULL);
    if (err < 0) {
      if (errno == EINTR)
        goto doselect;
      throw OSError(errno, "SELECT");
    }
    for (int i = 0; i < 2; i++) {
      if (ctx[i].status == STS_READ && FD_ISSET(ctx[i].isock->fd, &rfds)) {
        n = ctx[i].isock->recv(ctx[i].buf, SOCKS5_BUFSIZE, MSG_DONTWAIT);
        if (!n) {
          ctx[i].status = STS_DONE;
          ctx[i].osock->shutdown(SHUT_WR);
        } else {
          ctx[i].status = STS_WRITE;
          ctx[i].n = n;
          ctx[i].cur = 0;
        }
      } else if (ctx[i].status == STS_WRITE &&
                 FD_ISSET(ctx[i].osock->fd, &wfds)) {
        n = ctx[i].osock->send(ctx[i].buf + ctx[i].cur, ctx[i].n - ctx[i].cur,
                               MSG_DONTWAIT);
        if (n < 0) {
          isock.setsockopt(SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
          osock.setsockopt(SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
          ctx[0].status = STS_DONE;
          ctx[1].status = STS_DONE;
        } else {
          ctx[i].cur += n;
          if (ctx[i].cur == ctx[i].n)
            ctx[i].status = STS_READ;
        }
      }
    }
  }
}

defineRequestHandler(Socks5RequestHandler, {
  Socks5 socks5(*sock);
  socks5.run();
});

int main(int argc, char **argv) {
  Address addr;

  try {
    ASSERT(argc == 2, "Invalid argument");
    addr.pton(argv[1]);
    Server<Socks5RequestHandler> server(addr);
    server.run();
  } catch (const TCPPError &e) {
    std::cout << "ERROR:\t" + e.str() + "\n";
  }
}
