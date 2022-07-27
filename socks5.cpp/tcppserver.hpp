#ifndef TCPPSERVER_H
#define TCPPSERVER_H

#include "tcpp.hpp"

#include <pthread.h>

#include <iostream>
#include <utility>

///////////////////////////////////////////////////////////////////////////////
//                                   Server                                  //
///////////////////////////////////////////////////////////////////////////////

#define defineRequestHandler(NAME, BODY)                                       \
  class NAME {                                                                 \
  public:                                                                      \
    Socket *sock;                                                              \
    NAME(void *arg) {                                                          \
      sock = (Socket *)arg;                                                    \
      pthread_detach(pthread_self());                                          \
    }                                                                          \
    ~NAME() { delete sock; }                                                   \
    void run() BODY                                                            \
  };

template <class Handler> void *handleRequest(void *arg) {
  try {
    Handler handler(arg);
    handler.run();
  } catch (const TCPPError &e) {
    std::cout << "ERROR:\t" + e.str() + "\n";
  }
  return NULL;
}

template <class Handler> class Server {
public:
  Address &addr;

  Server(Address &addr) : addr(addr) {}
  void run() {
    int err;
    pthread_t tid;
    Socket srvsock, clisock, *arg;
    Address srvaddr, cliaddr;

    srvaddr = addr;
    srvaddr.getaddrinfo();
    srvsock.open(srvaddr);
    srvsock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1);
    srvsock.bind(srvaddr);
    srvsock.listen();
    srvsock.getsockname(srvaddr);
    std::cout << "SERVER:\tLISTEN@" + srvaddr.ntop() + "\n";

    for (;;) {
      srvsock.accept(clisock, cliaddr);
      arg = new Socket(std::move(clisock));
    docreate:
      err = pthread_create(&tid, NULL, handleRequest<Handler>, arg);
      if (err) {
        if (err == EAGAIN)
          goto docreate;
        delete arg;
        throw OSError(err, "PTHREAD_CREATE");
      }
    }
  }
};

#endif
