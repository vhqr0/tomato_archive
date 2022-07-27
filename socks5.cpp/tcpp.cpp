#include "tcpp.hpp"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>

#include <iostream>
#include <sstream>
#include <utility>

///////////////////////////////////////////////////////////////////////////////
//                                   Error                                   //
///////////////////////////////////////////////////////////////////////////////

TCPPError::TCPPError() {}

ASSERTError::ASSERTError(std::string msg) : msg(msg) {}
std::string ASSERTError::str() const noexcept { return "ASSERT:" + msg; }
const char *ASSERTError::what() const noexcept { return msg.c_str(); }

OSError::OSError(int no, std::string scname) : no(no), scname(scname) {}
std::string OSError::str() const noexcept {
  return scname + ':' + strerror(no);
}
const char *OSError::what() const noexcept { return scname.c_str(); }

GAIError::GAIError(int no, std::string domain) : no(no), domain(domain) {}
std::string GAIError::str() const noexcept {
  return "GAI@" + domain + ':' + gai_strerror(no);
}
const char *GAIError::what() const noexcept { return domain.c_str(); }

PTONError::PTONError(std::string pres) : pres(pres) {}
std::string PTONError::str() const noexcept { return "PTON@" + pres; }
const char *PTONError::what() const noexcept { return pres.c_str(); }

///////////////////////////////////////////////////////////////////////////////
//                                  Address                                  //
///////////////////////////////////////////////////////////////////////////////

socklen_t Address::length(int family) {
  switch (family) {
  case AF_INET:
    return sizeof(sin4);
  case AF_INET6:
    return sizeof(sin6);
  default:
    return 0;
  }
}

socklen_t Address::length() { return Address::length(sa.sa_family); }

void Address::getaddrinfo() {
  int err;
  unsigned short port;
  struct addrinfo hints, *rai;

#ifdef TCPP_DEBUG
  if (getenv("TCPP_DEBUG"))
    std::cout << "DEBUG:\tGETADDRINFO@" << sd.sd_addr << std::endl;
#endif

  if (sa.sa_family != AF_DOMAIN)
    return;
  port = sd.sd_port;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  err = ::getaddrinfo(sd.sd_addr, NULL, &hints, &rai);
  if (err)
    throw GAIError(err, sd.sd_addr);
  switch (rai->ai_family) {
  case AF_INET:
    sin4 = *(struct sockaddr_in *)rai->ai_addr;
    sin4.sin_port = port;
    freeaddrinfo(rai);
    break;
  case AF_INET6:
    sin6 = *(struct sockaddr_in6 *)rai->ai_addr;
    sin6.sin6_port = port;
    freeaddrinfo(rai);
    break;
  default:
    freeaddrinfo(rai);
    throw GAIError(EAI_ADDRFAMILY, sd.sd_addr);
  }
}

std::string Address::ntop() {
  std::ostringstream oss;
  char buf[INET6_ADDRSTRLEN];

  switch (sa.sa_family) {
  case AF_INET:
    inet_ntop(AF_INET, &sin4.sin_addr, buf, INET_ADDRSTRLEN);
    oss << buf << ':' << ntohs(sin4.sin_port);
    break;
  case AF_INET6:
    inet_ntop(AF_INET6, &sin6.sin6_addr, buf, INET6_ADDRSTRLEN);
    oss << '[' << buf << ']' << ':' << ntohs(sin6.sin6_port);
    break;
  case AF_DOMAIN:
    oss << sd.sd_addr << ':' << ntohs(sd.sd_port);
    break;
  default:
    oss << '?' << sa.sa_family << '?';
  }
  return oss.str();
}

void Address::pton(std::string pres) {
  if (pton(pres, AF_INET) && pton(pres, AF_INET6) && pton(pres, AF_DOMAIN))
    throw PTONError(pres);
}

int Address::pton(std::string pres, int family) {
  unsigned short port;
  std::string addrstr, portstr;
  std::string::size_type pos;

  if (!pres.length()) {
    return -1;
  } else if (pres[0] == '[') {
    pos = pres.find(']');
    if (pos == std::string::npos || pos + 1 == std::string::npos ||
        pres[pos + 1] != ':')
      return -1;
    addrstr = pres.substr(1, pos - 1);
    portstr = pres.substr(pos + 2);
  } else {
    pos = pres.find(':');
    if (pos == std::string::npos)
      return -1;
    addrstr = pres.substr(0, pos);
    portstr = pres.substr(pos + 1);
  }

  try {
    port = std::stoi(portstr);
  } catch (std::invalid_argument) {
    return -1;
  }

  memset(this, 0, sizeof(Address));
  switch (family) {
  case AF_INET:
    sin4.sin_family = AF_INET;
    sin4.sin_port = htons(port);
    if (inet_pton(AF_INET, addrstr.c_str(), &sin4.sin_addr) != 1)
      return -1;
    break;
  case AF_INET6:
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(port);
    if (inet_pton(AF_INET6, addrstr.c_str(), &sin6.sin6_addr) != 1)
      return -1;
    break;
  case AF_DOMAIN:
    sd.sd_family = AF_DOMAIN;
    sd.sd_port = htons(port);
    strncpy(sd.sd_addr, addrstr.c_str(), DOMAIN_MAX);
    break;
  default:
    return -1;
  }

  return 0;
}

///////////////////////////////////////////////////////////////////////////////
//                                   Socket                                  //
///////////////////////////////////////////////////////////////////////////////

Socket::Socket() : fd(-1), family(-1) {}
Socket::Socket(Socket &&sock) : fd(sock.fd), family(sock.family) {
  sock.fd = -1;
  sock.family = -1;
}
Socket::~Socket() { close(); }

void Socket::open(int family) {
  int fd;

  if (family != AF_INET && family != AF_INET6)
    throw OSError(EAFNOSUPPORT, "OPEN");
  fd = ::socket(family, SOCK_STREAM, 0);
  if (fd < 0)
    throw OSError(errno, "OPEN");
  this->fd = fd;
  this->family = family;

#ifdef TCPP_DEBUG
  if (getenv("TCPP_DEBUG"))
    std::cout << "DEBUG:\tOPEN@" << fd << std::endl;
#endif
}

void Socket::open(Address &addr) { open(addr.sa.sa_family); }

void Socket::close() {
  int fd, err;
  socklen_t len = sizeof(err);

#ifdef TCPP_DEBUG
  if (getenv("TCPP_DEBUG"))
    std::cout << "DEBUG:\tCLOSE@" << this->fd << std::endl;
#endif

  fd = this->fd;
  this->fd = -1;
  if (fd > 0) {
    ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
    ::shutdown(fd, SHUT_RDWR);
  doclose:
    err = ::close(fd);
    if (err && errno == EINTR)
      goto doclose;
  }
}

void Socket::shutdown(int how) {

#ifdef TCPP_DEBUG
  if (getenv("TCPP_DEBUG"))
    std::cout << "DEBUG:\tSHUTDOWN@" << fd << std::endl;
#endif

  if (fd > 0)
    ::shutdown(fd, how);
}

void Socket::bind(Address &addr) {
  int err;

#ifdef TCPP_DEBUG
  if (getenv("TCPP_DEBUG"))
    std::cout << "DEBUG:\tBIND@" << fd << std::endl;
#endif

  if (addr.sa.sa_family != family)
    throw OSError(EINVAL, "BIND");
  err = ::bind(fd, &addr.sa, addr.length());
  if (err)
    throw OSError(errno, "BIND");
}

void Socket::listen(int backlog) {
  int err;

#ifdef TCPP_DEBUG
  if (getenv("TCPP_DEBUG"))
    std::cout << "DEBUG:\tLISTEN@" << fd << std::endl;
#endif

  err = ::listen(fd, backlog);
  if (err)
    throw OSError(errno, "LISTEN");
}

void Socket::accept(Socket &sock, Address &addr) {
  int fd;
  socklen_t len = Address::length(family);

#ifdef TCPP_DEBUG
  if (getenv("TCPP_DEBUG"))
    std::cout << "DEBUG:\tACCEPT@" << this->fd << std::endl;
#endif

  memset(&addr, 0, sizeof(addr));
  fd = ::accept(this->fd, &addr.sa, &len);
  if (fd < -1)
    throw OSError(errno, "ACCEPT");
  sock.fd = fd;
  sock.family = addr.sa.sa_family;
}

void Socket::connect(Address &addr) {
  int err;

#ifdef TCPP_DEBUG
  if (getenv("TCPP_DEBUG"))
    std::cout << "DEBUG:\tCONNECT@" << fd << std::endl;
#endif

  if (addr.sa.sa_family != family)
    throw OSError(EINVAL, "CONNECT");
doconnect:
  err = ::connect(fd, &addr.sa, addr.length());
  if (err) {
    if (errno == EINTR)
      goto doconnect;
    throw OSError(errno, "CONNECT");
  }
}

///////////////////////////////////////////////////////////////////////////////
//                              Socket Recv&Send                             //
///////////////////////////////////////////////////////////////////////////////

ssize_t Socket::recv(void *buf, size_t len, int flags) {
  ssize_t n;

#ifdef TCPP_DEBUG
  if (getenv("TCPP_DEBUG"))
    std::cout << "DEBUG:\tRECV@" << fd << std::endl;
#endif

dorecv:
  n = ::recv(fd, buf, len, flags);
  if (n < 0) {
    if (errno == EINTR)
      goto dorecv;
    throw OSError(errno, "RECV");
  }
  return n;
}

ssize_t Socket::send(void *buf, size_t len, int flags) {
  ssize_t n;

#ifdef TCPP_DEBUG
  if (getenv("TCPP_DEBUG"))
    std::cout << "DEBUG:\tSEND@" << fd << std::endl;
#endif

dosend:
  n = ::send(fd, buf, len, flags | MSG_NOSIGNAL);
  if (n < 0) {
    if (errno == EINTR)
      goto dosend;
    if (errno == EPIPE)
      return -1;
    throw OSError(errno, "SEND");
  }
  return n;
}

void Socket::recvall(void *buf, size_t len) {
  ssize_t n;

#ifdef TCPP_DEBUG
  if (getenv("TCPP_DEBUG"))
    std::cout << "DEBUG:\tRECVALL@" << fd << std::endl;
#endif

dorecv:
  n = ::recv(fd, buf, len, MSG_WAITALL);
  if (n < 0) {
    if (errno == EINTR)
      goto dorecv;
    throw OSError(errno, "RECV");
  }
  if (n != len)
    throw OSError(EFAULT, "RECV");
}

void Socket::sendall(void *buf, size_t len) {
  ssize_t n;
  char *cur = (char *)buf;

#ifdef TCPP_DEBUG
  if (getenv("TCPP_DEBUG"))
    std::cout << "DEBUG:\tSENDALL@" << fd << std::endl;
#endif

  while (len) {
    n = ::send(fd, cur, len, MSG_NOSIGNAL);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      throw OSError(errno, "SEND");
    }
    cur += n;
    len -= n;
  }
}

///////////////////////////////////////////////////////////////////////////////
//                               Socket Get&Set                              //
///////////////////////////////////////////////////////////////////////////////

void Socket::getsockname(Address &addr) {
  int err;
  socklen_t len = Address::length(family);

  memset(&addr, 0, sizeof(addr));
  err = ::getsockname(fd, &addr.sa, &len);
  if (err)
    throw OSError(errno, "GETSOCKNAME");
}

void Socket::getpeername(Address &addr) {
  int err;
  socklen_t len = Address::length(family);

  memset(&addr, 0, sizeof(addr));
  err = ::getpeername(fd, &addr.sa, &len);
  if (err)
    throw OSError(errno, "GETPEERNAME");
}

std::string Socket::getsockstr() {
  Address addr;
  getsockname(addr);
  return addr.ntop();
}

std::string Socket::getpeerstr() {
  Address addr;
  getpeername(addr);
  return addr.ntop();
}

void Socket::getsockopt(int level, int opt, void *val, socklen_t *len) {
  int err;

  err = ::getsockopt(fd, level, opt, val, len);
  if (err)
    throw OSError(errno, "GETSOCKOPT");
}

void Socket::setsockopt(int level, int opt, void *val, socklen_t len) {
  int err;

  err = ::setsockopt(fd, level, opt, val, len);
  if (err)
    throw OSError(errno, "SETSOCKOPT");
}

int Socket::getsockopt(int level, int opt) {
  int val;
  socklen_t len = sizeof(val);

  getsockopt(level, opt, &val, &len);
  return val;
}

void Socket::setsockopt(int level, int opt, int val) {
  setsockopt(level, opt, &val, sizeof(val));
}

///////////////////////////////////////////////////////////////////////////////
//                                   Epoll                                   //
///////////////////////////////////////////////////////////////////////////////

Event::Event(Socket &&sock, int events) : sock(std::move(sock)) {
  epev.events = events;
  epev.data.ptr = this;
}
GenericEvent::GenericEvent(Socket &&sock, int events, CBType cb)
    : Event(std::move(sock), events), cb(cb) {}
void GenericEvent::callback(Epoll &ep, int events) { cb(ep, this, events); }

Epoll::Epoll() : fd(-1) {}
Epoll::Epoll(Epoll &&ep) : fd(ep.fd) { ep.fd = -1; }
Epoll::~Epoll() { close(); }

void Epoll::open() {
  int fd;

  fd = epoll_create(1);
  if (fd < 0)
    throw OSError(errno, "EPOLL_CREATE");
  this->fd = fd;

#ifdef TCPP_DEBUG
  if (getenv("TCPP_DEBUG"))
    std::cout << "DEBUG:\tEPOLL_CREATE@" << fd << std::endl;
#endif
}

void Epoll::close() {
  int fd, err;

#ifdef TCPP_DEBUG
  if (getenv("TCPP_DEBUG"))
    std::cout << "DEBUG:\tEPOLL_CLOSE@" << this->fd << std::endl;
#endif

  fd = this->fd;
  this->fd = -1;
  if (fd > 0) {
  doclose:
    err = ::close(fd);
    if (err && errno == EINTR)
      goto doclose;
  }
}

void Epoll::ctl(Event &ev, int op) {
  int err;

#ifdef TCPP_DEBUG
  if (getenv("TCPP_DEBUG"))
    std::cout << "DEBUG:\tEPOLL_CTL@" << fd << std::endl;
#endif

  err = epoll_ctl(fd, op, ev.sock.fd, &ev.epev);
  if (err)
    throw OSError(errno, "EPOLL_CTL");
}
void Epoll::add(Event &ev) { ctl(ev, EPOLL_CTL_ADD); }
void Epoll::mod(Event &ev) { ctl(ev, EPOLL_CTL_MOD); }
void Epoll::del(Event &ev) { ctl(ev, EPOLL_CTL_DEL); }

int Epoll::wait(std::vector<struct epoll_event> &epevs, int timeout) {
  int nfds;

#ifdef TCPP_DEBUG
  if (getenv("TCPP_DEBUG"))
    std::cout << "DEBUG:\tEPOLL_WAIT@" << fd << std::endl;
#endif

  nfds = epoll_wait(fd, &epevs[0], epevs.size(), timeout);
  if (nfds < 0)
    throw OSError(errno, "EPOLL_WAIT");
  return nfds;
}

void Epoll::run(int maxevents) {
  int i, nfds;
  std::vector<struct epoll_event> epevs(maxevents);

  for (;;) {
    nfds = wait(epevs, -1);
    for (i = 0; i < nfds; i++)
      ((Event *)epevs[i].data.ptr)->callback(*this, epevs[i].events);
  }
}
