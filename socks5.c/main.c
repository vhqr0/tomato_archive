#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#ifndef BUFSIZE
#define BUFSIZE 4096
#endif

#ifdef DAEMON
#define LOG(...) ;
#else
#define LOG(...) printf(__VA_ARGS__);
#endif

#define ADDRSTRLEN INET6_ADDRSTRLEN

#define METH_NOAUTH 0
#define METH_GSSAPI 1
#define METH_PASSWORD 3
#define METH_NOACCEPT 0xff

#define CMD_CONNECT 1
#define CMD_BIND 2
#define CMD_UDPASSOC 3

#define ATYPE_IPV4 1
#define ATYPE_IPV6 4
#define ATYPE_DOMAIN 3

#define REP_SUCCESS 0
#define REP_GENERAL_FAILURE 1
#define REP_CONN_NOT_ALLOWED 2
#define REP_NETWORK_UNREACH 3
#define REP_HOST_UNREADH 4
#define REP_CONN_REFUSED 5
#define REP_TTL_EXPIRED 6
#define REP_CMD_NOT_SUPPORT 7
#define REP_ATYPE_NOT_SUPPORT 8

void daemonize() {
  pid_t pid;

  if ((pid = fork()) < 0) {
    perror("fork failed");
    exit(-1);
  } else if (pid) {
    exit(0);
  }
  if (setsid() < 0) {
    perror("setsid failed");
    exit(-1);
  }
  signal(SIGHUP, SIG_IGN);
  chdir("/");
}

int Read(int fd, void *b, int n) {
  int ret;
doread:
  if ((ret = read(fd, b, n)) < 0) {
    if (errno == EINTR)
      goto doread;
    return -1;
  }
  return ret;
}

int Write(int fd, void *b, int n) {
  int ret;
dowrite:
  if ((ret = write(fd, b, n)) < 0) {
    if (errno == EINTR)
      goto dowrite;
    return -1;
  }
  return ret;
}

int Readn(int fd, void *b, int n) {
  int nread;
  while (n > 0) {
    nread = Read(fd, b, n);
    if (nread < 0)
      return -1;
    if (!nread)
      return 1;
    b += nread;
    n -= nread;
  }
  return 0;
}

int Writen(int fd, void *b, int n) {
  int nwrite;
  while (n > 0) {
    nwrite = Write(fd, b, n);
    if (nwrite < 0)
      return -1;
    if (!nwrite)
      return 1;
    b += nwrite;
    n -= nwrite;
  }
  return 0;
}

void *thread_main(void *arg) {
  pthread_t tid = pthread_self();
  int connfd = *(int *)arg, sockfd = -1, maxfd, ret, i;
  struct addrinfo hints, *rai;
  struct linger linger;
  union {
    struct sockaddr_in a4;
    struct sockaddr_in6 a6;
  } addr;
  socklen_t addrlen = sizeof(addr);
  char ntopbuf[ADDRSTRLEN];
  unsigned short port;
  uint8_t buf[BUFSIZE], buf2[BUFSIZE];
  int cur, cur2, len, len2;
  fd_set rfds, wfds;
  enum { in, out, done } bufsts = in, buf2sts = in;

  free(arg);
  if (pthread_detach(tid) < 0) {
    LOG("%ld: pthread_detach failed: %s\n", tid & 0xffff, strerror(errno));
    exit(-1);
  }
  tid &= 0xffff;
  if (getpeername(connfd, (struct sockaddr *)&addr, &addrlen) < 0) {
    LOG("%ld: getpeername failed: %s\n", tid, strerror(errno));
    goto exit;
  }
  switch (((struct sockaddr *)&addr)->sa_family) {
  case AF_INET:
    port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
    if (!inet_ntop(AF_INET, &addr.a4.sin_addr, ntopbuf, sizeof(ntopbuf))) {
      LOG("%ld: inet_ntop failed: %s\n", tid, strerror(errno));
      goto exit;
    }
    break;
  case AF_INET6:
    port = ((struct sockaddr_in6 *)&addr)->sin6_port;
    if (!inet_ntop(AF_INET6, &addr.a6.sin6_addr, ntopbuf, sizeof(ntopbuf))) {
      LOG("%ld: inet_ntop failed: %s\n", tid, strerror(errno));
      goto exit;
    }
    break;
  default:
    LOG("%ld: inet_ntop unknown address family: %d\n", tid,
        ((struct sockaddr *)&addr)->sa_family);
    goto exit;
  }
  LOG("%ld: accept from %s, port %d\n", tid, ntopbuf, port);

  /* state1 */
  if ((ret = Read(connfd, buf, sizeof(buf))) < 0) {
    LOG("%ld: state1 read failed: %s\n", tid, strerror(errno));
    goto exit;
  }
  if (ret < 2 || buf[0] != 5 || ret != buf[1] + 2) {
    LOG("%ld: state1 invalid data\n", tid);
    goto exit;
  }
  for (i = 2; i < ret; i++)
    if (buf[i] == METH_NOAUTH)
      break;
  buf[1] = i == ret ? METH_NOACCEPT : METH_NOAUTH;
  if ((ret = Writen(connfd, buf, 2)) < 0) {
    LOG("%ld: state1 write failed: %s\n", tid, strerror(errno));
    goto exit;
  } else if (ret) {
    LOG("%ld: state1 write EOF\n", tid);
    goto exit;
  }
  if (buf[1] == METH_NOACCEPT)
    goto exit;

  /* state2 */
  if ((ret = Readn(connfd, buf, 5))) {
    LOG("%ld: state2 read failed: %s\n", tid, strerror(errno));
    goto exit;
  } else if (ret) {
    LOG("%ld: state2 read EOF\n", tid);
    goto exit;
  }
  switch (buf[3]) {
  case ATYPE_IPV4:
    len = 10;
    break;
  case ATYPE_IPV6:
    len = 22;
    break;
  case ATYPE_DOMAIN:
    len = buf[4] + 7;
    break;
  default:
    LOG("%ld: state2 invalid data\n", tid);
    goto exit;
  }
  if (buf[0] != 5 || buf[2] != 0 || len > sizeof(buf)) {
    LOG("%ld: state2 invalid data\n", tid);
    goto exit;
  }
  if ((ret = Readn(connfd, buf + 5, len - 5)) < 0) {
    LOG("%ld: state2 read failed: %s\n", tid, strerror(errno));
    goto exit;
  } else if (ret) {
    LOG("%ld: state2 read EOF\n", tid);
    goto exit;
  }
  if (buf[1] != CMD_CONNECT) {
    buf[1] = REP_CMD_NOT_SUPPORT;
    goto reply;
  }
  port = (buf[len - 2] << 8) + buf[len - 1];
  memset(&addr, 0, sizeof(addr));
  switch (buf[3]) {
  case ATYPE_IPV4:
    addr.a4.sin_family = AF_INET;
    addr.a4.sin_port = htons(port);
    memcpy(&addr.a4.sin_addr, buf + 4, 4);
    addrlen = sizeof(struct sockaddr_in);
    if (!inet_ntop(AF_INET, &addr.a4.sin_addr, ntopbuf, sizeof(ntopbuf))) {
      LOG("%ld: inet_ntop failed: %s\n", tid, gai_strerror(ret));
      goto exit;
    }
    LOG("%ld: connect to %s, port %d\n", tid, ntopbuf, port);
    break;
  case ATYPE_IPV6:
    addr.a6.sin6_family = AF_INET6;
    addr.a6.sin6_port = htons(port);
    memcpy(&addr.a6.sin6_addr, buf + 4, 16);
    addrlen = sizeof(struct sockaddr_in6);
    if (!inet_ntop(AF_INET6, &addr.a6.sin6_addr, ntopbuf, sizeof(ntopbuf))) {
      LOG("%ld: inet_ntop failed: %s\n", tid, gai_strerror(ret));
      goto exit;
    }
    LOG("%ld: connect to %s, port %d\n", tid, ntopbuf, port);
    break;
  case ATYPE_DOMAIN:
    buf[len - 2] = 0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    if ((ret = getaddrinfo((void *)(buf + 5), NULL, &hints, &rai))) {
      LOG("%ld: getaddrinfo %s NULL failed: %s\n", tid, buf + 5,
          gai_strerror(ret));
      goto exit;
    }
    switch (rai->ai_family) {
    case AF_INET:
      addr.a4 = *(struct sockaddr_in *)rai->ai_addr;
      addr.a4.sin_port = htons(port);
      addrlen = sizeof(struct sockaddr_in);
      if (!inet_ntop(AF_INET, &addr.a4.sin_addr, ntopbuf, sizeof(ntopbuf))) {
        LOG("%ld: inet_ntop failed: %s\n", tid, gai_strerror(ret));
        goto exit;
      }
      break;
    case AF_INET6:
      addr.a6 = *(struct sockaddr_in6 *)rai->ai_addr;
      addr.a6.sin6_port = htons(port);
      addrlen = sizeof(struct sockaddr_in6);
      if (!inet_ntop(AF_INET6, &addr.a6.sin6_addr, ntopbuf, sizeof(ntopbuf))) {
        LOG("%ld: inet_ntop failed: %s\n", tid, gai_strerror(ret));
        goto exit;
      }
      break;
    default:
      LOG("%ld: getaddrinfo %s NULL unknown address family: %d\n", tid, buf + 5,
          rai->ai_family);
      freeaddrinfo(rai);
      goto exit;
    }
    freeaddrinfo(rai);
    LOG("%ld: connect to %s(%s), port %d\n", tid, buf + 5, ntopbuf, port);
    switch (((struct sockaddr *)&addr)->sa_family) {
    case AF_INET:
      buf[3] = ATYPE_IPV4;
      memcpy(buf + 4, &addr.a4.sin_addr, 4);
      buf[8] = port >> 8;
      buf[9] = port & 0xff;
      len = 10;
      break;
    case AF_INET6:
      buf[3] = ATYPE_IPV6;
      memcpy(buf + 4, &addr.a6.sin6_addr, 16);
      buf[20] = port >> 8;
      buf[21] = port & 0xff;
      len = 22;
      break;
    }
    break;
  }
  if ((sockfd = socket(((struct sockaddr *)&addr)->sa_family, SOCK_STREAM, 0)) <
      0) {
    LOG("%ld: socket failed: %s\n", tid, strerror(errno));
    goto exit;
  }
  ret = 1;
  if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &ret, sizeof(ret)) < 0) {
    LOG("%ld: setsockopt TCP_NODELAY failed: %s\n", tid, strerror(errno));
    goto exit;
  }
doconnect:
  if (connect(sockfd, (struct sockaddr *)&addr, addrlen) < 0) {
    switch (errno) {
    case EINTR:
      goto doconnect;
    case ENETUNREACH:
      buf[1] = REP_NETWORK_UNREACH;
      break;
    case EHOSTUNREACH:
      buf[1] = REP_HOST_UNREADH;
      break;
    case ECONNREFUSED:
      buf[1] = REP_CONN_REFUSED;
      break;
      /* TODO: TTL EXPIRED */
    default:
      buf[1] = REP_GENERAL_FAILURE;
    }
    goto reply;
  }
  buf[1] = REP_SUCCESS;
reply:
  if ((ret = Writen(connfd, buf, len)) < 0) {
    LOG("%ld: state2 write failed: %s\n", tid, strerror(errno));
    goto exit;
  } else if (ret) {
    LOG("%ld: state2 write EOF\n", tid);
    goto exit;
  }
  if (buf[1] != REP_SUCCESS)
    goto exit;

  /* state3 */
  maxfd = connfd < sockfd ? sockfd + 1 : connfd + 1;
  for (;;) {
    if (bufsts == done && buf2sts == done)
      break;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    switch (bufsts) {
    case in:
      FD_SET(connfd, &rfds);
      break;
    case out:
      FD_SET(sockfd, &wfds);
      break;
    case done:
      break;
    }
    switch (buf2sts) {
    case in:
      FD_SET(sockfd, &rfds);
      break;
    case out:
      FD_SET(connfd, &wfds);
      break;
    case done:
      break;
    }
  doselect:
    if (select(maxfd, &rfds, &wfds, NULL, NULL) < 0) {
      if (errno == EINTR)
        goto doselect;
      LOG("%ld: select failed: %s\n", tid, strerror(errno));
      goto exit;
    }
    switch (bufsts) {
    case in:
      if (FD_ISSET(connfd, &rfds)) {
        if ((ret = recv(connfd, buf, sizeof(buf), MSG_DONTWAIT)) < 0) {
          LOG("%ld: state3 recv failed: %s\n", tid, strerror(errno));
          goto exit;
        }
        if (ret) {
          cur = 0;
          len = ret;
          bufsts = out;
        } else {
          bufsts = done;
          shutdown(sockfd, SHUT_WR);
        }
      }
      break;
    case out:
      if (FD_ISSET(sockfd, &wfds)) {
        if ((ret = send(sockfd, buf + cur, len, MSG_DONTWAIT)) < 0) {
          if (errno == EPIPE) {
            LOG("%ld: state3 send RST\n", tid);
            linger.l_onoff = 1;
            linger.l_linger = 0;
            if (setsockopt(connfd, SOL_SOCKET, SO_LINGER, &linger,
                           sizeof(linger)) < 0 ||
                setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &linger,
                           sizeof(linger)) < 0) {
              LOG("%ld: setsockopt SO_LINGER failed: %s\n", tid,
                  strerror(errno));
            }
            goto exit;
          }
          LOG("%ld: state3 send failed: %s\n", tid, strerror(errno));
          goto exit;
        }
        if (ret == len) {
          bufsts = in;
        } else {
          cur += ret;
          len -= ret;
        }
      }
      break;
    case done:
      break;
    }
    switch (buf2sts) {
    case in:
      if (FD_ISSET(sockfd, &rfds)) {
        if ((ret = recv(sockfd, buf2, sizeof(buf2), MSG_DONTWAIT)) < 0) {
          LOG("%ld: state3 recv failed: %s\n", tid, strerror(errno));
          goto exit;
        }
        if (ret) {
          cur2 = 0;
          len2 = ret;
          buf2sts = out;
        } else {
          buf2sts = done;
          shutdown(connfd, SHUT_WR);
        }
      }
      break;
    case out:
      if (FD_ISSET(connfd, &wfds)) {
        if ((ret = send(connfd, buf2 + cur2, len2, MSG_DONTWAIT)) < 0) {
          if (errno == EPIPE) {
            LOG("%ld: state3 send RST\n", tid);
            linger.l_onoff = 1;
            linger.l_linger = 0;
            if (setsockopt(connfd, SOL_SOCKET, SO_LINGER, &linger,
                           sizeof(linger)) < 0 ||
                setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &linger,
                           sizeof(linger)) < 0) {
              LOG("%ld: setsockopt SO_LINGER failed: %s\n", tid,
                  strerror(errno));
            }
            goto exit;
          }
          LOG("%ld: state3 send failed: %s\n", tid, strerror(errno));
          goto exit;
        }
        if (ret == len2) {
          buf2sts = in;
        } else {
          cur2 += ret;
          len2 -= ret;
        }
      }
      break;
    case done:
      break;
    }
  }

exit:
  close(connfd);
  if (sockfd > 0)
    close(sockfd);
  return NULL;
}

int main(int argc, char **argv) {
  int listenfd, connfd, family = 0, *arg, ret, longind;
  const char *saddress = "localhost", *sport = "1080";
  struct addrinfo hints, *rai;
  union {
    struct sockaddr_in a4;
    struct sockaddr_in6 a6;
  } addr;
  socklen_t addrlen;
  char ntopbuf[ADDRSTRLEN];
  unsigned short port;
  pthread_t tid;

  struct option options[] = {{"help", no_argument, NULL, 'h'},
                             {"logfile", required_argument, NULL, 'l'},
                             {"address", required_argument, NULL, 'a'},
                             {"port", required_argument, NULL, 'p'},
                             {0, 0, NULL, 0}};

  while ((ret = getopt_long(argc, argv, "h46a:p:", options, &longind)) > 0) {
    switch (ret) {
    case 'h':
      printf("usage: %s [-h] [-46] [-a ADDRESS] [-p PORT]\n", argv[0]);
      puts("-h, --help          show this message");
      puts("-4                  force address IPv4");
      puts("-6                  force address IPv6");
      puts("-a, --address       address, default localhost");
      puts("-p, --port          port, default 1080");
      exit(1);
      break;
    case '4':
      family = AF_INET;
      break;
    case '6':
      family = AF_INET6;
      break;
    case 'a':
      saddress = optarg;
      break;
    case 'p':
      sport = optarg;
      break;
    default:
      printf("unknown option: %c\n", ret);
      exit(-1);
    }
  }

#ifdef DAEMON
  daemonize();
#endif

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = family;
  hints.ai_socktype = SOCK_STREAM;
  if ((ret = getaddrinfo(saddress, sport, &hints, &rai))) {
    LOG("getaddrinfo %s %s failed: %s\n", saddress, sport, gai_strerror(ret));
    exit(-1);
  }
  switch (rai->ai_family) {
  case AF_INET:
    family = AF_INET;
    addr.a4 = *(struct sockaddr_in *)rai->ai_addr;
    addrlen = sizeof(struct sockaddr_in);
    port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
    if (!inet_ntop(AF_INET, &addr.a4.sin_addr, ntopbuf, sizeof(ntopbuf))) {
      LOG("inet_ntop failed: %s\n", strerror(errno));
      exit(-1);
    }
    break;
  case AF_INET6:
    family = AF_INET6;
    addr.a6 = *(struct sockaddr_in6 *)rai->ai_addr;
    addrlen = sizeof(struct sockaddr_in6);
    port = ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
    if (!inet_ntop(AF_INET6, &addr.a6.sin6_addr, ntopbuf, sizeof(ntopbuf))) {
      LOG("inet_ntop failed: %s\n", strerror(errno));
      exit(-1);
    }
    break;
  default:
    LOG("getaddrinfo %s %s unknown address family: %d\n", saddress, sport,
        rai->ai_family);
    exit(-1);
  }
  freeaddrinfo(rai);
  LOG("listen %s, port %d\n", ntopbuf, port);

  if ((listenfd = socket(family, SOCK_STREAM, 0)) < 0) {
    LOG("socket failed: %s\n", strerror(errno));
    exit(-1);
  }
  ret = 1;
  if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &ret, sizeof(ret)) < 0) {
    LOG("setsockopt SO_REUSEADDR failed: %s\n", strerror(errno));
    exit(-1);
  }
  if (bind(listenfd, (struct sockaddr *)&addr, addrlen) < 0) {
    LOG("bind failed: %s\n", strerror(errno));
    exit(-1);
  }
  if (listen(listenfd, SOMAXCONN) < 0) {
    LOG("listen failed: %s\n", strerror(errno));
    exit(-1);
  }

  signal(SIGPIPE, SIG_IGN);
  for (;;) {
    if ((connfd = accept(listenfd, NULL, NULL)) < 0) {
      LOG("accept failed: %s\n", strerror(errno));
      exit(-1);
    }
    ret = 1;
    if (setsockopt(connfd, IPPROTO_TCP, TCP_NODELAY, &ret, sizeof(ret)) < 0) {
      LOG("setsockopt TCP_NODELAY failed: %s\n", strerror(errno));
      exit(-1);
    }
    arg = (int *)malloc(sizeof(int));
    *arg = connfd;
    if (pthread_create(&tid, NULL, thread_main, arg)) {
      LOG("pthread_create failed: %s\n", strerror(errno));
      exit(-1);
    }
  }
}
