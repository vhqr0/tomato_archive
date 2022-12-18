#include "tomato.hpp"

#include <string.h>

///////////////////////////////////////////////////////////////////////////////
//                                   Parser                                  //
///////////////////////////////////////////////////////////////////////////////

Socks5Parser::Socks5Parser(std::string &username, std::string &password)
  : username_(username), password_(password),
    authmeth_((username.empty() && password.empty()) ? AUTH_NOAUTH : AUTH_PASSWORD) {}

bool Socks5Parser::do_parse(unsigned char *buf, std::size_t length) {
  int ulen, plen, dlen, ridx;
  std::string username, password;

  ulen = buf[1];
  plen = buf[ulen + 2];
  ridx = ulen + plen + 3;

  if (ridx + 5 > length || buf[0] != 1 /*authver*/ || buf[ridx] != 5 /*ver*/
      || buf[ridx + 1] != 1 /*cmd*/ || buf[ridx + 2] != 0 /*rsv*/)
    return false;

  username = std::string((const char *)buf + 2, ulen);
  password = std::string((const char *)buf + ulen + 3, plen);
  if ((!username_.empty() && username_ != username) ||
      (!password_.empty() && password_ != password))
    return false;

  switch (buf[ridx + 3] /*atype*/) {
  case ATYPE_IPV4:
    if (ridx + 10 != length)
      return false;
    atype_ = ATYPE_IPV4;
    memcpy(&addr_.v4[0], buf + ridx + 4, 4);
    port_ = (buf[ridx + 8] << 8) + buf[ridx + 9];
    break;
  case ATYPE_IPV6:
    if (ridx + 22 != length)
      return false;
    atype_ = ATYPE_IPV6;
    memcpy(&addr_.v6[0], buf + ridx + 4, 16);
    port_ = (buf[ridx + 20] << 8) + buf[ridx + 21];
    break;
  case ATYPE_DOMAIN:
    dlen = buf[ridx + 4];
    if (ridx + dlen + 7 != length)
      return false;
    atype_ = ATYPE_DOMAIN;
    memcpy(addr_.domain, buf + ridx + 4, dlen + 1);
    port_ = (buf[ridx + dlen + 5] << 8) + buf[ridx + dlen + 6];
    break;
  default:
    return false;
  }

  return true;
}

///////////////////////////////////////////////////////////////////////////////
//                                   Socks5                                  //
///////////////////////////////////////////////////////////////////////////////

// Session ////////////////////////////////////////////////////////////////////

Socks5Session::Socks5Session(asio::io_context &context, asio::ip::tcp::socket &&isocket,
                             std::string &username, std::string &password, bool strict)
  : RAWProxy(context, std::move(isocket)), resolver_(context),
    parser_(username, password), strict_(strict) {}

void Socks5Session::run() {
  asio::error_code ec;
  // isocket_ opts: NODELAY KEEPALIVE
  SET_NODELAY(isocket_);
  SET_KEEPALIVE(isocket_);
  do_read_req();
}

// Fold Process ///////////////////////////////////////////////////////////////

void Socks5Session::do_read_req() {
  auto self(shared_from_this());
  isocket_.async_receive( // recv
    asio::buffer(ubuf_), [this, self](const asio::error_code &ec, std::size_t length) {
      if (ec) {
        LOGERR(ec, "RECV");
        destroy();
        return;
      }
      ulen_ = length;
      switch (ubuf_[0]) {
      case 1: // fold request
        do_parse_req();
        break;
      case 5: // standard request
        if (strict_) {
          LOGERR("STRICT");
          destroy();
          return;
        }
        do_read_stdauth();
        break;
      default:
        LOGERR("PARSE");
        destroy();
      }
    });
}

void Socks5Session::do_parse_req() {
  std::string domain;
  auto self(shared_from_this());
  if (!parser_.do_parse(&ubuf_[0], ulen_)) {
    LOGERR("PARSE");
    destroy();
    return;
  }
  switch (parser_.atype_) {
  case ATYPE_IPV4:
    endpoint_ =
      asio::ip::tcp::endpoint(asio::ip::address_v4(parser_.addr_.v4), parser_.port_);
    LOGTRACE(isocket_, endpoint_, "CONNECT");
    do_connect();
    break;
  case ATYPE_IPV6:
    endpoint_ =
      asio::ip::tcp::endpoint(asio::ip::address_v6(parser_.addr_.v6), parser_.port_);
    LOGTRACE(isocket_, endpoint_, "CONNECT");
    do_connect();
    break;
  case ATYPE_DOMAIN:
    domain = std::string((const char *)parser_.addr_.domain + 1, parser_.addr_.domain[0]);
    LOGTRACE(isocket_, domain, parser_.port_, "CONNECT");
    resolver_.async_resolve(
      domain, NULL,
      [this, self](const asio::error_code &ec, asio::ip::tcp::resolver::iterator it) {
        if (ec) {
          LOGERR(ec, "RESOLVE");
          destroy();
          return;
        }
        endpoint_ = *it;
        endpoint_.port(parser_.port_);
        do_connect();
      });
    break;
  }
}

void Socks5Session::do_connect() {
  asio::error_code ec;
  auto self(shared_from_this());

  // osocket_ opts: NODELAY KEEPALIVE FASTOPEN
  osocket_.open(endpoint_.protocol(), ec);
  SET_NODELAY(osocket_);
  SET_KEEPALIVE(osocket_);
  SET_TFO_CONNECT(osocket_);

  osocket_.async_connect( // connect
    endpoint_, [this, self](const asio::error_code &ec) {
      if (ec) {
        LOGERR(ec, "CONNECT");
        destroy();
        return;
      }
      do_proxy();
    });
}

// Standard Process ///////////////////////////////////////////////////////////

void Socks5Session::do_read_stdauth() {
  int i;
  auto self(shared_from_this());
  if (ubuf_[0] != 5 || ubuf_[1] + 2 != ulen_) {
    LOGERR("PARSE");
    destroy();
    return;
  }
  for (i = 2; i < ulen_; i++)
    if (ubuf_[i] == parser_.authmeth_)
      break;
  if (i == ulen_) {
    LOGERR("AUTHNEEDED");
    destroy();
    return;
  }
  ubuf_[1] = parser_.authmeth_;
  asio::async_write( // send
    isocket_, asio::buffer(ubuf_, 2),
    [this, self](const asio::error_code &ec, std::size_t length) {
      if (ec) {
        LOGERR(ec, "SEND");
        destroy();
        return;
      }
      switch (parser_.authmeth_) {
      case AUTH_NOAUTH:
        ubuf_[0] = 1;
        ubuf_[1] = 0;
        ubuf_[2] = 0;
        ulen_ = 3;
        do_read_stdreq();
        break;
      case AUTH_PASSWORD:
        isocket_.async_receive( // recv
          asio::buffer(ubuf_),
          [this, self](const asio::error_code &ec, std::size_t length) {
            if (ec) {
              LOGERR(ec, "RECV");
              destroy();
              return;
            }
            ulen_ = length;
            asio::async_write( // send
              isocket_, asio::buffer("\x01\x00", 2),
              [this, self](const asio::error_code &ec, size_t length) {
                if (ec) {
                  LOGERR(ec, "SEND");
                  destroy();
                  return;
                }
                do_read_stdreq();
              });
          });
        break;
      }
    });
}

void Socks5Session::do_read_stdreq() {
  auto self(shared_from_this());
  isocket_.async_receive( // recv
    asio::buffer(&ubuf_[ulen_], ubuf_.size() - ulen_),
    [this, self](const asio::error_code &ec, std::size_t length) {
      if (ec) {
        LOGERR(ec, "RECV");
        destroy();
        return;
      }
      ulen_ += length;
      asio::async_write( // send
        isocket_, asio::buffer("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10),
        [this, self](const asio::error_code &ec, std::size_t length) {
          if (ec) {
            LOGERR(ec, "SEND");
            destroy();
            return;
          }
          do_parse_req();
        });
    });
}

// Server /////////////////////////////////////////////////////////////////////

Socks5Server::Socks5Server(asio::io_context &context, asio::ip::tcp::endpoint &endpoint,
                           std::string &username, std::string &password, bool strict)
  : context_(context), acceptor_(context), endpoint_(endpoint), username_(username),
    password_(password), strict_(strict) {}

void Socks5Server::run() {
  // acceptor_ opts: REUSEADDR FASTOPEN
  acceptor_.open(endpoint_.protocol());
  SET_REUSEADDR(acceptor_);
  SET_TFO(acceptor_);
  acceptor_.bind(endpoint_);
  acceptor_.listen();
  LOGINFO("START", acceptor_);
  do_accept();
}

void Socks5Server::do_accept() {
  acceptor_.async_accept( // accept
    [this](const asio::error_code &ec, asio::ip::tcp::socket socket) {
      if (ec) {
        LOGERR(ec, "ACCEPT");
        return;
      }
      std::make_shared<Socks5Session>(context_, std::move(socket), username_, password_,
                                      strict_)
        ->run();
      do_accept();
    });
}

///////////////////////////////////////////////////////////////////////////////
//                                  Socks5S                                  //
///////////////////////////////////////////////////////////////////////////////

// Session ////////////////////////////////////////////////////////////////////

Socks5SSession::Socks5SSession(asio::io_context &context,
                               asio::ssl::stream<asio::ip::tcp::socket> &&stream,
                               std::string &username, std::string &password, bool strict)
  : TLSProxy(context, std::move(stream)), resolver_(context), parser_(username, password),
    strict_(strict) {}

void Socks5SSession::run() {
  asio::error_code ec;
  // stream_ opts: NODELAY KEEPALIVE
  SET_NODELAY(stream_.next_layer());
  SET_KEEPALIVE(stream_.next_layer());
  do_read_req();
}

// Fold Process ///////////////////////////////////////////////////////////////

void Socks5SSession::do_read_req() {
  auto self(shared_from_this());
  stream_.async_handshake( // handshake
    asio::ssl::stream<asio::ip::tcp::socket>::server,
    [this, self](const asio::error_code &ec) {
      if (ec) {
        LOGERR(ec, "TLS_HANDSHAKE");
        destroy();
        return;
      }
      stream_.async_read_some( // recv
        asio::buffer(ubuf_),
        [this, self](const asio::error_code &ec, std::size_t length) {
          if (ec) {
            LOGERR(ec, "RECV");
            destroy();
            return;
          }
          ulen_ = length;
          switch (ubuf_[0]) {
          case 1: // fold request
            do_parse_req();
            break;
          case 5: // standard request
            if (strict_) {
              LOGERR("STRICT");
              destroy();
              return;
            }
            do_read_stdauth();
            break;
          default:
            LOGERR("PARSE");
            destroy();
          }
        });
    });
}

void Socks5SSession::do_parse_req() {
  std::string domain;
  auto self(shared_from_this());
  if (!parser_.do_parse(&ubuf_[0], ulen_)) {
    LOGERR("PARSE");
    destroy();
    return;
  }
  switch (parser_.atype_) {
  case ATYPE_IPV4:
    endpoint_ =
      asio::ip::tcp::endpoint(asio::ip::address_v4(parser_.addr_.v4), parser_.port_);
    LOGTRACE(stream_.next_layer(), endpoint_, "CONNECT");
    do_connect();
    break;
  case ATYPE_IPV6:
    endpoint_ =
      asio::ip::tcp::endpoint(asio::ip::address_v6(parser_.addr_.v6), parser_.port_);
    LOGTRACE(stream_.next_layer(), endpoint_, "CONNECT");
    do_connect();
    break;
  case ATYPE_DOMAIN:
    domain = std::string((const char *)parser_.addr_.domain + 1, parser_.addr_.domain[0]);
    LOGTRACE(stream_.next_layer(), domain, parser_.port_, "CONNECT");
    resolver_.async_resolve(
      domain, NULL,
      [this, self](const asio::error_code &ec, asio::ip::tcp::resolver::iterator it) {
        if (ec) {
          LOGERR(ec, "RESOLVE");
          destroy();
          return;
        }
        endpoint_ = *it;
        endpoint_.port(parser_.port_);
        do_connect();
      });
    break;
  }
}

void Socks5SSession::do_connect() {
  asio::error_code ec;
  auto self(shared_from_this());

  // socket_ opts: NODELAY KEEPALIVE FASTOPEN
  socket_.open(endpoint_.protocol(), ec);
  SET_NODELAY(socket_);
  SET_KEEPALIVE(socket_);
  SET_TFO_CONNECT(socket_);

  socket_.async_connect( // connect
    endpoint_, [this, self](const asio::error_code &ec) {
      if (ec) {
        LOGERR(ec, "CONNECT");
        destroy();
        return;
      }
      do_proxy();
    });
}

// Standard Process ///////////////////////////////////////////////////////////

void Socks5SSession::do_read_stdauth() {
  int i;
  auto self(shared_from_this());
  if (ubuf_[0] != 5 || ubuf_[1] + 2 != ulen_) {
    LOGERR("PARSE");
    destroy();
    return;
  }
  for (i = 2; i < ulen_; i++)
    if (ubuf_[i] == parser_.authmeth_)
      break;
  if (i == ulen_) {
    LOGERR("AUTHNEEDED");
    destroy();
    return;
  }
  ubuf_[1] = parser_.authmeth_;
  asio::async_write( // send
    stream_, asio::buffer(ubuf_, 2),
    [this, self](const asio::error_code &ec, std::size_t length) {
      if (ec) {
        LOGERR(ec, "SEND");
        destroy();
        return;
      }
      switch (parser_.authmeth_) {
      case AUTH_NOAUTH:
        ubuf_[0] = 1;
        ubuf_[1] = 0;
        ubuf_[2] = 0;
        ulen_ = 3;
        do_read_stdreq();
        break;
      case AUTH_PASSWORD:
        stream_.async_read_some( // recv
          asio::buffer(ubuf_),
          [this, self](const asio::error_code &ec, std::size_t length) {
            if (ec) {
              LOGERR(ec, "RECV");
              destroy();
              return;
            }
            ulen_ = length;
            asio::async_write( // send
              stream_, asio::buffer("\x01\x00", 2),
              [this, self](const asio::error_code &ec, size_t length) {
                if (ec) {
                  LOGERR(ec, "SEND");
                  destroy();
                  return;
                }
                do_read_stdreq();
              });
          });
        break;
      }
    });
}

void Socks5SSession::do_read_stdreq() {
  auto self(shared_from_this());
  stream_.async_read_some( // recv
    asio::buffer(&ubuf_[ulen_], ubuf_.size() - ulen_),
    [this, self](const asio::error_code &ec, std::size_t length) {
      if (ec) {
        LOGERR(ec, "RECV");
        destroy();
        return;
      }
      ulen_ += length;
      asio::async_write( // send
        stream_, asio::buffer("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10),
        [this, self](const asio::error_code &ec, std::size_t length) {
          if (ec) {
            LOGERR(ec, "SEND");
            destroy();
            return;
          }
          do_parse_req();
        });
    });
}

// Server /////////////////////////////////////////////////////////////////////

Socks5SServer::Socks5SServer(asio::io_context &io_context,
                             asio::ssl::context &ssl_context,
                             asio::ip::tcp::endpoint &endpoint, std::string &username,
                             std::string &password, bool strict)
  : io_context_(io_context), ssl_context_(ssl_context), acceptor_(io_context),
    endpoint_(endpoint), username_(username), password_(password), strict_(strict) {}

void Socks5SServer::run() {
  // acceptor_ opts: REUSEADDR FASTOPEN
  acceptor_.open(endpoint_.protocol());
  SET_REUSEADDR(acceptor_);
  SET_TFO(acceptor_);
  acceptor_.bind(endpoint_);
  acceptor_.listen();
  LOGINFO("START", acceptor_);
  do_accept();
}

void Socks5SServer::do_accept() {
  acceptor_.async_accept( // accept
    [this](const asio::error_code &ec, asio::ip::tcp::socket socket) {
      if (ec) {
        LOGERR(ec, "ACCEPT");
        return;
      }
      std::make_shared<Socks5SSession>(
        io_context_,
        asio::ssl::stream<asio::ip::tcp::socket>(std::move(socket), ssl_context_),
        username_, password_, strict_)
        ->run();
      do_accept();
    });
}

///////////////////////////////////////////////////////////////////////////////
//                                    CLI                                    //
///////////////////////////////////////////////////////////////////////////////

extern "C" void socks5(const char *addr, const char *port, const char *username,
                       const char *password, int strict) {
  asio::io_context context;
  asio::ip::tcp::resolver resolver(context);
  asio::ip::tcp::endpoint endpoint;

  std::string _username(username ? username : ""), _password(password ? password : "");

  endpoint = *resolver.resolve(addr, port);

  Socks5Server server(context, endpoint, _username, _password, strict);
  server.run();
  context.run();
}

extern "C" void socks5s(const char *addr, const char *port, const char *username,
                        const char *password, const char *certfile, const char *keyfile,
                        const char *kpassword, int strict) {
  asio::io_context io_context;
  asio::ssl::context ssl_context(TLS_SERVER);
  asio::ip::tcp::resolver resolver(io_context);
  asio::ip::tcp::endpoint endpoint;

  std::string _certfile(certfile), _keyfile(keyfile),
    _kpassword(kpassword ? kpassword : "");
  std::string _username(username ? username : ""), _password(password ? password : "");

  endpoint = *resolver.resolve(addr, port);

  TLS::set_server(ssl_context, _certfile, _keyfile, _kpassword);

  Socks5SServer server(io_context, ssl_context, endpoint, _username, _password, strict);
  server.run();
  io_context.run();
}
