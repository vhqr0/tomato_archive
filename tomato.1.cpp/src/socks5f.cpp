#include "tomato.hpp"

#include <string.h>

///////////////////////////////////////////////////////////////////////////////
//                                 ProxyRules                                //
///////////////////////////////////////////////////////////////////////////////

IPRule::IPRule(int rule) : rule_(rule) {}

bool IPRule::open(std::string &file) {
  int err;
  err = MMDB_open(file.c_str(), MMDB_MODE_MMAP, &mmdb_);
  if (err != MMDB_SUCCESS) {
    LOGERR("MMDBOPEN: " + std::string(MMDB_strerror(err)));
    return true;
  }
  return false;
}

void IPRule::close() { MMDB_close(&mmdb_); }

int IPRule::match(struct sockaddr *addr) {
  MMDB_lookup_result_s res;
  int err;
  res = MMDB_lookup_sockaddr(&mmdb_, addr, &err);
  if (err != MMDB_SUCCESS) {
    LOGERR("MMDBLOOKUP: " + std::string(MMDB_strerror(err)));
    return 0;
  }
  return res.found_entry ? rule_ : 0;
}

int ProxyRules::default_rule = RULE_PROXY;
std::vector<IPRule *> ProxyRules::ip_rules;
std::unordered_map<std::string, int> ProxyRules::domain_rules;

void ProxyRules::set_default_rule(int rule) { ProxyRules::default_rule = rule; }

void ProxyRules::add_ip_rule(std::string &mmdb, int rule) {
  IPRule *rulep = new IPRule(rule);
  if (rulep->open(mmdb)) {
    delete rulep;
    return;
  }
  ip_rules.push_back(rulep);
}

void ProxyRules::add_domain_rule(std::string &domain, int rule) {
  domain_rules.emplace(domain, rule);
}

int ProxyRules::match_ip_rules(asio::ip::tcp::endpoint &endpoint) {
  int i, res;
  union {
    struct sockaddr a;
    struct sockaddr_in a4;
    struct sockaddr_in6 a6;
  } addr;

  memset(&addr, 0, sizeof(addr));
  if (endpoint.address().is_v4()) {
    addr.a4.sin_family = AF_INET;
    memcpy(&addr.a4.sin_addr, &endpoint.address().to_v4().to_bytes()[0], 4);
  } else if (endpoint.address().is_v6()) {
    addr.a6.sin6_family = AF_INET6;
    memcpy(&addr.a6.sin6_addr, &endpoint.address().to_v6().to_bytes()[0], 16);
  } else {
    LOGERR("PARSE");
    return 0;
  }

  for (int i = 0; i < ip_rules.size(); i++) {
    res = ip_rules[i]->match(&addr.a);
    if (res)
      return res;
  }
  return 0;
}

int ProxyRules::match_domain_rules(std::string &domain) {
  auto it = domain_rules.find(domain);
  if (it == domain_rules.end())
    return 0;
  return it->second;
}

void ProxyRules::clear_rules() {
  int i;
  for (i = 0; i < ip_rules.size(); i++) {
    ip_rules[i]->close();
    delete ip_rules[i];
  }
  ip_rules.clear();
  domain_rules.clear();
}

///////////////////////////////////////////////////////////////////////////////
//                                  Socks5F                                  //
///////////////////////////////////////////////////////////////////////////////

// Session ////////////////////////////////////////////////////////////////////

Socks5FSession::Socks5FSession(asio::io_context &io_context,
                               asio::ssl::context &ssl_context,
                               asio::ip::tcp::socket &&socket,
                               asio::ip::tcp::endpoint &endpoint, std::string &lusername,
                               std::string &lpassword, std::string &rusername,
                               std::string &rpassword)
  : TLSProxy(io_context, ssl_context, std::move(socket)), resolved_(false),
    resolver_(io_context), endpoint_(endpoint), parser_(lusername, lpassword),
    rusername_(rusername), rpassword_(rpassword) {}

void Socks5FSession::run() {
  asio::error_code ec;
  // socket_ opts: NODELAY KEEPALIVE
  SET_NODELAY(socket_);
  SET_KEEPALIVE(socket_);
  do_read_req();
}

// Fold Process ///////////////////////////////////////////////////////////////

void Socks5FSession::do_read_req() {
  auto self(shared_from_this());
  socket_.async_receive( // recv
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
        do_read_stdauth();
        break;
      default:
        LOGERR("PARSE");
        destroy();
      }
    });
}

void Socks5FSession::do_parse_req() {
  if (!parser_.do_parse(&ubuf_[0], ulen_)) {
    LOGERR("PARSE");
    destroy();
    return;
  }

  if (!ProxyRules::domain_rules.empty() && parser_.atype_ == ATYPE_DOMAIN) {
    do_match_domain_rules();
    return;
  }

  if (!ProxyRules::ip_rules.empty()) {
    do_match_ip_rules();
    return;
  }

  do_match_default_rules();
}

// Connect&Direct /////////////////////////////////////////////////////////////

void Socks5FSession::do_connect() {
  int ulen, plen, alen, rlen;
  asio::error_code ec;
  auto self(shared_from_this());

  ulen = rusername_.length();
  plen = rpassword_.length();
  alen = ulen + plen + 3;
  dbuf_[0] = 1;
  dbuf_[1] = ulen;
  dbuf_[ulen + 2] = plen;
  memcpy(&dbuf_[2], rusername_.c_str(), ulen);
  memcpy(&dbuf_[ulen + 3], rpassword_.c_str(), plen);
  if (resolved_) {
    dbuf_[alen] = 5;
    dbuf_[alen + 1] = 1;
    dbuf_[alen + 2] = 0;
    if (dendpoint_.address().is_v4()) {
      dbuf_[alen + 3] = ATYPE_IPV4;
      memcpy(&dbuf_[alen + 4], &dendpoint_.address().to_v4().to_bytes()[0], 4);
      dbuf_[alen + 8] = dendpoint_.port() >> 8;
      dbuf_[alen + 9] = dendpoint_.port() & 0xff;
      dlen_ = alen + 10;
    } else if (dendpoint_.address().is_v4()) {
      dbuf_[alen + 3] = ATYPE_IPV6;
      memcpy(&dbuf_[alen + 4], &dendpoint_.address().to_v6().to_bytes()[0], 16);
      dbuf_[alen + 20] = dendpoint_.port() >> 8;
      dbuf_[alen + 21] = dendpoint_.port() & 0xff;
      dlen_ = alen + 22;
    } else {
      LOGERR("PARSE");
      destroy();
      return;
    }
  } else {
    ulen = parser_.username_.length();
    plen = parser_.password_.length();
    rlen = ulen_ - (ulen + plen + 3);
    memcpy(&dbuf_[alen], &ubuf_[ulen_ - rlen], rlen);
    dlen_ = alen + rlen;
  }

  // stream_ opts: NODELAY KEEPALIVE FASTOPEN
  stream_.next_layer().open(endpoint_.protocol(), ec);
  SET_NODELAY(stream_.next_layer());
  SET_KEEPALIVE(stream_.next_layer());
  SET_TFO_CONNECT(stream_.next_layer());

  stream_.next_layer().async_connect( // connect
    endpoint_, [this, self](const asio::error_code &ec) {
      if (ec) {
        LOGERR(ec, "CONNECT");
        destroy();
        return;
      }
      TLS::set_session(stream_); // reuse session
      stream_.async_handshake(   // handshake
        asio::ssl::stream<asio::ip::tcp::socket>::client,
        [this, self](const asio::error_code &ec) {
          if (ec) {
            LOGERR(ec, "TLS_HANDSHAKE");
            destroy();
            return;
          }
          asio::async_write( // send
            stream_, asio::buffer(dbuf_, dlen_),
            [this, self](const asio::error_code &ec, std::size_t length) {
              if (ec) {
                LOGERR(ec, "SEND");
                destroy();
                return;
              }
              do_proxy();
            });
        });
    });
}

void Socks5FSession::do_direct() {
  std::string domain;
  asio::error_code ec;
  auto self(shared_from_this());

  if (!resolved_) {
    resolved_ = true;
    switch (parser_.atype_) {
    case ATYPE_IPV4:
      dendpoint_ =
        asio::ip::tcp::endpoint(asio::ip::address_v4(parser_.addr_.v4), parser_.port_);
      do_direct();
      break;
    case ATYPE_IPV6:
      dendpoint_ =
        asio::ip::tcp::endpoint(asio::ip::address_v6(parser_.addr_.v6), parser_.port_);
      do_direct();
      break;
    case ATYPE_DOMAIN:
      domain =
        std::string((const char *)parser_.addr_.domain + 1, parser_.addr_.domain[0]);
      resolver_.async_resolve(
        domain, NULL,
        [this, self](const asio::error_code &ec, asio::ip::tcp::resolver::iterator it) {
          if (ec) {
            LOGERR(ec, "RESOLVE");
            destroy();
            return;
          }
          dendpoint_ = *it;
          dendpoint_.port(parser_.port_);
          do_direct();
        });
      break;
    }
    return;
  }

  // stream_ opts: NODELAY KEEPALIVE FASTOPEN
  stream_.next_layer().open(dendpoint_.protocol(), ec);
  SET_NODELAY(stream_.next_layer());
  SET_KEEPALIVE(stream_.next_layer());
  SET_TFO_CONNECT(stream_.next_layer());

  stream_.next_layer().async_connect( // connect
    dendpoint_, [this, self](const asio::error_code &ec) {
      if (ec) {
        LOGERR(ec, "CONNECT");
        destroy();
        return;
      }
      std::make_shared<RAWProxy>(std::move(socket_), std::move(stream_.next_layer()))
        ->do_proxy();
    });
}

// Match Rules ////////////////////////////////////////////////////////////////

void Socks5FSession::do_match_default_rules() {
  switch (ProxyRules::default_rule) {
  case RULE_BLOCK:
    LOGTRACE(socket_, parser_, "CONNECT[BLOCK]");
    destroy();
    break;
  case RULE_PROXY:
    LOGTRACE(socket_, parser_, "CONNECT[PROXY]");
    do_connect();
    break;
  case RULE_DIRECT:
    LOGTRACE(socket_, parser_, "CONNECT[DIRECT]");
    do_direct();
    break;
  }
}

void Socks5FSession::do_match_ip_rules() {
  std::string domain;
  auto self(shared_from_this());

  if (!resolved_) {
    resolved_ = true;
    switch (parser_.atype_) {
    case ATYPE_IPV4:
      dendpoint_ =
        asio::ip::tcp::endpoint(asio::ip::address_v4(parser_.addr_.v4), parser_.port_);
      do_match_ip_rules();
      break;
    case ATYPE_IPV6:
      dendpoint_ =
        asio::ip::tcp::endpoint(asio::ip::address_v6(parser_.addr_.v6), parser_.port_);
      do_match_ip_rules();
      break;
    case ATYPE_DOMAIN:
      domain =
        std::string((const char *)parser_.addr_.domain + 1, parser_.addr_.domain[0]);
      resolver_.async_resolve(
        domain, NULL,
        [this, self](const asio::error_code &ec, asio::ip::tcp::resolver::iterator it) {
          if (ec) {
            LOGERR(ec, "RESOLVE");
            destroy();
            return;
          }
          dendpoint_ = *it;
          dendpoint_.port(parser_.port_);
          do_match_ip_rules();
        });
      break;
    }
    return;
  }

  switch (ProxyRules::match_ip_rules(dendpoint_)) {
  case RULE_BLOCK:
    LOGTRACE(socket_, parser_, "CONNECT[IBLOCK]");
    destroy();
    return;
  case RULE_PROXY:
    LOGTRACE(socket_, parser_, "CONNECT[IPROXY]");
    do_connect();
    return;
  case RULE_DIRECT:
    LOGTRACE(socket_, parser_, "CONNECT[IDIRECT]");
    do_direct();
    return;
  }

  do_match_default_rules();
}

void Socks5FSession::do_match_domain_rules() {
  std::string domain;
  auto self(shared_from_this());

  domain = std::string((const char *)parser_.addr_.domain + 1, parser_.addr_.domain[0]);
  switch (ProxyRules::match_domain_rules(domain)) {
  case RULE_BLOCK:
    LOGTRACE(socket_, parser_, "CONNECT[DBLOCK]");
    destroy();
    return;
  case RULE_PROXY:
    LOGTRACE(socket_, parser_, "CONNECT[DPROXY]");
    do_connect();
    return;
  case RULE_DIRECT:
    LOGTRACE(socket_, parser_, "CONNECT[DDIRECT]");
    do_direct();
    return;
  }

  if (!ProxyRules::ip_rules.empty()) {
    do_match_ip_rules();
    return;
  }

  do_match_default_rules();
}

// Standard Process ///////////////////////////////////////////////////////////

void Socks5FSession::do_read_stdauth() {
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
    socket_, asio::buffer(ubuf_, 2),
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
        socket_.async_receive( // recv
          asio::buffer(ubuf_),
          [this, self](const asio::error_code &ec, std::size_t length) {
            if (ec) {
              LOGERR(ec, "RECV");
              destroy();
              return;
            }
            ulen_ = length;
            asio::async_write( // send
              socket_, asio::buffer("\x01\x00", 2),
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

void Socks5FSession::do_read_stdreq() {
  auto self(shared_from_this());
  socket_.async_receive( // recv
    asio::buffer(&ubuf_[ulen_], ubuf_.size() - ulen_),
    [this, self](const asio::error_code &ec, std::size_t length) {
      if (ec) {
        LOGERR(ec, "RECV");
        destroy();
        return;
      }
      ulen_ += length;
      asio::async_write( // send
        socket_, asio::buffer("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10),
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

Socks5FServer::Socks5FServer(asio::io_context &io_context,
                             asio::ssl::context &ssl_context,
                             asio::ip::tcp::endpoint &lendpoint,
                             asio::ip::tcp::endpoint &rendpoint, std::string &lusername,
                             std::string &lpassword, std::string &rusername,
                             std::string &rpassword)
  : io_context_(io_context), ssl_context_(ssl_context), acceptor_(io_context),
    lendpoint_(lendpoint), rendpoint_(rendpoint), lusername_(lusername),
    lpassword_(lpassword), rusername_(rusername), rpassword_(rpassword) {}

void Socks5FServer::run() {
  // acceptor_ opts: REUSEADDR FASTOPEN
  acceptor_.open(lendpoint_.protocol());
  SET_REUSEADDR(acceptor_);
  SET_TFO(acceptor_);
  acceptor_.bind(lendpoint_);
  acceptor_.listen();
  LOGINFO("START", acceptor_);
  do_accept();
}

void Socks5FServer::do_accept() {
  acceptor_.async_accept( // accept
    [this](const asio::error_code &ec, asio::ip::tcp::socket socket) {
      if (ec) {
        LOGERR(ec, "ACCEPT");
        return;
      }
      std::make_shared<Socks5FSession>(io_context_, ssl_context_, std::move(socket),
                                       rendpoint_, lusername_, lpassword_, rusername_,
                                       rpassword_)
        ->run();
      do_accept();
    });
}

///////////////////////////////////////////////////////////////////////////////
//                                    CLI                                    //
///////////////////////////////////////////////////////////////////////////////

extern "C" void set_default_rule(int rule) { ProxyRules::set_default_rule(rule); }

extern "C" void add_ip_rule(const char *mmdb, int rule) {
  std::string _mmdb(mmdb);
  ProxyRules::add_ip_rule(_mmdb, rule);
}

extern "C" void add_domain_rule(const char *domain, int rule) {
  std::string _domain(domain);
  ProxyRules::add_domain_rule(_domain, rule);
}

extern "C" void clear_rules() { ProxyRules::clear_rules(); }

extern "C" void socks5f(const char *laddr, const char *lport, const char *lusername,
                        const char *lpassword, const char *raddr, const char *rport,
                        const char *rusername, const char *rpassword,
                        const char *hostname, const char *cafile) {
  asio::io_context io_context;
  asio::ssl::context ssl_context(TLS_CLIENT);
  asio::ip::tcp::resolver resolver(io_context);
  asio::ip::tcp::endpoint lendpoint, rendpoint;

  lendpoint = *resolver.resolve(laddr, lport);
  rendpoint = *resolver.resolve(raddr, rport);

  std::string _hostname(hostname ? hostname : raddr), _cafile(cafile ? cafile : "");
  std::string _lusername(lusername ? lusername : ""),
    _lpassword(lpassword ? lpassword : "");
  std::string _rusername(rusername ? rusername : ""),
    _rpassword(rpassword ? rpassword : "");

  TLS::set_client(ssl_context, _hostname, _cafile);
  TLS::set_session_mode(ssl_context);

  LOGINFO("IPRULES: " + std::to_string(ProxyRules::ip_rules.size()) +
          " ip rules was loaded");
  LOGINFO("DOMAINRULES: " + std::to_string(ProxyRules::domain_rules.size()) +
          " domain rules was loaded");

  Socks5FServer server(io_context, ssl_context, lendpoint, rendpoint, _lusername,
                       _lpassword, _rusername, _rpassword);
  server.run();
  io_context.run();
}
