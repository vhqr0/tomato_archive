#include "tomato.hpp"

const char *rule2tag(int rule) {
  const char *tag = "[unknown]";
  switch (rule) {
  case RULE_BLOCK:
    tag = "[block]";
    break;
  case RULE_PROXY:
    tag = "[proxy]";
    break;
  case RULE_DIRECT:
    tag = "[direct]";
    break;
  }
  return tag;
}

void loginfo(int id, const tcp::endpoint &from_endpoint, const tcp::endpoint &to_endpoint,
             int rule) {
  std::ostringstream oss;
  oss << id << '\t' << from_endpoint << " <=> " << to_endpoint << rule2tag(rule) << std::endl;
  std::cout << oss.str();
}

void loginfo(int id, const tcp::endpoint &from_endpoint,
             const std::pair<std::string, unsigned short> &to_domain, int rule) {
  std::ostringstream oss;
  oss << id << '\t' << from_endpoint << " <=> " << to_domain.first << ':' << to_domain.second
      << rule2tag(rule) << std::endl;
  std::cout << oss.str();
}

void loginfo(int id, const tcp::endpoint &from_endpoint, const tcp::endpoint to_endpoint,
             const std::pair<std::string, unsigned short> &to_domain, int rule) {
  std::ostringstream oss;
  oss << id << '\t' << from_endpoint << " <=> " << to_domain.first << ':' << to_domain.second
      << " => " << to_endpoint << rule2tag(rule) << std::endl;
  std::cout << oss.str();
}

void logerr(int id, std::string reasion, const std::string &what) {
  std::ostringstream oss;
  oss << id << '\t' << reasion << ": " << what << std::endl;
  std::cout << oss.str();
}

void socket_close(tcp::socket &socket) {
  asio::error_code ec;
  if (socket.is_open()) {
    socket.cancel(ec);
    socket.shutdown(tcp::socket::shutdown_both, ec);
    socket.set_option(tcp::socket::linger(true, 0), ec);
    socket.close(ec);
  }
}

co_async<void> proxy_raw2raw(Socket reader, Socket writer, int id) {
  TOMATO_BUF buf;
  std::size_t n;

  try {
    for (;;) {
      n = co_await reader->async_receive(asio::buffer(buf), asio::use_awaitable);
      co_await asio::async_write(*writer, asio::buffer(buf, n), asio::use_awaitable);
    }
  } catch (const asio::system_error &e) {
    asio::error_code ec = e.code();
    if (ec == asio::error::operation_aborted)
      co_return;
    if (ec == asio::error::eof) {
      writer->shutdown(tcp::socket::shutdown_send, ec);
      co_return;
    }
    socket_close(*reader);
    socket_close(*writer);
    // logerr(id, "proxy system error", e.what());
  } catch (const std::exception &e) {
    socket_close(*reader);
    socket_close(*writer);
    logerr(id, "proxy exception", e.what());
  }
}

co_async<void> proxy_raw2tls(Socket reader, TLSocket writer, int id) {
  TOMATO_BUF buf;
  std::size_t n;

  try {
    for (;;) {
      n = co_await reader->async_receive(asio::buffer(buf), asio::use_awaitable);
      co_await asio::async_write(*writer, asio::buffer(buf, n), asio::use_awaitable);
    }
  } catch (const asio::system_error &e) {
    asio::error_code ec = e.code();
    if (ec == asio::error::operation_aborted)
      co_return;
    if (ec == asio::error::eof) {
      asio::co_spawn(
        reader->get_executor(),
        [](Socket reader, TLSocket writer, int id) -> co_async<void> {
          try {
            co_await writer->async_shutdown(asio::use_awaitable);
          } catch (const asio::system_error &e) {
            asio::error_code ec = e.code();
            if (ec == asio::error::operation_aborted)
              co_return;
            socket_close(*reader);
            socket_close(writer->next_layer());
            // logerr(id, "proxy system error", e.what());
          } catch (const std::exception &e) {
            socket_close(*reader);
            socket_close(writer->next_layer());
            logerr(id, "proxy exception", e.what());
          }
        }(reader, writer, id),
        asio::detached);
      co_return;
    }
    socket_close(*reader);
    socket_close(writer->next_layer());
    // logerr(id, "proxy system error", e.what());
  } catch (const std::exception &e) {
    socket_close(*reader);
    socket_close(writer->next_layer());
    logerr(id, "proxy exception", e.what());
  }
}

co_async<void> proxy_tls2raw(TLSocket reader, Socket writer, int id) {
  TOMATO_BUF buf;
  std::size_t n;

  try {
    for (;;) {
      n = co_await reader->async_read_some(asio::buffer(buf), asio::use_awaitable);
      co_await asio::async_write(*writer, asio::buffer(buf, n), asio::use_awaitable);
    }
  } catch (const asio::system_error &e) {
    asio::error_code ec = e.code();
    if (ec == asio::error::operation_aborted)
      co_return;
    if (ec == asio::error::eof) {
      writer->shutdown(tcp::socket::shutdown_send, ec);
      co_return;
    }
    socket_close(reader->next_layer());
    socket_close(*writer);
    // logerr(id, "proxy system error", e.what());
  } catch (const std::exception &e) {
    socket_close(reader->next_layer());
    socket_close(*writer);
    logerr(id, "proxy exception", e.what());
  }
}

std::string trojan_password(const std::string &password) {
  unsigned char digest[EVP_MAX_MD_SIZE], hex[56];
  EVP_MD_CTX *ctx;
  unsigned int digest_len;

  if (!(ctx = EVP_MD_CTX_new()))
    throw std::runtime_error("EVP_MD_CTX_new failed");
  if (!EVP_DigestInit_ex(ctx, EVP_sha224(), NULL) ||
      !EVP_DigestUpdate(ctx, password.c_str(), password.length()) ||
      !EVP_DigestFinal_ex(ctx, digest, &digest_len)) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("EVP_Digest* failed");
  }

  assert(digest_len == 28);

  for (int i = 0; i < 28; i++) {
    unsigned char left = digest[i] >> 4;
    unsigned char right = digest[i] & 0xf;
    hex[2 * i] = left > 9 ? left - 10 + 'a' : left + '0';
    hex[2 * i + 1] = right > 9 ? right - 10 + 'a' : right + '0';
  }

  return std::string((const char *)hex, 56);
}

std::regex http_startline_re("^(\\w+) [^ ]+ (HTTP/[^ \r\n]+)$");
std::regex http_hostline_re("^Host: ([^ :\\[\\]\r\n]+|\\[[:0-9a-fA-F]+\\])(:([0-9]+))?$");

co_async<void> socks5_or_http_accept(Socket socket, socks5_req &req, std::string &rest) {
  TOMATO_BUF buf;
  std::size_t n;

  n = co_await socket->async_receive(asio::buffer(buf), asio::use_awaitable);

  if (buf[0] == 5) { // socks5
    if (buf[1] + 2 != n || std::find(&buf[2], &buf[n], 0) == &buf[n])
      throw std::invalid_argument("invalid socks5 handshake 1");
    co_await asio::async_write(*socket, asio::buffer("\x05\x00", 2), asio::use_awaitable);
    n = co_await socket->async_receive(asio::buffer(buf), asio::use_awaitable);
    if (buf[0] != 5 || buf[1] != 1 || buf[2] != 0)
      throw std::invalid_argument("invalid socks5 handshake 2");
    switch (buf[3]) {
    case ATYPE_IPV4:
      if (n != 10)
        throw std::invalid_argument("invalid socks5 handshake 2");
      req.endpoint.address(asio::ip::address_v4(*(asio::ip::address_v4::bytes_type *)&buf[4]));
      req.endpoint.port((buf[8] << 8) + buf[9]);
      req.atype = ATYPE::v4;
      break;
    case ATYPE_IPV6:
      if (n != 22)
        throw std::invalid_argument("invalid socks5 handshake 2");
      req.endpoint.address(asio::ip::address_v6(*(asio::ip::address_v6::bytes_type *)&buf[4]));
      req.endpoint.port((buf[20] << 8) + buf[21]);
      req.atype = ATYPE::v6;
      break;
    case ATYPE_DOMAIN:
      if (n != buf[4] + 7)
        throw std::invalid_argument("invalid socks5 handshake 2");
      req.domain.first = std::string((const char *)&buf[5], buf[4]);
      req.domain.second = (buf[buf[4] + 5] << 8) + buf[buf[4] + 6];
      req.atype = ATYPE::domain;
      break;
    default:
      throw std::invalid_argument("invalid socks5 handshake 2");
    }
    co_await asio::async_write(
      *socket, asio::buffer("\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10), asio::use_awaitable);
  } else { // http
    std::string message, startline, body, method, version, hostname, service;
    std::vector<std::string> headers;
    std::string::size_type pos;
    std::match_results<std::string::iterator> res;
    message = std::string((const char *)&buf[0], n);
    if ((pos = message.find("\r\n\r\n")) == std::string::npos)
      throw std::invalid_argument("invalid socks5 or http handshake");
    body = message.substr(pos + 4);
    message = message.substr(0, pos);
    if ((pos = message.find("\r\n")) == std::string::npos)
      throw std::invalid_argument("invalid socks5 or http handshake");
    startline = message.substr(0, pos);
    if (!std::regex_search(startline.begin(), startline.end(), res, http_startline_re))
      throw std::invalid_argument("invalid socks5 or http handshake");
    method = res[1];
    version = res[2];
    message = message.substr(pos + 2);
    while ((pos = message.find("\r\n")) != std::string::npos) {
      std::string header = message.substr(0, pos);
      message = message.substr(pos + 2);
      if (!header.starts_with("Proxy-"))
        headers.push_back(header);
    }
    if (!message.starts_with("Proxy-"))
      headers.push_back(message);
    for (auto &header : headers) {
      if (header.starts_with("Host: ")) {
        if (!std::regex_search(header.begin(), header.end(), res, http_hostline_re))
          throw std::invalid_argument("invalid http handshake");
        hostname = res[1];
        service = res[3];
        goto success;
      }
    }
    throw std::invalid_argument("invalid http handshake");
  success:
    if (hostname[0] == '[')
      hostname = hostname.substr(1, hostname.length() - 2);
    req.atype = ATYPE::domain;
    req.domain.first = hostname;
    req.domain.second = service.empty() ? 80 : std::stoi(service);
    if (method == "CONNECT") {
      rest = body;
      message = version + " 200 Connection Established\r\nConnection: close\r\n\r\n";
      co_await asio::async_write(*socket, asio::buffer(message), asio::use_awaitable);
    } else {
      rest = startline + "\r\n";
      for (auto &header : headers)
        rest += header + "\r\n";
      rest += "\r\n" + body;
    }
  }
}

co_async<void> trojan_accept(TLSocket socket, const std::string &password, socks5_req &req,
                             std::string &rest) {
  TOMATO_BUF buf;
  std::size_t n;

  co_await socket->async_handshake(ssl::stream<tcp::socket>::server, asio::use_awaitable);
  n = co_await socket->async_read_some(asio::buffer(buf), asio::use_awaitable);
  if (std::memcmp(&buf[0], password.c_str(), 56) || buf[56] != 0xd || buf[57] != 0xa || buf[58] != 1)
    throw std::invalid_argument("invalid trojan handshake");
  switch (buf[59]) {
  case ATYPE_IPV4:
    if (n < 68 || buf[66] != 0xd || buf[67] != 0xa)
      throw std::invalid_argument("invalid trojan handshake");
    req.endpoint.address(asio::ip::address_v4(*(asio::ip::address_v4::bytes_type *)&buf[60]));
    req.endpoint.port((buf[64] << 8) + buf[65]);
    req.atype = ATYPE::v4;
    if (n > 68)
      rest = std::string((const char *)&buf[68], n - 68);
    break;
  case ATYPE_IPV6:
    if (n < 80 || buf[78] != 0xd || buf[79] != 0xa)
      throw std::invalid_argument("invalid trojan handshake");
    req.endpoint.address(asio::ip::address_v6(*(asio::ip::address_v6::bytes_type *)&buf[60]));
    req.endpoint.port((buf[76] << 8) + buf[77]);
    req.atype = ATYPE::v6;
    if (n > 80)
      rest = std::string((const char *)&buf[80], n - 80);
    break;
  case ATYPE_DOMAIN:
    if (n < buf[60] + 65 || buf[buf[60] + 63] != 0xd || buf[buf[60] + 64] != 0xa)
      throw std::invalid_argument("invalid trojan handshake");
    req.domain.first = std::string((const char *)&buf[61], buf[60]);
    req.domain.second = (buf[buf[60] + 61] << 8) + buf[buf[60] + 62];
    req.atype = ATYPE::domain;
    if (n > buf[60] + 65)
      rest = std::string((const char *)&buf[buf[60] + 65], n - (buf[60] + 65));
    break;
  default:
    throw std::invalid_argument("invalid trojan handshake");
  }
}

co_async<void> socks5_connect(Socket socket, socks5_req &req, const std::string &rest) {
  socket->open(req.endpoint.protocol());
  socket->set_option(tcp::no_delay(true));
  socket->set_option(asio::socket_base::keep_alive(true));
  co_await socket->async_connect(req.endpoint, asio::use_awaitable);
  if (!rest.empty())
    co_await asio::async_write(*socket, asio::buffer(rest), asio::use_awaitable);
}

co_async<void> trojan_connect(TLSocket socket, const tcp::endpoint &endpoint,
                              const std::string &password, socks5_req &req,
                              const std::string &rest) {
  TOMATO_BUF buf;
  std::size_t n;

  std::memcpy(&buf[0], password.c_str(), 56);
  buf[56] = 0xd;
  buf[57] = 0xa;
  buf[58] = 1;
  switch (req.atype) {
  case ATYPE::v4:
    buf[59] = ATYPE_IPV4;
    std::memcpy(&buf[60], &req.endpoint.address().to_v4().to_bytes()[0], 4);
    buf[64] = req.endpoint.port() >> 8;
    buf[65] = req.endpoint.port() & 0xff;
    n = 66;
    break;
  case ATYPE::v6:
    buf[59] = ATYPE_IPV6;
    std::memcpy(&buf[60], &req.endpoint.address().to_v6().to_bytes()[0], 16);
    buf[76] = req.endpoint.port() >> 8;
    buf[77] = req.endpoint.port() & 0xff;
    n = 78;
    break;
  case ATYPE::domain:
    buf[59] = ATYPE_DOMAIN;
    buf[60] = n = req.domain.first.length();
    std::memcpy(&buf[61], req.domain.first.c_str(), n);
    buf[61 + n] = req.domain.second >> 8;
    buf[62 + n] = req.domain.second & 0xff;
    n += 63;
    break;
  }
  buf[n++] = 0xd;
  buf[n++] = 0xa;

  if (!rest.empty()) {
    assert(rest.length() + n <= sizeof(buf));
    std::memcpy(&buf[n], rest.c_str(), rest.length());
    n += rest.length();
  }

  socket->next_layer().open(endpoint.protocol());
  socket->next_layer().set_option(tcp::no_delay(true));
  socket->next_layer().set_option(asio::socket_base::keep_alive(true));
  co_await socket->next_layer().async_connect(endpoint, asio::use_awaitable);
  tls_set_session(socket);
  co_await socket->async_handshake(ssl::stream<tcp::socket>::client, asio::use_awaitable);
  co_await asio::async_write(*socket, asio::buffer(buf, n), asio::use_awaitable);
}

std::list<SSL_SESSION *> sessions;

int new_session_cb(SSL *ssl, SSL_SESSION *session) {
  sessions.push_front(session);
  return 0;
}

void remove_session_cb(SSL_CTX *ctx, SSL_SESSION *session) { sessions.remove(session); }

void tls_set_session_mode(ssl::context &tls_context) {
  SSL_CTX_set_session_cache_mode(tls_context.native_handle(), SSL_SESS_CACHE_CLIENT);
  SSL_CTX_sess_set_new_cb(tls_context.native_handle(), new_session_cb);
  SSL_CTX_sess_set_remove_cb(tls_context.native_handle(), remove_session_cb);
}

void tls_set_session(TLSocket socket) {
  if (!sessions.empty())
    SSL_set_session(socket->native_handle(), sessions.front());
}
