#include "tomato.hpp"

#include <iostream>

///////////////////////////////////////////////////////////////////////////////
//                                    LOG                                    //
///////////////////////////////////////////////////////////////////////////////

void Log::err(std::string reason) { std::cerr << "ERROR\t" + reason + "\n"; }

void Log::err(const asio::error_code &ec, std::string reason) {
  err(reason + ": " + ec.message());
}

void Log::info(std::string msg) { std::cerr << "INFO\t" + msg + "\n"; }

void Log::info(std::string msg, asio::ip::tcp::socket &socket) {
  asio::error_code ec;
  asio::ip::tcp::endpoint endpoint;

  endpoint = socket.remote_endpoint(ec);
  if (ec) {
    err(ec, "GETPEERNAME");
    return;
  }

  std::cerr << "INFO\t" + msg + ": " << endpoint << std::endl;
}

void Log::info(std::string msg, asio::ip::tcp::acceptor &acceptor) {
  asio::error_code ec;
  asio::ip::tcp::endpoint endpoint;

  endpoint = acceptor.local_endpoint(ec);
  if (ec) {
    err(ec, "GETPEERNAME");
    return;
  }

  std::cerr << "INFO\t" + msg + ": " << endpoint << std::endl;
}

void Log::trace(asio::ip::tcp::socket &isocket, asio::ip::tcp::socket &osocket,
                std::string reason) {
  asio::error_code ec;
  asio::ip::tcp::endpoint iendpoint, oendpoint;

  iendpoint = isocket.remote_endpoint(ec);
  if (ec) {
    err(ec, "GETPEERNAME");
    return;
  }
  oendpoint = osocket.remote_endpoint(ec);
  if (ec) {
    err(ec, "GETPEERNAME");
    return;
  }

  std::cout << "TRACE\t" + reason + ": " << iendpoint << " <=> " << oendpoint
            << std::endl;
}

void Log::trace(asio::ip::tcp::socket &socket, asio::ip::tcp::endpoint &endpoint,
                std::string reason) {
  asio::error_code ec;
  asio::ip::tcp::endpoint _endpoint;

  _endpoint = socket.remote_endpoint(ec);
  if (ec) {
    err(ec, "GETPEERNAME");
    return;
  }

  std::cout << "TRACE\t" + reason + ": " << _endpoint << " <=> " << endpoint << std::endl;
}

void Log::trace(asio::ip::tcp::socket &socket, std::string domain, unsigned short port,
                std::string reason) {
  asio::error_code ec;
  asio::ip::tcp::endpoint endpoint;

  endpoint = socket.remote_endpoint(ec);
  if (ec) {
    err(ec, "GETPEERNAME");
    return;
  }

  std::cout << "TRACE\t" + reason + ": " << endpoint << " <=> " << domain + ":" << port
            << std::endl;
}

void Log::trace(asio::ip::tcp::socket &socket, Socks5Parser &parser, std::string reason) {
  asio::error_code ec;
  asio::ip::tcp::endpoint endpoint, rendpoint;
  std::string domain;

  endpoint = socket.remote_endpoint(ec);
  if (ec) {
    err(ec, "GETPEERNAME");
    return;
  }

  switch (parser.atype_) {
  case ATYPE_IPV4:
    rendpoint =
      asio::ip::tcp::endpoint(asio::ip::address_v4(parser.addr_.v4), parser.port_);
    std::cout << "TRACE\t" + reason + ": " << endpoint << " <=> " << rendpoint
              << std::endl;
    break;
  case ATYPE_IPV6:
    rendpoint =
      asio::ip::tcp::endpoint(asio::ip::address_v6(parser.addr_.v6), parser.port_);
    std::cout << "TRACE\t" + reason + ": " << endpoint << " <=> " << rendpoint
              << std::endl;
    break;
  case ATYPE_DOMAIN:
    domain = std::string((const char *)parser.addr_.domain + 1, parser.addr_.domain[0]);
    std::cout << "TRACE\t" + reason + ": " << endpoint << " <=> " << domain + ":"
              << parser.port_ << std::endl;
    break;
  }
}

///////////////////////////////////////////////////////////////////////////////
//                                  SOCKOPTS                                 //
///////////////////////////////////////////////////////////////////////////////

void Sockopts::set_linger(asio::ip::tcp::socket &socket, bool active, int linger) {
  asio::error_code ec;
  socket.set_option(asio::ip::tcp::socket::linger(active, linger), ec);
}

void Sockopts::set_nodelay(asio::ip::tcp::socket &socket, bool active) {
  asio::error_code ec;
  socket.set_option(asio::ip::tcp::no_delay(active), ec);
}

void Sockopts::set_keepalive(asio::ip::tcp::socket &socket, bool active) {
  asio::error_code ec;
  socket.set_option(asio::socket_base::keep_alive(active), ec);
}

void Sockopts::set_reuseaddr(asio::ip::tcp::acceptor &acceptor, bool active) {
  asio::error_code ec;
  acceptor.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
}

void Sockopts::set_tfo(asio::ip::tcp::acceptor &acceptor, int qlen) {
  asio::error_code ec;
  acceptor.set_option(
    asio::detail::socket_option::integer<IPPROTO_TCP, TCP_FASTOPEN>(qlen), ec);
}

void Sockopts::set_tfo_connect(asio::ip::tcp::socket &socket, bool active) {
  asio::error_code ec;
  socket.set_option(
    asio::detail::socket_option::integer<IPPROTO_TCP, TCP_FASTOPEN_CONNECT>(active), ec);
}

///////////////////////////////////////////////////////////////////////////////
//                                    TLS                                    //
///////////////////////////////////////////////////////////////////////////////

std::list<SSL_SESSION *> TLS::sessions;

void TLS::set_server(asio::ssl::context &context, std::string &certfile,
                     std::string &keyfile, std::string &password) {
  context.set_options(asio::ssl::context::default_workarounds);
  context.use_certificate_chain_file(certfile);
  context.use_private_key_file(keyfile, asio::ssl::context::pem);
  if (!password.empty())
    context.set_password_callback(
      [password](std::size_t length, asio::ssl::context::password_purpose purpose) {
        return password;
      });
}

void TLS::set_client(asio::ssl::context &context, std::string &hostname,
                     std::string &cafile) {
  context.set_options(asio::ssl::context::default_workarounds);
  if (cafile.empty())
    context.set_default_verify_paths();
  else
    context.load_verify_file(cafile);
  context.set_verify_mode(asio::ssl::verify_peer);
  context.set_verify_callback(asio::ssl::host_name_verification(hostname));
}

int TLS::new_session_cb(SSL *ssl, SSL_SESSION *session) {
  sessions.push_front(session);
  return 0;
}

void TLS::remove_session_cb(SSL_CTX *context, SSL_SESSION *session) {
  sessions.remove(session);
}

void TLS::set_session_mode(asio::ssl::context &context) {
  SSL_CTX_set_session_cache_mode(context.native_handle(), SSL_SESS_CACHE_CLIENT);
  SSL_CTX_sess_set_new_cb(context.native_handle(), new_session_cb);
  SSL_CTX_sess_set_remove_cb(context.native_handle(), remove_session_cb);
}

void TLS::set_session(asio::ssl::stream<asio::ip::tcp::socket> &stream) {
  if (!sessions.empty())
    SSL_set_session(stream.native_handle(), sessions.front());
}
