#include "tomato.hpp"

#include <string.h>

#include <chrono>

///////////////////////////////////////////////////////////////////////////////
//                                  Acceptor                                 //
///////////////////////////////////////////////////////////////////////////////

// Session ////////////////////////////////////////////////////////////////////

AcceptorSession::AcceptorSession(asio::io_context &context,
                                 asio::ip::tcp::socket &&isocket,
                                 asio::ip::tcp::acceptor &&acceptor)
  : RAWProxy(context, std::move(isocket)), acceptor_(std::move(acceptor)),
    timer_(context) {}

void AcceptorSession::run() {
  asio::error_code ec;
  // isocket_ opts: NODELAY KEEPALIVE
  // acceptor_ opts: ()
  SET_NODELAY(isocket_);
  SET_KEEPALIVE(isocket_);

  // acceptor_ is open and bound
  acceptor_.listen(1, ec);
  do_accept();
}

void AcceptorSession::do_accept() {
  auto self(shared_from_this());
  timer_.expires_after(std::chrono::seconds(TOMATO_ACCEPTOR_TIMEWAIT));
  timer_.async_wait( // wait
    [this, self](const asio::error_code &ec) {
      asio::error_code _ec;
      if (ec) {
        if (ec != asio::error::operation_aborted) {
          LOGERR(ec, "WAIT");
          destroy();
        }
        return;
      }
      acceptor_.cancel(_ec);
    });
  acceptor_.async_accept( // accept
    osocket_, [this, self](const asio::error_code &ec) {
      asio::error_code _ec;
      if (ec) {
        if (ec != asio::error::operation_aborted) {
          LOGERR(ec, "ACCEPT");
          destroy();
        }
        return;
      }
      timer_.cancel(_ec);
      acceptor_.close(_ec);
      // osocket_ opts: NODELAY KEEPALIVE
      SET_NODELAY(osocket_);
      SET_KEEPALIVE(osocket_);
      do_proxy();
    });
}

void AcceptorSession::destroy() {
  asio::error_code ec;
  if (acceptor_.is_open()) {
    acceptor_.cancel(ec);
    acceptor_.close(ec);
  }
  timer_.cancel(ec);
  RAWProxy::destroy();
}

// Server /////////////////////////////////////////////////////////////////////

Acceptor::Acceptor(asio::io_context &io_context, asio::ssl::context &ssl_context,
                   asio::ip::tcp::endpoint &cendpoint, asio::ip::tcp::endpoint &endpoint,
                   std::string &username, std::string &password)
  : io_context_(io_context), ssl_context_(ssl_context), acceptor_(io_context),
    timer_(io_context), cendpoint_(cendpoint), endpoint_(endpoint), username_(username),
    password_(password) {}

void Acceptor::run() {
  in_rerun_ = false;
  stream_ = new asio::ssl::stream<asio::ip::tcp::socket>(io_context_, ssl_context_);
  do_connector_accept();
}

void Acceptor::rerun() {
  asio::error_code ec;

  if (in_rerun_)
    return;
  in_rerun_ = true;

  LOGINFO("RERUN TIMEWAIT");
  if (stream_->next_layer().is_open()) {
    stream_->next_layer().cancel(ec);
    SET_LINGER(stream_->next_layer());
    stream_->next_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    stream_->next_layer().close(ec);
  }
  if (acceptor_.is_open()) {
    acceptor_.cancel(ec);
    acceptor_.close(ec);
  }
  timer_.cancel(ec);
  timer_.expires_after(std::chrono::seconds(TOMATO_ACCEPTOR_RERUN_TIMEWAIT));
  timer_.async_wait( // wait
    [this](const asio::error_code &ec) {
      if (ec) {
        LOGERR(ec, "WAIT");
        return;
      }
      LOGINFO("RERUN");
      delete stream_;
      run();
    });
}

void Acceptor::do_connector_accept() {
  asio::error_code ec;
  // acceptor_ opts: REUSEADDR
  acceptor_.open(cendpoint_.protocol(), ec);
  SET_REUSEADDR(acceptor_);
  acceptor_.bind(cendpoint_, ec);
  acceptor_.listen(1, ec);
  acceptor_.async_accept( // accept
    stream_->next_layer(), [this](const asio::error_code &ec) {
      asio::error_code _ec;
      if (ec) {
        if (ec != asio::error::operation_aborted) {
          LOGERR(ec, "ACCEPT");
          rerun();
        }
        return;
      }
      acceptor_.close(_ec);
      LOGINFO("ACCEPT CONNECTOR", stream_->next_layer());
      // stream_ opts: LINGER NODELAY KEEPALIVE
      SET_LINGER(stream_->next_layer());
      SET_NODELAY(stream_->next_layer());
      SET_KEEPALIVE(stream_->next_layer());
      stream_->async_handshake( // handshake
        asio::ssl::stream<asio::ip::tcp::socket>::server,
        [this](const asio::error_code &ec) {
          if (ec) {
            if (ec != asio::error::operation_aborted) {
              LOGERR(ec, "TLS_HANDSHAKE");
              rerun();
            }
            return;
          }
          stream_->async_read_some( // recv
            asio::buffer(buf_), [this](const asio::error_code &ec, std::size_t length) {
              asio::error_code _ec;
              int ulen, plen;
              std::string username, password;
              if (ec) {
                if (ec != asio::error::operation_aborted) {
                  LOGERR(ec, "RECV");
                  rerun();
                }
                return;
              }
              ulen = buf_[0];
              plen = buf_[ulen + 1];
              if (length != ulen + plen + 2) {
                LOGERR("PARSE");
                rerun();
                return;
              }
              username = std::string((const char *)&buf_[1], ulen);
              password = std::string((const char *)&buf_[ulen + 2], plen);
              if ((!username_.empty() && username_ != username) ||
                  (!password_.empty() && password_ != password)) {
                LOGERR("AUTH");
                rerun();
                return;
              }
              // acceptor_ opts: REUSEADDR FASTOPEN
              acceptor_.open(endpoint_.protocol(), _ec);
              SET_REUSEADDR(acceptor_);
              SET_TFO(acceptor_);
              acceptor_.bind(endpoint_, _ec);
              acceptor_.listen(asio::socket_base::max_listen_connections, _ec);
              do_accept();
              stream_->next_layer().async_wait( // wait
                asio::ip::tcp::socket::wait_error,
                [this](const asio::error_code &ec) { rerun(); });
            });
        });
    });
}

void Acceptor::do_accept() {
  acceptor_.async_accept( // accept
    [this](const asio::error_code &ec, asio::ip::tcp::socket socket) {
      asio::error_code _ec;
      asio::ip::tcp::acceptor acceptor(io_context_);
      asio::ip::tcp::endpoint endpoint;
      if (ec) {
        if (ec != asio::error::operation_aborted) {
          LOGERR(ec, "ACCEPT");
          rerun();
        }
        return;
      }
      endpoint = cendpoint_;
      endpoint.port(0);
      acceptor.open(endpoint.protocol(), _ec);
      acceptor.bind(endpoint, _ec);
      endpoint = acceptor.local_endpoint(_ec);
      buf_[0] = endpoint.port() >> 8;
      buf_[1] = endpoint.port() & 0xff;
      std::make_shared<AcceptorSession>(io_context_, std::move(socket),
                                        std::move(acceptor))
        ->run();
      asio::async_write( // send
        *stream_, asio::buffer(buf_, 2),
        [this](const asio::error_code &ec, std::size_t length) {
          if (ec) {
            if (ec != asio::error::operation_aborted) {
              LOGERR(ec, "SEND");
              rerun();
            }
            return;
          }
          do_accept();
        });
    });
}

///////////////////////////////////////////////////////////////////////////////
//                                 Connector                                 //
///////////////////////////////////////////////////////////////////////////////

// Session ////////////////////////////////////////////////////////////////////

ConnectorSession::ConnectorSession(asio::io_context &context,
                                   asio::ip::tcp::endpoint &&aendpoint,
                                   asio::ip::tcp::endpoint &endpoint)
  : RAWProxy(context), aendpoint_(std::move(aendpoint)), endpoint_(endpoint) {}

void ConnectorSession::run() {
  asio::error_code ec;
  isocket_.open(aendpoint_.protocol(), ec);
  // isocket_ opts: NODELAY KEEPALIVE
  SET_NODELAY(isocket_);
  SET_KEEPALIVE(isocket_);
  do_connect();
}

void ConnectorSession::do_connect() {
  auto self(shared_from_this());
  isocket_.async_connect( // connect
    aendpoint_, [this, self](const asio::error_code &ec) {
      asio::error_code _ec;
      if (ec) {
        LOGERR(ec, "CONNECT");
        destroy();
        return;
      }
      // osocket_ opts: NODELAY KEEPALIVE FASTOPEN
      osocket_.open(endpoint_.protocol(), _ec);
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
    });
}

// Server /////////////////////////////////////////////////////////////////////

Connector::Connector(asio::io_context &io_context, asio::ssl::context &ssl_context,
                     asio::ip::tcp::endpoint &aendpoint,
                     asio::ip::tcp::endpoint &endpoint, std::string &username,
                     std::string &password)
  : io_context_(io_context), ssl_context_(ssl_context), timer_(io_context),
    aendpoint_(aendpoint), endpoint_(endpoint), username_(username), password_(password) {
}

void Connector::run() {
  in_rerun_ = false;
  stream_ = new asio::ssl::stream<asio::ip::tcp::socket>(io_context_, ssl_context_);
  do_acceptor_connect();
}

void Connector::rerun() {
  asio::error_code ec;

  if (in_rerun_)
    return;
  in_rerun_ = true;

  LOGINFO("RERUN TIMEWAIT");
  if (stream_->next_layer().is_open()) {
    stream_->next_layer().cancel(ec);
    SET_LINGER(stream_->next_layer());
    stream_->next_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    stream_->next_layer().close(ec);
  }
  timer_.cancel(ec);
  timer_.expires_after(std::chrono::seconds(TOMATO_CONNECTOR_RERUN_TIMEWAIT));
  timer_.async_wait( // wait
    [this](const asio::error_code &ec) {
      if (ec) {
        LOGERR(ec, "WAIT");
        return;
      }
      LOGINFO("RERUN");
      delete stream_;
      run();
    });
}

void Connector::do_acceptor_connect() {
  asio::error_code ec;
  // stream_ opts: LINGER NODELAY KEEPALIVE
  stream_->next_layer().open(aendpoint_.protocol(), ec);
  SET_LINGER(stream_->next_layer());
  SET_NODELAY(stream_->next_layer());
  SET_KEEPALIVE(stream_->next_layer());
  stream_->next_layer().async_connect( // connect
    aendpoint_, [this](const asio::error_code &ec) {
      if (ec) {
        if (ec != asio::error::operation_aborted) {
          LOGERR(ec, "CONNECT");
          rerun();
        }
        return;
      }
      LOGINFO("CONNECT ACCEPTOR", stream_->next_layer());
      stream_->async_handshake( // handshake
        asio::ssl::stream<asio::ip::tcp::socket>::client,
        [this](const asio::error_code &ec) {
          int ulen, plen;
          if (ec) {
            if (ec != asio::error::operation_aborted) {
              LOGERR(ec, "CONNECT");
              rerun();
            }
            return;
          }
          ulen = username_.length();
          plen = password_.length();
          buf_[0] = ulen;
          buf_[ulen + 1] = plen;
          memcpy(&buf_[1], username_.c_str(), ulen);
          memcpy(&buf_[ulen + 2], password_.c_str(), plen);
          asio::async_write( // send
            *stream_, asio::buffer(buf_, ulen + plen + 2),
            [this](const asio::error_code &ec, std::size_t length) {
              if (ec) {
                if (ec != asio::error::operation_aborted) {
                  LOGERR(ec, "SEND");
                  rerun();
                }
                return;
              }
              do_connect();
            });
        });
    });
}

void Connector::do_connect() {
  stream_->async_read_some( // recv
    asio::buffer(buf_), [this](const asio::error_code &ec, std::size_t length) {
      if (ec) {
        if (ec != asio::error::operation_aborted) {
          LOGERR(ec, "RECV");
          rerun();
        }
        return;
      }
      if (length != 2) {
        LOGERR("PARSE");
        rerun();
        return;
      }
      std::make_shared<ConnectorSession>(
        io_context_,
        asio::ip::tcp::endpoint(aendpoint_.address(), (buf_[0] << 8) + buf_[1]),
        endpoint_)
        ->run();
      do_connect();
    });
}

///////////////////////////////////////////////////////////////////////////////
//                                    CLI                                    //
///////////////////////////////////////////////////////////////////////////////

extern "C" void acceptor(const char *caddr, const char *cport, const char *addr,
                         const char *port, const char *username, const char *password,
                         const char *certfile, const char *keyfile,
                         const char *kpassword) {
  asio::io_context io_context;
  asio::ssl::context ssl_context(TLS_SERVER);
  asio::ip::tcp::resolver resolver(io_context);
  asio::ip::tcp::endpoint cendpoint, endpoint;

  std::string _certfile(certfile), _keyfile(keyfile),
    _kpassword(kpassword ? kpassword : "");
  std::string _username(username ? username : ""), _password(password ? password : "");

  cendpoint = *resolver.resolve(caddr, cport);
  endpoint = *resolver.resolve(addr, port);

  TLS::set_server(ssl_context, _certfile, _keyfile, _kpassword);

  Acceptor server(io_context, ssl_context, cendpoint, endpoint, _username, _password);
  server.run();
  io_context.run();
}

extern "C" void connector(const char *aaddr, const char *aport, const char *addr,
                          const char *port, const char *username, const char *password,
                          const char *hostname, const char *cafile) {
  asio::io_context io_context;
  asio::ssl::context ssl_context(TLS_CLIENT);
  asio::ip::tcp::resolver resolver(io_context);
  asio::ip::tcp::endpoint aendpoint, endpoint;

  std::string _hostname(hostname ? hostname : aaddr), _cafile(cafile ? cafile : "");
  std::string _username(username ? username : ""), _password(password ? password : "");

  aendpoint = *resolver.resolve(aaddr, aport);
  endpoint = *resolver.resolve(addr, port);

  TLS::set_client(ssl_context, _hostname, _cafile);

  Connector server(io_context, ssl_context, aendpoint, endpoint, _username, _password);
  server.run();
  io_context.run();
}
