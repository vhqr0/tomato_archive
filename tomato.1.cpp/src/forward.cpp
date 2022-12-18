#include "tomato.hpp"

///////////////////////////////////////////////////////////////////////////////
//                                  Forward                                  //
///////////////////////////////////////////////////////////////////////////////

// Session ////////////////////////////////////////////////////////////////////

ForwardSession::ForwardSession(asio::io_context &context, asio::ip::tcp::socket &&isocket,
                               asio::ip::tcp::endpoint &endpoint)
  : RAWProxy(context, std::move(isocket)), endpoint_(endpoint) {}

void ForwardSession::run() {
  asio::error_code ec;
  // isocket_ opts: NODELAY KEEPALIVE
  SET_NODELAY(isocket_);
  SET_KEEPALIVE(isocket_);
  do_connect();
}

void ForwardSession::do_connect() {
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

// Server /////////////////////////////////////////////////////////////////////

ForwardServer::ForwardServer(asio::io_context &context,
                             asio::ip::tcp::endpoint &lendpoint,
                             asio::ip::tcp::endpoint &rendpoint)
  : context_(context), acceptor_(context), lendpoint_(lendpoint), rendpoint_(rendpoint) {}

void ForwardServer::run() {
  // acceptor_ opts: REUSEADDR FASTOPEN
  acceptor_.open(lendpoint_.protocol());
  SET_REUSEADDR(acceptor_);
  SET_TFO(acceptor_);
  acceptor_.bind(lendpoint_);
  acceptor_.listen();
  LOGINFO("START", acceptor_);
  do_accept();
}

void ForwardServer::do_accept() {
  acceptor_.async_accept( // accept
    [this](const asio::error_code &ec, asio::ip::tcp::socket socket) {
      if (ec) {
        LOGERR(ec, "ACCEPT");
        return;
      }
      std::make_shared<ForwardSession>(context_, std::move(socket), rendpoint_)->run();
      do_accept();
    });
}

///////////////////////////////////////////////////////////////////////////////
//                                  TLS2RAW                                  //
///////////////////////////////////////////////////////////////////////////////

// Session ////////////////////////////////////////////////////////////////////

TLS2RAWSession::TLS2RAWSession(asio::io_context &context,
                               asio::ssl::stream<asio::ip::tcp::socket> &&stream,
                               asio::ip::tcp::endpoint &endpoint)
  : TLSProxy(context, std::move(stream)), endpoint_(endpoint) {}

void TLS2RAWSession::run() {
  asio::error_code ec;
  // stream_ opts: NODELAY KEEPALIVE
  SET_NODELAY(stream_.next_layer());
  SET_KEEPALIVE(stream_.next_layer());
  do_connect();
}

void TLS2RAWSession::do_connect() {
  auto self(shared_from_this());

  stream_.async_handshake( // handshake
    asio::ssl::stream<asio::ip::tcp::socket>::server,
    [this, self](const asio::error_code &ec) {
      asio::error_code _ec;
      if (ec) {
        LOGERR(ec, "TLS_HANDSHAKE");
        destroy();
        return;
      }
      // socket_ opts: NODELAY KEEPALIVE FASTOPEN
      socket_.open(endpoint_.protocol(), _ec);
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
    });
}

// Server /////////////////////////////////////////////////////////////////////

TLS2RAWServer::TLS2RAWServer(asio::io_context &io_context,
                             asio::ssl::context &ssl_context,
                             asio::ip::tcp::endpoint &lendpoint,
                             asio::ip::tcp::endpoint &rendpoint)
  : io_context_(io_context), ssl_context_(ssl_context), acceptor_(io_context),
    lendpoint_(lendpoint), rendpoint_(rendpoint) {}

void TLS2RAWServer::run() {
  // acceptor_ opts: REUSEADDR FASTOPEN
  acceptor_.open(lendpoint_.protocol());
  SET_REUSEADDR(acceptor_);
  SET_TFO(acceptor_);
  acceptor_.bind(lendpoint_);
  acceptor_.listen();
  LOGINFO("START", acceptor_);
  do_accept();
}

void TLS2RAWServer::do_accept() {
  acceptor_.async_accept( // accept
    [this](const asio::error_code &ec, asio::ip::tcp::socket socket) {
      if (ec) {
        LOGERR(ec, "ACCEPT");
        return;
      }
      std::make_shared<TLS2RAWSession>(
        io_context_,
        asio::ssl::stream<asio::ip::tcp::socket>(std::move(socket), ssl_context_),
        rendpoint_)
        ->run();
      do_accept();
    });
}

///////////////////////////////////////////////////////////////////////////////
//                                  RAW2TLS                                  //
///////////////////////////////////////////////////////////////////////////////

// Session ////////////////////////////////////////////////////////////////////

RAW2TLSSession::RAW2TLSSession(asio::io_context &io_context,
                               asio::ssl::context &ssl_context,
                               asio::ip::tcp::socket &&socket,
                               asio::ip::tcp::endpoint &endpoint)
  : TLSProxy(io_context, ssl_context, std::move(socket)), endpoint_(endpoint) {}

void RAW2TLSSession::run() {
  asio::error_code ec;
  // socket_ opts: NODELAY KEEPALIVE
  SET_NODELAY(socket_);
  SET_KEEPALIVE(socket_);
  do_connect();
}

void RAW2TLSSession::do_connect() {
  asio::error_code ec;
  auto self(shared_from_this());

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
          do_proxy();
        });
    });
}

// Server /////////////////////////////////////////////////////////////////////

RAW2TLSServer::RAW2TLSServer(asio::io_context &io_context,
                             asio::ssl::context &ssl_context,
                             asio::ip::tcp::endpoint &lendpoint,
                             asio::ip::tcp::endpoint &rendpoint)
  : io_context_(io_context), ssl_context_(ssl_context), acceptor_(io_context),
    lendpoint_(lendpoint), rendpoint_(rendpoint) {}

void RAW2TLSServer::run() {
  // acceptor_ opts: REUSEADDR FASTOPEN
  acceptor_.open(lendpoint_.protocol());
  SET_REUSEADDR(acceptor_);
  SET_TFO(acceptor_);
  acceptor_.bind(lendpoint_);
  acceptor_.listen();
  LOGINFO("START", acceptor_);
  do_accept();
}

void RAW2TLSServer::do_accept() {
  acceptor_.async_accept( // accept
    [this](const asio::error_code &ec, asio::ip::tcp::socket socket) {
      if (ec) {
        LOGERR(ec, "ACCEPT");
        return;
      }
      std::make_shared<RAW2TLSSession>(io_context_, ssl_context_, std::move(socket),
                                       rendpoint_)
        ->run();
      do_accept();
    });
}

///////////////////////////////////////////////////////////////////////////////
//                                    CLI                                    //
///////////////////////////////////////////////////////////////////////////////

extern "C" void forward(const char *laddr, const char *lport, const char *raddr,
                        const char *rport) {
  asio::io_context context;
  asio::ip::tcp::resolver resolver(context);
  asio::ip::tcp::endpoint lendpoint, rendpoint;

  lendpoint = *resolver.resolve(laddr, lport);
  rendpoint = *resolver.resolve(raddr, rport);

  ForwardServer server(context, lendpoint, rendpoint);
  server.run();
  context.run();
}

extern "C" void tls2raw(const char *laddr, const char *lport, const char *raddr,
                        const char *rport, const char *certfile, const char *keyfile,
                        const char *password) {
  asio::io_context io_context;
  asio::ssl::context ssl_context(TLS_SERVER);
  asio::ip::tcp::resolver resolver(io_context);
  asio::ip::tcp::endpoint lendpoint, rendpoint;

  std::string _certfile(certfile), _keyfile(keyfile), _password(password ? password : "");

  lendpoint = *resolver.resolve(laddr, lport);
  rendpoint = *resolver.resolve(raddr, rport);

  TLS::set_server(ssl_context, _certfile, _keyfile, _password);

  TLS2RAWServer server(io_context, ssl_context, lendpoint, rendpoint);
  server.run();
  io_context.run();
}

extern "C" void raw2tls(const char *laddr, const char *lport, const char *raddr,
                        const char *rport, const char *hostname, const char *cafile) {
  asio::io_context io_context;
  asio::ssl::context ssl_context(TLS_CLIENT);
  asio::ip::tcp::resolver resolver(io_context);
  asio::ip::tcp::endpoint lendpoint, rendpoint;

  std::string _hostname(hostname ? hostname : raddr), _cafile(cafile ? cafile : "");

  lendpoint = *resolver.resolve(laddr, lport);
  rendpoint = *resolver.resolve(raddr, rport);

  TLS::set_client(ssl_context, _hostname, _cafile);
  TLS::set_session_mode(ssl_context);

  RAW2TLSServer server(io_context, ssl_context, lendpoint, rendpoint);
  server.run();
  io_context.run();
}
