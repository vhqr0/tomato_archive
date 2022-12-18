#include "tomato.hpp"

co_async<void> trojanc_session(Socket isocket, const tcp::endpoint &server_endpoint,
                               ssl::context &tls_context, const std::string &password, int id) {
  int rule;
  socks5_req req;
  std::string rest;

  try {
    co_await socks5_or_http_accept(isocket, req, rest);
  } catch (const std::exception &e) {
    logerr(id, "handshake exception", e.what());
    socket_close(*isocket);
    co_return;
  }

  try {
    rule = co_await rules_match(req, false, *isocket, id);
  } catch (const std::exception &e) {
    logerr(id, "match rules exception", e.what());
    socket_close(*isocket);
    co_return;
  }

  switch (rule) {
  case RULE_BLOCK:
    socket_close(*isocket);
    co_return;
    break;
  case RULE_PROXY: {
    TLSocket osocket(new ssl::stream<tcp::socket>(isocket->get_executor(), tls_context));
    try {
      co_await trojan_connect(osocket, server_endpoint, password, req, rest);
    } catch (const std::exception &e) {
      logerr(id, "connect exception", e.what());
      socket_close(*isocket);
      socket_close(osocket->next_layer());
      co_return;
    }
    asio::co_spawn(isocket->get_executor(), proxy_raw2tls(isocket, osocket, id), asio::detached);
    asio::co_spawn(isocket->get_executor(), proxy_tls2raw(osocket, isocket, id), asio::detached);
  } break;
  case RULE_DIRECT: {
    Socket osocket(new tcp::socket(isocket->get_executor()));
    try {
      co_await socks5_connect(osocket, req, rest);
    } catch (const std::exception &e) {
      logerr(id, "connect exception", e.what());
      socket_close(*isocket);
      socket_close(*osocket);
      co_return;
    }
    asio::co_spawn(isocket->get_executor(), proxy_raw2raw(isocket, osocket, id), asio::detached);
    asio::co_spawn(isocket->get_executor(), proxy_raw2raw(osocket, isocket, id), asio::detached);
  } break;
  }
}

co_async<void> trojanc_server(asio::io_context &context, const tcp::endpoint &endpoint,
                              const tcp::endpoint &server_endpoint, ssl::context &tls_context,
                              const std::string &password) {
  int id = 0;
  tcp::acceptor acceptor(context);
  acceptor.open(endpoint.protocol());
  acceptor.set_option(tcp::acceptor::reuse_address(true));
  acceptor.bind(endpoint);
  acceptor.listen();

  std::cout << "server listen at " << endpoint << " => " << server_endpoint << std::endl;

  for (;;) {
    Socket isocket(new tcp::socket(context));
    co_await acceptor.async_accept(*isocket, asio::use_awaitable);
    isocket->set_option(tcp::no_delay(true));
    isocket->set_option(asio::socket_base::keep_alive(true));
    asio::co_spawn(context, trojanc_session(isocket, server_endpoint, tls_context, password, id++),
                   asio::detached);
  }
}

void trojanc_main(const std::string &hostname, const std::string &servicename,
                  const std::string &server_hostname, const std::string &server_servicename,
                  const std::string &password, const std::string &tls_hostname,
                  const std::string &tls_cafile) {
  asio::io_context context(1);
  tcp::resolver resolver(context);
  tcp::endpoint endpoint, server_endpoint;
  ssl::context tls_context(ssl::context::tlsv13_client);
  std::string _password;

  endpoint = *resolver.resolve(hostname, servicename);
  server_endpoint = *resolver.resolve(server_hostname, server_servicename);

  tls_context.set_options(ssl::context::default_workarounds);
  if (tls_cafile.empty())
    tls_context.set_default_verify_paths();
  else
    tls_context.load_verify_file(tls_cafile);
  tls_context.set_verify_mode(ssl::verify_peer);
  tls_context.set_verify_callback(ssl::host_name_verification(tls_hostname));

  tls_set_session_mode(tls_context);

  _password = trojan_password(password);

  asio::co_spawn(context,
                 trojanc_server(context, endpoint, server_endpoint, tls_context, _password),
                 asio::detached);
  context.run();
}
