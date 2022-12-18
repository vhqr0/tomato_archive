#include "tomato.hpp"

co_async<void> trojans_session(TLSocket isocket, const std::string &password, int id) {
  int rule;
  socks5_req req;
  std::string rest;

  try {
    co_await trojan_accept(isocket, password, req, rest);
  } catch (const std::exception &e) {
    logerr(id, "handshake exception", e.what());
    socket_close(isocket->next_layer());
    co_return;
  }

  try {
    rule = co_await rules_match(req, true, isocket->next_layer(), id);
  } catch (const std::exception &e) {
    logerr(id, "match rules exception", e.what());
    socket_close(isocket->next_layer());
    co_return;
  }

  if (rule == RULE_BLOCK) {
    socket_close(isocket->next_layer());
    co_return;
  }

  Socket osocket(new tcp::socket(isocket->get_executor()));

  try {
    co_await socks5_connect(osocket, req, rest);
  } catch (const std::exception &e) {
    logerr(id, "connect exception", e.what());
    socket_close(isocket->next_layer());
    socket_close(*osocket);
    co_return;
  }

  asio::co_spawn(isocket->get_executor(), proxy_tls2raw(isocket, osocket, id), asio::detached);
  asio::co_spawn(isocket->get_executor(), proxy_raw2tls(osocket, isocket, id), asio::detached);
}

co_async<void> trojans_server(asio::io_context &context, const tcp::endpoint &endpoint,
                              ssl::context &tls_context, const std::string &password) {
  int id = 0;
  tcp::acceptor acceptor(context);
  acceptor.open(endpoint.protocol());
  acceptor.set_option(tcp::acceptor::reuse_address(true));
  acceptor.bind(endpoint);
  acceptor.listen();

  std::cout << "server listen at " << endpoint << std::endl;

  for (;;) {
    TLSocket isocket(new ssl::stream<tcp::socket>(context, tls_context));
    co_await acceptor.async_accept(isocket->next_layer(), asio::use_awaitable);
    isocket->next_layer().set_option(tcp::no_delay(true));
    isocket->next_layer().set_option(asio::socket_base::keep_alive(true));
    asio::co_spawn(context, trojans_session(isocket, password, id++), asio::detached);
  }
}

void trojans_main(const std::string &hostname, const std::string &servicename,
                  const std::string &password, const std::string &tls_certfile,
                  const std::string &tls_keyfile, const std::string &tls_keypassword) {
  asio::io_context context(1);
  tcp::resolver resolver(context);
  tcp::endpoint endpoint;
  ssl::context tls_context(ssl::context::tlsv13_server);
  std::string _password;

  endpoint = *resolver.resolve(hostname, servicename);

  tls_context.set_options(ssl::context::default_workarounds);
  tls_context.use_certificate_chain_file(tls_certfile);
  tls_context.use_private_key_file(tls_keyfile, ssl::context::pem);
  if (!password.empty())
    tls_context.set_password_callback(
      [tls_keypassword](std::size_t length, ssl::context::password_purpose purpose) {
        return tls_keypassword;
      });

  _password = trojan_password(password);

  asio::co_spawn(context, trojans_server(context, endpoint, tls_context, _password),
                 asio::detached);
  context.run();
}
