#include "tomato.hpp"

co_async<void> socks5_session(Socket isocket, int id) {
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
    rule = co_await rules_match(req, true, *isocket, id);
  } catch (const std::exception &e) {
    logerr(id, "match rules exception", e.what());
    socket_close(*isocket);
    co_return;
  }
  
  if (rule == RULE_BLOCK) {
    socket_close(*isocket);
    co_return;
  }

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
}

co_async<void> socks5_server(asio::io_context &context, const tcp::endpoint &endpoint) {
  int id = 0;
  tcp::acceptor acceptor(context);
  acceptor.open(endpoint.protocol());
  acceptor.set_option(tcp::acceptor::reuse_address(true));
  acceptor.bind(endpoint);
  acceptor.listen();

  std::cout << "server listen at " << endpoint << std::endl;

  for (;;) {
    Socket isocket(new tcp::socket(context));
    co_await acceptor.async_accept(*isocket, asio::use_awaitable);
    isocket->set_option(tcp::no_delay(true));
    isocket->set_option(asio::socket_base::keep_alive(true));
    asio::co_spawn(context, socks5_session(isocket, id++), asio::detached);
  }
}

void socks5_main(const std::string &hostname, const std::string &servicename) {
  asio::io_context context(1);
  tcp::resolver resolver(context);
  tcp::endpoint endpoint;

  endpoint = *resolver.resolve(hostname, servicename);
  asio::co_spawn(context, socks5_server(context, endpoint), asio::detached);
  context.run();
}
