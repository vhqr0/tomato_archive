#ifndef TOMATO_H
#define TOMATO_H

#include <stdint.h>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <asio.hpp>
#include <asio/ssl.hpp>

#ifdef TOMATO_NOLOG
#define LOG_ERR(...)                                                                               \
  { ; }
#define LOG_MSG(...)                                                                               \
  { ; }
#else
#define LOG_ERR(...)                                                                               \
  { log('E', __VA_ARGS__); }
#define LOG_MSG(...)                                                                               \
  { log('M', __VA_ARGS__); }
#endif

#ifndef TOMATO_BUF_SIZE
#define TOMATO_BUF_SIZE 4096
#endif

class Config {
public:
  asio::io_context io_context;
  asio::ssl::context ssl_context;
  uint8_t password[16];
  asio::ip::tcp::endpoint local, remote;
  std::string server_index;
  std::vector<std::pair<asio::ip::tcp::endpoint, asio::ip::tcp::endpoint>> binds;
  std::vector<std::pair<asio::ip::udp::endpoint, asio::ip::udp::endpoint>> ubinds;

  Config();
  void setup_client();
  void setup_server();
  void resolve_binds();
  void resolve_ubinds();

private:
  static std::string env_string(const char *env, std::string dft);
  asio::ip::tcp::endpoint env_endpoint(const char *env, uint16_t port);
  std::pair<asio::ip::address, uint16_t> resolve(std::string host, uint16_t port, bool remotep);
  static std::vector<std::string> split_binds(std::string binds);
};

class Object {
public:
  Object(Config &config);
  Object(Object &object);

protected:
  Config &config;
  int id;

  void log(char level, std::string msg);
  void log(char level, std::string msg, asio::error_code ec);
  void log(char level, std::string msg, asio::ip::tcp::endpoint endpoint);
  void log(char level, std::string msg, asio::ip::udp::endpoint endpoint);
  void log(char level, std::string msg, asio::ip::tcp::endpoint local,
           asio::ip::tcp::endpoint remote);
  void log(char level, std::string msg, asio::ip::udp::endpoint local,
           asio::ip::udp::endpoint remote);
};

class ClientSession : public Object, public std::enable_shared_from_this<ClientSession> {
public:
  ClientSession(asio::ip::tcp::socket socket, Object &object);
  ~ClientSession();
  void start();

private:
  std::array<uint8_t, TOMATO_BUF_SIZE> in_buf_, out_buf_;
  asio::ip::tcp::socket socket_;
  asio::ssl::stream<asio::ip::tcp::socket> stream_;
  std::size_t length_;
  bool connectp_;

  void do_handshake();
  void do_http_handshake();
  void do_proxy_in();
  void do_proxy_out();
};

class Client : public Object {
public:
  Client(Config &config);

private:
  asio::ip::tcp::acceptor acceptor_;

  void do_accept();
};

class ServerSession : public Object, public std::enable_shared_from_this<ServerSession> {
public:
  ServerSession(asio::ip::tcp::socket socket, Object &object);
  ~ServerSession();
  void start();

private:
  std::array<uint8_t, TOMATO_BUF_SIZE> in_buf_, out_buf_;
  asio::ip::tcp::socket socket_;
  asio::ip::udp::socket usocket_;
  asio::ip::tcp::acceptor acceptor_;
  asio::ssl::stream<asio::ip::tcp::socket> stream_;
  asio::ip::tcp::endpoint endpoint_;
  asio::ip::udp::endpoint uendpoint_;
  asio::ip::tcp::resolver resolver_;
  asio::ip::udp::resolver uresolver_;
  std::string host_, port_;

  void do_handshake();
  void do_resolve();
  void do_execute();
  void do_proxy_in();
  void do_proxy_out();
  void do_udp_proxy_in();
  void do_udp_proxy_out();
  int make_response(asio::ip::address address, uint16_t port);
  int make_response(asio::ip::tcp::endpoint endpoint);
  int make_response(asio::ip::udp::endpoint endpoint);
};

class Server : public Object {
public:
  Server(Config &config);

private:
  asio::ip::tcp::acceptor acceptor_;

  void do_accept();
};

class BindSession : public Object, public std::enable_shared_from_this<BindSession> {
public:
  BindSession(asio::ip::tcp::endpoint &local, asio::ip::tcp::endpoint &remote, Object &object);
  ~BindSession();
  void start();

private:
  std::array<uint8_t, TOMATO_BUF_SIZE> in_buf_, out_buf_;
  asio::ip::tcp::socket socket_;
  asio::ssl::stream<asio::ip::tcp::socket> stream_;
  std::size_t length_;
  asio::ip::tcp::endpoint &local_, &remote_;

  void do_proxy_in();
  void do_proxy_out();
};

class Bind : public Object {
public:
  Bind(Config &config);
};

class UBindSession : public Object, public std::enable_shared_from_this<UBindSession> {
public:
  UBindSession(asio::ip::udp::endpoint &local, asio::ip::udp::endpoint &remote, Object &object);
  ~UBindSession();
  void start();

private:
  std::array<uint8_t, TOMATO_BUF_SIZE> in_buf_, out_buf_;
  asio::ip::udp::socket socket_;
  asio::ssl::stream<asio::ip::tcp::socket> stream_;
  std::size_t length_;
  asio::ip::udp::endpoint endpoint_, &local_, &remote_;

  void do_proxy_in();
  void do_proxy_out();
};

class UBind : public Object {
public:
  UBind(Config &config);
};

#endif
