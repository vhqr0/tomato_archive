#ifndef TOMATO_H
#define TOMATO_H

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include <asio.hpp>
#include <asio/ssl.hpp>

#ifdef TOMATO_NOLOG
#define LOG_ERR(...) ;
#define LOG_MSG(...) ;
#else
#define LOG_ERR(...) log(2, __VA_ARGS__);
#define LOG_MSG(...) log(1, __VA_ARGS__);
#endif

class Config {
public:
  asio::io_context io_context;
  int log_level, buf_size;
  uint8_t password[16];
  asio::ssl::context client_ssl_context, server_ssl_context;
  asio::ip::tcp::endpoint client_local, client_remote, server_local;
  std::string server_index;
  std::vector<asio::ip::tcp::endpoint> binds;
  std::vector<asio::ip::udp::endpoint> ubinds;

  Config();

private:
  static int parse_int(const char *env, int dft);
  static std::string parse_str(const char *env, std::string dft);
  static asio::ip::tcp::endpoint parse_endpoint(const char *env, std::string port);
  static asio::ip::udp::endpoint parse_uendpoint(const char *env, std::string port);

  void parse_binds();
  void parse_ubinds();
};

class Object {
public:
  Object(Config &config);
  Object(Object &object);

protected:
  Config &config;
  int id;

  void log(int level, std::string msg);
  void log(int level, std::string msg, asio::error_code ec);
  void log(int level, std::string msg, asio::ip::tcp::endpoint endpoint);
  void log(int level, std::string msg, asio::ip::udp::endpoint endpoint);
  void log(int level, std::string msg, asio::ip::tcp::endpoint local,
           asio::ip::tcp::endpoint remote);
  void log(int level, std::string msg, asio::ip::udp::endpoint local,
           asio::ip::udp::endpoint remote);
};

class ClientSession : public Object, public std::enable_shared_from_this<ClientSession> {
public:
  ClientSession(asio::ip::tcp::socket socket, Object &object);
  ~ClientSession();
  void start();

private:
  asio::ip::tcp::socket socket_;
  asio::ssl::stream<asio::ip::tcp::socket> stream_;
  std::vector<uint8_t> in_buf_, out_buf_;
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
  asio::ip::tcp::socket socket_;
  asio::ip::udp::socket usocket_;
  asio::ip::tcp::acceptor acceptor_;
  asio::ssl::stream<asio::ip::tcp::socket> stream_;
  std::vector<uint8_t> in_buf_, out_buf_;
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
  asio::ip::tcp::socket socket_;
  asio::ssl::stream<asio::ip::tcp::socket> stream_;
  std::vector<uint8_t> in_buf_, out_buf_;
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
  asio::ip::udp::socket socket_;
  asio::ssl::stream<asio::ip::tcp::socket> stream_;
  std::vector<uint8_t> in_buf_, out_buf_;
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
