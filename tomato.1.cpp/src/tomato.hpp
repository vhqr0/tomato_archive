#ifndef TOMATO_H
#define TOMATO_H

#include "tomato-cfg.h"
#include "tomato-cli.h"

#include <array>
#include <list>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <asio.hpp>
#include <asio/ssl.hpp>

#include <maxminddb.h>

///////////////////////////////////////////////////////////////////////////////
//                                    Util                                   //
///////////////////////////////////////////////////////////////////////////////

// LOG ////////////////////////////////////////////////////////////////////////

#ifndef TOMATO_DEBUG
#define LOGERR(...) ;
#define LOGINFO(...) ;
#define LOGTRACE(...) ;
#else
#define LOGERR(...) Log::err(__VA_ARGS__);
#define LOGINFO(...) Log::info(__VA_ARGS__);
#define LOGTRACE(...) Log::trace(__VA_ARGS__);
#endif

class Socks5Parser;

class Log {
public:
  // err: system call error (with error code) or soft error
  static void err(std::string reason);
  static void err(const asio::error_code &ec, std::string reason);
  // info: information, may with associated socket (remote endpoint)
  static void info(std::string msg);
  static void info(std::string msg, asio::ip::tcp::socket &socket);
  static void info(std::string msg, asio::ip::tcp::acceptor &acceptor);
  // trace: action (such as: proxy, socks5 connection request) between two endpoint:
  // a socket with {another socket, endpoint, domain:port, Socks5Parser}
  static void trace(asio::ip::tcp::socket &isocket, asio::ip::tcp::socket &osocket,
                    std::string reason);
  static void trace(asio::ip::tcp::socket &socket, asio::ip::tcp::endpoint &endpoint,
                    std::string reason);
  static void trace(asio::ip::tcp::socket &socket, std::string domain,
                    unsigned short port, std::string reason);
  static void trace(asio::ip::tcp::socket &socket, Socks5Parser &parser,
                    std::string reason);
};

// Sockopts ///////////////////////////////////////////////////////////////////

#define SET_LINGER(SOCKET) Sockopts::set_linger(SOCKET, true, 0);
#define SET_NODELAY(SOCKET) Sockopts::set_nodelay(SOCKET, true);
#define SET_KEEPALIVE(SOCKET) Sockopts::set_keepalive(SOCKET, true);
#define SET_REUSEADDR(ACCEPTOR) Sockopts::set_reuseaddr(ACCEPTOR, true);

#ifndef TOMATO_NO_TFO
#ifndef TOMATO_TFO_QLEN
#define TOMATO_TFO_QLEN 5
#endif
#define SET_TFO(ACCEPTOR) Sockopts::set_tfo(ACCEPTOR, TOMATO_TFO_QLEN);
#define SET_TFO_CONNECT(SOCKET) Sockopts::set_tfo_connect(SOCKET, true);
#else
#define SET_TFO(ACCEPTOR) ;
#define SET_TFO_CONNECT(SOCKET) ;
#endif

class Sockopts {
public:
  static void set_linger(asio::ip::tcp::socket &socket, bool active, int linger);
  static void set_nodelay(asio::ip::tcp::socket &socket, bool active);
  static void set_keepalive(asio::ip::tcp::socket &socket, bool active);
  static void set_reuseaddr(asio::ip::tcp::acceptor &acceptor, bool active);
  static void set_tfo(asio::ip::tcp::acceptor &acceptor, int qlen);
  static void set_tfo_connect(asio::ip::tcp::socket &socket, bool active);
};

// TLS ////////////////////////////////////////////////////////////////////////

#ifndef TOMATO_TLS_ALLOW_DOWNGRADE
#define TLS_CLIENT asio::ssl::context::tlsv13_client
#define TLS_SERVER asio::ssl::context::tlsv13_server
#else
#define TLS_CLIENT asio::ssl::context::tls_client
#define TLS_SERVER asio::ssl::context::tls_server
#endif

class TLS {
public:
  static void set_server(asio::ssl::context &context, std::string &certfile,
                         std::string &keyfile, std::string &password);
  static void set_client(asio::ssl::context &context, std::string &hostname,
                         std::string &cafile);
  static void set_session_mode(asio::ssl::context &context);
  static void set_session(asio::ssl::stream<asio::ip::tcp::socket> &stream);

private:
  static std::list<SSL_SESSION *> sessions;

  static int new_session_cb(SSL *ssl, SSL_SESSION *session);
  static void remove_session_cb(SSL_CTX *context, SSL_SESSION *session);
};

///////////////////////////////////////////////////////////////////////////////
//                                   Proxy                                   //
///////////////////////////////////////////////////////////////////////////////

#ifndef TOMATO_BUFSIZE
#define TOMATO_BUFSIZE 4096
#endif

// RAWProxy ///////////////////////////////////////////////////////////////////

class RAWProxy : public std::enable_shared_from_this<RAWProxy> {
public:
  RAWProxy(asio::io_context &context);
  RAWProxy(asio::io_context &context, asio::ip::tcp::socket &&isocket);
  RAWProxy(asio::ip::tcp::socket &&isocket, asio::ip::tcp::socket &&osocket);
  void do_proxy();

protected:
  std::size_t ulen_, dlen_;
  std::array<unsigned char, TOMATO_BUFSIZE> ubuf_, dbuf_;
  asio::ip::tcp::socket isocket_, osocket_;

  virtual void destroy();

  void do_upstream();
  void do_downstream();
};

// TLSProxy ///////////////////////////////////////////////////////////////////

class TLSProxy : public std::enable_shared_from_this<TLSProxy> {
public:
  TLSProxy(asio::io_context &io_context, asio::ssl::context &ssl_context);
  TLSProxy(asio::io_context &io_context, asio::ssl::context &ssl_context,
           asio::ip::tcp::socket &&socket);
  TLSProxy(asio::io_context &io_context,
           asio::ssl::stream<asio::ip::tcp::socket> &&stream);
  TLSProxy(asio::ip::tcp::socket &&socket,
           asio::ssl::stream<asio::ip::tcp::socket> &&stream);
  void do_proxy();

protected:
  std::size_t ulen_, dlen_;
  std::array<unsigned char, TOMATO_BUFSIZE> ubuf_, dbuf_;
  asio::ip::tcp::socket socket_;
  asio::ssl::stream<asio::ip::tcp::socket> stream_;

  virtual void destroy();

  void do_upstream();
  void do_downstream();
};

///////////////////////////////////////////////////////////////////////////////
//                                  Forward                                  //
///////////////////////////////////////////////////////////////////////////////

// Forward ////////////////////////////////////////////////////////////////////

class ForwardSession : public RAWProxy {
public:
  ForwardSession(asio::io_context &context, asio::ip::tcp::socket &&isocket,
                 asio::ip::tcp::endpoint &endpoint);
  void run();

private:
  asio::ip::tcp::endpoint &endpoint_;

  void do_connect();
};

class ForwardServer {
public:
  ForwardServer(asio::io_context &context, asio::ip::tcp::endpoint &lendpoint,
                asio::ip::tcp::endpoint &rendpoint);
  void run();

private:
  asio::io_context &context_;
  asio::ip::tcp::acceptor acceptor_;
  asio::ip::tcp::endpoint &lendpoint_, &rendpoint_;

  void do_accept();
};

// TLS2RAW ////////////////////////////////////////////////////////////////////

class TLS2RAWSession : public TLSProxy {
public:
  TLS2RAWSession(asio::io_context &context,
                 asio::ssl::stream<asio::ip::tcp::socket> &&stream,
                 asio::ip::tcp::endpoint &endpoint);
  void run();

private:
  asio::ip::tcp::endpoint &endpoint_;

  void do_connect();
};

class TLS2RAWServer {
public:
  TLS2RAWServer(asio::io_context &io_context, asio::ssl::context &ssl_context,
                asio::ip::tcp::endpoint &lendpoint, asio::ip::tcp::endpoint &rendpoint);
  void run();

private:
  asio::io_context &io_context_;
  asio::ssl::context &ssl_context_;
  asio::ip::tcp::acceptor acceptor_;
  asio::ip::tcp::endpoint &lendpoint_, &rendpoint_;

  void do_accept();
};

// RAW2TLS ////////////////////////////////////////////////////////////////////

class RAW2TLSSession : public TLSProxy {
public:
  RAW2TLSSession(asio::io_context &io_context, asio::ssl::context &ssl_context,
                 asio::ip::tcp::socket &&socket, asio::ip::tcp::endpoint &endpoint);
  void run();

private:
  asio::ip::tcp::endpoint &endpoint_;

  void do_connect();
};

class RAW2TLSServer {
public:
  RAW2TLSServer(asio::io_context &io_context, asio::ssl::context &ssl_context,
                asio::ip::tcp::endpoint &lendpoint, asio::ip::tcp::endpoint &rendpoint);
  void run();

private:
  asio::io_context &io_context_;
  asio::ssl::context &ssl_context_;
  asio::ip::tcp::acceptor acceptor_;
  asio::ip::tcp::endpoint &lendpoint_, &rendpoint_;

  void do_accept();
};

///////////////////////////////////////////////////////////////////////////////
//                                   Socks5                                  //
///////////////////////////////////////////////////////////////////////////////

#define AUTH_NOAUTH 0
#define AUTH_GSSAPI 1
#define AUTH_PASSWORD 2
#define AUTH_NOACCEPT 0xff

#define ATYPE_IPV4 1
#define ATYPE_IPV6 4
#define ATYPE_DOMAIN 3

// Parser /////////////////////////////////////////////////////////////////////

class Socks5Parser {
public:
  int authmeth_, atype_;
  std::string &username_, &password_;
  unsigned short port_;
  union {
    asio::ip::address_v4::bytes_type v4;
    asio::ip::address_v6::bytes_type v6;
    unsigned char domain[256];
  } addr_;

  Socks5Parser(std::string &username, std::string &password);
  bool do_parse(unsigned char *buf, std::size_t length);
};

// Socks5 /////////////////////////////////////////////////////////////////////

class Socks5Session : public RAWProxy {
public:
  Socks5Session(asio::io_context &context, asio::ip::tcp::socket &&isocket,
                std::string &username, std::string &password, bool strict);

  void run();

private:
  asio::ip::tcp::resolver resolver_;
  asio::ip::tcp::endpoint endpoint_;
  Socks5Parser parser_;
  bool strict_;

  void do_read_req();
  void do_parse_req();
  void do_connect();

  void do_read_stdauth();
  void do_read_stdreq();
};

class Socks5Server {
public:
  Socks5Server(asio::io_context &context, asio::ip::tcp::endpoint &endpoint,
               std::string &username, std::string &password, bool strict);
  void run();

private:
  asio::io_context &context_;
  asio::ip::tcp::acceptor acceptor_;
  asio::ip::tcp::endpoint &endpoint_;
  std::string &username_, &password_;
  bool strict_;

  void do_accept();
};

// Socks5S ////////////////////////////////////////////////////////////////////

class Socks5SSession : public TLSProxy {
public:
  Socks5SSession(asio::io_context &context,
                 asio::ssl::stream<asio::ip::tcp::socket> &&stream, std::string &username,
                 std::string &password, bool strict);

  void run();

private:
  asio::ip::tcp::resolver resolver_;
  asio::ip::tcp::endpoint endpoint_;
  Socks5Parser parser_;
  bool strict_;

  void do_read_req();
  void do_parse_req();
  void do_connect();

  void do_read_stdauth();
  void do_read_stdreq();
};

class Socks5SServer {
public:
  Socks5SServer(asio::io_context &io_context, asio::ssl::context &ssl_context,
                asio::ip::tcp::endpoint &endpoint, std::string &username,
                std::string &password, bool strict);
  void run();

private:
  asio::io_context &io_context_;
  asio::ssl::context &ssl_context_;
  asio::ip::tcp::acceptor acceptor_;
  asio::ip::tcp::endpoint &endpoint_;
  std::string &username_, &password_;
  bool strict_;

  void do_accept();
};

///////////////////////////////////////////////////////////////////////////////
//                                  Socks5F                                  //
///////////////////////////////////////////////////////////////////////////////

// ProxyRules /////////////////////////////////////////////////////////////////

#define RULE_BLOCK 1
#define RULE_PROXY 2
#define RULE_DIRECT 3

class IPRule {
public:
  IPRule(int rule);
  bool open(std::string &file);
  void close();
  int match(struct sockaddr *addr);

private:
  int rule_;
  MMDB_s mmdb_;
};

class ProxyRules {
public:
  static int default_rule;
  static std::vector<IPRule *> ip_rules;
  static std::unordered_map<std::string, int> domain_rules;

  static void set_default_rule(int rule);
  static void add_ip_rule(std::string &mmdb, int rule);
  static void add_domain_rule(std::string &domain, int rule);
  static int match_ip_rules(asio::ip::tcp::endpoint &endpoint);
  static int match_domain_rules(std::string &domain);
  static void clear_rules();
};

// Socks5F ////////////////////////////////////////////////////////////////////

class Socks5FSession : public TLSProxy {
public:
  Socks5FSession(asio::io_context &io_context, asio::ssl::context &ssl_context,
                 asio::ip::tcp::socket &&socket, asio::ip::tcp::endpoint &endpoint,
                 std::string &lusername, std::string &lpassword, std::string &rusername,
                 std::string &rpassword);
  void run();

private:
  bool resolved_;
  asio::ip::tcp::resolver resolver_;
  asio::ip::tcp::endpoint &endpoint_, dendpoint_;
  Socks5Parser parser_;
  std::string &rusername_, &rpassword_;

  void do_read_req();
  void do_parse_req();
  void do_direct();
  void do_connect();

  void do_match_default_rules();
  void do_match_ip_rules();
  void do_match_domain_rules();

  void do_read_stdauth();
  void do_read_stdreq();
};

class Socks5FServer {
public:
  Socks5FServer(asio::io_context &io_context, asio::ssl::context &ssl_context,
                asio::ip::tcp::endpoint &lendpoint, asio::ip::tcp::endpoint &rendpoint,
                std::string &lusername, std::string &lpassword, std::string &rusername,
                std::string &rpassword);
  void run();

private:
  asio::io_context &io_context_;
  asio::ssl::context &ssl_context_;
  asio::ip::tcp::acceptor acceptor_;
  asio::ip::tcp::endpoint &lendpoint_, &rendpoint_;
  std::string &lusername_, &lpassword_, &rusername_, &rpassword_;

  void do_accept();
};

///////////////////////////////////////////////////////////////////////////////
//                                  Reverse                                  //
///////////////////////////////////////////////////////////////////////////////

#ifndef TOMATO_ACCEPTOR_TIMEWAIT
#define TOMATO_ACCEPTOR_TIMEWAIT 5
#endif

#ifndef TOMATO_ACCEPTOR_RERUN_TIMEWAIT
#define TOMATO_ACCEPTOR_RERUN_TIMEWAIT 5
#endif

#ifndef TOMATO_CONNECTOR_RERUN_TIMEWAIT
#define TOMATO_CONNECTOR_RERUN_TIMEWAIT 15
#endif

// Acceptor ///////////////////////////////////////////////////////////////////

class AcceptorSession : public RAWProxy {
public:
  AcceptorSession(asio::io_context &context, asio::ip::tcp::socket &&isocket,
                  asio::ip::tcp::acceptor &&acceptor);
  void run();

private:
  asio::ip::tcp::acceptor acceptor_;
  asio::steady_timer timer_;

  void do_accept();

  virtual void destroy() override;
};

class Acceptor {
public:
  Acceptor(asio::io_context &io_context, asio::ssl::context &ssl_context,
           asio::ip::tcp::endpoint &cendpoint, asio::ip::tcp::endpoint &endpoint,
           std::string &username, std::string &password);
  void run();

private:
  bool in_rerun_;
  std::array<unsigned char, TOMATO_BUFSIZE> buf_;
  asio::io_context &io_context_;
  asio::ssl::context &ssl_context_;
  // rerun need to new a new stream_
  // new version of asio have a move assignment for ssl::stream may fix it
  asio::ssl::stream<asio::ip::tcp::socket> *stream_;
  asio::ip::tcp::acceptor acceptor_;
  asio::steady_timer timer_;
  asio::ip::tcp::endpoint &cendpoint_, &endpoint_;
  std::string &username_, &password_;

  void rerun();

  void do_connector_accept();
  void do_accept();
};

// Connector //////////////////////////////////////////////////////////////////

class ConnectorSession : public RAWProxy {
public:
  ConnectorSession(asio::io_context &context, asio::ip::tcp::endpoint &&aendpoint,
                   asio::ip::tcp::endpoint &endpoint);
  void run();

private:
  asio::ip::tcp::endpoint aendpoint_, &endpoint_;

  void do_connect();
};

class Connector {
public:
  Connector(asio::io_context &io_context, asio::ssl::context &ssl_context,
            asio::ip::tcp::endpoint &aendpoint, asio::ip::tcp::endpoint &endpoint,
            std::string &username, std::string &password);
  void run();

private:
  bool in_rerun_;
  std::array<unsigned char, TOMATO_BUFSIZE> buf_;
  asio::io_context &io_context_;
  asio::ssl::context &ssl_context_;
  // rerun need to new a new stream_
  // new version of asio have a move assignment for ssl::stream may fix it
  asio::ssl::stream<asio::ip::tcp::socket> *stream_;
  asio::steady_timer timer_;
  asio::ip::tcp::endpoint &aendpoint_, &endpoint_;
  std::string &username_, &password_;

  void rerun();

  void do_acceptor_connect();
  void do_connect();
};

#endif /* TOMATO_H */
