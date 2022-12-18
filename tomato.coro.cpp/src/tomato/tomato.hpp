#ifndef TOMATO_H
#define TOMATO_H

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0a00
#endif
#endif
#include <asio.hpp>
#include <asio/ssl.hpp>

#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <maxminddb.h>
#include <sqlite3.h>

#include <assert.h>
#include <getopt.h>
#include <unistd.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2ipdef.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <list>
#include <memory>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#ifndef TOMATO_BUFSIZE
#define TOMATO_BUFSIZE 4096
#endif

using TOMATO_BUF = std::array<unsigned char, TOMATO_BUFSIZE>;

#define co_async asio::awaitable
namespace ssl = asio::ssl;
using asio::ip::tcp;
using Socket = std::shared_ptr<tcp::socket>;
using TLSocket = std::shared_ptr<ssl::stream<tcp::socket>>;

void loginfo(int id, const tcp::endpoint &from_endpoint, const tcp::endpoint &to_endpoint,
             int rule);
void loginfo(int id, const tcp::endpoint &from_endpoint,
             const std::pair<std::string, unsigned short> &to_domain, int rule);
void loginfo(int id, const tcp::endpoint &from_endpoint, const tcp::endpoint to_endpoint,
             const std::pair<std::string, unsigned short> &to_domain, int rule);
void logerr(int id, std::string reasion, const std::string &what);

void socket_close(tcp::socket &socket);
co_async<void> proxy_raw2raw(Socket reader, Socket writer, int id);
co_async<void> proxy_raw2tls(Socket reader, TLSocket writer, int id);
co_async<void> proxy_tls2raw(TLSocket reader, Socket writer, int id);

#define ATYPE_IPV4 1
#define ATYPE_IPV6 4
#define ATYPE_DOMAIN 3

enum class ATYPE {
  v4 = ATYPE_IPV4,
  v6 = ATYPE_IPV6,
  domain = ATYPE_DOMAIN,
};

struct socks5_req {
  ATYPE atype;
  tcp::endpoint endpoint;
  std::pair<std::string, unsigned short> domain;
};

std::string trojan_password(const std::string &password);

co_async<void> socks5_or_http_accept(Socket socket, socks5_req &req, std::string &rest);
co_async<void> trojan_accept(TLSocket socket, const std::string &password, socks5_req &req,
                             std::string &rest);
co_async<void> socks5_connect(Socket socket, socks5_req &req, const std::string &rest);
co_async<void> trojan_connect(TLSocket socket, const tcp::endpoint &endpoint,
                              const std::string &password, socks5_req &req, const std::string &rest);

void tls_set_session_mode(ssl::context &tls_context);
void tls_set_session(TLSocket socket);

#define RULE_BLOCK 1
#define RULE_PROXY 2
#define RULE_DIRECT 3

void domain_rules_set_default_rule(int rule);
void domain_rules_set_db(const char *dbfile);
void ip_rules_set_default_rule(int rule);
void ip_rules_add_db(const char *dbfile, int rule);
co_async<int> rules_match(socks5_req &req, bool local_proxy, tcp::socket &socket, int id);

void socks5_main(const std::string &hostname, const std::string &servicename);
void trojanc_main(const std::string &hostname, const std::string &servicename,
                  const std::string &server_hostname, const std::string &server_servicename,
                  const std::string &password, const std::string &tls_hostname,
                  const std::string &tls_cafile);
void trojans_main(const std::string &hostname, const std::string &servicename,
                  const std::string &password, const std::string &tls_certfile,
                  const std::string &tls_keyfile, const std::string &tls_keypassword);

#endif /* TOMATO_H */
