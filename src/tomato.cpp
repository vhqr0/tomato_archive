#include "tomato.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include <openssl/md5.h>

Config::Config()
  : client_ssl_context(asio::ssl::context::sslv23), server_ssl_context(asio::ssl::context::sslv23) {
  log_level = parse_int("TOMATO_LOG_LEVEL", 1);
  buf_size = parse_int("TOMATO_BUF_SIZE", 4096);
  std::string pwd = parse_str("TOMATO_PASSWORD", "password");
  MD5((const unsigned char *)pwd.c_str(), pwd.length(), password);
  client_local = parse_endpoint("TOMATO_CLIENT_LOCAL", 1080);
  client_remote = parse_endpoint("TOMATO_CLIENT_REMOTE", 4433);
  server_local = parse_endpoint("TOMATO_SERVER_LOCAL", 4433);
  binds = parse_ints("TOMATO_BINDS");
  index = "HTTP/1.1 200 OK\r\n\r\n" + parse_str("TOMATO_SERVER_INDEX", "<p>hello world</p>");
  client_ssl_context.set_verify_mode(asio::ssl::verify_peer);
  client_ssl_context.load_verify_file(parse_str("TOMATO_CA", "crt/ca.crt"));
  server_ssl_context.set_verify_mode(asio::ssl::verify_peer);
  server_ssl_context.use_certificate_file(parse_str("TOMATO_CERT", "crt/server.crt"),
                                          asio::ssl::context::pem);
  server_ssl_context.use_private_key_file(parse_str("TOMATO_KEY", "crt/server.key"),
                                          asio::ssl::context::pem);
}

int Config::parse_int(const char *env, int dft) {
  const char *val = std::getenv(env);
  return val ? std::atoi(val) : dft;
}

std::string Config::parse_str(const char *env, std::string dft) {
  const char *val = std::getenv(env);
  return val ? std::string(val) : dft;
}

std::vector<int> Config::parse_ints(const char *env) {
  const char *val = std::getenv(env);
  std::vector<int> v;
  if (val) {
    const char *beg = val;
    const char *end = val + std::strlen(val);
    const char *cur = std::find(beg, end, ',');
    v.push_back(std::stoi(std::string(beg, cur - beg)));
    while (cur != end) {
      beg = cur + 1;
      cur = std::find(beg, end, ',');
      v.push_back(std::stoi(std::string(beg, cur - beg)));
    }
  }
  return std::move(v);
}

asio::ip::tcp::endpoint Config::parse_endpoint(const char *env, uint16_t dport) {
  std::string host = parse_str(env, "0.0.0.0");
  uint16_t port;
  auto pos = host.find(':');
  if (pos == std::string::npos) {
    port = dport;
  } else {
    port = std::stoi(host.substr(pos + 1));
    host = host.substr(0, pos);
  }
  return asio::ip::tcp::endpoint(asio::ip::address::from_string(host), port);
}

Object::Object(Config &config) : config(config), id(0) {}

Object::Object(Object &object) : config(object.config), id(object.id++) {}

void Object::log(int level, std::string msg) {
  if (level >= config.log_level)
    std::cout << level << ":" << id << ":" << msg << std::endl;
}

void Object::log(int level, std::string msg, asio::error_code ec) {
  log(level, msg + " : " + asio::system_error(ec).what());
}

void Object::log(int level, std::string msg, asio::ip::tcp::endpoint endpoint) {
  std::ostringstream oss;
  oss << msg << " @ " << endpoint;
  log(level, oss.str());
}

void Object::log(int level, std::string msg, asio::ip::tcp::endpoint endpoint,
                 asio::error_code ec) {
  std::ostringstream oss;
  oss << msg << " @ " << endpoint << " : " << asio::system_error(ec).what();
  log(level, oss.str());
}

int main(int argc, char **argv) {
  Config config;
  if (argc != 2) {
    std::cerr << "wrong argument" << std::endl;
    return -1;
  }
  if (!std::strcmp(argv[1], "-c")) {
    Client client(config);
    config.io_context.run();
  } else if (!std::strcmp(argv[1], "-s")) {
    Server server(config);
    config.io_context.run();
  } else {
    std::cerr << "wrong argument" << std::endl;
    return -1;
  }
}
