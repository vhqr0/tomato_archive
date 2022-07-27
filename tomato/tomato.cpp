#include "tomato.h"

#include <getopt.h> // getopt_long
#include <stdint.h>
#include <stdlib.h> // setenv

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <asio.hpp>
#include <asio/ssl.hpp>

#include <openssl/md5.h>

Config::Config() : ssl_context(asio::ssl::context::sslv23) {
  ssl_context.set_verify_mode(asio::ssl::verify_peer);
  std::string pwd = env_string("TOMATO_PASSWORD", "password");
  MD5((const unsigned char *)pwd.c_str(), pwd.length(), password);
}

void Config::setup_client() {
  local = env_endpoint("TOMATO_CLIENT_LOCAL", 1080);
  remote = env_endpoint("TOMATO_CLIENT_REMOTE", 4433);
  ssl_context.load_verify_file(env_string("TOMATO_CA", "crt/ca.crt"));
}

void Config::setup_server() {
  local = env_endpoint("TOMATO_SERVER_LOCAL", 4433);
  server_index =
    "HTTP/1.1 200 OK\r\n\r\n" + env_string("TOMATO_SERVER_INDEX", "<p>hello world</p>");
  ssl_context.use_certificate_file(env_string("TOMATO_CERT", "crt/server.crt"),
                                   asio::ssl::context::pem);
  ssl_context.use_private_key_file(env_string("TOMATO_KEY", "crt/server.key"),
                                   asio::ssl::context::pem);
}

std::string Config::env_string(const char *env, std::string dft) {
  const char *val = std::getenv(env);
  return val ? std::string(val) : dft;
}

asio::ip::tcp::endpoint Config::env_endpoint(const char *env, uint16_t port) {
  std::string host = env_string(env, "");
  auto res = resolve(host, port, false);
  return {res.first, res.second};
}

std::pair<asio::ip::address, uint16_t> Config::resolve(std::string host, uint16_t port,
                                                       bool remotep) {
  if (!host.empty() && host[0] == '[') {
    auto pos = host.find(']');
    if (pos == std::string::npos)
      throw std::exception();
    if (pos + 1 != std::string::npos) {
      if (host[pos + 1] != ':')
        throw std::exception();
      port = std::stoi(host.substr(pos + 2));
    }
    host = host.substr(1, pos - 1);
  } else {
    auto pos = host.find(':');
    if (pos != std::string::npos) {
      port = std::stoi(host.substr(pos + 1));
      host = host.substr(0, pos);
    }
  }
  if (host.empty())
    host = "0.0.0.0";
  std::pair<asio::ip::address, uint16_t> res;
  try {
    res.first = asio::ip::make_address(host);
    res.second = port;
  } catch (asio::system_error error) {
    if (remotep) {
      std::array<uint8_t, TOMATO_BUF_SIZE> buf;
      int length = host.length();
      std::memcpy(&buf[0], password, 16);
      buf[16] = 5;
      buf[17] = 0x80;
      buf[18] = 0;
      buf[19] = 3;
      buf[20] = length;
      std::memcpy(&buf[21], &host[0], length);
      length += 21;
      buf[length++] = port >> 8;
      buf[length++] = port;
      asio::ssl::stream<asio::ip::tcp::socket> stream(io_context, ssl_context);
      stream.lowest_layer().connect(remote);
      stream.handshake(stream.client);
      stream.write_some(asio::buffer(buf, length));
      length = stream.read_some(asio::buffer(buf));
      if (length < 4 || buf[0] != 5)
        throw std::exception();
      switch (buf[3]) {
      case 1:
        if (length != 10)
          throw std::exception();
        {
          asio::ip::address_v4::bytes_type addr;
          std::memcpy(&addr[0], &buf[4], 4);
          res.first = asio::ip::address_v4(addr);
          res.second = (buf[8] << 8) + buf[9];
        }
        break;
      case 4:
        if (length != 22)
          throw std::exception();
        {
          asio::ip::address_v6::bytes_type addr;
          std::memcpy(&addr[0], &buf[4], 16);
          res.first = asio::ip::address_v6(addr);
          res.second = (buf[20] << 8) + buf[21];
        }
        break;
      default:
        throw std::exception();
      }
    } else {
      asio::ip::tcp::endpoint endpoint =
        *asio::ip::tcp::resolver(io_context).resolve(host, std::to_string(port));
      res.first = endpoint.address();
      res.second = endpoint.port();
    }
  }
  return res;
}

std::vector<std::string> Config::split_binds(std::string binds) {
  std::vector<std::string> sp;
  for (;;) {
    auto pos = binds.find(';');
    sp.push_back(binds.substr(0, pos));
    if (pos == std::string::npos)
      break;
    binds = binds.substr(pos + 1);
  }
  return sp;
}

void Config::resolve_binds() {
  const char *val = std::getenv("TOMATO_BINDS");
  if (!val)
    return;
  std::vector<std::string> sp = split_binds(val);
  for (int i = 0; i + 1 < sp.size(); i += 2) {
    std::pair<asio::ip::tcp::endpoint, asio::ip::tcp::endpoint> bind;
    std::pair<asio::ip::address, uint16_t> res;
    res = resolve(sp[i], 0, false);
    bind.first = {res.first, res.second};
    res = resolve(sp[i + 1], 0, true);
    bind.second = {res.first, res.second};
    binds.push_back(bind);
  }
}

void Config::resolve_ubinds() {
  const char *val = std::getenv("TOMATO_UBINDS");
  if (!val)
    return;
  std::vector<std::string> sp = split_binds(val);
  for (int i = 0; i + 1 < sp.size(); i += 2) {
    std::pair<asio::ip::udp::endpoint, asio::ip::udp::endpoint> ubind;
    std::pair<asio::ip::address, uint16_t> res;
    res = resolve(sp[i], 0, false);
    ubind.first = {res.first, res.second};
    res = resolve(sp[i + 1], 0, true);
    ubind.second = {res.first, res.second};
    ubinds.push_back(ubind);
  }
}

Object::Object(Config &config) : config(config), id(0) {}

Object::Object(Object &object) : config(object.config), id(object.id++) {}

void Object::log(char level, std::string msg) {
  std::cout << level << ":" << id << ":" << msg << std::endl;
}

void Object::log(char level, std::string msg, asio::error_code ec) {
  log(level, msg + " : " + asio::system_error(ec).what());
}

void Object::log(char level, std::string msg, asio::ip::tcp::endpoint endpoint) {
  std::ostringstream oss;
  oss << endpoint;
  log(level, msg + " @ " + oss.str());
}

void Object::log(char level, std::string msg, asio::ip::udp::endpoint endpoint) {
  std::ostringstream oss;
  oss << endpoint;
  log(level, msg + " @ " + oss.str());
}

void Object::log(char level, std::string msg, asio::ip::tcp::endpoint local,
                 asio::ip::tcp::endpoint remote) {
  std::ostringstream oss;
  oss << local << " -> " << remote;
  log(level, msg + " @ " + oss.str());
}

void Object::log(char level, std::string msg, asio::ip::udp::endpoint local,
                 asio::ip::udp::endpoint remote) {
  std::ostringstream oss;
  oss << local << " -> " << remote;
  log(level, msg + " @ " + oss.str());
}

void help(bool invalid_argument_p) {
  if (invalid_argument_p)
    std::cerr << "invalid argument" << std::endl;
  std::cout << "usage: tomato -[csbu[arg]] [-r remote] [-p password]" << std::endl;
  std::cout << "-h, --help      show this message" << std::endl;
  std::cout << "-c, --client    client mode" << std::endl;
  std::cout << "-s, --server    server mode" << std::endl;
  std::cout << "-b, --binds     bind mode" << std::endl;
  std::cout << "-u, --ubinds    ubind mode" << std::endl;
  std::cout << "-r, --remote    specified remote server" << std::endl;
  std::cout << "-p, --password  specified password" << std::endl;
  std::cout << "    --index     specified index page used by server" << std::endl;
  std::cout << "    --ca        specified ca file used by client" << std::endl;
  std::cout << "    --cert      specified cert file used by server" << std::endl;
  std::cout << "    --key       specified key file used by server" << std::endl;
  exit(invalid_argument_p ? -1 : 1);
}

int main(int argc, char **argv) {
  char c, mode = -1;
  int lopt, loptind;
  struct option loptions[] = {
    {"help", no_argument, NULL, 'h'},           {"client", optional_argument, NULL, 'c'},
    {"server", optional_argument, NULL, 's'},   {"binds", optional_argument, NULL, 'b'},
    {"ubinds", optional_argument, NULL, 'u'},   {"remote", required_argument, NULL, 'r'},
    {"password", required_argument, NULL, 'p'}, {"index", required_argument, &lopt, 0},
    {"ca", required_argument, &lopt, 1},        {"cert", required_argument, &lopt, 2},
    {"key", required_argument, &lopt, 3},       {0, 0, 0, 0}};
  while ((c = getopt_long(argc, argv, "hc::s::b::u::r:p:", loptions, &loptind)) >= 0) {
    switch (c) {
    case 'h':
      help(false);
      break;
    case 'c':
      mode = c;
      if (optarg)
        setenv("TOMATO_CLIENT_LOCAL", optarg, true);
      break;
    case 's':
      mode = c;
      if (optarg)
        setenv("TOMATO_SERVER_LOCAL", optarg, true);
      break;
    case 'b':
      mode = c;
      if (optarg)
        setenv("TOMATO_BINDS", optarg, true);
      break;
    case 'u':
      mode = c;
      if (optarg)
        setenv("TOMATO_UBINDS", optarg, true);
      break;
    case 'r':
      setenv("TOMATO_CLIENT_REMOTE", optarg, true);
      break;
    case 'p':
      setenv("TOMATO_PASSWORD", optarg, true);
      break;
    case 0:
      switch (lopt) {
      case 0:
        setenv("TOMATO_SERVER_INDEX", optarg, true);
        break;
      case 1:
        setenv("TOMATO_CA", optarg, true);
        break;
      case 2:
        setenv("TOMATO_CERT", optarg, true);
        break;
      case 3:
        setenv("TOMATO_KEY", optarg, true);
        break;
      default:
        help(true);
      }
      break;
    default:
      help(true);
    }
  }
  Config config;
  switch (mode) {
  case 'c': {
    config.setup_client();
    Client client(config);
    config.io_context.run();
    break;
  }
  case 's': {
    config.setup_server();
    Server server(config);
    config.io_context.run();
    break;
  }
  case 'b': {
    config.setup_client();
    config.resolve_binds();
    Bind bind(config);
    config.io_context.run();
    break;
  }
  case 'u': {
    config.setup_client();
    config.resolve_ubinds();
    UBind ubind(config);
    config.io_context.run();
    break;
  }
  default:
    help(true);
  }
  return 0;
}
