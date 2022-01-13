#include "tomato.h"

#include <stdint.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <sstream>
#include <string>

#include <asio.hpp>
#include <asio/ssl.hpp>

#include <openssl/md5.h>

Config::Config()
  : client_ssl_context(asio::ssl::context::sslv23), server_ssl_context(asio::ssl::context::sslv23) {
  std::string pwd = env_string("TOMATO_PASSWORD", "password");
  MD5((const unsigned char *)pwd.c_str(), pwd.length(), password);
  client_local = env_endpoint("TOMATO_CLIENT_LOCAL", 1080);
  client_remote = env_endpoint("TOMATO_CLIENT_REMOTE", 4433);
  server_local = env_endpoint("TOMATO_SERVER_LOCAL", 4433);
  server_index =
    "HTTP/1.1 200 OK\r\n\r\n" + env_string("TOMATO_SERVER_INDEX", "<p>hello world</p>");
  client_ssl_context.set_verify_mode(asio::ssl::verify_peer);
  client_ssl_context.load_verify_file(env_string("TOMATO_CA", "crt/ca.crt"));
  server_ssl_context.set_verify_mode(asio::ssl::verify_peer);
  server_ssl_context.use_certificate_file(env_string("TOMATO_CERT", "crt/server.crt"),
                                          asio::ssl::context::pem);
  server_ssl_context.use_private_key_file(env_string("TOMATO_KEY", "crt/server.key"),
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
      asio::ssl::stream<asio::ip::tcp::socket> stream(io_context, client_ssl_context);
      stream.lowest_layer().connect(client_remote);
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
  for(;;) {
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

int main(int argc, char **argv) {
  Config config;
  if (argc < 2) {
    std::cerr << "wrong argument" << std::endl;
    return -1;
  }
  if (!std::strcmp(argv[1], "-c")) {
    Client client(config);
    config.io_context.run();
  } else if (!std::strcmp(argv[1], "-s")) {
    Server server(config);
    config.io_context.run();
  } else if (!std::strcmp(argv[1], "-b")) {
    config.resolve_binds();
    Bind bind(config);
    config.io_context.run();
  } else if (!std::strcmp(argv[1], "-u")) {
    config.resolve_ubinds();
    UBind ubind(config);
    config.io_context.run();
  } else {
    std::cerr << "wrong argument" << std::endl;
    return -1;
  }
}
