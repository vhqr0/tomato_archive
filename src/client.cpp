#include "tomato.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <exception>

ClientSession::ClientSession(asio::ip::tcp::socket socket, Object &object)
  : Object(object), socket_(std::move(socket)),
    stream_(config.io_context, config.client_ssl_context), in_buf_(config.buf_size),
    out_buf_(config.buf_size) {}

ClientSession::~ClientSession() { LOG_MSG("session closed"); }

void ClientSession::start() { do_handshake(); }

void ClientSession::do_handshake() {
  auto self(shared_from_this());
  socket_.async_receive( // receive handshake from browser
    asio::buffer(in_buf_), [this, self](asio::error_code ec, std::size_t length) {
      if (ec || !length) {
        LOG_ERR("socks handshake receive failed", ec);
        return;
      }
      if (in_buf_[0] != 5) {
        length_ = length;
        do_http_handshake();
        return;
      }
      if (length < 2 || length != in_buf_[1] + 2) {
        LOG_ERR("socks handshake invalid data");
        return;
      }
      auto beg = in_buf_.begin() + 2;
      auto end = in_buf_.begin() + length;
      if (std::find(beg, end, 0) == end) {
        LOG_ERR("socks handshake unsupported auth failed");
        return;
      }
      socket_.async_send( // send response to browser
        asio::buffer("\x05\x00", 2), [this, self](asio::error_code ec, std::size_t length) {
          if (ec) {
            LOG_ERR("socks handshake send failed", ec);
            return;
          }
          stream_.lowest_layer().async_connect( // connect
            config.client_remote, [this, self](asio::error_code ec) {
              if (ec) {
                LOG_ERR("tomato handshake connect failed", ec);
                return;
              }
              stream_.async_handshake( // tls handshake
                stream_.client, [this, self](asio::error_code ec) {
                  if (ec) {
                    LOG_ERR("tomato handshake tls handshake failed", ec);
                    return;
                  }
                  stream_.async_write_some( // send password
                    asio::buffer(config.password, 16),
                    [this, self](asio::error_code ec, std::size_t length) {
                      if (ec) {
                        LOG_ERR("tomato handshake send failed", ec);
                        return;
                      }
                      do_proxy_in();
                      do_proxy_out();
                    });
                });
            });
        });
    });
}

void ClientSession::do_http_handshake() {
  try {
    auto beg = in_buf_.begin();
    auto end = beg + length_;
    auto cur = std::find(beg, end, '\r');
    if (cur == end)
      throw std::exception();
    end = cur;
    cur = std::find(beg, end, ' ');
    if (cur == end)
      throw std::exception();
    std::string method((char *)&*beg, std::distance(beg, cur));
    connectp_ = method == "CONNECT";
    beg = cur + 1;
    cur = std::find(beg, end, ' ');
    if (cur == end)
      throw std::exception();
    end = cur;
    static const char *protodiv = "://";
    cur = std::search(beg, end, protodiv, protodiv + 3);
    if (cur != end)
      beg = cur + 3;
    cur = std::find_if(beg, end, [](uint8_t x) { return x == '/' || x == '?' || x == '#'; });
    std::string host((char *)&*beg, std::distance(beg, cur));
    LOG_MSG("http handshake accept " + method + " " + host);
    uint16_t port;
    auto pos = host.find(':');
    if (pos == std::string::npos) {
      port = 80;
    } else {
      port = std::stoi(host.substr(pos + 1));
      host = host.substr(0, pos);
    }
    int length = host.length();
    if (length + 23 + (connectp_ ? 0 : length_) > config.buf_size) {
      LOG_ERR("http handshake receive host too long");
      return;
    }
    std::memcpy(&out_buf_[0], config.password, 16);
    out_buf_[16] = 5;
    out_buf_[17] = 1;
    out_buf_[18] = 0;
    out_buf_[19] = 3;
    out_buf_[20] = length;
    std::memcpy(&out_buf_[21], &*beg, length);
    length += 21;
    out_buf_[length++] = port >> 8;
    out_buf_[length++] = port;
    if (connectp_) {
      length_ = length;
    } else {
      std::memcpy(&out_buf_[length], &in_buf_[0], length_);
      length_ += length;
    }
  } catch (std::exception e) {
    LOG_ERR("http handshake invalid data");
    return;
  }
  auto self(shared_from_this());
  stream_.lowest_layer().async_connect( // connect
    config.client_remote, [this, self](asio::error_code ec) {
      if (ec) {
        LOG_ERR("http tomato handshake connect failed", ec);
        return;
      }
      stream_.async_handshake( // tls handshake
        stream_.client, [this, self](asio::error_code ec) {
          if (ec) {
            LOG_ERR("http tomato handshake tls handshake failed", ec);
            return;
          }
          stream_.async_write_some( // send password and socks request
            asio::buffer(out_buf_, length_), [this, self](asio::error_code ec, std::size_t length) {
              if (ec) {
                LOG_ERR("http tomato handshake send failed", ec);
                return;
              }
              asio::async_read( // receive socks response 1
                stream_, asio::buffer(out_buf_, 4),
                [this, self](asio::error_code ec, std::size_t length) {
                  if (ec) {
                    LOG_ERR("http tomato handshake receive failed", ec);
                    return;
                  }
                  if (out_buf_[0] != 5 || out_buf_[1] != 0) {
                    LOG_ERR("http tomato handshake invalid data");
                    return;
                  }
                  switch (out_buf_[3]) {
                  case 1:
                    length = 6;
                    break;
                  case 4:
                    length = 18;
                    break;
                  default:
                    LOG_ERR("http tomato handshake unknown endpoint type");
                    return;
                  }
                  asio::async_read( // receive socks response 2
                    stream_, asio::buffer(out_buf_, length),
                    [this, self](asio::error_code ec, std::size_t length) {
                      if (ec) {
                        LOG_ERR("http tomato handshake receive failed", ec);
                        return;
                      }
                      if (connectp_) {
                        socket_.async_send( // send response to browser
                          asio::buffer("HTTP/1.1 200 Connection Established\r\n\r\n", 39),
                          [this, self](asio::error_code ec, std::size_t length) {
                            if (ec) {
                              LOG_ERR("http handshake send failed", ec);
                              return;
                            }
                            do_proxy_in();
                            do_proxy_out();
                          });
                      } else {
                        do_proxy_in();
                        do_proxy_out();
                      }
                    });
                });
            });
        });
    });
}

void ClientSession::do_proxy_in() {
  auto self(shared_from_this());
  socket_.async_receive( // receive
    asio::buffer(in_buf_), [this, self](asio::error_code ec, std::size_t length) {
      if (ec) {
        socket_.close();
        stream_.lowest_layer().close();
        return;
      }
      stream_.async_write_some( // send
        asio::buffer(in_buf_, length), [this, self](asio::error_code ec, std::size_t length) {
          if (ec) {
            socket_.close();
            stream_.lowest_layer().close();
            return;
          }
          do_proxy_in();
        });
    });
}

void ClientSession::do_proxy_out() {
  auto self(shared_from_this());
  stream_.async_read_some( // receive
    asio::buffer(out_buf_), [this, self](asio::error_code ec, std::size_t length) {
      if (ec) {
        socket_.close();
        stream_.lowest_layer().close();
        return;
      }
      socket_.async_send( // send
        asio::buffer(out_buf_, length), [this, self](asio::error_code ec, std::size_t length) {
          if (ec) {
            socket_.close();
            stream_.lowest_layer().close();
            return;
          }
          do_proxy_out();
        });
    });
}

Client::Client(Config &config) : Object(config), acceptor_(config.io_context, config.client_local) {
  LOG_MSG("client local", config.client_local);
  LOG_MSG("client remote", config.client_remote);
  do_accept();
}

void Client::do_accept() {
  acceptor_.async_accept( // accept from browser
    [this](asio::error_code ec, asio::ip::tcp::socket socket) {
      if (ec) {
        LOG_ERR("accept failed", ec);
      } else {
        LOG_MSG("accept", socket.remote_endpoint());
        std::make_shared<ClientSession>(std::move(socket), *this)->start();
      }
      do_accept();
    });
}
