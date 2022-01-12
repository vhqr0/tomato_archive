#include "tomato.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <memory>

#include <asio.hpp>

BindSession::BindSession(asio::ip::tcp::endpoint &local, asio::ip::tcp::endpoint &remote,
                         asio::ip::tcp::socket socket, Object &object)
  : ClientSession(std::move(socket), object), local_(local), remote_(remote) {}

void BindSession::bind() {
  LOG_MSG("bind", local_, remote_);
  std::memcpy(&out_buf_[0], config.password, 16);
  out_buf_[16] = 5;
  out_buf_[17] = 2;
  out_buf_[18] = 0;
  if (remote_.address().is_v4()) {
    length_ = 26;
    out_buf_[19] = 1;
    auto addr = remote_.address().to_v4().to_bytes();
    uint16_t port = remote_.port();
    std::memcpy(&out_buf_[20], &addr[0], 4);
    out_buf_[24] = port >> 8;
    out_buf_[25] = port;
  } else if (remote_.address().is_v6()) {
    length_ = 38;
    out_buf_[19] = 4;
    auto addr = remote_.address().to_v6().to_bytes();
    uint16_t port = remote_.port();
    std::memcpy(&out_buf_[20], &addr[0], 16);
    out_buf_[36] = port >> 8;
    out_buf_[37] = port;
  } else {
    LOG_ERR("bind tomato handshake unknown endpoint type");
    return;
  }
  auto self(shared_from_this());
  stream_.lowest_layer().async_connect( // connect
    config.client_remote, [this, self](asio::error_code ec) {
      if (ec) {
        LOG_ERR("bind tomato handshake connect failed", ec);
        return;
      }
      stream_.async_handshake( // tls handshake
        stream_.client, [this, self](asio::error_code ec) {
          if (ec) {
            LOG_ERR("bind tomato handshake tls handshake failed", ec);
            return;
          }
          stream_.async_write_some( // send password and socks request
            asio::buffer(out_buf_, length_), [this, self](asio::error_code ec, std::size_t length) {
              if (ec) {
                LOG_ERR("bind tomato handshake send failed", ec);
                return;
              }
              asio::async_read( // receive socks response 1
                stream_, asio::buffer(out_buf_, 4),
                [this, self](asio::error_code ec, std::size_t length) {
                  if (ec) {
                    LOG_ERR("bind tomato handshake receive failed", ec);
                    return;
                  }
                  if (out_buf_[0] != 5 || out_buf_[1] != 0) {
                    LOG_ERR("bind tomato handshake invalid data");
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
                    LOG_ERR("bind tomato handshake unknown endpoint type");
                    return;
                  }
                  asio::async_read( // receive socks response 2
                    stream_, asio::buffer(out_buf_, length),
                    [this, self](asio::error_code ec, std::size_t length) {
                      if (ec) {
                        LOG_ERR("bind tomato handshake receive failed", ec);
                        return;
                      }
                      asio::async_read( // receive socks response 1
                        stream_, asio::buffer(out_buf_, 4),
                        [this, self](asio::error_code ec, std::size_t length) {
                          if (ec) {
                            LOG_ERR("bind tomato handshake receive failed", ec);
                            return;
                          }
                          if (out_buf_[0] != 5 || out_buf_[1] != 0) {
                            LOG_ERR("bind tomato handshake invalid data");
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
                            LOG_ERR("bind tomato handshake unknown endpoint type");
                            return;
                          }
                          asio::async_read( // receive socks response 2
                            stream_, asio::buffer(out_buf_, length),
                            [this, self](asio::error_code ec, std::size_t length) {
                              if (ec) {
                                LOG_ERR("bind tomato handshake receive failed", ec);
                                return;
                              }
                              socket_.async_connect( // connect
                                local_, [this, self](asio::error_code ec) {
                                  std::make_shared<BindSession>(
                                    local_, remote_, asio::ip::tcp::socket(config.io_context),
                                    *this)
                                    ->bind();
                                  if (ec) {
                                    LOG_ERR("bind tomato handshake connect failed", ec);
                                    return;
                                  }
                                  do_proxy_in();
                                  do_proxy_out();
                                });
                            });
                        });
                    });
                });
            });
        });
    });
}

Bind::Bind(Config &config) : Object(config) {
  LOG_MSG("bind remote", config.client_remote);
  for (int i = 0; i + 1 < config.binds.size(); i += 2)
    std::make_shared<BindSession>(config.binds[i], config.binds[i + 1],
                                  asio::ip::tcp::socket(config.io_context), *this)
      ->bind();
}
