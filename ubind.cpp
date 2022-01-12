#include "tomato.h"

#include <stdint.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <memory>

#include <asio.hpp>

UBindSession::UBindSession(asio::ip::udp::endpoint &local, asio::ip::udp::endpoint &remote,
                           Object &object)
  : Object(object), socket_(config.io_context, local),
    stream_(config.io_context, config.client_ssl_context), in_buf_(config.buf_size),
    out_buf_(config.buf_size), local_(local), remote_(remote) {}

UBindSession::~UBindSession() { LOG_MSG("sesion closed"); }

void UBindSession::start() {
  LOG_MSG("ubind", local_, remote_);
  std::memcpy(&out_buf_[0], config.password, 16);
  out_buf_[16] = 5;
  out_buf_[17] = 0x81;
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
    LOG_ERR("unknown endpoint type");
    return;
  }
  auto self(shared_from_this());
  socket_.async_receive_from( // receive
    asio::buffer(in_buf_), endpoint_, [this, self](asio::error_code ec, std::size_t length) {
      socket_.close();
      std::make_shared<UBindSession>(local_, remote_, *this)->start();
      if (ec) {
        LOG_ERR("receive failed", ec);
        return;
      }
      LOG_MSG("receive", endpoint_);
      if (length_ + length + 2 > config.buf_size) {
        LOG_ERR("packet too long");
        return;
      }
      out_buf_[length_++] = length >> 8;
      out_buf_[length_++] = length;
      std::memcpy(&out_buf_[length_], &in_buf_[0], length);
      length_ += length;
      stream_.lowest_layer().async_connect( // connect
        config.client_remote, [this, self](asio::error_code ec) {
          if (ec) {
            LOG_ERR("connect failed", ec);
            return;
          }
          stream_.async_handshake( // tls handshake
            stream_.client, [this, self](asio::error_code ec) {
              if (ec) {
                LOG_ERR("tls handshake failed", ec);
                return;
              }
              stream_.async_write_some( // send password and request
                asio::buffer(out_buf_, length_),
                [this, self](asio::error_code ec, std::size_t length) {
                  if (ec) {
                    LOG_ERR("send failed", ec);
                    return;
                  }
                  asio::async_read( // receive response 1
                    stream_, asio::buffer(out_buf_, 4),
                    [this, self](asio::error_code ec, std::size_t length) {
                      if (ec) {
                        LOG_ERR("receive failed", ec);
                        return;
                      }
                      if (out_buf_[0] != 5 || out_buf_[1] != 0) {
                        LOG_ERR("invalid data");
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
                        LOG_ERR("unknown endpoint type");
                        return;
                      }
                      asio::async_read( // receive response 2
                        stream_, asio::buffer(out_buf_, length),
                        [this, self](asio::error_code ec, std::size_t length) {
                          if (ec) {
                            LOG_ERR("receive failed", ec);
                            return;
                          }
                          try {
                            socket_.open(endpoint_.protocol());
                          } catch (asio::system_error error) {
                            LOG_ERR("open failed", error.code());
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
}

void UBindSession::do_proxy_in() {
  auto self(shared_from_this());
  socket_.async_receive_from( // receive
    asio::buffer(&in_buf_[2], config.buf_size - 2), endpoint_,
    [this, self](asio::error_code ec, std::size_t length) {
      if (ec) {
        socket_.close();
        stream_.lowest_layer().close();
        return;
      }
      in_buf_[0] = length >> 8;
      in_buf_[1] = length;
      length += 2;
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

void UBindSession::do_proxy_out() {
  auto self(shared_from_this());
  asio::async_read( // receive length
    stream_, asio::buffer(out_buf_, 2), [this, self](asio::error_code ec, std::size_t length) {
      if (ec) {
        socket_.close();
        stream_.lowest_layer().close();
        return;
      }
      length = (out_buf_[0] << 8) + out_buf_[1];
      if (length > config.buf_size) {
        socket_.close();
        stream_.lowest_layer().close();
        return;
      }
      asio::async_read( // receive
        stream_, asio::buffer(out_buf_, length),
        [this, self](asio::error_code ec, std::size_t length) {
          if (ec) {
            socket_.close();
            stream_.lowest_layer().close();
            return;
          }
          socket_.async_send_to( // send
            asio::buffer(out_buf_, length), endpoint_,
            [this, self](asio::error_code ec, std::size_t length) {
              if (ec) {
                socket_.close();
                stream_.lowest_layer().close();
                return;
              }
              do_proxy_out();
            });
        });
    });
}

UBind::UBind(Config &config) : Object(config) {
  for (int i = 0; i + 1 < config.ubinds.size(); i += 2)
    std::make_shared<UBindSession>(config.ubinds[i], config.ubinds[i + 1], *this)->start();
}
