#include "tomato.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <exception>

ServerSession::ServerSession(asio::ip::tcp::socket socket, Object &object)
  : Object(object), socket_(config.io_context),
    stream_(std::move(socket), config.server_ssl_context), acceptor_(config.io_context),
    resolver_(config.io_context), in_buf_(config.buf_size), out_buf_(config.buf_size) {}

ServerSession::~ServerSession() { LOG_MSG("session closed"); }

void ServerSession::start() { do_handshake(); }

void ServerSession::do_handshake() {
  auto self(shared_from_this());
  stream_.async_handshake( // tls handshake
    stream_.server, [this, self](asio::error_code ec) {
      if (ec) {
        LOG_ERR("handshake tls handshake failed", ec);
        return;
      }
      asio::async_read( // receive password
        stream_, asio::buffer(in_buf_, 16), [this, self](asio::error_code ec, std::size_t length) {
          if (ec) {
            LOG_ERR("handshake receive password failed", ec);
            return;
          }
          if (std::memcmp(&in_buf_[0], config.password, 16)) {
            LOG_MSG("handshake receive wrong password");
            stream_.async_write_some( // send index
              asio::buffer(config.index), [this, self](asio::error_code ec, std::size_t length) {});
          } else {
            asio::async_read( // receive socks request
              stream_, asio::buffer(in_buf_, 4),
              [this, self](asio::error_code ec, std::size_t length) {
                if (ec) {
                  LOG_ERR("handshake receive socks command failed", ec);
                  return;
                }
                if (in_buf_[0] != 5) {
                  LOG_ERR("handshake receive invalid data");
                  return;
                }
                do_resolve();
              });
          }
        });
    });
}

void ServerSession::do_resolve() {
  auto self(shared_from_this());
  switch (in_buf_[3]) {
  case 1:
    asio::async_read( // receive ipv4 address
      stream_, asio::buffer(out_buf_, 6), [this, self](asio::error_code ec, std::size_t length) {
        if (ec) {
          LOG_ERR("handshake receive ipv4 address failed", ec);
          return;
        }
        asio::ip::address_v4::bytes_type addr;
        std::memcpy(&addr[0], &out_buf_[0], 4);
        endpoint_ = {asio::ip::address_v4(addr), (uint16_t)((out_buf_[4] << 8) + out_buf_[5])};
        do_execute();
      });
    break;
  case 4:
    asio::async_read( // receive ipv6 address
      stream_, asio::buffer(out_buf_, 18), [this, self](asio::error_code ec, std::size_t length) {
        if (ec) {
          LOG_ERR("handshake receive ipv6 address failed", ec);
          return;
        }
        asio::ip::address_v6::bytes_type addr;
        std::memcpy(&addr[0], &out_buf_[0], 16);
        endpoint_ = {asio::ip::address_v6(addr), (uint16_t)((out_buf_[16] << 8) + out_buf_[17])};
        do_execute();
      });
    break;
  case 3:
    asio::async_read( // receive host length
      stream_, asio::buffer(out_buf_, 1), [this, self](asio::error_code ec, std::size_t length) {
        if (ec) {
          LOG_ERR("handshake receive host length failed", ec);
          return;
        }
        if (out_buf_[0] + 2 > config.buf_size) {
          LOG_ERR("handshake receive host too long");
          return;
        }
        asio::async_read( // receive host
          stream_, asio::buffer(out_buf_, out_buf_[0] + 2),
          [this, self](asio::error_code ec, std::size_t length) {
            if (ec) {
              LOG_ERR("handshake receive host failed", ec);
              return;
            }
            host_ = std::string((char *)&out_buf_[0], length - 2);
            port_ = std::to_string((out_buf_[length - 2] << 8) + out_buf_[length - 1]);
            LOG_MSG("handshake receive address: " + host_ + ":" + port_);
            resolver_.async_resolve( // reslove host
              host_, port_,
              [this, self](asio::error_code ec, asio::ip::tcp::resolver::iterator it) {
                if (ec) {
                  LOG_ERR("handshake resolve failed", ec);
                  return;
                }
                endpoint_ = *it;
                do_execute();
              });
          });
      });
    break;
  default:
    LOG_ERR("handshake receive unsupported address type");
  }
}

void ServerSession::do_execute() {
  auto self(shared_from_this());
  switch (in_buf_[1]) {
  case 1:
    LOG_MSG("connect to", endpoint_);
    socket_.async_connect( // connect to web
      endpoint_, [this, self](asio::error_code ec) {
        if (ec) {
          LOG_ERR("connect failed", endpoint_, ec);
          return;
        }
        int length = make_response();
        if (length < 0)
          return;
        stream_.async_write_some( // send response
          asio::buffer(in_buf_, length), [this, self](asio::error_code ec, std::size_t length) {
            if (ec) {
              LOG_ERR("handshake send response failed", ec);
              return;
            }
            do_proxy_in();
            do_proxy_out();
          });
      });
    break;
  case 2:
    LOG_MSG("bind to", endpoint_);
    {
      try {
        acceptor_.open(endpoint_.protocol());
        acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
        acceptor_.bind(endpoint_);
        acceptor_.listen(1);
      } catch (asio::error_code ec) {
        LOG_ERR("bind failed", endpoint_, ec);
        return;
      }
      int length = make_response();
      if (length < 0)
        return;
      stream_.async_write_some( // send response
        asio::buffer(in_buf_, length), [this, self](asio::error_code ec, std::size_t length) {
          if (ec) {
            LOG_ERR("handshake send response failed", ec);
            return;
          }
          acceptor_.async_accept( // accept
            socket_, [this, self](asio::error_code ec) {
              if (ec) {
                LOG_ERR("accept failed", ec);
                return;
              }
              acceptor_.close();
              endpoint_ = socket_.remote_endpoint();
              LOG_MSG("bind accept", endpoint_);
              int length = make_response();
              if (length < 0)
                return;
              stream_.async_write_some( // send response
                asio::buffer(in_buf_, length),
                [this, self](asio::error_code ec, std::size_t length) {
                  if (ec) {
                    LOG_ERR("handshake send response failed", ec);
                    return;
                  }
                  do_proxy_in();
                  do_proxy_out();
                });
            });
        });
    }
    break;
  default:
    LOG_ERR("handshake receive unsupported command");
  }
}

int ServerSession::make_response() {
  int length;
  in_buf_[0] = 5;
  in_buf_[1] = 0;
  in_buf_[2] = 0;
  if (endpoint_.address().is_v4()) {
    length = 10;
    in_buf_[3] = 1;
    auto addr = endpoint_.address().to_v4().to_bytes();
    uint16_t port = htons(endpoint_.port());
    std::memcpy(&in_buf_[4], &addr[0], 4);
    std::memcpy(&in_buf_[8], &port, 2);
  } else if (endpoint_.address().is_v6()) {
    length = 22;
    in_buf_[3] = 4;
    auto addr = endpoint_.address().to_v6().to_bytes();
    uint16_t port = htons(endpoint_.port());
    std::memcpy(&in_buf_[4], &addr[0], 16);
    std::memcpy(&in_buf_[20], &port, 2);
  } else {
    LOG_ERR("unknown endpoint type", endpoint_);
    return -1;
  }
  return length;
}

void ServerSession::do_proxy_in() {
  auto self(shared_from_this());
  stream_.async_read_some( // receive
    asio::buffer(in_buf_), [this, self](asio::error_code ec, std::size_t length) {
      if (ec) {
        socket_.close();
        stream_.lowest_layer().close();
        return;
      }
      socket_.async_send( // send
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

void ServerSession::do_proxy_out() {
  auto self(shared_from_this());
  socket_.async_receive( // receive
    asio::buffer(out_buf_), [this, self](asio::error_code ec, std::size_t length) {
      if (ec) {
        socket_.close();
        stream_.lowest_layer().close();
        return;
      }
      stream_.async_write_some( // send
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

Server::Server(Config &config) : Object(config), acceptor_(config.io_context, config.server_local) {
  LOG_MSG("server local", config.server_local);
  do_accept();
}

void Server::do_accept() {
  acceptor_.async_accept( // accept from client
    [this](asio::error_code ec, asio::ip::tcp::socket socket) {
      if (ec) {
        LOG_ERR("accept failed", ec);
      } else {
        LOG_MSG("accept", socket.remote_endpoint());
        std::make_shared<ServerSession>(std::move(socket), *this)->start();
      }
      do_accept();
    });
}
