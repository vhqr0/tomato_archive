#include "tomato.h"

#include <stdint.h>

#include <cstring>
#include <memory>
#include <string>

#include <asio.hpp>

ServerSession::ServerSession(asio::ip::tcp::socket socket, Object &object)
  : Object(object), socket_(config.io_context), usocket_(config.io_context),
    acceptor_(config.io_context), stream_(std::move(socket), config.server_ssl_context),
    resolver_(config.io_context), uresolver_(config.io_context) {}

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
              asio::buffer(config.server_index),
              [this, self](asio::error_code ec, std::size_t length) {});
          } else {
            asio::async_read( // receive request
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
    asio::async_read( // receive ipv4
      stream_, asio::buffer(out_buf_, 6), [this, self](asio::error_code ec, std::size_t length) {
        if (ec) {
          LOG_ERR("handshake receive ipv4 address failed", ec);
          return;
        }
        asio::ip::address_v4::bytes_type addr;
        std::memcpy(&addr[0], &out_buf_[0], 4);
        if (in_buf_[1] & 0x80)
          uendpoint_ = {asio::ip::address_v4(addr), (uint16_t)((out_buf_[4] << 8) + out_buf_[5])};
        else
          endpoint_ = {asio::ip::address_v4(addr), (uint16_t)((out_buf_[4] << 8) + out_buf_[5])};
        do_execute();
      });
    break;
  case 4:
    asio::async_read( // receive ipv6
      stream_, asio::buffer(out_buf_, 18), [this, self](asio::error_code ec, std::size_t length) {
        if (ec) {
          LOG_ERR("handshake receive ipv6 address failed", ec);
          return;
        }
        asio::ip::address_v6::bytes_type addr;
        std::memcpy(&addr[0], &out_buf_[0], 16);
        if (in_buf_[1] & 0x80)
          uendpoint_ = {asio::ip::address_v6(addr), (uint16_t)((out_buf_[16] << 8) + out_buf_[17])};
        else
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
        asio::async_read( // receive host
          stream_, asio::buffer(out_buf_, out_buf_[0] + 2),
          [this, self](asio::error_code ec, std::size_t length) {
            if (ec) {
              LOG_ERR("handshake receive host failed", ec);
              return;
            }
            host_ = std::string((char *)&out_buf_[0], length - 2);
            port_ = std::to_string((out_buf_[length - 2] << 8) + out_buf_[length - 1]);
            LOG_MSG("handshake receive host: " + host_ + ":" + port_);
            if (in_buf_[1] & 0x80)
              uresolver_.async_resolve( // reslove udp
                host_, port_,
                [this, self](asio::error_code ec, asio::ip::udp::resolver::iterator it) {
                  if (ec) {
                    LOG_ERR("handshake resolve failed", ec);
                    return;
                  }
                  uendpoint_ = *it;
                  do_execute();
                });
            else
              resolver_.async_resolve( // reslove tcp
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
    socket_.async_connect( // connect
      endpoint_, [this, self](asio::error_code ec) {
        if (ec) {
          LOG_ERR("connect failed", ec);
          return;
        }
        int length = make_response(endpoint_);
        if (length < 0)
          return;
        stream_.async_write_some( // send response
          asio::buffer(in_buf_, length), [this, self](asio::error_code ec, std::size_t length) {
            if (ec) {
              LOG_ERR("handshake send failed", ec);
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
      } catch (asio::system_error error) {
        LOG_ERR("bind failed", error.code());
        return;
      }
      LOG_MSG("bind listen", acceptor_.local_endpoint());
      int length = make_response(acceptor_.local_endpoint());
      if (length < 0)
        return;
      stream_.async_write_some( // send response
        asio::buffer(in_buf_, length), [this, self](asio::error_code ec, std::size_t length) {
          if (ec) {
            LOG_ERR("handshake send failed", ec);
            return;
          }
          acceptor_.async_accept( // accept
            socket_, [this, self](asio::error_code ec) {
              acceptor_.close();
              if (ec) {
                LOG_ERR("bind accept failed", ec);
                socket_.close();
                stream_.lowest_layer().close();
                return;
              }
              LOG_MSG("bind accept", socket_.remote_endpoint());
              int length = make_response(socket_.remote_endpoint());
              if (length < 0) {
                socket_.close();
                stream_.lowest_layer().close();
                return;
              }
              stream_.async_write_some( // send response
                asio::buffer(in_buf_, length),
                [this, self](asio::error_code ec, std::size_t length) {
                  if (ec) {
                    LOG_ERR("handshake send failed", ec);
                    socket_.close();
                    stream_.lowest_layer().close();
                    return;
                  }
                  do_proxy_out();
                });
            });
          stream_.async_read_some( // watch connection and receive
            asio::buffer(in_buf_), [this, self](asio::error_code ec, std::size_t length) {
              if (acceptor_.is_open()) {
                if (ec) {
                  LOG_ERR("bind canceled for error", ec);
                } else {
                  LOG_ERR("bind canceled for receive");
                }
                acceptor_.cancel();
                socket_.close();
                stream_.lowest_layer().close();
                return;
              }
              if (ec) {
                socket_.close();
                stream_.lowest_layer().close();
                return;
              }
              socket_.async_send( // send
                asio::buffer(in_buf_, length),
                [this, self](asio::error_code ec, std::size_t length) {
                  if (ec) {
                    socket_.close();
                    stream_.lowest_layer().close();
                    return;
                  }
                  do_proxy_in();
                });
            });
        });
    }
    break;
  case 0x80:
    LOG_MSG("host query", uendpoint_);
    {
      int length = make_response(uendpoint_);
      if (length < 0)
        return;
      stream_.async_write_some( // send response
        asio::buffer(in_buf_, length), [this, self](asio::error_code ec, std::size_t length) {
          if (ec) {
            LOG_ERR("handshake send failed");
            return;
          }
        });
    }
    break;
  case 0x81:
    LOG_MSG("udp assoc", uendpoint_);
    {
      try {
        usocket_.open(uendpoint_.protocol());
      } catch (asio::system_error error) {
        LOG_ERR("udp open failed");
        return;
      }
      LOG_MSG("udp bind", usocket_.local_endpoint());
      int length = make_response(usocket_.local_endpoint());
      if (length < 0)
        return;
      stream_.async_write_some( // send response
        asio::buffer(in_buf_, length), [this, self](asio::error_code ec, std::size_t length) {
          if (ec) {
            LOG_ERR("handshake send failed");
            return;
          }
          do_udp_proxy_in();
          do_udp_proxy_out();
        });
    }
    break;
  default:
    LOG_ERR("handshake receive unsupported command");
  }
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

void ServerSession::do_udp_proxy_in() {
  auto self(shared_from_this());
  asio::async_read( // receive length
    stream_, asio::buffer(in_buf_, 2), [this, self](asio::error_code ec, std::size_t length) {
      if (ec) {
        usocket_.close();
        stream_.lowest_layer().close();
        return;
      }
      length = (in_buf_[0] << 8) + in_buf_[1];
      if (length > TOMATO_BUF_SIZE) {
        usocket_.close();
        stream_.lowest_layer().close();
        return;
      }
      asio::async_read( // receive
        stream_, asio::buffer(in_buf_, length),
        [this, self](asio::error_code ec, std::size_t length) {
          if (ec) {
            usocket_.close();
            stream_.lowest_layer().close();
            return;
          }
          usocket_.async_send_to( // send
            asio::buffer(in_buf_, length), uendpoint_,
            [this, self](asio::error_code ec, std::size_t length) {
              if (ec) {
                usocket_.close();
                stream_.lowest_layer().close();
                return;
              }
              do_udp_proxy_in();
            });
        });
    });
}

void ServerSession::do_udp_proxy_out() {
  auto self(shared_from_this());
  usocket_.async_receive_from( // receive
    asio::buffer(&out_buf_[2], TOMATO_BUF_SIZE - 2), uendpoint_,
    [this, self](asio::error_code ec, std::size_t length) {
      if (ec) {
        usocket_.close();
        stream_.lowest_layer().close();
        return;
      }
      out_buf_[0] = length >> 8;
      out_buf_[1] = length;
      length += 2;
      stream_.async_write_some( // send
        asio::buffer(out_buf_, length), [this, self](asio::error_code ec, std::size_t length) {
          if (ec) {
            usocket_.close();
            stream_.lowest_layer().close();
            return;
          }
          do_udp_proxy_out();
        });
    });
}

int ServerSession::make_response(asio::ip::address address, uint16_t port) {
  int length;
  in_buf_[0] = 5;
  in_buf_[1] = 0;
  in_buf_[2] = 0;
  if (address.is_v4()) {
    length = 10;
    in_buf_[3] = 1;
    auto addr = address.to_v4().to_bytes();
    std::memcpy(&in_buf_[4], &addr[0], 4);
    in_buf_[8] = port >> 8;
    in_buf_[9] = port;
  } else if (address.is_v6()) {
    length = 22;
    in_buf_[3] = 4;
    auto addr = address.to_v6().to_bytes();
    std::memcpy(&in_buf_[4], &addr[0], 16);
    in_buf_[20] = port >> 8;
    in_buf_[21] = port;
  } else {
    LOG_ERR("handshake send unknown endpoint type");
    return -1;
  }
  return length;
}

int ServerSession::make_response(asio::ip::tcp::endpoint endpoint) {
  return make_response(endpoint.address(), endpoint.port());
}

int ServerSession::make_response(asio::ip::udp::endpoint endpoint) {
  return make_response(endpoint.address(), endpoint.port());
}

Server::Server(Config &config) : Object(config), acceptor_(config.io_context, config.server_local) {
  LOG_MSG("server", config.server_local);
  do_accept();
}

void Server::do_accept() {
  acceptor_.async_accept( // accept
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
