#include "tomato.hpp"

///////////////////////////////////////////////////////////////////////////////
//                                  RAWProxy                                 //
///////////////////////////////////////////////////////////////////////////////

RAWProxy::RAWProxy(asio::io_context &context) : isocket_(context), osocket_(context) {}
RAWProxy::RAWProxy(asio::io_context &context, asio::ip::tcp::socket &&isocket)
  : isocket_(std::move(isocket)), osocket_(context) {}
RAWProxy::RAWProxy(asio::ip::tcp::socket &&isocket, asio::ip::tcp::socket &&osocket)
  : isocket_(std::move(isocket)), osocket_(std::move(osocket)) {}

void RAWProxy::destroy() {
  asio::error_code ec;

  if (isocket_.is_open()) {
    isocket_.cancel(ec);
    SET_LINGER(isocket_);
    isocket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    isocket_.close(ec);
  }
  if (osocket_.is_open()) {
    osocket_.cancel(ec);
    SET_LINGER(osocket_);
    osocket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    osocket_.close(ec);
  }
}

void RAWProxy::do_proxy() {
  LOGTRACE(isocket_, osocket_, "PROXY");
  do_upstream();
  do_downstream();
}

void RAWProxy::do_upstream() {
  auto self(shared_from_this());
  isocket_.async_receive( // recv
    asio::buffer(ubuf_), [this, self](const asio::error_code &ec, std::size_t length) {
      asio::error_code _ec;
      if (ec) {
        if (ec == asio::error::eof) {
          osocket_.shutdown(asio::ip::tcp::socket::shutdown_send, _ec);
        } else if (ec != asio::error::operation_aborted) {
          LOGERR(ec, "PROXY RECV");
          destroy();
        }
        return;
      }
      ulen_ = length;
      asio::async_write( // send
        osocket_, asio::buffer(ubuf_, ulen_),
        [this, self](const asio::error_code &ec, std::size_t length) {
          if (ec) {
            if (ec != asio::error::operation_aborted) {
              LOGERR(ec, "PROXY SEND");
              destroy();
            }
            return;
          }
          do_upstream();
        });
    });
}

void RAWProxy::do_downstream() {
  auto self(shared_from_this());
  osocket_.async_receive( // recv
    asio::buffer(dbuf_), [this, self](const asio::error_code &ec, std::size_t length) {
      asio::error_code _ec;
      if (ec) {
        if (ec == asio::error::eof) {
          isocket_.shutdown(asio::ip::tcp::socket::shutdown_send, _ec);
        } else if (ec != asio::error::operation_aborted) {
          LOGERR(ec, "PROXY RECV");
          destroy();
        }
        return;
      }
      dlen_ = length;
      asio::async_write( // send
        isocket_, asio::buffer(dbuf_, dlen_),
        [this, self](const asio::error_code &ec, std::size_t length) {
          if (ec) {
            if (ec != asio::error::operation_aborted) {
              LOGERR(ec, "PROXY SEND");
              destroy();
            }
            return;
          }
          do_downstream();
        });
    });
}

///////////////////////////////////////////////////////////////////////////////
//                                  TLSProxy                                 //
///////////////////////////////////////////////////////////////////////////////

TLSProxy::TLSProxy(asio::io_context &io_context, asio::ssl::context &ssl_context)
  : socket_(io_context), stream_(io_context, ssl_context) {}
TLSProxy::TLSProxy(asio::io_context &io_context, asio::ssl::context &ssl_context,
                   asio::ip::tcp::socket &&socket)
  : socket_(std::move(socket)), stream_(io_context, ssl_context) {}
TLSProxy::TLSProxy(asio::io_context &io_context,
                   asio::ssl::stream<asio::ip::tcp::socket> &&stream)
  : socket_(io_context), stream_(std::move(stream)) {}
TLSProxy::TLSProxy(asio::ip::tcp::socket &&socket,
                   asio::ssl::stream<asio::ip::tcp::socket> &&stream)
  : socket_(std::move(socket)), stream_(std::move(stream)) {}

void TLSProxy::destroy() {
  asio::error_code ec;

  if (socket_.is_open()) {
    socket_.cancel(ec);
    socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    SET_LINGER(socket_);
    socket_.close(ec);
  }
  if (stream_.next_layer().is_open()) {
    stream_.next_layer().cancel(ec);
    stream_.next_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    SET_LINGER(stream_.next_layer());
    stream_.next_layer().close(ec);
  }
}

void TLSProxy::do_proxy() {
  LOGTRACE(socket_, stream_.next_layer(), "PROXY");
  do_upstream();
  do_downstream();
}

void TLSProxy::do_upstream() {
  auto self(shared_from_this());
  socket_.async_receive( // recv
    asio::buffer(ubuf_), [this, self](const asio::error_code &ec, std::size_t length) {
      if (ec) {
        if (ec == asio::error::eof) {
          stream_.async_shutdown( // shutdown
            [this, self](const asio::error_code &ec) {
              if (ec) {
                if (ec != asio::error::operation_aborted) {
                  LOGERR(ec, "TLS_SHUTDOWN");
                  destroy();
                }
                return;
              }
            });
        } else if (ec != asio::error::operation_aborted) {
          LOGERR(ec, "PROXY RECV");
          destroy();
        }
        return;
      }
      ulen_ = length;
      asio::async_write( // send
        stream_, asio::buffer(ubuf_, ulen_),
        [this, self](const asio::error_code &ec, std::size_t length) {
          if (ec) {
            if (ec != asio::error::operation_aborted) {
              LOGERR(ec, "PROXY SEND");
              destroy();
            }
            return;
          }
          do_upstream();
        });
    });
}

void TLSProxy::do_downstream() {
  auto self(shared_from_this());
  stream_.async_read_some( // recv
    asio::buffer(dbuf_), [this, self](const asio::error_code &ec, std::size_t length) {
      asio::error_code _ec;
      if (ec) {
        if (ec == asio::error::eof) {
          socket_.shutdown(asio::ip::tcp::socket::shutdown_send, _ec);
        } else if (ec != asio::error::operation_aborted) {
          LOGERR(ec, "PROXY RECV");
          destroy();
        }
        return;
      }
      dlen_ = length;
      asio::async_write( // send
        socket_, asio::buffer(dbuf_, dlen_),
        [this, self](const asio::error_code &ec, std::size_t length) {
          if (ec) {
            if (ec != asio::error::operation_aborted) {
              LOGERR(ec, "PROXY SEND");
              destroy();
            }
            return;
          }
          do_downstream();
        });
    });
}
