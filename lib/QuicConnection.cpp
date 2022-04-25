#include "lib/QuicConnection.h"

#include <netdb.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <sys/types.h>

// QUIC's maximum packet size according to rfc9000
#define kMaxPacketLengthIPv4 1252
#define kMaxPacketLengthIPv6 1232

namespace rush {

namespace {

static uint64_t timestamp(void) {
  struct timespec tp;

  if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
    fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

static void
rand_cb(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* rand_ctx) {
  size_t i;
  (void)rand_ctx;

  for (i = 0; i < destlen; ++i) {
    *dest = (uint8_t)random();
  }
}

static int get_new_connection_id_cb(
    ngtcp2_conn* conn,
    ngtcp2_cid* cid,
    uint8_t* token,
    size_t cidlen,
    void* user_data) {
  (void)conn;
  (void)user_data;

  if (RAND_bytes(cid->data, (int)cidlen) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  cid->datalen = cidlen;

  if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int extend_max_local_streams_bidi(
    ngtcp2_conn* conn, uint64_t max_streams, void* user_data) {
  QuicConnection* c = (QuicConnection*)user_data;
  int rv;
  int64_t streamId;
  (void)max_streams;

  // For now open only one stream
  if (c->getStreamId() != -1) {
    return 0;
  }

  rv = ngtcp2_conn_open_bidi_stream(conn, &streamId, NULL);
  if (rv != 0) {
    return 0;
  }

  c->setStreamId(streamId);

  return 0;
}

static int recv_stream_data_cb(
    ngtcp2_conn* conn,
    uint32_t flags,
    int64_t stream_id,
    uint64_t offset,
    const uint8_t* data,
    size_t datalen,
    void* user_data,
    void* stream_user_data) {
  printf("recv_stream_data offset %llu, datalen: %lu\n", offset, datalen);
  for (int i = 0; i < datalen; ++i) {
    printf("%02x", data[i]);
  }
  printf("\n");

  return 0;
}

static void log_printf(void* user_data, const char* fmt, ...) {
  va_list ap;
  (void)user_data;

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  fprintf(stderr, "\n");
}

static void read_cb(struct ev_loop* loop, ev_io* w, int revents) {
  QuicConnection* connection = (QuicConnection*)w->data;
  (void)loop;
  (void)revents;

  if (!connection->onUdpSocketBytesAvailable()) {
    connection->closeConnection();
    return;
  }

  if (!connection->tryWriteToNgtcp2()) {
    connection->closeConnection();
  }
}

static void timer_cb(struct ev_loop* loop, ev_timer* w, int revents) {
  QuicConnection* connection = (QuicConnection*)w->data;
  (void)loop;
  (void)revents;

  if (!connection->handleExpiry()) {
    connection->closeConnection();
    return;
  }

  if (!connection->tryWriteToNgtcp2()) {
    connection->closeConnection();
  }
}

} // namespace

// Two phase construction because of how ngtcp2_conn_client_new would need to
//
std::unique_ptr<QuicConnection> QuicConnection::make(
    const QuicConnectionCallbacks& callbacks,
    struct ev_loop* loop,
    const std::string& remoteHost,
    uint32_t port,
    const std::vector<std::string>& alpns) {
  std::unique_ptr<QuicConnection> connection(
      new QuicConnection(callbacks, loop));
  if (!connection->setupUdpSocket(remoteHost.c_str(), port)) {
    fprintf(stderr, "Failed to setup udp socket\n");
    return nullptr;
  }
  if (!connection->connectSocket()) {
    fprintf(stderr, "Failed to connect udp socket\n");
    return nullptr;
  }
  if (!connection->setupNgtcp2()) {
    fprintf(stderr, "Failed to setup ngtcp2\n");
    return nullptr;
  }
  auto handshake = TLSHandshake::make(connection->conn_, remoteHost, alpns);
  if (!handshake) {
    fprintf(stderr, "Failed to create TLS handshake\n");
    return nullptr;
  }
  ngtcp2_conn_set_tls_native_handle(connection->conn_, handshake->getSSL());
  connection->setHandshake(std::move(handshake));

  connection->setupEv();
  return std::move(connection);
}

QuicConnection::QuicConnection(
    const QuicConnectionCallbacks& callbacks, struct ev_loop* loop)
  : callbacks_(callbacks), loop_(loop) {}

QuicConnection::~QuicConnection() {
  if (conn_) {
    ngtcp2_conn_del(conn_);
  }
}

// Sets the following fields:
// 1. remoteAddr_
// 2. remoteAddrLen_
// 3. fd_
// 4. maxUdpPacketSize_
bool QuicConnection::setupUdpSocket(const char* host, uint32_t port) {
  struct addrinfo hints = {0};
  struct addrinfo *res, *rp;
  int rv;
  int fd = -1;

  hints.ai_flags = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  char portStr[8];
  sprintf(portStr, "%d", port);

  rv = getaddrinfo(host, portStr, &hints, &res);
  if (rv != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return false;
  }

  for (rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1) {
      continue;
    }

    break;
  }

  if (fd == -1) {
    goto end;
  }

  switch (rp->ai_family) {
    case AF_INET:
      maxUdpPacketSize_ = kMaxPacketLengthIPv4;
      break;
    case AF_INET6:
      maxUdpPacketSize_ = kMaxPacketLengthIPv6;
      break;
  }

  remoteAddrLen_ = rp->ai_addrlen;
  memcpy(&remoteAddr_, rp->ai_addr, rp->ai_addrlen);

end:
  freeaddrinfo(res);

  fd_ = fd;
  return fd != -1;
}

// Sets up the following fields:
// 1. localAddr_
// 2. localAddrLen_
// and calls connect on the udp socket
bool QuicConnection::connectSocket() {
  socklen_t len = sizeof(localAddr_);

  if (::connect(fd_, (struct sockaddr*)&remoteAddr_, remoteAddrLen_) != 0) {
    fprintf(stderr, "connect: %s\n", strerror(errno));
    return false;
  }

  if (::getsockname(fd_, (struct sockaddr*)&localAddr_, &len) == -1) {
    fprintf(stderr, "getsockname: %s\n", strerror(errno));
    return false;
  }

  localAddrLen_ = len;

  return true;
}

bool QuicConnection::setupNgtcp2() {
  ngtcp2_path path = {
      {
          (struct sockaddr*)&localAddr_,
          localAddrLen_,
      },
      {
          (struct sockaddr*)&remoteAddr_,
          remoteAddrLen_,
      },
      NULL,
  };
  ngtcp2_callbacks callbacks = {
      ngtcp2_crypto_client_initial_cb,
      NULL, /* recv_client_initial */
      ngtcp2_crypto_recv_crypto_data_cb,
      NULL, /* handshake_completed */
      NULL, /* recv_version_negotiation */
      ngtcp2_crypto_encrypt_cb,
      ngtcp2_crypto_decrypt_cb,
      ngtcp2_crypto_hp_mask_cb,
      rush::recv_stream_data_cb,
      NULL, /* acked_stream_data_offset */
      NULL, /* stream_open */
      NULL, /* stream_close */
      NULL, /* recv_stateless_reset */
      ngtcp2_crypto_recv_retry_cb,
      rush::extend_max_local_streams_bidi,
      NULL, /* extend_max_local_streams_uni */
      rush::rand_cb,
      rush::get_new_connection_id_cb,
      NULL, /* remove_connection_id */
      ngtcp2_crypto_update_key_cb,
      NULL, /* path_validation */
      NULL, /* select_preferred_address */
      NULL, /* stream_reset */
      NULL, /* extend_max_remote_streams_bidi */
      NULL, /* extend_max_remote_streams_uni */
      NULL, /* extend_max_stream_data */
      NULL, /* dcid_status */
      NULL, /* handshake_confirmed */
      NULL, /* recv_new_token */
      ngtcp2_crypto_delete_crypto_aead_ctx_cb,
      ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
      NULL, /* recv_datagram */
      NULL, /* ack_datagram */
      NULL, /* lost_datagram */
      ngtcp2_crypto_get_path_challenge_data_cb,
      NULL, /* stream_stop_sending */
      ngtcp2_crypto_version_negotiation_cb,
  };
  ngtcp2_cid dcid, scid;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  int rv;

  dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
  if (RAND_bytes(dcid.data, (int)dcid.datalen) != 1) {
    fprintf(stderr, "RAND_bytes failed\n");
    return false;
  }

  scid.datalen = 8;
  if (RAND_bytes(scid.data, (int)scid.datalen) != 1) {
    fprintf(stderr, "RAND_bytes failed\n");
    return false;
  }

  ngtcp2_settings_default(&settings);

  settings.initial_ts = timestamp();
  settings.log_printf = log_printf;
  settings.handshake_timeout = 10 * NGTCP2_SECONDS;
  settings.initial_rtt = NGTCP2_DEFAULT_INITIAL_RTT;
  settings.max_udp_payload_size = maxUdpPacketSize_;
  settings.no_udp_payload_size_shaping = 1;

  ngtcp2_transport_params_default(&params);

  params.initial_max_streams_uni = 3;
  params.initial_max_streams_bidi = 3;
  params.initial_max_stream_data_bidi_local = 1024 * 1024;
  params.initial_max_data = 5 * 1024 * 1024;
  params.max_idle_timeout = 300 * NGTCP2_SECONDS;

  rv = ngtcp2_conn_client_new(
      &conn_,
      &dcid,
      &scid,
      &path,
      NGTCP2_PROTO_VER_V1,
      &callbacks,
      &settings,
      &params,
      NULL,
      this);
  if (rv != 0) {
    fprintf(stderr, "ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
    return false;
  }

  return true;
}

void QuicConnection::setupEv() {
  ev_io_init(&rev_, read_cb, fd_, EV_READ);
  rev_.data = this;
  ev_io_start(loop_, &rev_);

  ev_timer_init(&timer_, timer_cb, 0., 0.);
  timer_.data = this;
}

void QuicConnection::setHandshake(std::unique_ptr<TLSHandshake> handshake) {
  handshake_ = std::move(handshake);
}

void QuicConnection::setStreamId(int64_t streamId) { streamId_ = streamId; }

int64_t QuicConnection::getStreamId() const { return streamId_; }

bool QuicConnection::onUdpSocketBytesAvailable() {
  uint8_t buf[65536];
  struct sockaddr_storage addr;
  struct iovec iov = {buf, sizeof(buf)};
  struct msghdr msg = {0};
  ssize_t nread;
  ngtcp2_path path;
  ngtcp2_pkt_info pi = {0};
  int rv;

  msg.msg_name = &addr;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  for (;;) {
    msg.msg_namelen = sizeof(addr);

    nread = ::recvmsg(fd_, &msg, MSG_DONTWAIT);

    if (nread == -1) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        fprintf(stderr, "recvmsg: %s\n", strerror(errno));
      }

      break;
    }

    path.local.addrlen = localAddrLen_;
    path.local.addr = (struct sockaddr*)&localAddr_;
    path.remote.addrlen = msg.msg_namelen;
    path.remote.addr = (struct sockaddr*)msg.msg_name;

    rv = ngtcp2_conn_read_pkt(
        conn_, &path, &pi, buf, (size_t)nread, timestamp());
    if (rv != 0) {
      fprintf(stderr, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
      switch (rv) {
        case NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM:
        case NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM:
        case NGTCP2_ERR_TRANSPORT_PARAM:
        case NGTCP2_ERR_PROTO:
          // TODO
          /*ngtcp2_connection_close_error_set_transport_error_liberr(
              &c->last_error, rv, NULL, 0);*/
          break;
        default:
          // TODO
          /*if (!c->last_error.error_code) {
            ngtcp2_connection_close_error_set_transport_error_liberr(
                &c->last_error, rv, NULL, 0);
          }*/
          break;
      }
      return false;
    }
  }
  return true;
}

bool QuicConnection::tryWriteToNgtcp2() {
  if (!tryWriteStream()) {
    return false;
  }

  ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(conn_);
  ngtcp2_tstamp now = timestamp();

  ev_tstamp t =
      (expiry < now) ? 1e-9 : (ev_tstamp)(expiry - now) / NGTCP2_SECONDS;

  timer_.repeat = t;
  ev_timer_again(loop_, &timer_);

  return true;
}

bool QuicConnection::tryWriteStream() {
  ngtcp2_tstamp ts = timestamp();
  ngtcp2_pkt_info pi;
  ngtcp2_ssize nwrite;
  uint8_t buf[12800];
  ngtcp2_path_storage ps;
  ngtcp2_vec datav;
  size_t datavcnt;
  int64_t streamId;
  ngtcp2_ssize wdatalen;
  uint32_t flags;
  int fin;

  ngtcp2_path_storage_zero(&ps);

  for (;;) {
    datavcnt = callbacks_.onStreamWritable(
        &streamId, &fin, &datav, 1, callbacks_.context);

    flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin) {
      flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }

    nwrite = ngtcp2_conn_writev_stream(
        conn_,
        &ps.path,
        &pi,
        buf,
        sizeof(buf),
        &wdatalen,
        flags,
        streamId,
        &datav,
        datavcnt,
        ts);
    if (nwrite < 0) {
      switch (nwrite) {
        case NGTCP2_ERR_WRITE_MORE:
          callbacks_.onStreamDataFramed(streamId, wdatalen, callbacks_.context);
          continue;
        default:
          fprintf(
              stderr,
              "ngtcp2_conn_writev_stream: %s\n",
              ngtcp2_strerror((int)nwrite));
          /*ngtcp2_connection_close_error_set_transport_error_liberr(
              &c->last_error, (int)nwrite, NULL, 0);*/
          return false;
      }
    }

    if (nwrite == 0) {
      return true;
    }

    if (wdatalen > 0) {
      callbacks_.onStreamDataFramed(streamId, wdatalen, callbacks_.context);
    }

    if (!sendUdpDatagram(buf, (size_t)nwrite)) {
      break;
    }
  }

  return true;
}

bool QuicConnection::sendUdpDatagram(const uint8_t* data, size_t datalen) {
  struct iovec iov = {(uint8_t*)data, datalen};
  struct msghdr msg = {0};
  ssize_t nwrite;

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  do {
    nwrite = ::sendmsg(fd_, &msg, 0);
  } while (nwrite == -1 && errno == EINTR);

  if (nwrite == -1) {
    fprintf(stderr, "sendmsg: %s\n", strerror(errno));

    return false;
  }

  return true;
}

bool QuicConnection::handleExpiry() {
  int rv = ngtcp2_conn_handle_expiry(conn_, timestamp());
  if (rv != 0) {
    fprintf(stderr, "ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror(rv));
    return false;
  }

  return true;
}

void QuicConnection::closeConnection() {
  ngtcp2_ssize nwrite;
  ngtcp2_pkt_info pi;
  ngtcp2_path_storage ps;
  uint8_t buf[1280];

  if (ngtcp2_conn_is_in_closing_period(conn_) ||
      ngtcp2_conn_is_in_draining_period(conn_)) {
    goto fin;
  }

  ngtcp2_path_storage_zero(&ps);

  // TODO last_error
  ngtcp2_connection_close_error last_error;
  nwrite = ngtcp2_conn_write_connection_close(
      conn_, &ps.path, &pi, buf, sizeof(buf), &last_error, timestamp());
  if (nwrite < 0) {
    fprintf(
        stderr,
        "ngtcp2_conn_write_connection_close: %s\n",
        ngtcp2_strerror((int)nwrite));
    goto fin;
  }

  sendUdpDatagram(buf, (size_t)nwrite);

fin:
  ev_break(loop_, EVBREAK_ALL);
}
} // namespace rush
