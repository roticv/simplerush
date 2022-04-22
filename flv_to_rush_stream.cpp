#include <iostream>

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <vector>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <ev.h>

#include "flv/Flv.h"
#include "flv/FlvIo.h"
#include "lib/RushMuxer.h"

#define REMOTE_HOST "live-upload-staging.facebook.com"
#define REMOTE_PORT "443"
// rush draft says rush, but currently fbvp is the expected ALPN
unsigned char alpnlist[] = {0x04, 'f', 'b', 'v', 'p'};
size_t alpnlistlen = 5;

using namespace rush;

static uint64_t timestamp(void) {
  struct timespec tp;

  if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
    fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

static int create_sock(
    struct sockaddr* addr,
    socklen_t* paddrlen,
    const char* host,
    const char* port) {
  struct addrinfo hints = {0};
  struct addrinfo *res, *rp;
  int rv;
  int fd = -1;

  hints.ai_flags = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  rv = getaddrinfo(host, port, &hints, &res);
  if (rv != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return -1;
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

  *paddrlen = rp->ai_addrlen;
  memcpy(addr, rp->ai_addr, rp->ai_addrlen);

end:
  freeaddrinfo(res);

  return fd;
}

static int connect_sock(
    struct sockaddr* local_addr,
    socklen_t* plocal_addrlen,
    int fd,
    const struct sockaddr* remote_addr,
    size_t remote_addrlen) {
  socklen_t len;

  if (connect(fd, remote_addr, (socklen_t)remote_addrlen) != 0) {
    fprintf(stderr, "connect: %s\n", strerror(errno));
    return -1;
  }

  len = *plocal_addrlen;

  if (getsockname(fd, local_addr, &len) == -1) {
    fprintf(stderr, "getsockname: %s\n", strerror(errno));
    return -1;
  }

  *plocal_addrlen = len;

  return 0;
}

struct client {
  int fd;
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
  SSL_CTX* ssl_ctx;
  SSL* ssl;
  ngtcp2_conn* conn;
  RushMuxer muxer{1000, 1000};
  std::string connect_payload;

  struct {
    int64_t stream_id;
    std::vector<uint8_t> data;
    std::vector<uint8_t> media;
    size_t nwrite;
  } stream;

  ngtcp2_connection_close_error last_error;

  ev_io rev;
  ev_timer timer;
};

static int set_encryption_secrets(
    SSL* ssl,
    OSSL_ENCRYPTION_LEVEL ossl_level,
    const uint8_t* rx_secret,
    const uint8_t* tx_secret,
    size_t secretlen) {
  struct client* c = (struct client*)SSL_get_app_data(ssl);
  ngtcp2_crypto_level level =
      ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);

  if (rx_secret &&
      ngtcp2_crypto_derive_and_install_rx_key(
          c->conn, NULL, NULL, NULL, level, rx_secret, secretlen) != 0) {
    fprintf(stderr, "ngtcp2_crypto_derive_and_install_rx_key failed\n");
    return 0;
  }

  if (ngtcp2_crypto_derive_and_install_tx_key(
          c->conn, NULL, NULL, NULL, level, tx_secret, secretlen) != 0) {
    fprintf(stderr, "ngtcp2_crypto_derive_and_install_tx_key failed\n");
    return 0;
  }

  return 1;
}

static int add_handshake_data(
    SSL* ssl,
    OSSL_ENCRYPTION_LEVEL ossl_level,
    const uint8_t* data,
    size_t len) {
  struct client* c = (struct client*)SSL_get_app_data(ssl);
  ngtcp2_crypto_level level =
      ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);
  int rv;

  rv = ngtcp2_conn_submit_crypto_data(c->conn, level, data, len);
  if (rv != 0) {
    fprintf(
        stderr, "ngtcp2_conn_submit_crypto_data: %s\n", ngtcp2_strerror(rv));
    return 0;
  }

  return 1;
}

static int flush_flight(SSL* ssl) {
  (void)ssl;
  return 1;
}

static int
send_alert(SSL* ssl, OSSL_ENCRYPTION_LEVEL ossl_level, uint8_t alert) {
  struct client* c = (struct client*)SSL_get_app_data(ssl);
  (void)ossl_level;

  ngtcp2_connection_close_error_set_transport_error_tls_alert(
      &c->last_error, alert, NULL, 0);

  return 1;
}

static SSL_QUIC_METHOD quic_method = {
    set_encryption_secrets,
    add_handshake_data,
    flush_flight,
    send_alert,
};

static int numeric_host_family(const char* hostname, int family) {
  uint8_t dst[sizeof(struct in6_addr)];
  return inet_pton(family, hostname, dst) == 1;
}

static int numeric_host(const char* hostname) {
  return numeric_host_family(hostname, AF_INET) ||
         numeric_host_family(hostname, AF_INET6);
}

static int client_ssl_init(struct client* c) {
  c->ssl_ctx = SSL_CTX_new(TLS_client_method());
  if (!c->ssl_ctx) {
    fprintf(
        stderr, "SSL_CTX_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }

  SSL_CTX_set_min_proto_version(c->ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(c->ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_quic_method(c->ssl_ctx, &quic_method);

  c->ssl = SSL_new(c->ssl_ctx);
  if (!c->ssl) {
    fprintf(stderr, "SSL_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
    return -1;
  }

  SSL_set_app_data(c->ssl, c);
  SSL_set_connect_state(c->ssl);
  SSL_set_alpn_protos(c->ssl, (const unsigned char*)alpnlist, alpnlistlen);
  if (!numeric_host(REMOTE_HOST)) {
    SSL_set_tlsext_host_name(c->ssl, REMOTE_HOST);
  }

  // we are using "quic v1" and so we need to set quic transport version to
  // correct value
  SSL_set_quic_transport_version(c->ssl, TLSEXT_TYPE_quic_transport_parameters);

  return 0;
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
  struct client* c = (struct client*)user_data;
  int rv;
  int64_t stream_id;
  (void)max_streams;

  if (c->stream.stream_id != -1) {
    return 0;
  }

  rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
  if (rv != 0) {
    return 0;
  }

  c->stream.stream_id = stream_id;
  c->stream.data = c->muxer.createConnectPayload(c->connect_payload);

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

static int client_quic_init(
    struct client* c,
    const struct sockaddr* remote_addr,
    socklen_t remote_addrlen,
    const struct sockaddr* local_addr,
    socklen_t local_addrlen) {
  ngtcp2_path path = {
      {
          (struct sockaddr*)local_addr,
          local_addrlen,
      },
      {
          (struct sockaddr*)remote_addr,
          remote_addrlen,
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
      NULL, /* recv_stream_data */
      NULL, /* acked_stream_data_offset */
      NULL, /* stream_open */
      NULL, /* stream_close */
      NULL, /* recv_stateless_reset */
      ngtcp2_crypto_recv_retry_cb,
      extend_max_local_streams_bidi,
      NULL, /* extend_max_local_streams_uni */
      rand_cb,
      get_new_connection_id_cb,
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
    return -1;
  }

  scid.datalen = 8;
  if (RAND_bytes(scid.data, (int)scid.datalen) != 1) {
    fprintf(stderr, "RAND_bytes failed\n");
    return -1;
  }

  ngtcp2_settings_default(&settings);

  settings.initial_ts = timestamp();
  settings.log_printf = log_printf;
  settings.handshake_timeout = 10 * NGTCP2_SECONDS;
  settings.initial_rtt = NGTCP2_DEFAULT_INITIAL_RTT;

  ngtcp2_transport_params_default(&params);

  params.initial_max_streams_uni = 3;
  params.initial_max_streams_bidi = 3;
  params.initial_max_stream_data_bidi_local = 1024 * 1024;
  params.initial_max_data = 5 * 1024 * 1024;
  params.max_idle_timeout = 300 * NGTCP2_SECONDS;

  // changed to NGTCP2_PROTO_VER_V2_DRAFT (instead of NGTCP2_PROTO_VER_V1)
  rv = ngtcp2_conn_client_new(
      &c->conn,
      &dcid,
      &scid,
      &path,
      NGTCP2_PROTO_VER_V1,
      &callbacks,
      &settings,
      &params,
      NULL,
      c);
  if (rv != 0) {
    fprintf(stderr, "ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
    return -1;
  }

  ngtcp2_conn_set_tls_native_handle(c->conn, c->ssl);

  return 0;
}

static int client_read(struct client* c) {
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

    nread = recvmsg(c->fd, &msg, MSG_DONTWAIT);

    if (nread == -1) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        fprintf(stderr, "recvmsg: %s\n", strerror(errno));
      }

      break;
    }

    path.local.addrlen = c->local_addrlen;
    path.local.addr = (struct sockaddr*)&c->local_addr;
    path.remote.addrlen = msg.msg_namelen;
    path.remote.addr = (struct sockaddr*)msg.msg_name;

    rv = ngtcp2_conn_read_pkt(
        c->conn, &path, &pi, buf, (size_t)nread, timestamp());
    if (rv != 0) {
      fprintf(stderr, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
      switch (rv) {
        case NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM:
        case NGTCP2_ERR_MALFORMED_TRANSPORT_PARAM:
        case NGTCP2_ERR_TRANSPORT_PARAM:
        case NGTCP2_ERR_PROTO:
          ngtcp2_connection_close_error_set_transport_error_liberr(
              &c->last_error, rv, NULL, 0);
          break;
        default:
          if (!c->last_error.error_code) {
            ngtcp2_connection_close_error_set_transport_error_liberr(
                &c->last_error, rv, NULL, 0);
          }
          break;
      }
      return -1;
    }
  }

  return 0;
}

static int
client_send_packet(struct client* c, const uint8_t* data, size_t datalen) {
  struct iovec iov = {(uint8_t*)data, datalen};
  struct msghdr msg = {0};
  ssize_t nwrite;

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  do {
    nwrite = sendmsg(c->fd, &msg, 0);
  } while (nwrite == -1 && errno == EINTR);

  if (nwrite == -1) {
    fprintf(stderr, "sendmsg: %s\n", strerror(errno));

    return -1;
  }

  return 0;
}

static size_t client_get_message(
    struct client* c,
    int64_t* pstream_id,
    int* pfin,
    ngtcp2_vec* datav,
    size_t datavcnt) {
  if (datavcnt == 0) {
    return 0;
  }

  if (c->stream.stream_id != -1) {
    *pstream_id = c->stream.stream_id;
    *pfin = 0;
    if (c->stream.nwrite < c->stream.data.size()) {
      datav->base = (uint8_t*)c->stream.data.data() + c->stream.nwrite;
      datav->len = c->stream.data.size() - c->stream.nwrite;
    } else {
      datav->base = (uint8_t*)c->stream.media.data() + c->stream.nwrite -
                    c->stream.data.size();
      datav->len =
          c->stream.media.size() - (c->stream.nwrite - c->stream.data.size());
    }
    return 1;
  }

  *pstream_id = -1;
  *pfin = 0;
  datav->base = NULL;
  datav->len = 0;

  return 0;
}

static int client_write_streams(struct client* c) {
  ngtcp2_tstamp ts = timestamp();
  ngtcp2_pkt_info pi;
  ngtcp2_ssize nwrite;
  uint8_t buf[1280];
  ngtcp2_path_storage ps;
  ngtcp2_vec datav;
  size_t datavcnt;
  int64_t stream_id;
  ngtcp2_ssize wdatalen;
  uint32_t flags;
  int fin;

  ngtcp2_path_storage_zero(&ps);

  for (;;) {
    datavcnt = client_get_message(c, &stream_id, &fin, &datav, 1);

    flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
    if (fin) {
      flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }

    nwrite = ngtcp2_conn_writev_stream(
        c->conn,
        &ps.path,
        &pi,
        buf,
        sizeof(buf),
        &wdatalen,
        flags,
        stream_id,
        &datav,
        datavcnt,
        ts);
    if (nwrite < 0) {
      switch (nwrite) {
        case NGTCP2_ERR_WRITE_MORE:
          c->stream.nwrite += (size_t)wdatalen;
          continue;
        default:
          fprintf(
              stderr,
              "ngtcp2_conn_writev_stream: %s\n",
              ngtcp2_strerror((int)nwrite));
          ngtcp2_connection_close_error_set_transport_error_liberr(
              &c->last_error, (int)nwrite, NULL, 0);
          return -1;
      }
    }

    if (nwrite == 0) {
      return 0;
    }

    if (wdatalen > 0) {
      c->stream.nwrite += (size_t)wdatalen;
    }

    if (client_send_packet(c, buf, (size_t)nwrite) != 0) {
      break;
    }
  }

  return 0;
}

static int client_write(struct client* c) {
  ngtcp2_tstamp expiry, now;
  ev_tstamp t;

  if (client_write_streams(c) != 0) {
    return -1;
  }

  expiry = ngtcp2_conn_get_expiry(c->conn);
  now = timestamp();

  t = expiry < now ? 1e-9 : (ev_tstamp)(expiry - now) / NGTCP2_SECONDS;

  c->timer.repeat = t;
  ev_timer_again(EV_DEFAULT, &c->timer);

  return 0;
}

static int client_handle_expiry(struct client* c) {
  int rv = ngtcp2_conn_handle_expiry(c->conn, timestamp());
  if (rv != 0) {
    fprintf(stderr, "ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror(rv));
    return -1;
  }

  return 0;
}

static void client_close(struct client* c) {
  ngtcp2_ssize nwrite;
  ngtcp2_pkt_info pi;
  ngtcp2_path_storage ps;
  uint8_t buf[1280];

  if (ngtcp2_conn_is_in_closing_period(c->conn) ||
      ngtcp2_conn_is_in_draining_period(c->conn)) {
    goto fin;
  }

  ngtcp2_path_storage_zero(&ps);

  nwrite = ngtcp2_conn_write_connection_close(
      c->conn, &ps.path, &pi, buf, sizeof(buf), &c->last_error, timestamp());
  if (nwrite < 0) {
    fprintf(
        stderr,
        "ngtcp2_conn_write_connection_close: %s\n",
        ngtcp2_strerror((int)nwrite));
    goto fin;
  }

  client_send_packet(c, buf, (size_t)nwrite);

fin:
  ev_break(EV_DEFAULT, EVBREAK_ALL);
}

static void read_cb(struct ev_loop* loop, ev_io* w, int revents) {
  struct client* c = (struct client*)w->data;
  (void)loop;
  (void)revents;

  if (client_read(c) != 0) {
    client_close(c);
    return;
  }

  if (client_write(c) != 0) {
    client_close(c);
  }
}

static void timer_cb(struct ev_loop* loop, ev_timer* w, int revents) {
  struct client* c = (struct client*)w->data;
  (void)loop;
  (void)revents;

  if (client_handle_expiry(c) != 0) {
    client_close(c);
    return;
  }

  if (client_write(c) != 0) {
    client_close(c);
  }
}

static int client_init(struct client* c, const std::string& connect_payload) {
  struct sockaddr_storage remote_addr, local_addr;
  socklen_t remote_addrlen, local_addrlen = sizeof(local_addr);

  memset(c, 0, sizeof(*c));
  c->connect_payload = connect_payload;
  c->muxer = RushMuxer(1000, 1000);

  ngtcp2_connection_close_error_default(&c->last_error);

  c->fd = create_sock(
      (struct sockaddr*)&remote_addr,
      &remote_addrlen,
      REMOTE_HOST,
      REMOTE_PORT);
  if (c->fd == -1) {
    return -1;
  }

  if (connect_sock(
          (struct sockaddr*)&local_addr,
          &local_addrlen,
          c->fd,
          (struct sockaddr*)&remote_addr,
          remote_addrlen) != 0) {
    return -1;
  }

  memcpy(&c->local_addr, &local_addr, sizeof(c->local_addr));
  c->local_addrlen = local_addrlen;

  if (client_ssl_init(c) != 0) {
    return -1;
  }

  if (client_quic_init(
          c,
          (struct sockaddr*)&remote_addr,
          remote_addrlen,
          (struct sockaddr*)&local_addr,
          local_addrlen) != 0) {
    return -1;
  }

  c->stream.stream_id = -1;

  ev_io_init(&c->rev, read_cb, c->fd, EV_READ);
  c->rev.data = c;
  ev_io_start(EV_DEFAULT, &c->rev);

  ev_timer_init(&c->timer, timer_cb, 0., 0.);
  c->timer.data = c;

  return 0;
}

static void client_free(struct client* c) {
  ngtcp2_conn_del(c->conn);
  SSL_free(c->ssl);
  SSL_CTX_free(c->ssl_ctx);
}

std::vector<std::shared_ptr<FlvTag>> process_flv(const std::string& filename) {
  std::vector<std::shared_ptr<FlvTag>> tags;
  FileReader reader(filename);
  FlvHeader h(&reader);

  auto prevTagSize = reader.read32bit();
  while (true) {
    auto tag = FlvTag::parse(&reader);
    if (tag == nullptr) {
      break;
    }
    tags.emplace_back(tag);
    prevTagSize = reader.read32bit();
  }
  return tags;
}

void generate_media_payload(
    struct client* c, const std::vector<std::shared_ptr<FlvTag>>& tags) {
  for (const auto& tag : tags) {
    if (tag->getTagType() == FLVTAGTYPE::AUDIO) {
      // Skipping logic to check for AAC, assuming AAC
      auto audioTag = std::dynamic_pointer_cast<FlvTagAudioData>(tag);
      if (audioTag->getPacketType() == 0) {
        // AudioHeader, AudioSpecificConfig
        c->muxer.setAACAudioSpecificConfig(
            audioTag->getAudioData(), audioTag->getAudioDataSize());
      }
    } else if (tag->getTagType() == FLVTAGTYPE::VIDEO) {
      // Skipping logic to check for H264, assuming H264
      auto videoTag = std::dynamic_pointer_cast<FlvTagVideoData>(tag);
      if (videoTag->getPacketType() == 0) {
        // VideoHeader, AVCDecoderConfig
        c->muxer.setAVCDecoderConfig(
            videoTag->getVideoData(), videoTag->getVideoDataSize());
      }
    }
  }

  for (const auto& tag : tags) {
    if (tag->getTagType() == FLVTAGTYPE::AUDIO) {
      auto audioTag = std::dynamic_pointer_cast<FlvTagAudioData>(tag);
      if (audioTag->getPacketType() == 1) {
        // AudioData
        auto rushAudioData = c->muxer.createAudioPayload(
            audioTag->getTimestamp(),
            audioTag->getAudioData(),
            audioTag->getAudioDataSize());
        c->stream.media.insert(
            c->stream.media.end(), rushAudioData.begin(), rushAudioData.end());
      }
    } else if (tag->getTagType() == FLVTAGTYPE::VIDEO) {
      auto videoTag = std::dynamic_pointer_cast<FlvTagVideoData>(tag);
      if (videoTag->getPacketType() != 0) {
        // VideoData
        int64_t dts = videoTag->getTimestamp();
        int64_t pts = dts + videoTag->getCompositionTimestamp();
        auto rushVideoData = c->muxer.createVideoPayload(
            pts, dts, videoTag->getVideoData(), videoTag->getVideoDataSize());
        c->stream.media.insert(
            c->stream.media.end(), rushVideoData.begin(), rushVideoData.end());
      }
    }
  }
}

void print_usage() {
  // TODO
  printf("./flv_to_rush_stream <example.flv> <connect_payload>\n");
}

int main(int argc, char* argv[]) {
  std::string flv_filename;
  std::string connect_payload;
  if (argc < 3) {
    print_usage();
    return 0;
  }

  flv_filename.assign(argv[1]);
  connect_payload.assign(argv[2]);

  auto tags = process_flv(flv_filename);
  if (tags.size() == 0) {
    printf("Failed to process flv: %s\n", flv_filename.c_str());
    return 0;
  }
  struct client c;

  srandom((unsigned int)timestamp());

  if (client_init(&c, connect_payload) != 0) {
    exit(EXIT_FAILURE);
  }

  generate_media_payload(&c, tags);

  if (client_write(&c) != 0) {
    exit(EXIT_FAILURE);
  }

  ev_run(EV_DEFAULT, 0);

  client_free(&c);

  return 0;
}
