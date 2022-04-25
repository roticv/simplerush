#include "lib/TLSHandshake.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>
#include <openssl/err.h>

namespace rush {

namespace {
static int set_encryption_secrets(
    SSL* ssl,
    OSSL_ENCRYPTION_LEVEL ossl_level,
    const uint8_t* rx_secret,
    const uint8_t* tx_secret,
    size_t secretlen) {
  ngtcp2_conn* conn = (ngtcp2_conn*)SSL_get_app_data(ssl);
  ngtcp2_crypto_level level =
      ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);

  if (rx_secret &&
      ngtcp2_crypto_derive_and_install_rx_key(
          conn, NULL, NULL, NULL, level, rx_secret, secretlen) != 0) {
    fprintf(stderr, "ngtcp2_crypto_derive_and_install_rx_key failed\n");
    return 0;
  }

  if (ngtcp2_crypto_derive_and_install_tx_key(
          conn, NULL, NULL, NULL, level, tx_secret, secretlen) != 0) {
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
  ngtcp2_conn* conn = (ngtcp2_conn*)SSL_get_app_data(ssl);
  ngtcp2_crypto_level level =
      ngtcp2_crypto_openssl_from_ossl_encryption_level(ossl_level);
  int rv;

  rv = ngtcp2_conn_submit_crypto_data(conn, level, data, len);
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
  ngtcp2_conn* c = (ngtcp2_conn*)SSL_get_app_data(ssl);
  (void)ossl_level;

  // TODO
  // ngtcp2_connection_close_error_set_transport_error_tls_alert(
  //     &c->last_error, alert, NULL, 0);

  return 1;
}

static SSL_QUIC_METHOD quic_method = {
    set_encryption_secrets,
    add_handshake_data,
    flush_flight,
    send_alert,
};
} // namespace

static int numeric_host_family(const char* hostname, int family) {
  uint8_t dst[sizeof(struct in6_addr)];
  return inet_pton(family, hostname, dst) == 1;
}

static int numeric_host(const char* hostname) {
  return numeric_host_family(hostname, AF_INET) ||
         numeric_host_family(hostname, AF_INET6);
}

TLSHandshake::TLSHandshake(
    SSL_CTX* sslCtx,
    SSL* ssl,
    ngtcp2_conn* conn,
    const std::string& remoteHost,
    const std::vector<std::string>& alpns)
  : sslCtx_(sslCtx), ssl_(ssl) {}

TLSHandshake::~TLSHandshake() {
  if (ssl_) {
    SSL_free(ssl_);
  }
  if (sslCtx_) {
    SSL_CTX_free(sslCtx_);
  }
}

std::vector<uint8_t>
TLSHandshake::createOpenlsslAlpns(const std::vector<std::string>& alpns) {
  size_t totalLength = 0;
  for (const auto& alpn : alpns) {
    totalLength += 1 + alpn.size();
  }
  std::vector<uint8_t> encodedAlpns(totalLength, '\0');
  auto* p = encodedAlpns.data();
  for (const auto& alpn : alpns) {
    *p = alpn.size();
    ++p;
    std::memcpy(p, alpn.data(), alpn.size());
    p += alpn.size();
  }
  return encodedAlpns;
}

// Basically the constructor as I didn't want to go down the path of throwing
// an exception in a constructor (making sure nothing leaks take a lot of brain
// power).
std::unique_ptr<TLSHandshake> TLSHandshake::make(
    ngtcp2_conn* conn,
    const std::string& remoteHost,
    const std::vector<std::string>& alpns) {
  auto* sslCtx = SSL_CTX_new(TLS_client_method());
  if (!sslCtx) {
    fprintf(
        stderr, "SSL_CTX_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
    return nullptr;
  }

  SSL_CTX_set_min_proto_version(sslCtx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(sslCtx, TLS1_3_VERSION);
  SSL_CTX_set_quic_method(sslCtx, &quic_method);

  auto* ssl = SSL_new(sslCtx);
  if (!ssl) {
    fprintf(stderr, "SSL_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
    // free sslCtx
    SSL_CTX_free(sslCtx);
    return nullptr;
  }
  SSL_set_app_data(ssl, conn);
  SSL_set_connect_state(ssl);
  auto encodedAlpns = createOpenlsslAlpns(alpns);
  SSL_set_alpn_protos(ssl, encodedAlpns.data(), encodedAlpns.size());
  if (!numeric_host(remoteHost.c_str())) {
    SSL_set_tlsext_host_name(ssl, remoteHost.c_str());
  }

  // we are using "quic v1" and so we need to set quic transport version to
  // correct value
  SSL_set_quic_transport_version(ssl, TLSEXT_TYPE_quic_transport_parameters);

  return std::unique_ptr<TLSHandshake>(
      new TLSHandshake(sslCtx, ssl, conn, remoteHost, alpns));
}

SSL* TLSHandshake::getSSL() const {
  return ssl_;
}
} // namespace rush
