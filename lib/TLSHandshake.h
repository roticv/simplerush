#pragma once

#include <memory>
#include <string>
#include <vector>

#include <ngtcp2/ngtcp2.h>
#include <openssl/ssl.h>

#include "lib/NonCopyable.h"

namespace rush {

class TLSHandshake : private NonCopyable {
 public:
  static std::unique_ptr<TLSHandshake> make(
      ngtcp2_conn* conn,
      const std::string& remoteHost,
      const std::vector<std::string>& alpns);

  ~TLSHandshake();

  SSL* getSSL() const;

 private:
  TLSHandshake(
      SSL_CTX* sslCtx,
      SSL* ssl,
      ngtcp2_conn* conn,
      const std::string& remoteHost,
      const std::vector<std::string>& alpns);
  static std::vector<uint8_t>
  createOpenlsslAlpns(const std::vector<std::string>& alpns);

  SSL_CTX* sslCtx_{nullptr};
  SSL* ssl_{nullptr};
};
} // namespace rush
