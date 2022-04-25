#pragma once

#include <list>
#include <memory>
#include <thread>

#include "lib/NonCopyable.h"
#include "lib/QuicConnection.h"
#include "lib/RushMuxer.h"

namespace rush {

// TODO
// The class is not thread safe when accessed from multiple threads. Fix that
class RushClient : private NonCopyable {
 public:
  RushClient(
      const std::string& connectPayload,
      int audioTimescale,
      int videoTimescale);
  ~RushClient();

  bool connect();

  void setAVCDecoderConfig(const uint8_t* decoderConfig, size_t size);
  void
  setAACAudioSpecificConfig(const uint8_t* audioSpecificConfig, size_t size);
  void
  appendAudioPayload(int64_t ts, const uint8_t* aacData, size_t aacDataSize);
  void appendVideoPayload(
      int64_t pts, int64_t dts, const uint8_t* avccData, size_t size);

  ssize_t onQuicStreamWritable(
      int64_t* streamId, int* fin, ngtcp2_vec* vec, size_t vec_cnt);
  void onQuicStreamDataFramed(int64_t streamId, ssize_t dataLength);

 private:
  void removeItemsFromQueue();

  bool connectAttempted_{false};
  RushMuxer muxer_;
  std::unique_ptr<QuicConnection> connection_;
  std::list<std::vector<uint8_t>> queue_;
  ssize_t bytesProcessed_{0};

  std::unique_ptr<std::thread> evThread_;
  struct ev_loop* loop_;
};
} // namespace rush