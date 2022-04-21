#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rush {

/**
 * A muxer for rush. It currently assumes that h264/aac is used even though
 * technically VP8/VP9/Opus is supported by rush.
 */
class RushMuxer {
 public:
  RushMuxer(int64_t audioTimescale, int64_t videoTimescale);

  bool setAVCDecoderConfig(const uint8_t* decoderConfig, size_t size);
  void
  setAACAudioSpecificConfig(const uint8_t* audioSpecificConfig, size_t size);

  std::vector<uint8_t> createConnectPayload(const std::string& connectPayload);
  std::vector<uint8_t>
  createAudioPayload(int64_t ts, const uint8_t* aacData, size_t aacDataSize);
  std::vector<uint8_t> createVideoPayload(
      int64_t pts, int64_t dts, const uint8_t* avccData, size_t size);

 private:
  void parseH264(const uint8_t* avccData, size_t size, bool* isKeyFrame);
  const int64_t audioTimescale_;
  const int64_t videoTimescale_;

  int64_t seqId_{1};
  std::vector<uint8_t> audioSpecificConfig_;
  std::vector<uint8_t> sps_;
  std::vector<uint8_t> pps_;
};
} // namespace rush
