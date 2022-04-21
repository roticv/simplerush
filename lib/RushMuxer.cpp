#include "RushMuxer.h"

#include "lib/ByteUtils.h"
#include "lib/ByteReader.h"
#include "lib/H264.h"

namespace rush {

RushMuxer::RushMuxer(int64_t audioTimescale, int64_t videoTimescale)
  : audioTimescale_(audioTimescale), videoTimescale_(videoTimescale) {}

void RushMuxer::setAACAudioSpecificConfig(
    const uint8_t* audioSpecificConfig, size_t size) {
  audioSpecificConfig_.resize(size);

  auto* p = audioSpecificConfig_.data();
  wblob(&p, audioSpecificConfig, size);
}

bool RushMuxer::setAVCDecoderConfig(const uint8_t* decoderConfig, size_t size) {
  // TODO implement extracting pps/sps from AVCDecoderConfig
  ByteReader reader(decoderConfig, size);
  if (!reader.canAdvance(6)) {
    return false;
  }
  // Skip all the way to number of SPS
  reader.advance(5);

  auto numSps = reader.readByte();
  numSps &= 0x1f;
  for (int i = 0; i < numSps; ++i) {
    // Attempt to read sps
    if (!reader.canAdvance(2)) {
      return false;
    }
    auto spsLen = reader.readBE16();
    if (!reader.canAdvance(spsLen)) {
      return false;
    }
    // TODO validate that the nalu in "sps" is indeed SPS (check vs 0x67)
    sps_.resize(spsLen);
    std::memcpy(sps_.data(), decoderConfig + reader.currentOffset(), spsLen);
    reader.advance(spsLen);
  }
  if (!reader.canAdvance(1)) {
    return false;
  }
  auto numPps = reader.readByte();
  numPps &= 0x1f;
  for (int i = 0; i < numPps; ++i) {
    // Attempt to read pps
    if (!reader.canAdvance(2)) {
      return false;
    }
    auto ppsLen = reader.readBE16();
    if (!reader.canAdvance(ppsLen)) {
      return false;
    }
    // TODO validate that the nalu in "pps" is indeed PPS (check vs 0x68)
    pps_.resize(ppsLen);
    std::memcpy(pps_.data(), decoderConfig + reader.currentOffset(), ppsLen);
    reader.advance(ppsLen);
  }
  return true;
}

std::vector<uint8_t>
RushMuxer::createConnectPayload(const std::string& connectPayload) {
  int64_t len = 8 + 8 + 1 + 1 + 2 + 2 + 8 + connectPayload.size();
  std::vector<uint8_t> buf(len, '\0');

  auto* p = buf.data();
  wl64(&p, len);
  wl64(&p, seqId_);
  seqId_ += 1;
  // connect frame = 0x0
  w8(&p, 0);
  // version default value is 0
  w8(&p, 0);
  // 1000 for video and audio timescale
  wl16(&p, videoTimescale_);
  wl16(&p, audioTimescale_);
  // broadcast id = 0
  wl64(&p, 0);
  wblob(
      &p,
      reinterpret_cast<const uint8_t*>(connectPayload.data()),
      connectPayload.size());

  return buf;
}

std::vector<uint8_t> RushMuxer::createAudioPayload(
    int64_t ts, const uint8_t* aacData, size_t aacDataSize) {
  /*
   * 8byte len, 8byte id, 1byte frame type, 1byte codec, 8byte timestamp
   * 1byte track id, 2byte header len, header len, payload len
   */
  int64_t len =
      8 + 8 + 1 + 1 + 8 + 1 + 2 + audioSpecificConfig_.size() + aacDataSize;
  std::vector<uint8_t> buf(len, '\0');

  auto* p = buf.data();
  wl64(&p, len);
  wl64(&p, seqId_);
  seqId_ += 1;
  // audio data with header frame = 0x14
  w8(&p, 0x14);
  // aac is "codec 1"
  w8(&p, 1);
  wl64(&p, ts);
  // Hardcode track id = 1 for audio
  w8(&p, 1);
  wl16(&p, audioSpecificConfig_.size());
  if (audioSpecificConfig_.size() > 0) {
    wblob(&p, audioSpecificConfig_.data(), audioSpecificConfig_.size());
  }
  wblob(&p, aacData, aacDataSize);

  return buf;
}

void RushMuxer::parseH264(const uint8_t* avccData, size_t size, bool* isKeyFrame) {
  *isKeyFrame = false;
  ByteReader reader(avccData, size);
  if (!reader.canAdvance(5)) {
    return;
  }
  while (true) {
    if (!reader.canAdvance(2)) {
      break;
    }
    auto naluSize = reader.readBE32();
    if (!reader.canAdvance(naluSize)) {
      break;
    }
    auto naluHeader = reader.readByte();
    // Read one byte for the NALU header
    reader.advance(naluSize - 1);
    auto naluType = naluHeader & 0x1f;
    if (naluType == H264NALU::IDR_SLICE) {
      // I-frame
      *isKeyFrame = true;
    }
  }
}

// This method has logic to prepend SPS/PPS if it detects that IDR in the h264
// bitstream.
// TODO: Properly support sps/pps changing midstream (such as resolution
// changes)
std::vector<uint8_t> RushMuxer::createVideoPayload(
    int64_t pts, int64_t dts, const uint8_t* avccData, size_t size) {
  bool isKeyFrame;
  parseH264(avccData, size, &isKeyFrame);

  size_t newVideoPayloadSize = size;
  if (isKeyFrame) {
    newVideoPayloadSize += sps_.size() + pps_.size();
  }

  int64_t len = 8 + 8 + 1 + 1 + 8 + 8 + 1 + 2 + newVideoPayloadSize;
  std::vector<uint8_t> buf(len, '\0');

  auto* p = buf.data();
  wl64(&p, len);
  wl64(&p, seqId_);
  seqId_ += 1;
  // video with track frame = 0xd
  w8(&p, 0xd);
  // h264 is 0x1
  w8(&p, 0x1);
  wl64(&p, pts);
  wl64(&p, dts);
  // Hardcode track id = 0 for video
  w8(&p, 0);
  // Set required frame offset to 0 for now; to be fixed in the future
  wl16(&p, 0);

  // Prepending of SPS/PPS if the bitstream is detected to have IDR
  if (isKeyFrame) {
    wblob(&p, sps_.data(), sps_.size());
    wblob(&p, pps_.data(), pps_.size());
  }

  wblob(&p, avccData, size);
  return buf;
}

} // namespace rush
