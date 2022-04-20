#include <cstdio>
#include <vector>

#include "flv/Flv.h"
#include "flv/FlvIo.h"

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

void w8(uint8_t** p, uint8_t val) {
  (*p)[0] = val;
  ++*p;
}

void wl16(uint8_t** p, uint16_t val) {
  (*p)[0] = (val & 0xff);
  (*p)[1] = (val >> 8);
  *p += 2;
}

void wl64(uint8_t** p, uint64_t val) {
  (*p)[0] = (val & 0xff);
  (*p)[1] = (val >> 8) & 0xff;
  (*p)[2] = (val >> 16) & 0xff;
  (*p)[3] = (val >> 24) & 0xff;
  (*p)[4] = (val >> 32) & 0xff;
  (*p)[5] = (val >> 40) & 0xff;
  (*p)[6] = (val >> 48) & 0xff;
  (*p)[7] = (val >> 56) & 0xff;
  *p += 8;
}

void wblob(uint8_t** p, const uint8_t* blob, size_t blob_size) {
  std::memcpy(*p, blob, blob_size);
  *p += blob_size;
}

std::vector<uint8_t>
createConnectPayload(const std::string& connect_payload, int64_t* rush_id) {
  int64_t len = 8 + 8 + 1 + 1 + 2 + 2 + 8 + connect_payload.size();
  std::vector<uint8_t> buf(len, '\0');

  auto* p = buf.data();
  wl64(&p, len);
  wl64(&p, *rush_id);
  *rush_id += 1;
  // connect frame = 0x0
  w8(&p, 0);
  // version default value is 0
  w8(&p, 0);
  // 1000 for video and audio timescale
  wl16(&p, 1000);
  wl16(&p, 1000);
  // broadcast id = 0
  wl64(&p, 0);
  wblob(
      &p,
      reinterpret_cast<const uint8_t*>(connect_payload.data()),
      connect_payload.size());

  return buf;
}

// dts are assumed to be in timescale 1000 aka ms
std::vector<uint8_t> createAudioPayload(
    int64_t dts,
    const uint8_t* aacData,
    size_t aacDataSize,
    const uint8_t* audioSpecificConfigData,
    size_t audioSpecificConfigDataSize,
    int64_t* rush_id) {
  /*
   * 8byte len, 8byte id, 1byte frame type, 1byte codec, 8byte timestamp
   * 1byte track id, 2byte header len, header len, payload len
   */
  int64_t len =
      8 + 8 + 1 + 1 + 8 + 1 + 2 + audioSpecificConfigDataSize + aacDataSize;
  std::vector<uint8_t> buf(len, '\0');

  auto* p = buf.data();
  wl64(&p, len);
  wl64(&p, *rush_id);
  *rush_id += 1;
  // audio data with header frame = 0x14
  w8(&p, 0x14);
  // aac is "codec 1"
  w8(&p, 1);
  wl64(&p, dts);
  // Hardcode track id = 1 for audio
  w8(&p, 1);
  wl16(&p, audioSpecificConfigDataSize);
  wblob(&p, audioSpecificConfigData, audioSpecificConfigDataSize);
  wblob(&p, aacData, aacDataSize);

  return buf;
}

// pts, dts are assumed to be in timescale 1000 aka ms
std::vector<uint8_t> createVideoPayload(
    int64_t pts,
    int64_t dts,
    const uint8_t* avccData,
    size_t size,
    int64_t* rush_id) {

  // TODO: Missing logic to pre-pend sps/pps for h264 at keyframe
  int64_t len = 8 + 8 + 1 + 1 + 8 + 8 + 1 + 2 + size;
  std::vector<uint8_t> buf(len, '\0');

  auto* p = buf.data();
  wl64(&p, len);
  wl64(&p, *rush_id);
  *rush_id += 1;
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
  wblob(&p, avccData, size);
  return buf;
}

// 1. Figure out AudioSpecificConfig
// 2. Write connect payload
// 3. Write audio & video data (skipping AudioHeader, VideoHeader)
// Note: currently assuming that video/audio data is H264/AAC
void createRushFile(
    IWriter* writer,
    const std::vector<std::shared_ptr<FlvTag>>& tags,
    const std::string& connect_payload) {
  // rush_id begins with 1
  int64_t rush_id = 1;

  const uint8_t* audio_specific_config = nullptr;
  size_t audio_specific_config_size = 0;
  for (const auto& tag : tags) {
    if (tag->getTagType() == FLVTAGTYPE::AUDIO) {
      // Skipping logic to check for AAC, assuming AAC
      auto audioTag = std::dynamic_pointer_cast<FlvTagAudioData>(tag);
      if (audioTag->getPacketType() == 0) {
        // AudioHeader, AudioSpecificConfig
        audio_specific_config = audioTag->getAudioData();
        audio_specific_config_size = audioTag->getAudioDataSize();
      }
    }
  }

  auto connect = createConnectPayload(connect_payload, &rush_id);
  writer->write(connect.data(), connect.size());

  for (const auto& tag : tags) {
    if (tag->getTagType() == FLVTAGTYPE::AUDIO) {
      auto audioTag = std::dynamic_pointer_cast<FlvTagAudioData>(tag);
      if (audioTag->getPacketType() == 1) {
        // AudioData
        auto rushAudioData = createAudioPayload(
            audioTag->getTimestamp(),
            audioTag->getAudioData(),
            audioTag->getAudioDataSize(),
            audio_specific_config,
            audio_specific_config_size,
            &rush_id);
        writer->write(rushAudioData.data(), rushAudioData.size());
      }
    } else if (tag->getTagType() == FLVTAGTYPE::VIDEO) {
      auto videoTag = std::dynamic_pointer_cast<FlvTagVideoData>(tag);
      if (videoTag->getPacketType() != 0) {
        // VideoData
        int64_t dts = videoTag->getTimestamp();
        int64_t pts = dts + videoTag->getCompositionTimestamp();
        auto rushVideoData = createVideoPayload(
            pts,
            dts,
            videoTag->getVideoData(),
            videoTag->getVideoDataSize(),
            &rush_id);
        writer->write(rushVideoData.data(), rushVideoData.size());
      }
    }
  }
}

void print_usage() {
  printf(
      "flv_to_rush is an example program to convert from flv to fbvp/rush\n");
  printf("./flv_to_rush <example.flv> <example.fbvp> <connect_payload>\n");
}

int main(int argc, char* argv[]) {
  if (argc < 4) {
    print_usage();
    return 0;
  }
  std::string flv_filename(argv[1]);
  std::string rush_filename(argv[2]);
  std::string connect_payload(argv[3]);
  auto tags = process_flv(flv_filename);
  if (tags.size() == 0) {
    printf("Failed to process flv: %s\n", flv_filename.c_str());
    return 0;
  }

  FileWriter writer(rush_filename);
  if (!writer.isValid()) {
    printf("Failed to open/write to rush file: %s\n", rush_filename.c_str());
    return 0;
  }
  createRushFile(&writer, tags, connect_payload);
  return 0;
}
