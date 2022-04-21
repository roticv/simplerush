#include <cstdio>
#include <vector>

#include "flv/Flv.h"
#include "flv/FlvIo.h"
#include "lib/ByteUtils.h"
#include "lib/RushMuxer.h"

using namespace rush;

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

// pts, dts are assumed to be in timescale 1000 aka ms
// 1. Figure out AudioSpecificConfig
// 2. Write connect payload
// 3. Write audio & video data (skipping AudioHeader, VideoHeader)
// Note: currently assuming that video/audio data is H264/AAC
void createRushFile(
    IWriter* writer,
    const std::vector<std::shared_ptr<FlvTag>>& tags,
    const std::string& connect_payload) {
  // flv has audioTimescale = 1000, videoTimescale = 1000
  RushMuxer muxer(1000, 1000);

  for (const auto& tag : tags) {
    if (tag->getTagType() == FLVTAGTYPE::AUDIO) {
      // Skipping logic to check for AAC, assuming AAC
      auto audioTag = std::dynamic_pointer_cast<FlvTagAudioData>(tag);
      if (audioTag->getPacketType() == 0) {
        // AudioHeader, AudioSpecificConfig
        muxer.setAACAudioSpecificConfig(
            audioTag->getAudioData(), audioTag->getAudioDataSize());
      }
    } else if (tag->getTagType() == FLVTAGTYPE::VIDEO) {
      // Skipping logic to check for H264, assuming H264
      auto videoTag = std::dynamic_pointer_cast<FlvTagVideoData>(tag);
      if (videoTag->getPacketType() == 0) {
        // VideoHeader, AVCDecoderConfig
        muxer.setAVCDecoderConfig(
            videoTag->getVideoData(), videoTag->getVideoDataSize());
      }
    }
  }

  auto connect = muxer.createConnectPayload(connect_payload);
  writer->write(connect.data(), connect.size());

  for (const auto& tag : tags) {
    if (tag->getTagType() == FLVTAGTYPE::AUDIO) {
      auto audioTag = std::dynamic_pointer_cast<FlvTagAudioData>(tag);
      if (audioTag->getPacketType() == 1) {
        // AudioData
        auto rushAudioData = muxer.createAudioPayload(
            audioTag->getTimestamp(),
            audioTag->getAudioData(),
            audioTag->getAudioDataSize());
        writer->write(rushAudioData.data(), rushAudioData.size());
      }
    } else if (tag->getTagType() == FLVTAGTYPE::VIDEO) {
      auto videoTag = std::dynamic_pointer_cast<FlvTagVideoData>(tag);
      if (videoTag->getPacketType() != 0) {
        // VideoData
        int64_t dts = videoTag->getTimestamp();
        int64_t pts = dts + videoTag->getCompositionTimestamp();
        auto rushVideoData = muxer.createVideoPayload(
            pts,
            dts,
            videoTag->getVideoData(),
            videoTag->getVideoDataSize());
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
