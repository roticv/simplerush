#include <iostream>

#include "flv/Flv.h"
#include "flv/FlvIo.h"
#include "lib/RushClient.h"

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

void generate_media_payload(
    RushClient* client,
    const std::vector<std::shared_ptr<FlvTag>>& tags) {
  for (const auto& tag : tags) {
    if (tag->getTagType() == FLVTAGTYPE::AUDIO) {
      // Skipping logic to check for AAC, assuming AAC
      auto audioTag = std::dynamic_pointer_cast<FlvTagAudioData>(tag);
      if (audioTag->getPacketType() == 0) {
        // AudioHeader, AudioSpecificConfig
        client->setAACAudioSpecificConfig(
            audioTag->getAudioData(), audioTag->getAudioDataSize());
      }
    } else if (tag->getTagType() == FLVTAGTYPE::VIDEO) {
      // Skipping logic to check for H264, assuming H264
      auto videoTag = std::dynamic_pointer_cast<FlvTagVideoData>(tag);
      if (videoTag->getPacketType() == 0) {
        // VideoHeader, AVCDecoderConfig
        client->setAVCDecoderConfig(
            videoTag->getVideoData(), videoTag->getVideoDataSize());
      }
    }
  }

  for (const auto& tag : tags) {
    if (tag->getTagType() == FLVTAGTYPE::AUDIO) {
      auto audioTag = std::dynamic_pointer_cast<FlvTagAudioData>(tag);
      if (audioTag->getPacketType() == 1) {
        // AudioData
        client->appendAudioPayload(
            audioTag->getTimestamp(),
            audioTag->getAudioData(),
            audioTag->getAudioDataSize());
      }
    } else if (tag->getTagType() == FLVTAGTYPE::VIDEO) {
      auto videoTag = std::dynamic_pointer_cast<FlvTagVideoData>(tag);
      if (videoTag->getPacketType() != 0) {
        // VideoData
        int64_t dts = videoTag->getTimestamp();
        int64_t pts = dts + videoTag->getCompositionTimestamp();
        client->appendVideoPayload(
            pts, dts, videoTag->getVideoData(), videoTag->getVideoDataSize());
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

  // flv, so audioTimescale = 1000, videoTimescale = 1000
  RushClient client(connect_payload, 1000, 1000);
  if (!client.connect()) {
    printf("Failed to connect\n");
    return 0;
  }

  generate_media_payload(&client, tags);

  return 0;
}
