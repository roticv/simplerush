#include "Flv.h"

#include <cstdlib>

FlvHeader::FlvHeader(IReader* r) {
  r->read(signature_, 3);
  // Should be signature_ = 'FLV'
  r->read(&version_, 1);
  r->read(&flag_, 1);
  dataOffset_ = r->read32bit();
}

bool FlvHeader::write(IWriter* w) {
  w->write(signature_, 3);
  w->write(&version_, 1);
  w->write(&flag_, 1);

  uint32_t headerSize = htonl(9);
  w->write(reinterpret_cast<uint8_t*>(&headerSize), 4);

  return true;
}

bool FlvHeader::validate() {
  return signature_[0] == 'F' && signature_[1] == 'L' && signature_[2] == 'V' &&
         version_ == 1 && ((flag_ >> 3) & 0x1f) == 0 &&
         ((flag_ >> 1) & 0x01) == 0 && dataOffset_ == 9;
}

uint32_t FlvTag::getSize() { return 11 + getDataSize(); }

FlvTag* FlvTag::parse(IReader* r) {
  uint8_t tagType;
  bool success = r->read(&tagType, 1);
  if (!success) {
    return nullptr;
  }
  uint32_t dataSize = r->read24bit();
  uint32_t timestamp = r->read24bit();
  uint8_t extendedTimestamp;
  r->read(&extendedTimestamp, 1);
  timestamp |= extendedTimestamp << 24;
  uint32_t streamId = r->read24bit();

  uint8_t* data = reinterpret_cast<uint8_t*>(malloc(dataSize));
  r->read(data, dataSize);

  if (tagType == FLVTAGTYPE::AUDIO) {
    return new FlvTagAudioData(timestamp, streamId, data, dataSize);
  } else if (tagType == FLVTAGTYPE::VIDEO) {
    return new FlvTagVideoData(timestamp, streamId, data, dataSize);
  } else if (tagType == FLVTAGTYPE::SCRIPTDATAOBJECT) {
    return new FlvTagScript(timestamp, streamId, data, dataSize);
  } else {
    // Should handle tageType == 18 (SCRIPTDATAOBJECT) but whatever
    return new FlvTagScript(timestamp, streamId, data, dataSize);
    // return nullptr;
  }
}

bool FlvTag::writeCommonFields(IWriter* w) {
  w->write(&tagType_, 1);
  w->write24bit(getDataSize());
  w->write24bit(timestamp_ & 0x0ffffff);
  uint8_t extendedTimestamp = timestamp_ >> 24;
  w->write(&extendedTimestamp, 1);
  w->write24bit(streamId_ & 0x0ffffff);
  return true;
}

FlvTagAudioData::FlvTagAudioData(
    uint32_t timestamp, uint32_t streamId, uint8_t* data, uint32_t dataSize)
  : data_(data), dataSize_(dataSize),
    FlvTag(FLVTAGTYPE::AUDIO, timestamp, streamId) {
  uint8_t codecId = data[0] >> 4;
  packetType_ = data[1];
}

FlvTagAudioData::~FlvTagAudioData() {
  if (data_ != nullptr) {
    free(data_);
  }
}

uint32_t FlvTagAudioData::getDataSize() { return dataSize_; }

bool FlvTagAudioData::write(IWriter* w) {
  writeCommonFields(w);
  return w->write(data_, dataSize_);
}

const uint8_t* FlvTagAudioData::getAudioData() { return data_ + 2; }

const uint32_t FlvTagAudioData::getAudioDataSize() { return getDataSize() - 2; }

FlvTagVideoData::FlvTagVideoData(
    uint32_t timestamp, uint32_t streamId, uint8_t* data, uint32_t dataSize)
  : data_(data), dataSize_(dataSize),
    FlvTag(FLVTAGTYPE::VIDEO, timestamp, streamId) {
  frameType_ = data[0] >> 4;
  codecId_ = data[0] & 0xf;
  // Assume that codecId == 7 i.e. h264
  packetType_ = data[1];
  // Extract SI24 composition timestamp
  cts_ = 0;
  {
    uint8_t* p = reinterpret_cast<uint8_t*>(&cts_);
    p[2] = data_[2];
    p[1] = data_[3];
    p[0] = data_[4];
  }
  cts_ = (cts_ + 0xff800000) ^ 0xff800000;
}

FlvTagVideoData::~FlvTagVideoData() {
  if (data_ != nullptr) {
    free(data_);
  }
}

const uint8_t* FlvTagVideoData::getVideoData() { return data_ + 5; }

const uint32_t FlvTagVideoData::getVideoDataSize() { return getDataSize() - 5; }

uint32_t FlvTagVideoData::getDataSize() { return dataSize_; }

bool FlvTagVideoData::write(IWriter* w) {
  writeCommonFields(w);
  return w->write(data_, dataSize_);
}

FlvTagScript::FlvTagScript(
    uint32_t timestamp, uint32_t streamId, uint8_t* data, uint32_t dataSize)
  : data_(data), dataSize_(dataSize),
    FlvTag(FLVTAGTYPE::SCRIPTDATAOBJECT, timestamp, streamId) {}

FlvTagScript::~FlvTagScript() {
  if (data_ != nullptr) {
    free(data_);
  }
}

uint32_t FlvTagScript::getDataSize() { return dataSize_; }

bool FlvTagScript::write(IWriter* w) {
  writeCommonFields(w);
  return w->write(data_, dataSize_);
}
