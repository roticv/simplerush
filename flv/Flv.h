#pragma once

#include "FlvIo.h"

enum FLVTAGTYPE : uint8_t { AUDIO = 8, VIDEO = 9, SCRIPTDATAOBJECT = 18 };

class FlvHeader {
  public:
  FlvHeader(IReader* r);
  bool write(IWriter* w);
  bool validate();

  private:
  uint8_t signature_[3];
  uint8_t version_;
  uint8_t flag_;
  uint32_t dataOffset_;
};

/**
 * Current implementation of FlvTag is designed so that it reads the common
 * fields of VideoTag/AudioTag
 */
class FlvTag {
  public:
  virtual ~FlvTag() {}
  virtual bool write(IWriter* w) = 0;
  uint32_t getSize();
  uint32_t getTimestamp() { return timestamp_; }
  uint32_t getTagType() { return tagType_; }

  static FlvTag* parse(IReader* r);

  protected:
  FlvTag(uint8_t tagType, uint32_t timestamp, uint32_t streamId)
    : tagType_(tagType), timestamp_(timestamp), streamId_(streamId) {}
  bool writeCommonFields(IWriter* w);
  virtual uint32_t getDataSize() = 0;

  private:
  uint8_t tagType_;
  uint32_t timestamp_;
  uint32_t streamId_;
};

class FlvTagAudioData : public FlvTag {
  public:
  FlvTagAudioData(
      uint32_t timestamp, uint32_t streamId, uint8_t* data, uint32_t dataSize);
  virtual ~FlvTagAudioData();
  virtual bool write(IWriter* w) override;
  uint8_t getPacketType() { return packetType_; }
  const uint8_t* getAudioData();
  const uint32_t getAudioDataSize();

  protected:
  virtual uint32_t getDataSize() override;

  private:
  uint8_t* data_ = nullptr;
  uint32_t dataSize_ = 0;
  uint8_t packetType_;
};

class FlvTagVideoData : public FlvTag {
  public:
  FlvTagVideoData(
      uint32_t timestamp, uint32_t streamId, uint8_t* data, uint32_t dataSize);
  virtual ~FlvTagVideoData();
  virtual bool write(IWriter* w) override;
  uint8_t getCodecId() { return codecId_; }
  uint8_t getFrameType() { return frameType_; }
  uint8_t getPacketType() { return packetType_; }
  const uint8_t* getVideoData();
  const uint32_t getVideoDataSize();
  const int32_t getCompositionTimestamp() { return cts_; }

  protected:
  virtual uint32_t getDataSize() override;

  private:
  uint8_t* data_ = nullptr;
  uint32_t dataSize_ = 0;
  uint8_t codecId_;
  uint8_t frameType_;
  uint8_t packetType_;
  int32_t cts_;
};

class FlvTagScript : public FlvTag {
  public:
  FlvTagScript(
      uint32_t timestamp, uint32_t streamId, uint8_t* data, uint32_t dataSize);
  virtual ~FlvTagScript();
  virtual bool write(IWriter* w) override;

  protected:
  virtual uint32_t getDataSize() override;

  private:
  uint8_t* data_ = nullptr;
  uint32_t dataSize_ = 0;
};
