#include "lib/RushClient.h"

namespace rush {

namespace {

static ssize_t onQuicStreamWritable(
    int64_t* streamId,
    int* fin,
    ngtcp2_vec* vec,
    size_t vec_cnt,
    void* context) {
  RushClient* client = (RushClient*)context;
  return client->onQuicStreamWritable(streamId, fin, vec, vec_cnt);
}

static void
onQuicStreamDataFramed(int64_t streamId, ssize_t dataLength, void* context) {
  RushClient* client = (RushClient*)context;
  client->onQuicStreamDataFramed(streamId, dataLength);
}
} // namespace

RushClient::RushClient(
    const std::string& connectPayload, int audioTimescale, int videoTimescale)
  : muxer_(audioTimescale, videoTimescale) {
  // Set up ev_loop
  loop_ = ev_loop_new(EVFLAG_AUTO);

  auto rushConnectPayload = muxer_.createConnectPayload(connectPayload);
  queue_.push_back(std::move(rushConnectPayload));
}

RushClient::~RushClient() {
  if (evThread_) {
    evThread_->join();
  }
  ev_loop_destroy(loop_);
}

bool RushClient::connect() {
  if (connectAttempted_) {
    return true;
  }
  QuicConnectionCallbacks callbacks{
      .onStreamWritable = rush::onQuicStreamWritable,
      .onStreamDataFramed = rush::onQuicStreamDataFramed,
      .context = this,
  };
  auto connection = QuicConnection::make(
      callbacks, loop_, "live-upload-staging.facebook.com", 443, {"fbvp"});
  if (!connection) {
    fprintf(stderr, "Creating Quic connection failed\n");
    return false;
  }
  connection_ = std::move(connection);

  // ev_run can only happen after the QuicConnection setup hook back with loop_
  evThread_ =
      std::unique_ptr<std::thread>(new std::thread([&] { ev_run(loop_, 0); }));

  // Trigger handshake
  connection_->tryWriteToNgtcp2();
  connectAttempted_ = true;
  return true;
}

void RushClient::setAVCDecoderConfig(
    const uint8_t* decoderConfig, size_t size) {
  muxer_.setAVCDecoderConfig(decoderConfig, size);
}

void RushClient::setAACAudioSpecificConfig(
    const uint8_t* audioSpecificConfig, size_t size) {
  muxer_.setAACAudioSpecificConfig(audioSpecificConfig, size);
}

void RushClient::appendAudioPayload(
    int64_t ts, const uint8_t* aacData, size_t aacDataSize) {
  auto rushAudioData = muxer_.createAudioPayload(ts, aacData, aacDataSize);
  queue_.push_back(std::move(rushAudioData));
}

void RushClient::appendVideoPayload(
    int64_t pts, int64_t dts, const uint8_t* avccData, size_t size) {
  auto rushVideoData = muxer_.createVideoPayload(pts, dts, avccData, size);
  queue_.push_back(std::move(rushVideoData));
}

ssize_t RushClient::onQuicStreamWritable(
    int64_t* streamId, int* fin, ngtcp2_vec* vec, size_t vec_cnt) {
  if (vec_cnt == 0) {
    return 0;
  }
  *fin = 0;
  *streamId = connection_->getStreamId();

  ssize_t totalSofar = 0;
  for (const auto& buf : queue_) {
    if (totalSofar + buf.size() > bytesProcessed_) {
      vec->base = (uint8_t*)buf.data() + bytesProcessed_ - totalSofar;
      vec->len = buf.size() - (bytesProcessed_ - totalSofar);
      return 1;
    }
    totalSofar += buf.size();
  }
  vec->base = nullptr;
  vec->len = 0;
  return 0;
}

// Clear up memory that RushClient has been holding on to
void RushClient::onQuicStreamDataFramed(
    int64_t /*streamId*/, ssize_t dataLength) {
  bytesProcessed_ += dataLength;
  removeItemsFromQueue();
}

void RushClient::removeItemsFromQueue() {
  while (bytesProcessed_ > 0 && !queue_.empty() &&
         queue_.front().size() <= bytesProcessed_) {
    auto frontBufferLen = queue_.front().size();
    queue_.pop_front();
    bytesProcessed_ -= frontBufferLen;
  }
}
} // namespace rush
