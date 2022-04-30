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

static int64_t timestamp() {
  struct timespec tp;

  if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
    fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  return (int64_t)tp.tv_sec * NGTCP2_SECONDS + (int64_t)tp.tv_nsec;
}

} // namespace

RushClient::RushClient(
    const std::string& connectPayload, int audioTimescale, int videoTimescale)
  : muxer_(audioTimescale, videoTimescale),
    evLoop_(std::make_shared<EvLoop>()) {

  auto rushConnectPayload = muxer_.createConnectPayload(connectPayload);
  {
    const std::lock_guard<std::mutex> l(queueMutex_);
    queue_.emplace_back(timestamp(), std::move(rushConnectPayload));
  }
}

RushClient::~RushClient() {
  if (evThread_) {
    evThread_->join();
  }
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
      callbacks,
      evLoop_->getEvLoop(),
      "live-upload-staging.facebook.com",
      443,
      {"fbvp"});
  if (!connection) {
    fprintf(stderr, "Creating Quic connection failed\n");
    return false;
  }
  connection_ = std::move(connection);

  // ev_run can only happen after the QuicConnection setup hook back with loop_
  evThread_ = std::make_unique<std::thread>([&] { evLoop_->runLoop(); });

  // Trigger handshake
  //connection_->tryWriteToNgtcp2();
  evLoop_->enqueue([&] { connection_->tryWriteToNgtcp2(); });
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
  {
    const std::lock_guard<std::mutex> l(queueMutex_);
    queue_.emplace_back(timestamp(), std::move(rushAudioData));
  }
  evLoop_->enqueue([&] { connection_->tryWriteToNgtcp2(); });
}

void RushClient::appendVideoPayload(
    int64_t pts, int64_t dts, const uint8_t* avccData, size_t size) {
  auto rushVideoData = muxer_.createVideoPayload(pts, dts, avccData, size);
  {
    const std::lock_guard<std::mutex> l(queueMutex_);
    queue_.emplace_back(timestamp(), std::move(rushVideoData));
  }
  evLoop_->enqueue([&] { connection_->tryWriteToNgtcp2(); });
}

ssize_t RushClient::onQuicStreamWritable(
    int64_t* streamId, int* fin, ngtcp2_vec* vec, size_t vec_cnt) {
  if (vec_cnt == 0) {
    return 0;
  }
  *fin = 0;
  *streamId = connection_->getStreamId();

  {
    const std::lock_guard<std::mutex> l(queueMutex_);
    ssize_t totalSofar = 0;
    //int datavcnt = 0;
    for (const auto& [ts, buf] : queue_) {
      if (totalSofar + buf.size() > bytesProcessed_) {
        vec->base = (uint8_t*)buf.data() + bytesProcessed_ - totalSofar;
        vec->len = buf.size() - (bytesProcessed_ - totalSofar);
        return 1;
      }
      totalSofar += buf.size();
    }
  }

  // No data
  vec->base = nullptr;
  vec->len = 0;
  return 0;
}

// Clear up memory that RushClient has been holding on to
void RushClient::onQuicStreamDataFramed(
    int64_t /*streamId*/, ssize_t dataLength) {
  {
    const std::lock_guard<std::mutex> l(queueMutex_);
    bytesProcessed_ += dataLength;
  }
  removeItemsFromQueue();
}

void RushClient::removeItemsFromQueue() {
  {
    const std::lock_guard<std::mutex> l(queueMutex_);
    while (bytesProcessed_ > 0 && !queue_.empty() &&
           queue_.front().second.size() <= bytesProcessed_) {
      auto frontBufferLen = queue_.front().second.size();
      auto ts = queue_.front().first;
      printf("time delta: %lldns\n", timestamp() - ts);
      queue_.pop_front();
      bytesProcessed_ -= frontBufferLen;
    }
  }
}
} // namespace rush
