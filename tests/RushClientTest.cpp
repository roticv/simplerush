#include <gtest/gtest.h>

#include "lib/RushClient.h"

namespace rush {

TEST(RushClientTest, BufferManagement) {
  RushClient c("{}", 1000, 1000);
  // first payload in queue_ is connect payload
  auto connectPayloadSize = c.queue_.front().second.size();

  c.queue_.emplace_back(1000000, std::vector<uint8_t>(100, 0x11));

  int64_t streamId;
  int fin;
  ngtcp2_vec vec;

  // Empty "vec"
  EXPECT_EQ(c.onQuicStreamWritable(&streamId, &fin, &vec, 0), 0);
  c.onQuicStreamWritable(&streamId, &fin, &vec, 1);
  EXPECT_EQ(vec.len, connectPayloadSize);

  // Mark the connect payload as "consumed"
  c.onQuicStreamDataFramed(streamId, connectPayloadSize);

  c.onQuicStreamWritable(&streamId, &fin, &vec, 1);
  EXPECT_EQ(vec.len, 100);

  // Mark the second buffer as partially "consumed"
  c.onQuicStreamDataFramed(streamId, 40);
  c.onQuicStreamWritable(&streamId, &fin, &vec, 1);
  EXPECT_EQ(vec.len, 60);

  // Mark connect payload and parts of second buffer as "acked"
  // There should only be on buffer left in the queue_ (i.e. the second buffer)
  c.onQuicStreamAcked(streamId, 0, 60);
  EXPECT_EQ(c.queue_.size(), 1);

  // Mark the remaining of the second buffer as "acked"
  c.onQuicStreamAcked(streamId, 60, connectPayloadSize + 40);
  EXPECT_EQ(c.queue_.size(), 0);

  c.queue_.emplace_back(3000000, std::vector<uint8_t>(50, 0x12));

  // Mark the second buffer as completely "consumed"
  c.onQuicStreamDataFramed(streamId, 60);
  c.onQuicStreamWritable(&streamId, &fin, &vec, 1);
  EXPECT_EQ(vec.len, 50);
}
}
