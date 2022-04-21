#pragma once

#include <cstdint>

namespace rush {

enum H264NALU : uint8_t {
  // 1 ... 4 not defined
  IDR_SLICE = 5,
  SEI = 6,
  SPS = 7,
  PPS = 8,
  // Remaining not defined yet
};

}
