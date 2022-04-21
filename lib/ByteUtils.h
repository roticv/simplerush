#pragma once

#include <cstring>

namespace rush {

inline void w8(uint8_t** p, uint8_t val) {
  (*p)[0] = val;
  ++*p;
}

inline void wl16(uint8_t** p, uint16_t val) {
  (*p)[0] = (val & 0xff);
  (*p)[1] = (val >> 8);
  *p += 2;
}

inline void wl64(uint8_t** p, uint64_t val) {
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

inline void wblob(uint8_t** p, const uint8_t* blob, size_t blob_size) {
  std::memcpy(*p, blob, blob_size);
  *p += blob_size;
}
} // namespace rush
