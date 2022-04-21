#include "lib/ByteReader.h"

#include <stdexcept>

namespace rush {

ByteReader::ByteReader(const uint8_t* buf, size_t size)
  : head_(buf), p_(buf), remainingSize_(size) {}

bool ByteReader::canAdvance(size_t amount) { return remainingSize_ >= amount; }

void ByteReader::advance(size_t amount) {
  if (!canAdvance(amount)) {
    throw std::runtime_error("Invalid memory access in advance");
  }
  p_ += amount;
  remainingSize_ -= amount;
}

size_t ByteReader::currentOffset() { return p_ - head_; }

uint8_t ByteReader::readByte() {
  if (!canAdvance(1)) {
    throw std::runtime_error("Invalid memory access in readByte");
  }
  auto val = *p_;
  advance(1);
  return val;
}

uint16_t ByteReader::readBE16() {
  if (!canAdvance(2)) {
    throw std::runtime_error("Invalid memory access in readBE16");
  }
  uint16_t val = (p_[0] << 8) | p_[1];
  advance(2);
  return val;
}

uint32_t ByteReader::readBE32() {
  if (!canAdvance(4)) {
    throw std::runtime_error("Invalid memory access in readBE32");
  }
  uint32_t val = (p_[0] << 24) | (p_[1] << 16) | (p_[2] << 8) | p_[3];
  advance(4);
  return val;
}
} // namespace rush
