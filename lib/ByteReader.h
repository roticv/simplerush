#pragma once

#include <cstdint>
#include <cstring>

namespace rush {

/**
 * A class to make it easier (and potentially safer) to read bytes from a blob
 * of memory (represented by uint8_t* buf, size_t size).
 */
class ByteReader {
 public:
  ByteReader(const uint8_t* buf, size_t size);

  bool canAdvance(size_t amount);
  void advance(size_t amount);

	// How much we have advanced forward with ByteReader
	size_t currentOffset();

  // std::runtime_error is thrown if invalid memory is accessed.
  uint8_t readByte();
	uint16_t readBE16();
  uint32_t readBE32();

 private:
	const uint8_t* head_;
  const uint8_t* p_;
  size_t remainingSize_;
};
} // namespace rush
