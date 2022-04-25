#pragma once

namespace rush {

class NonCopyable {
 protected:
  NonCopyable() = default;
  ~NonCopyable() = default;

  // Disable default copy-constructor
  // Disable default copy assignment operator
  NonCopyable(const NonCopyable&) = delete;
  const NonCopyable& operator=(const NonCopyable&) = delete;
};
} // namespace rush
