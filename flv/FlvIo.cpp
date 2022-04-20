#include "FlvIo.h"

#include <fcntl.h>
#include <unistd.h>

#include <arpa/inet.h>

FileWriter::FileWriter(int fd) {
  if (fd != -1) {
    fd_ = fd;
  }
}

FileWriter::FileWriter(const std::string& filename) {
  fd_ = ::open(
      filename.c_str(),
      O_RDWR | O_CREAT | O_TRUNC,
      S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
}

FileWriter::~FileWriter() {
  if (fd_ != -1) {
    ::close(fd_);
  }
}

bool FileWriter::isValid() { return fd_ != -1; }

bool FileWriter::write(uint8_t* p, size_t size) {
  return ::write(fd_, p, size) == size;
}

bool FileWriter::write24bit(const uint32_t x) {
  uint8_t buffer[3];
  const uint8_t* p = reinterpret_cast<const uint8_t*>(&x);

  buffer[0] = p[2];
  buffer[1] = p[1];
  buffer[2] = p[0];

  return write(buffer, 3);
}

bool FileWriter::write32bit(const uint32_t x) {
  uint32_t tmp = htonl(x);
  return write(reinterpret_cast<uint8_t*>(&tmp), 4);
}

FileReader::FileReader(int fd) {
  if (fd != -1) {
    fd_ = fd;
  }
}

FileReader::FileReader(const std::string& filename) {
  fd_ = ::open(filename.c_str(), O_RDONLY);
}

FileReader::~FileReader() {
  if (fd_ != -1) {
    ::close(fd_);
  }
}

bool FileReader::read(uint8_t* p, size_t size) {
  return ::read(fd_, p, size) == size;
}

uint32_t FileReader::read24bit() {
  uint32_t res = 0;
  uint8_t buffer[3];
  read(buffer, 3);
  uint8_t* p = reinterpret_cast<uint8_t*>(&res);
  p[2] = buffer[0];
  p[1] = buffer[1];
  p[0] = buffer[2];
  return res;
}

uint32_t FileReader::read32bit() {
  uint32_t res = 0;
  read(reinterpret_cast<uint8_t*>(&res), 4);
  return ntohl(res);
}
