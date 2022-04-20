#pragma once

#include <string>

/**
 * Interfaces for writer and reader classes
 */
class IWriter {
  public:
  virtual ~IWriter() {}

  // Whether the writer is valid for writing
  virtual bool isValid() = 0;
  virtual bool write(uint8_t* p, size_t size) = 0;
  virtual bool write24bit(const uint32_t x) = 0;
  virtual bool write32bit(const uint32_t x) = 0;
};

class IReader {
  public:
  virtual ~IReader() {}
  virtual bool read(uint8_t* p, size_t size) = 0;
  virtual uint32_t read24bit() = 0;
  virtual uint32_t read32bit() = 0;
};

class FileWriter : public IWriter {
  public:
  FileWriter(int fd);
  FileWriter(const std::string& filename);
  ~FileWriter() override;

  bool isValid() override;
  bool write(uint8_t* p, size_t size) override;
  bool write24bit(const uint32_t x) override;
  bool write32bit(const uint32_t x) override;

  private:
  int fd_;
};

class FileReader : public IReader {
  public:
  FileReader(int fd);
  FileReader(const std::string& filename);

  ~FileReader() override;
  bool read(uint8_t* p, size_t size) override;
  uint32_t read24bit() override;
  uint32_t read32bit() override;

  private:
  int fd_;
};
