#pragma once

#include <ev.h>
#include <ngtcp2/ngtcp2.h>

#include "lib/NonCopyable.h"
#include "lib/TLSHandshake.h"

namespace rush {

/**
 * Callbacks for QuicConnection
 */
typedef struct {
  // This callback is called to see if there any data to be written to the
  // quic stream.
  //
  // @param streamId is the stream identifier used to  write the stream
  // @param fin is used to indicate if this is the last data (non zero if it is
  // last data)
  // @param vec contains the ngtcp2_vec (similar to iovec) to write data to
  // @param veccnt contains the number of ngtcp2_vec in vec
  // @param context contains the context that is passed (set in the callbacks).
  // @return Number of vec used
  ssize_t (*onStreamWritable)(
      int64_t* streamId,
      int* fin,
      ngtcp2_vec* vec,
      size_t vec_cnt,
      void* context);

  // This callback is called after the data provided by onStreamWritable is
  // assembled by ngtcp2 into STREAM_DATA frame. This is before the data is sent
  //
  // @param streamId is the stream identifier
  // @param dataLength is the length of data that have been accepted (data
  // passed by onStreamWritable)
  // @param context contains the context that is passed (set in the callbacks).
  void (*onStreamDataFramed)(
      int64_t streamId, ssize_t dataLength, void* context);

  // This callback is called when ngtcp2 received ack for the offset. According
  // to ngtcp2 documentation, this means that the data referenced by
  // onStreamWritable can now by freed.
  //
  // @param streamId is the stream identifier
  // @param offset is the offset of the data stream that has been acked
  // @param dataLength is the length of data that have been acked
  // @param context contains the context that is passed (set in the callbacks).
  void (*onAckedStreamDataOffset)(
      int64_t streamId, uint64_t offset, uint64_t dataLength, void* context);

  // This callback is called when data is received on the given stream
  //
  // @param streamId is the stream identifier
  // @param fin indicates if this is the last data on this stream
  // @param data is the buffer containing the data received
  // @param dataLength is the length of data received
  // @param context contains the context that is passed (set in the callbacks).
  void (*onRecvStreamData)(
      int64_t streamId,
      bool fin,
      const uint8_t* data,
      size_t dataLength,
      void* context);

  // This callback is called when write shutdown is returned when calling writev
  // on ngtcp2.
  //
  // @param streamId is the stream identifier
  // @param context contains the context that is passed (set in the callbacks).
  void (*onStreamWriteShutdown)(int64_t streamId, void* context);

  // This callback is called when write to ngtcp2 is blocked by QUIC flow control
  //
  // @param streamId is the stream identifier
  // @param context contains the context that is passed (set in the callbacks).
  void (*onStreamBlocked)(int64_t streamId, void* context);

  void* context;
} QuicConnectionCallbacks;

/**
 * A class to hold onto ngtcp2's ngtcp2_conn and also TLSHandshake
 */
class QuicConnection : private NonCopyable {
 public:
  static std::unique_ptr<QuicConnection> make(
      const QuicConnectionCallbacks& callbacks,
      struct ev_loop* loop,
      const std::string& remoteHost,
      uint32_t port,
      const std::vector<std::string>& alpns);
  ~QuicConnection();

  void setStreamId(int64_t streamId);
  int64_t getStreamId() const;

  void closeConnection();

  // for libev read notification on udp socket
  bool onUdpSocketBytesAvailable();
  bool tryWriteToNgtcp2();
  bool tryWriteStream();
  bool handleExpiry();

  // for ngtcp2 callbacks
  void
  ackedStreamDataOffset(int64_t streamId, uint64_t offset, uint64_t datalen);

 private:
  QuicConnection(
      const QuicConnectionCallbacks& callbacks, struct ev_loop* loop);
  bool setupUdpSocket(const char* host, uint32_t port);
  bool connectSocket();
  bool setupLocalAddr();
  bool setupNgtcp2();
  void setupEv();
  void setHandshake(std::unique_ptr<TLSHandshake> handshake);

  bool sendUdpDatagram(const uint8_t* data, size_t datalen);

  int64_t streamId_{-1};
  ngtcp2_conn* conn_{nullptr};
  std::unique_ptr<TLSHandshake> handshake_;
  QuicConnectionCallbacks callbacks_;

  // quic settings
  int maxUdpPacketSize_{1232};

  // socket related fields
  struct sockaddr_storage remoteAddr_;
  socklen_t remoteAddrLen_;
  struct sockaddr_storage localAddr_;
  socklen_t localAddrLen_;
  int fd_{-1};

  // udp socket read notification, timer
  struct ev_loop* loop_;
  ev_io rev_;
  ev_timer timer_;
};
} // namespace rush
