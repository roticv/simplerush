#pragma once

#include <ev.h>
#include <list>
#include <mutex>

namespace rush {

/**
 * EvLoop wraps an ev_loop running in a thread and exposes APIs that make it
 * easier and safer to use the event loop. The design of the class is such that
 * there is a separate thread "running" EvLoop's runLoop.
 */
class EvLoop {
 public:
  EvLoop();
  ~EvLoop();

  /**
   * This method basically calls ev_loop. Ideally, this should be called from
   * its own thread (i.e. the EvLoop thread).
   */
  void runLoop(int flags = 0);

  /**
   * This method requests for EvLoop to finish up its queue of "execution"
   * before ending the loop. This method is intended to be called for clean
   * shutdown/termination of the thread.
   */
  void terminateLoopSoon();

  /**
   * Enqueues a callback to be run asynchronously on the event loop. It is safe
   * to call this method from any thread.
   */
  bool enqueue(std::function<void()> func);

  /**
   * This method execute a callback on the event loop and wait. This is safe to
   * call from any thread.
   */
  bool executeOnEventLoopAndWait(std::function<void()> func);

  struct ev_loop* getEvLoop();

 private:
  static void processWork(std::list<std::function<void()>> workToDone);
  static void
  asyncWatcherCallback(struct ev_loop* loop, ev_async* w, int revents);

  struct ev_loop* loop_;
  ev_async asyncWatcher_;
  pthread_t eventLoopThread_;
  bool eventLoopThreadSet_;

  /// Hold on to queueMutex before trying to modify queue_
  std::mutex queueMutex_;
  std::list<std::function<void()>> queue_;
};
} // namespace rush
