#include "EvLoop.h"

#include <pthread.h>

namespace rush {

/*static*/ void
EvLoop::processWork(std::list<std::function<void()>> workToDone) {
  for (const auto& func : workToDone) {
    func();
  }
}

/*static*/ void
EvLoop::asyncWatcherCallback(struct ev_loop* loop, ev_async* w, int revents) {
  EvLoop* evloop = (EvLoop*)w->data;

  std::list<std::function<void()>> newList;
  {
    const std::lock_guard<std::mutex> l(evloop->queueMutex_);
    evloop->queue_.swap(newList);
  }

  processWork(std::move(newList));
}

EvLoop::EvLoop() {
  loop_ = ev_loop_new(EVFLAG_AUTO);
  ev_async_init(&asyncWatcher_, EvLoop::asyncWatcherCallback);
  asyncWatcher_.data = this;
  ev_async_start(loop_, &asyncWatcher_);
}

EvLoop::~EvLoop() {
  ev_async_stop(loop_, &asyncWatcher_);
  ev_loop_destroy(loop_);
}

void EvLoop::runLoop(int flags) {
  eventLoopThread_ = pthread_self();
  eventLoopThreadSet_ = true;
  ev_run(loop_, flags);
}

void EvLoop::terminateLoopSoon() {
  // ev_break needs to be called from the thread doing the ev_loop
  if (pthread_self() == eventLoopThread_) {
    ev_break(loop_, EVBREAK_ALL);
  } else {
    enqueue([this] { ev_break(loop_, EVBREAK_ALL); });
  }
}

bool EvLoop::enqueue(std::function<void()> func) {
  {
    const std::lock_guard<std::mutex> l(queueMutex_);
    queue_.emplace_back(std::move(func));
  }
  ev_async_send(loop_, &asyncWatcher_);
  return true;
}

bool EvLoop::executeOnEventLoopAndWait(std::function<void()> func) {
  if (pthread_self() == eventLoopThread_) {
    func();
  } else {
    bool ready = false;
    std::mutex m;
    std::condition_variable cv;
    enqueue([&m, &ready, &cv, func = std::move(func)] {
      func();
      {
        std::lock_guard<std::mutex> g(m);
        ready = true;
      }
      cv.notify_all();
    });
    {
      std::unique_lock<std::mutex> lk(m);
      cv.wait(lk, [&ready] { return ready; });
    }
  }
  return true;
}

struct ev_loop* EvLoop::getEvLoop() {
  return loop_;
}
} // namespace rush
