#include <gtest/gtest.h>
#include <thread>

#include "lib/EvLoop.h"

TEST(EvLoopTest, EnqueueTest) {
  rush::EvLoop evLoop;
  std::thread t([&] { evLoop.runLoop(); });

  bool ready = false;
  int a = 123;
  std::mutex m;
  std::condition_variable cv;

  evLoop.enqueue([&m, &ready, &cv, &a] {
    {
      std::lock_guard<std::mutex> g(m);
      a = 456;
      ready = true;
    }
    cv.notify_all();
  });

  {
    std::unique_lock<std::mutex> lk(m);
    cv.wait(lk, [&ready] { return ready; });
  }

  EXPECT_TRUE(ready);
  EXPECT_EQ(a, 456);

  // End stuff
  evLoop.terminateLoopSoon();
  t.join();
}

TEST(EvLoopTest, ExecuteInEventLoopAndWaitTest) {
  rush::EvLoop evLoop;
  std::thread t([&] { evLoop.runLoop(); });

  int a = 123;
  evLoop.executeOnEventLoopAndWait([&a] {
    sleep(1);
    a = 456;
  });

  EXPECT_EQ(a, 456);

  // End stuff
  evLoop.terminateLoopSoon();
  t.join();
}
