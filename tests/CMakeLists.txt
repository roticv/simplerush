include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/609281088cfefc76f9d0ce82e1ff6c30cc3591e5.zip
)

FetchContent_MakeAvailable(googletest)

add_executable(
  evloop_test
  EvloopTest.cpp
)
target_link_libraries(
  evloop_test
	rush
  gtest_main
)

add_executable(
  rushclient_test
  RushClientTest.cpp
)
target_link_libraries(
  rushclient_test
  rush
  gtest_main
)

include(GoogleTest)
gtest_discover_tests(evloop_test)
gtest_discover_tests(rushclient_test)
