cmake_minimum_required(VERSION 3.10)

# set the project name and version
project(SimpleRush VERSION 1.0)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

# set up dependencies
find_package(Libev REQUIRED)
include_directories(${LIBEV_INCLUDE_DIRS})

find_package(ngtcp2 REQUIRED)
include_directories(${NGTCP2_INCLUDE_DIRS})

# we need the quic fork of openssl
find_package(OpenSSL 1.1.1)
if (OPENSSL_FOUND)
message (STATUS "OpenSSL found.")
message (STATUS "OpenSSL include directories: ${OPENSSL_INCLUDE_DIR}")
message (STATUS "OpenSSL library: ${OPENSSL_LIBRARIES}")
message (STATUS "OpenSSL version: ${OPENSSL_VERSION_STR}")
else()
message (FATAL_ERROR "OpenSSL not found.")
endif()
include(CheckSymbolExists)
check_symbol_exists(SSL_is_quic "openssl/ssl.h" HAVE_SSL_IS_QUIC)

# Set up libraries
add_subdirectory(flv)
add_subdirectory(lib)

add_executable(flv_to_rush flv_to_rush)
target_link_libraries(flv_to_rush
	rush
	rush_flv)

add_executable(flv_to_rush_stream flv_to_rush_stream)
target_link_libraries(flv_to_rush_stream
	OpenSSL::SSL
	${NGTCP2_LIBRARIES}
	${NGTCP2_CRYPTO_LIBRARY}
	${LIBEV_LIBRARIES}
	rush
	rush_flv)
