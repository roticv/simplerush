add_library(rush
	ByteReader.cpp
	EvLoop.cpp
	QuicConnection.cpp
	RushClient.cpp
	RushMuxer.cpp
	TLSHandshake)
target_include_directories(rush
	PUBLIC ${PROJECT_SOURCE_DIR}
)
target_link_libraries(rush
	OpenSSL::SSL
	${LIBEV_LIBRARIES}
	${NGTCP2_CRYPTO_LIBRARY}
	${NGTCP2_LIBRARIES})
