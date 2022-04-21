add_library(rush
	ByteReader.cpp
	RushMuxer.cpp)
target_include_directories(rush
	PUBLIC ${PROJECT_SOURCE_DIR}
)
