add_library(rush_flv
	Flv.cpp
	FlvIo.cpp)
target_include_directories(rush_flv
	PUBLIC ${PROJECT_SOURCE_DIR}/flv
)
