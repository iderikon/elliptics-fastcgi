cmake_minimum_required(VERSION 2.6)
set(TARGET proxy)
project(${TARGET})
#set(${TARGET}_BINARY_DIR bin)
#set(CMAKE_BINARY_DIR  bin)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -Wall -pedantic -std=c++0x")

set(SOURCES 
	${PROJECT_SOURCE_DIR}/src/proxy.hpp
	${PROJECT_SOURCE_DIR}/src/proxy.cpp
	${PROJECT_SOURCE_DIR}/src/embed_processor.hpp
	${PROJECT_SOURCE_DIR}/src/embed_processor.cpp
	${PROJECT_SOURCE_DIR}/src/component_base.hpp
	${PROJECT_SOURCE_DIR}/src/component_base.cpp
	)

add_library(${TARGET} MODULE ${SOURCES})

target_link_libraries(
	${TARGET}
	elliptics-proxy
	fastcgi-daemon2 
	)

install(TARGETS ${TARGET} DESTINATION /usr/lib/fastcgi2/)

