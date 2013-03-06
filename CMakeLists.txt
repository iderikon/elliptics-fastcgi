cmake_minimum_required(VERSION 2.6)
set(TARGET proxy)
project(${TARGET})
#set(${TARGET}_BINARY_DIR bin)
set(CMAKE_BINARY_DIR  bin)

#g++ main.cpp -fPIC -lfastcgi-daemon2 -shared -o libcsimple.so

#include_directories(BEFORE ${PROJECT_SOURCE_DIR}/include)
#add_subdirectory(src bin)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -Wall -pedantic -std=c++0x")

set(SOURCES 
	${PROJECT_SOURCE_DIR}/src/proxy.hpp
	${PROJECT_SOURCE_DIR}/src/proxy.cpp
	)

add_library(${TARGET} MODULE ${SOURCES})

target_link_libraries(
	${TARGET}
	elliptics-proxy
	fastcgi-daemon2 
	)

install(TARGETS ${TARGET} DESTINATION /usr/lib/fastcgi2/)

