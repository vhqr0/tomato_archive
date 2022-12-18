cmake_minimum_required(VERSION 3.0)

project(TOMATO)

set(CMAKE_CXX_COMPILER "g++")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20 -fcoroutines")

if(CMAKE_BUILD_TYPE AND (CMAKE_BUILD_TYPE STREQUAL "Debug"))
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DASIO_ENABLE_HANDLER_TRACKING")
endif()

aux_source_directory(./src/tomato TOMATO_SRCS)

add_executable(tomato ${TOMATO_SRCS})

if(UNIX)
  target_link_libraries(tomato -lpthread -lcrypto -lssl -lsqlite3 -lmaxminddb)
elseif(WIN32)
  target_link_libraries(tomato -lwsock32 -lws2_32 -lcrypto -lssl -lsqlite3 -lmaxminddb)
else()
  message(FATAL_ERROR "unknown platform")
endif()
