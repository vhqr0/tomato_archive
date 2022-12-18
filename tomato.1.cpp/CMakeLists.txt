cmake_minimum_required(VERSION 3.0)

project(TOMATO)

aux_source_directory(./src SRCS)

add_library(tomato SHARED ${SRCS})

target_link_libraries(tomato -lpthread -lcrypto -lssl -lmaxminddb)
