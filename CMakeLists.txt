cmake_minimum_required(VERSION 3.8)
project(dfcipher)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.cpp DFC.cpp DFC.h Key.cpp Key.h)
add_executable(dfcipher ${SOURCE_FILES})