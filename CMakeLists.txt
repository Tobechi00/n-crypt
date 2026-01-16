cmake_minimum_required(VERSION 3.10)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#set standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

## Use the variable PROJECT_NAME for changing the target name
set( PROJECT_NAME "ncrypt" )

## Set our project name
project(${PROJECT_NAME})

## Use all the *.cpp files we found under this folder for the project
FILE(GLOB SRCS "*.cpp" "*.c")

set(SRCS
    src/util/util.cpp
    src/AES/aes_encryption/aes_encryption.cpp
    src/AES/key_scheduler/key_scheduler.cpp
    src/main.cpp
    src/AES/aes_encryption/aes_decryption.cpp
)

## Define the executable
add_executable(${PROJECT_NAME} ${SRCS})

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR})
