cmake_minimum_required(VERSION 3.5)

project(fic_ipc LANGUAGES CXX)

add_library(fic-ipc INTERFACE)

target_include_directories(fic-ipc INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

install(DIRECTORY include/ DESTINATION include)
