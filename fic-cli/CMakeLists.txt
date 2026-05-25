cmake_minimum_required(VERSION 3.5)

project(fic_cli LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(fic-cli
    src/main.cpp
)

target_include_directories(fic-cli PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../fic/src
)

install(TARGETS fic-cli DESTINATION bin)
