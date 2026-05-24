cmake_minimum_required(VERSION 3.5)

project(fic_cli LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)

file(GLOB_RECURSE FIC_CORE_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/../fic/src/core/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../fic/src/modules/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../fic/src/utils/*.cpp"
)

add_executable(fic-cli
    src/main.cpp
    ${FIC_CORE_SRC}
)

target_include_directories(fic-cli PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../fic/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../fic/src/core
    ${CMAKE_CURRENT_SOURCE_DIR}/../fic/src/modules
    ${CMAKE_CURRENT_SOURCE_DIR}/../fic/src/utils
)

target_link_libraries(fic-cli PRIVATE
    SQLite::SQLite3
    OpenSSL::SSL
    OpenSSL::Crypto
)

install(TARGETS fic-cli DESTINATION bin)
