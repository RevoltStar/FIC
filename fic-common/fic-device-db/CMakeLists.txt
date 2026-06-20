cmake_minimum_required(VERSION 3.5)

project(fic_device_db LANGUAGES CXX)

find_package(SQLite3 REQUIRED)

if(NOT TARGET fic-core)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../fic-core ${CMAKE_CURRENT_BINARY_DIR}/fic-core)
endif()

add_library(fic-device-db STATIC
    src/DB.cpp
)

target_include_directories(fic-device-db
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(fic-device-db PUBLIC SQLite::SQLite3 fic-core)

install(TARGETS fic-device-db ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
