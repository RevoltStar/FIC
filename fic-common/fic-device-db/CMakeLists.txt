cmake_minimum_required(VERSION 3.5)

project(fic_device_db LANGUAGES CXX)

find_package(SQLite3 REQUIRED)

add_library(fic-device-db STATIC
    src/DB.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../fic/src/utils/ConfigFileHandler.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../fic/src/utils/ExclusivePidLock.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../fic/src/utils/FileHandler.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../fic/src/utils/FileStats.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../fic/src/utils/GlobalConfig.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../fic/src/utils/Logger.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../fic/src/utils/ModuleConfigFileHandler.cpp
)

target_include_directories(fic-device-db
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../fic/src
        ${CMAKE_CURRENT_SOURCE_DIR}/../../fic/src/utils
)

target_link_libraries(fic-device-db PUBLIC SQLite::SQLite3)

install(TARGETS fic-device-db ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
