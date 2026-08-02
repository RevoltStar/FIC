cmake_minimum_required(VERSION 3.5)

project(fic LANGUAGES CXX)

include(CTest)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/FicInstallLayout.cmake)

add_subdirectory(fic-common/fic-version)
add_subdirectory(fic-common/fic-ipc)
add_subdirectory(fic-common/fic-core)
add_subdirectory(fic-common/fic-device-db)
add_subdirectory(fic-common/fic-policy)
add_subdirectory(fic)
add_subdirectory(fic-session-agent)
add_subdirectory(fic-cli)
add_subdirectory(fic-dick)
add_subdirectory(fic-gui)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
