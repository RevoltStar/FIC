cmake_minimum_required(VERSION 3.5)

project(fic_cli LANGUAGES CXX)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/FicInstallLayout.cmake)

if(NOT TARGET fic-ipc)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../fic-common/fic-ipc ${CMAKE_CURRENT_BINARY_DIR}/fic-ipc)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(fic-cli
    src/main.cpp
)

target_link_libraries(fic-cli PRIVATE fic-ipc)

install(TARGETS fic-cli RUNTIME DESTINATION "${FIC_PRIVATE_BINDIR}" COMPONENT fic-cli)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/../fic/src/resources/completion/fic"
        DESTINATION "${FIC_BASH_COMPLETION_DIR}"
        RENAME fic-cli COMPONENT fic-cli)
