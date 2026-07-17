cmake_minimum_required(VERSION 3.5)

project(fic_session_agent LANGUAGES CXX)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/FicInstallLayout.cmake)

if(NOT TARGET fic-ipc)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../fic-common/fic-ipc ${CMAKE_CURRENT_BINARY_DIR}/fic-ipc)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(fic-session-agent
    src/main.cpp
)

target_link_libraries(fic-session-agent PRIVATE fic-ipc)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/fic-session-agent.desktop.in"
    "${CMAKE_CURRENT_BINARY_DIR}/fic-session-agent.desktop"
    @ONLY)
install(TARGETS fic-session-agent RUNTIME DESTINATION "${FIC_PRIVATE_BINDIR}"
        COMPONENT fic-session-agent)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/fic-session-agent.desktop"
        DESTINATION "${FIC_XDG_AUTOSTART_DIR}" COMPONENT fic-session-agent)
