cmake_minimum_required(VERSION 3.5)

project(fic_session_agent LANGUAGES CXX)

if(NOT TARGET fic-ipc)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../fic-common/fic-ipc ${CMAKE_CURRENT_BINARY_DIR}/fic-ipc)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(fic-session-agent
    src/main.cpp
)

target_link_libraries(fic-session-agent PRIVATE fic-ipc)

install(TARGETS fic-session-agent DESTINATION bin)
install(FILES fic-session-agent.desktop DESTINATION /etc/xdg/autostart)
