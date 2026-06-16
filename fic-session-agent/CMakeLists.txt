cmake_minimum_required(VERSION 3.5)

project(fic_session_agent LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(fic-session-agent
    src/main.cpp
)

target_include_directories(fic-session-agent PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../fic/src
)

install(TARGETS fic-session-agent DESTINATION bin)
install(FILES fic-session-agent.desktop DESTINATION /etc/xdg/autostart)
