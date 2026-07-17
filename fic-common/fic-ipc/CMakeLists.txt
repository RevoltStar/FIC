cmake_minimum_required(VERSION 3.5)

project(fic_ipc LANGUAGES CXX)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/FicInstallLayout.cmake)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(FIC_IPC_GENERATED_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated/include)
file(MAKE_DIRECTORY ${FIC_IPC_GENERATED_INCLUDE_DIR}/fic/ipc)
configure_file(
    include/fic/ipc/FicIpcPathDefaults.h.in
    ${FIC_IPC_GENERATED_INCLUDE_DIR}/fic/ipc/FicIpcPathDefaults.h
    @ONLY
)

add_library(fic-ipc STATIC src/FicAdminSocket.cpp)

target_include_directories(fic-ipc PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${FIC_IPC_GENERATED_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:include>
)

install(TARGETS fic-ipc ARCHIVE DESTINATION lib COMPONENT Development)
install(DIRECTORY include/ DESTINATION include COMPONENT Development
        FILES_MATCHING PATTERN "*.h")
install(FILES ${FIC_IPC_GENERATED_INCLUDE_DIR}/fic/ipc/FicIpcPathDefaults.h
        DESTINATION include/fic/ipc COMPONENT Development)
