cmake_minimum_required(VERSION 3.5)

project(fic_core LANGUAGES CXX)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/FicInstallLayout.cmake)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_library(fic-core STATIC
    src/AtomicFileWriter.cpp
    src/CommandHashStore.cpp
    src/ConfigFileHandler.cpp
    src/ExclusivePidLock.cpp
    src/FileHandler.cpp
    src/FileStats.cpp
    src/FicRuntimePaths.cpp
    src/GlobalConfig.cpp
    src/LocalizationManager.cpp
    src/Logger.cpp
    src/ModuleConfigFileHandler.cpp
    src/MultilineConfigFileHandler.cpp
    src/NotifyUser.cpp
    src/ProcessExecutor.cpp
    src/SectionConfigFileHandler.cpp
    src/SingleLineFileHandler.cpp
    src/VerifiedProcessExecutor.cpp
)

set(FIC_CORE_GENERATED_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated/include)
file(MAKE_DIRECTORY ${FIC_CORE_GENERATED_INCLUDE_DIR}/fic/core)
configure_file(
    include/fic/core/FicPathDefaults.h.in
    ${FIC_CORE_GENERATED_INCLUDE_DIR}/fic/core/FicPathDefaults.h
    @ONLY
)

target_include_directories(fic-core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${FIC_CORE_GENERATED_INCLUDE_DIR}>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(fic-core PRIVATE OpenSSL::Crypto Threads::Threads)

install(TARGETS fic-core ARCHIVE DESTINATION lib COMPONENT Development)
install(DIRECTORY include/ DESTINATION include COMPONENT Development
        FILES_MATCHING PATTERN "*.h")
install(FILES ${FIC_CORE_GENERATED_INCLUDE_DIR}/fic/core/FicPathDefaults.h
        DESTINATION include/fic/core COMPONENT Development)
