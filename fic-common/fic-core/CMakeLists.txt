cmake_minimum_required(VERSION 3.5)

project(fic_core LANGUAGES CXX)

include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/FicInstallLayout.cmake)

if(NOT TARGET fic-version)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../fic-version ${CMAKE_CURRENT_BINARY_DIR}/fic-version)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_library(fic-core STATIC
    src/config/ConfigFileHandler.cpp
    src/config/ConfigSchemaManager.cpp
    src/config/ModuleConfigFileHandler.cpp
    src/config/MultilineConfigFileHandler.cpp
    src/config/PolicyConfig.cpp
    src/config/SectionConfigFileHandler.cpp
    src/config/SingleLineFileHandler.cpp
    src/fs/AtomicFileWriter.cpp
    src/fs/FileHandler.cpp
    src/fs/FileStats.cpp
    src/i18n/LocalizationManager.cpp
    src/integrity/CommandHashStore.cpp
    src/logging/Logger.cpp
    src/notification/NotifyUser.cpp
    src/process/ExclusivePidLock.cpp
    src/process/ProcessExecutor.cpp
    src/process/VerifiedProcessExecutor.cpp
    src/runtime/FicRuntimePaths.cpp
)

set(FIC_CORE_GENERATED_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated/include)
file(MAKE_DIRECTORY ${FIC_CORE_GENERATED_INCLUDE_DIR}/fic/core/runtime)
configure_file(
    include/fic/core/runtime/FicPathDefaults.h.in
    ${FIC_CORE_GENERATED_INCLUDE_DIR}/fic/core/runtime/FicPathDefaults.h
    @ONLY
)

target_include_directories(fic-core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${FIC_CORE_GENERATED_INCLUDE_DIR}>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(fic-core PUBLIC fic-version PRIVATE OpenSSL::Crypto Threads::Threads)

install(TARGETS fic-core ARCHIVE DESTINATION lib COMPONENT Development)
install(DIRECTORY include/ DESTINATION include COMPONENT Development
        FILES_MATCHING PATTERN "*.h")
install(FILES ${FIC_CORE_GENERATED_INCLUDE_DIR}/fic/core/runtime/FicPathDefaults.h
        DESTINATION include/fic/core/runtime COMPONENT Development)
