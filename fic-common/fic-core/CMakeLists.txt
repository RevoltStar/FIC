cmake_minimum_required(VERSION 3.5)

project(fic_core LANGUAGES CXX)

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

target_include_directories(fic-core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(fic-core PRIVATE OpenSSL::Crypto Threads::Threads)

install(TARGETS fic-core ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
