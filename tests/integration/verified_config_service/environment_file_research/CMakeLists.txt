cmake_minimum_required(VERSION 3.16)
project(fic_environment_file_research LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_subdirectory(../audit audit_setup EXCLUDE_FROM_ALL)
find_package(PkgConfig REQUIRED)
pkg_check_modules(RESEARCH_SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
get_filename_component(RESEARCH_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../.." ABSOLUTE)
add_executable(environment_file_research
    EnvironmentFileResearch.cpp
    ${RESEARCH_ROOT}/fic/src/service/VerifiedConfigMountSupport.cpp
    ${RESEARCH_ROOT}/fic/src/service/VerifiedConfigLaunchContract.cpp)
target_include_directories(environment_file_research PRIVATE ${RESEARCH_ROOT}/fic/src)
target_link_libraries(environment_file_research PRIVATE fic-core fic-platform PkgConfig::RESEARCH_SYSTEMD)
# Research fixture only: no activator or SSH production implementation linked.
