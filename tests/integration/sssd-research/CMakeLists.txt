cmake_minimum_required(VERSION 3.16)
project(fic_sssd_research LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_subdirectory(../user_creation platform_setup EXCLUDE_FROM_ALL)
find_package(PkgConfig REQUIRED)
pkg_check_modules(RESEARCH_SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
get_filename_component(RESEARCH_ROOT "../../.." ABSOLUTE)
add_executable(sssd_engine_probe EngineProbe.cpp
 ${RESEARCH_ROOT}/fic/src/service/VerifiedConfigServiceActivator.cpp
 ${RESEARCH_ROOT}/fic/src/service/VerifiedConfigMountSupport.cpp
 ${RESEARCH_ROOT}/fic/src/service/VerifiedConfigLaunchContract.cpp
 ${RESEARCH_ROOT}/fic/src/service/VerifiedConfigSystemd.cpp)
target_compile_definitions(sssd_engine_probe PRIVATE FIC_ACTIVATOR_TESTING=1)
target_include_directories(sssd_engine_probe PRIVATE ${RESEARCH_ROOT}/fic/src)
target_link_libraries(sssd_engine_probe PRIVATE fic-core fic-platform PkgConfig::RESEARCH_SYSTEMD)
