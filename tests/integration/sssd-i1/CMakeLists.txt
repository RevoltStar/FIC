cmake_minimum_required(VERSION 3.16)
project(fic_sssd_i1_native LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_subdirectory(../user_creation platform_setup EXCLUDE_FROM_ALL)
find_package(PkgConfig REQUIRED)
pkg_check_modules(I1_SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
get_filename_component(I1_ROOT "../../.." ABSOLUTE)
add_executable(sssd_i1_probe Driver.cpp
 ${I1_ROOT}/fic/src/service/sssd/SssdServiceAdmission.cpp
 ${I1_ROOT}/fic/src/service/sssd/SssdVerifiedInputClosure.cpp
 ${I1_ROOT}/fic/src/service/VerifiedConfigServiceActivator.cpp
 ${I1_ROOT}/fic/src/service/VerifiedConfigSystemd.cpp
 ${I1_ROOT}/fic/src/service/VerifiedConfigMountSupport.cpp
 ${I1_ROOT}/fic/src/service/VerifiedConfigLaunchContract.cpp)
target_compile_definitions(sssd_i1_probe PRIVATE FIC_SSSD_I1_TESTING=1)
target_include_directories(sssd_i1_probe PRIVATE ${I1_ROOT}/fic/src)
target_link_libraries(sssd_i1_probe PRIVATE fic-core fic-platform PkgConfig::I1_SYSTEMD)
