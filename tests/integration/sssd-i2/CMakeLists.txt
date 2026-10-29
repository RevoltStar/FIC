cmake_minimum_required(VERSION 3.16)
project(fic_sssd_i2_native LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_subdirectory(../user_creation platform_setup EXCLUDE_FROM_ALL)
find_package(PkgConfig REQUIRED)
pkg_check_modules(I2_SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
get_filename_component(I2_ROOT "../../.." ABSOLUTE)
add_executable(sssd_i2_probe Driver.cpp
 ${I2_ROOT}/fic/src/service/sssd/SssdDomainScope.cpp
 ${I2_ROOT}/fic/src/service/sssd/SssdEffectiveConfiguration.cpp
 ${I2_ROOT}/fic/src/service/sssd/SssdRelationValidator.cpp
 ${I2_ROOT}/fic/src/service/sssd/SssdServiceAdmission.cpp
 ${I2_ROOT}/fic/src/service/sssd/SssdVerifiedInputClosure.cpp
 ${I2_ROOT}/fic/src/service/VerifiedConfigServiceActivator.cpp
 ${I2_ROOT}/fic/src/service/VerifiedConfigSystemd.cpp
 ${I2_ROOT}/fic/src/service/VerifiedConfigMountSupport.cpp
 ${I2_ROOT}/fic/src/service/VerifiedConfigLaunchContract.cpp)
target_include_directories(sssd_i2_probe PRIVATE ${I2_ROOT}/fic/src)
target_link_libraries(sssd_i2_probe PRIVATE fic-core fic-platform PkgConfig::I2_SYSTEMD)
