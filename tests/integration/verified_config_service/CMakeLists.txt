cmake_minimum_required(VERSION 3.16)
project(fic_verified_config_native LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Threads REQUIRED)
add_subdirectory(../user_creation platform_setup EXCLUDE_FROM_ALL)
find_package(PkgConfig REQUIRED)
pkg_check_modules(NATIVE_SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
get_filename_component(FIC_ROOT "../../.." ABSOLUTE)
add_executable(verified_config_service_native_tests
    ${FIC_ROOT}/tests/fic/service/VerifiedConfigServiceNativeTests.cpp
    ${FIC_ROOT}/fic/src/service/VerifiedConfigServiceActivator.cpp
    ${FIC_ROOT}/fic/src/service/VerifiedConfigMountSupport.cpp
    ${FIC_ROOT}/fic/src/service/ssh/SshVerifiedActivationAdapter.cpp
    ${FIC_ROOT}/fic/src/service/ssh/SshVerifiedInputClosure.cpp
    ${FIC_ROOT}/fic/src/modules/net/ssh/SshRuntime.cpp
    ${FIC_ROOT}/fic/src/modules/net/ssh/SshConfigAudit.cpp
    ${FIC_ROOT}/fic/src/modules/net/ssh/SshConfigSyntax.cpp
    ${FIC_ROOT}/fic/src/modules/net/ssh/SshManagedBlock.cpp
    ${FIC_ROOT}/fic/src/service/VerifiedConfigSystemd.cpp
    ${FIC_ROOT}/fic/src/service/VerifiedConfigLaunchContract.cpp)
target_compile_definitions(verified_config_service_native_tests PRIVATE FIC_ACTIVATOR_TESTING=1)
target_include_directories(verified_config_service_native_tests PRIVATE ${FIC_ROOT}/fic/src)
target_link_libraries(verified_config_service_native_tests PRIVATE fic-core fic-platform PkgConfig::NATIVE_SYSTEMD)
