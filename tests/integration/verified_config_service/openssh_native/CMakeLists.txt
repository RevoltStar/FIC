cmake_minimum_required(VERSION 3.16)
project(fic_openssh_native LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_subdirectory(.. component EXCLUDE_FROM_ALL)
find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSH_SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
get_filename_component(FIC_ROOT "../../../.." ABSOLUTE)
add_executable(openssh_native_driver Driver.cpp
    ${FIC_ROOT}/fic/src/service/VerifiedConfigServiceActivator.cpp
    ${FIC_ROOT}/fic/src/service/VerifiedConfigMountSupport.cpp
    ${FIC_ROOT}/fic/src/service/VerifiedConfigLaunchContract.cpp
    ${FIC_ROOT}/fic/src/service/VerifiedConfigSystemd.cpp
    ${FIC_ROOT}/fic/src/service/ssh/SshVerifiedActivationAdapter.cpp
    ${FIC_ROOT}/fic/src/service/ssh/SshVerifiedInputClosure.cpp
    ${FIC_ROOT}/fic/src/modules/net/ssh/SshRuntime.cpp
    ${FIC_ROOT}/fic/src/modules/net/ssh/SshManagedBlock.cpp
    ${FIC_ROOT}/fic/src/modules/net/ssh/SshConfigAudit.cpp
    ${FIC_ROOT}/fic/src/modules/net/ssh/SshConfigSyntax.cpp)
target_compile_definitions(openssh_native_driver PRIVATE FIC_ACTIVATOR_TESTING=1)
target_include_directories(openssh_native_driver PRIVATE ${FIC_ROOT}/fic/src)
target_link_libraries(openssh_native_driver PRIVATE fic-core fic-platform PkgConfig::OPENSSH_SYSTEMD)
