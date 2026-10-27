cmake_minimum_required(VERSION 3.16)
project(fic_openssh_native LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_subdirectory(.. component EXCLUDE_FROM_ALL)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(OPENSSH_SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
get_filename_component(FIC_ROOT "../../../.." ABSOLUTE)
if(NOT TARGET fic-ipc)
    add_subdirectory(${FIC_ROOT}/fic-common/fic-ipc component/fic-ipc EXCLUDE_FROM_ALL)
endif()
add_executable(openssh_native_driver Driver.cpp
    ${FIC_ROOT}/fic/src/service/VerifiedConfigServiceActivator.cpp
    ${FIC_ROOT}/fic/src/service/VerifiedConfigMountSupport.cpp
    ${FIC_ROOT}/fic/src/service/VerifiedConfigLaunchContract.cpp
    ${FIC_ROOT}/fic/src/service/VerifiedConfigSystemd.cpp
    ${FIC_ROOT}/fic/src/service/ssh/SshVerifiedActivationAdapter.cpp
    ${FIC_ROOT}/fic/src/service/ssh/SshVerifiedInputClosure.cpp
    ${FIC_ROOT}/fic/src/service/ssh/UbuntuSshSocketFlow.cpp
    ${FIC_ROOT}/fic/src/service/ssh/SshListenerProof.cpp
    ${FIC_ROOT}/fic/src/service/ssh/AltSshServiceFlow.cpp
    ${FIC_ROOT}/fic/src/modules/net/ssh/SshRuntime.cpp
    ${FIC_ROOT}/fic/src/modules/net/ssh/SshManagedBlock.cpp
    ${FIC_ROOT}/fic/src/modules/net/ssh/SshConfigAudit.cpp
    ${FIC_ROOT}/fic/src/modules/net/ssh/SshConfigSyntax.cpp)
target_sources(openssh_native_driver PRIVATE ${FIC_ROOT}/fic/src/daemon/PolicyDisableFlow.cpp)
target_compile_definitions(openssh_native_driver PRIVATE FIC_ACTIVATOR_TESTING=1 FIC_SSH_TRANSACTION_TESTING=1)
target_include_directories(openssh_native_driver PRIVATE ${FIC_ROOT}/fic/src)
target_link_libraries(openssh_native_driver PRIVATE fic-core fic-platform PkgConfig::OPENSSH_SYSTEMD)

# Real production module entrypoint, sharing the provenance suite's source list.
include(${FIC_ROOT}/tests/fic/modules/net/ssh/SshApplyRollbackSources.cmake)
list(REMOVE_ITEM FIC_SSH_APPLY_ROLLBACK_SOURCES
    ${FIC_ROOT}/tests/fic/modules/net/ssh/SshApplyRollbackTests.cpp)
get_target_property(ssh_driver_sources openssh_native_driver SOURCES)
list(APPEND ssh_driver_sources ${FIC_SSH_APPLY_ROLLBACK_SOURCES}
    ${FIC_ROOT}/fic/src/modules/dac/sudo/SudoersAuthenticationTransaction.cpp)
list(REMOVE_DUPLICATES ssh_driver_sources)
set_property(TARGET openssh_native_driver PROPERTY SOURCES ${ssh_driver_sources})
target_link_libraries(openssh_native_driver PRIVATE fic-policy fic-ipc Threads::Threads)

# Portable pure contract tests exercise the same adapter sources/profile data.
enable_testing()
get_target_property(adapter_contract_sources verified_config_service_native_tests SOURCES)
list(REMOVE_ITEM adapter_contract_sources ${FIC_ROOT}/tests/fic/service/VerifiedConfigServiceNativeTests.cpp)
add_executable(ssh_verified_activation_tests ${FIC_ROOT}/tests/fic/service/SshVerifiedActivationTests.cpp ${adapter_contract_sources})
target_compile_definitions(ssh_verified_activation_tests PRIVATE FIC_ACTIVATOR_TESTING=1)
target_include_directories(ssh_verified_activation_tests PRIVATE ${FIC_ROOT}/fic/src)
target_link_libraries(ssh_verified_activation_tests PRIVATE fic-core fic-platform PkgConfig::OPENSSH_SYSTEMD)
add_test(NAME ssh_verified_activation_tests COMMAND ssh_verified_activation_tests)
