cmake_minimum_required(VERSION 3.16)
project(fic_ssh_provenance_native LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
enable_testing()
find_package(Threads REQUIRED)
# Existing native platform/core setup avoids unrelated GUI development packages.
add_subdirectory(../user_creation platform_setup EXCLUDE_FROM_ALL)
include("${CMAKE_CURRENT_SOURCE_DIR}/../../fic/modules/net/ssh/SshApplyRollbackSources.cmake")
add_executable(ssh_apply_rollback_tests ${FIC_SSH_APPLY_ROLLBACK_SOURCES})
# Root tests add this existing dispatcher dependency in their late target loop.
target_sources(ssh_apply_rollback_tests PRIVATE
    ${FIC_SSH_TEST_ROOT}/fic/src/modules/dac/sudo/SudoersAuthenticationTransaction.cpp)
target_compile_definitions(ssh_apply_rollback_tests PRIVATE FIC_SSH_TRANSACTION_TESTING=1)
target_include_directories(ssh_apply_rollback_tests PRIVATE ${FIC_SSH_TEST_ROOT}/fic/src)
target_link_libraries(ssh_apply_rollback_tests PRIVATE fic-core fic-policy fic-platform Threads::Threads)
add_test(NAME ssh_apply_rollback_tests COMMAND ssh_apply_rollback_tests)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SSH_PROVENANCE_SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
target_sources(ssh_apply_rollback_tests PRIVATE
    ${FIC_SSH_TEST_ROOT}/fic/src/service/VerifiedConfigServiceActivator.cpp
    ${FIC_SSH_TEST_ROOT}/fic/src/service/VerifiedConfigMountSupport.cpp
    ${FIC_SSH_TEST_ROOT}/fic/src/service/VerifiedConfigLaunchContract.cpp
    ${FIC_SSH_TEST_ROOT}/fic/src/service/VerifiedConfigSystemd.cpp
    ${FIC_SSH_TEST_ROOT}/fic/src/service/ssh/SshVerifiedActivationAdapter.cpp
    ${FIC_SSH_TEST_ROOT}/fic/src/service/ssh/SshVerifiedInputClosure.cpp
    ${FIC_SSH_TEST_ROOT}/fic/src/service/ssh/UbuntuSshSocketFlow.cpp)
target_link_libraries(ssh_apply_rollback_tests PRIVATE PkgConfig::SSH_PROVENANCE_SYSTEMD)
