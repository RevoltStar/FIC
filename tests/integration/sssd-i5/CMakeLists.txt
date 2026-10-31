cmake_minimum_required(VERSION 3.16)
project(fic_sssd_i5_native LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_subdirectory(../user_creation platform_setup EXCLUDE_FROM_ALL)
find_package(PkgConfig REQUIRED)
pkg_check_modules(I5_SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
get_filename_component(I5_ROOT "../../.." ABSOLUTE)
add_executable(sssd_i5_probe Driver.cpp ../sssd-i4/StagedWriteCrash.cpp
 ${I5_ROOT}/fic/src/modules/identity_access/sssd/SssdConfiguration.cpp
 ${I5_ROOT}/fic/src/modules/identity_access/shared/configuration/PreparedFileChange.cpp
 ${I5_ROOT}/fic/src/modules/identity_access/composite/ConfigurationTransaction.cpp
 ${I5_ROOT}/fic/src/service/sssd/SssdTransactionCoordinator.cpp
 ${I5_ROOT}/fic/src/rollback/MutationJournal.cpp
 ${I5_ROOT}/fic/src/modules/dac/sudo/SudoersDisabledWrapper.cpp
 ${I5_ROOT}/fic/src/service/sssd/SssdVerifiedActivationAdapter.cpp
 ${I5_ROOT}/fic/src/service/sssd/SssdRuntimeProof.cpp
 ${I5_ROOT}/fic/src/service/sssd/SssdDomainScope.cpp
 ${I5_ROOT}/fic/src/service/sssd/SssdEffectiveConfiguration.cpp
 ${I5_ROOT}/fic/src/service/sssd/SssdRelationValidator.cpp
 ${I5_ROOT}/fic/src/service/sssd/SssdServiceAdmission.cpp
 ${I5_ROOT}/fic/src/service/sssd/SssdVerifiedInputClosure.cpp
 ${I5_ROOT}/fic/src/service/VerifiedConfigServiceActivator.cpp
 ${I5_ROOT}/fic/src/service/VerifiedConfigSystemd.cpp
 ${I5_ROOT}/fic/src/service/VerifiedConfigMountSupport.cpp
 ${I5_ROOT}/fic/src/service/VerifiedConfigLaunchContract.cpp)
target_include_directories(sssd_i5_probe PRIVATE ${I5_ROOT}/fic/src)
target_link_libraries(sssd_i5_probe PRIVATE fic-core fic-policy fic-platform PkgConfig::I5_SYSTEMD)

target_compile_definitions(sssd_i5_probe PRIVATE FIC_ACTIVATOR_TESTING=1)
