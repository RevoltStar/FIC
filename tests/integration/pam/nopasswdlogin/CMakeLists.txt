cmake_minimum_required(VERSION 3.16)
project(fic_nopasswdlogin_native LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build the actual backend without unrelated GUI/PAM build dependencies.
get_filename_component(FIC_NOPASSWDLOGIN_SOURCE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../.." ABSOLUTE)
include("${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/cmake/FicTargetPlatform.cmake")
add_subdirectory("${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic-common/fic-policy" "${CMAKE_CURRENT_BINARY_DIR}/fic-policy")
find_package(Threads REQUIRED)

set(FIC_NOPASSWDLOGIN_GENERATED_INCLUDE "${CMAKE_CURRENT_BINARY_DIR}/generated/include")
file(MAKE_DIRECTORY "${FIC_NOPASSWDLOGIN_GENERATED_INCLUDE}/platform")
foreach(header PasswordAgingPolicyDefaultsGenerated UserCreationPolicyDefaultsGenerated SudoSecurePathDefaultGenerated)
    configure_file("${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/platform/generated/${header}.h.in"
        "${FIC_NOPASSWDLOGIN_GENERATED_INCLUDE}/platform/${header}.h" @ONLY)
endforeach()
add_library(fic-platform STATIC
    "${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/platform/ModeAndOwnerPlatform.cpp"
    "${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/platform/PlatformCompatibility.cpp"
    "${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/platform/PlatformExecutableResolver.cpp"
    "${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/platform/PamFaillockStrategy.cpp"
    "${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/platform/PamProviderMetadata.cpp"
    "${FIC_TARGET_PLATFORM_PROFILE_SOURCE}")
target_include_directories(fic-platform PUBLIC "${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src" "${FIC_NOPASSWDLOGIN_GENERATED_INCLUDE}")
if(CMAKE_LIBRARY_ARCHITECTURE)
    target_compile_definitions(fic-platform PRIVATE FIC_LIBRARY_ARCHITECTURE="${CMAKE_LIBRARY_ARCHITECTURE}")
endif()
add_executable(nopasswdlogin_native_driver driver.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/identity_access/pam/PamNopasswdloginPackageProof.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/identity_access/pam/PamNopasswdloginTransaction.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/rollback/MutationJournal.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/rollback/ScopeTransition.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/dac/sudo/SudoersDisabledWrapper.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/identity_access/pam/PamNopasswdloginFragment.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/identity_access/pam/PamCapabilityVerifier.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/identity_access/pam/PamManagedPasswordSlots.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/identity_access/pam/PamConfiguration.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/identity_access/pam/PamConfigFileTransaction.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/identity_access/pam/PamControlFlowAnalyzer.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/identity_access/pam/PamOptionFile.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/identity_access/pam/PamOptionValueCodec.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/identity_access/pam/PamPlatformComposition.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/identity_access/pam/PamProviderCatalog.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/identity_access/pam/PamProviderInspector.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/identity_access/pam/PamProviderSemanticVerifier.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/identity_access/pam/PwhistoryConfigFile.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/identity_access/pam/PamProviderModuleArguments.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/identity_access/pam/PamPwhistoryArguments.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/identity_access/pam/PasswdqcConfigFile.cpp
    ${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src/modules/identity_access/pam/PwqualityConfigFile.cpp
)
target_include_directories(nopasswdlogin_native_driver PRIVATE "${FIC_NOPASSWDLOGIN_SOURCE_ROOT}/fic/src")
target_link_libraries(nopasswdlogin_native_driver PRIVATE fic-core fic-policy fic-platform Threads::Threads)
