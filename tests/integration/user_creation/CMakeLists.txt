cmake_minimum_required(VERSION 3.16)
project(fic_user_creation_native LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build the actual backend without unrelated GUI/PAM build dependencies.
get_filename_component(FIC_USER_CREATION_SOURCE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
include("${FIC_USER_CREATION_SOURCE_ROOT}/cmake/FicTargetPlatform.cmake")
add_subdirectory("${FIC_USER_CREATION_SOURCE_ROOT}/fic-common/fic-policy" "${CMAKE_CURRENT_BINARY_DIR}/fic-policy")
find_package(Threads REQUIRED)

set(FIC_USER_CREATION_GENERATED_INCLUDE "${CMAKE_CURRENT_BINARY_DIR}/generated/include")
file(MAKE_DIRECTORY "${FIC_USER_CREATION_GENERATED_INCLUDE}/platform")
foreach(header PasswordAgingPolicyDefaultsGenerated UserCreationPolicyDefaultsGenerated SudoSecurePathDefaultGenerated)
    configure_file("${FIC_USER_CREATION_SOURCE_ROOT}/fic/src/platform/generated/${header}.h.in"
        "${FIC_USER_CREATION_GENERATED_INCLUDE}/platform/${header}.h" @ONLY)
endforeach()
add_library(fic-platform STATIC
    "${FIC_USER_CREATION_SOURCE_ROOT}/fic/src/platform/ModeAndOwnerPlatform.cpp"
    "${FIC_USER_CREATION_SOURCE_ROOT}/fic/src/platform/PlatformCompatibility.cpp"
    "${FIC_USER_CREATION_SOURCE_ROOT}/fic/src/platform/PlatformExecutableResolver.cpp"
    "${FIC_USER_CREATION_SOURCE_ROOT}/fic/src/platform/PamFaillockStrategy.cpp"
    "${FIC_USER_CREATION_SOURCE_ROOT}/fic/src/platform/PamProviderMetadata.cpp"
    "${FIC_TARGET_PLATFORM_PROFILE_SOURCE}")
target_include_directories(fic-platform PUBLIC "${FIC_USER_CREATION_SOURCE_ROOT}/fic/src" "${FIC_USER_CREATION_GENERATED_INCLUDE}")
if(CMAKE_LIBRARY_ARCHITECTURE)
    target_compile_definitions(fic-platform PRIVATE FIC_LIBRARY_ARCHITECTURE="${CMAKE_LIBRARY_ARCHITECTURE}")
endif()
add_executable(user_creation_native_driver native-driver.cpp
    ${FIC_USER_CREATION_SOURCE_ROOT}/fic/src/modules/identity_access/IdentityAccessPolicy.cpp
    ${FIC_USER_CREATION_SOURCE_ROOT}/fic/src/modules/identity_access/shared/configuration/LoginDefsFileHandler.cpp
    ${FIC_USER_CREATION_SOURCE_ROOT}/fic/src/modules/identity_access/shared/configuration/LocalGroupDatabase.cpp
    ${FIC_USER_CREATION_SOURCE_ROOT}/fic/src/modules/identity_access/user_creation/configuration/AdduserConfigFileHandler.cpp
    ${FIC_USER_CREATION_SOURCE_ROOT}/fic/src/modules/identity_access/user_creation/configuration/UseraddDefaultsFileHandler.cpp
    ${FIC_USER_CREATION_SOURCE_ROOT}/fic/src/modules/identity_access/user_creation/UserCreationPolicies.cpp
    ${FIC_USER_CREATION_SOURCE_ROOT}/fic/src/modules/identity_access/user_creation/UserCreationManagedConfig.cpp
    ${FIC_USER_CREATION_SOURCE_ROOT}/fic/src/modules/identity_access/user_creation/UserCreationManagedTransaction.cpp
    ${FIC_USER_CREATION_SOURCE_ROOT}/fic/src/modules/identity_access/shared/login_defs/IdentityLoginDefsManagedConfig.cpp
    ${FIC_USER_CREATION_SOURCE_ROOT}/fic/src/modules/identity_access/shared/login_defs/IdentityLoginDefsManagedTransaction.cpp
    ${FIC_USER_CREATION_SOURCE_ROOT}/fic/src/rollback/MutationJournal.cpp
    ${FIC_USER_CREATION_SOURCE_ROOT}/fic/src/rollback/DaemonMutationJournal.cpp
    ${FIC_USER_CREATION_SOURCE_ROOT}/fic/src/modules/dac/sudo/SudoersDisabledWrapper.cpp
)
target_include_directories(user_creation_native_driver PRIVATE "${FIC_USER_CREATION_SOURCE_ROOT}/fic/src")
target_link_libraries(user_creation_native_driver PRIVATE fic-core fic-policy fic-platform Threads::Threads)
