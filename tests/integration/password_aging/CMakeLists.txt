cmake_minimum_required(VERSION 3.16)
project(fic_password_aging_native LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Reuse the existing focused native platform/core setup. USER_CREATION
# regression coverage remains in the standard user_creation_tests target.
add_subdirectory(../user_creation user_creation EXCLUDE_FROM_ALL)
find_package(Threads REQUIRED)
get_filename_component(FIC_ROOT "../../.." ABSOLUTE)
add_executable(password_aging_native_driver native-driver.cpp
    ${FIC_ROOT}/fic/src/modules/identity_access/IdentityAccessPolicy.cpp
    ${FIC_ROOT}/fic/src/modules/identity_access/password_aging/PasswordAgingPolicies.cpp
    ${FIC_ROOT}/fic/src/modules/identity_access/password_aging/PasswordAgingRuntime.cpp
    ${FIC_ROOT}/fic/src/modules/identity_access/shared/login_defs/IdentityLoginDefsManagedConfig.cpp
    ${FIC_ROOT}/fic/src/modules/identity_access/shared/login_defs/IdentityLoginDefsManagedTransaction.cpp
    ${FIC_ROOT}/fic/src/rollback/MutationJournal.cpp
    ${FIC_ROOT}/fic/src/rollback/DaemonMutationJournal.cpp
    ${FIC_ROOT}/fic/src/modules/dac/sudo/SudoersDisabledWrapper.cpp)
target_include_directories(password_aging_native_driver PRIVATE ${FIC_ROOT}/fic/src)
target_link_libraries(password_aging_native_driver PRIVATE fic-core fic-policy fic-platform Threads::Threads)
