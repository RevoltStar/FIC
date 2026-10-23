cmake_minimum_required(VERSION 3.10)
project(fic_pam_hooks_native LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
include(CTest)
find_package(Threads REQUIRED)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_path(PAM_INCLUDE_DIR security/pam_modules.h REQUIRED)
find_library(PAM_LIBRARY pam REQUIRED)
get_filename_component(FIC_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)
include("${FIC_SOURCE_DIR}/cmake/FicTargetPlatform.cmake")
add_subdirectory("${FIC_SOURCE_DIR}/fic-common/fic-core" core)
add_subdirectory("${FIC_SOURCE_DIR}/fic-common/fic-ipc" ipc)
set(generated "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${generated}/platform")
foreach(header PasswordAgingPolicyDefaultsGenerated UserCreationPolicyDefaultsGenerated SudoSecurePathDefaultGenerated)
    configure_file("${FIC_SOURCE_DIR}/fic/src/platform/generated/${header}.h.in" "${generated}/platform/${header}.h" @ONLY)
endforeach()
set(daemon "${FIC_SOURCE_DIR}/fic/src")
add_library(fic-platform STATIC
    "${daemon}/platform/ModeAndOwnerPlatform.cpp"
    "${daemon}/platform/PlatformCompatibility.cpp"
    "${daemon}/platform/PlatformExecutableResolver.cpp"
    "${daemon}/platform/PamFaillockStrategy.cpp"
    "${daemon}/platform/PamProviderMetadata.cpp"
    ${FIC_TARGET_PLATFORM_PROFILE_SOURCE})
target_include_directories(fic-platform PUBLIC "${daemon}" "${generated}")
if(CMAKE_LIBRARY_ARCHITECTURE)
    target_compile_definitions(fic-platform PRIVATE FIC_LIBRARY_ARCHITECTURE="${CMAKE_LIBRARY_ARCHITECTURE}")
endif()
set_target_properties(fic-core fic-ipc fic-platform PROPERTIES POSITION_INDEPENDENT_CODE ON)
# Real production module; tests exercise its loadability, not PAM auth/session behavior.
add_library(pam_fic_access MODULE
    "${daemon}/pam-modules/pam_fic_access.cpp"
    "${daemon}/incident/IncidentAccessGateCore.cpp"
    "${daemon}/incident/IncidentAccessClient.cpp"
    "${daemon}/incident/IncidentRecoveryConfigReader.cpp"
    "${daemon}/incident/IncidentResponseMode.cpp"
    "${daemon}/modules/identity_access/pam/PamEffectiveGroupMembership.cpp")
set_target_properties(pam_fic_access PROPERTIES PREFIX "")
target_include_directories(pam_fic_access PRIVATE "${PAM_INCLUDE_DIR}")
target_link_libraries(pam_fic_access PRIVATE fic-platform fic-ipc fic-core "${PAM_LIBRARY}")
set(hook_sources
    "${daemon}/daemon/PackagePamHooks.cpp"
    "${daemon}/daemon/DaemonInstanceLock.cpp"
    "${daemon}/incident/PamIncidentAccessGateVerifier.cpp"
    "${daemon}/incident/AltIncidentAccessGateTopology.cpp"
    "${daemon}/modules/identity_access/pam/PamConfiguration.cpp"
    "${daemon}/modules/identity_access/pam/PamConfigFileTransaction.cpp")
add_executable(package_pam_hooks_tests "${FIC_SOURCE_DIR}/tests/fic/daemon/PackagePamHooksTests.cpp" ${hook_sources})
add_executable(package_pam_hooks_native_driver "${CMAKE_CURRENT_LIST_DIR}/../PackagePamHooksDriver.cpp" ${hook_sources})
foreach(target package_pam_hooks_tests package_pam_hooks_native_driver)
    target_link_libraries(${target} PRIVATE fic-platform fic-core ${CMAKE_DL_LIBS})
endforeach()
add_test(NAME package_pam_hooks_tests COMMAND package_pam_hooks_tests $<TARGET_FILE:pam_fic_access>)
set(alt_argument)
if(FIC_TARGET_PLATFORM STREQUAL "alt-p11")
    set(alt_argument alt)
endif()
add_test(NAME package_pam_hooks_native COMMAND ${Python3_EXECUTABLE}
    "${CMAKE_CURRENT_LIST_DIR}/../native_pam_hooks.py" "${FIC_SOURCE_DIR}"
    $<TARGET_FILE:package_pam_hooks_native_driver> $<TARGET_FILE:pam_fic_access> ${alt_argument})
set_tests_properties(package_pam_hooks_tests package_pam_hooks_native PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)
