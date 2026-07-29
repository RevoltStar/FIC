find_package(Python3 COMPONENTS Interpreter)
find_package(Threads REQUIRED)

if(Python3_Interpreter_FOUND)
    add_test(
        NAME device_control_static_checks
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/device-control/static_checks.py
                ${CMAKE_SOURCE_DIR}
    )
    add_test(
        NAME path_layout_static_checks
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/paths/static_checks.py
                ${CMAKE_SOURCE_DIR}
    )
    add_test(
        NAME ssh_policy_static_checks
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/ssh/static_checks.py
                ${CMAKE_SOURCE_DIR}
    )
    add_test(
        NAME platform_profile_static_checks
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/platform/static_checks.py
                ${CMAKE_SOURCE_DIR}
    )
endif()

add_executable(runtime_paths_tests paths/RuntimePathsTests.cpp)
target_link_libraries(runtime_paths_tests PRIVATE fic-core fic-device-db)
add_test(NAME runtime_paths_tests COMMAND runtime_paths_tests)

add_executable(ipc_paths_tests paths/IpcPathsTests.cpp)
target_link_libraries(ipc_paths_tests PRIVATE fic-ipc)
add_test(NAME ipc_paths_tests COMMAND ipc_paths_tests)

add_executable(admin_socket_tests paths/AdminSocketTests.cpp)
target_link_libraries(admin_socket_tests PRIVATE fic-ipc)
add_test(NAME admin_socket_tests COMMAND admin_socket_tests)
set_tests_properties(admin_socket_tests PROPERTIES SKIP_RETURN_CODE 77)

add_executable(sudoers_configuration_tests
    sudoers/SudoersConfigurationTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/dac/submodules/sudo/SudoersConfiguration.cpp
)
target_include_directories(sudoers_configuration_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(sudoers_configuration_tests PRIVATE fic-core Threads::Threads)
add_test(NAME sudoers_configuration_tests COMMAND sudoers_configuration_tests)

add_executable(file_handler_options_tests
    file-handler/FileHandlerOptionsTests.cpp
)
target_link_libraries(file_handler_options_tests PRIVATE fic-core)
add_test(NAME file_handler_options_tests COMMAND file_handler_options_tests)

add_executable(sysctl_configuration_tests
    sysctl/SysctlConfigurationTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/sysctl/SysctlConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/sysctl/SysctlRuntime.cpp
)
target_include_directories(sysctl_configuration_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(sysctl_configuration_tests PRIVATE fic-core)
add_test(NAME sysctl_configuration_tests COMMAND sysctl_configuration_tests)

add_executable(ssh_runtime_tests
    ssh/SshRuntimeTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/net/submodules/SshConfigAudit.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/net/submodules/SshConfigFile.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/net/submodules/SshConfigSyntax.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/net/submodules/SshRuntime.cpp
)
target_include_directories(ssh_runtime_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(ssh_runtime_tests PRIVATE fic-core fic-policy fic-platform)
add_test(NAME ssh_runtime_tests COMMAND ssh_runtime_tests)

add_executable(platform_profile_tests
    platform/PlatformProfileTests.cpp
)
target_include_directories(platform_profile_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(platform_profile_tests PRIVATE fic-platform)
add_test(NAME platform_profile_tests COMMAND platform_profile_tests)
