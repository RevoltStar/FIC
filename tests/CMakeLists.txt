find_package(Python3 COMPONENTS Interpreter)
find_package(Threads REQUIRED)

if(Python3_Interpreter_FOUND)
    add_test(
        NAME device_control_static_checks
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/device-control/static_checks.py
                ${CMAKE_SOURCE_DIR}
    )
endif()

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
)
target_include_directories(sysctl_configuration_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(sysctl_configuration_tests PRIVATE fic-core)
add_test(NAME sysctl_configuration_tests COMMAND sysctl_configuration_tests)
