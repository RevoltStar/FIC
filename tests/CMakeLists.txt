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

add_test(
    NAME packaging_build_resource_tests
    COMMAND bash
            ${CMAKE_CURRENT_SOURCE_DIR}/packaging/build-resources-test.sh
)

add_test(
    NAME version_contract_tests
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/version/version-contract-test.sh
)
add_test(
    NAME release_contract_tests
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/version/release-contract-test.sh
)

add_executable(build_info_tests version/BuildInfoTests.cpp)
target_link_libraries(build_info_tests PRIVATE fic-version)
add_test(NAME build_info_tests COMMAND build_info_tests)

add_executable(runtime_paths_tests paths/RuntimePathsTests.cpp)
target_link_libraries(runtime_paths_tests PRIVATE fic-core fic-device-db)
add_test(NAME runtime_paths_tests COMMAND runtime_paths_tests)

add_executable(device_tree_revision_tests
    device-control/DeviceTreeRevisionTests.cpp
)
target_compile_definitions(device_tree_revision_tests PRIVATE
    FIC_TEST_LEGACY_DEVICE_DB="${CMAKE_SOURCE_DIR}/fic/src/scripts/db/devices.db"
)
target_link_libraries(device_tree_revision_tests PRIVATE fic-device-db)
add_test(NAME device_tree_revision_tests COMMAND device_tree_revision_tests)

add_executable(ipc_paths_tests paths/IpcPathsTests.cpp)
target_link_libraries(ipc_paths_tests PRIVATE fic-ipc)
add_test(NAME ipc_paths_tests COMMAND ipc_paths_tests)

add_executable(ipc_protocol_validation_tests paths/IpcProtocolValidationTests.cpp)
target_link_libraries(ipc_protocol_validation_tests PRIVATE fic-ipc)
add_test(NAME ipc_protocol_validation_tests COMMAND ipc_protocol_validation_tests)

add_executable(ipc_transport_tests paths/IpcTransportTests.cpp)
target_link_libraries(ipc_transport_tests PRIVATE fic-ipc Threads::Threads)
add_test(NAME ipc_transport_tests COMMAND ipc_transport_tests)
set_tests_properties(ipc_transport_tests PROPERTIES SKIP_RETURN_CODE 77)

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

add_executable(grub_policy_tests
    oss/GrubPolicyTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/oss/OSS.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/oss/submodules/Grub.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/oss/submodules/GrubConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/oss/submodules/Grub/OSS_grub_timeout.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/oss/submodules/Grub/OSS_grub_cmdline_linux.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/oss/submodules/Grub/OSS_grub_disable_recovery.cpp
)
target_include_directories(grub_policy_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(grub_policy_tests PRIVATE
    fic-core
    fic-policy
    fic-platform
    Threads::Threads
)
add_test(NAME grub_policy_tests COMMAND grub_policy_tests)

add_executable(pam_configuration_tests
    identity_access/PamConfigurationTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamOptionFile.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamProviderInspector.cpp
)
target_include_directories(pam_configuration_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(pam_configuration_tests PRIVATE fic-core)
add_test(NAME pam_configuration_tests COMMAND pam_configuration_tests)

add_executable(identity_configuration_transaction_tests
    identity_access/ConfigurationTransactionTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/composite/ConfigurationTransaction.cpp
)
target_include_directories(identity_configuration_transaction_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
add_test(
    NAME identity_configuration_transaction_tests
    COMMAND identity_configuration_transaction_tests
)

add_executable(identity_policy_hierarchy_tests
    identity_access/IdentityPolicyHierarchyTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/IdentityAccessPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamOptionPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamOptionFile.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamProviderInspector.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/policies/PamFailedAuthenticationCountingPeriodPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/policies/PamFailedAuthenticationEnforceForRootPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/policies/PamPasswordHistoryEnforceForRootPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/sssd/SssdPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/kerberos/KerberosPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/nss/NssPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/configuration/PreparedFileChange.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/sssd/SssdConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/kerberos/KerberosConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/nss/NssConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/composite/CompositePolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/composite/ConfigurationTransaction.cpp
)
target_include_directories(identity_policy_hierarchy_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(identity_policy_hierarchy_tests PRIVATE
    fic-core
    fic-policy
    Threads::Threads
)
add_test(
    NAME identity_policy_hierarchy_tests
    COMMAND identity_policy_hierarchy_tests
)

add_executable(identity_configuration_editors_tests
    identity_access/IdentityConfigurationEditorsTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/configuration/PreparedFileChange.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/composite/ConfigurationTransaction.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/kerberos/KerberosConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/nss/NssConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/sssd/SssdConfiguration.cpp
)
target_include_directories(identity_configuration_editors_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(identity_configuration_editors_tests PRIVATE fic-core)
add_test(
    NAME identity_configuration_editors_tests
    COMMAND identity_configuration_editors_tests
)

add_executable(identity_concrete_policies_tests
    identity_access/IdentityConcretePoliciesTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/IdentityAccessPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/configuration/PreparedFileChange.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/composite/ConfigurationTransaction.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/sssd/SssdConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/sssd/SssdPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/sssd/SssdRuntime.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/sssd/policies/SssdOfflineCredentialsExpirationPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/kerberos/KerberosConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/kerberos/KerberosPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/kerberos/policies/KerberosTicketLifetimePolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/nss/NssConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/nss/NssPolicy.cpp
)
target_include_directories(identity_concrete_policies_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(identity_concrete_policies_tests PRIVATE
    fic-core
    fic-policy
    fic-platform
    Threads::Threads
)
add_test(
    NAME identity_concrete_policies_tests
    COMMAND identity_concrete_policies_tests
)

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

add_executable(command_hash_batch_tests
    trust/CommandHashBatchTests.cpp
)
target_link_libraries(command_hash_batch_tests PRIVATE fic-core)
add_test(NAME command_hash_batch_tests COMMAND command_hash_batch_tests)
set_tests_properties(command_hash_batch_tests PROPERTIES SKIP_RETURN_CODE 77)

add_executable(package_trust_selection_tests
    trust/PackageTrustSelectionTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/trust/PackageTrustSelection.cpp
)
target_include_directories(package_trust_selection_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
add_test(NAME package_trust_selection_tests COMMAND package_trust_selection_tests)

add_executable(upgrade_contract_tests upgrade/UpgradeContractTests.cpp)
target_compile_definitions(upgrade_contract_tests PRIVATE
    FIC_TEST_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)
target_link_libraries(upgrade_contract_tests PRIVATE
    fic-core
    fic-device-db
)
add_test(NAME upgrade_contract_tests COMMAND upgrade_contract_tests)
