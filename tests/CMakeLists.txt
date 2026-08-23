find_package(Python3 COMPONENTS Interpreter)
find_package(Threads REQUIRED)
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core)

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
    add_test(
        NAME pam_packaging_static_checks
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/packaging/PamPackagingChecks.py
                ${CMAKE_SOURCE_DIR}
    )
    add_test(
        NAME firewall_static_checks
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/firewall/static_checks.py
                ${CMAKE_SOURCE_DIR}
    )
    add_test(
        NAME module_ui_static_checks
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/module-ui/static_checks.py
                ${CMAKE_SOURCE_DIR}
    )
endif()

add_executable(module_registry_tests
    module-ui/ModuleRegistryTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/core/PolicyRegistryInitialization.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/core/PolicyRegistryJson.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/audit/AUDIT.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/audit/submodules/Logging.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/audit/submodules/logging/AUDIT_log_level.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/global/GLOBAL.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/global/submodules/SystemSettings.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/global/submodules/systemsettings/GLOBAL_lang.cpp
)
target_include_directories(module_registry_tests PRIVATE ${CMAKE_SOURCE_DIR}/fic/src)
target_link_libraries(module_registry_tests PRIVATE fic-core fic-policy)
add_test(NAME module_registry_tests COMMAND module_registry_tests)

add_executable(module_descriptor_tests
    module-ui/ModuleDescriptorTests.cpp
    ${CMAKE_SOURCE_DIR}/fic-gui/src/models/ModuleDescriptor.cpp
)
target_include_directories(module_descriptor_tests PRIVATE ${CMAKE_SOURCE_DIR}/fic-gui/src)
add_test(NAME module_descriptor_tests COMMAND module_descriptor_tests)

add_executable(policy_descriptor_tests
    module-ui/PolicyDescriptorTests.cpp
    ${CMAKE_SOURCE_DIR}/fic-gui/src/models/PolicyDescriptor.cpp
)
target_include_directories(policy_descriptor_tests PRIVATE ${CMAKE_SOURCE_DIR}/fic-gui/src)
add_test(NAME policy_descriptor_tests COMMAND policy_descriptor_tests)

add_executable(policy_service_tests
    module-ui/PolicyServiceTests.cpp
    ${CMAKE_SOURCE_DIR}/fic-gui/src/services/PolicyService.cpp
    ${CMAKE_SOURCE_DIR}/fic-gui/src/models/ModuleDescriptor.cpp
    ${CMAKE_SOURCE_DIR}/fic-gui/src/models/PolicyDescriptor.cpp
)
target_include_directories(policy_service_tests PRIVATE ${CMAKE_SOURCE_DIR}/fic-gui/src)
target_link_libraries(policy_service_tests PRIVATE Qt${QT_VERSION_MAJOR}::Core fic-ipc)
add_test(NAME policy_service_tests COMMAND policy_service_tests)

add_executable(firewall_tests
    firewall/FirewallTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/firewall/FirewallRule.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/firewall/FirewallNft.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/firewall/FirewallBackend.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/firewall/FirewallPolicies.cpp
)
target_include_directories(firewall_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(firewall_tests PRIVATE
    fic-core
    fic-policy
    fic-platform
    Threads::Threads
)
add_test(NAME firewall_tests COMMAND firewall_tests)

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

add_executable(exclusive_pid_lock_tests paths/ExclusivePidLockTests.cpp)
target_link_libraries(exclusive_pid_lock_tests PRIVATE fic-core)
add_test(NAME exclusive_pid_lock_tests COMMAND exclusive_pid_lock_tests)

add_executable(session_agent_client_tests
    session/SessionAgentClientTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/session/SessionAgentClient.cpp
)
target_include_directories(session_agent_client_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(session_agent_client_tests PRIVATE
    fic-ipc
    Threads::Threads
)
add_test(NAME session_agent_client_tests COMMAND session_agent_client_tests)
set_tests_properties(session_agent_client_tests PROPERTIES SKIP_RETURN_CODE 77)

add_executable(device_tree_revision_tests
    device-control/DeviceTreeRevisionTests.cpp
)
target_link_libraries(device_tree_revision_tests PRIVATE fic-device-db)
add_test(NAME device_tree_revision_tests COMMAND device_tree_revision_tests)

add_executable(device_tree_snapshot_tests
    device-control/DeviceTreeSnapshotTests.cpp
    ${CMAKE_SOURCE_DIR}/fic-dick/src/core/DeviceTreeSnapshot.cpp
)
target_include_directories(device_tree_snapshot_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic-dick/src
)
target_link_libraries(device_tree_snapshot_tests PRIVATE
    fic-core
    fic-device-db
    fic-ipc
)
add_test(NAME device_tree_snapshot_tests COMMAND device_tree_snapshot_tests)

add_executable(device_policy_compiler_tests
    device-control/DevicePolicyCompilerTests.cpp
    ${CMAKE_SOURCE_DIR}/fic-dick/src/core/DevicePolicyCompiler.cpp
)
target_include_directories(device_policy_compiler_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic-dick/src
)
target_link_libraries(device_policy_compiler_tests PRIVATE
    fic-core
    fic-device-db
)
add_test(NAME device_policy_compiler_tests COMMAND device_policy_compiler_tests)

add_executable(device_lifecycle_tests
    device-control/DeviceLifecycleTests.cpp
    ${CMAKE_SOURCE_DIR}/fic-dick/src/core/DeviceLifecycle.cpp
)
target_include_directories(device_lifecycle_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic-dick/src
)
target_link_libraries(device_lifecycle_tests PRIVATE
    fic-core
    fic-device-db
)
add_test(NAME device_lifecycle_tests COMMAND device_lifecycle_tests)

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

add_executable(mode_and_owner_tests
    dac/ModeAndOwnerTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/dac/DAC.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/dac/submodules/ModeAndOwner.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/dac/submodules/modeandowner/DAC_blocking_user_access_to_system_files.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/dac/submodules/modeandowner/DAC_custom_mode_and_owner.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/dac/submodules/modeandowner/DAC_systemcommandlock.cpp
)
target_include_directories(mode_and_owner_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(mode_and_owner_tests PRIVATE fic-core fic-policy)
add_test(NAME mode_and_owner_tests COMMAND mode_and_owner_tests)

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
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamCapabilityVerifier.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamControlFlowAnalyzer.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamOptionFile.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamProviderInspector.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamRequiredProviders.cpp
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
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamCapabilityVerifier.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamControlFlowAnalyzer.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamOptionFile.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamProviderInspector.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/PamRequiredProviders.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/policies/PamFailedAuthenticationCountingPeriodPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/policies/PamFailedAuthenticationEnforceForRootPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/policies/PamPasswordHistoryEnforceForRootPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/submodules/pam/policies/RequiredPamEnforcementPolicy.cpp
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

add_executable(schema_contract_tests version/SchemaContractTests.cpp)
target_link_libraries(schema_contract_tests PRIVATE
    fic-core
    fic-device-db
)
add_test(NAME schema_contract_tests COMMAND schema_contract_tests)
