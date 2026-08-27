find_package(Python3 COMPONENTS Interpreter)
find_package(Threads REQUIRED)
find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core)

# Several tests compile daemon sources directly instead of consuming
# fic-platform, so they need the generated part of the public platform header.
include_directories(${CMAKE_BINARY_DIR}/fic/generated/include)

if(Python3_Interpreter_FOUND)
    add_test(
        NAME device_control_static_checks
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/integration/device-control/static_checks.py
                ${CMAKE_SOURCE_DIR}
    )
    add_test(
        NAME path_layout_static_checks
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/common/static_checks.py
                ${CMAKE_SOURCE_DIR}
    )
    add_test(
        NAME ssh_policy_static_checks
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/fic/modules/net/ssh/static_checks.py
                ${CMAKE_SOURCE_DIR}
    )
    add_test(
        NAME platform_profile_static_checks
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/fic/platform/static_checks.py
                ${CMAKE_SOURCE_DIR}
    )
    add_test(
        NAME pam_packaging_static_checks
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/integration/packaging/PamPackagingChecks.py
                ${CMAKE_SOURCE_DIR}
    )
    add_test(
        NAME firewall_static_checks
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/fic/modules/firewall/static_checks.py
                ${CMAKE_SOURCE_DIR}
    )
    add_test(
        NAME module_ui_static_checks
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/fic-gui/policies/static_checks.py
                ${CMAKE_SOURCE_DIR}
    )
    add_test(
        NAME session_agent_static_checks
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/fic-session-agent/static_checks.py
                ${CMAKE_SOURCE_DIR}
    )
endif()

add_executable(module_registry_tests
    fic-gui/policies/ModuleRegistryTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/policy/execution/PolicyDependencyGraph.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/policy/registry/PolicyRegistryInitialization.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/policy/registry/PolicyRegistryJson.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/audit/AUDIT.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/audit/logging/Logging.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/audit/logging/policies/AUDIT_log_level.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/global/GLOBAL.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/global/system_settings/SystemSettings.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/global/system_settings/policies/GLOBAL_lang.cpp
)
target_include_directories(module_registry_tests PRIVATE ${CMAKE_SOURCE_DIR}/fic/src)
target_link_libraries(module_registry_tests PRIVATE fic-core fic-policy)
add_test(NAME module_registry_tests COMMAND module_registry_tests)

add_executable(policy_execution_planner_tests
    fic/policy/PolicyExecutionPlannerTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/policy/execution/PolicyApplication.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/policy/execution/PolicyDependencyGraph.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/policy/execution/PolicyExecutionPlanner.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/policy/registry/PolicyRegistryInitialization.cpp
)
target_include_directories(policy_execution_planner_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(policy_execution_planner_tests PRIVATE fic-core fic-policy)
add_test(NAME policy_execution_planner_tests COMMAND policy_execution_planner_tests)

add_executable(module_descriptor_tests
    fic-gui/policies/ModuleDescriptorTests.cpp
    ${CMAKE_SOURCE_DIR}/fic-gui/src/features/policies/models/ModuleDescriptor.cpp
)
target_include_directories(module_descriptor_tests PRIVATE ${CMAKE_SOURCE_DIR}/fic-gui/src)
add_test(NAME module_descriptor_tests COMMAND module_descriptor_tests)

add_executable(policy_descriptor_tests
    fic-gui/policies/PolicyDescriptorTests.cpp
    ${CMAKE_SOURCE_DIR}/fic-gui/src/features/policies/models/PolicyDescriptor.cpp
)
target_include_directories(policy_descriptor_tests PRIVATE ${CMAKE_SOURCE_DIR}/fic-gui/src)
add_test(NAME policy_descriptor_tests COMMAND policy_descriptor_tests)

add_executable(policy_service_tests
    fic-gui/policies/PolicyServiceTests.cpp
    ${CMAKE_SOURCE_DIR}/fic-gui/src/features/policies/services/PolicyService.cpp
    ${CMAKE_SOURCE_DIR}/fic-gui/src/features/policies/models/ModuleDescriptor.cpp
    ${CMAKE_SOURCE_DIR}/fic-gui/src/features/policies/models/PolicyDescriptor.cpp
)
target_include_directories(policy_service_tests PRIVATE ${CMAKE_SOURCE_DIR}/fic-gui/src)
target_link_libraries(policy_service_tests PRIVATE Qt${QT_VERSION_MAJOR}::Core fic-ipc)
add_test(NAME policy_service_tests COMMAND policy_service_tests)

add_executable(firewall_tests
    fic/modules/firewall/FirewallTests.cpp
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

add_executable(gsettings_value_parser_tests
    fic/modules/oss/desktop_environment/GSettingsValueParserTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/oss/desktop_environment/backends/GSettingsValueParser.cpp
)
target_include_directories(gsettings_value_parser_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
add_test(NAME gsettings_value_parser_tests COMMAND gsettings_value_parser_tests)

add_test(
    NAME packaging_build_resource_tests
    COMMAND bash
            ${CMAKE_CURRENT_SOURCE_DIR}/integration/packaging/build-resources-test.sh
)

add_test(
    NAME version_contract_tests
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/common/version/version-contract-test.sh
)
add_test(
    NAME release_contract_tests
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/common/version/release-contract-test.sh
)

add_executable(build_info_tests common/version/BuildInfoTests.cpp)
target_link_libraries(build_info_tests PRIVATE fic-version)
add_test(NAME build_info_tests COMMAND build_info_tests)

add_executable(runtime_paths_tests common/core/runtime/RuntimePathsTests.cpp)
target_link_libraries(runtime_paths_tests PRIVATE fic-core fic-device-db)
add_test(NAME runtime_paths_tests COMMAND runtime_paths_tests)

add_executable(exclusive_pid_lock_tests common/core/process/ExclusivePidLockTests.cpp)
target_link_libraries(exclusive_pid_lock_tests PRIVATE fic-core)
add_test(NAME exclusive_pid_lock_tests COMMAND exclusive_pid_lock_tests)

add_executable(session_agent_client_tests
    fic/session/SessionAgentClientTests.cpp
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

add_executable(session_identity_resolver_tests
    fic-session-agent/SessionIdentityResolverTests.cpp
    ${CMAKE_SOURCE_DIR}/fic-session-agent/src/SessionIdentityResolver.cpp
)
target_include_directories(session_identity_resolver_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic-session-agent/src
)
add_test(NAME session_identity_resolver_tests COMMAND session_identity_resolver_tests)

add_executable(device_tree_revision_tests
    fic-dick/device/DeviceTreeRevisionTests.cpp
)
target_link_libraries(device_tree_revision_tests PRIVATE fic-device-db)
add_test(NAME device_tree_revision_tests COMMAND device_tree_revision_tests)

add_executable(device_tree_snapshot_tests
    fic-dick/device/DeviceTreeSnapshotTests.cpp
    ${CMAKE_SOURCE_DIR}/fic-dick/src/device/DeviceTreeSnapshot.cpp
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
    fic-dick/policy/DevicePolicyCompilerTests.cpp
    ${CMAKE_SOURCE_DIR}/fic-dick/src/policy/DevicePolicyCompiler.cpp
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
    fic-dick/device/DeviceLifecycleTests.cpp
    ${CMAKE_SOURCE_DIR}/fic-dick/src/device/DeviceLifecycle.cpp
)
target_include_directories(device_lifecycle_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic-dick/src
)
target_link_libraries(device_lifecycle_tests PRIVATE
    fic-core
    fic-device-db
)
add_test(NAME device_lifecycle_tests COMMAND device_lifecycle_tests)

add_executable(device_enforcer_tests
    fic-dick/enforcement/DeviceEnforcerTests.cpp
    ${CMAKE_SOURCE_DIR}/fic-dick/src/enforcement/DeviceEnforcerSysfs.cpp
)
target_include_directories(device_enforcer_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic-dick/src
)
add_test(NAME device_enforcer_tests COMMAND device_enforcer_tests)

add_executable(ipc_paths_tests common/ipc/IpcPathsTests.cpp)
target_link_libraries(ipc_paths_tests PRIVATE fic-ipc)
add_test(NAME ipc_paths_tests COMMAND ipc_paths_tests)

add_executable(ipc_protocol_validation_tests common/ipc/IpcProtocolValidationTests.cpp)
target_link_libraries(ipc_protocol_validation_tests PRIVATE fic-ipc)
add_test(NAME ipc_protocol_validation_tests COMMAND ipc_protocol_validation_tests)

add_executable(ipc_transport_tests common/ipc/IpcTransportTests.cpp)
target_link_libraries(ipc_transport_tests PRIVATE fic-ipc Threads::Threads)
add_test(NAME ipc_transport_tests COMMAND ipc_transport_tests)
set_tests_properties(ipc_transport_tests PROPERTIES SKIP_RETURN_CODE 77)

add_executable(admin_socket_tests common/ipc/AdminSocketTests.cpp)
target_link_libraries(admin_socket_tests PRIVATE fic-ipc)
add_test(NAME admin_socket_tests COMMAND admin_socket_tests)
set_tests_properties(admin_socket_tests PROPERTIES SKIP_RETURN_CODE 77)

add_executable(sudoers_configuration_tests
    fic/modules/dac/SudoersConfigurationTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/dac/sudo/SudoersConfiguration.cpp
)
target_include_directories(sudoers_configuration_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(sudoers_configuration_tests PRIVATE fic-core Threads::Threads)
add_test(NAME sudoers_configuration_tests COMMAND sudoers_configuration_tests)

add_executable(file_handler_options_tests
    common/core/fs/FileHandlerOptionsTests.cpp
)
target_link_libraries(file_handler_options_tests PRIVATE fic-core)
add_test(NAME file_handler_options_tests COMMAND file_handler_options_tests)

add_executable(mode_and_owner_tests
    fic/modules/dac/ModeAndOwnerTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/dac/DAC.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/dac/mode_and_owner/ModeAndOwner.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/dac/mode_and_owner/policies/DAC_blocking_user_access_to_system_files.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/dac/mode_and_owner/policies/DAC_custom_mode_and_owner.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/dac/mode_and_owner/policies/DAC_systemcommandlock.cpp
)
target_include_directories(mode_and_owner_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(mode_and_owner_tests PRIVATE fic-core fic-policy)
add_test(NAME mode_and_owner_tests COMMAND mode_and_owner_tests)

add_executable(sysctl_configuration_tests
    fic/modules/sysctl/SysctlConfigurationTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/sysctl/SysctlConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/sysctl/SysctlRuntime.cpp
)
target_include_directories(sysctl_configuration_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(sysctl_configuration_tests PRIVATE fic-core)
add_test(NAME sysctl_configuration_tests COMMAND sysctl_configuration_tests)

add_executable(grub_policy_tests
    fic/modules/oss/grub/GrubPolicyTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/oss/OSS.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/oss/grub/Grub.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/oss/grub/GrubConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/oss/grub/policies/OSS_grub_timeout.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/oss/grub/policies/OSS_grub_cmdline_linux.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/oss/grub/policies/OSS_grub_disable_recovery.cpp
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
    fic/modules/identity_access/pam/PamConfigurationTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamCapabilityVerifier.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamControlFlowAnalyzer.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamOptionFile.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamOptionValueCodec.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamProviderInspector.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamRequiredProviders.cpp
)
target_include_directories(pam_configuration_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(pam_configuration_tests PRIVATE fic-core)
add_test(NAME pam_configuration_tests COMMAND pam_configuration_tests)

add_executable(alt_pam_faillock_topology_tests
    fic/modules/identity_access/pam/AltPamFaillockTopologyManagerTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/AltPamFaillockTopologyManager.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamControlFlowAnalyzer.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamCapabilityVerifier.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamProviderInspector.cpp
)
target_include_directories(alt_pam_faillock_topology_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(alt_pam_faillock_topology_tests PRIVATE
    fic-core
    fic-platform
    Threads::Threads
)
add_test(NAME alt_pam_faillock_topology_tests
         COMMAND alt_pam_faillock_topology_tests)

add_executable(identity_configuration_transaction_tests
    fic/modules/identity_access/composite/ConfigurationTransactionTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/composite/ConfigurationTransaction.cpp
)
target_include_directories(identity_configuration_transaction_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
add_test(
    NAME identity_configuration_transaction_tests
    COMMAND identity_configuration_transaction_tests
)

add_executable(identity_policy_hierarchy_tests
    fic/modules/identity_access/IdentityPolicyHierarchyTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/IdentityAccessPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamOptionPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamCapabilityVerifier.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamControlFlowAnalyzer.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamOptionFile.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamOptionValueCodec.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamProviderInspector.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/PamRequiredProviders.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/policies/PamFailedAuthenticationCountingPeriodPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/policies/PamFailedAuthenticationEnforceForRootPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/policies/PamPasswordHistoryEnforceForRootPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/policies/PamPasswordQualityPolicies.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/pam/policies/RequiredPamEnforcementPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/sssd/SssdPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/kerberos/KerberosPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/nss/NssPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/shared/configuration/PreparedFileChange.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/sssd/SssdConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/kerberos/KerberosConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/nss/NssConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/composite/CompositePolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/composite/ConfigurationTransaction.cpp
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
    fic/modules/identity_access/IdentityConfigurationEditorsTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/shared/configuration/PreparedFileChange.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/composite/ConfigurationTransaction.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/kerberos/KerberosConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/nss/NssConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/sssd/SssdConfiguration.cpp
)
target_include_directories(identity_configuration_editors_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(identity_configuration_editors_tests PRIVATE fic-core)
add_test(
    NAME identity_configuration_editors_tests
    COMMAND identity_configuration_editors_tests
)

add_executable(password_aging_tests
    fic/modules/identity_access/password_aging/PasswordAgingTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/policy/execution/PolicyApplication.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/policy/execution/PolicyDependencyGraph.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/policy/execution/PolicyExecutionPlanner.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/policy/registry/PolicyRegistryInitialization.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/IdentityAccessPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/shared/configuration/LoginDefsFileHandler.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/password_aging/PasswordAgingPolicies.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/password_aging/PasswordAgingRuntime.cpp
)
target_include_directories(password_aging_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_compile_definitions(password_aging_tests PRIVATE
    FIC_GENERATED_IDENTITY_CONFIG_PATH="${CMAKE_BINARY_DIR}/fic/generated/scripts/config/IDENTITY_ACCESS.conf"
)
target_link_libraries(password_aging_tests PRIVATE
    fic-core
    fic-policy
    fic-platform
    Threads::Threads
)
add_test(NAME password_aging_tests COMMAND password_aging_tests)

add_executable(user_creation_tests
    fic/modules/identity_access/user_creation/UserCreationTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/IdentityAccessPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/shared/configuration/LoginDefsFileHandler.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/shared/configuration/LocalGroupDatabase.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/user_creation/configuration/AdduserConfigFileHandler.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/user_creation/configuration/UseraddDefaultsFileHandler.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/user_creation/UserCreationPolicies.cpp
)
target_include_directories(user_creation_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_compile_definitions(user_creation_tests PRIVATE
    FIC_GENERATED_IDENTITY_CONFIG_PATH="${CMAKE_BINARY_DIR}/fic/generated/scripts/config/IDENTITY_ACCESS.conf"
)
target_link_libraries(user_creation_tests PRIVATE
    fic-core
    fic-policy
    fic-platform
    Threads::Threads
)
add_test(NAME user_creation_tests COMMAND user_creation_tests)

add_executable(identity_concrete_policies_tests
    fic/modules/identity_access/IdentityConcretePoliciesTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/IdentityAccessPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/shared/configuration/PreparedFileChange.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/composite/ConfigurationTransaction.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/sssd/SssdConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/sssd/SssdPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/sssd/SssdRuntime.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/sssd/policies/SssdOfflineCredentialsExpirationPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/kerberos/KerberosConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/kerberos/KerberosPolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/kerberos/policies/KerberosTicketLifetimePolicy.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/nss/NssConfiguration.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/identity_access/nss/NssPolicy.cpp
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
    fic/modules/net/ssh/SshRuntimeTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/net/ssh/SshConfigAudit.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/net/ssh/SshConfigFile.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/net/ssh/SshConfigSyntax.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/modules/net/ssh/SshRuntime.cpp
)
target_include_directories(ssh_runtime_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(ssh_runtime_tests PRIVATE fic-core fic-policy fic-platform)
add_test(NAME ssh_runtime_tests COMMAND ssh_runtime_tests)

add_executable(platform_profile_tests
    fic/platform/PlatformProfileTests.cpp
)
target_include_directories(platform_profile_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
target_link_libraries(platform_profile_tests PRIVATE fic-platform)
add_test(NAME platform_profile_tests COMMAND platform_profile_tests)

add_executable(command_hash_batch_tests
    common/core/integrity/CommandHashBatchTests.cpp
)
target_link_libraries(command_hash_batch_tests PRIVATE fic-core)
add_test(NAME command_hash_batch_tests COMMAND command_hash_batch_tests)
set_tests_properties(command_hash_batch_tests PROPERTIES SKIP_RETURN_CODE 77)

add_executable(package_trust_selection_tests
    fic/trust/PackageTrustSelectionTests.cpp
    ${CMAKE_SOURCE_DIR}/fic/src/trust/PackageTrustSelection.cpp
)
target_include_directories(package_trust_selection_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/fic/src
)
add_test(NAME package_trust_selection_tests COMMAND package_trust_selection_tests)

add_executable(schema_contract_tests common/version/SchemaContractTests.cpp)
target_link_libraries(schema_contract_tests PRIVATE
    fic-core
    fic-device-db
)
add_test(NAME schema_contract_tests COMMAND schema_contract_tests)
