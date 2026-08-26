#ifndef MAIN_FUNCTION_H
#define MAIN_FUNCTION_H

#include <map>
#include <memory>
#include <string>

#include <fic/core/config/SingleLineFileHandler.h>
#include <fic/core/config/ConfigFileHandler.h>
#include <fic/core/config/SectionConfigFileHandler.h>
#include <fic/core/i18n/LocalizationManager.h>
#include <fic/policy/PolicyApplyResult.h>
#include "policy/execution/PolicyApplication.h"
#include "policy/registry/PolicyRegistry.h"
#include "platform/PlatformProfile.h"
#include "platform/PlatformExecutableResolver.h"

//Дискреционное разграничение доступа
#include "modules/dac/mode_and_owner/policies/DAC_blocking_user_access_to_system_files.h"
#include "modules/dac/mode_and_owner/policies/DAC_custom_mode_and_owner.h"
#include "modules/dac/mode_and_owner/policies/DAC_systemcommandlock.h"
#include "modules/dac/sudo/policies/DAC_sudo_env_reset.h"
#include "modules/dac/sudo/policies/DAC_sudo_passwd_tries.h"
#include "modules/dac/sudo/policies/DAC_sudo_securepath.h"
#include "modules/dac/sudo/policies/DAC_sudo_timeout.h"
#include "modules/dac/sudo/policies/DAC_sudo_require_authentication.h"

// Identity and access: PAM policies
#include "modules/identity_access/pam/policies/PamFailedAuthenticationAttemptsPolicy.h"
#include "modules/identity_access/pam/policies/PamFailedAuthenticationCountingPeriodPolicy.h"
#include "modules/identity_access/pam/policies/PamFailedAuthenticationEnforceForRootPolicy.h"
#include "modules/identity_access/pam/policies/PamFailedAuthenticationUnlockTimePolicy.h"
#include "modules/identity_access/pam/policies/PamPasswordHistoryDepthPolicy.h"
#include "modules/identity_access/pam/policies/PamPasswordHistoryEnforceForRootPolicy.h"
#include "modules/identity_access/pam/policies/PamPasswordMinClassesPolicy.h"
#include "modules/identity_access/pam/policies/PamPasswordMinLengthPolicy.h"
#include "modules/identity_access/pam/policies/PamPasswordQualityPolicies.h"
#include "modules/identity_access/pam/policies/RequiredPamEnforcementPolicy.h"
#include "modules/identity_access/sssd/policies/SssdOfflineCredentialsExpirationPolicy.h"
#include "modules/identity_access/kerberos/policies/KerberosTicketLifetimePolicy.h"
#include "modules/identity_access/password_aging/PasswordAgingPolicies.h"
#include "modules/identity_access/user_creation/UserCreationPolicies.h"

//Настройки ядра
#include "modules/sysctl/fs_kernel/policies/SYSCTL_fd_limits.h"
#include "modules/sysctl/fs_kernel/policies/SYSCTL_fs_protection.h"
#include "modules/sysctl/fs_kernel/policies/SYSCTL_nr_open_limit.h"
#include "modules/sysctl/fs_kernel/policies/SYSCTL_protected_symlinks.h"
#include "modules/sysctl/fs_kernel/policies/SYSCTL_suid_dump_disable.h"

#include "modules/sysctl/network_kernel/policies/SYSCTL_ipv4_default_accept_redirects_disable.h"
#include "modules/sysctl/network_kernel/policies/SYSCTL_ipv4_default_rp_filter_enable.h"
#include "modules/sysctl/network_kernel/policies/SYSCTL_ipv4_default_send_redirects_disable.h"
#include "modules/sysctl/network_kernel/policies/SYSCTL_ipv6_all_accept_redirects_disable.h"
#include "modules/sysctl/network_kernel/policies/SYSCTL_ipv6_default_accept_redirects_disable.h"
#include "modules/sysctl/network_kernel/policies/SYSCTL_ipv6_packet_forwarding_disable.h"
#include "modules/sysctl/network_kernel/policies/SYSCTL_packet_forwarding_disable.h"
#include "modules/sysctl/network_kernel/policies/SYSCTL_redirects_disable.h"
#include "modules/sysctl/network_kernel/policies/SYSCTL_rp_filter_enable.h"
#include "modules/sysctl/network_kernel/policies/SYSCTL_send_redirects_disable.h"
#include "modules/sysctl/network_kernel/policies/SYSCTL_syn_flood_protection.h"
#include "modules/sysctl/network_kernel/policies/SYSCTL_tcp_keepalive_time.h"
#include "modules/sysctl/network_kernel/policies/SYSCTL_tcp_max_syn_backlog.h"
#include "modules/sysctl/network_kernel/policies/SYSCTL_tcp_synack_retries.h"
#include "modules/sysctl/network_kernel/policies/SYSCTL_tcp_fin_timeout.h"

#include "modules/sysctl/global_kernel/policies/SYSCTL_dmesg_restrict.h"
#include "modules/sysctl/global_kernel/policies/SYSCTL_kernel_code_execution_restrict.h"
#include "modules/sysctl/global_kernel/policies/SYSCTL_perf_event_paranoid.h"
#include "modules/sysctl/global_kernel/policies/SYSCTL_process_limits.h"
#include "modules/sysctl/global_kernel/policies/SYSCTL_ptrace_restrict.h"
#include "modules/sysctl/global_kernel/policies/SYSCTL_randomize_va_space.h"
#include "modules/sysctl/global_kernel/policies/SYSCTL_sysrq_disable.h"
#include "modules/sysctl/global_kernel/policies/SYSCTL_threads_max_limit.h"
#include "modules/sysctl/global_kernel/policies/SYSCTL_user_ns_restrict.h"

//Настройки ОС
#include "modules/oss/grub/policies/OSS_grub_timeout.h"
#include "modules/oss/grub/policies/OSS_grub_cmdline_linux.h"
#include "modules/oss/grub/policies/OSS_grub_disable_recovery.h"
#include "modules/oss/display_manager/policies/OSS_disable_autologin.h"
#include "modules/oss/desktop_environment/policies/OSS_disable_videodisplay_when_locked.h"
#include "modules/oss/session_management/policies/OSS_lock_on_tty_switch.h"
#include "modules/oss/desktop_environment/policies/OSS_screenlock_timeout.h"
#include "modules/oss/fstab/policies/OSS_fstab_boot_efi_profile.h"
#include "modules/oss/fstab/policies/OSS_fstab_boot_profile.h"
#include "modules/oss/fstab/policies/OSS_fstab_dev_shm_profile.h"
#include "modules/oss/fstab/policies/OSS_fstab_home_profile.h"
#include "modules/oss/fstab/policies/OSS_fstab_opt_profile.h"
#include "modules/oss/fstab/policies/OSS_fstab_removable_media_profile.h"
#include "modules/oss/fstab/policies/OSS_fstab_srv_profile.h"
#include "modules/oss/fstab/policies/OSS_fstab_tmp_profile.h"
#include "modules/oss/fstab/policies/OSS_fstab_var_tmp_profile.h"
#include "modules/oss/fstab/policies/OSS_fstab_var_log_audit_secure_options.h"
#include "modules/oss/fstab/policies/OSS_fstab_var_log_secure_options.h"

//Сетевые настройки
#include "modules/net/ssh/policies/NET_ssh_port.h"
#include "modules/net/ssh/policies/NET_ssh_max_auth_tries.h"
#include "modules/net/ssh/policies/NET_ssh_root_login.h"
#include "modules/net/ssh/policies/NET_ssh_pubkey_auth.h"

// Межсетевой экран nftables
#include "modules/firewall/FirewallPolicies.h"

//Аудит и глобальные настройки программы
#include "modules/audit/logging/policies/AUDIT_log_level.h"
#include "modules/global/system_settings/policies/GLOBAL_lang.h"

//Контроль устройств: общие настройки
#include "modules/dc/DC.h"

/*Функции вывода справки*/
void print_program_info();
void print_help_apply();
void print_help_enable();
void print_help_set();
void print_help_disable();
void print_help_modulelist();
void print_help_policylist();
void print_help_policyrestrictioninfo();
void print_help_help();
void print_help_lock();
void print_help_unlock();
void print_help_lockstatus();
void print_help_hash();
void print_help_policy_action();

// Функция для вывода общей справки
void print_help();
/*Функции вывода справки*/


//Заблокировать компьютер
bool lock(const fic::platform::PlatformExecutableResolver& executables);
//Разблокировать компьютер
bool unlock();
//Текущий статус
bool lockstatus();
//Вычислить хэш для исполняемого файла
bool calcHash(const std::string& command);

//Получить значение параметра
std::string getArgvValue(int argc, char* argv[], int ind);

PolicyModule* getModule(
        PolicyRegistry& policyRegistry,
        const std::string& module);
Policy* getPolicyClass(
            PolicyRegistry& policyRegistry,
            const std::string& module,
            const std::string& policy
        );

//Дать информацию об ограничении
bool policy_info_restriction(PolicyRegistry& policyRegistry, std::string module, std::string policy);
//Дать список модулей
bool module_list(PolicyRegistry& policyRegistry);

bool policy_list(PolicyRegistry& policyRegistry, std::string module);

bool apply(PolicyRegistry& policyRegistry, std::string module, std::string policy);

//Отключить политику
bool disable (PolicyRegistry& policyRegistry, std::string module, std::string policy);
//Включить политику
bool enable(PolicyRegistry& policyRegistry, std::string module, std::string policy);

bool set(PolicyRegistry& policyRegistry, std::string module, std::string policy, std::string value);


bool initPolicyRegistry(
    const fic::platform::PlatformProfile& platform,
    const fic::platform::PlatformExecutableResolver& executables,
    PolicyRegistry& registry,
    std::string& error);
#endif // MAIN_FUNCTION_H
