#ifndef MAIN_FUNCTION_H
#define MAIN_FUNCTION_H

#include <map>
#include <memory>
#include <string>

#include <fic/core/SingleLineFileHandler.h>
#include <fic/core/ConfigFileHandler.h>
#include <fic/core/SectionConfigFileHandler.h>
#include <fic/core/LocalizationManager.h>
#include <fic/policy/PolicyApplyResult.h>
#include "platform/PlatformProfile.h"
#include "platform/PlatformExecutableResolver.h"

//Дискреционное разграничение доступа
#include "modules/dac/submodules/modeandowner/DAC_blocking_user_access_to_system_files.h"
#include "modules/dac/submodules/modeandowner/DAC_custom_mode_and_owner.h"
#include "modules/dac/submodules/modeandowner/DAC_systemcommandlock.h"
#include "modules/dac/submodules/sudo/DAC_sudo_env_reset.h"
#include "modules/dac/submodules/sudo/DAC_sudo_passwd_tries.h"
#include "modules/dac/submodules/sudo/DAC_sudo_securepath.h"
#include "modules/dac/submodules/sudo/DAC_sudo_timeout.h"
#include "modules/dac/submodules/sudo/DAC_sudo_require_authentication.h"

//Настройки ядра
#include "modules/sysctl/submodules/fskernelprotection/SYSCTL_fd_limits.h"
#include "modules/sysctl/submodules/fskernelprotection/SYSCTL_fs_protection.h"
#include "modules/sysctl/submodules/fskernelprotection/SYSCTL_nr_open_limit.h"
#include "modules/sysctl/submodules/fskernelprotection/SYSCTL_protected_symlinks.h"
#include "modules/sysctl/submodules/fskernelprotection/SYSCTL_suid_dump_disable.h"

#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_ipv4_default_accept_redirects_disable.h"
#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_ipv4_default_rp_filter_enable.h"
#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_ipv4_default_send_redirects_disable.h"
#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_ipv6_all_accept_redirects_disable.h"
#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_ipv6_default_accept_redirects_disable.h"
#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_ipv6_packet_forwarding_disable.h"
#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_packet_forwarding_disable.h"
#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_redirects_disable.h"
#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_rp_filter_enable.h"
#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_send_redirects_disable.h"
#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_syn_flood_protection.h"
#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_tcp_keepalive_time.h"
#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_tcp_max_syn_backlog.h"
#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_tcp_synack_retries.h"
#include "modules/sysctl/submodules/networkkernelprotection/SYSCTL_tcp_fin_timeout.h"

#include "modules/sysctl/submodules/globalkernelprotection/SYSCTL_buffer_overflow_protection.h"
#include "modules/sysctl/submodules/globalkernelprotection/SYSCTL_dmesg_restrict.h"
#include "modules/sysctl/submodules/globalkernelprotection/SYSCTL_kernel_code_execution_restrict.h"
#include "modules/sysctl/submodules/globalkernelprotection/SYSCTL_perf_event_paranoid.h"
#include "modules/sysctl/submodules/globalkernelprotection/SYSCTL_process_limits.h"
#include "modules/sysctl/submodules/globalkernelprotection/SYSCTL_ptrace_restrict.h"
#include "modules/sysctl/submodules/globalkernelprotection/SYSCTL_randomize_va_space.h"
#include "modules/sysctl/submodules/globalkernelprotection/SYSCTL_threads_max_limit.h"
#include "modules/sysctl/submodules/globalkernelprotection/SYSCTL_user_ns_restrict.h"

//Настройки ОС
#include "modules/oss/submodules/DisplayManager/OSS_disable_autologin.h"
#include "modules/oss/submodules/DisplayManager/OSS_disable_videodisplay_when_locked.h"
#include "modules/oss/submodules/SessionManagement/OSS_lock_on_tty_switch.h"
#include "modules/oss/submodules/DesktopEnvironment/OSS_screenlock_timeout.h"
#include "modules/oss/submodules/Fstab/OSS_fstab_boot_efi_profile.h"
#include "modules/oss/submodules/Fstab/OSS_fstab_boot_profile.h"
#include "modules/oss/submodules/Fstab/OSS_fstab_dev_shm_profile.h"
#include "modules/oss/submodules/Fstab/OSS_fstab_home_profile.h"
#include "modules/oss/submodules/Fstab/OSS_fstab_opt_profile.h"
#include "modules/oss/submodules/Fstab/OSS_fstab_removable_media_profile.h"
#include "modules/oss/submodules/Fstab/OSS_fstab_srv_profile.h"
#include "modules/oss/submodules/Fstab/OSS_fstab_tmp_profile.h"
#include "modules/oss/submodules/Fstab/OSS_fstab_var_tmp_profile.h"
#include "modules/oss/submodules/Fstab/OSS_fstab_var_log_audit_secure_options.h"
#include "modules/oss/submodules/Fstab/OSS_fstab_var_log_secure_options.h"

//Сетевые настройки
#include "modules/net/submodules/ssh/NET_ssh_port.h"
#include "modules/net/submodules/ssh/NET_ssh_max_auth_tries.h"
#include "modules/net/submodules/ssh/NET_ssh_root_login.h"
#include "modules/net/submodules/ssh/NET_ssh_pubkey_auth.h"

//Глобальные настройки программы
#include "modules/global/submodules/systemsettings/GLOBAL_log_level.h"
#include "modules/global/submodules/systemsettings/GLOBAL_lang.h"

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

using PolicyMap = std::map<std::string, std::map<std::string, std::map<std::string, std::unique_ptr<Policy>>>>;
using ModulePolicyMap = std::map<std::string, std::map<std::string, std::unique_ptr<Policy>>>;

ModulePolicyMap* getModule(
        PolicyMap& policyMap,
        const std::string& module);
Policy* getPolicyClass(
            PolicyMap& policyMap,
            const std::string& module,
            const std::string& policy
        );

//Дать информацию об ограничении
bool policy_info_restriction(PolicyMap& policyMap, std::string module, std::string policy);
//Дать список модулей
bool module_list(PolicyMap& policyMap);

bool policy_list(PolicyMap& policyMap, std::string module);

PolicyApplyResult applyPolicy(PolicyMap& policyMap, std::string module, std::string policy);
PolicyApplySummary applyModulePolicies(PolicyMap& policyMap, std::string module);
PolicyApplySummary applyAllPolicies(PolicyMap& policyMap);
bool isPolicyApplySuccessful(const PolicyApplySummary& summary, std::string module, std::string policy);
bool apply(PolicyMap& policyMap, std::string module, std::string policy);

//Отключить политику
bool disable (PolicyMap& policyMap, std::string module, std::string policy);
//Включить политику
bool enable(PolicyMap& policyMap, std::string module, std::string policy);

bool set(PolicyMap& policyMap, std::string module, std::string policy, std::string value);


PolicyMap init_policyMap(
    const fic::platform::PlatformProfile& platform,
    const fic::platform::PlatformExecutableResolver& executables);
#endif // MAIN_FUNCTION_H
