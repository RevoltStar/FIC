#include "main_function.h"

#include "core/PolicyRegistryInitialization.h"

#include <fic/core/CommandHashStore.h>
#include <fic/core/FicRuntimePaths.h>
#include <fic/core/VerifiedProcessExecutor.h>

/*Функции вывода справки*/
void print_program_info(){
    std::cout << "  FREE INTEGRITY CONTROL (FIC) - программа настройки СЗИ для ОС на базе ядра Linux" << std::endl;
}
void print_help_apply(){
    std::cout << "  policy apply <модуль> <политика>         Применяет политику. Укажите all вместо <модуль>, если требуется применить все политики. Укажите all вместо <политика>, если требуется применить все политики в модуле" << std::endl;
}
void print_help_enable(){
    std::cout << "  policy enable <модуль> <политика>        Включает политику." << std::endl;
}
void print_help_set(){
    std::cout << "  policy set <модуль> <политика> <значение> Задать значение политики." << std::endl;
}
void print_help_disable(){
    std::cout << "  policy disable <модуль> <политика>       Отключает политику." << std::endl;
}

void print_help_modulelist(){
    std::cout << "  module list Показывает список всех модулей программы" << std::endl;
}
void print_help_policylist(){
    std::cout << "  policy list <модуль> Показывает список всех политик модуля" << std::endl;
}
void print_help_policyrestrictioninfo(){
    std::cout << "  policy info restriction <модуль> <политика> Показывает ограничения на значения данной политики" << std::endl;
}
void print_help_help(){
    std::cout << "  help                                     Выводит эту справку." << std::endl;
}

void print_help_lock(){
    std::cout << "  lock                                     Заблокировать компьютер." << std::endl;
}
void print_help_unlock(){
    std::cout << "  unlock                                   Разблокировать компьютер." << std::endl;
}

void print_help_lockstatus(){
    std::cout << "  lockstatus                               Информация о блокировке" << std::endl;
}

void print_help_hash(){
    std::cout << "  hash calc <путь_к_исполняемому_файлу>    Вычислить (пересчитать хэш-сумму файла)" << std::endl;
}

void print_help_policy_action(){
    print_help_enable();
    print_help_disable();
    print_help_apply();
    print_help_set();
    print_help_policyrestrictioninfo();
    print_help_policylist();
}

// Функция для вывода справки
void print_help() {
    print_program_info();
    std::cout << "Синтаксис команд:" << std::endl;
    print_help_enable();
    print_help_disable();
    print_help_apply();
    print_help_set();

    print_help_help();
    print_help_policyrestrictioninfo();
    print_help_policylist();
    print_help_modulelist();

    print_help_lock();
    print_help_unlock();
    print_help_lockstatus();

    print_help_hash();
}
/*Функции вывода справки*/

/*Собственно, функции FIC*/
//Заблокировать компьютер
bool lock(const fic::platform::PlatformExecutableResolver& executables){
    const std::string lockStatusPath = fic::core::FicRuntimePaths::get().lockStatusFile.string();
    SingleLineFileHandler slch = SingleLineFileHandler(lockStatusPath);
    if(!slch.loadConfig()){
        std::cerr << "    Не удалось прочитать файл " << lockStatusPath << std::endl;
        return false;
    }

    if(!slch.setValue("", "1")){
        std::cerr << "    Прозошла ошибка при блокировке компьютера" << std::endl;
        return false;
    }
    if(!slch.saveConfig()){
        std::cerr << "    Прозошла ошибка при блокировке компьютера" << std::endl;
        return false;
    }

    std::cout << "    Компьютер заблокирован" << std::endl;

    //Производим блокировку всех активных сессий
    std::filesystem::path loginctl;
    std::string resolverError;
    if (!executables.resolve(
            fic::platform::ExecutableId::Loginctl,
            loginctl,
            resolverError)) {
        std::cerr << "    Не удалось выбрать loginctl: "
                  << resolverError << std::endl;
        return false;
    }
    const bool res = VerifiedProcessExecutor::execute(
        loginctl.string(), {"lock-sessions"}).success();

    if(!res){
        std::cerr << "    Не удалось произвести блокировку активных сессий." << std::endl;
        return false;
    }
    return true;
}

//Разблокировать компьютер
bool unlock(){
    const std::string lockStatusPath = fic::core::FicRuntimePaths::get().lockStatusFile.string();
    SingleLineFileHandler slch = SingleLineFileHandler(lockStatusPath);
    if(!slch.loadConfig()){
        std::cerr << "    Не удалось прочитать файл " << lockStatusPath << std::endl;
        return false;
    }

    if(!slch.setValue("", "0")){
        std::cerr << "    Прозошла ошибка при разблокировке компьютера" << std::endl;
        return false;
    }
    if(!slch.saveConfig()){
        std::cerr << "    Прозошла ошибка при разблокировке компьютера" << std::endl;
        return false;
    }
    std::cout << "    Компьютер разблокирован" << std::endl;
    return true;
}

//Текущий статус
bool lockstatus(){
    const std::string lockStatusPath = fic::core::FicRuntimePaths::get().lockStatusFile.string();
    SingleLineFileHandler slch = SingleLineFileHandler(lockStatusPath);
    if(!slch.loadConfig()){
        std::cerr << "    Не удалось прочитать файл " << lockStatusPath << std::endl;
        return false;
    }
    if (slch.getValue() == "0"){
        std::cout << "    Разблокировано" << std::endl;
    }else{
        std::cout << "    Заблокировано" << std::endl;
    }
    return true;
}

//Вычислить хэш для исполняемого файла
bool calcHash(const std::string& command){
    std::string error;
    if(!CommandHashStore::saveHash(command, error)){
        std::cerr << error << std::endl;
        return false;
    }
    return true;
}

//Получить значение параметра
std::string getArgvValue(int argc, char* argv[], int ind){
    if(ind >= argc){
        return "";
    }
    return argv[ind];
}

PolicyModule* getModule(
        PolicyRegistry& policyRegistry,
        const std::string& module){
        // Проверяем внешний ключ
        auto outerIt = policyRegistry.find(module);
        if (outerIt != policyRegistry.end()) {
            return &outerIt->second;
        }
        //Возвращаем пустой массив (нет политик)
        return nullptr;
}
//Дать класс политики
Policy* getPolicyClass(
    PolicyRegistry& policyRegistry,
    const std::string& module,
    const std::string& policy
) {
    // Проверяем внешний ключ (ищем модуль)
    auto moduleIt = policyRegistry.find(module);
    if (moduleIt == policyRegistry.end()) {
        return nullptr;  // Модуль не найден
    }

    // Ищем политику во всех подмодулях этого модуля
    for (const auto& submodulePair : moduleIt->second.submodules) {
        const auto& submodulePolicies = submodulePair.second;
        auto policyIt = submodulePolicies.find(policy);
        if (policyIt != submodulePolicies.end()) {
            return policyIt->second.get();  // Нашли политику
        }
    }

    return nullptr;  // Политика не найдена ни в одном подмодуле
}

//Дать информацию об ограничении
bool policy_info_restriction(PolicyRegistry& policyRegistry, std::string module, std::string policy){
    Policy* concretePolicy = getPolicyClass(policyRegistry, module, policy);
    if(concretePolicy != nullptr){
        std::cout << concretePolicy->getPolicyRestriction();
        return true;
    }else{
        std::cerr << "Политика '" + policy + "' не существует" << std::endl;
    }
    return false;
}
//Дать список модулей
bool module_list(PolicyRegistry& policyRegistry){
    std::string moduleList;
       bool first = true;
       for (const auto& [moduleConcrete, module] : policyRegistry){
           if (!first) moduleList += " ";
           moduleList += moduleConcrete;
           first = false;
       }
       std::cout << moduleList;
       return true;
}

bool policy_list(PolicyRegistry& policyRegistry, std::string module){
    if(module == "all"){
        for(const auto& [moduleName, policyModule] : policyRegistry){
            policy_list(policyRegistry, moduleName);
            std::cout << " ";
        }
        return true;
    }
    auto outerIt = policyRegistry.find(module);
       if (outerIt == policyRegistry.end()) {
           return false;
       }
       std::string policyList;
       bool first = true;
       for(const auto& [submoduleName, submoduleMap]: outerIt->second.submodules){
           for(const auto& [policyName, policyClass] : submoduleMap){
            if (!first) policyList += " ";
            policyList += policyName;
            first = false;
           }
       }
       std::cout << policyList;
       return true;
}

static void printPolicyApplyResult(const PolicyApplyResult& result) {
    const std::string policyInfo = result.moduleName + " " + result.policyName;
    if (result.status == PolicyApplyStatus::Applied) {
        std::cout << "Политика " << policyInfo << " успешно применена" << '\n';
        return;
    }
    if (result.status == PolicyApplyStatus::Disabled) {
        std::cout << "Политика " << policyInfo << " отключена. Применение не будет выполнено." << '\n';
        return;
    }
    if (result.status == PolicyApplyStatus::NotFound) {
        std::cout << result.message << ": " << policyInfo << '\n';
        return;
    }
    std::cout << "Не удалось применить политику " << policyInfo << '\n';
}

static void printPolicyApplySummary(const PolicyApplySummary& summary, std::string module, std::string policy) {
    for (const PolicyApplyResult& result : summary.getResults()) {
        printPolicyApplyResult(result);
    }

    if (isPolicyApplySuccessful(summary, module, policy)) {
        std::cout << "Итог применения: успешно"
                  << " (применено: " << summary.appliedCount()
                  << ", отключено: " << summary.disabledCount()
                  << ")" << '\n';
    } else {
        std::cout << "Итог применения: есть проблемы"
                  << " (применено: " << summary.appliedCount()
                  << ", ошибок: " << summary.failedCount()
                  << ", отключено: " << summary.disabledCount()
                  << ", не найдено: " << summary.notFoundCount()
                  << ")" << '\n';
    }
}

bool apply(PolicyRegistry& policyRegistry, std::string module, std::string policy) {
    PolicyApplySummary summary;
    if (module == "all") {
        summary = applyAllPolicies(policyRegistry);
    } else if (policy == "all") {
        summary = applyModulePolicies(policyRegistry, module);
    } else {
        summary = applyPolicy(policyRegistry, module, policy);
    }

    printPolicyApplySummary(summary, module, policy);
    return isPolicyApplySuccessful(summary, module, policy);
}

//Отключить политику
bool disable (PolicyRegistry& policyRegistry, std::string module, std::string policy){
    Policy* concretePolicy = getPolicyClass(policyRegistry, module, policy);
    if(concretePolicy!=nullptr){
        std::cout << "Производим отключение политики: '" + policy + "' в модуле '" + module + "'"<<std::endl;
        ModuleConfigFileHandler mcfh = ModuleConfigFileHandler(module);
        if(!mcfh.loadConfig()){
            std::cout << "Не удалось загрузить конфигурационный файл" << '\n';
            return false;
        }
        if(!mcfh.disablePolicy(policy)){
            std::cout << "Не удалось отключить параметр" << '\n';
            return false;
        }
        std::cout << "Параметр " + policy + " отключен" << '\n';
        //mcfh.printConfig();
        if(!mcfh.saveConfig()){
            std::cout << "Не удалось отключить политику" << '\n';
            return false;
        }else{
            std::cout << "Политика была успешно дезактивирована" << '\n';
            return true;
        }
    }
    return false;
}
//Включить политику
bool enable(PolicyRegistry& policyRegistry, std::string module, std::string policy){
    Policy* concretePolicy = getPolicyClass(policyRegistry, module, policy);
    if(concretePolicy!=nullptr){
        std::cout << "Производим включение политики: '" + policy + "' в модуле '" + module + "'"<<std::endl;
        ModuleConfigFileHandler mcfh = ModuleConfigFileHandler(module);
        if(!mcfh.loadConfig()){
            std::cout << "Не удалось загрузить конфигурационный файл" << '\n';
            return false;
        }
        if(!mcfh.enablePolicy(policy)){
            std::cout << "Не удалось включить параметр" << '\n';
            return false;
        }
        std::cout << "Параметр " + policy + " включен" << '\n';
        //mcfh.printConfig();
        if(!mcfh.saveConfig()){
            std::cout << "Не удалось включить политику" << '\n';
            return false;
        }else{
            std::cout << "Политика была успешна активирована" << '\n';
            return true;
        }
    } else {
        std::cout << "Указанная политика не существует" << '\n';
        return false;
    }
    return false;
}

bool set(PolicyRegistry& policyRegistry, std::string module, std::string policy, std::string value){
   Policy* concretePolicy = getPolicyClass(policyRegistry, module, policy);
    if(concretePolicy != nullptr){
        std::cout << "Производим попытку смены значения политики " + policy + " в модуле " + module + "..." << std::endl;
        //Производим валидацию и преобразование параметра
        if(!concretePolicy->validate(value)){
            std::cerr << "Параметр не является допустимым для политики " + policy << '\n';
            concretePolicy->getPolicyRestriction();
            return false;
        }
        ModuleConfigFileHandler mcfh = ModuleConfigFileHandler(module);
        if(!mcfh.loadConfig()){
            std::cerr << "Не удалось загрузить конфигурационный файл" << '\n';
            return false;
        }
        //После валидации преобразуем в удобный для хранения вид
        std::string valPostprocessing = concretePolicy->postprocessingValue(value);
        //Улучшить!
        if(valPostprocessing == ""){
            std::cerr << "Не удалось преобразовать параметр." << '\n';
            return false;
        }
        if(!mcfh.setPolicyValue(policy, valPostprocessing)){
            std::cerr << "Не удалось задать значение параметра" << '\n';
            return false;
        }
        std::cout << "Параметру " + policy + " было присвоено переданное значение. Если статус не был задан ранее, политика остается выключенной." << '\n';
        if(!mcfh.saveConfig()){
            std::cerr << "Не удалось сохранить конфигурационный файл" << '\n';
            return false;
        }else{
            std::cout << "Конфигурационный файл был обновлен" << '\n';
            return true;
        }
    } else {
        std::cerr << "Указанная политика не существует" << '\n';
        return false;
    }
    return false;
}

/*Ининциализируем массив классов*/
bool initPolicyRegistry(
    const fic::platform::PlatformProfile& platform,
    const fic::platform::PlatformExecutableResolver& executables,
    PolicyRegistry& registry,
    std::string& error)
{
    return rebuildPolicyRegistry([&]() {
        PolicyList cafArr;

    //Дискреционное разграничение доступа (DAC)
    cafArr.push_back(std::make_unique<DAC_systemcommandlock>(platform.dac));
    cafArr.push_back(std::make_unique<DAC_blocking_user_access_to_system_files>(
        platform.dac));
    cafArr.push_back(std::make_unique<DAC_custom_mode_and_owner>());
    cafArr.push_back(std::make_unique<DAC_sudo_env_reset>(
        platform.sudo, executables));
    cafArr.push_back(std::make_unique<DAC_sudo_passwd_tries>(
        platform.sudo, executables));
    cafArr.push_back(std::make_unique<DAC_sudo_securepath>(
        platform.sudo, executables));
    cafArr.push_back(std::make_unique<DAC_sudo_timeout>(
        platform.sudo, executables));
    cafArr.push_back(std::make_unique<DAC_sudo_require_authentication>(
        platform.sudo, executables));

    // Identity and access: PAM
    cafArr.push_back(
        std::make_unique<PamPasswordMinLengthPolicy>(platform.pam));
    cafArr.push_back(
        std::make_unique<PamPasswordMinClassesPolicy>(platform.pam));
    cafArr.push_back(
        std::make_unique<PamPasswordHistoryDepthPolicy>(platform.pam));
    cafArr.push_back(
        std::make_unique<PamPasswordHistoryEnforceForRootPolicy>(
            platform.pam));
    cafArr.push_back(std::make_unique<PamFailedAuthenticationAttemptsPolicy>(
        platform.pam));
    cafArr.push_back(
        std::make_unique<PamFailedAuthenticationCountingPeriodPolicy>(
            platform.pam));
    cafArr.push_back(
        std::make_unique<PamFailedAuthenticationEnforceForRootPolicy>(
            platform.pam));
    cafArr.push_back(std::make_unique<PamFailedAuthenticationUnlockTimePolicy>(
        platform.pam));
    cafArr.push_back(
        std::make_unique<RequiredPamEnforcementPolicy>(platform.pam));

    // Identity and access: SSSD, Kerberos and NSS
    cafArr.push_back(
        std::make_unique<SssdOfflineCredentialsExpirationPolicy>(executables));
    cafArr.push_back(std::make_unique<KerberosTicketLifetimePolicy>());

    //Настройки ядра (SYSCTL)
    cafArr.push_back(std::make_unique<SYSCTL_dmesg_restrict>());
    cafArr.push_back(std::make_unique<SYSCTL_fd_limits>());
    cafArr.push_back(std::make_unique<SYSCTL_fs_protection>());
    cafArr.push_back(std::make_unique<SYSCTL_ipv4_default_accept_redirects_disable>());
    cafArr.push_back(std::make_unique<SYSCTL_ipv4_default_rp_filter_enable>());
    cafArr.push_back(std::make_unique<SYSCTL_ipv4_default_send_redirects_disable>());
    cafArr.push_back(std::make_unique<SYSCTL_ipv6_all_accept_redirects_disable>());
    cafArr.push_back(std::make_unique<SYSCTL_ipv6_default_accept_redirects_disable>());
    cafArr.push_back(std::make_unique<SYSCTL_ipv6_packet_forwarding_disable>());
    cafArr.push_back(std::make_unique<SYSCTL_kernel_code_execution_restrict>());
    cafArr.push_back(std::make_unique<SYSCTL_nr_open_limit>());
    cafArr.push_back(std::make_unique<SYSCTL_packet_forwarding_disable>());
    cafArr.push_back(std::make_unique<SYSCTL_perf_event_paranoid>());
    cafArr.push_back(std::make_unique<SYSCTL_protected_symlinks>());
    cafArr.push_back(std::make_unique<SYSCTL_process_limits>());
    cafArr.push_back(std::make_unique<SYSCTL_ptrace_restrict>());
    cafArr.push_back(std::make_unique<SYSCTL_randomize_va_space>());
    cafArr.push_back(std::make_unique<SYSCTL_redirects_disable>());
    cafArr.push_back(std::make_unique<SYSCTL_rp_filter_enable>());
    cafArr.push_back(std::make_unique<SYSCTL_send_redirects_disable>());
    cafArr.push_back(std::make_unique<SYSCTL_suid_dump_disable>());
    cafArr.push_back(std::make_unique<SYSCTL_sysrq_disable>());
    cafArr.push_back(std::make_unique<SYSCTL_syn_flood_protection>());
    cafArr.push_back(std::make_unique<SYSCTL_tcp_keepalive_time>());
    cafArr.push_back(std::make_unique<SYSCTL_tcp_max_syn_backlog>());
    cafArr.push_back(std::make_unique<SYSCTL_tcp_synack_retries>());
    cafArr.push_back(std::make_unique<SYSCTL_tcp_fin_timeout>());
    cafArr.push_back(std::make_unique<SYSCTL_threads_max_limit>());
    cafArr.push_back(std::make_unique<SYSCTL_user_ns_restrict>());

    //Настройки операционной системы (OSS)
    cafArr.push_back(std::make_unique<OSS_grub_timeout>(
        platform.grub, executables));
    cafArr.push_back(std::make_unique<OSS_grub_cmdline_linux>(
        platform.grub, executables));
    cafArr.push_back(std::make_unique<OSS_grub_disable_recovery>(
        platform.grub, executables));
    cafArr.push_back(std::make_unique<OSS_screenlock_timeout>(
        executables));
    cafArr.push_back(std::make_unique<OSS_disable_autologin>(
        executables, platform.displayManager));
    cafArr.push_back(
        std::make_unique<OSS_disable_videodisplay_when_locked>(
        executables));
    cafArr.push_back(std::make_unique<OSS_lock_on_tty_switch>());
    cafArr.push_back(std::make_unique<OSS_fstab_tmp_profile>());
    cafArr.push_back(std::make_unique<OSS_fstab_var_tmp_profile>());
    cafArr.push_back(std::make_unique<OSS_fstab_dev_shm_profile>());
    cafArr.push_back(std::make_unique<OSS_fstab_home_profile>());
    cafArr.push_back(std::make_unique<OSS_fstab_removable_media_profile>());
    cafArr.push_back(std::make_unique<OSS_fstab_var_log_secure_options>());
    cafArr.push_back(std::make_unique<OSS_fstab_var_log_audit_secure_options>());
    cafArr.push_back(std::make_unique<OSS_fstab_boot_profile>());
    cafArr.push_back(std::make_unique<OSS_fstab_boot_efi_profile>());
    cafArr.push_back(std::make_unique<OSS_fstab_srv_profile>());
    cafArr.push_back(std::make_unique<OSS_fstab_opt_profile>());

    //Сетевые настройки
    cafArr.push_back(std::make_unique<NET_ssh_port>(
        platform.ssh, executables));
    cafArr.push_back(std::make_unique<NET_ssh_max_auth_tries>(
        platform.ssh, executables));
    cafArr.push_back(std::make_unique<NET_ssh_root_login>(
        platform.ssh, executables));
    cafArr.push_back(std::make_unique<NET_ssh_pubkey_auth>(
        platform.ssh, executables));

    // Межсетевой экран nftables
    cafArr.push_back(std::make_unique<fic::firewall::BlockRdpPolicy>(executables));
    cafArr.push_back(std::make_unique<fic::firewall::BlockFtpPolicy>(executables));
    cafArr.push_back(std::make_unique<fic::firewall::CustomRulesPolicy>(executables));
    cafArr.push_back(
        std::make_unique<fic::firewall::ExclusiveFirewallControlPolicy>(executables));

    //Общие настройки контроля устройств
    cafArr.push_back(std::make_unique<DC_block_usb_storage>());
    cafArr.push_back(std::make_unique<DC_block_printers_scanners>());
    cafArr.push_back(std::make_unique<DC_block_optical_drives>());

    //Глобальные настройки программы
    cafArr.push_back(std::make_unique<AUDIT_log_level>());
    cafArr.push_back(std::make_unique<GLOBAL_lang>());
    //Для удобства отсортируем в массив вида "модуль->подмодуль->политика->класс,представляющий политику для данного модуля"
    for (auto& policyClass : cafArr) {
        if (auto* sysctlPolicy = dynamic_cast<Sysctl*>(policyClass.get())) {
            sysctlPolicy->setPlatformConfig(platform.sysctl);
        }
    }
        return cafArr;
    }, registry, error);
}
