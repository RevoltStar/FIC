#include "main_function.h"

#include "utils/ProcessExecutor.h"


//Реализация test
void test(){
    std::cout << "<<-- START TEST() -->>";
    std::string p = "/home/MFC.LOCAL/poroshinmi/sudoers-test2.txt";
    SudoersConfigFileHandler scfh = SudoersConfigFileHandler(p);
    if(!scfh.loadConfig()){
       std::cout << "Не удалось сгенерировать конфиг" << std::endl;
    }
    std::cout << "ВЫВОД:" <<std::endl;
    scfh.printConfig();
    std::cout << "<<-- END TEST() -->>";
}


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
bool lock(){
    SingleLineFileHandler slch = SingleLineFileHandler("/opt/fic/lockstatus");
    if(!slch.loadConfig()){
        std::cerr << "    Не удалось прочитать файл /opt/fic/lockstatus" << std::endl;
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
    //В новых системах - /usr/bin/loginctl
    //В старых системах (а также в некоторых новых) - /bin/loginctl
    bool res = ProcessExecutor::execute("/usr/bin/loginctl", {"lock-sessions"}).success() ||
            ProcessExecutor::execute("/bin/loginctl", {"lock-sessions"}).success();

    if(!res){
        std::cerr << "    Не удалось произвести блокировку активных сессий." << std::endl;
    }
    return true;
}

//Разблокировать компьютер
bool unlock(){
    SingleLineFileHandler slch = SingleLineFileHandler("/opt/fic/lockstatus");
    if(!slch.loadConfig()){
        std::cerr << "    Не удалось прочитать файл /opt/fic/lockstatus" << std::endl;
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
    SingleLineFileHandler slch = SingleLineFileHandler("/opt/fic/lockstatus");
    if(!slch.loadConfig()){
        std::cerr << "    Не удалось прочитать файл /opt/fic/lockstatus" << std::endl;
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
    if(!CommandExecutor::calcHash(command)){
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

ModulePolicyMap getModule(
        PolicyMap& cafMap,
        const std::string& module){
        // Проверяем внешний ключ
        auto outerIt = cafMap.find(module);
        if (outerIt != cafMap.end()) {
            return outerIt->second;
        }
        //Возвращаем пустой массив (нет политик)
        return ModulePolicyMap();
}
//Дать класс политики
std::shared_ptr<Policy> getPolicyClass(
    PolicyMap& cafMap,
    const std::string& module,
    const std::string& policy
) {
    // Проверяем внешний ключ (ищем модуль)
    auto moduleIt = cafMap.find(module);
    if (moduleIt == cafMap.end()) {
        return nullptr;  // Модуль не найден
    }

    // Ищем политику во всех подмодулях этого модуля
    for (const auto& submodulePair : moduleIt->second) {
        const auto& policyMap = submodulePair.second;
        auto policyIt = policyMap.find(policy);
        if (policyIt != policyMap.end()) {
            return policyIt->second;  // Нашли политику
        }
    }

    return nullptr;  // Политика не найдена ни в одном подмодуле
}

//Дать информацию об ограничении
bool policy_info_restriction(PolicyMap& cafMap, std::string module, std::string policy){
    std::shared_ptr<Policy> concretePolicy = getPolicyClass(cafMap, module, policy);
    if(concretePolicy != nullptr){
        std::cout << concretePolicy->getPolicyRestriction();
        return true;
    }else{
        std::cerr << "Политика '" + policy + "' не существует" << std::endl;
    }
    return false;
}
//Дать список модулей
bool module_list(PolicyMap& cafMap){
    std::string moduleList;
       bool first = true;
       for (const auto& [moduleConcrete, policyMap] : cafMap){
           if (!first) moduleList += " ";
           moduleList += moduleConcrete;
           first = false;
       }
       std::cout << moduleList;
       return true;
}

bool policy_list(PolicyMap& cafMap, std::string module){
    if(module == "all"){
        for(const auto& [moduleName, submoduleMap] : cafMap){
            policy_list(cafMap, moduleName);
            std::cout << " ";
        }
        return true;
    }
    auto outerIt = cafMap.find(module);
       if (outerIt == cafMap.end()) {
           return false;
       }
       std::string policyList;
       bool first = true;
       for(const auto& [submoduleName, submoduleMap]: cafMap[module]){
           for(const auto& [policyName, policyClass] : submoduleMap){
            if (!first) policyList += " ";
            policyList += policyName;
            first = false;
           }
       }
       std::cout << policyList;
       return true;
}

PolicyApplyResult applyPolicy(PolicyMap& cafMap, std::string module, std::string policy) {
    auto moduleIt = cafMap.find(module);
    if (moduleIt == cafMap.end()) {
        return {module, "", policy, PolicyApplyStatus::NotFound, "Модуль не существует"};
    }

    for (const auto& [submoduleName, policyMap] : moduleIt->second) {
        auto policyIt = policyMap.find(policy);
        if (policyIt == policyMap.end()) {
            continue;
        }

        const std::shared_ptr<Policy>& policyClass = policyIt->second;
        if (!policyClass->isEnabled()) {
            return {
                module,
                submoduleName,
                policy,
                PolicyApplyStatus::Disabled,
                "Политика отключена. Применение не будет выполнено."
            };
        }

        const bool applied = policyClass->apply();
        return {
            module,
            submoduleName,
            policy,
            applied ? PolicyApplyStatus::Applied : PolicyApplyStatus::Failed,
            applied ? "Политика успешно применена" : "Не удалось применить политику"
        };
    }

    return {module, "", policy, PolicyApplyStatus::NotFound, "Политика не существует"};
}

PolicyApplySummary applyModulePolicies(PolicyMap& cafMap, std::string module) {
    PolicyApplySummary summary;
    auto moduleIt = cafMap.find(module);
    if (moduleIt == cafMap.end()) {
        summary.add({module, "", "all", PolicyApplyStatus::NotFound, "Модуль не существует"});
        return summary;
    }

    for (const auto& [submoduleName, policyMap] : moduleIt->second) {
        for (const auto& [policyName, policyClass] : policyMap) {
            if (!policyClass->isEnabled()) {
                summary.add({
                    module,
                    submoduleName,
                    policyName,
                    PolicyApplyStatus::Disabled,
                    "Политика отключена. Применение не будет выполнено."
                });
                continue;
            }

            const bool applied = policyClass->apply();
            summary.add({
                module,
                submoduleName,
                policyName,
                applied ? PolicyApplyStatus::Applied : PolicyApplyStatus::Failed,
                applied ? "Политика успешно применена" : "Не удалось применить политику"
            });
        }
    }

    return summary;
}

PolicyApplySummary applyAllPolicies(PolicyMap& cafMap) {
    PolicyApplySummary summary;
    for (const auto& [moduleName, submoduleMap] : cafMap) {
        for (const auto& [submoduleName, policyMap] : submoduleMap) {
            for (const auto& [policyName, policyClass] : policyMap) {
                if (!policyClass->isEnabled()) {
                    summary.add({
                        moduleName,
                        submoduleName,
                        policyName,
                        PolicyApplyStatus::Disabled,
                        "Политика отключена. Применение не будет выполнено."
                    });
                    continue;
                }

                const bool applied = policyClass->apply();
                summary.add({
                    moduleName,
                    submoduleName,
                    policyName,
                    applied ? PolicyApplyStatus::Applied : PolicyApplyStatus::Failed,
                    applied ? "Политика успешно применена" : "Не удалось применить политику"
                });
            }
        }
    }

    return summary;
}

bool isPolicyApplySuccessful(const PolicyApplySummary& summary, std::string module, std::string policy) {
    if (summary.hasFailures()) {
        return false;
    }

    const bool isSinglePolicyRequest = module != "all" && policy != "all";
    if (isSinglePolicyRequest) {
        return summary.totalCount() == 1 && summary.appliedCount() == 1;
    }

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

bool apply(PolicyMap& cafMap, std::string module, std::string policy) {
    PolicyApplySummary summary;
    if (module == "all") {
        summary = applyAllPolicies(cafMap);
    } else if (policy == "all") {
        summary = applyModulePolicies(cafMap, module);
    } else {
        summary.add(applyPolicy(cafMap, module, policy));
    }

    printPolicyApplySummary(summary, module, policy);
    return isPolicyApplySuccessful(summary, module, policy);
}

//Отключить политику
bool disable (std::map<std::string, std::map<std::string, std::map<std::string ,std::shared_ptr<Policy>>>>& cafMap, std::string module, std::string policy){
    std::shared_ptr<Policy> concretePolicy = getPolicyClass(cafMap, module, policy);
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
bool enable(std::map<std::string, std::map<std::string, std::map<std::string ,std::shared_ptr<Policy>>>>& cafMap, std::string module, std::string policy){
    std::shared_ptr<Policy> concretePolicy = getPolicyClass(cafMap, module, policy);
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

bool set(std::map<std::string, std::map<std::string, std::map<std::string ,std::shared_ptr<Policy>>>>& cafMap, std::string module, std::string policy, std::string value){
   std::shared_ptr<Policy> concretePolicy = getPolicyClass(cafMap, module, policy);
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
std::map<std::string, std::map<std::string, std::map<std::string ,std::shared_ptr<Policy>>>> init_cafMap(){
    std::vector<std::shared_ptr<Policy>> cafArr;

    //Дискреционное разграничение доступа (DAC)
    cafArr.push_back(std::make_shared<DAC_systemcommandlock>());
    cafArr.push_back(std::make_shared<DAC_blocking_user_access_to_system_files>());
    cafArr.push_back(std::make_shared<DAC_custom_mode_and_owner>());
    cafArr.push_back(std::make_shared<DAC_sudo_env_reset>());
    cafArr.push_back(std::make_shared<DAC_sudo_passwd_tries>());
    cafArr.push_back(std::make_shared<DAC_sudo_securepath>());
    cafArr.push_back(std::make_shared<DAC_sudo_timeout>());

    //Настройки ядра (SYSCTL)
    cafArr.push_back(std::make_shared<SYSCTL_buffer_overflow_protection>());
    cafArr.push_back(std::make_shared<SYSCTL_dmesg_restrict>());
    cafArr.push_back(std::make_shared<SYSCTL_fd_limits>());
    cafArr.push_back(std::make_shared<SYSCTL_fs_protection>());
    cafArr.push_back(std::make_shared<SYSCTL_ipv4_default_accept_redirects_disable>());
    cafArr.push_back(std::make_shared<SYSCTL_ipv4_default_rp_filter_enable>());
    cafArr.push_back(std::make_shared<SYSCTL_ipv4_default_send_redirects_disable>());
    cafArr.push_back(std::make_shared<SYSCTL_ipv6_all_accept_redirects_disable>());
    cafArr.push_back(std::make_shared<SYSCTL_ipv6_default_accept_redirects_disable>());
    cafArr.push_back(std::make_shared<SYSCTL_ipv6_packet_forwarding_disable>());
    cafArr.push_back(std::make_shared<SYSCTL_kernel_code_execution_restrict>());
    cafArr.push_back(std::make_shared<SYSCTL_nr_open_limit>());
    cafArr.push_back(std::make_shared<SYSCTL_packet_forwarding_disable>());
    cafArr.push_back(std::make_shared<SYSCTL_perf_event_paranoid>());
    cafArr.push_back(std::make_shared<SYSCTL_protected_symlinks>());
    cafArr.push_back(std::make_shared<SYSCTL_process_limits>());
    cafArr.push_back(std::make_shared<SYSCTL_ptrace_restrict>());
    cafArr.push_back(std::make_shared<SYSCTL_randomize_va_space>());
    cafArr.push_back(std::make_shared<SYSCTL_redirects_disable>());
    cafArr.push_back(std::make_shared<SYSCTL_rp_filter_enable>());
    cafArr.push_back(std::make_shared<SYSCTL_send_redirects_disable>());
    cafArr.push_back(std::make_shared<SYSCTL_suid_dump_disable>());
    cafArr.push_back(std::make_shared<SYSCTL_syn_flood_protection>());
    cafArr.push_back(std::make_shared<SYSCTL_tcp_keepalive_time>());
    cafArr.push_back(std::make_shared<SYSCTL_tcp_max_syn_backlog>());
    cafArr.push_back(std::make_shared<SYSCTL_tcp_synack_retries>());
    cafArr.push_back(std::make_shared<SYSCTL_tcp_timeout>());
    cafArr.push_back(std::make_shared<SYSCTL_threads_max_limit>());
    cafArr.push_back(std::make_shared<SYSCTL_user_ns_restrict>());

    //Настройки операционной системы (OSS)
    cafArr.push_back(std::make_shared<OSS_screenlock_timeout>());
    cafArr.push_back(std::make_shared<OSS_disable_autologin>());
    cafArr.push_back(std::make_shared<OSS_disable_videodisplay_when_locked>());
    cafArr.push_back(std::make_shared<OSS_lock_on_tty_switch>());

    //Сетевые настройки
    cafArr.push_back(std::make_shared<NET_ssh_port>());
    cafArr.push_back(std::make_shared<NET_ssh_max_auth_tries>());
    cafArr.push_back(std::make_shared<NET_ssh_root_login>());


    //Глобальные настройки программы
    cafArr.push_back(std::make_shared<GLOBAL_log_level>());
    cafArr.push_back(std::make_shared<GLOBAL_lang>());
    //Для удобства отсортируем в массив вида "модуль->подмодуль->политика->класс,представляющий политику для данного модуля"
    std::map<std::string, std::map<std::string, std::map<std::string ,std::shared_ptr<Policy>>>> cafMap;

    auto it = cafArr.begin();
        while (it != cafArr.end()) {
            //std::cout << (*it)->moduleName << std::endl;
            //std::cout << (*it)->submoduleName << std::endl;
            //std::cout << (*it)->policyName << std::endl;
            if((*it)->moduleName == "" || (*it)->policyName == "" || (*it)->submoduleName == ""){
                if((*it)->submoduleName == ""){
                    //submodule пуст -> нужно быть осторожным и следить, чтобы это поле не было пусто когда не надо
                }else{
                    std::cerr << "Не заданы значения moduleName, policyName. Требуется проверить код!" << std::endl;
                    cafMap.clear();
                    return cafMap;
                }
            }
            cafMap[(*it)->moduleName][(*it)->submoduleName][(*it)->policyName] = (*it);
            ++it;  // перемещаемся вперёд на один элемент
    }
    return cafMap;
}
