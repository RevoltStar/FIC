#include "daemon/PolicyDisableFlow.h"

#include <fic/core/config/ModuleConfigFileHandler.h>

#include <iostream>
#include <algorithm>

namespace fic::daemon {

PolicyMutationResult disablePolicyAfterLookup(
    const PolicyRef& policy,
    const std::string& resourceHint,
    const fic::rollback::RollbackExecutorDeps& rollbackDeps) {
    const fic::rollback::RollbackReport rollbackReport =
        fic::rollback::rollbackPolicyBeforeDisable(
            policy, resourceHint, rollbackDeps);
    for (const fic::rollback::MutationRollbackOutcome& outcome :
         rollbackReport.outcomes) {
        std::cout << "Rollback [" << outcome.id << "] " << outcome.resource
                  << ": " << fic::rollback::rollbackStatusToString(outcome.status)
                  << (outcome.message.empty() ? "" : (": " + outcome.message))
                  << '\n';
    }
    if (!rollbackReport.rollbackCompleted()) {
        std::cout << "Rollback не завершен: " << rollbackReport.message << '\n';
        std::cout << "Отключение политики отменено, чтобы не оставить "
                     "незадокументированные изменения FIC." << '\n';
        return PolicyMutationResult::failure(rollbackReport.message);
    }
    if (rollbackReport.status == fic::rollback::RollbackStatus::Success) {
        std::cout << "Rollback выполнен: " << rollbackReport.message << '\n';
    }

    const bool ssh=policy.moduleName=="NET"&&policy.submoduleName=="SshEdit"&&
        rollbackDeps.sshOptions&&rollbackDeps.sshOptions().verifiedRelease;
    const bool awaiting=std::any_of(rollbackReport.outcomes.begin(),rollbackReport.outcomes.end(),
        [](const auto& outcome){return outcome.awaitingPolicyDisable;});
    FileHandlerOptions options;
    if(ssh){options.writeOptions.createIfMissing=false;options.writeOptions.rejectSymlink=true;}
    ModuleConfigFileHandler config(policy.moduleName,options);
    if (!config.loadConfig()) {
        std::cout << "Не удалось загрузить конфигурационный файл" << '\n';
        return PolicyMutationResult::failure(
            awaiting?"SSH ownership released; current configuration unavailable; DISABLE unconfirmed, release intent retained":"could not load module configuration");
    }
    if (!config.disablePolicy(policy.policyName)) {
        std::cout << "Не удалось отключить параметр" << '\n';
        return PolicyMutationResult::failure(
            "could not disable policy in module configuration");
    }
    std::cout << "Параметр " << policy.policyName << " отключен" << '\n';
    if (!config.saveConfig()) {
        std::cout << "Не удалось отключить политику" << '\n';
        return PolicyMutationResult::failure(
            awaiting?"SSH ownership released; DISABLE save/durability unconfirmed; release intent retained":"could not save module configuration");
    }
    std::cout << "Политика была успешно дезактивирована" << '\n';
    std::string detail;
    if(ssh)for(const auto& outcome:rollbackReport.outcomes) {
        if(!detail.empty())detail+="; ";
        detail+=outcome.message;
    }
    return {true,std::move(detail)};
}

} // namespace fic::daemon
