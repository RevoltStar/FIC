#include "daemon/PolicyDisableFlow.h"

#include <fic/core/config/ModuleConfigFileHandler.h>

#include <iostream>

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

    ModuleConfigFileHandler config(policy.moduleName);
    if (!config.loadConfig()) {
        std::cout << "Не удалось загрузить конфигурационный файл" << '\n';
        return PolicyMutationResult::failure(
            "could not load module configuration");
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
            "could not save module configuration");
    }
    std::cout << "Политика была успешно дезактивирована" << '\n';
    return PolicyMutationResult::success();
}

} // namespace fic::daemon
