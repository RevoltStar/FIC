#include "daemon/PolicyDisableFlow.h"
#include "policy/registry/PolicyRegistry.h"
#include <fic/core/runtime/FicRuntimePaths.h>

#include <fic/core/config/ModuleConfigFileHandler.h>

#include <iostream>
#include <algorithm>

namespace fic::daemon {

PolicyMutationResult disablePolicyAfterLookup(
    const PolicyRef& policy,
    const std::string& resourceHint,
    const fic::rollback::RollbackExecutorDeps& rollbackDeps) {
    const bool sssd=policy.moduleName=="IDENTITY_ACCESS"&&policy.submoduleName=="SSSD";
    const auto failed=[&](std::string detail,std::optional<bool> saved=std::nullopt) {
        auto result=PolicyMutationResult::failure(std::move(detail));
        if(sssd){result.saved=saved;result.applied=false;}
        return result;
    };
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
        return failed(rollbackReport.message,false);
    }
    if (rollbackReport.status == fic::rollback::RollbackStatus::Success) {
        std::cout << "Rollback выполнен: " << rollbackReport.message << '\n';
    }

    const bool ssh=policy.moduleName=="NET"&&policy.submoduleName=="SshEdit"&&
        rollbackDeps.sshOptions&&rollbackDeps.sshOptions().verifiedRelease;
    const bool awaiting=std::any_of(rollbackReport.outcomes.begin(),rollbackReport.outcomes.end(),
        [](const auto& outcome){return outcome.awaitingPolicyDisable;});
    FileHandlerOptions options;
    if(ssh||sssd){options.writeOptions.createIfMissing=false;options.writeOptions.rejectSymlink=true;}
    if(sssd) {
        auto* current=rollbackDeps.sssdRegistry?rollbackDeps.sssdRegistry->findPolicy(policy):nullptr;
        std::string path,error;AtomicTargetState snapshot;
        if(!current||!current->captureConfigurationVersion(path,snapshot,error)||snapshot.owner!=0||(snapshot.mode&0022)||
           path!=(fic::core::FicRuntimePaths::get().configDir/"IDENTITY_ACCESS.conf").string())
            return failed("SSSD release retained; current trusted registry/configuration required before DISABLE save: "+error,false);
        options.writeOptions.expectedTargetState=snapshot;
    }
    ModuleConfigFileHandler config(policy.moduleName,options);
    if (!config.loadConfig()) {
        std::cout << "Не удалось загрузить конфигурационный файл" << '\n';
        return failed(
            awaiting?"Ownership released; current configuration unavailable; DISABLE unconfirmed, release intent retained":"could not load module configuration",false);
    }
    if (!config.disablePolicy(policy.policyName)) {
        std::cout << "Не удалось отключить параметр" << '\n';
        return failed("could not disable policy in module configuration",false);
    }
    std::cout << "Параметр " << policy.policyName << " отключен" << '\n';
    if (!config.saveConfig()) {
        std::cout << "Не удалось отключить политику" << '\n';
        return failed(
            awaiting?"Ownership released; DISABLE save/durability unconfirmed; release intent retained":"could not save module configuration");
    }
    std::cout << (sssd?"DISABLE сохранён; требуется acknowledgement":"Политика была успешно дезактивирована") << '\n';
    std::string detail;
    if(ssh)for(const auto& outcome:rollbackReport.outcomes) {
        if(!detail.empty())detail+="; ";
        detail+=outcome.message;
    }
    PolicyMutationResult result{true,std::move(detail)};
    if(sssd){result.saved=true;result.applied=false;}
    return result;
}

} // namespace fic::daemon
