#pragma once
#include "modules/net/ssh/SshConfigFile.h"
#include "rollback/MutationJournal.h"
#include "service/ssh/SshVerifiedActivationAdapter.h"
#include <functional>

// Specialized SSH Port operation; callers hold sshResourceMutex throughout.
// Uses the existing journal and verified adapter, never another ownership engine.
struct SshPortMutationPlan {
    fic::service::ssh::SshPortSourceMap source;
    std::map<std::string,std::string> targets;
    fic::rollback::UndoRemoveSshManagedPolicy targetOwnership;
    std::map<std::string,fic::rollback::SshPlannedFilePublication> publication;
    bool changed=false;
};
SshPortMutationPlan planSshPortMutation(
    fic::service::ssh::SshPortSourceMap source,
    const fic::rollback::UndoRemoveSshManagedPolicy* previous,
    const std::string& value,bool release=false);
struct SshPortOperationResult {bool ok=false;std::string message;};
SshPortOperationResult applySshPortGraph(fic::rollback::MutationJournal&,const PolicyRef&,
    const std::string& value,const AtomicTargetState& mainSnapshot,
    const std::map<std::string,std::string>& expectedService,
    const std::map<std::string,std::string>& additionalPolicies,
    const std::function<bool(std::string&)>& currentIntent,
    const std::function<void()>& beforeWrite);
// Publishes a complete, already Prepared plan. No service action or compensation.
// Every file has its own CAS and durable receipt; possible effects retain intent.
bool publishSshPortPlan(fic::rollback::MutationJournal&,fic::rollback::MutationId,
    const SshPortMutationPlan&,const std::function<bool(std::string&)>& admission,
    const std::function<void()>& beforeWrite,
    std::map<std::string,AtomicTargetState>& installed,std::set<std::string>& notInstalled,std::string& error);
bool verifySshPortReleasedFiles(const fic::rollback::SshOwnershipTransition&,std::string& error);
struct SshRollbackOptions;
struct SshRollbackResult;
SshRollbackResult releaseSshPortGraph(const SshRollbackOptions&,
    const fic::rollback::UndoRemoveSshManagedPolicy&,const AtomicTargetState& mainSnapshot);
