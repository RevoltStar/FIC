#pragma once

#include "modules/net/NET.h"
#include "modules/net/ssh/SshRollback.h"
#include "service/ssh/SshVerifiedActivationAdapter.h"
#include "rollback/MutationJournal.h"

namespace fic::ssh {

class SshMfaPolicy final : public Net {
public:
    SshMfaPolicy();
    bool apply() override;
};

// Call while holding sshResourceMutex. The generation belongs to the current
// PolicyRegistry in apply and to the current trusted release intent in rollback.
std::optional<fic::service::ssh::SshMfaReference> requiredMfaForOperation(
    const fic::rollback::MutationJournal&, const std::string& configPath,
    const AtomicTargetState& generation);
bool proveSshMfaPrepareUninstall(const fic::rollback::MutationJournal&, std::string& error);
// Called only by the authorized rollback-all path, with sshResourceMutex held.
void proveSshMfaUninstallReleased(const fic::rollback::MutationJournal&,
                                 std::optional<AtomicTargetState>& configGeneration);
struct SshMfaReleaseIntent {
    SshReleaseContext context = SshReleaseContext::PolicyDisable;
    std::function<bool(std::string&)> uninstallFence;
    std::string path;
    AtomicTargetState generation;
    std::map<std::string, std::string> survivingPolicies;
};
// The release executor holds sshResourceMutex across the transaction.
SshRollbackResult releaseSshMfa(fic::rollback::MutationJournal&, const SshMfaReleaseIntent&);
bool acknowledgeSshMfaDisable(
    fic::rollback::MutationJournal&, const fic::rollback::MutationRecord&, std::string&);

} // namespace fic::ssh
