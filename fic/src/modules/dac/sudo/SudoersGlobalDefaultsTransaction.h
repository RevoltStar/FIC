#ifndef FIC_SUDOERS_GLOBAL_DEFAULTS_TRANSACTION_H
#define FIC_SUDOERS_GLOBAL_DEFAULTS_TRANSACTION_H

#include "modules/dac/sudo/SudoersConfiguration.h"
#include "rollback/MutationJournal.h"
#include <functional>

namespace fic::sudoers {

enum class GlobalDefaultsPhase {
    BeforePrepared, Prepared, OwnedFileInstalled, IncludeInstalled,
    PostconditionVerified, InertFileInstalled, IncludeReleased, FileReleased
};
using GlobalDefaultsPhaseHook = std::function<void(GlobalDefaultsPhase)>;

// Callers hold SudoersConfiguration::mutationMutex(). Filesystem ownership is
// always derived from active typed journal records, never from marker names.
class GlobalDefaultsTransaction {
public:
    GlobalDefaultsTransaction(SudoersConfigurationOptions options,
                              rollback::MutationJournal& journal,
                              GlobalDefaultsPhaseHook hook = {});
    SudoersOperationResult reconcile(const PolicyRef& policy,
                                    const std::string& key,
                                    const std::string& renderedLine,
                                    const std::string& expectedValue);
    SudoersOperationResult release(const rollback::MutationRecord& record);
    // Shared source editors may preserve a failed rollback owner whose exact
    // target is still physically present, without resolving its journal state.
    // Construction guarantees keep the stricter default.
    bool verifyNoOwnedSetting(const std::string& key, std::string& error,
                              bool allowProvenFailedOwners = false);

private:
    SudoersConfigurationOptions options_;
    rollback::MutationJournal& journal_;
    GlobalDefaultsPhaseHook hook_;
    void phase(GlobalDefaultsPhase value) { if (hook_) hook_(value); }
};
} // namespace fic::sudoers
#endif
