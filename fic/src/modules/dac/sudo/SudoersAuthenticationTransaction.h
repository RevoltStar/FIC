#pragma once
#include "SudoersAuthenticationWrapper.h"
#include "SudoersScopedDefaultsTransaction.h"
#include "rollback/MutationJournal.h"
namespace fic::sudoers {
struct AuthenticationHooks {
    std::function<bool(std::string&)> verifySharedOwnership;
    std::function<bool(bool& scopedRequested, std::string&)> requestedScopedState;
    std::function<void(const std::filesystem::path&)> beforeWrite;
    std::function<void(const char*)> checkpoint;
};
// Caller holds SudoersConfiguration::mutationMutex throughout this lifecycle.
class AuthenticationTransaction {
public:
    AuthenticationTransaction(SudoersConfigurationOptions options,
                              fic::rollback::MutationJournal& journal,
                              AuthenticationHooks hooks = {});
    SudoersOperationResult reconcile();
    SudoersOperationResult release(const fic::rollback::UndoReleaseSudoAuthentication& payload);
    bool verifyOwnership(std::string& error, bool rejectScopedFrames = false);
private:
    SudoersConfigurationOptions options_;
    fic::rollback::MutationJournal& journal_;
    AuthenticationHooks hooks_;
    bool boundary(SudoersConfiguration& config, std::string& error, bool compensation = false);
    bool capture(SudoersConfiguration& config, const std::vector<AuthenticationProof>& proofs,
                 ScopedDefaultsCapturedState& out, std::string& error);
    bool prove(const ScopedDefaultsCapturedState& state, const std::vector<AuthenticationProof>& proofs,
               bool exact, bool fullyReleased, bool semantics, std::string& error);
    bool compensate(SudoersConfiguration& config, const std::vector<AuthenticationProof>& previous,
                    const std::vector<AuthenticationProof>& target, std::string& error);
};
}

namespace fic::sudoers {
bool readSudoRequestedState(bool& authentication, bool& scoped, std::string& error);
// Read-only cross-policy release guard. Only restored entries are assessed;
// requested policies without a mutation record still protect their invariant.
bool guardScopedAuthenticationRelease(SudoersConfiguration& configuration,
    const std::vector<SudoScopedDefaultsWrapperProof>& proofs,
    bool authenticationRequested, std::string& error);
}
