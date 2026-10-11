#ifndef FIC_SCOPE_TRANSITION_H
#define FIC_SCOPE_TRANSITION_H

#include "rollback/MutationJournal.h"

#include <functional>
#include <string>
#include <vector>

namespace fic::rollback {

struct ScopeTransitionState {
    std::vector<std::string> committed;
    std::vector<std::string> target;
    std::string phase;
    MutationId id = 0;
};

// Checkpoints grant no physical ownership. Each callback must use the
// independently journaled resource proofs; empty desired state is never an
// implicit authorization to remove a resource. Call under the FIC apply lock.
class ScopeTransition {
public:
    using Operation = std::function<bool(std::string&)>;

    enum class FailurePhase { None, State, Configuration, Preflight, CheckpointPrepare, Ensure, Release, Verify, CheckpointCommit };
    enum class Domain { Desktop, DisplayManager };
    explicit ScopeTransition(MutationJournal& journal, Domain domain = Domain::Desktop)
        : journal_(journal), domain_(domain) {}
    bool state(ScopeTransitionState& state, std::string& error) const;
    bool requireCommitted(const std::vector<std::string>& configured,
                          std::string& error) const;
    bool invalidate(const std::string& reason, std::string& error);
    bool reconcile(const std::vector<std::string>& configured,
                   const Operation& preflight,
                   const Operation& ensure,
                   const Operation& release,
                   const Operation& verify,
                   std::string& error, FailurePhase* failurePhase = nullptr);

private:
    MutationJournal& journal_;
    Domain domain_;
};

} // namespace fic::rollback
#endif
