#ifndef FIC_ROLLBACK_DAEMON_MUTATION_JOURNAL_H
#define FIC_ROLLBACK_DAEMON_MUTATION_JOURNAL_H

#include "rollback/MutationJournal.h"

#include <filesystem>
#include <memory>
#include <mutex>
#include <string>

namespace fic::rollback {

// Process-wide access to the daemon mutation journal. Policy backends use the
// record* helpers around their system mutations; the rollback executor uses
// tryGet(). The journal path comes from FicRuntimePaths; unit tests may
// override it with setOverridePath().
class DaemonMutationJournal {
public:
    static DaemonMutationJournal& instance();

    // Returns nullptr when FIC runtime paths are not initialized (unit-test
    // environment). Sets error and returns nullptr when the journal exists
    // but cannot be loaded: callers must fail closed in that case.
    MutationJournal* tryGet(std::string& error);

    void setOverridePath(std::filesystem::path path);
    void resetOverride();

private:
    DaemonMutationJournal() = default;

    MutationJournal* open(std::string& error);

    std::filesystem::path overridePath_;
    std::unique_ptr<MutationJournal> journal_;
    std::mutex mutex_;
    bool open_ = false;
};

// Recording helpers used by backends around a system mutation:
//   recordPreparedMutation  -> call BEFORE the system mutation is committed;
//   commitMutation          -> call after the mutation was applied & verified;
//   discardMutation         -> call when the mutation did not happen.
bool recordPreparedMutation(const PolicyRef& policy,
                            const std::string& resource,
                            const UndoAction& undo,
                            MutationId& id,
                            std::string& error);
bool commitMutation(MutationId id, std::string& error);
bool discardMutation(MutationId id, std::string& error);

} // namespace fic::rollback

#endif // FIC_ROLLBACK_DAEMON_MUTATION_JOURNAL_H
