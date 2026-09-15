#include "rollback/DaemonMutationJournal.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#include <memory>
#include <mutex>
#include <utility>

namespace fic::rollback {
namespace {
std::mutex instanceMutex;
}

DaemonMutationJournal& DaemonMutationJournal::instance() {
    static DaemonMutationJournal instance;
    return instance;
}

MutationJournal* DaemonMutationJournal::open(std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (open_) {
        return journal_.get();
    }
    std::filesystem::path path = overridePath_;
    if (path.empty()) {
        if (!fic::core::FicRuntimePaths::isInitialized()) {
            // Unit-test environment without daemon runtime paths.
            error.clear();
            return nullptr;
        }
        path = fic::core::FicRuntimePaths::get().mutationJournalFile;
    }
    auto journal = std::make_unique<MutationJournal>(std::move(path));
    if (!journal->load(error)) {
        // Fail closed: a broken journal must not silently lose provenance.
        return nullptr;
    }
    journal_ = std::move(journal);
    open_ = true;
    error.clear();
    return journal_.get();
}

MutationJournal* DaemonMutationJournal::tryGet(std::string& error) {
    return open(error);
}

void DaemonMutationJournal::setOverridePath(std::filesystem::path path) {
    std::lock_guard<std::mutex> lock(mutex_);
    overridePath_ = std::move(path);
    journal_.reset();
    open_ = false;
}

void DaemonMutationJournal::resetOverride() {
    std::lock_guard<std::mutex> lock(mutex_);
    overridePath_.clear();
    journal_.reset();
    open_ = false;
}

bool recordPreparedMutation(const PolicyRef& policy,
                            const std::string& resource,
                            const UndoAction& undo,
                            MutationId& id,
                            std::string& error) {
    std::string journalError;
    MutationJournal* journal = DaemonMutationJournal::instance().tryGet(journalError);
    if (journal == nullptr) {
        error = journalError.empty()
            ? "Mutation journal недоступен: runtime paths не инициализированы"
            : journalError;
        return false;
    }
    MutationRecord record;
    record.policy = policy;
    record.resource = resource;
    record.undo = undo;
    return journal->prepareMutation(std::move(record), id, error);
}

bool commitMutation(MutationId id, std::string& error) {
    std::string journalError;
    MutationJournal* journal = DaemonMutationJournal::instance().tryGet(journalError);
    if (journal == nullptr) {
        error = journalError.empty()
            ? "Mutation journal недоступен: runtime paths не инициализированы"
            : journalError;
        return false;
    }
    return journal->setStatus(id, MutationStatus::Applied, error);
}

bool discardMutation(MutationId id, std::string& error) {
    std::string journalError;
    MutationJournal* journal = DaemonMutationJournal::instance().tryGet(journalError);
    if (journal == nullptr) {
        error = journalError.empty()
            ? "Mutation journal недоступен: runtime paths не инициализированы"
            : journalError;
        return false;
    }
    return journal->discard(id, error);
}

} // namespace fic::rollback
