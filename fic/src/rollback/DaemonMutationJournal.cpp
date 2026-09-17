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
        if (journal_ == nullptr) {
            error = "Mutation journal не инициализирован";
            return nullptr;
        }
        if (journal_->usable()) {
            error.clear();
            return journal_.get();
        }
        // Lazy recovery (fail closed): the journal became unusable
        // (Indeterminate durability, not yet loaded). Retry through the
        // corrected load(), which requires the parsed snapshot to be
        // re-proved against the path AND the parent directory fsync to
        // succeed — a merely readable journal never restores Healthy.
        // Defensive re-check: the journal is handed out ONLY when it is
        // usable() after all recovery actions, never merely because
        // load() returned true.
        std::string reloadError;
        if (journal_->initializeOrLoad(reloadError) && journal_->usable() &&
            journal_->lifecycleInitialized()) {
            error.clear();
            return journal_.get();
        }
        error = "Mutation journal is Indeterminate; successful durable "
                "reload/recovery of persistent journal state is required";
        if (!reloadError.empty()) {
            error += ": " + reloadError;
        }
        return nullptr;
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
    // Witness-aware initialization: the ONLY operational initialization path
    // (state table journal/witness, including migration and provenance-loss
    // detection). The journal is handed out ONLY after a fully completed
    // witness-aware lifecycle (lifecycleInitialized()) AND a usable() state —
    // a raw journal load can never make an object operational here.
    if (!journal->initializeOrLoad(error) || !journal->usable() ||
        !journal->lifecycleInitialized()) {
        // Fail closed: a broken journal must not silently lose provenance,
        // and a journal that is not usable() after load must never become
        // the process-wide operational journal.
        if (error.empty()) {
            error = "Mutation journal is not usable after load";
        }
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
