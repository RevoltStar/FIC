#ifndef FIC_ROLLBACK_MUTATION_JOURNAL_H
#define FIC_ROLLBACK_MUTATION_JOURNAL_H

#include "rollback/MutationRecord.h"

#include <filesystem>
#include <string>
#include <vector>

namespace fic::rollback {

// Persistent JSON journal of executed FIC mutations.
//
// Reliability contract:
//   * every update rewrites the whole document atomically (temp file + rename);
//   * the document carries a schema_version and is rejected (fail closed) on
//     unknown schema versions, unknown enum values or structurally broken
//     content;
//   * a missing file is an empty journal; a malformed file is a load error and
//     callers must refuse rollback rather than guess.
class MutationJournal {
public:
    static constexpr std::uint32_t kSchemaVersion = 1;

    explicit MutationJournal(std::filesystem::path path);

    // Loads the journal from disk. Must be called before mutations.
    bool load(std::string& error);
    bool loaded() const { return loaded_; }

    const std::vector<MutationRecord>& records() const { return records_; }

    // Inserts a new Prepared record, or updates an existing active record for
    // the same (policy, backend, resource) triple. Returns the record id.
    bool prepareMutation(MutationRecord record, MutationId& id, std::string& error);
    bool setStatus(MutationId id, MutationStatus status, std::string& error);
    bool setStatusWithMessage(MutationId id, MutationStatus status,
                              const std::string& message, std::string& error);
    bool discard(MutationId id, std::string& error);

    std::vector<MutationRecord> activeRecords(const PolicyRef& policy) const;

private:
    bool persist(std::string& error);
    MutationRecord* find(MutationId id);

    std::filesystem::path path_;
    std::vector<MutationRecord> records_;
    MutationId nextId_ = 1;
    bool loaded_ = false;
};

} // namespace fic::rollback

#endif // FIC_ROLLBACK_MUTATION_JOURNAL_H