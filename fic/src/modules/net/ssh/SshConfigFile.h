#ifndef SSHCONFIGFILE_H
#define SSHCONFIGFILE_H

#include "rollback/MutationRecord.h"

#include <fic/core/fs/FileHandler.h>

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

// In-memory plan of the exact textual mutation setValue() performs. Built
// BEFORE the file is written so the rollback journal can record the reverse
// delta first. Occurrence line indices are in-memory helpers for the
// immediate in-process apply; the persisted journal payload carries only the
// semantic occurrence information (see MutationRecord.h).
struct SshDirectiveMutationPlan {
    std::string parameter;          // normalized parameter
    std::string canonicalParameter; // keyword used for the written line
    std::string appliedValue;       // value FIC applies
    std::vector<fic::rollback::SshDirectiveOccurrenceMutation> occurrences;
    // File line index of each occurrence in the loaded representation,
    // parallel to occurrences; used only for the in-memory setValue() apply.
    std::vector<std::size_t> occurrenceLineIndices;
};

// Mutation-local state of the current global section against one recorded
// SSH directive mutation.
enum class SshMutationState {
    After,    // every recorded occurrence is in its FIC after-state
    Before,   // every recorded occurrence is in its pre-FIC before-state
    Conflict  // mixed, ambiguous or drifted state
};

class SshConfigFileHandler : public FileHandler {
public:
    explicit SshConfigFileHandler(const std::string& filepath);

    bool loadConfig() override;
    std::string getValue(const std::string& parameter) const override;
    bool setValue(const std::string& parameter, const std::string& value) override;
    void printConfig() const override;
    bool isParameterExists(const std::string& parameter) const;

    // Builds the exact mutation setValue() would perform without mutating
    // anything: the recorded occurrences (before/after representations) of
    // every changed global-section directive.
    bool planSetValue(const std::string& parameter,
                      const std::string& value,
                      SshDirectiveMutationPlan& plan) const;

    // Classifies the current global section against a recorded mutation
    // (mutation-local BEFORE/AFTER matching). When the result is After,
    // afterLineIndices receives the current file line index of every
    // recorded occurrence (parallel to undo.occurrences).
    SshMutationState classifyRecordedMutation(
        const fic::rollback::UndoRestoreSshDirective& undo,
        std::vector<std::size_t>& afterLineIndices,
        std::string& error) const;

    // Applies recorded reverse edits by the indices produced by
    // classifyRecordedMutation(). Fails closed when a target line no longer
    // matches the recorded after-state.
    bool applyRecordedReverseEdits(
        const fic::rollback::UndoRestoreSshDirective& undo,
        const std::vector<std::size_t>& afterLineIndices,
        std::string& error);

private:
    bool findFirstMatchLine(std::size_t& line) const;
    std::size_t countExactLines(const std::string& text,
                                std::size_t globalEnd) const;
    std::size_t countParameterDirectives(const std::string& normalizedParameter,
                                         std::size_t globalEnd,
                                         bool& parseError) const;

    std::unordered_map<std::string, std::string> config_;
    std::unordered_map<std::string, std::string> canonicalNames_;
};

#endif // SSHCONFIGFILE_H
