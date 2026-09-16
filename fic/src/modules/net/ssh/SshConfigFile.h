#ifndef SSHCONFIGFILE_H
#define SSHCONFIGFILE_H

#include "rollback/MutationRecord.h"

#include <fic/core/fs/FileHandler.h>

#include <cstddef>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
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

    // Classifies the current global section against a recorded mutation by
    // comparing the whole ordered mutation-local projection of the target
    // resource against the recorded BEFORE and AFTER sequences (never by
    // absolute line indices, never by per-occurrence independent counting).
    // Identical line texts and before/after collisions across occurrences
    // are handled naturally by the sequence comparison. When the result is
    // After, afterLineIndices receives the current file line index of every
    // recorded occurrence (parallel to undo.occurrences).
    SshMutationState classifyRecordedMutation(
        const fic::rollback::UndoRestoreSshDirective& undo,
        std::vector<std::size_t>& afterLineIndices,
        std::string& error) const;

    // Repeated-apply matcher: maps the current target-resource projection
    // onto the slots of an already recorded mutation. A slot is repairable
    // when it is already in the recorded AFTER state or when it is an active
    // directive of the same keyword in a slot FIC owns (beforeLine exists);
    // the repair rewrites it to the recorded AFTER representation while the
    // journal keeps the original BEFORE baseline. Any untracked target
    // occurrence (structural drift) fails closed: nothing may be mutated
    // without undo provenance. A single inserted occurrence is repairable
    // when the keyword is completely absent (the re-insertion is exactly the
    // recorded mutation). On success slotLineIndices holds the current file
    // line index per occurrence (nullopt = re-insert at the end of the
    // global section) and needsWrite tells whether any slot must be
    // rewritten.
    bool matchRecordedMutationForRepair(
        const fic::rollback::UndoRestoreSshDirective& undo,
        std::vector<std::optional<std::size_t>>& slotLineIndices,
        bool& needsWrite,
        std::string& error) const;

    // Applies the repair edits produced by matchRecordedMutationForRepair().
    bool applyRecordedRepairEdits(
        const fic::rollback::UndoRestoreSshDirective& undo,
        const std::vector<std::optional<std::size_t>>& slotLineIndices,
        std::string& error);

    // Applies recorded reverse edits by the indices produced by
    // classifyRecordedMutation(). Fails closed when a target line no longer
    // matches the recorded after-state.
    bool applyRecordedReverseEdits(
        const fic::rollback::UndoRestoreSshDirective& undo,
        const std::vector<std::size_t>& afterLineIndices,
        std::string& error);

private:
    bool findFirstMatchLine(std::size_t& line) const;
    // Mutation-local projection of the target resource: every global-section
    // line that is an active directive of the target keyword or exactly
    // matches a recorded BEFORE/AFTER line, in file order, paired with its
    // file line index.
    bool buildTargetProjection(
        const std::string& normalizedParameter,
        const std::vector<std::string>& recordedLines,
        std::vector<std::pair<std::size_t, std::string>>& projection,
        std::string& error) const;

    std::unordered_map<std::string, std::string> config_;
    std::unordered_map<std::string, std::string> canonicalNames_;
};

#endif // SSHCONFIGFILE_H
