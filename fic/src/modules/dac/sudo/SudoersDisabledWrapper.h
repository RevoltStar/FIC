#ifndef FIC_SUDOERSDISABLEDWRAPPER_H
#define FIC_SUDOERSDISABLEDWRAPPER_H

#include <cstddef>
#include <string>
#include <vector>

// Explicit FIC ownership model for TEMPORARILY DISABLED foreign sudoers
// entries. This is the SUDO backend counterpart of the SSH FIC_DISABLED
// wrappers, with its OWN marker namespace (`#@FIC_SUDO_DISABLED_*`): SSH and
// sudoers are different grammars with different backend semantics, so sharing
// the marker strings themselves would couple two unrelated ownership models.
//
// FIC does not record reverse textual mutations of foreign sudoers content.
// Instead, an offending foreign entry is COMMENTED OUT inside explicit FIC
// markers that live in the foreign file itself:
//
//   #@FIC_SUDO_DISABLED_BEGIN policy=<name> mutation=<id>@
//   #@FIC_SUDO_DISABLED_LINE@<original physical line, byte-exact>
//   #@FIC_SUDO_DISABLED_END policy=<name> mutation=<id>@
//
// The original bytes live inside the wrapper (never in the journal), so
// rollback restores exactly what FIC found without any historical snapshot,
// while the journal payload only PROVES PERMISSION to unwrap specific ids.
namespace fic::sudoers {

constexpr const char* kSudoDisabledBeginPrefix = "#@FIC_SUDO_DISABLED_BEGIN ";
constexpr const char* kSudoDisabledEndPrefix = "#@FIC_SUDO_DISABLED_END ";
constexpr const char* kSudoDisabledLinePrefix = "#@FIC_SUDO_DISABLED_LINE@";
// A line starting with this introducer but not matching the grammar below is
// malformed: FIC never guesses whether a similar comment is its own.
constexpr const char* kSudoMarkerIntroducer = "#@FIC_SUDO_";

struct SudoDisabledWrapper {
    std::string policy;     // policy= field
    std::string mutationId; // mutation= field (stable provenance id)
    // Exact original physical lines, in order (a logical entry may span
    // several physical lines).
    std::vector<std::string> originalLines;
    std::size_t beginLine = 0; // index of the BEGIN marker
    std::size_t endLine = 0;   // index of the END marker
};

enum class SudoWrapperParseStatus {
    Ok,
    Malformed // duplicate, nested, misplaced or unparsable FIC markers
};

// Parses the FIC wrapper markers of one sudoers file's physical lines.
SudoWrapperParseStatus parseSudoDisabledWrappers(
    const std::vector<std::string>& lines,
    std::vector<SudoDisabledWrapper>& wrappers,
    std::string& error);

// Replaces the physical lines [firstLine, firstLine + lineCount) with a FIC
// wrapper that preserves the original lines byte-exact. Idempotency and
// marker-parsing failures are the caller's precondition.
void disableSudoEntry(std::vector<std::string>& lines,
                      std::size_t firstLine,
                      std::size_t lineCount,
                      const std::string& policyName,
                      const std::string& mutationId);

// Ownership-release provenance check (subset semantics, same contract as the
// SSH model): every wrapper of the policy that STILL EXISTS must be proven by
// the journal payload; payload ids whose wrappers already disappeared are an
// externally released subset and never an error.
struct SudoWrapperProvenanceCheck {
    bool payloadMalformed = false;  // duplicate ids in the journal payload
    bool fileDuplicate = false;     // duplicate mutation id among file wrappers
    std::vector<std::string> unknownIds;   // actual ids absent from the payload
    std::vector<std::string> releasedIds;  // payload ids already gone (info)

    bool safeToRelease() const {
        return !payloadMalformed && !fileDuplicate && unknownIds.empty();
    }
};

SudoWrapperProvenanceCheck checkSudoWrapperProvenance(
    const std::vector<SudoDisabledWrapper>& wrappers,
    const std::string& policyName,
    const std::vector<std::string>& expectedMutationIds);

// Human-readable description of a failed provenance check; empty when
// check.safeToRelease().
std::string describeSudoWrapperProvenance(
    const SudoWrapperProvenanceCheck& check,
    const std::string& policyName);

// Restores the exact original lines of every wrapper of the policy whose id is
// in allowedMutationIds and removes the wrappers. Fails closed when a wrapper
// id is outside the allowed set or the markers are structurally broken: FIC
// never uncomments a line it cannot prove it disabled itself.
bool restoreSudoDisabledEntries(std::vector<std::string>& lines,
                                const std::string& policyName,
                                const std::vector<std::string>& allowedMutationIds,
                                bool& changed,
                                std::string& error);

// Stable, unique wrapper mutation id: wall-clock time with nanosecond
// resolution, the process id and a per-process counter. Unique across rapid
// daemon restarts within the same second.
std::string generateSudoWrapperMutationId(int ordinal);

} // namespace fic::sudoers

#endif // FIC_SUDOERSDISABLEDWRAPPER_H
