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

// One physical sudoers line together with its ORIGINAL line terminator.
// Keeping the terminator is what makes the byte-exact contract real for CRLF
// sudoers: stripping it and re-emitting "\n" would silently rewrite every line
// of a foreign file.
struct SudoPhysicalLine {
    // Line content WITHOUT the terminator.
    std::string text;
    // The terminator that followed this line in the original bytes: "\n",
    // "\r\n", or empty for a final line without a terminator.
    std::string terminator;
};

// Splits raw file bytes into physical lines that REMEMBER their original
// terminator. Never rewrites "\r\n" into "\n".
std::vector<SudoPhysicalLine> splitPhysicalLines(const std::string& content);

// Re-serializes physical lines, preserving every original terminator.
std::string joinPhysicalLines(const std::vector<SudoPhysicalLine>& lines);

// Canonical exact byte sequence of a suppressed entry: the concatenation of
// every physical line's content plus its original terminator. This is the
// byte-exact contract FIC suppresses and must restore, and the only thing the
// journal fingerprints.
std::string suppressedEntryBytes(const std::vector<SudoPhysicalLine>& lines);

struct SudoDisabledWrapper {
    std::string policy;     // policy= field
    std::string mutationId; // mutation= field (stable provenance id)
    // Exact original physical lines, in order (a logical entry may span
    // several physical lines), terminators included.
    std::vector<SudoPhysicalLine> originalLines;
    std::size_t beginLine = 0; // index of the BEGIN marker
    std::size_t endLine = 0;   // index of the END marker

    // Stable digest of the CURRENT suppressed payload. Compared against the
    // journal proof before unwrapping: a mismatch means the body changed after
    // FIC wrapped it, and FIC must never activate content it does not own.
    std::string payloadDigest() const;
};

enum class SudoWrapperParseStatus {
    Ok,
    Malformed // duplicate, nested, misplaced or unparsable FIC markers
};

// One wrapper proof as persisted in the mutation journal: it names the wrapper
// FIC created AND fingerprints the exact bytes FIC suppressed, so unwrapping
// can be proven to release exactly FIC-owned content and nothing else. The
// suppressed bytes themselves stay inside the wrapper; this is NOT a backup.
struct SudoScopedDefaultsWrapperProof {
    std::string wrapperId;
    std::string payloadDigest;

    bool operator==(const SudoScopedDefaultsWrapperProof& other) const {
        return wrapperId == other.wrapperId &&
            payloadDigest == other.payloadDigest;
    }
};

// Canonical wrapper id syntax produced by generateSudoWrapperMutationId():
// "FIC-SUDO-<digits>-<digits>-<digits>-<digits>-<digits>". Persisted proofs are
// validated against it so a malformed or hand-written id is never treated as
// proven provenance.
bool isCanonicalSudoWrapperId(const std::string& wrapperId);

// Parses the FIC wrapper markers of one sudoers file's physical lines.
SudoWrapperParseStatus parseSudoDisabledWrappers(
    const std::vector<SudoPhysicalLine>& lines,
    std::vector<SudoDisabledWrapper>& wrappers,
    std::string& error);

// Replaces the physical lines [firstLine, firstLine + lineCount) with a FIC
// wrapper that preserves the original bytes exactly.
void disableSudoEntry(std::vector<SudoPhysicalLine>& lines,
                      std::size_t firstLine,
                      std::size_t lineCount,
                      const std::string& policyName,
                      const std::string& mutationId);

// Ownership-release provenance check (subset semantics, same contract as the
// SSH model) extended with PAYLOAD PROOF:
//   * every wrapper of the policy that STILL EXISTS must be proven by the
//     journal payload, by id AND by payload digest;
//   * payload entries whose wrappers already disappeared are an externally
//     released subset and never an error;
//   * a proven id whose CURRENT payload digest differs from the recorded one is
//     DRIFT: FIC must not unwrap content it did not suppress.
struct SudoWrapperProvenanceCheck {
    bool payloadMalformed = false; // duplicate ids in the journal payload
    bool fileDuplicate = false;    // duplicate mutation id among file wrappers
    std::vector<std::string> unknownIds;  // actual ids absent from the payload
    std::vector<std::string> releasedIds; // payload ids already gone (info)
    // Proven ids whose current suppressed payload no longer matches the
    // recorded digest. Never safe to release.
    std::vector<std::string> driftedIds;

    bool safeToRelease() const {
        return !payloadMalformed && !fileDuplicate && unknownIds.empty() &&
            driftedIds.empty();
    }
};

SudoWrapperProvenanceCheck checkSudoWrapperProvenance(
    const std::vector<SudoDisabledWrapper>& wrappers,
    const std::string& policyName,
    const std::vector<SudoScopedDefaultsWrapperProof>& expectedProofs);

// Human-readable description of a failed provenance check; empty when
// check.safeToRelease().
std::string describeSudoWrapperProvenance(
    const SudoWrapperProvenanceCheck& check,
    const std::string& policyName);

// Restores the exact original bytes of every wrapper of the policy whose id is
// in allowedProofs and removes the wrappers. The proofs are re-verified FIRST,
// so drift is refused with zero writes.
bool restoreSudoDisabledEntries(
    std::vector<SudoPhysicalLine>& lines,
    const std::string& policyName,
    const std::vector<SudoScopedDefaultsWrapperProof>& allowedProofs,
    bool& changed,
    std::string& error);

// Stable, unique wrapper mutation id: wall-clock time with nanosecond
// resolution, the process id and a per-process counter. Unique across rapid
// daemon restarts within the same second.
std::string generateSudoWrapperMutationId(int ordinal);

} // namespace fic::sudoers

#endif // FIC_SUDOERSDISABLEDWRAPPER_H
