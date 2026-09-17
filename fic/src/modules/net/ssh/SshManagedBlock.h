#ifndef SSHMANAGEDBLOCK_H
#define SSHMANAGEDBLOCK_H

#include <cstddef>
#include <string>
#include <vector>

// Explicit FIC ownership model of the main sshd_config.
//
// FIC no longer records reverse textual mutations of the user file. Instead
// everything FIC owns is expressed by explicit FIC markers inside the config
// itself:
//   - one top-level FIC managed block (global section, placed at the very
//     top so scalar first-obtained-value directives override user lines and
//     included files) containing one sub-block per policy;
//   - FIC_DISABLED wrapper blocks around user lines FIC had to disable
//     temporarily (multi-value directives such as Port).
//
// Rollback therefore removes / restores only explicitly owned state and
// never reconstructs historical user data.

// Semantics of an SSH directive with respect to multiple occurrences.
enum class SshDirectiveSemantics {
    ScalarFirstWins, // first obtained value wins; early FIC override is sufficient
    MultiValue,      // every occurrence is effective (Port); others must be disabled
    Unsupported      // no explicit classification: fail closed
};

// Explicit classification of the existing FIC SSH policies. A new SSH policy
// without an entry here is Unsupported and must never be applied.
SshDirectiveSemantics sshPolicyDirectiveSemantics(const std::string& policyName);

// Normalized sshd directive keyword of a known policy (empty when unknown).
std::string sshPolicyDirectiveKeyword(const std::string& policyName);

// FIC marker constants. A marker line starts exactly with one of these
// prefixes; arbitrary user comments are never treated as FIC markers. A line
// starting with the FIC marker introducer but not matching a known marker
// grammar is malformed and fails closed.
constexpr const char* kSshBlockBeginPrefix = "#@FIC_SSH_BLOCK_BEGIN ";
constexpr const char* kSshBlockEnd = "#@FIC_SSH_BLOCK_END@";
constexpr const char* kSshPolicyBeginPrefix = "#@FIC_POLICY_BEGIN ";
constexpr const char* kSshPolicyEndPrefix = "#@FIC_POLICY_END ";
constexpr const char* kSshDisabledBeginPrefix = "#@FIC_DISABLED_BEGIN ";
constexpr const char* kSshDisabledEndPrefix = "#@FIC_DISABLED_END ";
constexpr const char* kSshDisabledLinePrefix = "#@FIC_DISABLED_LINE@";
constexpr int kSshManagedBlockVersion = 1;
constexpr const char* kSshMarkerIntroducer = "#@FIC_";

struct SshManagedPolicyBlock {
    std::string name;          // policy name (name= field)
    std::string directiveLine; // the single directive line inside the block
    std::size_t beginLine = 0; // index of the POLICY_BEGIN marker
    std::size_t endLine = 0;   // index of the POLICY_END marker
};

struct SshDisabledBlock {
    std::string policy;        // policy= field
    std::string mutationId;    // mutation= field (stable provenance id)
    std::string originalLine;  // exact disabled line (after the LINE marker)
    std::size_t beginLine = 0; // index of the DISABLED_BEGIN marker
    std::size_t endLine = 0;   // index of the DISABLED_END marker
};

struct SshManagedModel {
    bool blockPresent = false;
    int version = 0;
    std::size_t blockBegin = 0; // index of BLOCK_BEGIN
    std::size_t blockEnd = 0;   // index of BLOCK_END
    std::vector<SshManagedPolicyBlock> policies;
    std::vector<SshDisabledBlock> disabled;
};

enum class SshManagedParseStatus {
    Ok,
    Malformed,         // duplicate, misplaced or unparsable FIC markers
    UnsupportedVersion // managed block version newer than supported
};

// Parses the FIC ownership model of a sshd_config line vector. Scans only
// the global section (up to the first Match directive); any FIC marker inside
// a Match section is malformed. Fail closed: duplicate managed blocks,
// mismatched markers, unknown fields, nested or dangling markers and
// sub-blocks with more than one directive line are Malformed.
SshManagedParseStatus parseSshManagedModel(const std::vector<std::string>& lines,
                                           SshManagedModel& model,
                                           std::string& error);

// The exact directive line FIC writes inside a policy sub-block.
std::string sshManagedDirectiveLine(const std::string& directive,
                                    const std::string& value);

// Inserts or updates the managed sub-block of the policy. Creates the
// top-level managed block at the very top of the file when absent.
// Idempotent: when the sub-block already carries exactly directiveLine,
// nothing changes.
bool upsertSshManagedPolicyBlock(std::vector<std::string>& lines,
                                 const std::string& policyName,
                                 const std::string& directiveLine,
                                 bool& changed,
                                 std::string& error);

// Removes the managed sub-block of the policy (and the whole managed block
// when it becomes empty). Ownership must be provable: the sub-block line
// must be exactly expectedDirectiveLine, otherwise nothing is changed and
// the function fails closed (a manually edited FIC block is a conflict).
bool removeSshManagedPolicyBlock(std::vector<std::string>& lines,
                                 const std::string& policyName,
                                 const std::string& expectedDirectiveLine,
                                 bool& removed,
                                 std::string& error);

// True when the parsed model contains a managed sub-block for the policy.
bool sshManagedModelHasPolicy(const SshManagedModel& model,
                              const std::string& policyName);

// True when the parsed model contains a FIC_DISABLED block of the policy.
bool sshManagedModelHasDisabledForPolicy(const SshManagedModel& model,
                                         const std::string& policyName);

// Wraps the line at index into a FIC_DISABLED block owned by the policy with
// the given stable mutation id. The original line is preserved byte-exact.
void disableSshLine(std::vector<std::string>& lines,
                    std::size_t index,
                    const std::string& policyName,
                    const std::string& mutationId);

// Restores the exact original lines of every FIC_DISABLED block of the
// policy whose mutation id is listed in allowedMutationIds (the journal
// payload is the provenance source) and removes the wrappers. Fails closed
// when a block of the policy has an id outside the allowed set or is
// structurally broken: FIC never uncomments a line it cannot prove it
// disabled itself.
bool restoreSshDisabledLines(std::vector<std::string>& lines,
                             const std::string& policyName,
                             const std::vector<std::string>& allowedMutationIds,
                             bool& changed,
                             std::string& error);

// Symmetric comparison of the FIC_DISABLED wrapper provenance of one policy:
// the wrapper mutation ids present in the parsed model and the ids recorded
// in the journal payload must coincide exactly (as sets, without duplicates
// on either side). FIC owns the wrappers only as a complete, exact set: a
// missing id (the owned representation partially disappeared), an unknown id
// (an unproven wrapper) or a duplicated id means the ownership cannot be
// proven and every consumer must fail closed.
struct SshDisabledProvenanceCheck {
    bool payloadMalformed = false;       // duplicate ids in the journal payload
    bool fileDuplicate = false;          // duplicate mutation id among the file wrappers
    std::vector<std::string> unknownIds; // in the file, absent from the payload
    std::vector<std::string> missingIds; // in the payload, absent from the file

    bool ok() const {
        return !payloadMalformed && !fileDuplicate && unknownIds.empty() &&
               missingIds.empty();
    }
};

SshDisabledProvenanceCheck checkSshDisabledProvenance(
    const SshManagedModel& model,
    const std::string& policyName,
    const std::vector<std::string>& expectedMutationIds);

// Human-readable description of a failed provenance check (for logs and
// apply/rollback error messages). Returns an empty string when check.ok().
std::string describeSshDisabledProvenance(
    const SshDisabledProvenanceCheck& check,
    const std::string& policyName);

// Generates a stable, unique disabled-block mutation id (provenance token
// stored in the journal payload and in the marker itself). The id is unique
// across process restarts within the same second: wall-clock time with
// nanosecond resolution, the process id and a per-process counter.
std::string generateSshDisabledMutationId(int ordinal);

#endif // SSHMANAGEDBLOCK_H