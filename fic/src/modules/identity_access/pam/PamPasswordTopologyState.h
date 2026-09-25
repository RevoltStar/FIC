#ifndef FIC_IDENTITY_ACCESS_PAM_PASSWORD_TOPOLOGY_STATE_H
#define FIC_IDENTITY_ACCESS_PAM_PASSWORD_TOPOLOGY_STATE_H

#include "modules/identity_access/pam/PamManagedPasswordSlots.h"
#include "modules/identity_access/pam/PamPasswordTopologyModel.h"

#include <rollback/MutationJournal.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>

namespace fic::identity::pam {

// Production read-only inspection and three-profile resulting-state proof
// for the C2 (activation-time FIC-owned password hooks) topology.
//
// This component builds ONE typed snapshot of the physical password
// topology:
//
//   - the FIC profile selections observed in the pam-auth-update password
//     state database (exact "Module: <id>" records);
//   - the three managed slot states (canonical grammar of
//     PamManagedPasswordSlots);
//   - the generated stack evidence of common-password (include lines of
//     the three managed slots, the stock pam_unix position, and direct
//     pam_pwquality.so rules) with TRAILING-WHITESPACE-TOLERANT line
//     grammar — the real pam-auth-update generation appends trailing
//     whitespace to include lines, so anchored "$" proofs never converge;
//   - the foreign (stock distro pwquality) producer discovery, Rule I
//     style: the stock profile selection and a direct pam_pwquality.so
//     rule in the generated stack must AGREE (XOR = Rule I violation);
//   - the FIC journal ownership per identity (physical selection is
//     deliberately distinct from ownership: a canonical Active slot is
//     owned only when its marker id matches an Applied journal record
//     whose payload carries the identity-specific activation identifier —
//     the exact payload contract of PamManagedPasswordSlotWriter);
//   - the semantic PamPasswordTopology, its classification and the C2
//     selection/slot safety verdict.
//
// The snapshot assembly NEVER mutates the filesystem, the journal or
// pam-auth-update state; mutation belongs exclusively to the C2 transition
// executor.

// Sentinel position for stack elements absent from the generated stack.
constexpr std::size_t kPamPasswordStackAbsent =
    static_cast<std::size_t>(-1);

// Stock distro pwquality profile identifier (libpam-pwquality
// /usr/share/pam-configs/pwquality on Debian 12 / Ubuntu 24.04).
constexpr const char* kStockPwqualityProfileId = "pwquality";

struct PamPasswordGeneratedStackEvidence {
    // Include lines of the managed slots in the generated stack.
    bool qualityInclude = false;
    bool historyInclude = false;
    bool historyInitialInclude = false;
    // Line positions of the include lines (absent sentinel when missing).
    std::size_t qualityIncludePosition = kPamPasswordStackAbsent;
    std::size_t historyIncludePosition = kPamPasswordStackAbsent;
    std::size_t historyInitialIncludePosition = kPamPasswordStackAbsent;
    // First stock pam_unix.so password rule position.
    std::size_t pamUnixPosition = kPamPasswordStackAbsent;
    // A DIRECT pam_pwquality.so password rule (a module line, not the FIC
    // quality slot include): this is how a foreign/stock pwquality
    // producer appears in the generated stack.
    bool foreignPwqualityDirectRule = false;
    std::size_t foreignPwqualityPosition = kPamPasswordStackAbsent;
};

struct PamPasswordTopologySnapshot {
    // Exact FIC profile selections from the state database.
    PamPasswordSelections selections;
    // Managed slot states and marker ids.
    ManagedPasswordSlotState qualitySlotState =
        ManagedPasswordSlotState::Broken;
    ManagedPasswordSlotState historySlotState =
        ManagedPasswordSlotState::Broken;
    ManagedPasswordSlotState historyInitialSlotState =
        ManagedPasswordSlotState::Broken;
    std::uint64_t qualitySlotMutationId = 0;
    std::uint64_t historySlotMutationId = 0;
    std::uint64_t historyInitialSlotMutationId = 0;
    // Generated stack evidence.
    PamPasswordGeneratedStackEvidence generated;
    // Foreign producer discovery (Rule I).
    bool foreignPwqualityProfileSelected = false;
    bool foreignQualityProducer = false;
    // Journal-bound FIC ownership per identity (physical selection is NOT
    // ownership).
    PamPasswordOwnership ownership;
    // Semantic model + classification + C2 structural safety.
    PamPasswordTopology topology;
    PamPasswordTopologyClassification classification;
    PamPasswordC2SafetyVerdict safety;
    // Coherence diagnostic of the raw inspection (empty when coherent).
    std::string coherenceError;
};

struct PamPasswordStateInspectionOptions {
    // pam-auth-update profile selection state directory. Empty means the
    // platform default (/var/lib/pam).
    std::filesystem::path stateDirectory;
    // Directory with the generated common-* files and the managed slot
    // files. Empty means the platform default (/etc/pam.d).
    std::filesystem::path configDirectory;
    // Password state file name; empty means "password".
    std::string passwordStateFileName;
    // Generated password stack file name; empty means "common-password".
    std::string generatedPasswordStackFile;
};

// Builds the typed snapshot. Returns false only when the inspection could
// not be performed (unreadable state/slot files, an unprovable persistent
// journal state); a semantically broken topology is a SUCCESSFUL
// inspection with classification.valid == false (fail closed at the
// decision layer, never a silent guess).
bool inspectPamPasswordTopology(
    const PamPasswordStateInspectionOptions& options,
    fic::rollback::MutationJournal& journal,
    PamPasswordTopologySnapshot& snapshot, std::string& error);

// Three-profile resulting-state proof of a snapshot: for every selected
// identity — exact generated include, expected effective ordering
// (producer include < history consumer include < pam_unix; for
// history-only: history-initial include < pam_unix; for quality-only:
// quality include < pam_unix; foreign producer rule < history consumer
// include), exact absence of the unselected identities' includes and the
// consumer/initial mutual exclusion. Trailing whitespace in generated
// lines is tolerated. Returns false with a diagnostic when the semantic
// proof fails.
bool provePamPasswordTopologySemantics(
    const PamPasswordTopologySnapshot& snapshot, std::string& error);

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PASSWORD_TOPOLOGY_STATE_H
