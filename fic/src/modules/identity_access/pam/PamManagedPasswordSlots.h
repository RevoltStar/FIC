#ifndef FIC_IDENTITY_ACCESS_PAM_MANAGED_PASSWORD_SLOTS_H
#define FIC_IDENTITY_ACCESS_PAM_MANAGED_PASSWORD_SLOTS_H

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace fic::identity::pam {

// Physical model of the three FIC-owned managed password slots
// (Step 1 design gate, docs/HANDOFF.md, decisions A/B/C):
//
//   /etc/pam.d/fic-password-quality           quality, enable_password_quality
//   /etc/pam.d/fic-password-history           history-normal, enable_password_history
//   /etc/pam.d/fic-password-history-initial   history-initial, enable_password_history
//
// This component is pure logic: it renders canonical slot bodies and
// strictly parses/inspects file contents. It never touches the
// filesystem and never mutates PAM state. Physical writing belongs to
// the later activation manager lifecycle (Step 3+).
//
// Key invariants enforced here:
//   - A missing slot file is Unavailable and is NEVER Neutral: PAM
//     treats a missing include target as a silent no-op, so physical
//     ownership requires the canonical file to exist (Step 1, r3).
//   - A file that exists but does not exactly match the canonical
//     neutral bytes or the canonical active grammar is Broken. PAM
//     semantic equivalence is not FIC physical ownership.
//   - history-normal requires use_authtok exactly once; history-initial
//     forbids use_authtok. The existing
//     PamPwhistoryArguments::evaluate() contract for the authoritative
//     legacy rule is unchanged.
enum class ManagedPasswordSlotRole {
    Quality,
    HistoryNormal,
    HistoryInitial
};

enum class ManagedPasswordCapability {
    PasswordQuality,
    PasswordHistory
};

enum class ManagedPasswordSlotState {
    // File exists and matches the exact canonical neutral bytes.
    Neutral,
    // File exists and matches the exact canonical active grammar.
    Active,
    // File exists but is not canonical (empty, modified, malformed
    // marker, unknown arguments, ...).
    Broken,
    // File (or input) is missing. Never neutral.
    Unavailable
};


// FIC-managed module arguments of a canonical active pwhistory slot.
// The option values are physical fields parsed from the slot body; the
// semantic effectiveness of the resulting enforcement (for example
// remember=0) is verified at a higher layer (Step 4+).
struct ManagedPwhistorySlotOptions {
    std::optional<unsigned> remember;
    bool enforceForRoot = false;

    bool operator==(const ManagedPwhistorySlotOptions& other) const {
        return remember == other.remember &&
            enforceForRoot == other.enforceForRoot;
    }
};

struct ManagedPasswordSlotInspection {
    ManagedPasswordSlotState state = ManagedPasswordSlotState::Broken;
    ManagedPasswordSlotRole role = ManagedPasswordSlotRole::Quality;
    ManagedPasswordSlotRole observedRole = ManagedPasswordSlotRole::Quality;
    ManagedPasswordCapability capability =
        ManagedPasswordCapability::PasswordQuality;
    // Non-zero only when state == Active.
    std::uint64_t mutationId = 0;
    // Present only for Active history slots.
    std::optional<ManagedPwhistorySlotOptions> pwhistoryOptions;
    // Human-readable failure diagnostic for Broken/Unavailable.
    std::string error;
};

// Pair-level inspection of the two history slots. The pair is the unit
// of consistency: mixed states, divergent options or divergent mutation
// ids are Broken, never a partially enabled topology.
enum class ManagedHistoryPairState {
    Neutral,
    Active,
    Broken
};

struct ManagedHistoryPairInspection {
    ManagedHistoryPairState state = ManagedHistoryPairState::Broken;
    std::uint64_t mutationId = 0;
    std::optional<ManagedPwhistorySlotOptions> options;
    std::string error;
};

struct ManagedPasswordSlotSpec {
    ManagedPasswordSlotRole role;
    // File name inside the PAM configuration directory (not a full path).
    const char* fileName;
    ManagedPasswordCapability capability;
};

class PamManagedPasswordSlots {
public:
    PamManagedPasswordSlots() = delete;

    static const ManagedPasswordSlotSpec& qualitySlot();
    static const ManagedPasswordSlotSpec& historyNormalSlot();
    static const ManagedPasswordSlotSpec& historyInitialSlot();
    static const std::vector<ManagedPasswordSlotSpec>& slots();

    static std::string capabilityName(ManagedPasswordCapability capability);
    static std::string slotName(ManagedPasswordSlotRole role);
    static std::filesystem::path slotFilePath(
        const ManagedPasswordSlotSpec& spec,
        const std::filesystem::path& configDirectory =
            std::filesystem::path("/etc/pam.d"));

    // Exact canonical neutral bytes for every managed password slot:
    // one comment line plus a trailing newline, no PAM rules.
    static std::string neutralBody();
    static std::string renderNeutral(const ManagedPasswordSlotSpec& spec);

    // Canonical active bodies. Quality keeps the current FIC legacy
    // provider rule; options belong to /etc/security/pwquality.conf and
    // are never encoded in the slot. Pwhistory options are FIC-managed
    // module arguments (Debian 12 argument mode); on config-file
    // platforms the bodies simply carry no optional arguments. Option
    // values are rendered in one canonical order.
    //
    // Fail-safe contract (Step 2 hardening): a canonical renderer must
    // never successfully return non-canonical active slot bytes. A
    // mutation id of 0 (or any other id the strict parser would reject)
    // makes the renderer fail with no active bytes produced. On success
    // the rendered bytes are guaranteed to inspect as Active by
    // inspectContent(); the caller never needs to re-inspect its own
    // render to detect invalid input.
    static bool renderActiveQuality(
        std::uint64_t mutationId,
        std::string& content,
        std::string& error);
    static bool renderActiveHistoryNormal(
        std::uint64_t mutationId,
        const ManagedPwhistorySlotOptions& options,
        std::string& content,
        std::string& error);
    static bool renderActiveHistoryInitial(
        std::uint64_t mutationId,
        const ManagedPwhistorySlotOptions& options,
        std::string& content,
        std::string& error);
    static bool renderActive(
        const ManagedPasswordSlotSpec& spec,
        std::uint64_t mutationId,
        const ManagedPwhistorySlotOptions& options,
        std::string& content,
        std::string& error);

    // Strict inspection of slot content. content == nullopt means the
    // slot file does not exist (Unavailable, never Neutral). content is
    // the exact file bytes. On failure inspection.state is Broken (or
    // Unavailable) and error carries a diagnostic.
    static bool inspectContent(
        const ManagedPasswordSlotSpec& spec,
        const std::optional<std::string>& content,
        ManagedPasswordSlotInspection& inspection,
        std::string& error);

    // Pair-level consistency of the two history slots. The pair API is
    // type-safe on its own: before any state comparison it requires the
    // first inspection to carry the exact history-normal identity
    // (role, observed role and PasswordHistory capability) and the
    // second to carry the exact history-initial identity, in every
    // state (Neutral, Active, Broken, Unavailable). Valid outcomes:
    // both Neutral, or both Active with the same mutation id, the same
    // logical remember/enforce_for_root values and the role-specific
    // use_authtok invariant. Everything else (wrong identity, mixed
    // states, divergent ids/options, missing or malformed files) is
    // Broken; per-slot inspections expose Unavailable explicitly.
    static bool inspectHistoryPair(
        const ManagedPasswordSlotInspection& normal,
        const ManagedPasswordSlotInspection& initial,
        ManagedHistoryPairInspection& pair,
        std::string& error);
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_MANAGED_PASSWORD_SLOTS_H
