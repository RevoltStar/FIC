#ifndef FIC_IDENTITY_ACCESS_PAM_PASSWORD_TOPOLOGY_MODEL_H
#define FIC_IDENTITY_ACCESS_PAM_PASSWORD_TOPOLOGY_MODEL_H

#include "modules/identity_access/pam/PamManagedPasswordSlots.h"

#include <string>

namespace fic::identity::pam {

// C2 (activation-time FIC-owned password hooks) semantic topology model.
//
// The rejected Step 5C design (permanently selected, permanently attached
// high-priority comment-only neutral hooks, disproved by the architecture
// gate and replaced by the owner-run v7 experiments) is intentionally NOT
// modeled here. Under C2 the package owns the profile DEFINITIONS and the
// managed slot files, while the runtime policy decides which FIC-owned
// activation profiles are selected; pam-auth-update exclusively owns the
// generated common-password stack.
//
// v7 evidence baseline (docs/HANDOFF.md, Debian 12 + Ubuntu 24.04):
//   - a password stack needs exactly one token producer before the first
//     use_authtok consumer; the producer may be FIC quality, FIC history
//     initial (history without use_authtok IS a producer) or the foreign
//     stock pwquality profile;
//   - "history requires quality" is WRONG; "history requires a token
//     producer, otherwise history itself is the producer" is the rule;
//   - a pre-existing or later-appearing foreign stock pwquality producer
//     satisfies the quality capability: FIC must never add a second
//     quality producer and must never claim or remove the foreign one.
//
// This component is pure logic: it only classifies typed states and never
// touches the filesystem, the journal or pam-auth-update. Mutation
// (attaching/detaching profiles, writing slots, journal records,
// compensation) belongs to the later C2 runtime transition executor.

// FIC-owned activation profile identifiers (package payload, all
// "Default: no"; the package never selects them itself).
constexpr const char* kFicPasswordQualityHookProfileId =
    "fic-password-quality-hook";
constexpr const char* kFicPasswordHistoryHookProfileId =
    "fic-password-history-hook";
constexpr const char* kFicPasswordHistoryInitialHookProfileId =
    "fic-password-history-initial-hook";

// Activation profile priorities (pam-auth-update sorts Primary password
// profiles by descending priority; the stock Debian/Ubuntu `unix` profile
// has priority 256). Verified ordering evidence (v7):
//   quality producer (1024) < history consumer (1023) < pam_unix (256),
// where `<` means earlier in the generated stack.
constexpr int kFicPasswordQualityHookPriority = 1024;
constexpr int kFicPasswordHistoryHookPriority = 1023;
// The initial-producer profile is never co-selected with the consumer
// profile (planner/validator fail closed on that state), so its exact
// value inside (256, 1023) carries no ordering requirement beyond the
// producer position before pam_unix; 1022 is the deterministic choice.
constexpr int kFicPasswordHistoryInitialHookPriority = 1022;
constexpr int kStockUnixPasswordPriority = 256;

// Semantic kind of the token producer the topology relies on.
enum class PamPasswordProducerKind {
    // No producer in the Primary password stack.
    None,
    // The FIC quality profile is selected and its slot provides the
    // pam_pwquality.so producer.
    FicQuality,
    // The FIC history-initial profile is selected and its slot provides
    // the pam_pwhistory.so producer (no use_authtok).
    FicHistoryInitial,
    // A foreign (stock distro) pwquality profile provides the producer.
    ForeignQuality,
};

// Semantic kind of the FIC history enforcement.
enum class PamPasswordHistoryKind {
    None,
    // The FIC history consumer profile is selected; its slot requires
    // use_authtok and therefore an earlier producer.
    FicConsumer,
};

// Physical FIC selection state observed in the pam-auth-update password
// state database. Physical selection is deliberately distinct from FIC
// ownership (PamPasswordOwnership): an administrator may select a
// FIC-owned profile manually, and a foreign producer may appear while FIC
// profiles are selected.
struct PamPasswordSelections {
    bool ficQualitySelected = false;
    bool ficHistorySelected = false;
    bool ficHistoryInitialSelected = false;

    bool operator==(const PamPasswordSelections& other) const {
        return ficQualitySelected == other.ficQualitySelected &&
            ficHistorySelected == other.ficHistorySelected &&
            ficHistoryInitialSelected == other.ficHistoryInitialSelected;
    }
    bool operator!=(const PamPasswordSelections& other) const {
        return !(*this == other);
    }
};

// FIC-owned-by-provenance state (journal-bound): which FIC password
// mutations FIC can PROVE it owns and is therefore allowed to detach.
// Ownership never follows physical selection automatically.
//
// The *Prepared flags mark crash-leftover compensation bindings: the
// identity's slot is canonical Active with a marker id that matches a
// valid Prepared journal record of the canonical domain carrying the
// role-specific activation identifier. A Prepared binding is NEVER
// ownership: it only identifies the exact-id crash-partial state the
// production compensation primitive is allowed to neutralize (package
// release recovery; runtime recovery belongs to the activation matrix).
struct PamPasswordOwnership {
    bool ficQualityOwned = false;
    bool ficHistoryOwned = false;
    bool ficHistoryInitialOwned = false;
    bool ficQualityPrepared = false;
    bool ficHistoryPrepared = false;
    bool ficHistoryInitialPrepared = false;

    bool operator==(const PamPasswordOwnership& other) const {
        return ficQualityOwned == other.ficQualityOwned &&
            ficHistoryOwned == other.ficHistoryOwned &&
            ficHistoryInitialOwned == other.ficHistoryInitialOwned &&
            ficQualityPrepared == other.ficQualityPrepared &&
            ficHistoryPrepared == other.ficHistoryPrepared &&
            ficHistoryInitialPrepared == other.ficHistoryInitialPrepared;
    }
};

// Full semantic topology state. The semantic kinds and the physical
// selections are represented independently on purpose: states like
// "foreign quality producer + FIC quality selected" (a foreign profile
// added while FIC was active) must stay distinguishable instead of being
// collapsed into a boolean "quality present".
struct PamPasswordTopology {
    PamPasswordProducerKind producer = PamPasswordProducerKind::None;
    PamPasswordHistoryKind history = PamPasswordHistoryKind::None;
    // FIC selections physically present.
    PamPasswordSelections selections;
    // Foreign producer/capability discovered independently (stock distro
    // pwquality provider in the effective Primary password stack).
    bool foreignQualityProducer = false;
};

// Coarse classification of a topology. Every state from the accepted C2
// state model is distinguishable; malformed/ambiguous states are NEVER
// silently represented as valid.
enum class PamPasswordTopologyClass {
    None,
    FicQuality,
    FicHistoryInitial,
    FicQualityPlusFicHistory,
    ForeignQuality,
    ForeignQualityPlusFicHistory,
    // A foreign stock quality profile appeared while the FIC quality
    // profile is still selected (foreign-added-during-FIC state). Not an
    // attach-safe state; the ownership-aware disable path removes ONLY the
    // FIC-owned selection and preserves the foreign one.
    ForeignQualityPlusFicQuality,
    // Conflicting or incoherent state (e.g. both FIC history variants
    // selected, semantic fields contradicting the selections). Fails
    // closed everywhere.
    Ambiguous,
};

struct PamPasswordTopologyClassification {
    PamPasswordTopologyClass topologyClass =
        PamPasswordTopologyClass::Ambiguous;
    // true only when the topology is semantically coherent and attach-safe
    // at the model level. false = ambiguous/unsupported; fail closed.
    bool valid = false;
    std::string detail;
};

// Classifies a topology state. Structural coherence rules:
//   - both FIC history variants selected  -> Ambiguous;
//   - foreign producer + FIC history-initial selected -> Ambiguous
//     (two producers, one of them FIC-owned initial; fail closed);
//   - semantic kinds must agree with the physical selections;
//   - the consumer history kind requires an existing producer that is not
//     the FIC history-initial producer.
PamPasswordTopologyClassification classifyPamPasswordTopology(
    const PamPasswordTopology& topology);

// Slot states of the three managed password slots for the C2 selection
// safety evaluation.
struct PamPasswordC2SlotStates {
    ManagedPasswordSlotState quality = ManagedPasswordSlotState::Broken;
    ManagedPasswordSlotState history = ManagedPasswordSlotState::Broken;
    ManagedPasswordSlotState historyInitial =
        ManagedPasswordSlotState::Broken;
};

// Structural C2 safety verdict of a selection/slot combination
// (validator redesign groundwork, C2 rules):
//   - FIC quality profile selected -> quality slot must be Active
//     (Neutral + selected is UNSAFE: the high-priority selected profile
//     would occupy the provider position without any semantic module);
//   - FIC history-initial profile selected -> initial slot must be Active
//     AND the consumer history profile must not be selected;
//   - FIC history consumer profile selected -> history slot must be Active
//     AND a producer must exist (FIC quality with an Active slot, or the
//     foreign stock quality producer);
//   - no FIC profile selected -> every managed slot must be Neutral
//     (comment-only Neutral bytes are safe ONLY while the corresponding
//     activation profile is unselected; an Active slot without its
//     profile is an orphaned FIC-owned state and fails closed);
//   - Broken and Unavailable slots always fail closed (package existence
//     invariant).
// Journal provenance of Active FIC slots (MatchingApplied, exact mutation
// ids) is NOT checked here; it stays the responsibility of the read-only
// attach validator layered on top of this classification.
struct PamPasswordC2SafetyVerdict {
    bool safe = false;
    std::string reason;
};

PamPasswordC2SafetyVerdict evaluatePamPasswordC2SelectionSafety(
    const PamPasswordSelections& selections,
    const PamPasswordC2SlotStates& slots,
    bool foreignQualityProducer);

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PASSWORD_TOPOLOGY_MODEL_H