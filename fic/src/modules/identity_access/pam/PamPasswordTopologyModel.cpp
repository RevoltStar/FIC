#include "modules/identity_access/pam/PamPasswordTopologyModel.h"

namespace fic::identity::pam {

PamPasswordTopologyClassification classifyPamPasswordTopology(
    const PamPasswordTopology& topology) {
    PamPasswordTopologyClassification result;
    const PamPasswordSelections& selections = topology.selections;
    const bool producerPresent =
        topology.producer != PamPasswordProducerKind::None ||
        topology.foreignQualityProducer;

    // Hard conflicts first: they fail closed regardless of every other
    // field.
    if (selections.ficHistorySelected &&
        selections.ficHistoryInitialSelected) {
        result.detail =
            "ambiguous: both FIC history variants are selected "
            "(consumer and initial producer)";
        return result;
    }
    if (topology.foreignQualityProducer &&
        selections.ficHistoryInitialSelected) {
        result.detail =
            "ambiguous: a foreign quality producer coexists with the "
            "FIC history-initial producer selection";
        return result;
    }

    // Semantic fields must agree with the physical selections.
    if (topology.producer == PamPasswordProducerKind::FicQuality &&
        !selections.ficQualitySelected) {
        result.detail =
            "incoherent: FicQuality producer without the FIC quality "
            "profile selection";
        return result;
    }
    if (topology.producer == PamPasswordProducerKind::FicHistoryInitial &&
        !selections.ficHistoryInitialSelected) {
        result.detail =
            "incoherent: FicHistoryInitial producer without the FIC "
            "history-initial profile selection";
        return result;
    }
    if (topology.history == PamPasswordHistoryKind::FicConsumer &&
        !selections.ficHistorySelected) {
        result.detail =
            "incoherent: FicConsumer history without the FIC history "
            "profile selection";
        return result;
    }
    if (selections.ficQualitySelected &&
        topology.producer != PamPasswordProducerKind::FicQuality) {
        result.detail =
            "incoherent: the FIC quality profile is selected but the "
            "semantic producer is not FicQuality";
        return result;
    }
    if (selections.ficHistoryInitialSelected &&
        topology.producer != PamPasswordProducerKind::FicHistoryInitial) {
        result.detail =
            "incoherent: the FIC history-initial profile is selected but "
            "the semantic producer is not FicHistoryInitial";
        return result;
    }
    if (selections.ficHistorySelected &&
        topology.history != PamPasswordHistoryKind::FicConsumer) {
        result.detail =
            "incoherent: the FIC history profile is selected but the "
            "semantic history kind is not FicConsumer";
        return result;
    }
    if (topology.producer == PamPasswordProducerKind::None &&
        (selections.ficQualitySelected ||
         selections.ficHistoryInitialSelected ||
         topology.foreignQualityProducer)) {
        result.detail =
            "incoherent: no semantic producer while a producer selection "
            "or a foreign producer exists";
        return result;
    }

    // Consumer history requires an existing producer that is not the FIC
    // history-initial producer.
    if (topology.history == PamPasswordHistoryKind::FicConsumer) {
        if (!producerPresent ||
            topology.producer == PamPasswordProducerKind::FicHistoryInitial) {
            result.detail =
                "unsupported: FIC history consumer without an earlier "
                "token producer";
            return result;
        }
    }

    // Coherent state: pick the class.
    if (topology.producer == PamPasswordProducerKind::FicHistoryInitial) {
        result.topologyClass = PamPasswordTopologyClass::FicHistoryInitial;
        result.valid = true;
        result.detail = "FIC history-initial producer topology";
        return result;
    }
    if (topology.producer == PamPasswordProducerKind::FicQuality) {
        if (topology.foreignQualityProducer) {
            result.topologyClass =
                PamPasswordTopologyClass::ForeignQualityPlusFicQuality;
            result.valid = false;
            result.detail =
                "foreign quality producer coexists with the selected FIC "
                "quality profile (foreign-added-during-FIC state); not "
                "attach-safe, the ownership-aware disable path applies";
            return result;
        }
        result.topologyClass =
            topology.history == PamPasswordHistoryKind::FicConsumer
                ? PamPasswordTopologyClass::FicQualityPlusFicHistory
                : PamPasswordTopologyClass::FicQuality;
        result.valid = true;
        result.detail = "FIC quality producer topology";
        return result;
    }
    if (topology.foreignQualityProducer) {
        result.topologyClass =
            topology.history == PamPasswordHistoryKind::FicConsumer
                ? PamPasswordTopologyClass::ForeignQualityPlusFicHistory
                : PamPasswordTopologyClass::ForeignQuality;
        result.valid = true;
        result.detail = "foreign quality producer topology";
        return result;
    }

    result.topologyClass = PamPasswordTopologyClass::None;
    result.valid = true;
    result.detail = "no password producer and no FIC history enforcement";
    return result;
}

PamPasswordC2SafetyVerdict evaluatePamPasswordC2SelectionSafety(
    const PamPasswordSelections& selections,
    const PamPasswordC2SlotStates& slots,
    bool foreignQualityProducer) {
    PamPasswordC2SafetyVerdict verdict;

    // Hard conflict: both FIC history variants selected. pam-auth-update
    // would generate an ambiguous history stack with two different
    // semantic identities for the same capability.
    if (selections.ficHistorySelected &&
        selections.ficHistoryInitialSelected) {
        verdict.reason =
            "unsafe: both FIC history variants (consumer and initial "
            "producer) are selected";
        return verdict;
    }

    // Per-identity selection/slot agreement. A selected high-priority
    // profile occupies the provider position in the generated stack, so
    // its managed slot MUST carry the semantic module (Active); a
    // comment-only Neutral slot under a selected profile is exactly the
    // state the architecture gate disproved. An unselected profile must
    // NOT include anything, so its slot must be back in the canonical
    // Neutral state; an Active slot without its profile is an orphaned
    // FIC-owned state. Broken/Unavailable slots always fail closed
    // (package existence invariant).
    struct IdentityRule {
        const char* profileId;
        bool selected;
        ManagedPasswordSlotState slot;
        const char* slotName;
    };
    const IdentityRule rules[] = {
        {"fic-password-quality-hook", selections.ficQualitySelected,
         slots.quality, "quality"},
        {"fic-password-history-hook", selections.ficHistorySelected,
         slots.history, "history"},
        {"fic-password-history-initial-hook",
         selections.ficHistoryInitialSelected, slots.historyInitial,
         "history-initial"},
    };
    for (const IdentityRule& rule : rules) {
        if (rule.slot == ManagedPasswordSlotState::Unavailable) {
            verdict.reason = std::string("unsafe: managed ") +
                rule.slotName + " slot is missing while the package " +
                "existence invariant requires it";
            return verdict;
        }
        if (rule.slot == ManagedPasswordSlotState::Broken) {
            verdict.reason = std::string("unsafe: managed ") +
                rule.slotName + " slot is not canonical";
            return verdict;
        }
        if (rule.selected &&
            rule.slot != ManagedPasswordSlotState::Active) {
            verdict.reason = std::string("unsafe: ") + rule.profileId +
                " is selected while its managed slot is not Active "
                "(a selected profile would occupy the provider position "
                "without a semantic module)";
            return verdict;
        }
        if (!rule.selected &&
            rule.slot != ManagedPasswordSlotState::Neutral) {
            verdict.reason = std::string("unsafe: managed ") +
                rule.slotName + " slot is Active (orphaned FIC-owned "
                "state) while " + rule.profileId + " is not selected";
            return verdict;
        }
    }

    // History consumer requires an existing producer: either the FIC
    // quality profile with an Active slot, or the foreign stock quality
    // producer. The initial producer variant is already excluded by the
    // hard-conflict check above.
    if (selections.ficHistorySelected) {
        const bool ficQualityProducer =
            selections.ficQualitySelected &&
            slots.quality == ManagedPasswordSlotState::Active;
        if (!ficQualityProducer && !foreignQualityProducer) {
            verdict.reason =
                "unsafe: the FIC history consumer profile is selected "
                "but no token producer exists (Rule G)";
            return verdict;
        }
    }

    verdict.safe = true;
    verdict.reason = "C2 selection/slot state is structurally safe";
    return verdict;
}

} // namespace fic::identity::pam
