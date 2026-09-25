// Pure C2 password topology model tests: typed semantic classification
// (all accepted C2 states + ambiguity fail-closed) and the structural
// selection/slot safety evaluation (selected+Neutral = unsafe).
#include "modules/identity_access/pam/PamPasswordTopologyModel.h"

#include <iostream>
#include <stdexcept>
#include <string>

using fic::identity::pam::ManagedPasswordSlotState;
using fic::identity::pam::PamPasswordC2SlotStates;
using fic::identity::pam::PamPasswordHistoryKind;
using fic::identity::pam::PamPasswordProducerKind;
using fic::identity::pam::PamPasswordSelections;
using fic::identity::pam::PamPasswordTopology;
using fic::identity::pam::PamPasswordTopologyClass;
using fic::identity::pam::classifyPamPasswordTopology;
using fic::identity::pam::evaluatePamPasswordC2SelectionSafety;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

PamPasswordTopology makeTopology(PamPasswordProducerKind producer,
                                 PamPasswordHistoryKind history,
                                 PamPasswordSelections selections,
                                 bool foreignProducer) {
    PamPasswordTopology topology;
    topology.producer = producer;
    topology.history = history;
    topology.selections = selections;
    topology.foreignQualityProducer = foreignProducer;
    return topology;
}

void runClassificationTests() {
    // None.
    {
        auto result = classifyPamPasswordTopology(
            makeTopology(PamPasswordProducerKind::None,
                         PamPasswordHistoryKind::None, {}, false));
        require(result.valid && result.topologyClass ==
                                    PamPasswordTopologyClass::None,
                "None topology must classify valid None");
    }
    // FicQuality.
    {
        PamPasswordSelections selections;
        selections.ficQualitySelected = true;
        auto result = classifyPamPasswordTopology(
            makeTopology(PamPasswordProducerKind::FicQuality,
                         PamPasswordHistoryKind::None, selections, false));
        require(result.valid && result.topologyClass ==
                                    PamPasswordTopologyClass::FicQuality,
                "FicQuality topology must classify valid");
    }
    // FicHistoryInitial (history-only IS a valid producer topology).
    {
        PamPasswordSelections selections;
        selections.ficHistoryInitialSelected = true;
        auto result = classifyPamPasswordTopology(makeTopology(
            PamPasswordProducerKind::FicHistoryInitial,
            PamPasswordHistoryKind::None, selections, false));
        require(result.valid &&
                    result.topologyClass ==
                        PamPasswordTopologyClass::FicHistoryInitial,
                "history-only initial producer must be a valid topology");
    }
    // FicQuality + FicHistory.
    {
        PamPasswordSelections selections;
        selections.ficQualitySelected = true;
        selections.ficHistorySelected = true;
        auto result = classifyPamPasswordTopology(makeTopology(
            PamPasswordProducerKind::FicQuality,
            PamPasswordHistoryKind::FicConsumer, selections, false));
        require(result.valid &&
                    result.topologyClass ==
                        PamPasswordTopologyClass::FicQualityPlusFicHistory,
                "FicQuality+FicHistory must classify valid");
    }
    // ForeignQuality.
    {
        auto result = classifyPamPasswordTopology(makeTopology(
            PamPasswordProducerKind::ForeignQuality,
            PamPasswordHistoryKind::None, {}, true));
        require(result.valid && result.topologyClass ==
                                    PamPasswordTopologyClass::ForeignQuality,
                "ForeignQuality must classify valid");
    }
    // ForeignQuality + FicHistory.
    {
        PamPasswordSelections selections;
        selections.ficHistorySelected = true;
        auto result = classifyPamPasswordTopology(makeTopology(
            PamPasswordProducerKind::ForeignQuality,
            PamPasswordHistoryKind::FicConsumer, selections, true));
        require(result.valid &&
                    result.topologyClass ==
                        PamPasswordTopologyClass::
                            ForeignQualityPlusFicHistory,
                "ForeignQuality+FicHistory must classify valid");
    }
    // ForeignQuality + FicQuality (foreign added during FIC):
    // distinguishable and NOT valid.
    {
        PamPasswordSelections selections;
        selections.ficQualitySelected = true;
        auto result = classifyPamPasswordTopology(makeTopology(
            PamPasswordProducerKind::FicQuality,
            PamPasswordHistoryKind::None, selections, true));
        require(!result.valid && result.topologyClass ==
                                     PamPasswordTopologyClass::
                                         ForeignQualityPlusFicQuality,
                "foreign+FIC quality must be distinguishable and invalid");
    }
    // Both history variants -> Ambiguous, fail closed.
    {
        PamPasswordSelections selections;
        selections.ficHistorySelected = true;
        selections.ficHistoryInitialSelected = true;
        auto result = classifyPamPasswordTopology(makeTopology(
            PamPasswordProducerKind::FicHistoryInitial,
            PamPasswordHistoryKind::FicConsumer, selections, false));
        require(!result.valid && result.topologyClass ==
                                     PamPasswordTopologyClass::Ambiguous,
                "both history variants must fail closed");
    }
    // Foreign producer + FIC history-initial -> Ambiguous.
    {
        PamPasswordSelections selections;
        selections.ficHistoryInitialSelected = true;
        auto result = classifyPamPasswordTopology(makeTopology(
            PamPasswordProducerKind::FicHistoryInitial,
            PamPasswordHistoryKind::None, selections, true));
        require(!result.valid && result.topologyClass ==
                                     PamPasswordTopologyClass::Ambiguous,
                "foreign producer + initial producer must fail closed");
    }
    // Semantic/selection incoherence -> Ambiguous.
    {
        PamPasswordSelections selections;
        selections.ficQualitySelected = true;
        auto result = classifyPamPasswordTopology(
            makeTopology(PamPasswordProducerKind::None,
                         PamPasswordHistoryKind::None, selections, false));
        require(!result.valid,
                "quality selected without producer semantics must fail "
                "closed");
    }
    // Consumer without any producer -> unsupported.
    {
        PamPasswordSelections selections;
        selections.ficHistorySelected = true;
        auto result = classifyPamPasswordTopology(
            makeTopology(PamPasswordProducerKind::None,
                         PamPasswordHistoryKind::FicConsumer, selections,
                         false));
        require(!result.valid,
                "consumer without producer must fail closed");
    }
}

void runSafetyTests() {
    // No selection: all Neutral slots -> safe (C2 allows comment-only
    // Neutral while the profile is unselected).
    {
        PamPasswordC2SlotStates slots;
        slots.quality = ManagedPasswordSlotState::Neutral;
        slots.history = ManagedPasswordSlotState::Neutral;
        slots.historyInitial = ManagedPasswordSlotState::Neutral;
        auto verdict =
            evaluatePamPasswordC2SelectionSafety({}, slots, false);
        require(verdict.safe, "unselected + Neutral must be safe");
        // Foreign producer only is equally safe.
        verdict = evaluatePamPasswordC2SelectionSafety({}, slots, true);
        require(verdict.safe, "foreign-only + Neutral slots must be safe");
    }
    // No selection + Active slot -> orphaned FIC-owned state, unsafe.
    {
        PamPasswordC2SlotStates slots;
        slots.quality = ManagedPasswordSlotState::Active;
        slots.history = ManagedPasswordSlotState::Neutral;
        slots.historyInitial = ManagedPasswordSlotState::Neutral;
        auto verdict =
            evaluatePamPasswordC2SelectionSafety({}, slots, false);
        require(!verdict.safe, "orphaned Active slot must be unsafe");
    }
    // Selected quality + Neutral quality slot -> UNSAFE (the disproved
    // permanent-neutral state).
    {
        PamPasswordSelections selections;
        selections.ficQualitySelected = true;
        PamPasswordC2SlotStates slots;
        slots.quality = ManagedPasswordSlotState::Neutral;
        slots.history = ManagedPasswordSlotState::Neutral;
        slots.historyInitial = ManagedPasswordSlotState::Neutral;
        auto verdict = evaluatePamPasswordC2SelectionSafety(selections,
                                                            slots, false);
        require(!verdict.safe,
                "selected+Neutral quality must be unsafe");
        // Active quality slot makes it structurally safe again.
        slots.quality = ManagedPasswordSlotState::Active;
        verdict = evaluatePamPasswordC2SelectionSafety(selections, slots,
                                                       false);
        require(verdict.safe, "selected+Active quality must be safe");
    }
    // History-initial selected: initial slot Active + consumer NOT
    // selected -> safe.
    {
        PamPasswordSelections selections;
        selections.ficHistoryInitialSelected = true;
        PamPasswordC2SlotStates slots;
        slots.quality = ManagedPasswordSlotState::Neutral;
        slots.history = ManagedPasswordSlotState::Neutral;
        slots.historyInitial = ManagedPasswordSlotState::Active;
        auto verdict = evaluatePamPasswordC2SelectionSafety(selections,
                                                            slots, false);
        require(verdict.safe,
                "history-initial selected + Active slot must be safe");
    }
    // Both history variants selected -> unsafe.
    {
        PamPasswordSelections selections;
        selections.ficHistorySelected = true;
        selections.ficHistoryInitialSelected = true;
        PamPasswordC2SlotStates slots;
        slots.quality = ManagedPasswordSlotState::Neutral;
        slots.history = ManagedPasswordSlotState::Active;
        slots.historyInitial = ManagedPasswordSlotState::Active;
        auto verdict = evaluatePamPasswordC2SelectionSafety(selections,
                                                            slots, false);
        require(!verdict.safe, "both history variants must be unsafe");
    }
    // History consumer selected without any producer -> unsafe; with the
    // foreign producer -> safe.
    {
        PamPasswordSelections selections;
        selections.ficHistorySelected = true;
        PamPasswordC2SlotStates slots;
        slots.quality = ManagedPasswordSlotState::Neutral;
        slots.history = ManagedPasswordSlotState::Active;
        slots.historyInitial = ManagedPasswordSlotState::Neutral;
        auto verdict = evaluatePamPasswordC2SelectionSafety(selections,
                                                            slots, false);
        require(!verdict.safe, "consumer without producer must be unsafe");
        verdict = evaluatePamPasswordC2SelectionSafety(selections, slots,
                                                       true);
        require(verdict.safe, "consumer with foreign producer must be safe");
    }
    // Consumer selected with FIC quality producer (both Active) -> safe;
    // with a Neutral quality slot -> unsafe (Rule G).
    {
        PamPasswordSelections selections;
        selections.ficQualitySelected = true;
        selections.ficHistorySelected = true;
        PamPasswordC2SlotStates slots;
        slots.quality = ManagedPasswordSlotState::Active;
        slots.history = ManagedPasswordSlotState::Active;
        slots.historyInitial = ManagedPasswordSlotState::Neutral;
        auto verdict = evaluatePamPasswordC2SelectionSafety(selections,
                                                            slots, false);
        require(verdict.safe, "quality+consumer both Active must be safe");
        slots.quality = ManagedPasswordSlotState::Neutral;
        verdict = evaluatePamPasswordC2SelectionSafety(selections, slots,
                                                       false);
        require(!verdict.safe,
                "consumer with Neutral FIC quality slot must be unsafe");
    }
    // Broken and Unavailable slots always fail closed.
    {
        PamPasswordSelections selections;
        selections.ficQualitySelected = true;
        PamPasswordC2SlotStates slots;
        slots.quality = ManagedPasswordSlotState::Active;
        slots.history = ManagedPasswordSlotState::Broken;
        slots.historyInitial = ManagedPasswordSlotState::Neutral;
        auto verdict = evaluatePamPasswordC2SelectionSafety(selections,
                                                            slots, false);
        require(!verdict.safe, "Broken slot must be unsafe");
        slots.history = ManagedPasswordSlotState::Unavailable;
        verdict = evaluatePamPasswordC2SelectionSafety(selections, slots,
                                                       false);
        require(!verdict.safe, "Unavailable slot must be unsafe");
    }
}

} // namespace

int main() {
    try {
        runClassificationTests();
        runSafetyTests();
    } catch (const std::exception& error) {
        std::cerr << "FAILED: " << error.what() << std::endl;
        return 1;
    }
    std::cout << "pam_password_topology_model_tests: all passed"
              << std::endl;
    return 0;
}
