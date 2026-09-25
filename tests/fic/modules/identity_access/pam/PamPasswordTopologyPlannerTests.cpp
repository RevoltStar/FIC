// Pure C2 password topology planner tests (P1-P12 matrix): desired-state
// derivation, ordered transition actions with history-variant switching,
// foreign-producer awareness and ownership-aware disable.
#include "modules/identity_access/pam/PamPasswordTopologyPlanner.h"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using fic::identity::pam::PamPasswordHistoryKind;
using fic::identity::pam::PamPasswordOwnership;
using fic::identity::pam::PamPasswordPlanActionKind;
using fic::identity::pam::PamPasswordProducerKind;
using fic::identity::pam::PamPasswordTopology;
using fic::identity::pam::PamPasswordTopologyPlan;
using fic::identity::pam::planPamPasswordTopology;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::vector<PamPasswordPlanActionKind> actionKinds(
    const PamPasswordTopologyPlan& plan) {
    std::vector<PamPasswordPlanActionKind> kinds;
    for (const auto& action : plan.actions) {
        kinds.push_back(action.kind);
    }
    return kinds;
}

void requireDesired(const PamPasswordTopologyPlan& plan, bool quality,
                    bool initial, bool consumer,
                    const std::string& context) {
    require(plan.success, context + ": plan must succeed");
    require(plan.wantFicQuality == quality,
            context + ": wantFicQuality mismatch");
    require(plan.wantFicHistoryInitial == initial,
            context + ": wantFicHistoryInitial mismatch");
    require(plan.wantFicHistoryConsumer == consumer,
            context + ": wantFicHistoryConsumer mismatch");
}

PamPasswordTopology topology(bool qualitySelected, bool historySelected,
                             bool historyInitialSelected,
                             bool foreignProducer) {
    PamPasswordTopology topology;
    topology.selections.ficQualitySelected = qualitySelected;
    topology.selections.ficHistorySelected = historySelected;
    topology.selections.ficHistoryInitialSelected = historyInitialSelected;
    topology.foreignQualityProducer = foreignProducer;
    topology.producer =
        qualitySelected
            ? PamPasswordProducerKind::FicQuality
            : (historyInitialSelected
                   ? PamPasswordProducerKind::FicHistoryInitial
                   : (foreignProducer
                          ? PamPasswordProducerKind::ForeignQuality
                          : PamPasswordProducerKind::None));
    topology.history =
        historySelected ? PamPasswordHistoryKind::FicConsumer
                        : PamPasswordHistoryKind::None;
    return topology;
}

void runMatrix() {
    const PamPasswordOwnership noOwnership;

    // P1: none + Q0/H0 -> no FIC selections, no actions.
    {
        auto plan = planPamPasswordTopology(
            topology(false, false, false, false), false, false,
            noOwnership);
        requireDesired(plan, false, false, false, "P1");
        require(plan.actions.empty(), "P1: no actions expected");
    }
    // P2: none + Q1/H0 -> FIC quality.
    {
        auto plan = planPamPasswordTopology(
            topology(false, false, false, false), true, false,
            noOwnership);
        requireDesired(plan, true, false, false, "P2");
        require(actionKinds(plan) ==
                    std::vector<PamPasswordPlanActionKind>{
                        PamPasswordPlanActionKind::AttachFicQuality},
                "P2: single AttachFicQuality expected");
    }
    // P3: none + Q0/H1 -> FIC history-initial (producer), NOT consumer.
    {
        auto plan = planPamPasswordTopology(
            topology(false, false, false, false), false, true,
            noOwnership);
        requireDesired(plan, false, true, false, "P3");
        require(actionKinds(plan) ==
                    std::vector<PamPasswordPlanActionKind>{
                        PamPasswordPlanActionKind::
                            AttachFicHistoryInitial},
                "P3: single AttachFicHistoryInitial expected");
    }
    // P4: none + Q1/H1 -> FIC quality + FIC history consumer (producer
    // attaches before the consumer).
    {
        auto plan = planPamPasswordTopology(
            topology(false, false, false, false), true, true,
            noOwnership);
        requireDesired(plan, true, false, true, "P4");
        require(actionKinds(plan) ==
                    std::vector<PamPasswordPlanActionKind>{
                        PamPasswordPlanActionKind::AttachFicQuality,
                        PamPasswordPlanActionKind::
                            AttachFicHistoryConsumer},
                "P4: ordered quality-then-consumer attach expected");
    }
    // P5: foreignQ + Q1/H0 -> no FIC quality; foreign untouched.
    {
        auto plan = planPamPasswordTopology(
            topology(false, false, false, true), true, false,
            noOwnership);
        requireDesired(plan, false, false, false, "P5");
        require(plan.actions.empty(), "P5: no actions expected");
    }
    // P6: foreignQ + Q1/H1 -> FIC history consumer only.
    {
        auto plan = planPamPasswordTopology(
            topology(false, false, false, true), true, true,
            noOwnership);
        requireDesired(plan, false, false, true, "P6");
        require(actionKinds(plan) ==
                    std::vector<PamPasswordPlanActionKind>{
                        PamPasswordPlanActionKind::
                            AttachFicHistoryConsumer},
                "P6: single AttachFicHistoryConsumer expected");
    }
    // P7: foreignQ + Q0/H1 -> FIC history consumer only.
    {
        auto plan = planPamPasswordTopology(
            topology(false, false, false, true), false, true,
            noOwnership);
        requireDesired(plan, false, false, true, "P7");
        require(actionKinds(plan) ==
                    std::vector<PamPasswordPlanActionKind>{
                        PamPasswordPlanActionKind::
                            AttachFicHistoryConsumer},
                "P7: single AttachFicHistoryConsumer expected");
    }

    // P8: FIC quality owned + foreignQ appeared + Q disabled ->
    // remove ONLY FIC quality, preserve foreign.
    {
        auto plan = planPamPasswordTopology(
            topology(true, false, false, true), false, false,
            PamPasswordOwnership{true, false, false});
        requireDesired(plan, false, false, false, "P8");
        require(actionKinds(plan) ==
                    std::vector<PamPasswordPlanActionKind>{
                        PamPasswordPlanActionKind::DetachFicQuality},
                "P8: single DetachFicQuality expected");
    }
    // P9: FIC quality + FIC history, H disabled -> preserve quality,
    // remove history.
    {
        auto plan = planPamPasswordTopology(topology(true, true, false,
                                                     false),
                                            true, false,
                                            PamPasswordOwnership{true, true,
                                                                 false});
        requireDesired(plan, true, false, false, "P9");
        require(actionKinds(plan) ==
                    std::vector<PamPasswordPlanActionKind>{
                        PamPasswordPlanActionKind::
                            DetachFicHistoryConsumer},
                "P9: single DetachFicHistoryConsumer expected");
    }
    // P10: FIC quality + FIC history -> Q disabled / H enabled: switch
    // the history variant consumer -> initial producer, remove quality.
    {
        auto plan = planPamPasswordTopology(topology(true, true, false,
                                                     false),
                                            false, true,
                                            PamPasswordOwnership{true, true,
                                                                 false});
        requireDesired(plan, false, true, false, "P10");
        // The consumer must be detached BEFORE its producer; the initial
        // producer attaches last.
        require(actionKinds(plan) ==
                    std::vector<PamPasswordPlanActionKind>{
                        PamPasswordPlanActionKind::
                            DetachFicHistoryConsumer,
                        PamPasswordPlanActionKind::DetachFicQuality,
                        PamPasswordPlanActionKind::
                            AttachFicHistoryInitial},
                "P10: consumer-detach -> quality-detach -> "
                "initial-attach expected");
    }
    // P11: history-initial -> Q enabled / H enabled: switch to quality
    // producer + history consumer; the initial profile must go away.
    {
        auto plan = planPamPasswordTopology(topology(false, false, true,
                                                     false),
                                            true, true,
                                            PamPasswordOwnership{false,
                                                                 false,
                                                                 true});
        requireDesired(plan, true, false, true, "P11");
        require(actionKinds(plan) ==
                    std::vector<PamPasswordPlanActionKind>{
                        PamPasswordPlanActionKind::
                            DetachFicHistoryInitial,
                        PamPasswordPlanActionKind::AttachFicQuality,
                        PamPasswordPlanActionKind::
                            AttachFicHistoryConsumer},
                "P11: initial-detach -> quality-attach -> "
                "consumer-attach expected");
    }
    // P12: ambiguous conflicting FIC history variants -> fail closed.
    {
        auto plan = planPamPasswordTopology(topology(false, true, true,
                                                     false),
                                            true, true, noOwnership);
        require(!plan.success, "P12: planning must fail closed");
        require(!plan.error.empty(), "P12: error diagnostic expected");
        require(plan.actions.empty(), "P12: no actions on failure");
    }

    // Ownership-aware disable: quality selected but NOT owned + Q0 ->
    // refuse to detach (removal must not be based on capability
    // satisfaction).
    {
        auto plan = planPamPasswordTopology(topology(true, false, false,
                                                     false),
                                            false, false, noOwnership);
        require(!plan.success,
                "unowned selected quality must not be detachable");
        require(!plan.error.empty(), "unowned detach: error expected");
    }
    // Stale ownership: owned but not selected -> fail closed.
    {
        auto plan = planPamPasswordTopology(
            topology(false, false, false, false), true, false,
            PamPasswordOwnership{true, false, false});
        require(!plan.success, "stale ownership must fail closed");
    }
    // Unowned-but-kept selection is reported to the executor, not
    // silently accepted.
    {
        auto plan = planPamPasswordTopology(topology(true, false, false,
                                                     false),
                                            true, false, noOwnership);
        require(plan.success, "kept unowned selection plans fine");
        require(plan.actions.empty(),
                "kept unowned selection: no actions");
        require(plan.unownedSelectionsPreserved.size() == 1 &&
                    plan.unownedSelectionsPreserved[0] ==
                        std::string("fic-password-quality-hook"),
                "kept unowned selection must be reported");
    }
    // Foreign producer appears during FIC history-only: H stays enabled,
    // the owned initial producer switches to the consumer variant.
    {
        auto plan = planPamPasswordTopology(topology(false, false, true,
                                                     true),
                                            false, true,
                                            PamPasswordOwnership{false,
                                                                 false,
                                                                 true});
        requireDesired(plan, false, false, true, "foreign-during-H");
        require(actionKinds(plan) ==
                    std::vector<PamPasswordPlanActionKind>{
                        PamPasswordPlanActionKind::
                            DetachFicHistoryInitial,
                        PamPasswordPlanActionKind::
                            AttachFicHistoryConsumer},
                "foreign-during-H: initial-detach -> consumer-attach");
    }
    // Disable-all from Quality+History: consumer detached before the
    // producer.
    {
        auto plan = planPamPasswordTopology(topology(true, true, false,
                                                     false),
                                            false, false,
                                            PamPasswordOwnership{true, true,
                                                                 false});
        requireDesired(plan, false, false, false, "disable-all");
        require(actionKinds(plan) ==
                    std::vector<PamPasswordPlanActionKind>{
                        PamPasswordPlanActionKind::
                            DetachFicHistoryConsumer,
                        PamPasswordPlanActionKind::DetachFicQuality},
                "disable-all: consumer-detach before quality-detach");
    }
}

} // namespace

int main() {
    try {
        runMatrix();
    } catch (const std::exception& error) {
        std::cerr << "FAILED: " << error.what() << std::endl;
        return 1;
    }
    std::cout << "pam_password_topology_planner_tests: all passed"
              << std::endl;
    return 0;
}
