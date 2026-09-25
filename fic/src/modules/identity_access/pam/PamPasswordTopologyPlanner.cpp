#include "modules/identity_access/pam/PamPasswordTopologyPlanner.h"

namespace fic::identity::pam {

namespace {

const char* planActionProfileId(PamPasswordPlanActionKind kind) {
    switch (kind) {
        case PamPasswordPlanActionKind::AttachFicQuality:
        case PamPasswordPlanActionKind::DetachFicQuality:
            return kFicPasswordQualityHookProfileId;
        case PamPasswordPlanActionKind::AttachFicHistoryInitial:
        case PamPasswordPlanActionKind::DetachFicHistoryInitial:
            return kFicPasswordHistoryInitialHookProfileId;
        case PamPasswordPlanActionKind::AttachFicHistoryConsumer:
        case PamPasswordPlanActionKind::DetachFicHistoryConsumer:
            return kFicPasswordHistoryHookProfileId;
    }
    return kFicPasswordQualityHookProfileId;
}

// Per-identity view of one FIC password activation identifier.
struct IdentityPlanInput {
    const char* profileId;
    bool selected;
    bool owned;
    bool desired;
    PamPasswordPlanActionKind attach;
    PamPasswordPlanActionKind detach;
};

} // namespace

const char* PamPasswordPlanAction::profileId() const {
    return planActionProfileId(kind);
}

PamPasswordTopologyPlan planPamPasswordTopology(
    const PamPasswordTopology& current,
    bool qualityRequested,
    bool historyRequested,
    const PamPasswordOwnership& ownership) {
    PamPasswordTopologyPlan plan;
    const PamPasswordSelections& selections = current.selections;

    // P12: conflicting FIC history variants can never be planned around;
    // fail closed.
    if (selections.ficHistorySelected &&
        selections.ficHistoryInitialSelected) {
        plan.error =
            "ambiguous current topology: both FIC history variants "
            "(consumer and initial producer) are selected";
        return plan;
    }

    // Desired FIC selection state (§ planner rules). The foreign quality
    // producer satisfies the quality capability: FIC never adds a second
    // quality producer and never removes the foreign one.
    const bool foreignProducer = current.foreignQualityProducer;
    plan.wantFicQuality = qualityRequested && !foreignProducer;
    const bool desiredProducerExists =
        foreignProducer || plan.wantFicQuality;
    plan.wantFicHistoryConsumer = historyRequested && desiredProducerExists;
    plan.wantFicHistoryInitial = historyRequested && !desiredProducerExists;

    const IdentityPlanInput identities[] = {
        {kFicPasswordQualityHookProfileId,
         selections.ficQualitySelected, ownership.ficQualityOwned,
         plan.wantFicQuality,
         PamPasswordPlanActionKind::AttachFicQuality,
         PamPasswordPlanActionKind::DetachFicQuality},
        {kFicPasswordHistoryHookProfileId,
         selections.ficHistorySelected, ownership.ficHistoryOwned,
         plan.wantFicHistoryConsumer,
         PamPasswordPlanActionKind::AttachFicHistoryConsumer,
         PamPasswordPlanActionKind::DetachFicHistoryConsumer},
        {kFicPasswordHistoryInitialHookProfileId,
         selections.ficHistoryInitialSelected,
         ownership.ficHistoryInitialOwned, plan.wantFicHistoryInitial,
         PamPasswordPlanActionKind::AttachFicHistoryInitial,
         PamPasswordPlanActionKind::DetachFicHistoryInitial},
    };

    for (const IdentityPlanInput& identity : identities) {
        if (identity.selected && !identity.owned) {
            if (identity.desired) {
                // Physically selected but unproven: the desired state is
                // already satisfied physically, but the executor must
                // resolve the missing provenance before any mutation.
                plan.unownedSelectionsPreserved.push_back(
                    identity.profileId);
            } else {
                plan.error = std::string("refusing to plan the detach of ") +
                    identity.profileId +
                    ": the profile is selected but not FIC-owned by "
                    "journal provenance (ownership-aware disable)";
                return plan;
            }
        }
        if (!identity.selected && identity.owned) {
            plan.error = std::string("incoherent current topology: ") +
                identity.profileId +
                " is FIC-owned by journal provenance but not selected";
            return plan;
        }
    }

    // Ordered actions. Detaches run first: a history variant is always
    // detached before the producer it consumes disappears (Quality+History
    // -> History-only must not remove the producer while the consumer is
    // still selected). Attaches run after all detaches, producers before
    // consumers (History-only -> Quality+History must attach the quality
    // producer before the use_authtok consumer).
    const PamPasswordPlanActionKind detachOrder[] = {
        PamPasswordPlanActionKind::DetachFicHistoryConsumer,
        PamPasswordPlanActionKind::DetachFicHistoryInitial,
        PamPasswordPlanActionKind::DetachFicQuality,
    };
    for (const PamPasswordPlanActionKind kind : detachOrder) {
        for (const IdentityPlanInput& identity : identities) {
            if (identity.detach == kind && identity.selected &&
                identity.owned && !identity.desired) {
                plan.actions.push_back({kind});
            }
        }
    }
    const PamPasswordPlanActionKind attachOrder[] = {
        PamPasswordPlanActionKind::AttachFicQuality,
        PamPasswordPlanActionKind::AttachFicHistoryInitial,
        PamPasswordPlanActionKind::AttachFicHistoryConsumer,
    };
    for (const PamPasswordPlanActionKind kind : attachOrder) {
        for (const IdentityPlanInput& identity : identities) {
            if (identity.attach == kind && !identity.selected &&
                identity.desired) {
                plan.actions.push_back({kind});
            }
        }
    }

    plan.success = true;
    return plan;
}

} // namespace fic::identity::pam
