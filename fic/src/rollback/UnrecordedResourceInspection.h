#pragma once
#include "rollback/RollbackExecutor.h"
#include "rollback/MutationJournal.h"
namespace fic::rollback {
enum class UnrecordedResourceState { Continue, ProvenEmpty, UnprovenOwnership, Error };
enum class ResourceInspectionPhase { PolicyDisable, UninstallFinal };
struct ReleasedResourceInspection {
    std::string domain;
    UnrecordedResourceState state;
    std::string detail;
};
// Read-only proof over the backend's ownership scope, not provider compliance.
// Never adopts artifacts or resolves journal entries. Active domain ownership
// always returns Continue and must go through the existing strict backend.
UnrecordedResourceState inspectUnrecordedResource(const PolicyRef&,
    const RollbackExecutorDeps&,MutationJournal&,std::string& error,
    ResourceInspectionPhase phase = ResourceInspectionPhase::PolicyDisable);
// Final bulk-uninstall proof, after recorded owners have been attempted.
// Continue means active ownership remains: preserve the original rollback error.
std::vector<ReleasedResourceInspection> inspectReleasedOptionalResources(
    const RollbackExecutorDeps&, MutationJournal&);
}
