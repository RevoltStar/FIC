#pragma once
#include "rollback/RollbackExecutor.h"
#include "rollback/MutationJournal.h"
namespace fic::rollback {
enum class UnrecordedResourceState { Continue, ProvenEmpty, UnprovenOwnership, Error };
// Read-only proof over the backend's ownership scope, not provider compliance.
// Never adopts artifacts or resolves journal entries. Active domain ownership
// always returns Continue and must go through the existing strict backend.
UnrecordedResourceState inspectUnrecordedResource(const PolicyRef&,
    const RollbackExecutorDeps&,MutationJournal&,std::string& error);
}
