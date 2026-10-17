#pragma once
#ifdef FIC_ACTIVATOR_TESTING
#include "service/VerifiedConfigServiceActivator.h"
#include <functional>
namespace fic::service::detail {
enum class TestPhase { SnapshotReadOnly, Watching, RestartQueued, BeforeCleanup };
// Deliberately compiled OUT of the production executable. Faults return errno;
// checkpoints permit barrier-based native races, not alternative implementations.
struct TestHooks {
    std::function<int(const std::string&, std::size_t)> fault;
    std::function<void(TestPhase, const std::string&)> checkpoint;
};
ActivationResult activateForTests(const ActivationRequest&, const TestHooks&);
}
#endif
