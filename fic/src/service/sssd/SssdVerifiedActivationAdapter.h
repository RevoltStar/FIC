#pragma once
#include "service/VerifiedConfigActivationProof.h"
#include "service/sssd/SssdRelationValidator.h"
namespace fic::service::detail {
struct TestHooks;
}
namespace fic::service::sssd {
enum class SssdProofState { NotProven, Proven, Unsupported, Drifted };
enum class SssdActivationStatus {
  Refused,
  ActivationFailed,
  RuntimeEffectUnknown,
  RuntimeActivatedButPersistentUnproven,
  CleanupFailed,
  Success
};
struct SssdSemanticExpectation {
  SettingKey key;
  SemanticValue value;
};
enum class SssdActivationIntent { Apply, ConfigurationRelease };
struct SssdVerifiedActivationRequest {
  SssdInputReference input;
  DomainScopeReference scope;
  std::vector<SssdSemanticExpectation> expectations;
  std::chrono::milliseconds timeout{10000};
  SssdActivationIntent intent=SssdActivationIntent::Apply;
};
struct SssdProcessEvidence {
  pid_t pid = 0, parent = 0;
  std::string role, domain, startToken, executable, cgroup, mountNamespace;
  uid_t uid = 0;
  gid_t gid = 0;
  detail::Identity executableIdentity, configDbIdentity;
  bool initializationConfirmed = false;
  unsigned consumerSocket = 0, monitorSocket = 0;
  std::string backendBusOwner;
};
struct SssdParameterEvidence {
  SettingKey key;
  SemanticValue configuredValue, consumerValue;
  std::string consumer, processToken, configDbGeneration, sourceContract,
      readMoment, scope;
};
struct SssdVerifiedActivationResult {
  SssdActivationStatus status = SssdActivationStatus::Refused;
  SssdProofState admission = SssdProofState::NotProven,
                 inputs = SssdProofState::NotProven,
                 activation = SssdProofState::NotProven,
                 semantics = SssdProofState::NotProven,
                 persistent = SssdProofState::NotProven;
  ActivationResult engine;
  std::string diagnostic, oldInvocation, newInvocation, configDbGeneration;
  bool runtimeEffectPossible = false;
  PolicyCoverage policyCoverage = PolicyCoverage::NotEvaluated;
  std::vector<SssdProcessEvidence> processes;
  std::vector<SssdParameterEvidence> parameters;
  std::map<std::string, std::string> nativeCode;
  bool success() const {
    return status == SssdActivationStatus::Success &&
           admission == SssdProofState::Proven &&
           inputs == SssdProofState::Proven &&
           activation == SssdProofState::Proven &&
           semantics == SssdProofState::Proven &&
           persistent == SssdProofState::Proven && engine.success() &&
           engine.primaryStatus == ActivationStatus::Success &&
           engine.activationAttempted && engine.readinessConfirmed &&
           engine.cleanupErrors.empty() && engine.residualPaths.empty();
  }
};
// One bounded protected restart of an already active service. No policy/journal
// authority, ownership acquisition, functional login, or runtime-receipt cache.
SssdVerifiedActivationResult activate(const SssdVerifiedActivationRequest &);
namespace detail_i3 {
bool sameValue(const SemanticValue &, const SemanticValue &);
void validateExpectations(const EffectiveConfiguration &,
                          const std::vector<SssdSemanticExpectation> &);
detail::LaunchContract configurationOnly(detail::LaunchContract);
ActivationRequest protectedRequest(const SssdInputReference &,
                                   std::chrono::milliseconds);
#ifdef FIC_ACTIVATOR_TESTING
struct AdapterTestHooks {
  detail::TestHooks *engine = nullptr;
  std::function<void(const std::string &)> checkpoint;
};
SssdVerifiedActivationResult
activateForTests(const SssdVerifiedActivationRequest &,
                 const AdapterTestHooks &);
#endif
} // namespace detail_i3
} // namespace fic::service::sssd
