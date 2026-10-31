#include "service/sssd/SssdVerifiedActivationAdapter.h"
#include "service/VerifiedConfigServiceActivatorTestAccess.h"
#include "service/sssd/SssdRuntimeProof.h"
#include <fic/core/integrity/ContentDigest.h>
#include <mutex>
#include <nlohmann/json.hpp>
#include <thread>
namespace fic::service::sssd {
namespace d = fic::service::detail;
namespace {
std::timed_mutex operationMutex;
[[noreturn]] void unsupported(const std::string &why) {
  throw d::Failure(ActivationStatus::UnsupportedConfiguration,
                   "SSSD adapter: " + why);
}
std::string invocation(const d::LaunchContract &launch) {
  const auto values =
      nlohmann::json::parse(launch.at("launch.InvocationID")).at("value");
  std::string out;
  const char *hex = "0123456789abcdef";
  for (const auto &v : values) {
    auto b = v.get<unsigned>();
    if (b > 255)
      unsupported("invocation bytes");
    out += hex[b >> 4];
    out += hex[b & 15];
  }
  return out;
}
} // namespace
namespace detail_i3 {
bool sameValue(const SemanticValue &a, const SemanticValue &b) {
  if (a.index() != b.index() || std::holds_alternative<std::monostate>(a))
    return false;
  if (auto x = std::get_if<Days>(&a))
    return x->value == std::get<Days>(b).value;
  if (auto x = std::get_if<Seconds>(&a))
    return x->value == std::get<Seconds>(b).value;
  return std::get<bool>(a) == std::get<bool>(b);
}
d::LaunchContract configurationOnly(d::LaunchContract c) {
  for (const auto &key :
       {"ActiveState", "SubState", "MainPID", "InvocationID", "Job"})
    c.erase(std::string("launch.") + key);
  return c;
}
void validateExpectations(
    const EffectiveConfiguration &cfg,
    const std::vector<SssdSemanticExpectation> &expectations) {
  if (expectations.empty() || expectations.size() > 256)
    unsupported("bounded nonempty expectations required");
  if (cfg.scope.data().hypothetical ||
      !validateRelations(cfg).semanticProjectionValidated())
    unsupported("canonical supported observed LDAP semantics required");
  std::set<SettingKey> keys;
  for (const auto &e : expectations) {
    if (!keys.insert(e.key).second)
      unsupported("duplicate expectation");
    const EffectiveValue *value = nullptr;
    if (e.key.section == "pam" && e.key.key == "offline_credentials_expiration")
      value = &cfg.offlineDays;
    else if (e.key.section.rfind("domain/", 0) == 0) {
      const auto name = e.key.section.substr(7);
      auto domain = cfg.scope.data().domains.find(name);
      if (domain == cfg.scope.data().domains.end() ||
          !domain->second.selected || !domain->second.enabled ||
          domain->second.provider != ProviderClass::LdapPassword)
        unsupported(
            "expectation outside canonical selected enabled LDAP scope");
      const auto &values = cfg.domains.at(name);
      if (e.key.key == "cache_credentials")
        value = &values.cacheCredentials;
      else if (e.key.key == "account_cache_expiration")
        value = &values.accountDays;
      else if (e.key.key == "cached_auth_timeout")
        value = &values.cachedAuthSeconds;
    }
    if (!value || value->status != SemanticStatus::Validated ||
        !sameValue(value->value, e.value))
      unsupported(
          "selected expectation does not match captured canonical value/type");
  }
}
ActivationRequest protectedRequest(const SssdInputReference &input,
                                   std::chrono::milliseconds timeout) {
  ActivationRequest out;
  out.unit = "sssd.service";
  out.timeout = timeout;
  out.maxSnapshotBytes = 8 * 1024 * 1024;
  const auto &source = input.sources.at("/etc/sssd");
  if (!source.present)
    unsupported("complete SSSD parent required");
  ControlledPath tree{"/etc/sssd", ControlledPathKind::Directory, {}, {}, {}};
  for (const auto &[name, bytes] : source.tree.files)
    tree.manifest[name] = fic::core::ContentDigest::sha256Hex(bytes);
  for (const auto &[name, st] : source.tree.attributes)
    if (!name.empty() && S_ISDIR(st.st_mode))
      tree.directories.insert(name);
  out.paths.push_back(std::move(tree));
  const auto &environment = input.sources.at(input.launch.profile.environment);
  if (!environment.present)
    unsupported("absent optional EnvironmentFile is not protected outside SSSD "
                "parent; no fabricated file");
  out.paths.push_back(
      {input.launch.profile.environment,
       ControlledPathKind::File,
       fic::core::ContentDigest::sha256Hex(environment.tree.files.at("")),
       {},
       {}});
  d::validateRequest(out);
  return out;
}
} // namespace detail_i3
namespace {
SssdVerifiedActivationResult
perform(const SssdVerifiedActivationRequest &request
#ifdef FIC_ACTIVATOR_TESTING
        ,
        const detail_i3::AdapterTestHooks *tests
#endif
) {
  SssdVerifiedActivationResult result;
  const auto started = std::chrono::steady_clock::now();
  const auto deadline = started + request.timeout;
  std::unique_lock<std::timed_mutex> operation(operationMutex, std::defer_lock);
  auto checkpoint = [&](const std::string &phase) {
#ifdef FIC_ACTIVATOR_TESTING
    if (tests && tests->checkpoint)
      tests->checkpoint(phase);
#else
    (void)phase;
#endif
  };
  bool engineEntered = false;
  try {
    if (request.timeout.count() <= 0 ||
        request.timeout > std::chrono::minutes(5))
      unsupported("invalid bounded timeout");
    if (!operation.try_lock_until(deadline))
      throw d::Failure(ActivationStatus::TimedOut,
                       "SSSD operation resource busy");
    const auto canonical = domainScope(request.input);
    if (request.scope.data().hypothetical ||
        !sameScopeReference(canonical, request.scope))
      unsupported("untrusted, hypothetical or stale domain scope");
    auto cfg = effectiveConfiguration(request.input);
    detail_i3::validateExpectations(cfg, request.expectations);
    if (request.input.applyConflict())
      unsupported("later eligible foreign snippet outside activation support");
    auto paths = detail_i3::protectedRequest(request.input, request.timeout);
    revalidate(request.input, deadline);
    result.oldInvocation = invocation(request.input.launch.contract);
    auto native = detail_i3::nativePreflight(request, cfg, deadline);
    d::validatePublicationEnvironment(paths, &result.engine.residualPaths);
    result.admission = SssdProofState::Proven;
    checkpoint("admitted");
    const auto expected =
        detail_i3::configurationOnly(request.input.launch.contract);
    d::ActivationProof proof;
    proof.profile = d::ActivationProfile::SssdNotify;
    proof.expectedConfiguration = expected;
    proof.sssdLaunchValidation = [&](const d::LaunchContract &launch) {
      validateLaunchProfile(launch, request.input.launch.profile);
      detail_i3::verifyNativeCode(native);
    };
    for (const auto &path : paths.paths) {
      const auto &source = request.input.sources.at(path.path.string());
      proof.sourceRoots[path.path.string()] = source.identity;
      proof.sourceAttributes[path.path.string()] = source.tree.attributes;
    }
    bool publishedValidated = false;
    proof.published = [&](Deadline current) {
      const auto snapshot =
          detail_i1::snapshotGraph(request.input.launch, current);
      if (snapshot.order != request.input.order ||
          snapshot.negativeDependencies != request.input.negativeDependencies ||
          snapshot.laterForeignSnippets != request.input.laterForeignSnippets)
        throw d::Failure(ActivationStatus::InterferenceDetected,
                         "SSSD published graph/negative set changed");
      for (const auto &[path, before] : request.input.sources) {
        const auto &after = snapshot.sources.at(path);
        if (before.present != after.present ||
            before.tree.files != after.tree.files ||
            before.tree.attributes.size() != after.tree.attributes.size())
          throw d::Failure(ActivationStatus::InterferenceDetected,
                           "SSSD snapshot bytes/manifest changed");
        for (const auto &[name, a] : before.tree.attributes) {
          auto it = after.tree.attributes.find(name);
          if (it == after.tree.attributes.end())
            throw d::Failure(ActivationStatus::InterferenceDetected,
                             "SSSD snapshot object missing");
          const auto &b = it->second;
          if (a.st_mode != b.st_mode || a.st_uid != b.st_uid ||
              a.st_gid != b.st_gid ||
              (S_ISREG(a.st_mode) && a.st_size != b.st_size) ||
              a.st_mtim.tv_sec != b.st_mtim.tv_sec ||
              a.st_mtim.tv_nsec != b.st_mtim.tv_nsec)
            throw d::Failure(ActivationStatus::InterferenceDetected,
                             "SSSD protected metadata differs");
        }
      }
      detail_i3::validateExpectations(effectiveConfiguration(snapshot),
                                      request.expectations);
      detail_i3::verifyNativeCode(native);
      // Publication is a prerequisite, not evidence of runtime consumption.
      publishedValidated = true;
      checkpoint("published");
    };
    proof.ready = [&](const d::ServiceState &state, Deadline current) {
      checkpoint("ready");
      std::string lastReadiness;
      for (;;) {
        SssdVerifiedActivationResult attempt;
        try {
          detail_i3::proveRuntime(request, cfg, native, state, current,
                                  attempt);
          if (!publishedValidated)
            throw d::Failure(ActivationStatus::ReadinessUnconfirmed,
                             "SSSD protected publication not confirmed");
          result.processes = std::move(attempt.processes);
          result.parameters = std::move(attempt.parameters);
          result.configDbGeneration = std::move(attempt.configDbGeneration);
          result.nativeCode = std::move(attempt.nativeCode);
          result.newInvocation = attempt.newInvocation;
          // Historical input consumption survives later P/cleanup failures.
          result.inputs = SssdProofState::Proven;
          result.activation = SssdProofState::Proven;
          result.semantics = SssdProofState::Proven;
          break;
        } catch (const d::Failure &e) {
          if (attempt.activation == SssdProofState::Proven) {
            result.activation = attempt.activation;
            result.processes = std::move(attempt.processes);
            result.newInvocation = attempt.newInvocation;
          }
          if (e.status != ActivationStatus::ReadinessUnconfirmed) {
            if (e.status == ActivationStatus::TimedOut &&
                !lastReadiness.empty())
              throw d::Failure(e.status, std::string(e.what()) +
                                             "; last consumer observation: " +
                                             lastReadiness);
            throw;
          }
          lastReadiness = e.what();
          if (std::chrono::steady_clock::now() >= current)
            throw d::Failure(ActivationStatus::TimedOut,
                             std::string("SSSD consumer proof deadline: ") +
                                 e.what());
          std::this_thread::sleep_for(
              std::min(std::chrono::milliseconds(10),
                       std::chrono::duration_cast<std::chrono::milliseconds>(
                           current - std::chrono::steady_clock::now())));
        }
      }
      checkpoint("semantics");
    };
    paths.timeout = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now());
    if (paths.timeout.count() <= 0)
      throw d::Failure(ActivationStatus::TimedOut,
                       "SSSD deadline before protected publication");
    engineEntered = true;
#ifdef FIC_ACTIVATOR_TESTING
    if (tests && tests->engine)
      result.engine =
          d::activateWithProofForTests(paths, proof, *tests->engine);
    else
#endif
      result.engine = d::activateWithProof(paths, proof);
    result.runtimeEffectPossible = result.engine.activationAttempted;
    if (!result.engine.cleanupErrors.empty() ||
        !result.engine.residualPaths.empty()) {
      result.status = SssdActivationStatus::CleanupFailed;
      result.diagnostic =
          result.engine.diagnostic +
          "; cleanup incomplete; persistent proof not attempted";
      return result;
    }
    checkpoint("persistent");
    try {
      if (std::chrono::steady_clock::now() >= deadline)
        throw d::Failure(ActivationStatus::TimedOut,
                         "SSSD persistent deadline exhausted");
      detail_i1::verifyPersistentSources(request.input, deadline);
      const auto after = capture(deadline);
      if (detail_i3::configurationOnly(after.launch.contract) != expected ||
          after.launch.executables != request.input.launch.executables ||
          after.launch.environmentFingerprint !=
              request.input.launch.environmentFingerprint ||
          after.launch.unitLookupFingerprint !=
              request.input.launch.unitLookupFingerprint)
        throw d::Failure(ActivationStatus::InterferenceDetected,
                         "SSSD persistent launch/source generation changed");
      if (!result.newInvocation.empty() &&
          invocation(after.launch.contract) != result.newInvocation) {
        result.activation = SssdProofState::NotProven;
        result.semantics = SssdProofState::NotProven;
        result.diagnostic =
            "SSSD newly proven runtime generation changed after cleanup";
      }
      result.persistent = SssdProofState::Proven;
    } catch (const d::Failure &e) {
      result.persistent = (e.status == ActivationStatus::InterferenceDetected ||
                           e.status == ActivationStatus::ChecksumMismatch)
                              ? SssdProofState::Drifted
                              : SssdProofState::NotProven;
      result.diagnostic =
          std::string("post-cleanup persistent proof: ") + e.what();
    }
    if (result.persistent == SssdProofState::Proven &&
        result.semantics == SssdProofState::Proven) {
      try {
        detail_i3::confirmRuntime(native, result, deadline);
      } catch (const std::exception &e) {
        result.activation = result.semantics = SssdProofState::NotProven;
        result.diagnostic =
            std::string("post-cleanup runtime confirmation: ") + e.what();
      }
    }
    if (result.engine.success() && result.inputs == SssdProofState::Proven &&
        result.activation == SssdProofState::Proven &&
        result.semantics == SssdProofState::Proven &&
        result.persistent == SssdProofState::Proven) {
      result.status = SssdActivationStatus::Success;
      result.diagnostic = "SSSD adapter A/B/source-causal C/P proven for "
                          "selected expectations; coverage not evaluated";
    } else if (result.engine.success())
      result.status =
          result.activation == SssdProofState::Proven &&
                  result.semantics == SssdProofState::Proven
              ? SssdActivationStatus::RuntimeActivatedButPersistentUnproven
              : SssdActivationStatus::RuntimeEffectUnknown;
    else if (result.engine.activationAttempted)
      result.status =
          result.engine.primaryStatus == ActivationStatus::RestartFailed
              ? SssdActivationStatus::ActivationFailed
              : SssdActivationStatus::RuntimeEffectUnknown;
    result.diagnostic +=
        (result.diagnostic.empty() ? "" : "; ") + result.engine.diagnostic;
  } catch (const d::Failure &e) {
    result.diagnostic = e.what();
    if (!engineEntered) {
      result.engine.status = result.engine.primaryStatus = e.status;
      result.engine.diagnostic = e.what();
      if (e.status == ActivationStatus::UnsupportedConfiguration)
        result.admission = SssdProofState::Unsupported;
    } else {
      result.runtimeEffectPossible = result.engine.activationAttempted;
      result.status =
          result.engine.success()
              ? SssdActivationStatus::RuntimeActivatedButPersistentUnproven
              : SssdActivationStatus::RuntimeEffectUnknown;
    }
  } catch (const std::exception &e) {
    result.diagnostic = e.what();
    if (!engineEntered)
      result.engine.diagnostic = e.what();
    else {
      result.runtimeEffectPossible = result.engine.activationAttempted;
      result.status = SssdActivationStatus::RuntimeEffectUnknown;
    }
  }
  return result;
}
} // namespace
SssdVerifiedActivationResult
activate(const SssdVerifiedActivationRequest &request) {
  return perform(request
#ifdef FIC_ACTIVATOR_TESTING
                 ,
                 nullptr
#endif
  );
}
#ifdef FIC_ACTIVATOR_TESTING
SssdVerifiedActivationResult
detail_i3::activateForTests(const SssdVerifiedActivationRequest &request,
                            const AdapterTestHooks &tests) {
  return perform(request, &tests);
}
#endif
} // namespace fic::service::sssd
