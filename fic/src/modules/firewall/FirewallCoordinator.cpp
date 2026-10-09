#include "modules/firewall/FirewallCoordinator.h"
#include "modules/firewall/FirewallPolicies.h"
#include "incident/IncidentController.h"
#include "incident/IncidentProfileSynchronization.h"
#include "rollback/DaemonMutationJournal.h"
#include <fic/core/config/ConfigAuthority.h>
#include <fic/core/runtime/FicRuntimePaths.h>
#include <sstream>
#include <cctype>
#include <algorithm>

namespace fic::incident {
bool IncidentController::productionNetworkQuarantineRequired() {
    std::lock_guard<std::recursive_mutex> guard(incidentProfileMutex());
    const auto mode = IncidentResponseModeResolver::production();
    const auto state = IncidentStateStore().read();
    return networkQuarantineRequired(mode, state, incidentForcedNetworkQuarantine());
}
bool IncidentController::networkQuarantineRequired(const IncidentResponseModeResult& mode,
    const IncidentStateStore::ReadResult& state, bool forcedEffectiveIsolate) {
    return (!mode.proven || mode.mode == IncidentResponseMode::Active) &&
        (forcedEffectiveIsolate || state.provenance != IncidentStateStore::Provenance::Proven ||
         state.severity == fic::core::IncidentSeverity::Isolate);
}
}

namespace fic::firewall {
FirewallCoordinator::FirewallCoordinator(const FirewallBackend& backend,
                                         FirewallCoordinatorOptions options)
    : backend_(backend), options_(std::move(options)) {
    if (!options_.profile) {
        options_.profile = backend_.quarantineDecision_
            ? std::function<FirewallEffectiveProfile()>([this] {
                return backend_.quarantineDecision_() ? FirewallEffectiveProfile::IncidentQuarantine
                                                     : FirewallEffectiveProfile::Normal;
              })
            : std::function<FirewallEffectiveProfile()>(productionProfile);
    }
    if (!options_.configuration) options_.configuration = backend_.configuration_
        ? backend_.configuration_ : productionConfiguration;
}
FirewallEffectiveProfile FirewallCoordinator::productionProfile() {
    return incident::IncidentController::productionNetworkQuarantineRequired()
        ? FirewallEffectiveProfile::IncidentQuarantine : FirewallEffectiveProfile::Normal;
}
bool FirewallCoordinator::productionConfiguration(FirewallDesiredState& desired,
                                                  std::string& error) {
    using namespace fic::core;
    ConfigAuthorityIdentity authority;
    if (!productionConfigAuthority(authority, error)) return false;
    const auto path = FicRuntimePaths::get().configDir / "FIREWALL.conf";
    const auto expected = configAuthorityExpectation(authority);
    return readConfiguration(path, expected, productionProfile(), desired, error);
}
bool FirewallCoordinator::readConfiguration(const std::filesystem::path& path,
    const fic::core::SecureStateFileExpectation& expected, FirewallEffectiveProfile profile,
    FirewallDesiredState& desired, std::string& error) {
    using namespace fic::core;
    if (!proveSafeParentDirectory(path.parent_path().parent_path(), expected, error)) return false;
    const auto file = readSecureFileBounded(path, expected, MAX_WORKING_CONFIG_BYTES);
    if (file.status != SecureStateReadStatus::Proven) {
        error = "FIREWALL.conf is unproven: " + file.detail; return false;
    }
    std::map<std::string, std::string> config;
    std::istringstream input(file.content);
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty() || line.front() == '#') continue;
        const auto equal = line.find('=');
        const auto key = line.substr(0, equal);
        if (equal == std::string::npos || key.empty() ||
            line.find_first_of("\r\0", 0, 2) != std::string::npos ||
            std::any_of(key.begin(), key.end(), [](unsigned char ch) { return std::isspace(ch); }) ||
            !config.emplace(key, line.substr(equal + 1)).second) {
            error = "malformed/ambiguous FIREWALL.conf"; return false;
        }
    }
    if (config["_schema_version"] != "1") { error = "unsupported FIREWALL.conf schema"; return false; }
    desired = {};
    if (profile == FirewallEffectiveProfile::IncidentQuarantine) {
        const auto status = config["incident_quarantine.status"];
        if (status != "ENABLE" && status != "DISABLE") {
            error = "incident_quarantine status is invalid"; return false;
        }
        if (status == "ENABLE") {
            std::string normalized;
            if (!parseQuarantineRules(config["incident_quarantine.value"],
                                      desired.exceptions, normalized, error)) return false;
        }
    } else {
        std::map<std::string, bool> enabled;
        auto policies = managedFirewallPolicies();
        policies.push_back("exclusive_firewall_control");
        for (const auto& policy : policies) {
            const auto status = config[policy + ".status"];
            if (status != "ENABLE" && status != "DISABLE") {
                error = "invalid normal FIREWALL status: " + policy; return false;
            }
            enabled[policy] = status == "ENABLE";
        }
        if (!buildFirewallDesiredState(enabled, config["custom_rules.value"], desired, error)) return false;
    }
    error.clear();
    return true;
}
bool FirewallCoordinator::effectiveState(const FirewallDesiredState* normalIntent,
    FirewallDesiredState& desired, std::string& configError) {
    const auto profile = options_.profile();
    const bool configOk = options_.configuration(desired, configError);
    if (profile == FirewallEffectiveProfile::IncidentQuarantine) {
        // Invalid exceptions fail closed to an empty exception set, but the
        // configuration error remains visible even after a proven strict apply.
        if (!configOk) desired = {};
        desired.quarantine = true;
        desired.policyRules.clear(); desired.exclusive = false;
        return true;
    }
    if (!configOk) return false;
    if (normalIntent) desired = *normalIntent;
    desired.quarantine = false; desired.exceptions.clear();
    return true;
}
bool FirewallCoordinator::reconcile(const FirewallDesiredState* normalIntent,
    bool& changed, std::vector<ForeignBaseChain>& neutralized, std::string& error,
    bool exclusiveRequested) {
    std::lock_guard<std::recursive_mutex> lock(incident::incidentProfileMutex());
    FirewallDesiredState desired;
    std::string configError;
    if (!effectiveState(normalIntent, desired, configError)) { error = configError; return false; }
    if (exclusiveRequested && !desired.quarantine) desired.exclusive = true;
    if (!backend_.applyEffective(desired, changed, neutralized, error)) return false;
    // Re-read authority: a competing incident/mode change invalidates success.
    if ((options_.profile() == FirewallEffectiveProfile::IncidentQuarantine) != desired.quarantine) {
        error = "firewall authority changed during apply"; return false;
    }
    if (!configError.empty()) { error = "strict quarantine installed; invalid configuration: " + configError; return false; }
    return true;
}
bool FirewallCoordinator::applyPolicy(const std::string& policy,
    const std::vector<FirewallRule>& rules, bool& changed, std::string& error) {
    std::lock_guard<std::recursive_mutex> lock(incident::incidentProfileMutex());
    changed = false;
    FirewallDesiredState desired;
    std::string configError;
    if (!effectiveState(nullptr, desired, configError)) { error = configError; return false; }
    if (!desired.quarantine) {
        if (policy == "incident_quarantine") { changed = false; error.clear(); return true; }
        desired.policyRules[policy] = rules;
    }
    std::vector<ForeignBaseChain> neutralized;
    bool kernelChanged = false;
    if (!backend_.applyEffective(desired, kernelChanged, neutralized, error,
                                 desired.quarantine ? "" : policy)) {
        changed = !desired.quarantine && kernelChanged;
        return false;
    }
    // Ordinary apply during quarantine creates no ordinary journal obligation.
    changed = !desired.quarantine && kernelChanged;
    if ((options_.profile() == FirewallEffectiveProfile::IncidentQuarantine) != desired.quarantine) {
        error = "firewall authority changed during policy apply"; return false;
    }
    if (!configError.empty()) { error = "strict quarantine installed; invalid configuration: " + configError; return false; }
    return true;
}
bool FirewallCoordinator::requestProfile(bool quarantine, std::string& error) {
    // The request cannot lower the persistent authority. Clear writes UNLOCKED
    // durably before this call, OFF/PASSIVE are read from trusted GLOBAL.conf.
    if ((options_.profile() == FirewallEffectiveProfile::IncidentQuarantine) != quarantine) {
        error = "requested firewall profile disagrees with incident authority";
        return false;
    }
    bool changed = false;
    std::vector<ForeignBaseChain> neutralized;
    return reconcile(nullptr, changed, neutralized, error);
}
bool FirewallCoordinator::applyJournaledPolicy(const PolicyRef& policy,
    const std::vector<FirewallRule>& rules, std::string& error) {
    std::lock_guard<std::recursive_mutex> lock(incident::incidentProfileMutex());
    bool changed = false;
    if (options_.profile() == FirewallEffectiveProfile::IncidentQuarantine ||
        policy.policyName == "incident_quarantine")
        return applyPolicy(policy.policyName, rules, changed, error);

    using namespace fic::rollback;
    auto* journal = DaemonMutationJournal::instance().tryGet(error);
    if (!journal) return false;
    MutationId id = 0;
    bool existing = false;
    for (const auto& record : journal->activeRecords(policy)) {
        if (record.resource != policy.policyName) continue;
        const auto* undo = std::get_if<UndoRemoveFirewallPolicy>(&record.undo.payload);
        if (record.undo.backend != MutationBackend::Firewall || !undo || undo->policyName != policy.policyName) {
            error = "ordinary FIREWALL journal ownership conflicts with policy"; return false;
        }
        id = record.id; existing = true; break;
    }
    if (!existing && !recordPreparedMutation(policy, policy.policyName,
            {MutationBackend::Firewall, UndoRemoveFirewallPolicy{policy.policyName}}, id, error)) return false;
    if (!applyPolicy(policy.policyName, rules, changed, error)) {
        if (!existing && !changed) {
            std::string cleanup;
            if (!discardMutation(id, cleanup)) error += "; journal cleanup failed: " + cleanup;
        }
        return false;
    }
    if (changed) return commitMutation(id, error);
    // prepareMutation is idempotent and may return an existing active id.
    // A no-op must NEVER discard that older rollback obligation.
    return existing || discardMutation(id, error);
}
}
