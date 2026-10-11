#ifndef FIC_DESKTOP_GLOBAL_CONFIG_RECONCILER_H
#define FIC_DESKTOP_GLOBAL_CONFIG_RECONCILER_H

#include "modules/oss/desktop_environment/DesktopEnvironmentControl.h"
#include "policy/registry/PolicyRegistry.h"
#include "rollback/MutationJournal.h"

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

struct GlobalDesktopConfigKey {
    std::string setting;

    bool operator<(const GlobalDesktopConfigKey& other) const;
    bool operator==(const GlobalDesktopConfigKey& other) const;
};

struct GlobalDesktopPolicyContribution {
    std::string backend;
    DesktopEnvironmentKind desktop = DesktopEnvironmentKind::Unknown;
    PolicyRef owner;
    GlobalDesktopConfigKey key;
    std::string value;
};

// Owner references are persisted by journaled physical backends; they are
// independent of the physical key and of the record's primary policy.
struct GlobalDesktopConfigValue {
    std::string value;
    std::set<PolicyRef> owners;

    bool operator==(const GlobalDesktopConfigValue& other) const;
};

// One active physical requirement per backend namespace, with all requesters.
using DesktopGlobalConfigRequirements =
    std::map<GlobalDesktopConfigKey, GlobalDesktopConfigValue>;

// The backend-facing state contains only physical settings and values.
using DesktopManagedSettings = std::map<GlobalDesktopConfigKey, std::string>;

class GlobalDesktopPolicyContributor {
public:
    virtual ~GlobalDesktopPolicyContributor() = default;
    virtual bool globalDesktopPolicyContributions(
        std::vector<GlobalDesktopPolicyContribution>& contributions,
        std::string& error) = 0;
};

// Each backend is bound to exactly one canonical DesktopEnvironmentKind;
// desktop() is the typed source of truth, backendName() is only a stable
// identifier for diagnostics, lookup, and audit.
//
// A backend ensures only the supplied active requirements. Missing settings
// are unmanaged and must not be removed, reset, or otherwise changed. Verify
// must inspect effective protected system state, not merely a FIC fragment.
class DesktopSystemBackend {
public:
    virtual ~DesktopSystemBackend() = default;

    virtual DesktopEnvironmentKind desktop() const = 0;
    virtual std::string backendName() const = 0;
    virtual bool verifiedEnforcementAvailable(std::string& error) const {
        error = "desktop backend cannot prove effective enforcement"; return false;
    }
    virtual bool ensureManagedSettings(
        const DesktopManagedSettings& required,
        std::string& error) = 0;
    virtual bool verifyManagedSettings(
        const DesktopManagedSettings& required,
        std::string& error) = 0;
    virtual bool preflightJournaled(const DesktopGlobalConfigRequirements&,
                                   fic::rollback::MutationJournal&,
                                   std::string& error) {
        error = "desktop backend has no journaled preflight"; return false;
    }
    virtual bool reconcileJournaled(const DesktopGlobalConfigRequirements&,
                                   fic::rollback::MutationJournal&,
                                   std::string& error) {
        error = "desktop backend has no journaled reconciliation"; return false;
    }
    virtual bool releaseOwnerJournaled(const PolicyRef&, fic::rollback::MutationJournal&,
                                      std::string& error, bool = false) {
        error = "desktop backend has no owner release"; return false;
    }
};

struct DesktopGlobalBackendResult {
    bool attempted = false;
    bool verified = false;
    std::string diagnostic;
};

// Diagnostic ownership evidence only; never authorizes physical rollback.
struct DesktopGlobalReleaseFailure {
    PolicyRef owner;
    DesktopEnvironmentKind desktop = DesktopEnvironmentKind::Unknown;
    fic::rollback::MutationId mutation = 0;
    std::string resource;
    std::string phase;
    std::string diagnostic;
};

struct DesktopGlobalReconcileReport {
    bool requirementsValid = true;
    std::string stageADiagnostic;
    // Actual coordinator phase; retained even when ownership collection is incomplete.
    std::string phase = "global_preflight";
    std::map<std::string, DesktopGlobalBackendResult> backends;
    std::map<PolicyRef, PolicyGlobalEnforcementResults> policies;
    std::vector<DesktopGlobalReleaseFailure> releaseFailures;

    bool successful() const;
    bool successfulForPolicy(const PolicyRef& policy) const;
    bool successfulForModule(const std::string& module) const;
    PolicyGlobalEnforcementResult resultFor(
        const PolicyRef& policy,
        DesktopEnvironmentKind desktop) const;
    PolicyGlobalEnforcementResults resultsFor(const PolicyRef& policy) const;
    std::string diagnostic() const;
};

class DesktopGlobalConfigReconciler {
public:
    explicit DesktopGlobalConfigReconciler(
        std::vector<std::shared_ptr<DesktopSystemBackend>> backends = {},
        fic::rollback::MutationJournal* journal = nullptr);

    DesktopGlobalReconcileReport reconcile(PolicyRegistry& registry);
    bool releasePolicy(const PolicyRef& owner, fic::rollback::MutationJournal& journal,
                       std::string& error, bool preview = false);
    bool releaseAll(fic::rollback::MutationJournal& journal, std::string& error,
                    bool preview = false);

private:
    std::vector<std::shared_ptr<DesktopSystemBackend>> backends_;
    fic::rollback::MutationJournal* journal_;
};

#endif // FIC_DESKTOP_GLOBAL_CONFIG_RECONCILER_H
