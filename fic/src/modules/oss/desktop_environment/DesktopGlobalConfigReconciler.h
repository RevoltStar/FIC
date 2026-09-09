#ifndef FIC_DESKTOP_GLOBAL_CONFIG_RECONCILER_H
#define FIC_DESKTOP_GLOBAL_CONFIG_RECONCILER_H

#include "modules/oss/desktop_environment/DesktopEnvironmentControl.h"
#include "policy/registry/PolicyRegistry.h"

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

// Ownership is transient reconciliation metadata, never part of physical
// identity or persistent backend state.
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

// A backend ensures only the supplied active requirements. Missing settings
// are unmanaged and must not be removed, reset, or otherwise changed. Verify
// must inspect effective protected system state, not merely a FIC fragment.
class DesktopSystemBackend {
public:
    virtual ~DesktopSystemBackend() = default;
    virtual std::string backendName() const = 0;
    virtual bool ensureManagedSettings(
        const DesktopManagedSettings& required,
        std::string& error) = 0;
    virtual bool verifyManagedSettings(
        const DesktopManagedSettings& required,
        std::string& error) = 0;
};

struct DesktopGlobalBackendResult {
    bool attempted = false;
    bool verified = false;
    std::string diagnostic;
};

struct DesktopGlobalReconcileReport {
    bool requirementsValid = true;
    std::string stageADiagnostic;
    std::map<std::string, DesktopGlobalBackendResult> backends;
    std::map<PolicyRef, PolicyGlobalEnforcementResults> policies;

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
        std::vector<std::shared_ptr<DesktopSystemBackend>> backends = {});

    DesktopGlobalReconcileReport reconcile(PolicyRegistry& registry);

private:
    std::vector<std::shared_ptr<DesktopSystemBackend>> backends_;
};

#endif // FIC_DESKTOP_GLOBAL_CONFIG_RECONCILER_H
