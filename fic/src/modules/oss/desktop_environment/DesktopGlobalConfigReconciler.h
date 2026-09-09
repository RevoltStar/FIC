#ifndef FIC_DESKTOP_GLOBAL_CONFIG_RECONCILER_H
#define FIC_DESKTOP_GLOBAL_CONFIG_RECONCILER_H

#include "policy/registry/PolicyRegistry.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

struct GlobalDesktopConfigKey {
    PolicyRef owner;
    std::string setting;

    bool operator<(const GlobalDesktopConfigKey& other) const;
    bool operator==(const GlobalDesktopConfigKey& other) const;
};

struct GlobalDesktopPolicyContribution {
    std::string backend;
    GlobalDesktopConfigKey key;
    std::string value;
};

using DesktopGlobalConfigState =
    std::map<GlobalDesktopConfigKey, std::string>;

class GlobalDesktopPolicyContributor {
public:
    virtual ~GlobalDesktopPolicyContributor() = default;
    virtual bool globalDesktopPolicyContributions(
        std::vector<GlobalDesktopPolicyContribution>& contributions,
        std::string& error) = 0;
};

// A backend exposes only its FIC-owned namespace. replaceManagedState() must
// preserve all foreign configuration outside that namespace.
class DesktopSystemBackend {
public:
    virtual ~DesktopSystemBackend() = default;
    virtual std::string backendName() const = 0;
    virtual bool readManagedState(
        DesktopGlobalConfigState& state,
        std::string& error) = 0;
    virtual bool replaceManagedState(
        const DesktopGlobalConfigState& desired,
        std::string& error) = 0;
};

class DesktopGlobalConfigReconciler {
public:
    explicit DesktopGlobalConfigReconciler(
        std::vector<std::shared_ptr<DesktopSystemBackend>> backends = {});

    bool reconcile(PolicyRegistry& registry, std::string& error);

private:
    std::vector<std::shared_ptr<DesktopSystemBackend>> backends_;
};

#endif // FIC_DESKTOP_GLOBAL_CONFIG_RECONCILER_H
