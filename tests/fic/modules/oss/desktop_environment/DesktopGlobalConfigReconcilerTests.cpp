#include "modules/oss/desktop_environment/DesktopGlobalConfigReconciler.h"

#include <fic/core/config/ModuleConfigFileHandler.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace {
void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

class FakeBackend final : public DesktopSystemBackend {
public:
    std::string name = "fake";
    DesktopGlobalConfigState managed;
    std::map<std::string, std::string> foreign{{"administrator", "keep"}};
    int replacements = 0;
    int reads = 0;
    bool failRead = false;
    bool failVerifyRead = false;
    bool failReplace = false;
    bool corruptReplace = false;

    std::string backendName() const override { return name; }
    bool readManagedState(
        DesktopGlobalConfigState& state,
        std::string& error) override {
        ++reads;
        if (failRead || (failVerifyRead && reads == 2)) {
            error = "injected read failure";
            return false;
        }
        state = managed;
        error.clear();
        return true;
    }
    bool replaceManagedState(
        const DesktopGlobalConfigState& desired,
        std::string& error) override {
        ++replacements;
        if (failReplace) {
            error = "injected replacement failure";
            return false;
        }
        managed = desired;
        if (corruptReplace) {
            managed[{"corrupt"}] = {"corrupt", {}};
        }
        error.clear();
        return true;
    }
};

class ContributorPolicy final
    : public Policy,
      public GlobalDesktopPolicyContributor {
public:
    ContributorPolicy(const std::filesystem::path& configDirectory,
                      std::string name,
                      std::string desiredValue)
        : value(std::move(desiredValue)) {
        moduleName = "OSS";
        submoduleName = "DesktopEnvironment";
        policyName = std::move(name);
        moduleConf = std::make_unique<ModuleConfigFileHandler>(
            configDirectory, moduleName);
        if (!moduleConf->loadConfig()) {
            throw std::runtime_error("test module config could not be loaded");
        }
    }

    std::string value;
    std::string backend = "fake";
    std::string setting = "setting";
    bool failContribution = false;
    bool advertiseCapability = true;
    PolicyRef ownerOverride;
    std::vector<GlobalDesktopPolicyContribution> extra;
    bool apply() override { return true; }
    std::vector<PolicyCapability> capabilities() const override {
        return advertiseCapability
            ? std::vector<PolicyCapability>{PolicyCapability::GlobalDesktopConfiguration}
            : std::vector<PolicyCapability>{};
    }
    bool globalDesktopPolicyContributions(
        std::vector<GlobalDesktopPolicyContribution>& contributions,
        std::string& error) override {
        if (failContribution) { error = "injected contribution failure"; return false; }
        contributions.push_back({backend,
            ownerOverride.policyName.empty() ? PolicyRef{moduleName, submoduleName, policyName} : ownerOverride,
            {setting}, value});
        contributions.insert(contributions.end(), extra.begin(), extra.end());
        error.clear();
        return true;
    }
};

class CapabilityOnlyPolicy final : public Policy {
public:
    explicit CapabilityOnlyPolicy(const std::filesystem::path& directory) {
        moduleName = "OSS";
        submoduleName = "DesktopEnvironment";
        policyName = "first";
        moduleConf = std::make_unique<ModuleConfigFileHandler>(directory, moduleName);
        require(moduleConf->loadConfig(), "test config load failed");
    }
    bool apply() override { return true; }
    std::vector<PolicyCapability> capabilities() const override {
        return {PolicyCapability::GlobalDesktopConfiguration};
    }
};

void writeConfig(const std::filesystem::path& directory,
                 const std::string& firstStatus,
                 const std::string& secondStatus) {
    std::ofstream(directory / "OSS.conf")
        << "first.status=" << firstStatus << '\n'
        << "second.status=" << secondStatus << '\n';
}

PolicyRegistry registryWithPolicies(
    const std::filesystem::path& directory,
    const std::string& firstValue,
    const std::string& secondValue) {
    PolicyRegistry registry;
    std::string error;
    require(registry.addModule("OSS", ModuleView::Standard, 0, error),
            "module registration failed");
    require(registry.addPolicy(std::make_unique<ContributorPolicy>(
                directory, "first", firstValue), error),
            "first policy registration failed");
    require(registry.addPolicy(std::make_unique<ContributorPolicy>(
                directory, "second", secondValue), error),
            "second policy registration failed");
    return registry;
}

PolicyRegistry registryWithSecondPolicy(
    const std::filesystem::path& directory,
    const std::string& value) {
    PolicyRegistry registry;
    std::string error;
    require(registry.addModule("OSS", ModuleView::Standard, 0, error),
            "module registration failed");
    require(registry.addPolicy(std::make_unique<ContributorPolicy>(
                directory, "second", value), error),
            "second policy registration failed");
    return registry;
}

ContributorPolicy& contributor(PolicyRegistry& registry, const std::string& name) {
    auto* policy = dynamic_cast<ContributorPolicy*>(registry.findPolicy(
        {"OSS", "DesktopEnvironment", name}));
    require(policy != nullptr, "missing contributor");
    return *policy;
}

void requireUntouched(const std::vector<std::shared_ptr<FakeBackend>>& backends) {
    for (const auto& backend : backends) {
        require(backend->replacements == 0 && backend->reads == 0,
                "Stage A error touched a backend");
    }
}

} // namespace

int main() {
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-global-desktop-config-test-" + std::to_string(::getpid()));
    fs::create_directories(root);
    const PolicyRef firstOwner{"OSS", "DesktopEnvironment", "first"};
    const PolicyRef secondOwner{"OSS", "DesktopEnvironment", "second"};
    writeConfig(root, "ENABLE", "ENABLE");
    std::string error;
    auto backend = std::make_shared<FakeBackend>();
    DesktopGlobalConfigReconciler reconciler({backend});
    auto registry = registryWithPolicies(root, "true", "true");
    require(reconciler.reconcile(registry, error), error.c_str());
    require(backend->managed.size() == 1 && backend->replacements == 1,
            "same physical setting was not coalesced");
    require(backend->managed.at({"setting"}) == GlobalDesktopConfigValue{
                "true", {firstOwner, secondOwner}}, "shared ownership was lost");
    require(reconciler.reconcile(registry, error), error.c_str());
    require(backend->replacements == 1, "matching state was rewritten");
    // Identical duplicate from one owner is idempotent too.
    contributor(registry, "first").extra.push_back({"fake", firstOwner, {"setting"}, "true"});
    require(reconciler.reconcile(registry, error), error.c_str());
    require(backend->replacements == 1, "identical duplicate changed ownership");

    writeConfig(root, "DISABLE", "ENABLE");
    auto afterDisable = registryWithPolicies(root, "ignored", "true");
    require(reconciler.reconcile(afterDisable, error), error.c_str());
    require(backend->managed.at({"setting"}) == GlobalDesktopConfigValue{
                "true", {secondOwner}}, "disabling one owner removed shared setting");
    contributor(afterDisable, "second").value = "updated";
    require(reconciler.reconcile(afterDisable, error), error.c_str());
    require(backend->managed.at({"setting"}).value == "updated", "value change ignored");
    backend->managed[{"stale"}] = {"old", {firstOwner}};
    auto afterRemoval = registryWithSecondPolicy(root, "updated");
    require(reconciler.reconcile(afterRemoval, error), error.c_str());
    require(backend->managed.size() == 1, "removed policy left stale setting");
    writeConfig(root, "DISABLE", "DISABLE");
    auto afterRestart = registryWithPolicies(root, "ignored", "ignored");
    require(reconciler.reconcile(afterRestart, error), error.c_str());
    require(backend->managed.empty(), "last owner disable did not clean up");
    require(backend->foreign.at("administrator") == "keep", "foreign state changed");

    writeConfig(root, "ENABLE", "ENABLE");
    // Each Stage A failure follows a valid contribution; no partial backend pass.
    for (const std::string failure : {"conflict", "reverse conflict", "same owner conflict",
                                      "unknown", "owner", "empty", "contributor"}) {
        auto first = std::make_shared<FakeBackend>();
        auto second = std::make_shared<FakeBackend>(); second->name = "secondBackend";
        DesktopGlobalConfigReconciler subject({first, second});
        auto policies = failure == "same owner conflict"
            ? registryWithSecondPolicy(root, "true")
            : registryWithPolicies(root, "true", "true");
        auto& b = contributor(policies, "second");
        if (failure == "conflict") b.value = "false";
        if (failure == "reverse conflict") contributor(policies, "first").value = "false";
        if (failure == "same owner conflict") b.extra.push_back({"fake", secondOwner, {"setting"}, "false"});
        if (failure == "unknown") b.backend = "missing";
        if (failure == "owner") b.ownerOverride = firstOwner;
        if (failure == "empty") b.setting.clear();
        if (failure == "contributor") b.failContribution = true;
        require(!subject.reconcile(policies, error), "invalid desired state accepted");
        require(!error.empty(), "Stage A diagnostic missing");
        if (failure.find("conflict") != std::string::npos) {
            require(error.find("conflicting global desktop setting: fake/setting") != std::string::npos,
                    "conflict diagnostic missing physical key");
        }
        requireUntouched({first, second});
    }

    auto different = registryWithPolicies(root, "true", "false");
    contributor(different, "second").setting = "other";
    require(reconciler.reconcile(different, error), error.c_str());
    require(backend->managed.size() == 2 && backend->managed.at({"other"}).value == "false",
            "different physical settings conflicted");
    auto otherBackend = std::make_shared<FakeBackend>(); otherBackend->name = "otherBackend";
    DesktopGlobalConfigReconciler separate({backend, otherBackend});
    contributor(different, "second").setting = "setting";
    contributor(different, "second").backend = "otherBackend";
    require(separate.reconcile(different, error), error.c_str());
    require(backend->managed.size() == 1 && backend->managed.at({"setting"}).value == "true" &&
            otherBackend->managed.size() == 1 && otherBackend->managed.at({"setting"}).value == "false",
            "backend namespaces were conflated");

    for (const std::string failure : {"read", "replace", "verify", "verify read", "multiple"}) {
        auto first = std::make_shared<FakeBackend>(); first->name = "firstBackend";
        auto second = std::make_shared<FakeBackend>(); second->name = "secondBackend";
        auto third = std::make_shared<FakeBackend>(); third->name = "thirdBackend";
        for (auto& target : {first, second, third}) target->managed[{"stale"}] = {"old", {firstOwner}};
        first->failRead = failure == "read" || failure == "multiple";
        first->failReplace = failure == "replace";
        first->corruptReplace = failure == "verify";
        first->failVerifyRead = failure == "verify read";
        third->corruptReplace = failure == "multiple";
        DesktopGlobalConfigReconciler subject({first, second, third});
        PolicyRegistry empty;
        require(!subject.reconcile(empty, error), "failed backend accepted");
        require(error.find("firstBackend:") != std::string::npos, "first diagnostic lost");
        const std::string stage = failure == "replace" ? "replaceManagedState failed" :
            failure == "verify" ? "verification failed" :
            failure == "verify read" ? "verification readManagedState failed" : "readManagedState failed";
        require(error.find(stage) != std::string::npos, "backend failure stage missing");
        require(second->managed.empty() && second->replacements == 1 && second->reads == 2,
                "failed backend blocked independent cleanup/readback");
        require(third->reads == 2, "later backend not visited");
        if (failure == "multiple") {
            require(error.find("thirdBackend: verification failed") != std::string::npos &&
                    error.find('\n') != std::string::npos, "multiple errors not aggregated");
        } else require(third->managed.empty(), "third backend cleanup failed");
        for (const auto& target : {first, second, third}) {
            require(target->foreign.at("administrator") == "keep", "foreign state modified on failure");
        }
    }

    // A contributor without its capability must not silently disappear.
    PolicyRegistry mismatch;
    require(mismatch.addModule("OSS", ModuleView::Standard, 0, error), error.c_str());
    auto hidden = std::make_unique<ContributorPolicy>(root, "first", "true");
    hidden->advertiseCapability = false;
    require(mismatch.addPolicy(std::move(hidden), error), error.c_str());
    auto untouched = std::make_shared<FakeBackend>();
    DesktopGlobalConfigReconciler consistency({untouched});
    require(!consistency.reconcile(mismatch, error), "capability mismatch accepted");
    requireUntouched({untouched});

    PolicyRegistry missingContributor;
    require(missingContributor.addModule("OSS", ModuleView::Standard, 0, error), error.c_str());
    require(missingContributor.addPolicy(std::make_unique<CapabilityOnlyPolicy>(root), error), error.c_str());
    require(!consistency.reconcile(missingContributor, error), "capability without contributor accepted");
    requireUntouched({untouched});
    for (const auto& backends : std::vector<std::vector<std::shared_ptr<DesktopSystemBackend>>>{
             {untouched, nullptr}, {untouched, untouched}}) {
        DesktopGlobalConfigReconciler invalid(backends);
        require(!invalid.reconcile(registry, error), "invalid backend registration accepted");
        requireUntouched({untouched});
    }

    fs::remove_all(root);
    return 0;
}
