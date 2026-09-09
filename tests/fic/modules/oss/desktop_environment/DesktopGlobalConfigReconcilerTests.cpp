#include "modules/oss/desktop_environment/DesktopGlobalConfigReconciler.h"
#include <fic/core/config/ModuleConfigFileHandler.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

class FakeBackend final : public DesktopSystemBackend {
public:
    std::string name = "fake";
    DesktopManagedSettings effective;
    std::map<std::string, std::string> foreign{{"administrator", "keep"}};
    std::vector<DesktopManagedSettings> ensures;
    int verifies = 0;
    bool failEnsure = false;
    bool failVerify = false;

    std::string backendName() const override { return name; }

    bool ensureManagedSettings(const DesktopManagedSettings& required,
                               std::string& error) override {
        ensures.push_back(required);
        if (failEnsure) {
            error = "injected ensure failure";
            return false;
        }
        for (const auto& [key, value] : required) effective[key] = value;
        error.clear();
        return true;
    }

    bool verifyManagedSettings(const DesktopManagedSettings& required,
                               std::string& error) override {
        ++verifies;
        if (failVerify) {
            error = "injected verification failure";
            return false;
        }
        for (const auto& [key, value] : required) {
            const auto actual = effective.find(key);
            if (actual == effective.end() || actual->second != value) {
                error = "effective setting differs from requirement";
                return false;
            }
        }
        error.clear();
        return true;
    }
};

class ContributorPolicy final : public Policy,
                                public GlobalDesktopPolicyContributor {
public:
    ContributorPolicy(const std::filesystem::path& directory,
                      std::string name,
                      std::string desiredValue)
        : value(std::move(desiredValue)) {
        moduleName = "OSS";
        submoduleName = "DesktopEnvironment";
        policyName = std::move(name);
        moduleConf = std::make_unique<ModuleConfigFileHandler>(directory, moduleName);
        if (!moduleConf->loadConfig()) throw std::runtime_error("config load failed");
    }

    std::string value;
    std::string backend = "fake";
    std::string setting = "setting";
    PolicyRef ownerOverride;
    std::vector<GlobalDesktopPolicyContribution> extra;
    bool failContribution = false;
    bool advertiseCapability = true;

    bool apply() override { return true; }
    std::vector<PolicyCapability> capabilities() const override {
        if (!advertiseCapability) return {};
        return {PolicyCapability::GlobalDesktopConfiguration};
    }
    bool globalDesktopPolicyContributions(
        std::vector<GlobalDesktopPolicyContribution>& contributions,
        std::string& error) override {
        if (failContribution) {
            error = "injected contribution failure";
            return false;
        }
        const PolicyRef self{moduleName, submoduleName, policyName};
        contributions.push_back({backend,
            ownerOverride.policyName.empty() ? self : ownerOverride,
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
        if (!moduleConf->loadConfig()) throw std::runtime_error("config load failed");
    }
    bool apply() override { return true; }
    std::vector<PolicyCapability> capabilities() const override {
        return {PolicyCapability::GlobalDesktopConfiguration};
    }
};

void writeConfig(const std::filesystem::path& directory,
                 const std::string& first,
                 const std::string& second) {
    std::ofstream(directory / "OSS.conf")
        << "first.status=" << first << '\n'
        << "second.status=" << second << '\n';
}

PolicyRegistry makeRegistry(const std::filesystem::path& directory,
                            const std::string& firstValue,
                            const std::string& secondValue) {
    PolicyRegistry registry;
    std::string error;
    require(registry.addModule("OSS", ModuleView::Standard, 0, error),
            "module registration failed");
    require(registry.addPolicy(std::make_unique<ContributorPolicy>(
                directory, "first", firstValue), error), "first registration failed");
    require(registry.addPolicy(std::make_unique<ContributorPolicy>(
                directory, "second", secondValue), error), "second registration failed");
    return registry;
}

ContributorPolicy& policy(PolicyRegistry& registry, const std::string& name) {
    auto* result = dynamic_cast<ContributorPolicy*>(registry.findPolicy(
        {"OSS", "DesktopEnvironment", name}));
    require(result != nullptr, "contributor missing");
    return *result;
}

void requireUntouched(const std::vector<std::shared_ptr<FakeBackend>>& backends) {
    for (const auto& backend : backends) {
        require(backend->ensures.empty() && backend->verifies == 0,
                "Stage A error touched backend");
    }
}
} // namespace

int main() {
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-global-desktop-config-test-" + std::to_string(::getpid()));
    fs::create_directories(root);
    const PolicyRef firstOwner{"OSS", "DesktopEnvironment", "first"};
    std::string error;

    writeConfig(root, "ENABLE", "DISABLE");
    auto backend = std::make_shared<FakeBackend>();
    backend->effective[{"existing"}] = "old";
    DesktopGlobalConfigReconciler reconciler({backend});
    auto one = makeRegistry(root, "true", "ignored");
    require(reconciler.reconcile(one, error), error.c_str());
    require(backend->ensures.size() == 1 && backend->ensures.back().size() == 1 &&
                backend->ensures.back().at({"setting"}) == "true",
            "one active policy was not ensured");
    require(backend->effective.at({"existing"}) == "old" &&
                backend->foreign.at("administrator") == "keep",
            "unrelated state was changed");

    writeConfig(root, "ENABLE", "ENABLE");
    auto shared = makeRegistry(root, "true", "true");
    require(reconciler.reconcile(shared, error), error.c_str());
    require(backend->ensures.back().size() == 1,
            "same-value owners did not merge");
    policy(shared, "first").extra.push_back(
        {"fake", firstOwner, {"setting"}, "true"});
    require(reconciler.reconcile(shared, error), error.c_str());

    writeConfig(root, "DISABLE", "ENABLE");
    auto secondOnly = makeRegistry(root, "ignored", "true");
    const auto beforeOneDisable = backend->ensures.size();
    require(reconciler.reconcile(secondOnly, error), error.c_str());
    require(backend->ensures.size() == beforeOneDisable + 1 &&
                backend->effective.at({"setting"}) == "true",
            "remaining requester was not enforced");

    writeConfig(root, "DISABLE", "DISABLE");
    auto disabled = makeRegistry(root, "ignored", "ignored");
    const auto beforeLastDisable = backend->ensures.size();
    const int verifiesBeforeLastDisable = backend->verifies;
    require(reconciler.reconcile(disabled, error), error.c_str());
    require(backend->ensures.size() == beforeLastDisable &&
                backend->verifies == verifiesBeforeLastDisable &&
                backend->effective.at({"setting"}) == "true",
            "disable changed previously applied state");

    writeConfig(root, "ENABLE", "DISABLE");
    auto changed = makeRegistry(root, "false", "ignored");
    require(reconciler.reconcile(changed, error), error.c_str());
    require(backend->effective.at({"setting"}) == "false",
            "enabled value change was not enforced");

    writeConfig(root, "ENABLE", "ENABLE");
    for (const std::string failure : {"conflict", "self", "unknown", "owner",
                                      "empty", "generation"}) {
        auto firstBackend = std::make_shared<FakeBackend>();
        auto other = std::make_shared<FakeBackend>(); other->name = "other";
        DesktopGlobalConfigReconciler subject({firstBackend, other});
        auto invalid = makeRegistry(root, "true", "true");
        auto& second = policy(invalid, "second");
        if (failure == "conflict") second.value = "false";
        if (failure == "self") second.extra.push_back(
            {"fake", {"OSS", "DesktopEnvironment", "second"}, {"setting"}, "false"});
        if (failure == "unknown") second.backend = "missing";
        if (failure == "owner") second.ownerOverride = firstOwner;
        if (failure == "empty") second.setting.clear();
        if (failure == "generation") second.failContribution = true;
        if (subject.reconcile(invalid, error)) {
            throw std::runtime_error("invalid requirements accepted: " + failure);
        }
        if (failure == "conflict" || failure == "self")
            require(error.find("conflicting global desktop setting") != std::string::npos,
                    "conflict diagnostic missing");
        requireUntouched({firstBackend, other});
    }

    PolicyRegistry capabilityMismatch;
    require(capabilityMismatch.addModule(
                "OSS", ModuleView::Standard, 0, error), error.c_str());
    auto hiddenContributor =
        std::make_unique<ContributorPolicy>(root, "first", "true");
    hiddenContributor->advertiseCapability = false;
    require(capabilityMismatch.addPolicy(
                std::move(hiddenContributor), error), error.c_str());
    auto mismatchBackend = std::make_shared<FakeBackend>();
    DesktopGlobalConfigReconciler mismatchReconciler({mismatchBackend});
    require(!mismatchReconciler.reconcile(capabilityMismatch, error),
            "contributor without capability accepted");
    requireUntouched({mismatchBackend});

    PolicyRegistry missingContributor;
    require(missingContributor.addModule(
                "OSS", ModuleView::Standard, 0, error), error.c_str());
    require(missingContributor.addPolicy(
                std::make_unique<CapabilityOnlyPolicy>(root), error), error.c_str());
    require(!mismatchReconciler.reconcile(missingContributor, error),
            "capability without contributor accepted");
    requireUntouched({mismatchBackend});

    auto distinct = makeRegistry(root, "true", "false");
    policy(distinct, "second").setting = "otherSetting";
    auto distinctBackend = std::make_shared<FakeBackend>();
    DesktopGlobalConfigReconciler distinctReconciler({distinctBackend});
    require(distinctReconciler.reconcile(distinct, error), error.c_str());
    require(distinctBackend->ensures.back().size() == 2,
            "different physical settings were not both enforced");

    auto namespaced = makeRegistry(root, "true", "false");
    policy(namespaced, "second").backend = "other";
    auto other = std::make_shared<FakeBackend>(); other->name = "other";
    DesktopGlobalConfigReconciler separate({backend, other});
    require(separate.reconcile(namespaced, error), error.c_str());
    require(backend->effective.at({"setting"}) == "true" &&
                other->effective.at({"setting"}) == "false",
            "backend namespaces conflicted");

    auto failures = makeRegistry(root, "one", "two");
    policy(failures, "first").backend = "first";
    for (const std::string failure : {"ensure", "verify", "multiple"}) {
        auto first = std::make_shared<FakeBackend>(); first->name = "first";
        auto second = std::make_shared<FakeBackend>(); second->name = "second";
        auto third = std::make_shared<FakeBackend>(); third->name = "third";
        first->failEnsure = failure == "ensure" || failure == "multiple";
        first->failVerify = failure == "verify";
        policy(failures, "second").backend = failure == "multiple" ? "third" : "second";
        third->failVerify = failure == "multiple";
        DesktopGlobalConfigReconciler subject({first, second, third});
        require(!subject.reconcile(failures, error), "backend failure accepted");
        require(error.find("first:") != std::string::npos,
                "first backend diagnostic missing");
        if (failure == "multiple") {
            require(error.find("third: verifyManagedSettings failed") != std::string::npos &&
                        error.find('\n') != std::string::npos,
                    "multiple errors were not aggregated");
        } else {
            require(second->effective.at({"setting"}) == "two" && second->verifies == 1,
                    "failed backend blocked later enforcement");
        }
    }

    auto untouched = std::make_shared<FakeBackend>();
    for (const auto& backends :
         std::vector<std::vector<std::shared_ptr<DesktopSystemBackend>>>{
             {untouched, nullptr}, {untouched, untouched}}) {
        DesktopGlobalConfigReconciler invalid(backends);
        require(!invalid.reconcile(shared, error), "invalid backend accepted");
        requireUntouched({untouched});
    }

    fs::remove_all(root);
    return 0;
}
