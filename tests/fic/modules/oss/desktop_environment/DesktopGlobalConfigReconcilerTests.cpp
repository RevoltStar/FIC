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
    bool failReplace = false;
    bool corruptReplace = false;

    std::string backendName() const override { return name; }
    bool readManagedState(
        DesktopGlobalConfigState& state,
        std::string& error) override {
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
        if (corruptReplace && !managed.empty()) {
            managed.begin()->second = "corrupt";
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
    bool apply() override { return true; }
    std::vector<PolicyCapability> capabilities() const override {
        return {PolicyCapability::GlobalDesktopConfiguration};
    }
    bool globalDesktopPolicyContributions(
        std::vector<GlobalDesktopPolicyContribution>& contributions,
        std::string& error) override {
        contributions.push_back({
            "fake",
            {{moduleName, submoduleName, policyName}, "setting"},
            value});
        error.clear();
        return true;
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
}

int main() {
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-global-desktop-config-test-" + std::to_string(::getpid()));
    fs::create_directories(root);
    writeConfig(root, "ENABLE", "ENABLE");

    auto backend = std::make_shared<FakeBackend>();
    DesktopGlobalConfigReconciler reconciler({backend});
    PolicyRegistry registry = registryWithPolicies(root, "one", "two");
    std::string error;
    require(reconciler.reconcile(registry, error), error.c_str());
    require(backend->managed.size() == 2 && backend->replacements == 1,
            "enabled contributions did not create desired state");
    require(backend->foreign.at("administrator") == "keep",
            "foreign state was modified");

    require(reconciler.reconcile(registry, error), error.c_str());
    require(backend->replacements == 1,
            "idempotent reconciliation rewrote matching state");

    auto* first = dynamic_cast<ContributorPolicy*>(registry.findPolicy(
        {"OSS", "DesktopEnvironment", "first"}));
    require(first != nullptr, "first contributor missing");
    first->value = "updated";
    require(reconciler.reconcile(registry, error), error.c_str());
    require(backend->replacements == 2 &&
                backend->managed.at({
                    {"OSS", "DesktopEnvironment", "first"}, "setting"}) ==
                    "updated",
            "changed contribution was not updated");

    writeConfig(root, "DISABLE", "ENABLE");
    PolicyRegistry afterDisable = registryWithPolicies(root, "ignored", "two");
    require(reconciler.reconcile(afterDisable, error), error.c_str());
    require(backend->managed.size() == 1 &&
                backend->managed.begin()->first.owner.policyName == "second",
            "disabled policy did not remove only its owned state");
    require(backend->foreign.at("administrator") == "keep",
            "cleanup removed foreign state");

    backend->managed.insert({
        {{"OSS", "DesktopEnvironment", "first"}, "setting"}, "stale"});
    PolicyRegistry afterRemoval = registryWithSecondPolicy(root, "two");
    require(reconciler.reconcile(afterRemoval, error), error.c_str());
    require(backend->managed.size() == 1 &&
                backend->managed.begin()->first.owner.policyName == "second",
            "removed policy left stale FIC-owned state");

    writeConfig(root, "DISABLE", "DISABLE");
    PolicyRegistry afterRestart = registryWithPolicies(root, "ignored", "ignored");
    require(reconciler.reconcile(afterRestart, error), error.c_str());
    require(backend->managed.empty(),
            "restart/rebuild did not remove stale FIC-owned state");

    writeConfig(root, "ENABLE", "DISABLE");
    PolicyRegistry failing = registryWithPolicies(root, "expected", "ignored");
    backend->corruptReplace = true;
    require(!reconciler.reconcile(failing, error),
            "unverified partial state was accepted");
    require(error.find("verification failed") != std::string::npos,
            "verification failure diagnostic was lost");

    backend->corruptReplace = false;
    backend->managed.clear();
    backend->failReplace = true;
    require(!reconciler.reconcile(failing, error),
            "backend write failure was accepted");

    fs::remove_all(root);
    return 0;
}
