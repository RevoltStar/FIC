#include "PolicySaveDaemonFixture.h"
#include "policy/registry/PolicyRegistryJson.h"
#include "policy/execution/PolicyDependencyGraph.h"
#include "policy/execution/PolicyExecutionPlanner.h"
#include "modules/oss/desktop_environment/policies/OSS_controlled_desktop_environments.h"
#include "modules/oss/desktop_environment/policies/OSS_absence_of_uncontrolled_desktop_environments.h"
#include "modules/oss/display_manager/policies/OSS_controlled_display_managers.h"
#include "modules/oss/display_manager/policies/OSS_absence_of_uncontrolled_display_managers.h"
#include "modules/oss/display_manager/policies/OSS_disable_autologin.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <unistd.h>

namespace policy_save_test {
class FixturePolicy final : public Policy {
public:
    FixturePolicy(const std::string& name, std::vector<PolicyDependency> dependencies,
                  bool backendRequires) : backendRequires_(backendRequires) {
        moduleName = "OSS"; submoduleName = "fixture"; policyName = name;
        policyTypeValue = std::make_unique<PossibleListPolicyTypeValue>(
            std::vector<std::string>{"0", "1", "2"});
        moduleConf = std::make_unique<ModuleConfigFileHandler>(moduleName);
        require(moduleConf->loadConfig(), "load fixture config");
        for (const auto& edge : dependencies) {
            if (edge.strength == PolicyDependencyStrength::Required)
                addRequiredDependency(edge.policy, edge.condition);
            else addRecommendedDependency(edge.policy, edge.condition);
        }
    }
    bool apply() override { throw std::runtime_error("real apply forbidden"); }
    bool supportsDependencyCapability(const std::string& value) const override {
        return value == "fixture_capability";
    }
    bool requiresDependencyCapability(const std::string&) const override {
        return backendRequires_;
    }
private:
    bool backendRequires_;
};

Fixture::Fixture() : root(std::filesystem::temp_directory_path() /
                     ("fic-gui-save-" + std::to_string(getpid()))) {
        std::filesystem::create_directories(root / "config");
        std::filesystem::create_directories(root / "log");
        auto paths = fic::core::FicProductPaths::production();
        paths.configDir = root / "config"; paths.logDir = root / "log";
        std::string error;
        require(fic::core::FicRuntimePaths::initialize(paths, error), error);
        reset();
    }
Fixture::~Fixture() { std::filesystem::remove_all(root); }
void Fixture::reset() {
        enabled.clear(); values.clear(); commands.clear(); ownerDependencies.clear();
        backendRequires = true; failCommand.clear(); listCalls = 0;
        for (const auto& name : {de, deConsumer, dm, dmConsumer,
                                 std::string("disable_autologin"), std::string("a_owner"),
                                 std::string("z_dependency"), std::string("independent")}) {
            enabled[name] = false;
            values[name] = name == de || name == dm ? "[]" :
                (name == "a_owner" || name == "z_dependency" || name == "independent")
                    ? "0" : "ENABLE";
        }
        persist();
    }
void Fixture::persist() {
        std::ofstream out(root / "config/OSS.conf");
        out << "_schema_version=1\n";
        for (const auto& [name, state] : enabled)
            out << name << ".status=" << (state ? "ENABLE" : "DISABLE") << '\n'
                << name << ".value=" << values[name] << '\n';
    }
PolicyRegistry Fixture::registry() {
        PolicyRegistry result;
        std::string error;
        require(result.addModule("OSS", ModuleView::Standard, 0, error), error);
        const auto add = [&](std::unique_ptr<Policy> policy) {
            require(result.addPolicy(std::move(policy), error), error);
        };
        auto desktop = std::make_unique<OSS_controlled_desktop_environments>();
        auto* desktopScope = desktop.get(); add(std::move(desktop));
        add(std::make_unique<OSS_absence_of_uncontrolled_desktop_environments>(
            *desktopScope, nullptr));
        auto manager = std::make_unique<OSS_controlled_display_managers>(nullptr, nullptr);
        auto* managerScope = manager.get(); add(std::move(manager));
        add(std::make_unique<OSS_absence_of_uncontrolled_display_managers>(*managerScope, nullptr));
        add(std::make_unique<OSS_disable_autologin>(*managerScope, nullptr, nullptr));
        add(std::make_unique<FixturePolicy>("a_owner", ownerDependencies, backendRequires));
        for (const char* name : {"z_dependency", "independent"})
            add(std::make_unique<FixturePolicy>(name, std::vector<PolicyDependency>{}, true));
        require(validatePolicyDependencyGraph(result, error), error);
        return result;
    }
nlohmann::json Fixture::request(const nlohmann::json& request) {
            auto current = registry();
            const std::string command = request.at("command");
            if (command == "policy_list") {
                ++listCalls;
                return {{"ok", true}, {"message", "listed"},
                        {"policies", policyListJson(current, "OSS")}};
            }
            const std::string name = request.value("policy", "");
            commands.push_back(command + (name.empty() ? "" : ":" + name));
            const auto respond = [](bool ok, const std::string& message) {
                return nlohmann::json{{"ok", ok}, {"message", message}};
            };
            if (command == failCommand) return respond(false, "injected failure");
            if (command == "disable_policy") {
                PolicyRef identity;
                for (const auto& ref : current.policyRefs())
                    if (ref.policyName == name) identity = ref;
                if (!enabledRequiredDependents(current, identity).empty())
                    return respond(false, "enabled Required dependent");
                enabled[name] = false;
            } else if (command == "enable_policy") {
                Policy* policy = nullptr;
                for (const auto& ref : current.policyRefs())
                    if (ref.policyName == name) policy = current.findPolicy(ref);
                ModuleConfigFileHandler config("OSS");
                std::string error;
                if (!policy || !config.loadConfig() ||
                    !policy->validateValueBeforeEnable(config, error))
                    return respond(false, error);
                enabled[name] = true;
            }
            else if (command == "set_policy_value") {
                Policy* policy = nullptr;
                for (const auto& ref : current.policyRefs())
                    if (ref.policyName == name) policy = current.findPolicy(ref);
                const std::string logicalValue = request.at("value");
                if (!policy || !policy->validate(logicalValue)) return respond(false, "invalid value");
                std::string error;
                if (enabled[name] && !policy->validateEnabledValue(logicalValue, error))
                    return respond(false, error);
                values[name] = policy->postprocessingValue(logicalValue);
            }
            persist();
            auto reloaded = registry();
            PolicyExecutionRequest execution;
            for (const auto& ref : reloaded.policyRefs())
                if (reloaded.findPolicy(ref)->isEnabled()) execution.requestedRoots.push_back(ref);
            // Real dependency planner; own OS operations deliberately replaced.
            PolicyExecutionPlanner planner(reloaded, [](const PolicyRef& ref, Policy& policy)
                -> std::optional<PolicyApplyResult> {
                const bool valid = policy.getValue().has_value() &&
                    ((ref.policyName != de && ref.policyName != dm) ||
                     !policy.getValue()->empty());
                return PolicyApplyResult{ref.moduleName, ref.submoduleName, ref.policyName,
                    valid ? PolicyApplyStatus::Applied : PolicyApplyStatus::Failed,
                    valid ? "fixture applied" : "unconfigured scope"};
            });
            const auto summary = planner.execute(execution);
            return respond(!summary.hasFailures(), "intermediate reconciliation");
    }
void Fixture::expect(const std::vector<std::string>& expected) {
        if (commands != expected) {
            for (const auto& command : commands) std::cerr << command << '\n';
            throw std::runtime_error("unexpected IPC operation sequence");
        }
    }

}
