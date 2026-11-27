#include "features/policies/services/PolicyService.h"
#include "PolicySaveDaemonFixture.h"
#include <iostream>
#include <fstream>
#include <iterator>

using namespace policy_save_test;
namespace {
PolicyService service(Fixture& fixture) {
    return PolicyService([&fixture](const nlohmann::json& request) {
        return PolicyService::RequestResult{true, fixture.request(request), {}};
    });
}
PolicyChange state(const std::string& name, bool enabled) {
    PolicyChange result; result.policyName = name;
    result.enabledChanged = true; result.enabled = enabled; return result;
}
PolicyChange value(const std::string& name, const std::string& target) {
    PolicyChange result; result.policyName = name; result.value = target;
    result.valueChanged = true; result.valueConfigurable = true; return result;
}
PolicyChange enableWithValue(const std::string& name, const std::string& target) {
    auto result = value(name, target); result.enabledChanged = true; result.enabled = true;
    return result;
}
PolicyDependency edge(PolicyDependencyStrength strength, PolicyDependencyCondition condition = {}) {
    return {{"OSS", "fixture", "z_dependency"}, strength, std::move(condition)};
}

void run() {
    Fixture f; QString error;
    // Both public save paths, actual DE/DM constructors and daemon JSON producer.
    for (const bool apply : {false, true}) {
        f.reset();
        auto changes = std::vector<PolicyChange>{state(deConsumer, true),
            enableWithValue(de, "GNOME")};
        auto client = service(f);
        if (apply) require(client.saveAndApplyChanges("OSS", changes).status ==
            PolicyService::ApplyStatus::Completed, "DE save/apply");
        else require(client.saveChanges("OSS", changes, error), error.toStdString());
        std::vector<std::string> expected{"set_policy_value:" + de,
            "enable_policy:" + de, "enable_policy:" + deConsumer};
        if (apply) expected.push_back("apply_module");
        f.expect(expected); require(f.listCalls == 1, "one fresh metadata snapshot");

        f.reset();
        changes = {state(dmConsumer, true), state("disable_autologin", true),
                   enableWithValue(dm, "SDDM")};
        client = service(f);
        if (apply) require(client.saveAndApplyChanges("OSS", changes).status ==
            PolicyService::ApplyStatus::Completed, "DM save/apply");
        else require(client.saveChanges("OSS", changes, error), error.toStdString());
        expected = {"set_policy_value:" + dm, "enable_policy:" + dm,
                    "enable_policy:" + dmConsumer, "enable_policy:disable_autologin"};
        if (apply) expected.push_back("apply_module");
        f.expect(expected);
    }
    // The target state is checked before the first mutating IPC request.
    for (const auto& name : {de, dm}) {
        f.reset();
        require(!service(f).saveChanges("OSS", {state(name, true)}, error),
                "empty scope enable accepted by GUI");
        f.expect({});
        require(error.toStdString().find(name) != std::string::npos,
                "scope diagnostic omitted policy name");
        f.reset(); f.enabled[name] = true; f.values[name] = "[]"; f.persist();
        require(!service(f).saveChanges("OSS", {value(name, "")}, error),
                "enabled scope clear accepted by GUI");
        f.expect({});
        require(service(f).saveChanges("OSS", {value(name, name == de ? "GNOME" : "SDDM")}, error),
                error.toStdString());
        f.expect({"set_policy_value:" + name});
    }
    f.reset();
    require(!service(f).saveChanges("OSS", {state(deConsumer, true),
        state(dmConsumer, true), state(de, true), state(dm, true)}, error),
        "all scopes enabled with empty defaults");
    f.expect({});
    // Daemon-side validation also rejects direct mutations before persistence.
    for (const auto& name : {de, dm}) {
        f.reset();
        const auto before = f.values[name];
        const auto configBytes = [&] {
            std::ifstream input(f.root / "config/OSS.conf");
            return std::string(std::istreambuf_iterator<char>(input), {});
        };
        const auto original = configBytes();
        auto denied = f.request({{"command", "enable_policy"}, {"policy", name}});
        require(!denied.at("ok").get<bool>() && f.values[name] == before && !f.enabled[name] && configBytes() == original,
                "direct empty enable changed configuration");
        f.reset(); f.enabled[name] = true; f.values[name] = "[\"" +
            std::string(name == de ? "GNOME" : "SDDM") + "\"]"; f.persist();
        const auto enabledOriginal = configBytes();
        denied = f.request({{"command", "set_policy_value"}, {"policy", name}, {"value", ""}});
        require(!denied.at("ok").get<bool>() && f.values[name] != "[]" && configBytes() == enabledOriginal,
                "direct clear of enabled scope changed configuration");
    }
    // Disable dependents before changing (or disabling) their old scope.
    f.reset(); f.enabled[de] = f.enabled[deConsumer] = true;
    f.values[de] = "[\"GNOME\"]"; f.persist();
    auto scope = value(de, ""); scope.enabledChanged = true; scope.enabled = false;
    require(service(f).saveChanges("OSS", {scope, state(deConsumer, false)}, error), error.toStdString());
    f.expect({"disable_policy:" + deConsumer, "disable_policy:" + de, "set_policy_value:" + de});

    f.reset(); f.enabled[dm] = true; f.values[dm] = "[\"SDDM\"]"; f.persist();
    auto clearManager = value(dm, "");
    clearManager.enabledChanged = true; clearManager.enabled = false;
    require(service(f).saveChanges("OSS", {clearManager}, error), error.toStdString());
    f.expect({"disable_policy:" + dm, "set_policy_value:" + dm});

    f.reset(); f.enabled[dm] = f.enabled[dmConsumer] = f.enabled["disable_autologin"] = true;
    f.values[dm] = "[\"SDDM\"]"; f.persist();
    require(service(f).saveChanges("OSS", {state(dm, false), state(dmConsumer, false),
        state("disable_autologin", false)}, error), error.toStdString());
    f.expect({"disable_policy:" + dmConsumer, "disable_policy:disable_autologin", "disable_policy:" + dm});

    // Recommended edge chooses order but never adds changes or blocks an owner.
    for (const bool includeDependency : {false, true}) {
        f.reset(); f.ownerDependencies = {edge(PolicyDependencyStrength::Recommended)};
        std::vector<PolicyChange> changes{state("a_owner", true)};
        if (includeDependency) changes.push_back(state("z_dependency", true));
        require(service(f).saveChanges("OSS", changes, error), error.toStdString());
        f.expect(includeDependency ? std::vector<std::string>{"enable_policy:z_dependency", "enable_policy:a_owner"}
                                   : std::vector<std::string>{"enable_policy:a_owner"});
    }
    f.reset(); f.ownerDependencies = {edge(PolicyDependencyStrength::Recommended)};
    f.enabled["a_owner"] = f.enabled["z_dependency"] = true; f.persist();
    require(service(f).saveChanges("OSS", {state("z_dependency", false), state("a_owner", false)}, error), error.toStdString());
    f.expect({"disable_policy:a_owner", "disable_policy:z_dependency"});

    f.reset();
    require(service(f).saveChanges("OSS", {state("z_dependency", true),
        state("independent", true), state("a_owner", true)}, error), error.toStdString());
    f.expect({"enable_policy:z_dependency", "enable_policy:independent", "enable_policy:a_owner"});
    f.commands.clear();
    require(service(f).saveChanges("OSS", {}, error), "empty save"); f.expect({});

    // Target value, rather than the disabled owner's current value, selects edge.
    for (const std::string target : {"1", "2"}) {
        f.reset(); f.ownerDependencies = {edge(PolicyDependencyStrength::Required, whenOwnerValueEquals("2"))};
        auto changes = std::vector<PolicyChange>{enableWithValue("a_owner", target)};
        if (target == "2") changes.push_back(state("z_dependency", true));
        require(service(f).saveChanges("OSS", changes, error), error.toStdString());
        f.expect(target == "2" ? std::vector<std::string>{"enable_policy:z_dependency", "set_policy_value:a_owner", "enable_policy:a_owner"}
                               : std::vector<std::string>{"set_policy_value:a_owner", "enable_policy:a_owner"});
    }
    // Already enabled owner acquires/releases a conditional dependency.
    f.reset(); f.ownerDependencies = {edge(PolicyDependencyStrength::Required, whenOwnerValueEquals("2"))};
    f.enabled["a_owner"] = true; f.persist();
    require(service(f).saveChanges("OSS", {value("a_owner", "2"), state("z_dependency", true)}, error), error.toStdString());
    f.expect({"enable_policy:z_dependency", "set_policy_value:a_owner"});
    f.commands.clear();
    require(service(f).saveChanges("OSS", {state("z_dependency", false), value("a_owner", "1")}, error), error.toStdString());
    f.expect({"set_policy_value:a_owner", "disable_policy:z_dependency"});

    for (const bool required : {false, true}) {
        f.reset(); f.backendRequires = required;
        f.ownerDependencies = {edge(PolicyDependencyStrength::Required,
            whenBackendRequiresCapability("fixture_capability"))};
        std::vector<PolicyChange> changes{state("a_owner", true)};
        if (required) changes.push_back(state("z_dependency", true));
        require(service(f).saveChanges("OSS", changes, error), error.toStdString());
        f.expect(required ? std::vector<std::string>{"enable_policy:z_dependency", "enable_policy:a_owner"}
                          : std::vector<std::string>{"enable_policy:a_owner"});
    }
    // A chain, not just a pair; names oppose the dependency order.
    f.reset(); f.ownerDependencies = {{{"OSS", "DesktopEnvironment", deConsumer}, PolicyDependencyStrength::Required, {}}};
    require(service(f).saveChanges("OSS", {state("a_owner", true), state(deConsumer, true),
        enableWithValue(de, "GNOME")}, error), error.toStdString());
    f.expect({"set_policy_value:" + de, "enable_policy:" + de,
              "enable_policy:" + deConsumer, "enable_policy:a_owner"});

    for (const std::string fail : {"set_policy_value", "enable_policy", "disable_policy"}) {
        f.reset(); f.failCommand = fail;
        std::vector<PolicyChange> changes{state(deConsumer, true), enableWithValue(de, "GNOME")};
        if (fail == "disable_policy") {
            f.enabled[de] = f.enabled[deConsumer] = true; f.values[de] = "[\"GNOME\"]"; f.persist();
            changes = {state(de, false), state(deConsumer, false)};
        }
        const auto result = service(f).saveAndApplyChanges("OSS", changes);
        require(result.status == PolicyService::ApplyStatus::SaveFailed &&
            result.error.contains("injected failure"), "preserve daemon failure");
        std::vector<std::string> expected;
        if (fail == "enable_policy") expected.push_back("set_policy_value:" + de);
        expected.push_back(fail + ":" + (fail == "disable_policy" ? deConsumer : de));
        f.expect(expected);
        require(f.enabled[deConsumer] == (fail == "disable_policy"), "no subsequent owner mutation");
    }
}
}
int main() {
    try { run(); std::cout << "Policy save dependency regressions passed\n"; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
