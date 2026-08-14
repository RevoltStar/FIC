#include <fic/core/FicRuntimePaths.h>
#include <fic/core/Logger.h>

#include "core/PolicyRegistry.h"
#include "core/PolicyRegistryInitialization.h"
#include "core/PolicyRegistryJson.h"
#include "modules/audit/submodules/logging/AUDIT_log_level.h"
#include "modules/global/submodules/systemsettings/GLOBAL_lang.h"

#include <nlohmann/json.hpp>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

namespace {
class UnknownModulePolicy final : public Policy {
public:
    UnknownModulePolicy()
    {
        moduleName = "UNKNOWN";
        submoduleName = "test";
        policyName = "unknown_policy";
    }

    bool apply() override { return true; }
};
}

int main()
{
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-module-registry-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root / "config");
    fs::create_directories(root / "log");
    std::ofstream(root / "config/GLOBAL.conf")
        << "_schema_version=2\nlang.status=ENABLE\nlang.value=ru\n";
    std::ofstream(root / "config/AUDIT.conf")
        << "_schema_version=2\nlog_level.status=ENABLE\nlog_level.value=FATAL\n";

    auto paths = fic::core::FicProductPaths::production();
    paths.configDir = root / "config";
    paths.logDir = root / "log";
    std::string error;
    assert(fic::core::FicRuntimePaths::initialize(paths, error));

    PolicyRegistry registry;
    assert(rebuildPolicyRegistry([] {
        PolicyList policies;
        policies.push_back(std::make_unique<AUDIT_log_level>());
        policies.push_back(std::make_unique<GLOBAL_lang>());
        return policies;
    }, registry, error));

    assert(registry.at("DC").view == ModuleView::Device);
    assert(registry.at("AUDIT").view == ModuleView::Audit);
    assert(registry.at("DAC").view == ModuleView::Standard);
    assert(registry.at("GLOBAL").view == ModuleView::Standard);
    assert(registry.at("AUDIT").submodules.at("logging").count("log_level") == 1);
    assert(registry.at("GLOBAL").submodules.at("system_settings").count("lang") == 1);
    assert(registry.at("GLOBAL").submodules.at("system_settings").count("log_level") == 0);
    assert(registry.at("DAC").submodules.empty());

    const nlohmann::json descriptors = moduleDescriptorsJson(registry);
    assert(descriptors == nlohmann::json::array({
        {{"name", "AUDIT"}, {"view", "audit"}},
        {{"name", "DAC"}, {"view", "standard"}},
        {{"name", "DC"}, {"view", "device"}},
        {{"name", "FIREWALL"}, {"view", "standard"}},
        {{"name", "GLOBAL"}, {"view", "standard"}},
        {{"name", "IDENTITY_ACCESS"}, {"view", "standard"}},
        {{"name", "NET"}, {"view", "standard"}},
        {{"name", "OSS"}, {"view", "standard"}},
        {{"name", "SYSCTL"}, {"view", "standard"}}
    }));
    for (const auto& descriptor : descriptors) {
        assert(descriptor.size() == 2);
        assert(descriptor.contains("name"));
        assert(descriptor.contains("view"));
    }

    Policy* const originalAuditPolicy =
        registry.at("AUDIT").submodules.at("logging").at("log_level").get();

    std::vector<std::unique_ptr<Policy>> unknownModulePolicies;
    unknownModulePolicies.push_back(std::make_unique<UnknownModulePolicy>());
    assert(!buildPolicyRegistry(
        std::move(unknownModulePolicies), registry, error));
    assert(error == "policy references unknown module: UNKNOWN");
    assert(moduleDescriptorsJson(registry) == descriptors);
    assert(registry.at("AUDIT").submodules.at("logging").at("log_level").get() ==
           originalAuditPolicy);
    assert(!registry.empty());

    std::vector<std::unique_ptr<Policy>> duplicatePolicies;
    duplicatePolicies.push_back(std::make_unique<AUDIT_log_level>());
    duplicatePolicies.push_back(std::make_unique<AUDIT_log_level>());
    assert(!buildPolicyRegistry(std::move(duplicatePolicies), registry, error));
    assert(error == "duplicate policy registration: AUDIT/logging/log_level");
    assert(moduleDescriptorsJson(registry) == descriptors);
    assert(registry.at("AUDIT").submodules.at("logging").at("log_level").get() ==
           originalAuditPolicy);

    assert(!rebuildPolicyRegistry([]() -> std::vector<std::unique_ptr<Policy>> {
        throw std::runtime_error("policy constructor failed");
    }, registry, error));
    assert(error == "PolicyRegistry policy creation failed: policy constructor failed");
    assert(moduleDescriptorsJson(registry) == descriptors);
    assert(registry.at("AUDIT").submodules.at("logging").at("log_level").get() ==
           originalAuditPolicy);

    PolicyRegistry metadataConflictRegistry;
    assert(metadataConflictRegistry.addModule("DAC", ModuleView::Standard, error));
    assert(!metadataConflictRegistry.addModule("DAC", ModuleView::Audit, error));
    assert(error == "conflicting view for module: DAC");

    Logger::ScopedCapture capture;
    assert(Logger::log("filtered", logLevel::ERROR, "daemon"));
    assert(Logger::log("accepted", logLevel::FATAL, "daemon"));
    const LogCaptureResult captured = capture.finish();
    assert(captured.records.size() == 1);
    assert(captured.records.front().message == "accepted");

    Policy* auditPolicy = registry.at("AUDIT").submodules.at("logging").at("log_level").get();
    assert(auditPolicy->moduleName == "AUDIT");
    assert(auditPolicy->submoduleName == "logging");
    assert(auditPolicy->policyName == "log_level");
    assert(auditPolicy->getValue() == std::optional<std::string>("FATAL"));

    std::ofstream(root / "config/AUDIT.conf", std::ios::trunc)
        << "_schema_version=2\nlog_level.status=ENABLE\nlog_level.value=NoLog\n";
    Logger::ScopedCapture noLogCapture;
    assert(Logger::log("suppressed by NoLog", logLevel::FATAL, "daemon"));
    assert(noLogCapture.finish().records.empty());

    fs::remove_all(root);
    return 0;
}
