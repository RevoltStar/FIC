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

    std::vector<std::unique_ptr<Policy>> policies;
    policies.push_back(std::make_unique<AUDIT_log_level>());
    policies.push_back(std::make_unique<GLOBAL_lang>());
    PolicyRegistry registry;
    assert(buildPolicyRegistry(std::move(policies), registry, error));

    assert(registry.at("DC").view == ModuleView::Device);
    assert(registry.at("AUDIT").view == ModuleView::Audit);
    assert(registry.at("DAC").view == ModuleView::Standard);
    assert(registry.at("GLOBAL").view == ModuleView::Standard);
    assert(registry.at("AUDIT").submodules.at("logging").count("log_level") == 1);
    assert(registry.at("GLOBAL").submodules.at("system_settings").count("lang") == 1);
    assert(registry.at("GLOBAL").submodules.at("system_settings").count("log_level") == 0);
    assert(registry.at("DAC").submodules.empty());

    const nlohmann::json descriptors = moduleDescriptorsJson(registry);
    assert(descriptors.size() == 9);
    assert(descriptors.at(0) == nlohmann::json({{"name", "AUDIT"}, {"view", "audit"}}));
    assert(descriptors.at(2) == nlohmann::json({{"name", "DC"}, {"view", "device"}}));
    for (const auto& descriptor : descriptors) {
        assert(descriptor.size() == 2);
        assert(descriptor.contains("name"));
        assert(descriptor.contains("view"));
    }

    PolicyRegistry invalidRegistry;
    assert(invalidRegistry.addModule("DAC", ModuleView::Standard, error));
    assert(!invalidRegistry.addPolicy(std::make_unique<UnknownModulePolicy>(), error));
    assert(error == "policy references unknown module: UNKNOWN");
    assert(!invalidRegistry.addModule("DAC", ModuleView::Audit, error));
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
