#include <fic/core/FicRuntimePaths.h>
#include <fic/core/Logger.h>

#include "core/PolicyRegistry.h"
#include "core/PolicyRegistryJson.h"
#include "modules/audit/submodules/logging/AUDIT_log_level.h"

#include <nlohmann/json.hpp>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <unistd.h>

int main()
{
    PolicyRegistry registry;
    registry["DAC"].view = moduleViewForName("DAC");
    registry["DC"].view = moduleViewForName("DC");
    registry["AUDIT"].view = moduleViewForName("AUDIT");

    assert(moduleViewName(registry.at("DAC").view) == "standard");
    assert(moduleViewName(registry.at("DC").view) == "device");
    assert(moduleViewName(registry.at("AUDIT").view) == "audit");

    const nlohmann::json descriptors = moduleDescriptorsJson(registry);
    assert(descriptors == nlohmann::json::array({
        {{"name", "AUDIT"}, {"view", "audit"}},
        {{"name", "DAC"}, {"view", "standard"}},
        {{"name", "DC"}, {"view", "device"}}
    }));

    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() /
        ("fic-module-registry-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root / "config");
    fs::create_directories(root / "log");
    std::ofstream(root / "config/GLOBAL.conf")
        << "_schema_version=2\nlog_level.status=ENABLE\nlog_level.value=TRACE\n";
    std::ofstream(root / "config/AUDIT.conf")
        << "_schema_version=2\nlog_level.status=ENABLE\nlog_level.value=FATAL\n";

    auto paths = fic::core::FicProductPaths::production();
    paths.configDir = root / "config";
    paths.logDir = root / "log";
    std::string error;
    assert(fic::core::FicRuntimePaths::initialize(paths, error));
    Logger::ScopedCapture capture;
    assert(Logger::log("filtered", logLevel::ERROR, "daemon"));
    assert(Logger::log("accepted", logLevel::FATAL, "daemon"));
    const LogCaptureResult captured = capture.finish();
    assert(captured.records.size() == 1);
    assert(captured.records.front().message == "accepted");

    AUDIT_log_level policy;
    assert(policy.moduleName == "AUDIT");
    assert(policy.submoduleName == "logging");
    assert(policy.policyName == "log_level");
    assert(policy.getValue() == std::optional<std::string>("FATAL"));

    fs::remove_all(root);
    return 0;
}
