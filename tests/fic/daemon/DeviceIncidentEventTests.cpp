// Severity-resolver tests for the permanent-device-missing detector reaction.
//
// These tests call the SAME production function the incident handler calls
// (fic::daemon::resolve_device_missing_severity) with a temporary module
// configuration, so the contract is proven against the real code, not against
// a reimplementation.
#include "daemon/DeviceIncidentEvent.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include <fic/core/incident/IncidentSeverity.h>
#include <fic/core/config/ModuleConfigFileHandler.h>
#include <fic/core/runtime/FicRuntimePaths.h>

#include "modules/dc/DC.h"

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAILED: " << message << "\n";
        std::exit(1);
    }
}

namespace fs = std::filesystem;
using fic::daemon::DeviceMissingReaction;
using fic::daemon::DeviceMissingReactionKind;
using fic::core::IncidentSeverity;

class TempConfigDir {
public:
    TempConfigDir() {
        char pattern[] = "/tmp/fic-device-severity-XXXXXX";
        char* created = ::mkdtemp(pattern);
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        root_ = created;
    }
    ~TempConfigDir() {
        std::error_code ignored;
        fs::remove_all(root_, ignored);
    }
    const fs::path& dir() const { return root_; }

    void writeDcConf(const std::string& content) {
        std::ofstream output(root_ / "DC.conf", std::ios::trunc);
        output << content;
    }

private:
    fs::path root_;
};

DeviceMissingReaction resolveWith(const TempConfigDir& dir) {
    // The production policy class, reading the SAME configuration layout the
    // daemon uses: the runtime config dir was pointed at the temp directory
    // once, and each scenario rewrites DC.conf in place before resolving.
    DC_permanent_device_missing_severity policy;
    return fic::daemon::resolve_device_missing_severity(policy);
}

} // namespace
int main() {
    TempConfigDir dir;
    // The runtime config dir is initialized ONCE for the whole run; each
    // scenario rewrites DC.conf in place, because the paths singleton cannot
    // be re-initialized.
    {
        fic::core::FicProductPaths paths = fic::core::FicProductPaths::production();
        paths.configDir = dir.dir();
        paths.languageDir = dir.dir() / "lang";
        std::string error;
        require(fic::core::FicRuntimePaths::initialize(paths, error), error);
    }

    {
        dir.writeDcConf("_schema_version=1\n");
        std::vector<std::unique_ptr<Policy>> categories;
        categories.push_back(std::make_unique<DC_block_usb_storage>());
        categories.push_back(std::make_unique<DC_block_printers_scanners>());
        categories.push_back(std::make_unique<DC_block_optical_drives>());
        for (const auto& policy : categories) {
            require(policy->getDefaultValue() == "all", "DC default must be all");
            require(policy->validate("all") && policy->validate("new") &&
                    !policy->validate("true") && !policy->validate("disabled"),
                    "category value must be independent from ENABLE/DISABLE");
            const auto editor = policy->getPolicyTypeValue().getEditorSpec();
            require(editor.editor == "combobox" &&
                    editor.possibleValues == std::vector<std::string>{"all", "new"},
                    "CLI/GUI metadata must expose all/new select");
        }
    }

    // G1: ENABLE + STANDARD -> the configured severity.
    {
        dir.writeDcConf(
            "_schema_version=1\n"
            "permanent_device_missing_severity.status=ENABLE\n"
            "permanent_device_missing_severity.value=STANDARD\n");
        const auto reaction = resolveWith(dir);
        require(reaction.kind == DeviceMissingReactionKind::Severity,
                "ENABLE + STANDARD must resolve to the severity");
        require(reaction.severity == IncidentSeverity::Standard,
                "ENABLE + STANDARD must be STANDARD");
    }

    // G2: ENABLE + NONE -> an intentional ignore, never ISOLATE.
    {
        dir.writeDcConf(
            "_schema_version=1\n"
            "permanent_device_missing_severity.status=ENABLE\n"
            "permanent_device_missing_severity.value=NONE\n");
        const auto reaction = resolveWith(dir);
        require(reaction.kind == DeviceMissingReactionKind::None,
                "ENABLE + NONE must be an intentional ignore");
        require(reaction.severity == IncidentSeverity::Unlocked,
                "NONE must not raise");
    }

    // G3: proven DISABLE -> an intentional ignore.
    {
        dir.writeDcConf(
            "_schema_version=1\n"
            "permanent_device_missing_severity.status=DISABLE\n"
            "permanent_device_missing_severity.value=STANDARD\n");
        const auto reaction = resolveWith(dir);
        require(reaction.kind == DeviceMissingReactionKind::Disabled,
                "proven DISABLE must be an intentional ignore");
    }

    // G4: ENABLE + an invalid value -> FAIL CLOSED to ISOLATE (R1).
    {
        dir.writeDcConf(
            "_schema_version=1\n"
            "permanent_device_missing_severity.status=ENABLE\n"
            "permanent_device_missing_severity.value=INVALID\n");
        const auto reaction = resolveWith(dir);
        require(reaction.kind == DeviceMissingReactionKind::Unproven,
                "an invalid value must be UNPROVEN, not an intentional ignore");
        require(reaction.severity == IncidentSeverity::Isolate,
                "an invalid value must fail closed to ISOLATE");
        require(reaction.diagnostic.find("fail-closed") != std::string::npos,
                "the diagnostic must name the fail-closed reaction");
    }

    // R1: a MISSING value entry -> fail closed.
    {
        dir.writeDcConf(
            "_schema_version=1\n"
            "permanent_device_missing_severity.status=ENABLE\n");
        const auto reaction = resolveWith(dir);
        require(reaction.kind == DeviceMissingReactionKind::Unproven,
                "a missing value must be UNPROVEN");
        require(reaction.severity == IncidentSeverity::Isolate,
                "a missing value must fail closed to ISOLATE");
    }

    // G6: a malformed status must NOT be read as a proven DISABLE.
    {
        dir.writeDcConf(
            "_schema_version=1\n"
            "permanent_device_missing_severity.status=BROKEN\n"
            "permanent_device_missing_severity.value=STANDARD\n");
        const auto reaction = resolveWith(dir);
        require(reaction.kind == DeviceMissingReactionKind::Unproven,
                "a malformed status must not be read as DISABLE");
        require(reaction.severity == IncidentSeverity::Isolate,
                "a malformed status must fail closed to ISOLATE");
    }

    std::cout << "Device incident severity resolver contract proven\n";
    return 0;
}
