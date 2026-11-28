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
#include <algorithm>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

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

    // ---- The two newer detector severity policies --------------------------
    // They are independent settings with their own factory values, so an
    // operator can react to forbidden static hardware differently from a
    // failed dynamic block.
    {
        DC_static_device_present_severity staticPolicy;
        DC_device_block_failed_severity blockPolicy;
        require(staticPolicy.getDefaultValue() == "NONE",
                "static_device_present_severity factory default must be NONE");
        require(blockPolicy.getDefaultValue() == "STANDARD",
                "device_block_failed_severity factory default must be "
                "STANDARD");
        const auto staticEditor =
            staticPolicy.getPolicyTypeValue().getEditorSpec();
        const auto blockEditor = blockPolicy.getPolicyTypeValue().getEditorSpec();
        const std::vector<std::string> tokens{
            "NONE", "SOFT", "STANDARD", "HARD", "ISOLATE"};
        auto containsAll = [&tokens](const std::vector<std::string>& values) {
            for (const std::string& token : tokens) {
                if (std::find(values.begin(), values.end(), token) ==
                    values.end())
                    return false;
            }
            return true;
        };
        require(containsAll(staticEditor.possibleValues),
                "the static severity policy must offer every severity token");
        require(containsAll(blockEditor.possibleValues),
                "the block-failure severity policy must offer every severity "
                "token");
    }

    const auto resolveKind = [](fic::ipc::DeviceIncidentKind kind) {
        const auto spec = fic::daemon::device_incident_severity_spec(kind);
        if (kind == fic::ipc::DeviceIncidentKind::StaticDevicePresent) {
            DC_static_device_present_severity policy;
            return fic::daemon::resolve_device_incident_severity(policy, spec);
        }
        DC_device_block_failed_severity policy;
        return fic::daemon::resolve_device_incident_severity(policy, spec);
    };

    // An installation upgraded from a configuration written before these
    // policies existed has NO entry at all: the packaged factory value
    // applies instead of a fail-closed ISOLATE.
    {
        dir.writeDcConf("_schema_version=1\n");
        const auto staticReaction =
            resolveKind(fic::ipc::DeviceIncidentKind::StaticDevicePresent);
        require(staticReaction.kind == DeviceMissingReactionKind::None,
                "an absent static severity policy must use the factory NONE");
        require(staticReaction.severity == IncidentSeverity::Unlocked,
                "factory NONE must not raise");
        const auto blockReaction =
            resolveKind(fic::ipc::DeviceIncidentKind::DeviceBlockFailed);
        require(blockReaction.kind == DeviceMissingReactionKind::Severity,
                "an absent block-failure policy must use the factory STANDARD");
        require(blockReaction.severity == IncidentSeverity::Standard,
                "factory STANDARD must resolve to STANDARD");

        // The permanent-device setting keeps its original fail-closed
        // behaviour for an absent entry.
        DC_permanent_device_missing_severity permanent;
        const auto permanentReaction =
            fic::daemon::resolve_device_missing_severity(permanent);
        require(permanentReaction.kind == DeviceMissingReactionKind::Unproven,
                "an absent permanent_device_missing_severity must stay "
                "unproven");
        require(permanentReaction.severity == IncidentSeverity::Isolate,
                "an absent permanent_device_missing_severity must fail closed");
    }

    // Every allowed token of the new policies maps to the documented reaction.
    {
        struct Case {
            const char* value;
            DeviceMissingReactionKind kind;
            IncidentSeverity severity;
        };
        const Case cases[] = {
            {"NONE", DeviceMissingReactionKind::None, IncidentSeverity::Unlocked},
            {"SOFT", DeviceMissingReactionKind::Severity, IncidentSeverity::Soft},
            {"STANDARD", DeviceMissingReactionKind::Severity,
             IncidentSeverity::Standard},
            {"HARD", DeviceMissingReactionKind::Severity, IncidentSeverity::Hard},
            {"ISOLATE", DeviceMissingReactionKind::Severity,
             IncidentSeverity::Isolate}};
        const std::pair<const char*, fic::ipc::DeviceIncidentKind> policies[] = {
            {"static_device_present_severity",
             fic::ipc::DeviceIncidentKind::StaticDevicePresent},
            {"device_block_failed_severity",
             fic::ipc::DeviceIncidentKind::DeviceBlockFailed}};
        for (const auto& [policyName, incidentKind] : policies) {
            for (const Case& testCase : cases) {
                dir.writeDcConf(std::string("_schema_version=1\n") + policyName +
                                ".status=ENABLE\n" + policyName + ".value=" +
                                testCase.value + "\n");
                const auto reaction = resolveKind(incidentKind);
                require(reaction.kind == testCase.kind,
                        std::string(policyName) + "=" + testCase.value +
                            " produced the wrong reaction kind");
                require(reaction.severity == testCase.severity,
                        std::string(policyName) + "=" + testCase.value +
                            " produced the wrong severity");
            }

            // A proven DISABLE is an intentional ignore.
            dir.writeDcConf(std::string("_schema_version=1\n") + policyName +
                            ".status=DISABLE\n" + policyName +
                            ".value=STANDARD\n");
            const auto disabled = resolveKind(incidentKind);
            require(disabled.kind == DeviceMissingReactionKind::Disabled,
                    std::string(policyName) + " DISABLE must be recognized");

            // A malformed status still fails closed.
            dir.writeDcConf(std::string("_schema_version=1\n") + policyName +
                            ".status=BROKEN\n" + policyName +
                            ".value=STANDARD\n");
            const auto broken = resolveKind(incidentKind);
            require(broken.kind == DeviceMissingReactionKind::Unproven,
                    std::string(policyName) +
                        " with a malformed status must stay unproven");
            require(broken.severity == IncidentSeverity::Isolate,
                    std::string(policyName) +
                        " with a malformed status must fail closed");

            // A present status without a value is unproven, not a factory
            // default: the fallback only applies to a COMPLETELY absent policy.
            dir.writeDcConf(std::string("_schema_version=1\n") + policyName +
                            ".status=ENABLE\n");
            const auto missingValue = resolveKind(incidentKind);
            require(missingValue.kind == DeviceMissingReactionKind::Unproven,
                    std::string(policyName) +
                        " with a missing value must stay unproven");
        }
    }

    std::cout << "Device incident severity resolver contract proven\n";
    return 0;
}
