// Step 7F REAL distro gate driver: drives the PRODUCTION managed provider
// components (PamProviderManagedEntryExecutor, PamProviderManagedFlagExecutor,
// PamProviderRollback, PamProviderPackageRelease) against the REAL
// /etc/security provider primaries with the compiled-in production platform
// profile (makeBuildPlatformProfile) and a real daemon mutation journal.
//
// Built on demand INSIDE a disposable container as root by
// tests/integration/pam-c2/pam_provider_rollback_gate.sh. NOT a CTest; must
// never run against a real host policy state outside the gate harness.
#include "modules/identity_access/pam/PamProviderCatalog.h"
#include "modules/identity_access/pam/PamProviderManagedBlock.h"
#include "modules/identity_access/pam/PamProviderManagedEntryExecutor.h"
#include "modules/identity_access/pam/PamProviderManagedFlagExecutor.h"
#include "modules/identity_access/pam/PamProviderPackageRelease.h"
#include "modules/identity_access/pam/PamProviderRollback.h"
#include "modules/identity_access/pam/PasswdqcConfigFile.h"
#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamProviderSemanticVerifier.h"
#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamProviderManagedLock.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"
#include "platform/PlatformProfile.h"
#include "rollback/MutationJournal.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

using namespace fic::identity::pam;
namespace fr = fic::rollback;
namespace fp = fic::platform;

namespace {

const char* kJournalPath = "/var/lib/fic/pam-provider-gate/mutation-journal.json";

// Canonical FIC policy identity for a routed binding feature (same SSOT
// table production uses). The driver never invents synthetic policy names:
// journal records, physical markers and the orphan no-journal inspection
// must address identical policy identities.
std::string managedPolicyName(const fp::PamPolicyFeature& feature) {
    const char* name = pamProviderManagedFeaturePolicyName(feature);
    if (name == nullptr) {
        std::cerr << "binding feature is not a managed provider policy\n";
        std::exit(3);
    }
    return name;
}

std::string readFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

void writeFile(const std::filesystem::path& path, const std::string& content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << content;
}

// Active (non-comment, non-FIC) occurrences of a managed key line.
std::vector<std::string> activeOccurrences(const std::string& content,
                                           const std::string& key) {
    std::vector<std::string> found;
    std::size_t position = 0;
    while (position <= content.size()) {
        const std::size_t end = content.find('\n', position);
        std::string line = content.substr(
            position, end == std::string::npos ? std::string::npos
                                               : end - position);
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        const std::size_t first = line.find_first_not_of(" \t");
        const std::string trimmed =
            first == std::string::npos ? std::string() : line.substr(first);
        const bool isFic = trimmed.find("FIC_PAM_") != std::string::npos;
        const bool isComment = !trimmed.empty() && trimmed[0] == '#';
        if (!isFic && !isComment &&
            (trimmed == key || trimmed.rfind(key + " =", 0) == 0 ||
             trimmed.rfind(key + "=", 0) == 0)) {
            found.push_back(trimmed);
        }
        if (end == std::string::npos) {
            break;
        }
        position = end + 1;
    }
    return found;
}

struct Context {
    fp::PlatformProfile profile = fp::makeBuildPlatformProfile();
    fr::MutationJournal journal{kJournalPath};
    PamProviderRollbackOptions rollbackOptions;

    Context() {
        rollbackOptions.platform = profile.pam;
        std::string error;
        std::filesystem::create_directories(
            std::filesystem::path(kJournalPath).parent_path());
        PamProviderManagedLock::setLockFilePathForTests(
            std::filesystem::path(kJournalPath).parent_path() / "managed-provider.lock");
        if (!journal.initializeOrLoad(error)) {
            std::cerr << "journal init failed: " << error << "\n";
            std::exit(2);
        }
    }

    const fp::PamCapabilityConfig* capability(
        fp::PamProviderKind kind) const {
        for (const fp::PamCapabilityConfig& capability :
             profile.pam.capabilities) {
            if (capability.provider == kind &&
                capability.configurationMode ==
                    fp::PamCapabilityConfigurationMode::ProviderConfigFile) {
                return &capability;
            }
        }
        return nullptr;
    }

    const PamProviderDescriptor* descriptor(const std::string& name) const {
        for (const PamProviderDescriptor& candidate :
             pamProviderDescriptors()) {
            if (name == candidate.name) {
                return &candidate;
            }
        }
        return nullptr;
    }

    // Resolves the FULL typed apply/route context for one option of one
    // provider through the SSOT helpers (never hardcoded in the driver).
    bool resolve(const std::string& providerName, const std::string& option,
                 const PamProviderDescriptor** descriptor,
                 const PamProviderPolicyBinding** binding,
                 const fp::PamCapabilityConfig** capability,
                 PamProviderBlockPlacementRequest* placement,
                 fp::PamPolicyFeature* feature, std::string& error) const {
        *descriptor = this->descriptor(providerName);
        if (*descriptor == nullptr) {
            error = "unknown provider: " + providerName;
            return false;
        }
        for (const PamProviderPolicyBinding& candidate :
             (*descriptor)->policies) {
            if (candidate.option == option) {
                *binding = &candidate;
                *feature = candidate.feature;
                break;
            }
        }
        if (*binding == nullptr) {
            error = "unknown option: " + option;
            return false;
        }
        *capability = this->capability((*descriptor)->kind);
        if (*capability == nullptr) {
            error = "provider is not a ProviderConfigFile capability on "
                    "this platform: " +
                providerName;
            return false;
        }
        const std::optional<PamProviderBlockPlacementRequest> derived =
            pamProviderManagedEntryPlacement(**descriptor, **capability,
                                             **binding, *feature);
        if (!derived.has_value()) {
            error = "option is NOT routed through the managed provider "
                    "configuration on this platform: " +
                option;
            return false;
        }
        *placement = *derived;
        return true;
    }
};

bool verifyEffectiveEntry(const Context& context,
                          const fp::PamCapabilityConfig& capability,
                          PamProviderBlockPlacementRequest placement,
                          const std::string& key,
                          const std::string& expectedNativeValue,
                          std::string& error) {
    if (capability.provider == fp::PamProviderKind::PamPasswdqc) {
        if (!PasswdqcConfigFile::hasEffectiveValue(capability.configPath,
                key, expectedNativeValue, error)) return false;
        PamConfiguration configuration(context.profile.pam);
        PamCapabilityVerification proof;
        if (!PamCapabilityVerifier::verify(configuration, context.profile.pam,
                scopeConfig(context.profile.pam, capability.scope)->services,
                capability.capability, capability.provider, proof)) {
            error = formatPamCapabilityVerification(proof); return false;
        }
        return PamProviderSemanticVerifier::verifyOption(proof.inspection,
            capability, key, expectedNativeValue, error);
    }
    const std::string content = readFile(capability.configPath);
    const std::vector<std::string> occurrences =
        activeOccurrences(content, key);
    if (occurrences.empty()) {
        error = "no active occurrence of " + key + " in " +
                capability.configPath.string();
        return false;
    }
    const std::string expected = key + " = " + expectedNativeValue;
    const std::string& effective =
        placement == PamProviderBlockPlacementRequest::Beginning
            ? occurrences.front()
            : occurrences.back();
    if (effective != expected) {
        error = "effective " + key + " is '" + effective +
                "', expected '" + expected + "'";
        return false;
    }
    (void)context;
    return true;
}

bool verifyEffectiveFlag(const Context& context,
                         const fp::PamCapabilityConfig& capability,
                         const std::string& key, bool expectedEnabled,
                         std::string& error) {
    const std::vector<std::string> occurrences =
        activeOccurrences(readFile(capability.configPath), key);
    if (expectedEnabled && occurrences.empty()) {
        error = "flag " + key + " is not effective (no active occurrence)";
        return false;
    }
    if (!expectedEnabled && !occurrences.empty()) {
        error = "flag " + key + " is still active";
        return false;
    }
    (void)context;
    return true;
}

const fr::MutationRecord* activeRecord(const Context& context,
                                       const std::string& policyName) {
    for (const fr::MutationRecord& record : context.journal.records()) {
        if (record.policy.moduleName == "IDENTITY_ACCESS" &&
            record.policy.policyName == policyName && record.isActive()) {
            return &record;
        }
    }
    return nullptr;
}

int cmdReport(const Context& context) {
    for (const fp::PamCapabilityConfig& capability :
         context.profile.pam.capabilities) {
        if (capability.configurationMode ==
            fp::PamCapabilityConfigurationMode::ProviderConfigFile) {
            std::cout << "CONFIG " << static_cast<int>(capability.provider) << " "
                      << capability.configPath.string() << "\n";
        }
    }
    std::string message;
    for (const PamProviderDescriptor& descriptor :
         pamProviderDescriptors()) {
        for (const PamProviderPolicyBinding& binding : descriptor.policies) {
            const std::optional<PamProviderRollbackRoute> route =
                pamProviderRollbackRouteForFeature(context.rollbackOptions,
                                                   binding.feature, message);
            std::cout << "ROUTE " << descriptor.name << " "
                      << binding.option << " "
                      << (route.has_value() ? "routed" : "not-routed")
                      << "\n";
        }
    }
    return 0;
}

int cmdApply(Context& context, const std::string& providerName,
             const std::string& option, const std::string& value) {
    const PamProviderDescriptor* descriptor = nullptr;
    const PamProviderPolicyBinding* binding = nullptr;
    const fp::PamCapabilityConfig* capability = nullptr;
    PamProviderBlockPlacementRequest placement =
        PamProviderBlockPlacementRequest::End;
    fp::PamPolicyFeature feature = fp::PamPolicyFeature::PasswordMinLength;
    std::string error;
    if (!context.resolve(providerName, option, &descriptor, &binding,
                         &capability, &placement, &feature, error)) {
        std::cerr << "apply refused: " << error << "\n";
        return 3;
    }
    PamProviderManagedEntryRequest request;
    request.policyName = managedPolicyName(feature);
    request.provider = descriptor->kind;
    request.providerName = descriptor->name;
    request.managedKey = binding->option;
    request.nativeValue = value;
    request.configPath = capability->configPath;
    request.placement = placement;
    request.absentDecision =
        pamProviderAbsentContainerDecision(*descriptor);
    // Integration-only fault injection over production atomic/CAS primitives.
    const char* faultValue = std::getenv("FIC_PROVIDER_GATE_FAULT");
    const std::string fault = faultValue ? faultValue : "";
    if (fault == "primary-cas") {
        AtomicFileWriter::setPreInstallHookForTests(
            [path = capability->configPath.string()](const std::string& target) {
                if (target == path) {
                    std::ofstream admin(path, std::ios::app); admin << "# concurrent admin\n";
                }
            });
    }
    if (fault == "primary-fsync" || fault == "journal-fsync") {
        const std::string target = fault == "primary-fsync"
            ? capability->configPath.string() : kJournalPath;
        AtomicFileWriter::setDirectoryFsyncHookForTests(
            [target](const std::string& path) { return path != target; });
    }
    PamProviderManagedEntryOutcome outcome;
    if (!PamProviderManagedEntryExecutor::apply(
            request, context.journal,
            [&](const std::string& expectedNativeValue, std::string& error) {
                if (fault == "semantic") { error = "injected post-write semantic failure"; return false; }
                if (fault == "applied-fsync") {
                    AtomicFileWriter::setDirectoryFsyncHookForTests(
                        [](const std::string& path) { return path != kJournalPath; });
                }
                return verifyEffectiveEntry(context, *capability, placement,
                                            binding->option,
                                            expectedNativeValue, error);
            },
            outcome, error)) {
        std::cerr << "apply failed: " << error << "\n";
        return 1;
    }
    std::cout << "applied " << option << "=" << value << " outcome="
              << (outcome == PamProviderManagedEntryOutcome::Applied
                      ? "Applied"
                      : "AppliedNoOp")
              << "\n";
    return 0;
}

int cmdApplyFlag(Context& context, const std::string& providerName,
                 const std::string& option, bool enabled) {
    const PamProviderDescriptor* descriptor = nullptr;
    const PamProviderPolicyBinding* binding = nullptr;
    const fp::PamCapabilityConfig* capability = nullptr;
    PamProviderBlockPlacementRequest placement =
        PamProviderBlockPlacementRequest::End;
    fp::PamPolicyFeature feature = fp::PamPolicyFeature::PasswordMinLength;
    std::string error;
    if (!context.resolve(providerName, option, &descriptor, &binding,
                         &capability, &placement, &feature, error)) {
        std::cerr << "apply-flag refused: " << error << "\n";
        return 3;
    }
    PamProviderManagedFlagRequest request;
    request.policyName = managedPolicyName(feature);
    request.provider = descriptor->kind;
    request.providerName = descriptor->name;
    request.managedKey = binding->option;
    request.expectedEnabled = enabled;
    request.configPath = capability->configPath;
    request.placement = placement;
    PamProviderManagedEntryOutcome outcome;
    if (!PamProviderManagedFlagExecutor::apply(
            request, context.journal,
            [&](bool expectedEnabled, std::string& error) {
                return verifyEffectiveFlag(context, *capability,
                                           binding->option, expectedEnabled,
                                           error);
            },
            outcome, error)) {
        std::cerr << "apply-flag failed: " << error << "\n";
        return 1;
    }
    std::cout << "applied flag " << option << "="
              << (enabled ? "true" : "false") << "\n";
    return 0;
}

// Canonical policy identity of a routed option, resolved through the same
// descriptor SSOT as apply (the disable path never fabricates identities).
std::string policyNameForOption(const Context& context,
                                const std::string& providerName,
                                const std::string& option) {
    const PamProviderDescriptor* descriptor = context.descriptor(providerName);
    if (descriptor == nullptr) {
        std::cerr << "unknown provider: " << providerName << "\n";
        std::exit(3);
    }
    for (const PamProviderPolicyBinding& binding : descriptor->policies) {
        if (binding.option == option) {
            return managedPolicyName(binding.feature);
        }
    }
    std::cerr << "unknown option: " << option << "\n";
    std::exit(3);
}

int cmdDisableEntry(Context& context, const std::string& providerName,
                    const std::string& option) {
    const std::string policyName =
        policyNameForOption(context, providerName, option);
    const fr::MutationRecord* record = activeRecord(context, policyName);
    if (record == nullptr) {
        const PamProviderRollbackResult orphan =
            inspectUnrecordedPamProviderManagedState(context.rollbackOptions,
                                                    policyName);
        if (orphan.conflict) {
            std::cerr << "orphan FIC state without journal provenance: "
                      << orphan.message << "\n";
            return 1;
        }
        std::cout << "disable " << option << ": NothingToDo (no record, no "
                  << "physical FIC state)\n";
        return 0;
    }
    const PamProviderRollbackResult result = undoPamProviderManagedEntry(
        context.rollbackOptions, context.journal, *record,
        std::get<fr::UndoRemovePamProviderManagedEntry>(record->undo.payload));
    if (result.ok) {
        // Production lifecycle contract (docs/rollback.md): the OUTER
        // RollbackExecutor marks the policy record RolledBack after a
        // successful undo. The driver reproduces this exactly, otherwise
        // the record stays active and a later fresh apply of the same
        // identity is refused as AppliedDrifted.
        std::string statusError;
        if (!context.journal.setStatus(record->id,
                                       fr::MutationStatus::RolledBack,
                                       statusError)) {
            std::cerr << "disable " << option
                      << ": journal RolledBack resolution failed: "
                      << statusError << "\n";
            return 1;
        }
    }
    std::cout << "disable " << option << ": ok=" << result.ok
              << (result.nothingToDo ? " nothingToDo" : "")
              << (result.conflict ? " conflict" : "") << " "
              << result.message << "\n";
    return result.ok ? 0 : 1;
}

int cmdDisableFlag(Context& context, const std::string& providerName,
                   const std::string& option) {
    const std::string policyName =
        policyNameForOption(context, providerName, option);
    const fr::MutationRecord* record = activeRecord(context, policyName);
    if (record == nullptr) {
        const PamProviderRollbackResult orphan =
            inspectUnrecordedPamProviderManagedState(context.rollbackOptions,
                                                    policyName);
        if (orphan.conflict) {
            std::cerr << "orphan FIC state without journal provenance: "
                      << orphan.message << "\n";
            return 1;
        }
        std::cout << "disable-flag " << option << ": NothingToDo\n";
        return 0;
    }
    const PamProviderRollbackResult result = undoPamProviderManagedFlag(
        context.rollbackOptions, context.journal, *record,
        std::get<fr::UndoRemovePamProviderManagedFlag>(record->undo.payload));
    if (result.ok) {
        // Production lifecycle contract (docs/rollback.md): the OUTER
        // RollbackExecutor marks the policy record RolledBack after a
        // successful undo. The driver reproduces this exactly, otherwise
        // the record stays active and a later fresh apply of the same
        // identity is refused as AppliedDrifted.
        std::string statusError;
        if (!context.journal.setStatus(record->id,
                                       fr::MutationStatus::RolledBack,
                                       statusError)) {
            std::cerr << "disable-flag " << option
                      << ": journal RolledBack resolution failed: "
                      << statusError << "\n";
            return 1;
        }
    }
    std::cout << "disable-flag " << option << ": ok=" << result.ok
              << (result.nothingToDo ? " nothingToDo" : "")
              << (result.conflict ? " conflict" : "") << " "
              << result.message << "\n";
    return result.ok ? 0 : 1;
}

int cmdRelease(Context& context, PamProviderPackageRelease::Mode mode) {
    PamProviderPackageRelease::Options options;
    options.lockFilePath = PamProviderManagedLock::lockFilePath();
    if (const char* fault = std::getenv("FIC_PROVIDER_GATE_FAULT");
        fault && std::string(fault) == "journal-fsync") {
        AtomicFileWriter::setDirectoryFsyncHookForTests(
            [](const std::string& path) { return path != kJournalPath; });
    }
    PamProviderPackageRelease release(context.journal, context.profile.pam,
                                      options);
    PamProviderPackageRelease::Report report;
    std::string error;
    if (!release.run(mode, report, error)) {
        std::cerr << "package provider "
                  << (mode == PamProviderPackageRelease::Mode::Preflight
                          ? "preflight"
                          : "release")
                  << " failed: " << error << "\n";
        return 1;
    }
    std::cout << "package provider "
              << (mode == PamProviderPackageRelease::Mode::Preflight
                      ? "preflight"
                      : "release")
              << " ok: released=" << report.releasedRecords.size()
              << " deleted=" << report.containersDeleted.size()
              << " detached=" << report.containersDetached.size()
              << "\n";
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0]
                  << " report|apply <provider> <option> <value>|"
                     "apply-flag <provider> <option> true|false|"
                     "disable <provider> <option>|"
                     "disable-flag <provider> <option>|"
                     "preflight|release\n";
        return 2;
    }
    Context context;
    const std::string command = argv[1];
    if (command == "hold-lock" && argc == 2) {
        PamProviderManagedLock::Handle lock; std::string error;
        if (!PamProviderManagedLock::tryAcquire(lock, error)) return 1;
        std::cout << "locked" << std::endl;
        std::cin.get(); return 0;
    }
    if (command == "report" && argc == 2) {
        return cmdReport(context);
    }
    if (command == "apply" && argc == 5) {
        return cmdApply(context, argv[2], argv[3], argv[4]);
    }
    if (command == "apply-flag" && argc == 5) {
        const std::string value = argv[4];
        if (value != "true" && value != "false") {
            std::cerr << "flag value must be true|false\n";
            return 2;
        }
        return cmdApplyFlag(context, argv[2], argv[3], value == "true");
    }
    if (command == "disable" && argc == 4) {
        return cmdDisableEntry(context, argv[2], argv[3]);
    }
    if (command == "disable-flag" && argc == 4) {
        return cmdDisableFlag(context, argv[2], argv[3]);
    }
    if (command == "preflight" && argc == 2) {
        return cmdRelease(context, PamProviderPackageRelease::Mode::Preflight);
    }
    if (command == "release" && argc == 2) {
        return cmdRelease(context, PamProviderPackageRelease::Mode::Release);
    }
    std::cerr << "bad arguments\n";
    return 2;
}
