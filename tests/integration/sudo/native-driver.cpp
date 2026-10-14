#include "modules/dac/sudo/SudoersAuthenticationTransaction.h"
#include "modules/dac/sudo/policies/DAC_sudo_require_authentication.h"
#include "modules/dac/sudo/SudoersGlobalDefaultsTransaction.h"
#include "modules/dac/sudo/SudoProviderCapabilities.h"
#include "modules/dac/sudo/policies/DAC_sudo_env_reset.h"
#include "modules/dac/sudo/policies/DAC_sudo_passwd_tries.h"
#include "modules/dac/sudo/policies/DAC_sudo_securepath.h"
#include "modules/dac/sudo/policies/DAC_sudo_timeout.h"
#include "modules/dac/sudo/policies/DAC_sudo_exempt_group_disable.h"
#include "modules/dac/sudo/policies/DAC_sudo_disable_scoped_defaults.h"
#include "modules/dac/sudo/SudoersScopedDefaultsTransaction.h"
#include "rollback/DaemonMutationJournal.h"

#include <fic/core/config/ModuleConfigFileHandler.h>
#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/runtime/FicRuntimePaths.h>

#include <fstream>
#include <iostream>
#include <map>
#include <sys/stat.h>
#include <unistd.h>

using namespace fic::sudoers;
using namespace fic::rollback;

int main(int argc, char** argv) {
    if (::getuid() != 0 || !std::filesystem::exists("/run/.containerenv")) {
        std::cerr << "Container-only native driver; host execution refused\n";
        return 77;
    }
    if (argc < 2) return 2;
    const std::string action = argv[1];
    const auto platform = fic::platform::makeBuildPlatformProfile();
    fic::platform::PlatformExecutableResolver executables(platform.executables);
    const std::filesystem::path root = "/var/lib/fic-sudo-native-test";
    auto paths = fic::core::FicProductPaths::production();
    paths.configDir = root / "config";
    paths.logDir = root / "log";
    paths.dataDir = root / "state";
    paths.notifyDir = root / "notify";
    paths.runtimeDir = root / "run";
    paths.commandHashFile = root / "command-hashes";
    paths.mutationJournalFile = root / "journal.json";
    for (const auto& directory : {paths.configDir, paths.logDir, paths.dataDir,
                                 paths.notifyDir, paths.runtimeDir})
        std::filesystem::create_directories(directory);
    std::string error;
    if (!fic::core::FicRuntimePaths::initialize(paths, error)) {
        std::cerr << error << '\n'; return 1;
    }
    std::filesystem::path sudo, visudo;
    if (!executables.resolve(fic::platform::ExecutableId::Sudo, sudo, error) ||
        !executables.resolve(fic::platform::ExecutableId::Visudo, visudo, error) ||
        !CommandHashStore::saveHashes({sudo.string(), visudo.string()}, error)) {
        std::cerr << error << '\n'; return 1;
    }
    SudoProviderCapabilities capabilities;
    if (!detectSudoProviderCapabilities(platform.sudo, executables, capabilities, error)) {
        std::cerr << error << '\n'; return 1;
    }
    std::cout << "provider=" << (capabilities.provider == SudoProvider::Rust ? "sudo-rs" : "classic")
              << " version=" << capabilities.version << " config=" << capabilities.mainPath
              << " validator=" << capabilities.validator << '\n';
    if (action == "provider") return 0;
    if (argc < 3) return 2;
    const std::string name = argv[2];
    const std::map<std::string, std::string> keys{
        {"sudo_env_reset", "env_reset"}, {"sudo_passwd_tries", "passwd_tries"},
        {"sudo_securepath", "secure_path"}, {"sudo_timeout", "timestamp_timeout"},
        {"sudo_exempt_group_disable", "exempt_group"},
        {"sudo_disable_scoped_defaults", "scoped_defaults"},
        {"sudo_require_authentication", kAuthenticationResource}};
    if (!keys.count(name)) return 2;
    if (!std::filesystem::exists(paths.configDir / "DAC.conf")) {
        std::ofstream config(paths.configDir / "DAC.conf");
        config << "_schema_version=1\n";
        for (const auto& [policy, key] : keys) {
            (void)key;
            const std::string value = (policy == "sudo_disable_scoped_defaults" || policy == kAuthenticationPolicy) ? "ENABLE"
                : policy == "sudo_exempt_group_disable" ? "DISABLE"
                : policy == "sudo_env_reset" ? "ENABLE"
                : policy == "sudo_securepath" ? platform.sudo.securePathDefault
                : policy == "sudo_timeout" ? "10" : "3";
            config << policy << ".status=" << (policy == kAuthenticationPolicy ? "DISABLE" : "ENABLE") << "\n" << policy << ".value=" << value << '\n';
        }
    }
    if (!std::filesystem::exists(paths.configDir / "AUDIT.conf")) {
        std::ofstream audit(paths.configDir / "AUDIT.conf");
        audit << "_schema_version=1\nlog_level.status=ENABLE\nlog_level.value=ERROR\n";
    }
    auto* journal = DaemonMutationJournal::instance().tryGet(error);
    if (!journal) { std::cerr << error << '\n'; return 1; }
    const auto finishDisable = [&name] {
        ModuleConfigFileHandler config("DAC");
        return config.loadConfig() && config.setPolicyStatus(name, "DISABLE") && config.saveConfig();
    };
    const PolicyRef identity{"DAC", "SudoEdit", name};
    if (action == "intent" && argc == 4) {
        ModuleConfigFileHandler config("DAC");
        return config.loadConfig() && config.setPolicyStatus(name, argv[3]) && config.saveConfig() ? 0 : 1;
    }

    if (action == "release" || action == "crash-release" || action == "crash-apply") {
        const std::lock_guard<std::mutex> lock(SudoersConfiguration::mutationMutex());
        SudoersConfigurationOptions options;
        options.mainPath = platform.sudo.mainConfigPath;
        options.managedPath = platform.sudo.managedConfigPath;
        options.managedFileMode = platform.sudo.managedFileMode;
        options.validatorPath = visudo.string();
        options.requireValidator = true;
        options.verifyProviderUnchanged = [&platform, &executables, capabilities](std::string& error) {
            SudoProviderCapabilities current;
            if (!detectSudoProviderCapabilities(platform.sudo, executables, current, error)) return false;
            if (current.provider != capabilities.provider || current.version != capabilities.version ||
                current.executable != capabilities.executable || current.validator != capabilities.validator) {
                error = "Native provider changed during release";
                return false;
            }
            return true;
        };
        options.releaseOwnedUnsupportedSetting = capabilities.provider == SudoProvider::Rust &&
                                                keys.at(name) == "exempt_group";
        if (name == kAuthenticationPolicy) {
            if ((action == "crash-apply" && argc != 5) || (action == "crash-release" && argc != 4)) return 2;
            AuthenticationHooks hooks;
            hooks.requestedScopedState = [](bool& scoped, std::string& error) { bool auth; return readSudoRequestedState(auth, scoped, error); };
            if (action != "release") {
                const auto phase = std::string(argv[action == "crash-apply" ? 4 : 3]);
                hooks.checkpoint = [phase](const char* reached) { if (phase == reached) ::_exit(86); };
            }
            AuthenticationTransaction auth(options, *journal, hooks);
            if (action == "crash-apply") {
                const auto result = auth.reconcile(); std::cerr << result.message << '\n'; return result.ok ? 0 : 1;
            }
            const auto records = journal->activeRecords(identity);
            if (records.empty()) {
                if (!auth.verifyOwnership(error)) { std::cerr << error << '\n'; return 1; }
                return finishDisable() ? 0 : 1;
            }
            if (records.size() != 1) return 1;
            const auto* payload = std::get_if<UndoReleaseSudoAuthentication>(&records.front().undo.payload);
            if (!payload) return 1;
            const auto result = auth.release(*payload);
            if (!result.ok) {
                journal->setStatusWithMessage(records.front().id, MutationStatus::RollbackFailed, result.message, error);
                std::cerr << result.message << '\n'; return 1;
            }
            if (!journal->setStatus(records.front().id, MutationStatus::RolledBack, error)) return 1;
            return finishDisable() ? 0 : 1;
        }
        GlobalDefaultsPhaseHook hook;
        if (action != "release") {
            const int phaseArgument = action == "crash-apply" ? 4 : 3;
            if (argc != phaseArgument + 1) return 2;
            const std::map<std::string, GlobalDefaultsPhase> cuts{
                {"before-prepared", GlobalDefaultsPhase::BeforePrepared},
                {"prepared", GlobalDefaultsPhase::Prepared},
                {"file", GlobalDefaultsPhase::OwnedFileInstalled},
                {"include", GlobalDefaultsPhase::IncludeInstalled},
                {"verified", GlobalDefaultsPhase::PostconditionVerified},
                {"inert", GlobalDefaultsPhase::InertFileInstalled},
                {"detached", GlobalDefaultsPhase::IncludeReleased},
                {"deleted", GlobalDefaultsPhase::FileReleased}};
            const auto cut = cuts.find(argv[phaseArgument]);
            if (cut == cuts.end()) return 2;
            hook = [phase = cut->second](auto reached) {
                if (reached == phase) ::_exit(86);
            };
        }
        GlobalDefaultsTransaction transaction(options, *journal, hook);
        if (name == "sudo_disable_scoped_defaults") {
            if (action != "release" || !transaction.verifyNoOwnedSetting("", error, true)) {
                std::cerr << error << '\n'; return 1;
            }
            SudoersConfiguration configuration(options);
            if (!configuration.load(error)) { std::cerr << error << '\n'; return 1; }
            ScopedDefaultsTransaction scoped(configuration, name);
            const auto records = journal->activeRecords(identity);
            if (records.empty()) {
                error = scoped.validateCurrentOwnership({});
                if (!error.empty()) { std::cerr << error << '\n'; return 1; }
                std::cout << "NothingToDo\n";
                return finishDisable() ? 0 : 1;
            }
            if (records.size() != 1) return 1;
            const auto* payload = std::get_if<UndoReleaseSudoScopedDefaults>(&records.front().undo.payload);
            if (!payload) return 1;
            SudoScopedDefaultsHooks hooks;
            hooks.validate = [&configuration](std::string& error) {
                return configuration.validateConfiguration(error);
            };
            hooks.reloadAndVerify = [&configuration](std::string& error) {
                return configuration.load(error);
            };
            bool authRequested, scopeRequested;
            if (!readSudoRequestedState(authRequested, scopeRequested, error) ||
                !AuthenticationTransaction(options, *journal).verifyOwnership(error) ||
                !guardScopedAuthenticationRelease(configuration, payload->targetProofs, authRequested, error)) {
                std::cerr << error << '\n'; return 1;
            }
            const auto restored = scoped.release(payload->targetProofs, hooks);
            if (!restored.ok() || !transaction.verifyNoOwnedSetting("", error, true) ||
                !configuration.verifyIncludedDirectoryTopologyUnchanged(error) ||
                !journal->setStatus(records.front().id, MutationStatus::RolledBack, error)) {
                std::cerr << (restored.ok() ? error : restored.operation.message) << '\n'; return 1;
            }
            std::cout << "Released scoped Defaults ownership\n";
            return finishDisable() ? 0 : 1;
        }
        if (action == "crash-apply") {
            // The native crash fixture intentionally admits only this narrow
            // value grammar; normal apply still exercises production Policy.
            if (name != "sudo_passwd_tries" ||
                (std::string(argv[3]) != "3" && std::string(argv[3]) != "4")) return 2;
            const auto result = transaction.reconcile(identity, "passwd_tries",
                "Defaults passwd_tries=" + std::string(argv[3]), argv[3]);
            std::cerr << (result.ok ? "Crash boundary not reached" : result.message) << '\n';
            return 1;
        }
        const auto records = journal->activeRecords(identity);
        if (records.empty()) {
            if (!transaction.verifyNoOwnedSetting(keys.at(name), error)) {
                std::cerr << error << '\n'; return 1;
            }
            std::cout << "NothingToDo\n";
            return finishDisable() ? 0 : 1;
        }
        if (records.size() != 1) return 1;
        const auto result = transaction.release(records.front());
        if (!result.ok) {
            if (!journal->setStatusWithMessage(records.front().id, MutationStatus::RollbackFailed,
                                               result.message, error)) std::cerr << error << '\n';
            std::cerr << result.message << '\n'; return 1;
        }
        if (!journal->setStatus(records.front().id, MutationStatus::RolledBack, error)) {
            std::cerr << error << '\n'; return 1;
        }
        std::cout << result.message << '\n';
        return finishDisable() ? 0 : 1;
    }
    if (action != "apply" || argc != 4) return 2;
    ModuleConfigFileHandler config("DAC");
    if (!config.loadConfig() || !config.setPolicyStatus(name, "ENABLE") ||
        !config.setPolicyValue(name, argv[3]) || !config.saveConfig()) return 1;
    std::unique_ptr<Sudo> policy;
    if (name == "sudo_env_reset") policy = std::make_unique<DAC_sudo_env_reset>(platform.sudo, executables);
    if (name == "sudo_passwd_tries") policy = std::make_unique<DAC_sudo_passwd_tries>(platform.sudo, executables);
    if (name == "sudo_securepath") policy = std::make_unique<DAC_sudo_securepath>(platform.sudo, executables);
    if (name == "sudo_timeout") policy = std::make_unique<DAC_sudo_timeout>(platform.sudo, executables);
    if (name == "sudo_exempt_group_disable") policy = std::make_unique<DAC_sudo_exempt_group_disable>(platform.sudo, executables);
    if (name == "sudo_disable_scoped_defaults") policy = std::make_unique<DAC_sudo_disable_scoped_defaults>(platform.sudo, executables);
    if (name == kAuthenticationPolicy) policy = std::make_unique<DAC_sudo_require_authentication>(platform.sudo, executables);
    if (!policy || !policy->validate(argv[3]) || !policy->apply()) return 1;
    std::cout << "active-policy-records=" << journal->activeRecords(identity).size() << '\n';
    return 0;
}
