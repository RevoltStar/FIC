#include "modules/identity_access/password_aging/PasswordAgingPolicies.h"
#include "modules/identity_access/shared/login_defs/IdentityLoginDefsManagedTransaction.h"
#include "rollback/DaemonMutationJournal.h"
#include "platform/PlatformCompatibility.h"
#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/config/ModuleConfigFileHandler.h>
#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/process/VerifiedProcessExecutor.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <unistd.h>

using namespace fic::identity::password_aging;
namespace ld = fic::identity::login_defs;
using namespace fic::rollback;
using nlohmann::json;
namespace fs = std::filesystem;

int main(int argc, char** argv) {
    if (getuid() != 0 || (!fs::exists("/run/.containerenv") && !fs::exists("/.dockerenv")) || argc < 3) return 77;
    const std::string action = argv[1], name = argv[2];
    const auto profile = fic::platform::makeBuildPlatformProfile();
    std::string error;
    if (!fic::platform::validateHostCompatibility(profile, "/etc/os-release", error)) {
        std::cerr << error; return 1;
    }
    const auto& platform = profile.passwordAging;
    auto paths = fic::core::FicProductPaths::production();
    const fs::path root = "/var/lib/fic-password-aging-native";
    paths.configDir = root / "config"; paths.logDir = root / "logs";
    paths.dataDir = root / "state"; paths.runtimeDir = root / "run";
    paths.lockDebugLogFile = root / "logs/locks.log";
    paths.commandHashFile = root / "hashes"; paths.mutationJournalFile = root / "journal.json";
    for (const auto& path : {paths.configDir, paths.logDir, paths.dataDir, paths.runtimeDir}) fs::create_directories(path);
    if (!fic::core::FicRuntimePaths::initialize(paths, error)) { std::cerr << error; return 1; }
    const std::map<std::string, std::string> defaults = {
        {"password_min_age_days", "1"}, {"password_max_age_days", "90"},
        {"password_expiration_warning_days", "7"}, {"regular_user_uid_min", "30000"},
        {"regular_user_uid_max", "40000"}, {"password_aging_apply_to_existing_accounts", "yes"},
        {"password_aging_enforce_for_root", "yes"}};
    if (!fs::exists(paths.configDir / "IDENTITY_ACCESS.conf")) {
        std::ofstream config(paths.configDir / "IDENTITY_ACCESS.conf"); config << "_schema_version=1\n";
        for (const auto& [p, v] : defaults) config << p << ".status=ENABLE\n" << p << ".value=" << v << '\n';
        std::ofstream audit(paths.configDir / "AUDIT.conf");
        audit << "_schema_version=1\nlog_level.status=ENABLE\nlog_level.value=DEBUG\n";
    }
    if (action == "snapshot") {
        LocalAccountSnapshot state;
        if (!PasswordAgingRuntime::readLocalAccounts(platform, state, error)) { std::cerr << error; return 1; }
        json out;
        for (const auto& [user, a] : state.shadowAccounts)
            out[user] = {a.lastChange, a.minDays, a.maxDays, a.warningDays};
        std::cout << out.dump() << '\n'; return 0;
    }
    if (action == "profile") {
        std::cout << json{{"missing", {platform.missingKeySemantics.minDays, platform.missingKeySemantics.maxDays,
                                      platform.missingKeySemantics.warningDays}},
                         {"tcb", platform.shadowKind == fic::platform::LocalShadowKind::TcbDirectory}}.dump();
        return 0;
    }
    if (action == "peer") {
        auto* shared = DaemonMutationJournal::instance().tryGet(error);
        if (!shared || !ld::applyManagedPolicy(platform.loginDefsPath.string(),
                {"IDENTITY_ACCESS", "USER_CREATION", "user_create_home"}, "no", *shared, {}, error)) {
            std::cerr << error; return 1;
        }
        std::cout << "Peer acquired\n"; return 0;
    }
    if (!defaults.count(name)) return 2;
    const PolicyRef policy{"IDENTITY_ACCESS", "PASSWORD_AGING", name};
    auto* journal = DaemonMutationJournal::instance().tryGet(error);
    if (!journal) { std::cerr << error; return 1; }
    if (action == "release") {
        const auto records = journal->activeRecords(policy);
        if (records.size() != 1) return 1;
        ld::IdentityLoginDefsSemantics semantics;
        semantics.missingKey = {platform.missingKeySemantics.minDays, platform.missingKeySemantics.maxDays};
        const auto status = ld::releaseManagedPolicy(platform.loginDefsPath.string(), records.front(), *journal, semantics, error);
        if (status != ld::ReleaseStatus::Success || !journal->setStatus(records.front().id, MutationStatus::RolledBack, error)) {
            std::cerr << error; return 1;
        }
        std::cout << "Released\n"; return 0;
    }
    ModuleConfigFileHandler config("IDENTITY_ACCESS");
    if (!config.loadConfig()) return 1;
    if (action == "disable") {
        if (!config.disablePolicy(name) || !config.saveConfig()) return 1;
        std::cout << "Disabled; no account restoration\n"; return 0;
    }
    if (action != "apply" && action != "crash-apply" && action != "fail-second") return 2;
    if (argc >= 4 && (!config.setPolicyValue(name, argv[3]) || !config.saveConfig())) return 1;
    unsigned writes = 0;
    const std::string cut = action == "crash-apply" && argc == 5 ? argv[4] : "";
    ld::setBeforeIdentityLoginDefsWriteHookForTests([&] { ++writes; if (cut == "before") ::_exit(86); });
    ld::setAfterIdentityLoginDefsWriteHookForTests([&] { if (cut == "after") ::_exit(86); });
    const fic::platform::PlatformExecutableResolver executables(profile.executables);
    std::unique_ptr<Policy> instance;
    if (name == "password_min_age_days") instance = std::make_unique<PasswordMinAgeDaysPolicy>(platform);
    if (name == "password_max_age_days") instance = std::make_unique<PasswordMaxAgeDaysPolicy>(platform);
    if (name == "password_expiration_warning_days") instance = std::make_unique<PasswordExpirationWarningDaysPolicy>(platform);
    if (name == "regular_user_uid_min") instance = std::make_unique<RegularUserUidMinPolicy>(platform);
    if (name == "regular_user_uid_max") instance = std::make_unique<RegularUserUidMaxPolicy>(platform);
    json calls = json::array();
    if (!instance) {
        fs::path chage;
        if (!executables.resolve(fic::platform::ExecutableId::Chage, chage, error) || !CommandHashStore::saveHash(chage, error)) {
            std::cerr << error; return 1;
        }
        PasswordAgingRuntime runtime(platform, executables,
            [&](const std::string& executable, const std::vector<std::string>& args) {
                calls.push_back(args.back());
                if (action == "fail-second" && calls.size() == 2) {
                    ProcessResult failed; failed.started = true; failed.exitCode = 23;
                    failed.standardError = "native gate injected second-command failure"; return failed;
                }
                return VerifiedProcessExecutor::execute(executable, args);
            });
        if (name == "password_aging_apply_to_existing_accounts") instance = std::make_unique<PasswordAgingApplyToExistingAccountsPolicy>(platform, std::move(runtime));
        else instance = std::make_unique<PasswordAgingEnforceForRootPolicy>(platform, std::move(runtime));
    }
    const bool enabled = instance->isEnabled();
    const bool ok = !enabled || instance->apply();
    const auto records = journal->activeRecords(policy);
    std::cout << json{{"ok", ok}, {"enabled", enabled}, {"writes", writes}, {"calls", calls},
                     {"active_records", records.size()},
                     {"applied_record", records.size() == 1 && records.front().status == MutationStatus::Applied}}.dump() << '\n';
    return ok ? 0 : 1;
}
