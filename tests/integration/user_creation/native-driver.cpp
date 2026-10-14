#include "modules/identity_access/user_creation/UserCreationPolicies.h"
#include "modules/identity_access/user_creation/UserCreationManagedTransaction.h"
#include "modules/identity_access/shared/login_defs/IdentityLoginDefsManagedTransaction.h"
#include "rollback/DaemonMutationJournal.h"
#include "platform/PlatformCompatibility.h"
#include <fic/core/config/ModuleConfigFileHandler.h>
#include <fic/core/runtime/FicRuntimePaths.h>
#include <fstream>
#include <iostream>
#include <map>
#include <unistd.h>

namespace uc = fic::identity::user_creation;
namespace ld = fic::identity::login_defs;
using namespace fic::rollback;

int main(int argc, char** argv) {
    if (getuid() != 0 || !std::filesystem::exists("/run/.containerenv")) {
        std::cerr << "Container-only native driver; host execution refused\n";
        return 77;
    }
    if (argc < 3) return 2;
    const std::string action = argv[1], name = argv[2];
    const auto profile = fic::platform::makeBuildPlatformProfile();
    std::string error;
    if (!fic::platform::validateHostCompatibility(profile, "/etc/os-release", error)) {
        std::cerr << error; return 1;
    }
    const auto& platform = profile.userCreation;
    auto paths = fic::core::FicProductPaths::production();
    const std::filesystem::path root = "/var/lib/fic-user-creation-native";
    paths.configDir = root / "config";
    paths.logDir = root / "logs";
    paths.dataDir = root / "state";
    paths.notifyDir = root / "notify";
    paths.runtimeDir = root / "run";
    paths.commandHashFile = root / "command-hashes";
    paths.mutationJournalFile = root / "journal.json";
    for (const auto& path : {paths.configDir, paths.logDir, paths.dataDir, paths.notifyDir, paths.runtimeDir})
        std::filesystem::create_directories(path);
    if (!fic::core::FicRuntimePaths::initialize(paths, error)) { std::cerr << error; return 1; }
    const std::map<std::string, std::string> defaults{
        {"user_home_base_directory", "/home"}, {"user_create_home", "yes"},
        {"user_skeleton_directory", "/etc/skel"}, {"user_default_shell", "/bin/sh"},
        {"user_create_private_group", "yes"}, {"user_default_primary_group", "users"},
        {"user_default_supplementary_groups", "[]"}};
    if (!defaults.count(name)) return 2;
    if (!std::filesystem::exists(paths.configDir / "IDENTITY_ACCESS.conf")) {
        std::ofstream config(paths.configDir / "IDENTITY_ACCESS.conf");
        config << "_schema_version=1\n";
        for (const auto& [policy, value] : defaults)
            config << policy << ".status=ENABLE\n" << policy << ".value=" << value << '\n';
        std::ofstream audit(paths.configDir / "AUDIT.conf");
        audit << "_schema_version=1\nlog_level.status=ENABLE\nlog_level.value=ERROR\n";
    }
    auto* journal = DaemonMutationJournal::instance().tryGet(error);
    if (!journal) { std::cerr << error; return 1; }
    const PolicyRef policy{"IDENTITY_ACCESS", "USER_CREATION", name};
    if (action == "release") {
        const std::lock_guard<std::mutex> lock(IdentityAccessPolicy::configurationMutex());
        const auto records = journal->activeRecords(policy);
        if (records.size() > 1) return 1;
        // Repeated release must run the same backend coherence check. A closed
        // record supplies routing only; active journal proof still determines
        // ownership, so a newly introduced orphan cannot be released.
        const MutationRecord* record = records.empty() ? nullptr : &records.front();
        if (!record) {
            for (const auto& candidate : journal->records())
                if (candidate.policy == policy) record = &candidate;
        }
        if (!record) { std::cerr << "No release provenance\n"; return 1; }
        bool released = false, absent = false;
        if (name == "user_create_home" || name == "user_create_private_group") {
            const auto status = ld::releaseManagedPolicy(platform.loginDefsPath.string(), *record, *journal, {}, error);
            released = status == ld::ReleaseStatus::Success;
            absent = status == ld::ReleaseStatus::NothingToDo;
        } else {
            const auto status = uc::releaseManagedPolicy(platform, *record, *journal, error);
            released = status == uc::ReleaseStatus::Success;
            absent = status == uc::ReleaseStatus::NothingToDo;
        }
        if ((!released && !absent) ||
            (!records.empty() && !journal->setStatus(record->id, MutationStatus::RolledBack, error))) {
            std::cerr << error; return 1;
        }
        std::cout << (absent ? "NothingToDo\n" : "Released\n"); return 0;
    }
    if ((action != "apply" && action != "crash-apply") || argc < 4) return 2;
    ModuleConfigFileHandler config("IDENTITY_ACCESS");
    if (!config.loadConfig() || !config.setPolicyValue(name, argv[3]) || !config.saveConfig()) return 1;
    unsigned writes = 0;
    const std::string cut = action == "crash-apply" && argc == 5 ? argv[4] : "";
    auto before = [&] { ++writes; if (cut == "before") ::_exit(86); };
    auto after = [&] { if (cut == "after") ::_exit(86); };
    uc::setBeforeUserCreationWriteHookForTests(before);
    uc::setAfterUserCreationWriteHookForTests(after);
    ld::setBeforeIdentityLoginDefsWriteHookForTests(before);
    ld::setAfterIdentityLoginDefsWriteHookForTests(after);
    std::unique_ptr<Policy> instance;
    if (name == "user_home_base_directory") instance = std::make_unique<UserHomeBaseDirectoryPolicy>(platform);
    else if (name == "user_create_home") instance = std::make_unique<UserCreateHomePolicy>(platform);
    else if (name == "user_skeleton_directory") instance = std::make_unique<UserSkeletonDirectoryPolicy>(platform);
    else if (name == "user_default_shell") instance = std::make_unique<UserDefaultShellPolicy>(platform);
    else if (name == "user_create_private_group") instance = std::make_unique<UserCreatePrivateGroupPolicy>(platform);
    else if (name == "user_default_primary_group") instance = std::make_unique<UserDefaultPrimaryGroupPolicy>(platform);
    else instance = std::make_unique<UserDefaultSupplementaryGroupsPolicy>(platform);
    if (!instance->apply()) return 1;
    const auto active = journal->activeRecords(policy);
    if (active.size() != 1 || active.front().status != MutationStatus::Applied) return 1;
    std::cout << "SUCCESS writes=" << writes << " ownership=Applied\n";
    return 0;
}
