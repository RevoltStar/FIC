#include "modules/identity_access/user_creation/configuration/AdduserConfigFileHandler.h"
#include "modules/identity_access/user_creation/configuration/UseraddDefaultsFileHandler.h"
#include "modules/identity_access/user_creation/UserCreationPolicies.h"
#include "modules/identity_access/user_creation/UserCreationManagedTransaction.h"
#include "policy/registry/PolicyRegistryJson.h"
#include "policy/registry/PolicyRegistryMutation.h"
#include "rollback/DaemonMutationJournal.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/runtime/FicRuntimePaths.h>

#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {
namespace fs = std::filesystem;
using namespace fic::identity;

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

void writeFile(const fs::path& path, const std::string& content,
               mode_t mode = 0644) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(output.is_open(), "cannot write " + path.string());
    output << content;
    output.close();
    require(::chmod(path.c_str(), mode) == 0, "chmod failed");
}

std::string readFile(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

void initializePaths(const fs::path& root) {
    auto paths = fic::core::FicProductPaths::production();
    paths.configDir = root / "config";
    paths.logDir = root / "log";
    paths.dataDir = root / "data";
    paths.runtimeDir = root / "run";
    paths.commandHashFile = root / "data/hash";
    paths.lockStatusFile = root / "run/lock";
    paths.deviceDatabaseFile = root / "data/devices.db";
    paths.deviceDatabaseLockFile = root / "data/devices.lock";
    paths.lockDebugLogFile = root / "log/locks.log";
    fs::create_directories(paths.configDir);
    fs::create_directories(paths.logDir);
    fs::create_directories(paths.dataDir);
    writeFile(paths.configDir / "AUDIT.conf",
              "_schema_version=1\nlog_level.status=ENABLE\n"
              "log_level.value=DEBUG\n");
    std::string error;
    require(fic::core::FicRuntimePaths::initialize(paths, error), error);
    fic::rollback::DaemonMutationJournal::instance().setOverridePath(
        root / "data/user-creation-mutations.json");
}

void useJournal(const fs::path& root, const std::string& name) {
    fic::rollback::DaemonMutationJournal::instance().setOverridePath(
        root / ("data/" + name + ".json"));
}

void writePolicyConfig(
    const fs::path& root,
    const std::string& home,
    const std::string& skel,
    const std::string& shell,
    const std::string& group,
    const std::string& createHome = "yes",
    const std::string& privateGroup = "yes",
    const std::string& supplementaryGroups = "[]") {
    writeFile(root / "config/IDENTITY_ACCESS.conf",
        "_schema_version=1\n"
        "user_home_base_directory.status=ENABLE\n"
        "user_home_base_directory.value=" + home + "\n"
        "user_create_home.status=ENABLE\n"
        "user_create_home.value=" + createHome + "\n"
        "user_skeleton_directory.status=ENABLE\n"
        "user_skeleton_directory.value=" + skel + "\n"
        "user_default_shell.status=ENABLE\n"
        "user_default_shell.value=" + shell + "\n"
        "user_create_private_group.status=ENABLE\n"
        "user_create_private_group.value=" + privateGroup + "\n"
        "user_default_primary_group.status=ENABLE\n"
        "user_default_primary_group.value=" + group + "\n"
        "user_default_supplementary_groups.status=ENABLE\n"
        "user_default_supplementary_groups.value=" + supplementaryGroups + "\n");
}

fic::platform::UserCreationPlatformConfig platformFor(const fs::path& root) {
    fic::platform::UserCreationPlatformConfig platform;
    platform.useraddDefaultsPath = root / "etc/default/useradd";
    platform.loginDefsPath = root / "etc/login.defs";
    platform.passwdPath = root / "etc/passwd";
    platform.groupPath = root / "etc/group";
    platform.shellsPath = root / "etc/shells";
    return platform;
}

fic::rollback::MutationRecord userCreationRecord(
    const fic::platform::UserCreationPlatformConfig& platform,
    const std::vector<fic::identity::user_creation::Assignment>& applied,
    const std::vector<fic::identity::user_creation::Assignment>& previous = {}) {
    using namespace fic::rollback;
    MutationRecord record;
    record.policy = {"IDENTITY_ACCESS", "USER_CREATION",
                     "user_home_base_directory"};
    record.resource = platform.useraddDefaultsPath.string();
    UndoRemoveUserCreationManagedPolicy undo;
    undo.policyName = record.policy.policyName;
    undo.configKind = UserCreationConfigKind::UseraddDefaults;
    undo.configPath = record.resource;
    for (const auto& value : applied)
        undo.appliedAssignments.push_back({value.key, value.line});
    for (const auto& value : previous)
        undo.previousAppliedAssignments.push_back({value.key, value.line});
    record.undo = {MutationBackend::UserCreation, std::move(undo)};
    return record;
}

fic::rollback::MutationId prepareUserCreationRecord(
    fic::rollback::MutationJournal& journal,
    const fic::platform::UserCreationPlatformConfig& platform,
    const std::vector<fic::identity::user_creation::Assignment>& applied,
    const std::vector<fic::identity::user_creation::Assignment>& previous = {}) {
    fic::rollback::MutationId id = 0;
    std::string error;
    require(journal.prepareMutation(
                userCreationRecord(platform, applied, previous), id, error),
            error);
    return id;
}

void testHandler(const fs::path& root) {
    const fs::path path = root / "handler/useradd";
    const std::string original =
        "# keep\nUNKNOWN=value\nHOME=/home\nSKEL=/etc/skel\n";
    writeFile(path, original, 0600);
    UseraddDefaultsFileHandler handler(path.string());
    require(handler.loadConfig(), "useradd defaults load failed");
    require(handler.lookup("HOME").state == UseraddDefaultsValueState::Unique &&
                handler.lookup("HOME").value == "/home",
            "HOME was not parsed");
    require(handler.setValue("HOME", "/srv/home"), "HOME update failed");
    require(handler.setValue("SHELL", "/bin/sh"), "SHELL append failed");
    require(handler.saveAndReload(), "useradd defaults save/reload failed");
    const std::string changed = readFile(path);
    require(changed.find("# keep\nUNKNOWN=value\n") == 0,
            "comments or unknown keys changed");
    require(changed.find("HOME=/srv/home\n") != std::string::npos,
            "HOME not canonicalized");
    struct stat status {};
    require(::stat(path.c_str(), &status) == 0 &&
                (status.st_mode & 0777) == 0600,
            "existing mode was not preserved");

    for (const std::string& malformed : {
             "HOME\n", "HOME=\n", "HOME=/home extra\n",
             " HOME=/home\n", "HOME =/home\n", "HOME= /home\n"}) {
        writeFile(path, malformed);
        require(handler.loadConfig(), "malformed handler load failed");
        require(handler.lookup("HOME").state ==
                    UseraddDefaultsValueState::Malformed,
                "malformed target not detected");
        require(!handler.setValue("HOME", "/home"),
                "malformed target was repaired");
        require(readFile(path) == malformed, "malformed file mutated");
    }

    writeFile(path, "HOME=/home\nHOME=/srv/home\n");
    require(handler.loadConfig() &&
                handler.lookup("HOME").state ==
                    UseraddDefaultsValueState::Duplicate,
            "duplicate target not detected");
    require(!handler.setValue("HOME", "/home"), "duplicate target accepted");
}

void prepareNativeFiles(
    const fic::platform::UserCreationPlatformConfig& platform,
    const fs::path& home,
    const fs::path& skel,
    const fs::path& shell) {
    fs::create_directories(home);
    fs::create_directories(skel);
    writeFile(shell, "#!/bin/sh\n", 0755);
    writeFile(platform.shellsPath, shell.string() + "\n");
    writeFile(platform.groupPath,
              "root:x:0:\nusers:x:100:\naudio:x:101:\nvideo:x:102:\n");
    writeFile(platform.passwdPath, "root:x:0:0:root:/root:/bin/sh\n");
    writeFile(platform.useraddDefaultsPath,
              "# vendor\nGROUP=100\nHOME=/home\nSHELL=/bin/sh\n"
              "SKEL=/etc/skel\nINACTIVE=-1\nEXPIRE=\n", 0600);
    writeFile(platform.loginDefsPath,
              "CREATE_HOME no\nUSERGROUPS_ENAB no\n", 0644);
}

void testGroupListValueType() {
    GroupListPolicyTypeValue value;
    require(value.getDefaultValue() == "" && value.validate("") &&
                value.validate(value.getDefaultValue()) &&
                value.postProcessingValue(value.getDefaultValue()) == "[]" &&
                value.reverse_postProcessingValue("[]") == "",
            "empty group list is not canonical");
    require(value.validate("audio") &&
                value.postProcessingValue("audio") == "[\"audio\"]",
            "single group is not canonical");
    require(value.validate("video, audio") &&
                value.postProcessingValue("video, audio") ==
                    "[\"audio\",\"video\"]",
            "group list is not sorted deterministically");
    require(value.reverse_postProcessingValue("[\"audio\",\"video\"]") ==
                "audio,video",
            "stored group list was not decoded");
    require(!value.validate("audio,audio"), "duplicate group was accepted");
    require(!value.validate("100") && !value.validate("audio,,video"),
            "invalid group name/list was accepted");
    bool invalidSerialization = false;
    try {
        (void)value.reverse_postProcessingValue("not-json");
    } catch (const std::exception&) {
        invalidSerialization = true;
    }
    require(invalidSerialization, "invalid serialization was accepted");
    const PolicyEditorSpec editor = value.getEditorSpec();
    require(editor.editor == "textedit" && editor.textDelimiter == ",",
            "group-list editor metadata is wrong");
}

void testAdduserHandler(const fs::path& root) {
    const fs::path path = root / "handler/adduser.conf";
    writeFile(path,
              "# vendor\nUNKNOWN = keep\nADD_EXTRA_GROUPS = 0\n"
              "EXTRA_GROUPS='users audio video'\n",
              0600);
    AdduserConfigFileHandler handler(path.string());
    require(handler.loadConfig(), "adduser config load failed");
    require(handler.lookup("ADD_EXTRA_GROUPS").value == "0" &&
                handler.lookup("EXTRA_GROUPS").value == "users audio video",
            "quoted/whitespace adduser config was not parsed");
    require(handler.setSupplementaryGroups(true, {"audio", "video"}) &&
                handler.saveAndReload(),
            "adduser two-key update failed");
    const std::string changed = readFile(path);
    require(changed.find("# vendor\nUNKNOWN = keep\n") == 0 &&
                changed.find("ADD_EXTRA_GROUPS=1\n") != std::string::npos &&
                changed.find("EXTRA_GROUPS=\"audio video\"\n") !=
                    std::string::npos,
            "adduser config was not written canonically/atomically");
    struct stat status {};
    require(::stat(path.c_str(), &status) == 0 &&
                (status.st_mode & 0777) == 0600,
            "adduser config mode was not preserved");

    for (const std::string& malformed : {
             "ADD_EXTRA_GROUPS 1\nEXTRA_GROUPS=\"audio\"\n",
             "ADD_EXTRA_GROUPS=1\nEXTRA_GROUPS=\"audio\n"}) {
        writeFile(path, malformed);
        require(handler.loadConfig(), "malformed adduser load failed");
        const std::string before = readFile(path);
        require(!handler.setSupplementaryGroups(true, {"audio"}) &&
                    readFile(path) == before,
                "malformed adduser target was repaired");
    }
    writeFile(path,
              "add_extra_groups=0\nADD_EXTRA_GROUPS=1\n"
              "EXTRA_GROUPS=audio\n");
    require(handler.loadConfig() &&
                handler.lookup("ADD_EXTRA_GROUPS").state ==
                    AdduserConfigValueState::Duplicate &&
                !handler.setSupplementaryGroups(true, {"audio"}),
            "duplicate adduser option was accepted");
}

void writeSupplementaryConfig(
    const fs::path& root,
    const std::string& serialized) {
    writeFile(root / "config/IDENTITY_ACCESS.conf",
              "_schema_version=1\n"
              "user_default_supplementary_groups.status=ENABLE\n"
              "user_default_supplementary_groups.value=" + serialized + "\n");
}

// Independent test model of shadow 4.17 useradd's documented GROUPS path:
// each later GROUPS= assignment replaces the saved text and get_groups("")
// clears the resulting list. This deliberately does not call FIC's
// effectiveValue() implementation.
std::vector<std::string> shadow417Groups(const std::string& content) {
    std::string value;
    std::istringstream lines(content);
    for (std::string line; std::getline(lines, line);) {
        if (line.rfind("GROUPS=", 0) == 0) value = line.substr(7);
    }
    std::vector<std::string> groups;
    std::size_t start = 0;
    while (start < value.size()) {
        const std::size_t comma = value.find(',', start);
        groups.push_back(value.substr(start, comma == std::string::npos
            ? std::string::npos : comma - start));
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return groups;
}

void testShadowSupplementaryPolicy(const fs::path& root) {
    useJournal(root, "shadow-supplementary");
    auto platform = platformFor(root);
    platform.supplementaryGroupsProvider =
        fic::platform::UserSupplementaryGroupsProviderKind::ShadowUseraddDefaults;
    const fs::path home = root / "supplementary/home";
    const fs::path skel = root / "supplementary/skel";
    const fs::path shell = root / "supplementary/shell";
    prepareNativeFiles(platform, home, skel, shell);

    writeSupplementaryConfig(root, "[\"video\",\"audio\"]");
    UserDefaultSupplementaryGroupsPolicy set(platform);
    require(set.apply() &&
                readFile(platform.useraddDefaultsPath).find(
                    "GROUPS=audio,video\n") != std::string::npos,
            "shadow supplementary groups were not applied");
    require(readFile(platform.useraddDefaultsPath).find(
                "# vendor\nGROUP=100\nHOME=/home\n") == 0,
            "shadow apply did not preserve comments/unknown keys");

    writeFile(platform.useraddDefaultsPath,
              "# keep\nGROUPS=audio\nHOME=/home\n");
    require(set.apply() &&
                readFile(platform.useraddDefaultsPath).find(
                    "GROUPS=audio,video\n") != std::string::npos,
            "different shadow GROUPS was not replaced");

    writeFile(platform.useraddDefaultsPath,
              "# keep\nGROUPS=video,audio\nHOME=/home\n");
    writeSupplementaryConfig(root, "[\"audio\",\"video\"]");
    UserDefaultSupplementaryGroupsPolicy orderInsensitive(platform);
    const std::string reordered = readFile(platform.useraddDefaultsPath);
    require(orderInsensitive.apply() &&
                readFile(platform.useraddDefaultsPath) == reordered,
            "equivalent native group order caused mutation");

    writeSupplementaryConfig(root, "[]");
    UserDefaultSupplementaryGroupsPolicy clear(platform);
    require(clear.apply() &&
                readFile(platform.useraddDefaultsPath).find("GROUPS=\n") !=
                    std::string::npos &&
                shadow417Groups(readFile(platform.useraddDefaultsPath)).empty(),
            "empty shadow list did not install the neutralizing GROUPS=");
    const std::string cleared = readFile(platform.useraddDefaultsPath);
    require(clear.apply() && readFile(platform.useraddDefaultsPath) == cleared,
            "empty shadow list is not idempotent");

    writeFile(platform.useraddDefaultsPath,
              "GROUPS=audio\nGROUPS=video\nHOME=/home\n");
    writeSupplementaryConfig(root, "[\"audio\"]");
    UserDefaultSupplementaryGroupsPolicy duplicate(platform);
    const std::string before = readFile(platform.useraddDefaultsPath);
    require(duplicate.apply() && readFile(platform.useraddDefaultsPath).find(
                "#@FIC_POLICY_BEGIN name=user_default_supplementary_groups@") !=
                std::string::npos,
            "last-wins duplicate native GROUPS was not safely overridden");

    writeFile(platform.useraddDefaultsPath, "GROUPS=\nHOME=/home\n");
    UserDefaultSupplementaryGroupsPolicy malformed(platform);
    require(malformed.apply(), "valid empty native GROUPS was rejected");

    writeFile(platform.useraddDefaultsPath, "HOME=/home\n");
    writeSupplementaryConfig(root, "[\"missing\"]");
    UserDefaultSupplementaryGroupsPolicy missingGroup(platform);
    require(!missingGroup.apply(), "missing supplementary group was accepted");

    writeSupplementaryConfig(root, "not-json");
    UserDefaultSupplementaryGroupsPolicy invalidSerialized(platform);
    require(!invalidSerialized.apply(), "invalid stored list was accepted");

    writeSupplementaryConfig(root, "[\"audio\"]");
    const fs::path realDefaults = root / "etc/default/useradd.supp-real";
    writeFile(realDefaults, "HOME=/home\n");
    fs::remove(platform.useraddDefaultsPath);
    fs::create_symlink(realDefaults, platform.useraddDefaultsPath);
    UserDefaultSupplementaryGroupsPolicy symlink(platform);
    require(!symlink.apply() &&
                readFile(realDefaults) == "HOME=/home\n",
            "symlink shadow defaults was accepted");
    fs::remove(platform.useraddDefaultsPath);
    UserDefaultSupplementaryGroupsPolicy missingTarget(platform);
    require(!missingTarget.apply() && !fs::exists(platform.useraddDefaultsPath),
            "missing shadow defaults was created");
}

void testAdduserSupplementaryPolicy(const fs::path& root) {
    useJournal(root, "adduser-supplementary");
    auto platform = platformFor(root);
    platform.supplementaryGroupsProvider =
        fic::platform::UserSupplementaryGroupsProviderKind::DebianAdduser;
    platform.adduserConfigPath = root / "etc/adduser.conf";
    writeFile(platform.groupPath,
              "root:x:0:\nusers:x:100:\naudio:x:101:\nvideo:x:102:\n");
    writeFile(platform.adduserConfigPath,
              "# vendor\nADD_EXTRA_GROUPS = 0\n"
              "EXTRA_GROUPS='users audio'\n",
              0600);
    writeSupplementaryConfig(root, "[\"video\",\"audio\"]");
    UserDefaultSupplementaryGroupsPolicy set(platform);
    require(set.apply(), "adduser supplementary groups apply failed");
    const std::string applied = readFile(platform.adduserConfigPath);
    require(applied.find("ADD_EXTRA_GROUPS=1\n") != std::string::npos &&
                applied.find("EXTRA_GROUPS=\"audio video\"\n") !=
                    std::string::npos,
            "adduser supplementary state is partial or wrong");
    require(set.apply() && readFile(platform.adduserConfigPath) == applied,
            "adduser apply is not idempotent");

    writeSupplementaryConfig(root, "[]");
    UserDefaultSupplementaryGroupsPolicy clear(platform);
    require(clear.apply(), "empty adduser list failed");
    const std::string cleared = readFile(platform.adduserConfigPath);
    require(cleared.find("ADD_EXTRA_GROUPS=0\n") != std::string::npos &&
                cleared.find("EXTRA_GROUPS='users audio'\n") !=
                    std::string::npos &&
                cleared.find("EXTRA_GROUPS=\"audio video\"\n") ==
                    std::string::npos,
            "empty adduser list did not release managed EXTRA_GROUPS while preserving foreign state");

    writeFile(platform.adduserConfigPath, "EXTRA_GROUPS=users audio\n");
    UserDefaultSupplementaryGroupsPolicy explicitEmpty(platform);
    require(explicitEmpty.apply() &&
                readFile(platform.adduserConfigPath).find(
                    "ADD_EXTRA_GROUPS=0\n") != std::string::npos,
            "empty list did not materialize disabled adduser state");

    writeFile(platform.adduserConfigPath,
              "ADD_EXTRA_GROUPS=0\nADD_EXTRA_GROUPS=1\nEXTRA_GROUPS=audio\n");
    writeSupplementaryConfig(root, "[\"audio\"]");
    UserDefaultSupplementaryGroupsPolicy duplicate(platform);
    const std::string before = readFile(platform.adduserConfigPath);
    require(duplicate.apply() && readFile(platform.adduserConfigPath) == before,
            "last-wins compliant adduser config was adopted or mutated");

    const fs::path real = root / "etc/adduser.real";
    writeFile(real, "ADD_EXTRA_GROUPS=0\nEXTRA_GROUPS=audio\n");
    fs::remove(platform.adduserConfigPath);
    fs::create_symlink(real, platform.adduserConfigPath);
    UserDefaultSupplementaryGroupsPolicy symlink(platform);
    require(!symlink.apply(), "symlink adduser config was accepted");
    fs::remove(platform.adduserConfigPath);
    UserDefaultSupplementaryGroupsPolicy missing(platform);
    require(!missing.apply() && !fs::exists(platform.adduserConfigPath),
            "missing adduser config was created");
}

void testUnsupportedSupplementaryProvider(const fs::path& root) {
    auto platform = platformFor(root);
    platform.supplementaryGroupsProvider =
        fic::platform::UserSupplementaryGroupsProviderKind::Unsupported;
    writeSupplementaryConfig(root, "[]");
    UserDefaultSupplementaryGroupsPolicy policy(platform);
    require(!policy.apply(), "unsupported supplementary provider was accepted");
}

void testPolicies(const fs::path& root) {
    useJournal(root, "scalar-policies");
    auto platform = platformFor(root);
    const fs::path home = root / "srv/home";
    const fs::path skel = root / "etc/skel";
    const fs::path shell = root / "bin/login-shell";
    prepareNativeFiles(platform, home, skel, shell);
    writePolicyConfig(root, home.string(), skel.string(), shell.string(), "users");

    UserHomeBaseDirectoryPolicy homePolicy(platform);
    UserCreateHomePolicy createHomePolicy(platform);
    UserSkeletonDirectoryPolicy skelPolicy(platform);
    UserDefaultShellPolicy shellPolicy(platform);
    UserCreatePrivateGroupPolicy privateGroupPolicy(platform);
    UserDefaultPrimaryGroupPolicy primaryGroupPolicy(platform);
    require(homePolicy.apply(), "HOME policy failed");
    require(createHomePolicy.apply(), "CREATE_HOME policy failed");
    require(skelPolicy.apply(), "SKEL policy failed");
    require(shellPolicy.apply(), "SHELL policy failed");
    require(privateGroupPolicy.apply(), "USERGROUPS_ENAB policy failed");
    require(primaryGroupPolicy.apply(), "GROUP policy failed");
    const std::string useradd = readFile(platform.useraddDefaultsPath);
    require(useradd.find("HOME=" + home.string()) != std::string::npos,
            "HOME was not written");
    require(useradd.find("SKEL=" + skel.string()) != std::string::npos,
            "SKEL was not written");
    require(useradd.find("SHELL=" + shell.string()) != std::string::npos,
            "SHELL was not written");
    require(useradd.find("GROUP=users") != std::string::npos,
            "named GROUP was not written");
    require(useradd.find("INACTIVE=-1\nEXPIRE=\n") != std::string::npos,
            "unrelated useradd defaults changed");
    const std::string loginDefs = readFile(platform.loginDefsPath);
    require(loginDefs.find("CREATE_HOME yes") != std::string::npos &&
                loginDefs.find("USERGROUPS_ENAB yes") != std::string::npos,
            "login.defs booleans were not written");
    const std::string onceUseradd = useradd;
    const std::string onceLoginDefs = loginDefs;
    require(homePolicy.apply() && createHomePolicy.apply() &&
                skelPolicy.apply() && shellPolicy.apply() &&
                privateGroupPolicy.apply() && primaryGroupPolicy.apply(),
            "idempotent apply failed");
    require(readFile(platform.useraddDefaultsPath) == onceUseradd &&
                readFile(platform.loginDefsPath) == onceLoginDefs,
            "idempotent apply changed files");

    writePolicyConfig(root, home.string(), skel.string(), shell.string(),
                      "users", "no", "no");
    UserCreateHomePolicy noCreateHome(platform);
    UserCreatePrivateGroupPolicy noPrivateGroup(platform);
    require(noCreateHome.apply() && noPrivateGroup.apply(),
            "native no values were not applied");
    require(readFile(platform.loginDefsPath).find("CREATE_HOME no") !=
                std::string::npos &&
            readFile(platform.loginDefsPath).find("USERGROUPS_ENAB no") !=
                std::string::npos,
            "yes/no mapping is not native");
}

void testFailClosedValidation(const fs::path& root) {
    auto platform = platformFor(root);
    const fs::path home = root / "valid/home";
    const fs::path skel = root / "valid/skel";
    const fs::path shell = root / "valid/shell";
    prepareNativeFiles(platform, home, skel, shell);

    auto homeRejected = [&](const std::string& value) {
        writePolicyConfig(root, value, skel.string(), shell.string(), "users");
        UserHomeBaseDirectoryPolicy policy(platform);
        const std::string before = readFile(platform.useraddDefaultsPath);
        require(!policy.apply() && readFile(platform.useraddDefaultsPath) == before,
                "unsafe HOME was not fail-closed: " + value);
    };
    homeRejected("/");
    homeRejected("relative");
    homeRejected((root / "missing").string());
    homeRejected((home / "../home").string());
    const fs::path linkedHome = root / "linked-home";
    fs::create_directory_symlink(home, linkedHome);
    homeRejected(linkedHome.string());

    writePolicyConfig(root, home.string(), skel.string(), shell.string(), "100");
    UserDefaultPrimaryGroupPolicy numericGroup(platform);
    require(!numericGroup.apply(), "numeric GROUP was accepted");
    writePolicyConfig(root, home.string(), skel.string(), shell.string(), "missing");
    UserDefaultPrimaryGroupPolicy missingGroup(platform);
    require(!missingGroup.apply(), "missing local GROUP was accepted");
    writeFile(platform.groupPath, "root:x:0:\nmalformed\nusers:x:100:\n");
    writePolicyConfig(root, home.string(), skel.string(), shell.string(), "users");
    UserDefaultPrimaryGroupPolicy malformedGroupFile(platform);
    require(!malformedGroupFile.apply(), "malformed local group file accepted");
    writeFile(platform.groupPath, "root:x:0:\nusers:x:100:\n");

    writePolicyConfig(root, home.string(), skel.string(), shell.string(), "users");
    writeFile(platform.shellsPath, "/bin/false\n");
    UserDefaultShellPolicy unlistedShell(platform);
    require(!unlistedShell.apply(), "shell absent from /etc/shells was accepted");
    fs::remove(platform.shellsPath);
    UserDefaultShellPolicy noShellsFile(platform);
    require(noShellsFile.apply(), "missing optional /etc/shells was rejected");

    const fs::path linkedShell = root / "valid/linked-shell";
    fs::create_symlink(shell, linkedShell);
    writeFile(platform.shellsPath, linkedShell.string() + "\n");
    writePolicyConfig(root, home.string(), skel.string(), linkedShell.string(),
                      "users");
    UserDefaultShellPolicy symlinkShell(platform);
    require(symlinkShell.apply(),
            "shell symlink resolving to an executable regular file was rejected");

    writeFile(platform.useraddDefaultsPath, "HOME=/home\nHOME=/srv/home\n");
    writePolicyConfig(root, home.string(), skel.string(), shell.string(), "users");
    UserHomeBaseDirectoryPolicy duplicate(platform);
    const std::string before = readFile(platform.useraddDefaultsPath);
    require(duplicate.apply() && readFile(platform.useraddDefaultsPath) != before &&
                readFile(platform.useraddDefaultsPath).find(
                    "HOME=" + home.string() + "\n") != std::string::npos,
            "last-wins duplicate native key was not overridden at EOF");

    const fs::path realDefaults = root / "etc/default/useradd.real";
    writeFile(realDefaults, "HOME=/home\n");
    fs::remove(platform.useraddDefaultsPath);
    fs::create_symlink(realDefaults, platform.useraddDefaultsPath);
    writePolicyConfig(root, home.string(), skel.string(), shell.string(), "users");
    UserHomeBaseDirectoryPolicy symlinkConfig(platform);
    const std::string realBefore = readFile(realDefaults);
    require(!symlinkConfig.apply() && readFile(realDefaults) == realBefore,
            "symlink native config was mutated");

    fs::remove(platform.useraddDefaultsPath);
    UserSkeletonDirectoryPolicy missingTarget(platform);
    require(!missingTarget.apply() && !fs::exists(platform.useraddDefaultsPath),
            "missing native config was created");
}

void testDefaultsAndMetadata() {
    fic::platform::UserCreationPlatformConfig platform;
    require(platform.provider ==
                fic::platform::UserCreationProviderKind::ShadowUseradd,
            "wrong provider default");
    require(platform.useraddDefaultsPath == "/etc/default/useradd" &&
                platform.adduserConfigPath == "/etc/adduser.conf" &&
                platform.loginDefsPath == "/etc/login.defs" &&
                platform.passwdPath == "/etc/passwd" &&
                platform.groupPath == "/etc/group" &&
                platform.shellsPath == "/etc/shells",
            "platform native paths are incomplete");
    UserHomeBaseDirectoryPolicy policy(platform);
    require(policy.moduleName == "IDENTITY_ACCESS" &&
                policy.submoduleName == "USER_CREATION" &&
                policy.policyName == "user_home_base_directory",
            "policy hierarchy metadata is wrong");
    UserSkeletonDirectoryPolicy skeleton(platform);
    UserDefaultShellPolicy defaultShell(platform);
    UserDefaultPrimaryGroupPolicy primaryGroup(platform);
    for (const Policy* stringPolicy :
         std::vector<const Policy*>{
             &policy, &skeleton, &defaultShell, &primaryGroup}) {
        const PolicyEditorSpec editor =
            stringPolicy->getPolicyTypeValue().getEditorSpec();
        require(editor.editor == "lineedit" && editor.validator == "none",
                "string policy editor metadata incorrectly requires a numeric value");
    }
    UserDefaultSupplementaryGroupsPolicy supplementary(platform);
    require(supplementary.policyName ==
                "user_default_supplementary_groups" &&
                supplementary.getDefaultValue() == "",
            "supplementary policy metadata/default is wrong");
}

void testSupplementaryGroupsDaemonContract(const fs::path& root) {
    writeFile(
        root / "config/IDENTITY_ACCESS.conf",
        "_schema_version=1\n"
        "user_default_supplementary_groups.status=DISABLE\n");

    fic::platform::UserCreationPlatformConfig platform;
    auto policy =
        std::make_unique<UserDefaultSupplementaryGroupsPolicy>(platform);
    Policy* const policyPtr = policy.get();
    PolicyRegistry registry;
    std::string error;
    require(
        registry.addModule(
            "IDENTITY_ACCESS", ModuleView::Standard, 20, error) &&
            registry.addPolicy(std::move(policy), error),
        error);

    const nlohmann::json descriptor = policyToJson(
        "IDENTITY_ACCESS",
        "USER_CREATION",
        "user_default_supplementary_groups",
        *policyPtr);
    require(
        descriptor.at("default_value") == "" &&
            descriptor.at("value") == "" &&
            !descriptor.at("set").get<bool>() &&
            descriptor.at("value_valid").get<bool>(),
        "unset supplementary-groups descriptor is not logical/API data");

    require(
        setPolicyValue(
            registry,
            "IDENTITY_ACCESS",
            "user_default_supplementary_groups",
            "",
            error),
        error);
    const std::string stored =
        readFile(root / "config/IDENTITY_ACCESS.conf");
    require(
        stored.find("user_default_supplementary_groups.value=[]\n") !=
            std::string::npos,
        "daemon did not store the empty logical group list as []");
}

void testGeneratedConfig() {
    const std::string config = readFile(FIC_GENERATED_IDENTITY_CONFIG_PATH);
    const fic::platform::UserCreationPolicyDefaults defaults;
    for (const auto& [name, value] :
         std::vector<std::pair<std::string, std::string>>{
             {"user_home_base_directory", defaults.homeBaseDirectory},
             {"user_create_home", defaults.createHome},
             {"user_skeleton_directory", defaults.skeletonDirectory},
             {"user_default_shell", defaults.defaultShell},
             {"user_create_private_group", defaults.createPrivateGroup},
             {"user_default_primary_group", defaults.defaultPrimaryGroup}}) {
        require(config.find(name + ".status=DISABLE\n") != std::string::npos,
                "generated policy is not disabled: " + name);
        require(config.find(name + ".value=" + value + "\n") !=
                    std::string::npos,
                "generated policy default is wrong: " + name);
    }
    require(config.find(
                "user_default_supplementary_groups.status=DISABLE\n") !=
                std::string::npos &&
                config.find(
                    "user_default_supplementary_groups.value=[]\n") !=
                    std::string::npos,
            "generated supplementary policy default is unsafe");
}

void testManagedOwnershipLifecycle(const fs::path& root) {
    using namespace fic::identity::user_creation;
    useJournal(root, "managed-lifecycle");
    auto platform = platformFor(root);
    const fs::path path = platform.useraddDefaultsPath;
    const std::string foreign =
        "# foreign\nHOME=/home\nHOME_FOO=/collision\nSHELL=/bin/sh\n";
    writeFile(path, foreign, 0600);
    std::string error;
    auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);

    require(applyManagedPolicy(platform, "user_home_base_directory",
                {{"HOME", "HOME=/srv/home"}}, *journal, error), error);
    require(applyManagedPolicy(platform, "user_default_shell",
                {{"SHELL", "SHELL=/bin/zsh"}}, *journal, error), error);
    std::string applied = readFile(path);
    require(applied.rfind(kBlockEnd) == applied.size() -
                std::string(kBlockEnd).size() - 1,
            "managed block is not at logical EOF");
    require(applied.substr(0, foreign.size()) == foreign,
            "foreign bytes changed during apply");

    int refreshWrites = 0;
    setBeforeUserCreationWriteHookForTests([&]() { ++refreshWrites; });
    require(applyManagedPolicy(platform, "user_home_base_directory",
                {{"HOME", "HOME=/data/home"}}, *journal, error), error);
    setBeforeUserCreationWriteHookForTests({});
    require(refreshWrites == 1 &&
                readFile(path).find("HOME=/data/home\n") != std::string::npos &&
                readFile(path).find("HOME=/srv/home\n") == std::string::npos,
            "value refresh was not one in-place atomic A-to-B replacement");
    applied = readFile(path);

    const std::string shellBlock = canonicalPolicyBlock(
        "user_default_shell", {{"SHELL", "SHELL=/bin/zsh"}});
    const std::string edited = applied + "# edited foreign\nHOME=/actual\n";
    writeFile(path, edited, 0600);
    require(applyManagedPolicy(platform, "user_home_base_directory",
                {{"HOME", "HOME=/data/home"}}, *journal, error), error);
    applied = readFile(path);
    require(applied.find("# edited foreign\nHOME=/actual\n") != std::string::npos &&
                applied.find(shellBlock) != std::string::npos,
            "foreign append canonicalization lost foreign/peer bytes");

    const auto homeRecords = journal->activeRecords(
        {"IDENTITY_ACCESS", "USER_CREATION", "user_home_base_directory"});
    require(homeRecords.size() == 1, "HOME provenance missing");
    require(releaseManagedPolicy(platform, homeRecords.front(), *journal, error) ==
                ReleaseStatus::Success,
            error);
    const std::string released = readFile(path);
    require(released.find("HOME=/actual\n") != std::string::npos &&
                released.find("HOME=/data/home\n") == std::string::npos &&
                released.find(shellBlock) != std::string::npos,
            "HOME release restored history or damaged peer ownership");

    std::optional<std::string> effective;
    require(effectiveValue("GROUP=users\nGROUPS=audio,video\nGROUP=staff\n",
                ConfigKind::UseraddDefaults,
                fic::platform::UseraddDefaultsLookupSemantics::LegacyPrefixMatch,
                "GROUP", effective, error) && effective == "staff",
            "legacy GROUP/GROUPS prefix collision semantics are wrong");
    require(effectiveValue("HOME=/home\nHOME_FOO=/bad\nHOME=/srv/home\n",
                ConfigKind::UseraddDefaults,
                fic::platform::UseraddDefaultsLookupSemantics::LegacyPrefixMatch,
                "HOME", effective, error) && effective == "/srv/home",
            "legacy HOME prefix collision was not neutralized by EOF value");
}

void testManagedDriftAndCas(const fs::path& root) {
    using namespace fic::identity::user_creation;
    useJournal(root, "managed-drift-cas");
    auto platform = platformFor(root);
    const fs::path path = platform.useraddDefaultsPath;
    writeFile(path, "HOME=/home\n", 0600);
    std::string error;
    auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    require(applyManagedPolicy(platform, "user_home_base_directory",
                {{"HOME", "HOME=/srv/home"}}, *journal, error), error);

    std::string drifted = readFile(path);
    const std::size_t value = drifted.find("HOME=/srv/home");
    require(value != std::string::npos, "managed HOME missing");
    drifted.replace(value, std::string("HOME=/srv/home").size(),
                    "HOME=/manual");
    writeFile(path, drifted, 0600);
    const std::string beforeDriftApply = readFile(path);
    require(!applyManagedPolicy(platform, "user_home_base_directory",
                {{"HOME", "HOME=/srv/home"}}, *journal, error) &&
                readFile(path) == beforeDriftApply,
            "manual FIC body edit was overwritten");

    useJournal(root, "managed-cas-race");
    writeFile(path, "HOME=/home\n", 0600);
    journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    setBeforeUserCreationWriteHookForTests([&]() {
        writeFile(path, "HOME=/admin-race\n", 0600);
    });
    require(!applyManagedPolicy(platform, "user_home_base_directory",
                {{"HOME", "HOME=/srv/home"}}, *journal, error),
            "concurrent replacement bypassed CAS");
    setBeforeUserCreationWriteHookForTests({});
    require(readFile(path) == "HOME=/admin-race\n",
            "CAS failure overwrote the external writer");
}

void testManagedPreparedRecovery(const fs::path& root) {
    using namespace fic::identity::user_creation;
    using fic::rollback::MutationStatus;
    const std::vector<Assignment> oldValue{{"HOME", "HOME=/srv/home"}};
    const std::vector<Assignment> newValue{{"HOME", "HOME=/data/home"}};
    const std::vector<Assignment> thirdValue{{"HOME", "HOME=/manual"}};
    auto platform = platformFor(root);
    const fs::path path = platform.useraddDefaultsPath;
    std::string error;

    // Crash after Prepared and before the physical write: absent ownership is
    // released, so retry creates a fresh mutation from current foreign state.
    useJournal(root, "prepared-before-write");
    writeFile(path, "HOME=/home\n", 0600);
    auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    prepareUserCreationRecord(*journal, platform, oldValue);
    useJournal(root, "prepared-before-write"); // reopen persisted crash state
    journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr &&
                applyManagedPolicy(platform, "user_home_base_directory",
                                   oldValue, *journal, error),
            error);
    auto active = journal->activeRecords(
        {"IDENTITY_ACCESS", "USER_CREATION", "user_home_base_directory"});
    require(active.size() == 1 && active.front().status == MutationStatus::Applied,
            "Prepared-before-write recovery did not finish Applied");

    // Crash after physical install and before Prepared -> Applied.
    useJournal(root, "prepared-after-write");
    writeFile(path, "HOME=/home\n", 0600);
    journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    prepareUserCreationRecord(*journal, platform, oldValue);
    std::string installed;
    bool changed = false;
    require(upsertPolicyBlock(readFile(path), ConfigKind::UseraddDefaults,
                "user_home_base_directory", oldValue, installed, changed, error),
            error);
    writeFile(path, installed, 0600);
    useJournal(root, "prepared-after-write");
    journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr &&
                applyManagedPolicy(platform, "user_home_base_directory",
                                   oldValue, *journal, error),
            error);
    active = journal->activeRecords(
        {"IDENTITY_ACCESS", "USER_CREATION", "user_home_base_directory"});
    require(active.size() == 1 && active.front().status == MutationStatus::Applied,
            "physical target was not adopted as Applied after restart");

    // Prepared refresh with the previous side present continues A -> B.
    useJournal(root, "prepared-refresh-previous");
    writeFile(path, "HOME=/home\n", 0600);
    journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr &&
                applyManagedPolicy(platform, "user_home_base_directory",
                                   oldValue, *journal, error),
            error);
    prepareUserCreationRecord(*journal, platform, newValue, oldValue);
    useJournal(root, "prepared-refresh-previous");
    journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr &&
                applyManagedPolicy(platform, "user_home_base_directory",
                                   newValue, *journal, error),
            error);
    require(readFile(path).find("HOME=/data/home\n") != std::string::npos,
            "Prepared refresh did not advance the previous side");

    // Prepared refresh with the target side present commits that same record.
    useJournal(root, "prepared-refresh-target");
    writeFile(path, "HOME=/home\n", 0600);
    journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr &&
                applyManagedPolicy(platform, "user_home_base_directory",
                                   oldValue, *journal, error),
            error);
    prepareUserCreationRecord(*journal, platform, newValue, oldValue);
    require(upsertPolicyBlock(readFile(path), ConfigKind::UseraddDefaults,
                "user_home_base_directory", newValue, installed, changed, error),
            error);
    writeFile(path, installed, 0600);
    useJournal(root, "prepared-refresh-target");
    journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr &&
                applyManagedPolicy(platform, "user_home_base_directory",
                                   newValue, *journal, error),
            error);
    active = journal->activeRecords(
        {"IDENTITY_ACCESS", "USER_CREATION", "user_home_base_directory"});
    require(active.size() == 1 && active.front().status == MutationStatus::Applied,
            "Prepared target side was not committed Applied");

    // A third same-policy body is neither side of the durable transition.
    useJournal(root, "prepared-refresh-conflict");
    writeFile(path, "HOME=/home\n", 0600);
    journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr &&
                applyManagedPolicy(platform, "user_home_base_directory",
                                   oldValue, *journal, error),
            error);
    prepareUserCreationRecord(*journal, platform, newValue, oldValue);
    require(upsertPolicyBlock(readFile(path), ConfigKind::UseraddDefaults,
                "user_home_base_directory", thirdValue, installed, changed, error),
            error);
    writeFile(path, installed, 0600);
    const std::string conflict = readFile(path);
    require(!applyManagedPolicy(platform, "user_home_base_directory",
                               newValue, *journal, error) &&
                readFile(path) == conflict,
            "third Prepared refresh state was overwritten");
}

void testManagedReleaseCrashRecovery(const fs::path& root) {
    using namespace fic::identity::user_creation;
    useJournal(root, "release-before-journal-commit");
    auto platform = platformFor(root);
    const fs::path path = platform.useraddDefaultsPath;
    writeFile(path, "HOME=/home\n", 0600);
    std::string error;
    auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    const std::vector<Assignment> desired{{"HOME", "HOME=/srv/home"}};
    require(journal != nullptr &&
                applyManagedPolicy(platform, "user_home_base_directory",
                                   desired, *journal, error),
            error);
    const auto active = journal->activeRecords(
        {"IDENTITY_ACCESS", "USER_CREATION", "user_home_base_directory"});
    require(active.size() == 1, "release recovery provenance missing");
    require(releaseManagedPolicy(platform, active.front(), *journal, error) ==
                ReleaseStatus::Success,
            error);
    useJournal(root, "release-before-journal-commit"); // physical release won
    journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr &&
                releaseManagedPolicy(platform, active.front(), *journal, error) ==
                    ReleaseStatus::NothingToDo,
            "released ownership was reconstructed after restart");
    require(readFile(path) == "HOME=/home\n",
            "release recovery changed current foreign state");
}

void testManagedDurabilityAndCompensation(const fs::path& root) {
    using namespace fic::identity::user_creation;
    const std::vector<Assignment> desired{{"HOME", "HOME=/srv/home"}};
    auto platform = platformFor(root);
    const fs::path path = platform.useraddDefaultsPath;
    std::string error;

    // The replacement was installed but its first directory fsync failed.
    // A durable exact compensation proves that no mutation remains, so fresh
    // Prepared provenance must be discarded.
    useJournal(root, "durability-compensated");
    writeFile(path, "HOME=/home\n", 0600);
    auto* journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    int configFsyncs = 0;
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [&](const std::string& fsyncPath) {
            if (fsyncPath != path.string()) return true;
            return ++configFsyncs > 1;
        });
    require(!applyManagedPolicy(platform, "user_home_base_directory",
                                desired, *journal, error),
            "post-rename durability failure was reported as success");
    AtomicFileWriter::setDirectoryFsyncHookForTests({});
    require(readFile(path) == "HOME=/home\n" &&
                journal->activeRecords({"IDENTITY_ACCESS", "USER_CREATION",
                    "user_home_base_directory"}).empty(),
            "durable compensation left fresh provenance or changed bytes");

    // If neither install nor compensation durability can be proven, keep the
    // Prepared record recoverable instead of claiming a clean rollback.
    useJournal(root, "durability-indeterminate");
    writeFile(path, "HOME=/home\n", 0600);
    journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [&](const std::string& fsyncPath) {
            return fsyncPath != path.string();
        });
    require(!applyManagedPolicy(platform, "user_home_base_directory",
                                desired, *journal, error),
            "indeterminate directory state was reported as success");
    AtomicFileWriter::setDirectoryFsyncHookForTests({});
    const auto active = journal->activeRecords(
        {"IDENTITY_ACCESS", "USER_CREATION", "user_home_base_directory"});
    require(active.size() == 1 &&
                active.front().status == fic::rollback::MutationStatus::Prepared,
            "unproven compensation discarded recoverable Prepared provenance");

    // An external replacement after FIC's install invalidates compensation's
    // CAS proof. It must survive byte-exact, with Prepared retained.
    useJournal(root, "compensation-race");
    writeFile(path, "HOME=/home\n", 0600);
    journal = fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    setAfterUserCreationWriteHookForTests(
        [&]() { writeFile(path, "HOME=/external\n", 0600); });
    require(!applyManagedPolicy(platform, "user_home_base_directory",
                                desired, *journal, error),
            "external post-install replacement was reported as success");
    setAfterUserCreationWriteHookForTests({});
    require(readFile(path) == "HOME=/external\n",
            "compensation overwrote an external replacement");
    const auto raced = journal->activeRecords(
        {"IDENTITY_ACCESS", "USER_CREATION", "user_home_base_directory"});
    require(raced.size() == 1 &&
                raced.front().status == fic::rollback::MutationStatus::Prepared,
            "compensation race lost recoverable Prepared provenance");
}

} // namespace

int main() {
    try {
        std::string pattern =
            (fs::temp_directory_path() / "fic-user-creation-tests-XXXXXX")
                .string();
        char* created = ::mkdtemp(pattern.data());
        require(created != nullptr, "cannot create unique test directory");
        const fs::path root = created;
        initializePaths(root);
        testHandler(root);
        testGroupListValueType();
        testAdduserHandler(root);
        testShadowSupplementaryPolicy(root);
        testAdduserSupplementaryPolicy(root);
        testUnsupportedSupplementaryProvider(root);
        testPolicies(root);
        testFailClosedValidation(root);
        testDefaultsAndMetadata();
        testGeneratedConfig();
        testManagedOwnershipLifecycle(root);
        testManagedDriftAndCas(root);
        testManagedPreparedRecovery(root);
        testManagedReleaseCrashRecovery(root);
        testManagedDurabilityAndCompensation(root);
        testSupplementaryGroupsDaemonContract(root);
        fs::remove_all(root);
        std::cout << "UserCreationTests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "UserCreationTests failed: " << error.what() << '\n';
        return 1;
    }
}
