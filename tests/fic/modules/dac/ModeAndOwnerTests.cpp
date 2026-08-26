#include "modules/dac/mode_and_owner/ModeAndOwner.h"
#include "modules/dac/mode_and_owner/policies/DAC_blocking_user_access_to_system_files.h"
#include "modules/dac/mode_and_owner/policies/DAC_custom_mode_and_owner.h"
#include "modules/dac/mode_and_owner/policies/DAC_systemcommandlock.h"

#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/logging/Logger.h>

#include <algorithm>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <grp.h>
#include <pwd.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {
namespace fs = std::filesystem;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::string currentOwner() {
    const struct passwd* owner = ::getpwuid(::geteuid());
    require(owner != nullptr, "could not resolve test owner");
    return owner->pw_name;
}

std::string currentGroup() {
    const struct group* group = ::getgrgid(::getegid());
    require(group != nullptr, "could not resolve test group");
    return group->gr_name;
}

void writeFile(const fs::path& path,
               const std::string& content,
               mode_t mode) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(output.is_open(), "could not create " + path.string());
    output << content;
    output.close();
    require(output.good(), "could not write " + path.string());
    require(::chmod(path.c_str(), mode) == 0,
            "could not chmod " + path.string());
}

mode_t fileMode(const fs::path& path) {
    struct stat info {};
    require(::lstat(path.c_str(), &info) == 0,
            "could not stat " + path.string());
    return info.st_mode & 07777;
}

void initializeRuntimePaths(const fs::path& root,
                            const fs::path& missingCustomPath) {
    auto paths = fic::core::FicProductPaths::production();
    paths.privateBinDir = root / "bin";
    paths.configDir = root / "config";
    paths.defaultConfigDir = root / "share/default-config";
    paths.languageDir = root / "lang";
    paths.logDir = root / "log";
    paths.notifyDir = root / "notify";
    paths.dataDir = root / "data";
    paths.shareDir = root / "share";
    paths.imageDir = root / "image";
    paths.runtimeDir = root / "run";
    paths.lockStatusFile = root / "lockstatus";
    paths.commandHashFile = root / "data/commandhash.txt";
    paths.deviceDatabaseFile = root / "data/devices.db";
    paths.deviceDatabaseLockFile = root / "log/devices.lock";
    paths.lockDebugLogFile = root / "log/db-lock.log";

    fs::create_directories(paths.configDir);
    fs::create_directories(paths.logDir);
    fs::create_directories(paths.dataDir);
    const std::string customValue =
        "[{\"path\":\"" + missingCustomPath.string() +
        "\",\"owner\":\"" + currentOwner() +
        "\",\"group\":\"" + currentGroup() +
        "\",\"mode\":\"0644\"}]";
    writeFile(
        paths.configDir / "DAC.conf",
        "_schema_version=1\n"
        "custom_mode_and_owner.status=ENABLE\n"
        "custom_mode_and_owner.value=" + customValue + "\n",
        0640);
    writeFile(
        paths.configDir / "AUDIT.conf",
        "_schema_version=1\n"
        "log_level.status=ENABLE\n"
        "log_level.value=TRACE\n",
        0640);

    std::string error;
    require(fic::core::FicRuntimePaths::initialize(paths, error), error);
}

class TestModeAndOwner final : public ModeAndOwner {
public:
    explicit TestModeAndOwner(MissingFilePolicy missingPolicy)
        : ModeAndOwner(missingPolicy) {
        policyName = "mode_and_owner_test";
    }

    void addRule(const fs::path& path,
                 const std::string& owner,
                 const std::string& group,
                 mode_t mode,
                 std::vector<fs::path> allowedTargets = {}) {
        addExpectedRule(
            path, owner, group, mode, std::move(allowedTargets));
    }

    std::string expectedOwner(const fs::path& path) const {
        return expected.at(path.string()).stats._owner;
    }

    std::string expectedGroup(const fs::path& path) const {
        return expected.at(path.string()).stats._group;
    }
};

void testSpecialPermissionBits(const fs::path& root) {
    const fs::path file = root / "special-bits";
    writeFile(file, "data", 04755);

    FileStats actual4755(file.string());
    FileStats expected0755(currentOwner(), currentGroup(), 0755);
    FileStats expected4755(currentOwner(), currentGroup(), 04755);
    require(!actual4755.check_permission(expected0755),
            "4755 unexpectedly matched 0755");
    require(actual4755.check_permission(expected4755),
            "4755 did not match 4755");

    require(::chmod(file.c_str(), 03775) == 0, "could not set SGID/sticky bits");
    FileStats actual3775(file.string());
    FileStats expected1775(currentOwner(), currentGroup(), 01775);
    FileStats expected3775(currentOwner(), currentGroup(), 03775);
    require(!actual3775.check_permission(expected1775),
            "SGID bit was ignored during comparison");
    require(actual3775.check_permission(expected3775),
            "SGID/sticky bits were not preserved during comparison");
}

void testRemediationAndVerification(const fs::path& root) {
    const fs::path addSuid = root / "add-suid";
    writeFile(addSuid, "data", 0755);
    TestModeAndOwner addPolicy(MissingFilePolicy::Fail);
    addPolicy.addRule(addSuid, currentOwner(), currentGroup(), 04755);
    require(addPolicy.apply(), "4755 remediation failed verification");
    require(fileMode(addSuid) == 04755, "4755 was not applied");

    const fs::path removeSuid = root / "remove-suid";
    writeFile(removeSuid, "data", 04755);
    TestModeAndOwner removePolicy(MissingFilePolicy::Fail);
    removePolicy.addRule(removeSuid, currentOwner(), currentGroup(), 0755);
    require(removePolicy.apply(), "0755 remediation failed verification");
    require(fileMode(removeSuid) == 0755, "unexpected SUID bit remained");
}

void testMissingFilePolicies(const fs::path& root,
                             const fs::path& customMissing) {
    fic::platform::DacPlatformConfig systemFiles;
    systemFiles.protectedSystemFiles.push_back(
        {root / "missing-system-file", currentOwner(), currentGroup(), 0644});
    DAC_blocking_user_access_to_system_files filesPolicy(systemFiles);
    require(filesPolicy.apply(), "missing profiled system file was not ignored");

    fic::platform::DacPlatformConfig commands;
    commands.protectedSystemCommands.push_back(
        {root / "missing-system-command", currentOwner(), currentGroup(), 0755});
    DAC_systemcommandlock commandPolicy(commands);
    require(commandPolicy.apply(), "missing profiled command was not ignored");

    require(!fs::exists(customMissing), "custom test path unexpectedly exists");
    DAC_custom_mode_and_owner customPolicy;
    require(!customPolicy.apply(), "missing custom path was ignored");
}

void testSymlinkIsRejected(const fs::path& root) {
    const fs::path target = root / "symlink-target";
    const fs::path link = root / "symlink-rule";
    writeFile(target, "unchanged", 0644);
    fs::create_symlink(target, link);

    FileStats linkStats(link.string());
    require(linkStats.has_error(), "symlink was not reported as an open error");
    require(!linkStats.is_missing(), "symlink error was treated as missing");
    require(linkStats.error_code().value() == ELOOP,
            "symlink errno was not preserved");
    require(linkStats.error_message().find("errno=") != std::string::npos,
            "system error details were lost");

    TestModeAndOwner policy(MissingFilePolicy::Fail);
    policy.addRule(link, currentOwner(), currentGroup(), 0600);
    require(!policy.apply(), "symlink rule unexpectedly succeeded");
    require(fs::is_symlink(link), "symlink was replaced");
    require(fileMode(target) == 0644, "symlink target was modified");
}

void testProfileDrivenFinalSymlinks(const fs::path& root) {
    const std::string owner = currentOwner();
    const std::string group = currentGroup();

    const fs::path regular = root / "regular-with-empty-allowlist";
    writeFile(regular, "regular", 0644);
    TestModeAndOwner regularPolicy(MissingFilePolicy::Fail);
    regularPolicy.addRule(regular, owner, group, 0600);
    require(regularPolicy.apply(),
            "regular path with an empty allowlist failed");
    require(fileMode(regular) == 0600,
            "regular path permissions were not changed");

    const fs::path absoluteTarget = root / "absolute-target";
    const fs::path absoluteLink = root / "absolute-link";
    writeFile(absoluteTarget, "absolute", 0644);
    fs::create_symlink(absoluteTarget, absoluteLink);
    fic::platform::DacPlatformConfig profiledRules;
    profiledRules.protectedSystemFiles.push_back(
        {absoluteLink, owner, group, 0600, {absoluteTarget}});
    DAC_blocking_user_access_to_system_files absolutePolicy(profiledRules);
    require(absolutePolicy.apply(), "allowed absolute symlink failed");
    require(fileMode(absoluteTarget) == 0600,
            "absolute symlink target was not changed");

    const fs::path relativeTarget = root / "relative-target";
    const fs::path linkDirectory = root / "relative-links";
    const fs::path relativeLink = linkDirectory / "resolv.conf";
    writeFile(relativeTarget, "relative", 0644);
    fs::create_directories(linkDirectory);
    fs::create_symlink("../relative-target", relativeLink);
    TestModeAndOwner relativePolicy(MissingFilePolicy::Fail);
    relativePolicy.addRule(
        relativeLink, owner, group, 0600, {relativeTarget});
    require(relativePolicy.apply(),
            "allowed relative symlink with .. was not normalized");
    require(fileMode(relativeTarget) == 0600,
            "relative symlink target was not changed");

    const fs::path unexpectedTarget = root / "unexpected-target";
    const fs::path unexpectedLink = root / "unexpected-link";
    writeFile(unexpectedTarget, "unexpected", 0644);
    fs::create_symlink(unexpectedTarget, unexpectedLink);
    TestModeAndOwner unexpectedPolicy(MissingFilePolicy::Fail);
    unexpectedPolicy.addRule(
        unexpectedLink, owner, group, 0600, {absoluteTarget});
    require(!unexpectedPolicy.apply(),
            "unexpected final symlink target was accepted");
    require(fileMode(unexpectedTarget) == 0644,
            "unexpected symlink target was modified");

    const fs::path attackerDirectory = root / "attacker-directory";
    const fs::path attackerTarget = attackerDirectory / "target";
    const fs::path allowedNamespace = root / "allowed-namespace";
    const fs::path intermediateLink = allowedNamespace / "component";
    const fs::path lexicalAllowedTarget = intermediateLink / "target";
    const fs::path policyLink = root / "intermediate-policy-link";
    writeFile(attackerTarget, "attacker", 0644);
    fs::create_directories(allowedNamespace);
    fs::create_directory_symlink(attackerDirectory, intermediateLink);
    fs::create_symlink(lexicalAllowedTarget, policyLink);
    TestModeAndOwner intermediatePolicy(MissingFilePolicy::Fail);
    intermediatePolicy.addRule(
        policyLink, owner, group, 0600, {lexicalAllowedTarget});
    require(!intermediatePolicy.apply(),
            "intermediate target symlink was accepted");
    require(fileMode(attackerTarget) == 0644,
            "target behind an intermediate symlink was modified");

    const fs::path missingTarget = root / "missing-allowed-target";
    const fs::path missingLink = root / "missing-allowed-link";
    fs::create_symlink(missingTarget, missingLink);
    fic::platform::DacPlatformConfig missingProfileRule;
    missingProfileRule.protectedSystemFiles.push_back(
        {missingLink, owner, group, 0644, {missingTarget}});
    DAC_blocking_user_access_to_system_files ignoredMissingPolicy(
        missingProfileRule);
    require(ignoredMissingPolicy.apply(),
            "missing allowed profile target was not ignored");
    TestModeAndOwner requiredMissingPolicy(MissingFilePolicy::Fail);
    requiredMissingPolicy.addRule(
        missingLink, owner, group, 0644, {missingTarget});
    require(!requiredMissingPolicy.apply(),
            "missing allowed required target was ignored");

    FileAccessRulesPolicyTypeValue restrictionInfo({
        {regular, owner, group, 0600},
        {absoluteLink, owner, group, 0600, {absoluteTarget}}
    });
    const std::string displayed = restrictionInfo.getPolicyRestrictionInfo();
    require(displayed.find(absoluteTarget.string()) != std::string::npos,
            "profile symlink exception is absent from restriction info");
    const std::string marker = "final symlink ->";
    const std::size_t firstMarker = displayed.find(marker);
    require(firstMarker != std::string::npos &&
                displayed.find(marker, firstMarker + marker.size()) ==
                    std::string::npos,
            "restriction info showed a symlink exception for a regular rule");
}

void testCustomSymlinkRemainsFailClosed(const fs::path& root) {
    const fs::path target = root / "custom-symlink-target";
    const fs::path link = root / "custom-symlink-rule";
    writeFile(target, "custom", 0644);
    fs::create_symlink(target, link);
    const std::string customValue =
        "[{\"path\":\"" + link.string() +
        "\",\"owner\":\"" + currentOwner() +
        "\",\"group\":\"" + currentGroup() +
        "\",\"mode\":\"0600\"}]";
    writeFile(
        root / "config/DAC.conf",
        "_schema_version=1\n"
        "custom_mode_and_owner.status=ENABLE\n"
        "custom_mode_and_owner.value=" + customValue + "\n",
        0640);

    DAC_custom_mode_and_owner policy;
    require(!policy.apply(), "custom policy accepted a final symlink");
    require(fileMode(target) == 0644,
            "custom policy modified a symlink target");
}

void testChownThenRestoresSpecialBits(const fs::path& root) {
    std::string targetOwner;
    std::string targetGroup;
    uid_t targetOwnerId = ::geteuid();
    gid_t targetGroupId = ::getegid();
    if (::geteuid() == 0) {
        const struct passwd* user = ::getpwnam("nobody");
        if (user == nullptr) {
            return;
        }
        const struct group* group = ::getgrgid(user->pw_gid);
        if (group == nullptr) {
            return;
        }
        targetOwner = user->pw_name;
        targetGroup = group->gr_name;
        targetOwnerId = user->pw_uid;
        targetGroupId = group->gr_gid;
    } else {
        int groupCount = ::getgroups(0, nullptr);
        if (groupCount <= 0) {
            return;
        }
        std::vector<gid_t> groups(static_cast<std::size_t>(groupCount));
        require(::getgroups(groupCount, groups.data()) == groupCount,
                "could not read supplementary groups");
        const auto different = std::find_if(
            groups.begin(), groups.end(),
            [](gid_t id) { return id != ::getegid(); });
        if (different == groups.end()) {
            return;
        }
        const struct group* group = ::getgrgid(*different);
        if (group == nullptr) {
            return;
        }
        targetOwner = currentOwner();
        targetGroup = group->gr_name;
        targetGroupId = group->gr_gid;
    }

    const fs::path probe = root / "chown-capability-probe";
    writeFile(probe, "probe", 04755);
    if (::chown(probe.c_str(), targetOwnerId, targetGroupId) != 0) {
        fs::remove(probe);
        return;
    }
    fs::remove(probe);

    const fs::path file = root / "chown-clears-suid";
    writeFile(file, "special", 04755);
    TestModeAndOwner policy(MissingFilePolicy::Fail);
    policy.addRule(file, targetOwner, targetGroup, 04755);
    require(policy.apply(),
            "one apply did not restore special bits cleared by fchown");
    require(fileMode(file) == 04755,
            "SUID bit cleared by fchown was not restored");
}

void testUnknownIdentitiesAndDiagnostics(const fs::path& root) {
    const fs::path unknownGroupFile = root / "unknown-group";
    writeFile(unknownGroupFile, "data", 0644);
    TestModeAndOwner groupPolicy(MissingFilePolicy::Fail);
    const std::string missingGroup = "fic-no-such-group-9f67b7";
    groupPolicy.addRule(
        unknownGroupFile, currentOwner(), missingGroup, 0644);
    require(!groupPolicy.apply(), "unknown group fell back to another group");
    require(groupPolicy.expectedGroup(unknownGroupFile) == missingGroup,
            "apply mutated the expected group");

    const fs::path unknownOwnerFile = root / "unknown-owner";
    writeFile(unknownOwnerFile, "data", 0600);
    TestModeAndOwner ownerPolicy(MissingFilePolicy::Fail);
    const std::string missingOwner = "fic-no-such-owner-5c11aa";
    ownerPolicy.addRule(
        unknownOwnerFile, missingOwner, currentGroup(), 0644);
    Logger::ScopedCapture capture;
    require(!ownerPolicy.apply(), "unknown owner unexpectedly succeeded");
    const LogCaptureResult logs = capture.finish();
    require(ownerPolicy.expectedOwner(unknownOwnerFile) == missingOwner,
            "apply mutated the expected owner");
    require(fileMode(unknownOwnerFile) == 0644,
            "successful permission remediation was rolled back");

    bool lookupCauseLogged = false;
    bool verificationLogged = false;
    for (const LogRecord& record : logs.records) {
        lookupCauseLogged = lookupCauseLogged ||
            record.message.find("expected owner does not exist") !=
                std::string::npos;
        verificationLogged = verificationLogged ||
            record.message.find("Контрольная проверка владельца/группы") !=
                std::string::npos;
    }
    require(lookupCauseLogged && verificationLogged,
            "not all diagnostics for one failed requirement were logged");
}

void testChownFailureReturnsFalse(const fs::path& root) {
    if (::geteuid() == 0) {
        return;
    }
    const struct passwd* rootUser = ::getpwnam("root");
    if (rootUser == nullptr || rootUser->pw_uid == ::geteuid()) {
        return;
    }
    const fs::path file = root / "chown-failure";
    writeFile(file, "data", 0644);
    TestModeAndOwner policy(MissingFilePolicy::Fail);
    policy.addRule(file, "root", currentGroup(), 0644);
    Logger::ScopedCapture capture;
    require(!policy.apply(), "failed fchown did not fail apply");
    const LogCaptureResult logs = capture.finish();
    bool syscallCauseLogged = false;
    for (const LogRecord& record : logs.records) {
        syscallCauseLogged = syscallCauseLogged ||
            record.message.find("fchown") != std::string::npos;
    }
    require(syscallCauseLogged, "fchown system cause was not logged");
}
} // namespace

int main() {
    const fs::path root = fs::temp_directory_path() /
        ("fic-mode-owner-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root);
    const fs::path customMissing = root / "missing-custom";
    initializeRuntimePaths(root, customMissing);

    testSpecialPermissionBits(root);
    testRemediationAndVerification(root);
    testMissingFilePolicies(root, customMissing);
    testSymlinkIsRejected(root);
    testProfileDrivenFinalSymlinks(root);
    testCustomSymlinkRemainsFailClosed(root);
    testChownThenRestoresSpecialBits(root);
    testUnknownIdentitiesAndDiagnostics(root);
    testChownFailureReturnsFalse(root);

    fs::remove_all(root);
    return 0;
}
