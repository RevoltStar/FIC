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
#include <iomanip>
#include <pwd.h>
#include <sstream>
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

bool applyCustomRule(const fs::path& configRoot,
                     const fs::path& path,
                     mode_t mode) {
    std::ostringstream modeText;
    modeText << std::setfill('0') << std::setw(4) << std::oct << mode;
    const std::string customValue =
        "[{\"path\":\"" + path.string() +
        "\",\"owner\":\"" + currentOwner() +
        "\",\"group\":\"" + currentGroup() +
        "\",\"mode\":\"" + modeText.str() + "\"}]";
    writeFile(
        configRoot / "config/DAC.conf",
        "_schema_version=1\n"
        "custom_mode_and_owner.status=ENABLE\n"
        "custom_mode_and_owner.value=" + customValue + "\n",
        0640);
    DAC_custom_mode_and_owner policy;
    return policy.apply();
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
                 std::vector<fs::path> allowedTargets = {},
                 std::vector<fic::platform::ProviderManagedFileTarget>
                     providerTargets = {}) {
        addExpectedRule(
            path, owner, group, mode, std::move(allowedTargets),
            std::move(providerTargets));
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

void testBuiltInMaximumModeSemantics(const fs::path& root) {
    const fs::path tightened = root / "maximum-tightened";
    const fs::path alreadyStricter = root / "maximum-already-stricter";
    const fs::path excessiveBits = root / "maximum-excessive-bits";
    const fs::path specialBits = root / "maximum-special-bits";
    const fs::path allowedSpecialAbsent = root / "maximum-special-absent";
    writeFile(tightened, "tightened", 0644);
    writeFile(alreadyStricter, "stricter", 0600);
    writeFile(excessiveBits, "excessive", 0677);
    writeFile(specialBits, "special", 06755);
    writeFile(allowedSpecialAbsent, "no-special", 0755);

    fic::platform::DacPlatformConfig files;
    files.protectedSystemFiles = {
        {tightened, currentOwner(), currentGroup(), 0600},
        {alreadyStricter, currentOwner(), currentGroup(), 0640},
        {excessiveBits, currentOwner(), currentGroup(), 0640},
        {specialBits, currentOwner(), currentGroup(), 0755},
        {allowedSpecialAbsent, currentOwner(), currentGroup(), 04755}
    };
    DAC_blocking_user_access_to_system_files filePolicy(files);
    require(filePolicy.apply(), "built-in maximum file modes failed");
    require(fileMode(tightened) == 0600,
            "built-in policy did not remove excessive permissions");
    require(fileMode(alreadyStricter) == 0600,
            "built-in policy widened an already stricter mode");
    require(fileMode(excessiveBits) == 0640,
            "built-in policy did not remove group/other permissions");
    require(fileMode(specialBits) == 0755,
            "built-in policy did not remove disallowed special bits");
    require(fileMode(allowedSpecialAbsent) == 0755,
            "built-in policy added an allowed but absent SUID bit");

    const fs::path stricterCommand = root / "maximum-command";
    writeFile(stricterCommand, "command", 0700);
    fic::platform::DacPlatformConfig commands;
    commands.protectedSystemCommands = {
        {stricterCommand, currentOwner(), currentGroup(), 0755}
    };
    DAC_systemcommandlock commandPolicy(commands);
    require(commandPolicy.apply(), "built-in command maximum mode failed");
    require(fileMode(stricterCommand) == 0700,
            "systemcommandlock widened an already stricter mode");

    const fs::path customExact = root / "custom-exact-mode";
    writeFile(customExact, "custom", 0600);
    require(applyCustomRule(root, customExact, 0640),
            "custom exact mode application failed");
    require(fileMode(customExact) == 0640,
            "custom_mode_and_owner lost exact mode semantics");

    if (::geteuid() == 0) {
        const fs::path ownership = root / "maximum-owner";
        writeFile(ownership, "owner", 0600);
        fic::platform::DacPlatformConfig ownershipConfig;
        ownershipConfig.protectedSystemFiles = {
            {ownership, "nobody", "nobody", 0640}
        };
        DAC_blocking_user_access_to_system_files ownershipPolicy(
            ownershipConfig);
        require(ownershipPolicy.apply(),
                "built-in owner/group remediation failed");
        struct stat info {};
        require(::stat(ownership.c_str(), &info) == 0,
                "could not stat ownership fixture");
        const struct passwd* nobody = ::getpwnam("nobody");
        const struct group* nobodyGroup = ::getgrnam("nobody");
        require(nobody != nullptr && nobodyGroup != nullptr,
                "nobody identity is unavailable");
        require(info.st_uid == nobody->pw_uid &&
                    info.st_gid == nobodyGroup->gr_gid,
                "built-in owner/group was not enforced");
        require((info.st_mode & 07777) == 0600,
                "owner/group remediation widened the file mode");
    }
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
    require(
        customPolicy.getDefaultValue() == "" &&
            customPolicy.validate(customPolicy.getDefaultValue()) &&
            customPolicy.postprocessingValue("") == "[]" &&
            customPolicy.reverse_postprocessingValue("[]") == "",
        "custom mode-and-owner logical/storage contract is incorrect");
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

void testProviderManagedFinalSymlinks(const fs::path& root) {
    using Provider = fic::platform::ManagedFileProvider;
    const std::string owner = currentOwner();
    const std::string group = currentGroup();
    const std::vector<std::pair<std::string, Provider>> cases = {
        {"resolved-stub", Provider::SystemdResolved},
        {"resolved-non-stub", Provider::SystemdResolved},
        {"network-manager", Provider::NetworkManager},
        {"resolvconf", Provider::Resolvconf}
    };
    for (const auto& [name, provider] : cases) {
        const fs::path target = root / (name + "-target");
        const fs::path link = root / (name + "-link");
        writeFile(target, name, 0644);
        fs::create_symlink(target, link);
        fic::platform::DacPlatformConfig config;
        config.protectedSystemFiles = {{
            link, owner, group, 0644, {}, {{target, provider}}
        }};
        DAC_blocking_user_access_to_system_files policy(config);
        require(policy.apply(),
                "valid provider-managed resolver target was rejected: " + name);
        require(fileMode(target) == 0644,
                "compliant provider-managed target was modified: " + name);
    }

    const fs::path staticFile = root / "static-resolv.conf";
    writeFile(staticFile, "static", 0666);
    fic::platform::DacPlatformConfig staticConfig;
    staticConfig.protectedSystemFiles = {{
        staticFile, owner, group, 0644
    }};
    DAC_blocking_user_access_to_system_files staticPolicy(staticConfig);
    require(staticPolicy.apply(), "static resolver file remediation failed");
    require(fileMode(staticFile) == 0644,
            "static resolver file was not remediated");

    const fs::path invalidTarget = root / "provider-invalid-mode";
    const fs::path invalidLink = root / "provider-invalid-link";
    writeFile(invalidTarget, "invalid", 0666);
    fs::create_symlink(invalidTarget, invalidLink);
    fic::platform::DacPlatformConfig invalidConfig;
    invalidConfig.protectedSystemFiles = {{
        invalidLink, owner, group, 0644, {},
        {{invalidTarget, Provider::NetworkManager}}
    }};
    DAC_blocking_user_access_to_system_files invalidPolicy(invalidConfig);
    require(!invalidPolicy.apply(),
            "provider-managed target with excessive mode was accepted");
    require(fileMode(invalidTarget) == 0666,
            "validate-only provider target was chmoded");

    const fs::path arbitraryTarget = root / "evil-resolv.conf";
    const fs::path arbitraryLink = root / "evil-resolv-link";
    writeFile(arbitraryTarget, "evil", 0644);
    fs::create_symlink(arbitraryTarget, arbitraryLink);
    fic::platform::DacPlatformConfig arbitraryConfig;
    arbitraryConfig.protectedSystemFiles = {{
        arbitraryLink, owner, group, 0644, {},
        {{invalidTarget, Provider::NetworkManager}}
    }};
    DAC_blocking_user_access_to_system_files arbitraryPolicy(arbitraryConfig);
    require(!arbitraryPolicy.apply(), "arbitrary resolver target was accepted");
    require(fileMode(arbitraryTarget) == 0644,
            "arbitrary resolver target was modified");

    if (::geteuid() == 0) {
        const fs::path ownerTarget = root / "provider-invalid-owner";
        const fs::path ownerLink = root / "provider-owner-link";
        writeFile(ownerTarget, "owner", 0644);
        const struct passwd* nobody = ::getpwnam("nobody");
        const struct group* nobodyGroup = ::getgrnam("nobody");
        require(nobody != nullptr && nobodyGroup != nullptr,
                "nobody identity is unavailable");
        require(::chown(ownerTarget.c_str(), nobody->pw_uid,
                        nobodyGroup->gr_gid) == 0,
                "could not alter provider target owner");
        fs::create_symlink(ownerTarget, ownerLink);
        fic::platform::DacPlatformConfig ownerConfig;
        ownerConfig.protectedSystemFiles = {{
            ownerLink, "root", "root", 0644, {},
            {{ownerTarget, Provider::NetworkManager}}
        }};
        DAC_blocking_user_access_to_system_files ownerPolicy(ownerConfig);
        require(!ownerPolicy.apply(),
                "provider-managed target with wrong owner was accepted");
        struct stat info {};
        require(::stat(ownerTarget.c_str(), &info) == 0,
                "could not inspect provider owner target");
        require(info.st_uid == nobody->pw_uid &&
                    info.st_gid == nobodyGroup->gr_gid,
                "validate-only provider target was chowned");
    }

    const fs::path pinnedTarget = root / "provider-pinned-target";
    const fs::path replacementTarget = root / "provider-replacement-target";
    const fs::path racedLink = root / "provider-raced-link";
    writeFile(pinnedTarget, "pinned", 0644);
    writeFile(replacementTarget, "replacement", 0644);
    fs::create_symlink(pinnedTarget, racedLink);
    FileStats pinned = FileStats::openPolicyPath(racedLink, {pinnedTarget});
    require(!pinned.has_error() && !pinned.is_missing(),
            "could not open provider target for replacement test");
    fs::remove(racedLink);
    fs::create_symlink(replacementTarget, racedLink);
    require(static_cast<bool>(pinned.change_permissions(0600)),
            "descriptor-pinned chmod failed after symlink replacement");
    require(fileMode(pinnedTarget) == 0600 &&
                fileMode(replacementTarget) == 0644,
            "symlink replacement redirected a descriptor-based mutation");
}

void testCustomSymlinkRemainsFailClosed(const fs::path& root) {
    const fs::path target = root / "custom-symlink-target";
    const fs::path link = root / "custom-symlink-rule";
    writeFile(target, "custom", 0644);
    fs::create_symlink(target, link);
    require(!applyCustomRule(root, link, 0600),
            "custom policy accepted a final symlink");
    require(fileMode(target) == 0644,
            "custom policy modified a symlink target");
}

void testCustomTrustedIntermediateResolution(const fs::path& root) {
    const fs::path regular = root / "custom-regular";
    writeFile(regular, "regular", 0644);
    require(applyCustomRule(root, regular, 0600),
            "custom policy rejected a regular trusted path");
    require(fileMode(regular) == 0600,
            "custom regular path was not remediated");

    const fs::path trustedTargetDirectory = root / "trusted-target";
    const fs::path trustedTarget = trustedTargetDirectory / "file";
    const fs::path trustedLink = root / "trusted-link";
    writeFile(trustedTarget, "trusted", 0644);
    fs::create_directory_symlink("trusted-target", trustedLink);
    require(applyCustomRule(root, trustedLink / "file", 0600),
            "custom policy rejected a trusted intermediate symlink");
    require(fileMode(trustedTarget) == 0600,
            "trusted intermediate symlink target was not remediated");

    const fs::path usrBin = root / "usr/bin";
    const fs::path usrmergeTarget = usrBin / "tool";
    const fs::path binLink = root / "bin";
    writeFile(usrmergeTarget, "usrmerge", 0755);
    fs::create_directory_symlink("usr/bin", binLink);
    require(applyCustomRule(root, binLink / "tool", 0700),
            "custom policy rejected an usrmerge-like intermediate symlink");
    require(fileMode(usrmergeTarget) == 0700,
            "usrmerge-like target was not remediated");

    const fs::path victimDirectory = root / "victim";
    const fs::path victim = victimDirectory / "target";
    const fs::path attackerDirectory = root / "attacker-controlled";
    const fs::path redirect = attackerDirectory / "redirect";
    writeFile(victim, "victim", 0644);
    fs::create_directories(attackerDirectory);
    require(::chmod(attackerDirectory.c_str(), 0777) == 0,
            "could not make the attacker directory writable");
    fs::create_directory_symlink(victimDirectory, redirect);
    require(!applyCustomRule(root, redirect / "target", 0600),
            "custom policy accepted an attacker-controlled redirect");
    require(fileMode(victim) == 0644,
            "attacker-controlled redirect changed the victim mode");

    if (::geteuid() == 0) {
        const fs::path unprivilegedDirectory = root / "unprivileged-owned";
        const fs::path unprivilegedTarget = unprivilegedDirectory / "target";
        fs::create_directories(unprivilegedDirectory);
        writeFile(unprivilegedTarget, "unprivileged", 0644);
        require(::chown(unprivilegedDirectory.c_str(), 65534, 65534) == 0,
                "could not assign the directory to an unprivileged UID");
        require(!applyCustomRule(root, unprivilegedTarget, 0600),
                "custom policy accepted an unprivileged-owned directory");
        require(fileMode(unprivilegedTarget) == 0644,
                "unprivileged-owned path changed the target mode");
    }
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
    testBuiltInMaximumModeSemantics(root);
    testSymlinkIsRejected(root);
    testProfileDrivenFinalSymlinks(root);
    testProviderManagedFinalSymlinks(root);
    testCustomSymlinkRemainsFailClosed(root);
    testCustomTrustedIntermediateResolution(root);
    testChownThenRestoresSpecialBits(root);
    testUnknownIdentitiesAndDiagnostics(root);
    testChownFailureReturnsFalse(root);

    fs::remove_all(root);
    return 0;
}
