#include "core/PolicyApplication.h"
#include "core/PolicyRegistryInitialization.h"
#include "modules/identity_access/submodules/password_aging/LoginDefsFileHandler.h"
#include "modules/identity_access/submodules/password_aging/PasswordAgingPolicies.h"

#include <fic/core/FicRuntimePaths.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {
namespace fs = std::filesystem;
using namespace fic::identity::password_aging;

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

void writeFile(const fs::path& path, const std::string& content, mode_t mode = 0644) {
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
              "_schema_version=1\nlog_level.status=ENABLE\nlog_level.value=DEBUG\n");
    std::string error;
    require(fic::core::FicRuntimePaths::initialize(paths, error), error);
}

void writePolicyConfig(const fs::path& root, bool maxEnabled = true,
                       bool minEnabled = true) {
    writeFile(root / "config/IDENTITY_ACCESS.conf",
        "_schema_version=1\n"
        "password_min_age_days.status=" +
            std::string(minEnabled ? "ENABLE\n" : "DISABLE\n") +
        "password_min_age_days.value=1\n"
        "password_max_age_days.status=" +
            std::string(maxEnabled ? "ENABLE\n" : "DISABLE\n") +
        "password_max_age_days.value=90\n"
        "password_expiration_warning_days.status=ENABLE\n"
        "password_expiration_warning_days.value=7\n"
        "regular_user_uid_min.status=ENABLE\n"
        "regular_user_uid_min.value=1000\n"
        "regular_user_uid_max.status=ENABLE\n"
        "regular_user_uid_max.value=60000\n"
        "password_aging_apply_to_existing_accounts.status=ENABLE\n"
        "password_aging_apply_to_existing_accounts.value=yes\n"
        "password_aging_enforce_for_root.status=ENABLE\n"
        "password_aging_enforce_for_root.value=yes\n");
}

fic::platform::PasswordAgingPlatformConfig platformFor(const fs::path& root) {
    fic::platform::PasswordAgingPlatformConfig platform;
    platform.loginDefsPath = root / "etc/login.defs";
    platform.passwdPath = root / "etc/passwd";
    platform.shadowPath = root / "etc/shadow";
    return platform;
}

fic::platform::PlatformExecutableResolver resolverFor(const fs::path& executable) {
    fic::platform::PlatformExecutables specs;
    specs.entries.push_back({fic::platform::ExecutableId::Chage, {executable}});
    fic::platform::PlatformExecutableResolverOptions options;
    options.enforceTrustedOwnership = false;
    return fic::platform::PlatformExecutableResolver(
        std::move(specs), options);
}

void testLoginDefsHandler(const fs::path& root) {
    const fs::path file = root / "handler/login.defs";
    const std::string original =
        "# keep comment\n\nPASS_MIN_DAYS 0\nPASS_MAX_DAYS     99999\n"
        "PASS_WARN_AGE\t7\nUNKNOWN odd text stays\nMALFORMED\n";
    writeFile(file, original);
    LoginDefsFileHandler handler(file.string());
    require(handler.loadConfig(), "handler load failed");
    require(handler.lookup("PASS_MIN_DAYS").value == "0", "space parse");
    require(handler.lookup("PASS_MAX_DAYS").value == "99999", "multi-space parse");
    require(handler.lookup("PASS_WARN_AGE").value == "7", "tab parse");
    require(handler.setValue("PASS_MAX_DAYS", "90"), "update failed");
    require(handler.setValue("UID_MIN", "1000"), "append failed");
    require(handler.saveAndReload(), "save/reload failed");
    const std::string changed = readFile(file);
    require(changed.find("# keep comment\n\n") == 0, "comment/blank changed");
    require(changed.find("UNKNOWN odd text stays") != std::string::npos,
            "unknown line changed");
    require(changed.find("MALFORMED\n") != std::string::npos,
            "malformed line changed");
    require(changed.find("PASS_MAX_DAYS 90") != std::string::npos,
            "target not canonicalized");
    require(handler.lookup("UID_MIN").state == LoginDefsValueState::Unique,
            "reload/postcondition missing");

    writeFile(file, "PASS_MAX_DAYS 90\nPASS_MAX_DAYS 99999\n");
    require(handler.loadConfig(), "duplicate load failed");
    const std::string duplicate = readFile(file);
    require(handler.lookup("PASS_MAX_DAYS").state ==
                LoginDefsValueState::Duplicate,
            "duplicate not detected");
    require(!handler.setValue("PASS_MAX_DAYS", "30"),
            "duplicate accepted");
    require(readFile(file) == duplicate, "duplicate mutated file");
}

void testOptionPolicies(const fs::path& root) {
    auto platform = platformFor(root);
    writePolicyConfig(root);
    writeFile(platform.loginDefsPath,
        "# header\nPASS_MIN_DAYS 0\nPASS_MAX_DAYS 99999\nPASS_WARN_AGE 7\n"
        "UID_MIN 1000\nUID_MAX 60000\n");
    PasswordMinAgeDaysPolicy min(platform);
    require(min.apply(), "min option failed");
    require(readFile(platform.loginDefsPath).find("PASS_MIN_DAYS 1") !=
                std::string::npos,
            "min option not written");
    const std::string once = readFile(platform.loginDefsPath);
    require(min.apply() && readFile(platform.loginDefsPath) == once,
            "option is not idempotent");

    writeFile(platform.loginDefsPath,
        "PASS_MIN_DAYS 1\nPASS_MAX_DAYS 90\nPASS_MAX_DAYS 99999\n"
        "PASS_WARN_AGE 7\nUID_MIN 1000\nUID_MAX 60000\n");
    PasswordMaxAgeDaysPolicy max(platform);
    const std::string duplicate = readFile(platform.loginDefsPath);
    require(!max.apply() && readFile(platform.loginDefsPath) == duplicate,
            "duplicate option was not fail-closed");

    writeFile(platform.loginDefsPath,
        "PASS_MIN_DAYS 100\nPASS_MAX_DAYS 90\nPASS_WARN_AGE 7\n"
        "UID_MIN 1000\nUID_MAX 60000\n");
    require(!max.apply(), "invalid resulting password relation accepted");
    writeFile(platform.loginDefsPath,
        "PASS_MIN_DAYS 1\nPASS_MAX_DAYS 90\nPASS_WARN_AGE 7\n"
        "UID_MIN 65000\nUID_MAX 60000\n");
    RegularUserUidMaxPolicy uidMax(platform);
    require(!uidMax.apply(), "invalid resulting UID relation accepted");
}

void testPolicyValueContracts(const fs::path& root) {
    auto platform = platformFor(root);
    PasswordMinAgeDaysPolicy min(platform);
    PasswordMaxAgeDaysPolicy max(platform);
    PasswordExpirationWarningDaysPolicy warning(platform);
    RegularUserUidMinPolicy uidMin(platform);
    RegularUserUidMaxPolicy uidMax(platform);
    require(min.getDefaultValue() == "0" && min.validate("0") &&
                !min.validate("-1") && !min.validate("invalid"),
            "PASS_MIN_DAYS value contract is wrong");
    require(max.getDefaultValue() == "99999" && max.validate("-1") &&
                !max.validate("invalid"),
            "PASS_MAX_DAYS value contract is wrong");
    require(warning.getDefaultValue() == "7" && warning.validate("-1") &&
                !warning.validate("invalid"),
            "PASS_WARN_AGE value contract is wrong");
    require(uidMin.getDefaultValue() == "1000" && uidMin.validate("0") &&
                !uidMin.validate("-1") && !uidMin.validate("invalid"),
            "UID_MIN value contract is wrong");
    require(uidMax.getDefaultValue() == "60000" && uidMax.validate("0") &&
                !uidMax.validate("-1") && !uidMax.validate("invalid"),
            "UID_MAX value contract is wrong");
    platform.defaults.maxDays = -1;
    platform.defaults.warningDays = -1;
    require(PasswordMaxAgeDaysPolicy(platform).getDefaultValue() == "-1" &&
                PasswordExpirationWarningDaysPolicy(platform).getDefaultValue() ==
                    "-1",
            "ALT sentinel defaults are not exposed by policy metadata");
}

LocalAccountSnapshot sampleAccounts() {
    LocalAccountSnapshot accounts;
    accounts.passwdAccounts = {
        {"root", 0}, {"daemon", 10}, {"alice", 1000},
        {"locked", 1001}, {"high", 60001}};
    accounts.shadowAccounts = {
        {"root", {100, 0, 99999, 7}},
        {"daemon", {101, 0, 99999, 7}},
        {"alice", {102, 0, 99999, 7}},
        {"locked", {103, 0, 99999, 7}},
        {"high", {104, 0, 99999, 7}}};
    return accounts;
}

void testOperationalPolicies(const fs::path& root) {
    auto platform = platformFor(root);
    writePolicyConfig(root);
    writeFile(platform.loginDefsPath,
        "PASS_MIN_DAYS 1\nPASS_MAX_DAYS 90\nPASS_WARN_AGE 7\n"
        "UID_MIN 1000\nUID_MAX 60000\n");
    const fs::path chage = root / "bin/chage";
    writeFile(chage, "fake", 0755);
    auto resolver = resolverFor(chage);
    LocalAccountSnapshot state = sampleAccounts();
    int reads = 0;
    std::vector<std::vector<std::string>> calls;
    auto reader = [&](const auto&, LocalAccountSnapshot& result, std::string&) {
        ++reads;
        result = state;
        return true;
    };
    auto runner = [&](const std::string&, const std::vector<std::string>& args) {
        calls.push_back(args);
        const std::string& user = args.back();
        state.shadowAccounts[user].minDays = 1;
        state.shadowAccounts[user].maxDays = 90;
        state.shadowAccounts[user].warningDays = 7;
        ProcessResult result;
        result.started = true;
        result.exitCode = 0;
        return result;
    };
    auto trust = [](const std::string&, std::string&) { return true; };
    PasswordAgingRuntime bulkRuntime(platform, resolver, runner, trust, reader);
    PasswordAgingApplyToExistingAccountsPolicy bulk(platform, std::move(bulkRuntime));
    require(bulk.apply(), "bulk operational policy failed");
    require(calls.size() == 2 && calls[0].back() == "alice" &&
                calls[1].back() == "locked",
            "bulk eligibility is wrong");
    require(std::find(calls[0].begin(), calls[0].end(), "-d") == calls[0].end(),
            "chage -d used");
    require(calls[0][calls[0].size() - 2] == "--", "missing option barrier");
    require(state.shadowAccounts["alice"].lastChange == 102,
            "sp_lstchg changed");
    const std::size_t afterFirst = calls.size();
    require(bulk.apply() && calls.size() == afterFirst, "bulk not idempotent");

    PasswordAgingRuntime rootRuntime(platform, resolver, runner, trust, reader);
    PasswordAgingEnforceForRootPolicy rootPolicy(platform, std::move(rootRuntime));
    require(rootPolicy.apply(), "root operational policy failed");
    require(calls.back().back() == "root", "root policy changed another user");
    require(state.shadowAccounts["root"].lastChange == 100,
            "root sp_lstchg changed");
    require(reads >= 5, "postcondition did not reread structured state");
}

void testStructuredLocalReaders(const fs::path& root) {
    auto platform = platformFor(root);
    writeFile(platform.passwdPath,
        "root:x:0:0:root:/root:/bin/sh\n"
        "alice:x:1000:1000:Alice:/home/alice:/bin/sh\n");
    writeFile(platform.shadowPath,
        "root:!:100:0:99999:7:::\n"
        "alice:$6$not-logged:101:1:90:7:::\n",
        0600);
    LocalAccountSnapshot snapshot;
    std::string error;
    require(PasswordAgingRuntime::readLocalAccounts(
                platform, snapshot, error), error);
    require(snapshot.passwdAccounts.size() == 2 &&
                snapshot.shadowAccounts.at("alice").lastChange == 101 &&
                snapshot.shadowAccounts.at("alice").minDays == 1,
            "structured /etc/passwd + /etc/shadow reader failed");

    platform.shadowKind = fic::platform::LocalShadowKind::TcbDirectory;
    platform.tcbDirectory = root / "etc/tcb";
    writeFile(platform.tcbDirectory / "root/shadow",
              "root:!:100:0:99999:7:::\n", 0600);
    writeFile(platform.tcbDirectory / "alice/shadow",
              "alice:!:101:1:90:7:::\n", 0600);
    require(PasswordAgingRuntime::readLocalAccounts(
                platform, snapshot, error), error);
    require(snapshot.shadowAccounts.size() == 2 &&
                snapshot.shadowAccounts.at("root").lastChange == 100,
            "structured TCB reader failed");
}

void testOperationalFailures(const fs::path& root) {
    auto platform = platformFor(root);
    writePolicyConfig(root);
    writeFile(platform.loginDefsPath,
        "PASS_MIN_DAYS 1\nPASS_MAX_DAYS 90\nPASS_WARN_AGE 7\n"
        "UID_MIN 1000\nUID_MAX 60000\n");
    const fs::path chage = root / "bin/chage";
    auto resolver = resolverFor(chage);
    LocalAccountSnapshot state = sampleAccounts();
    int calls = 0;
    auto reader = [&](const auto&, LocalAccountSnapshot& result, std::string&) {
        result = state;
        return true;
    };
    auto successRunner = [&](const std::string&, const std::vector<std::string>& args) {
        ++calls;
        state.shadowAccounts[args.back()].minDays = 1;
        state.shadowAccounts[args.back()].maxDays = 90;
        state.shadowAccounts[args.back()].warningDays = 7;
        ProcessResult result;
        result.started = true;
        result.exitCode = 0;
        return result;
    };
    auto noTrust = [](const std::string&, std::string& error) {
        error = "hash mismatch";
        return false;
    };
    PasswordAgingRuntime untrusted(
        platform, resolver, successRunner, noTrust, reader);
    PasswordAgingApplyToExistingAccountsPolicy untrustedPolicy(
        platform, std::move(untrusted));
    require(!untrustedPolicy.apply() && calls == 0,
            "trust failure did not stop preflight");

    auto trust = [](const std::string&, std::string&) { return true; };
    PasswordAgingRuntime optionSafeRuntime(
        platform, resolver, successRunner, trust, reader);
    require(!optionSafeRuntime.apply(chage, "-option", 1, 90, 7).success() &&
                calls == 0,
            "option-like username reached the command runner");
    state.shadowAccounts.erase("root");
    PasswordAgingRuntime missingRootRuntime(
        platform, resolver, successRunner, trust, reader);
    PasswordAgingEnforceForRootPolicy missingRoot(
        platform, std::move(missingRootRuntime));
    require(!missingRoot.apply() && calls == 0,
            "missing local root shadow did not fail before mutation");

    state = sampleAccounts();
    auto failRunner = [&](const std::string&, const std::vector<std::string>&) {
        ++calls;
        ProcessResult result;
        result.started = true;
        result.exitCode = 1;
        result.standardError = "synthetic chage failure";
        return result;
    };
    PasswordAgingRuntime failedCommand(
        platform, resolver, failRunner, trust, reader);
    PasswordAgingApplyToExistingAccountsPolicy failedPolicy(
        platform, std::move(failedCommand));
    require(!failedPolicy.apply() && calls == 1,
            "chage failure did not stop after first mutation attempt");

    calls = 0;
    auto changesLastDate = [&](const std::string&,
                               const std::vector<std::string>& args) {
        ++calls;
        auto& aging = state.shadowAccounts[args.back()];
        aging.minDays = 1;
        aging.maxDays = 90;
        aging.warningDays = 7;
        ++aging.lastChange;
        ProcessResult result;
        result.started = true;
        result.exitCode = 0;
        return result;
    };
    PasswordAgingRuntime badPostcondition(
        platform, resolver, changesLastDate, trust, reader);
    PasswordAgingApplyToExistingAccountsPolicy postconditionPolicy(
        platform, std::move(badPostcondition));
    require(!postconditionPolicy.apply() && calls == 1,
            "sp_lstchg mutation was not detected");
}

PolicyRegistry makeRegistry(
    const fic::platform::PasswordAgingPlatformConfig& platform,
    const fic::platform::PlatformExecutableResolver& resolver,
    LocalAccountReader reader,
    int& commandCalls) {
    auto runner = [&](const std::string&, const std::vector<std::string>&) {
        ++commandCalls;
        ProcessResult result;
        result.started = true;
        result.exitCode = 0;
        return result;
    };
    auto trust = [](const std::string&, std::string&) { return true; };
    PolicyList policies;
    policies.push_back(std::make_unique<PasswordMinAgeDaysPolicy>(platform));
    policies.push_back(std::make_unique<PasswordMaxAgeDaysPolicy>(platform));
    policies.push_back(
        std::make_unique<PasswordExpirationWarningDaysPolicy>(platform));
    policies.push_back(std::make_unique<RegularUserUidMinPolicy>(platform));
    policies.push_back(std::make_unique<RegularUserUidMaxPolicy>(platform));
    PasswordAgingRuntime runtime(platform, resolver, runner, trust, reader);
    policies.push_back(
        std::make_unique<PasswordAgingApplyToExistingAccountsPolicy>(
            platform, std::move(runtime)));
    PasswordAgingRuntime rootRuntime(platform, resolver, runner, trust, reader);
    policies.push_back(std::make_unique<PasswordAgingEnforceForRootPolicy>(
        platform, std::move(rootRuntime)));
    PolicyRegistry registry;
    std::string error;
    require(buildPolicyRegistry(std::move(policies), registry, error), error);
    return registry;
}

void testDependencies(const fs::path& root) {
    auto platform = platformFor(root);
    writeFile(platform.loginDefsPath,
        "PASS_MIN_DAYS 1\nPASS_MAX_DAYS 90\nPASS_WARN_AGE 7\n"
        "UID_MIN 1000\nUID_MAX 60000\n");
    const fs::path chage = root / "bin/chage";
    auto resolver = resolverFor(chage);
    int reads = 0;
    int commands = 0;
    auto reader = [&](const auto&, LocalAccountSnapshot& result, std::string&) {
        ++reads;
        result = {};
        return true;
    };
    writePolicyConfig(root, false, true);
    PolicyRegistry blocked = makeRegistry(platform, resolver, reader, commands);
    const PolicyApplySummary summary = applyPolicy(
        blocked, "IDENTITY_ACCESS",
        "password_aging_apply_to_existing_accounts");
    const auto& results = summary.getResults();
    auto status = [&](const std::string& name) {
        const auto found = std::find_if(results.begin(), results.end(),
            [&](const PolicyApplyResult& result) { return result.policyName == name; });
        require(found != results.end(), "missing dependency result " + name);
        return found->status;
    };
    require(status("password_max_age_days") == PolicyApplyStatus::Disabled,
            "disabled required dependency status wrong");
    require(status("password_aging_apply_to_existing_accounts") ==
                PolicyApplyStatus::Failed,
            "dependent was not failed");
    require(reads == 0 && commands == 0,
            "blocked operational apply reached runtime");

    writePolicyConfig(root, true, true);
    PolicyRegistry enabled = makeRegistry(platform, resolver, reader, commands);
    const PolicyApplySummary applied = applyPolicy(
        enabled, "IDENTITY_ACCESS",
        "password_aging_apply_to_existing_accounts");
    require(applied.requestedRootsApplied(), "enabled dependency chain failed");
    require(reads == 1, "operational policy did not run after dependencies");
    const Policy* policy = enabled.findPolicy({
        "IDENTITY_ACCESS", "PASSWORD_AGING",
        "password_aging_apply_to_existing_accounts"});
    require(policy != nullptr && policy->dependencies().size() == 5,
            "bulk dependency metadata wrong");

    reads = 0;
    writePolicyConfig(root, true, false);
    PolicyRegistry rootBlocked = makeRegistry(platform, resolver, reader, commands);
    const PolicyApplySummary rootSummary = applyPolicy(
        rootBlocked, "IDENTITY_ACCESS", "password_aging_enforce_for_root");
    require(!rootSummary.requestedRootsApplied() && reads == 0,
            "disabled root dependency did not block runtime");
    const Policy* rootPolicy = rootBlocked.findPolicy({
        "IDENTITY_ACCESS", "PASSWORD_AGING",
        "password_aging_enforce_for_root"});
    require(rootPolicy != nullptr && rootPolicy->dependencies().size() == 3,
            "root dependency metadata wrong");
}

} // namespace

int main() {
    try {
        const fs::path root = fs::temp_directory_path() /
            ("fic-password-aging-tests-" + std::to_string(::getpid()));
        fs::remove_all(root);
        fs::create_directories(root);
        initializePaths(root);
        testLoginDefsHandler(root);
        testOptionPolicies(root);
        testPolicyValueContracts(root);
        testStructuredLocalReaders(root);
        testOperationalPolicies(root);
        testOperationalFailures(root);
        testDependencies(root);
        fs::remove_all(root);
        std::cout << "PasswordAgingTests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "PasswordAgingTests failed: " << error.what() << '\n';
        return 1;
    }
}
