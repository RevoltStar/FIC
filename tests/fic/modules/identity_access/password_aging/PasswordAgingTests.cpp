#include "policy/execution/PolicyApplication.h"
#include "policy/registry/PolicyRegistryInitialization.h"
#include "modules/identity_access/shared/configuration/LoginDefsFileHandler.h"
#include "modules/identity_access/password_aging/PasswordAgingPolicies.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {
namespace fs = std::filesystem;
using namespace fic::identity::password_aging;
using namespace fic::identity;

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

std::map<std::string, std::string> policyConfigValues(const fs::path& path) {
    std::map<std::string, std::string> values;
    std::ifstream input(path);
    require(input.is_open(), "cannot read generated policy config " + path.string());
    std::string line;
    while (std::getline(input, line)) {
        const std::size_t marker = line.find(".value=");
        if (marker != std::string::npos) {
            values.emplace(line.substr(0, marker), line.substr(marker + 7));
        }
    }
    return values;
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

    for (const std::string& malformed : {
             std::string("PASS_MAX_DAYS\n"),
             std::string("PASS_MAX_DAYS # no value\n"),
             std::string("PASS_MAX_DAYS 90 extra\n")}) {
        writeFile(file, malformed);
        require(handler.loadConfig(), "malformed target load failed");
        require(handler.lookup("PASS_MAX_DAYS").state ==
                    LoginDefsValueState::Malformed,
                "malformed target occurrence was not detected");
        require(!handler.setValue("PASS_MAX_DAYS", "90"),
                "malformed target was automatically repaired");
        require(readFile(file) == malformed, "malformed target file changed");
    }

    writeFile(file, "PASS_MAX_DAYS 90\n");
    require(handler.loadConfig() &&
                handler.lookup("PASS_MAX_DAYS").state ==
                    LoginDefsValueState::Unique &&
                handler.lookup("PASS_MAX_DAYS").value == "90",
            "unique target occurrence is not parsed exactly");
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

    writeFile(platform.loginDefsPath,
        "PASS_MIN_DAYS 0\nPASS_WARN_AGE 7\nUID_MIN 1000\nUID_MAX 60000\n");
    platform.policyDefaults.maxDays = 0;
    platform.missingKeySemantics.maxDays = -1;
    writePolicyConfig(root);
    PasswordMinAgeDaysPolicy missingPasswordPeer(platform);
    require(missingPasswordPeer.apply(),
            "explicit unlimited missing PASS_MAX_DAYS semantics were ignored");
    require(readFile(platform.loginDefsPath).find("PASS_MIN_DAYS 1") !=
                std::string::npos,
            "policy with missing password peer did not apply");

    writeFile(platform.loginDefsPath,
        "PASS_MAX_DAYS 99999\nPASS_WARN_AGE 7\nUID_MIN 1000\nUID_MAX 60000\n");
    platform.policyDefaults.minDays = 100;
    platform.missingKeySemantics.minDays = -1;
    PasswordMaxAgeDaysPolicy missingPasswordMinimum(platform);
    require(missingPasswordMinimum.apply() &&
                readFile(platform.loginDefsPath).find("PASS_MAX_DAYS 90") !=
                    std::string::npos,
            "explicit missing PASS_MIN_DAYS semantics were ignored");

    writeFile(platform.loginDefsPath,
        "PASS_MIN_DAYS 1\nPASS_MAX_DAYS 90\nPASS_WARN_AGE 7\nUID_MIN 1000\n");
    const std::string missingUidPeer = readFile(platform.loginDefsPath);
    RegularUserUidMinPolicy missingUidMax(platform);
    require(!missingUidMax.apply() &&
                readFile(platform.loginDefsPath) == missingUidPeer,
            "missing UID_MAX peer did not fail closed");
}

void testPolicyValueContracts(const fs::path& root) {
    auto platform = platformFor(root);
    PasswordMinAgeDaysPolicy min(platform);
    PasswordMaxAgeDaysPolicy max(platform);
    PasswordExpirationWarningDaysPolicy warning(platform);
    RegularUserUidMinPolicy uidMin(platform);
    RegularUserUidMaxPolicy uidMax(platform);
    require(min.getDefaultValue() ==
                    std::to_string(platform.policyDefaults.minDays) &&
                min.validate("0") &&
                !min.validate("-1") && !min.validate("invalid"),
            "PASS_MIN_DAYS value contract is wrong");
    require(max.getDefaultValue() ==
                    std::to_string(platform.policyDefaults.maxDays) &&
                max.validate("-1") &&
                !max.validate("invalid"),
            "PASS_MAX_DAYS value contract is wrong");
    require(warning.getDefaultValue() ==
                    std::to_string(platform.policyDefaults.warningDays) &&
                warning.validate("-1") &&
                !warning.validate("invalid"),
            "PASS_WARN_AGE value contract is wrong");
    const std::string uidMaximum =
        std::to_string(std::numeric_limits<uid_t>::max());
    require(uidMin.getDefaultValue() ==
                    std::to_string(platform.policyDefaults.uidMin) &&
                uidMin.validate("0") &&
                uidMin.validate(uidMaximum) &&
                !uidMin.validate("-1") && !uidMin.validate("invalid"),
            "UID_MIN value contract is wrong");
    require(uidMax.getDefaultValue() ==
                    std::to_string(platform.policyDefaults.uidMax) &&
                uidMax.validate("0") &&
                uidMax.validate(uidMaximum) &&
                !uidMax.validate("-1") && !uidMax.validate("invalid"),
            "UID_MAX value contract is wrong");
    if (std::numeric_limits<uid_t>::max() >
        static_cast<std::uintmax_t>(std::numeric_limits<int>::max())) {
        require(uidMax.validate(std::to_string(
                    static_cast<std::uintmax_t>(std::numeric_limits<int>::max()) + 1)),
                "UID policy is still artificially limited to INT_MAX");
    }
    const PolicyEditorSpec uidMinEditor =
        uidMin.getPolicyTypeValue().getEditorSpec();
    const PolicyEditorSpec uidMaxEditor =
        uidMax.getPolicyTypeValue().getEditorSpec();
    require(uidMinEditor.editor == "lineedit" &&
                uidMaxEditor.editor == "lineedit" &&
                uidMinEditor.validator == "unsigned_integer" &&
                uidMaxEditor.validator == "unsigned_integer",
            "UID policy editor cannot round-trip the uid_t range");

    const auto generated = policyConfigValues(FIC_GENERATED_IDENTITY_CONFIG_PATH);
    require(generated.at("password_min_age_days") == min.getDefaultValue() &&
                generated.at("password_max_age_days") == max.getDefaultValue() &&
                generated.at("password_expiration_warning_days") ==
                    warning.getDefaultValue() &&
                generated.at("regular_user_uid_min") == uidMin.getDefaultValue() &&
                generated.at("regular_user_uid_max") == uidMax.getDefaultValue(),
            "generated config defaults differ from Policy metadata");
    for (const char* name : {
             "password_min_age_days", "password_max_age_days",
             "password_expiration_warning_days", "regular_user_uid_min",
             "regular_user_uid_max", "password_aging_apply_to_existing_accounts",
             "password_aging_enforce_for_root"}) {
        require(readFile(FIC_GENERATED_IDENTITY_CONFIG_PATH).find(
                    std::string(name) + ".status=DISABLE") != std::string::npos,
                std::string("generated policy is not disabled: ") + name);
    }
}

LocalAccountSnapshot sampleAccounts() {
    LocalAccountSnapshot accounts;
    accounts.passwdAccounts = {
        {"root", 0}, {"emergency", 0}, {"daemon", 10}, {"alice", 1000},
        {"locked", 1001}, {"high", 60001}};
    accounts.shadowAccounts = {
        {"root", {100, 0, 99999, 7}},
        {"emergency", {105, 0, 99999, 7}},
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
    require(calls.size() == afterFirst + 2 &&
                calls[afterFirst].back() == "root" &&
                calls[afterFirst + 1].back() == "emergency",
            "root policy did not cover all root-equivalent UID 0 accounts");
    require(state.shadowAccounts["root"].lastChange == 100,
            "root sp_lstchg changed");
    require(state.shadowAccounts["emergency"].lastChange == 105,
            "root-equivalent sp_lstchg changed");
    require(reads >= 5, "postcondition did not reread structured state");
}

void testStructuredLocalReaders(const fs::path& root) {
    auto platform = platformFor(root);
    const std::string validPasswd =
        "root:x:0:0:root:/root:/bin/sh\n"
        "alice:x:1000:1000:Alice:/home/alice:/bin/sh\n";
    const std::string validShadow =
        "root:!:100:0:99999:7:::\n"
        "alice:$6$not-logged:101:1:90:7:::\n";
    writeFile(platform.passwdPath, validPasswd);
    writeFile(platform.shadowPath, validShadow, 0600);
    LocalAccountSnapshot snapshot;
    std::string error;
    require(PasswordAgingRuntime::readLocalAccounts(
                platform, snapshot, error), error);
    require(snapshot.passwdAccounts.size() == 2 &&
                snapshot.shadowAccounts.at("alice").lastChange == 101 &&
                snapshot.shadowAccounts.at("alice").minDays == 1,
            "structured /etc/passwd + /etc/shadow reader failed");

    auto expectStrictFailure = [&](const std::string& passwd,
                                   const std::string& shadow,
                                   const std::string& label) {
        writeFile(platform.passwdPath, passwd);
        writeFile(platform.shadowPath, shadow, 0600);
        snapshot = {};
        error.clear();
        require(!PasswordAgingRuntime::readLocalAccounts(
                    platform, snapshot, error) && !error.empty(),
                label + " did not fail the entire local account read");
    };
    expectStrictFailure(
        "root:x:0:0:root:/root:/bin/sh\nmalformed\n"
        "alice:x:1000:1000:Alice:/home/alice:/bin/sh\n",
        validShadow,
        "malformed passwd record between valid records");
    expectStrictFailure(
        validPasswd + "alice:x:1001:1001:Duplicate:/tmp:/bin/sh\n",
        validShadow,
        "duplicate passwd username");
    expectStrictFailure(
        "root:x:not-a-uid:0:root:/root:/bin/sh\n",
        "root:!:100:0:99999:7:::\n",
        "invalid passwd UID");
    expectStrictFailure(
        validPasswd,
        "root:!:100:0:99999:7:::\nmalformed\n"
        "alice:!:101:1:90:7:::\n",
        "malformed shadow record between valid records");
    expectStrictFailure(
        validPasswd,
        validShadow + "alice:!:102:1:90:7:::\n",
        "duplicate shadow username");
    expectStrictFailure(
        validPasswd,
        "root:!:not-a-number:0:99999:7:::\n"
        "alice:!:101:1:90:7:::\n",
        "malformed shadow aging field");

    writeFile(platform.passwdPath, validPasswd);
    platform.shadowKind = fic::platform::LocalShadowKind::TcbDirectory;
    platform.tcbDirectory = root / "etc/tcb";
    fs::remove_all(platform.tcbDirectory);
    writeFile(platform.tcbDirectory / "root/shadow",
              "root:!:100:0:99999:7:::\n", 0600);
    writeFile(platform.tcbDirectory / "alice/shadow",
              "alice:!:101:1:90:7:::\n", 0600);
    require(PasswordAgingRuntime::readLocalAccounts(
                platform, snapshot, error), error);
    require(snapshot.shadowAccounts.size() == 2 &&
                snapshot.shadowAccounts.at("root").lastChange == 100,
            "structured TCB reader failed");

    writeFile(platform.tcbDirectory / "alice/shadow",
              "alice:!:101:1:90:7:::\nmalformed\n", 0600);
    error.clear();
    require(!PasswordAgingRuntime::readLocalAccounts(
                platform, snapshot, error),
            "malformed TCB shadow record was skipped");

    const fs::path outside = root / "outside-tcb";
    fs::remove_all(outside);
    writeFile(outside / "shadow", "alice:!:101:1:90:7:::\n", 0600);
    fs::remove_all(platform.tcbDirectory / "alice");
    fs::create_directory_symlink(outside, platform.tcbDirectory / "alice");
    error.clear();
    require(!PasswordAgingRuntime::readLocalAccounts(
                platform, snapshot, error),
            "symlink TCB account directory was followed");

    fs::remove(platform.tcbDirectory / "alice");
    fs::create_directories(platform.tcbDirectory / "alice");
    fs::create_symlink(outside / "shadow",
                       platform.tcbDirectory / "alice/shadow");
    error.clear();
    require(!PasswordAgingRuntime::readLocalAccounts(
                platform, snapshot, error),
            "symlink TCB shadow file was followed");

    writeFile(platform.passwdPath, "..:x:1000:1000::/:/bin/sh\n");
    error.clear();
    require(!PasswordAgingRuntime::readLocalAccounts(
                platform, snapshot, error),
            "unsafe TCB '..' account component was accepted");
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
    require(optionSafeRuntime.apply(chage, "-option", 1, 90, 7).success() &&
                calls == 1,
            "argv-safe option-like username was rejected despite '--'");
    calls = 0;
    state.shadowAccounts.erase("root");
    PasswordAgingRuntime missingRootRuntime(
        platform, resolver, successRunner, trust, reader);
    PasswordAgingEnforceForRootPolicy missingRoot(
        platform, std::move(missingRootRuntime));
    require(!missingRoot.apply() && calls == 0,
            "missing local root shadow did not fail before mutation");

    state = sampleAccounts();
    state.shadowAccounts.erase("alice");
    PasswordAgingRuntime missingEligibleRuntime(
        platform, resolver, successRunner, trust, reader);
    PasswordAgingApplyToExistingAccountsPolicy missingEligible(
        platform, std::move(missingEligibleRuntime));
    require(!missingEligible.apply() && calls == 0,
            "eligible passwd account without shadow did not fail preflight");

    state = sampleAccounts();
    state.shadowAccounts.erase("daemon");
    PasswordAgingRuntime missingSystemRuntime(
        platform, resolver, successRunner, trust, reader);
    PasswordAgingApplyToExistingAccountsPolicy missingSystem(
        platform, std::move(missingSystemRuntime));
    require(missingSystem.apply() && calls == 2,
            "out-of-range system account without shadow blocked bulk apply");
    calls = 0;

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
