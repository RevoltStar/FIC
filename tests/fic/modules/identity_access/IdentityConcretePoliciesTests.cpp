#include "modules/identity_access/kerberos/policies/KerberosTicketLifetimePolicy.h"
#include "modules/identity_access/sssd/policies/SssdOfflineCredentialsExpirationPolicy.h"

#include "rollback/DaemonMutationJournal.h"
#include "rollback/MutationRecord.h"
#include "rollback/RollbackExecutor.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void writeFile(const fs::path& path,
               const std::string& content,
               mode_t mode) {
    fs::create_directories(path.parent_path());
    ::chmod(path.parent_path().c_str(), 0755);
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(output.is_open(), "could not create " + path.string());
    output << content;
    output.close();
    require(output.good(), "could not write " + path.string());
    require(::chmod(path.c_str(), mode) == 0, "could not chmod " + path.string());
}

std::string readFile(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    require(input.is_open(), "could not read " + path.string());
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

// Rewrites the configured policy value: concrete policies read their value
// from IDENTITY_ACCESS.conf on every apply.
void setPolicyValues(const fs::path& root,
                     const std::string& sssdValue,
                     const std::string& kerberosValue) {
    writeFile(
        root / "config/IDENTITY_ACCESS.conf",
        "sssd_offline_credentials_expiration.status=ENABLE\n"
        "sssd_offline_credentials_expiration.value=" + sssdValue + "\n"
        "kerberos_ticket_lifetime.status=ENABLE\n"
        "kerberos_ticket_lifetime.value=" + kerberosValue + "\n",
        0644);
}

fic::identity::SecureConfigurationFileOptions secureFile(
    const fs::path& path,
    std::optional<mode_t> exactMode = std::nullopt) {
    fic::identity::SecureConfigurationFileOptions options;
    options.path = fs::absolute(path);
    options.expectedOwner = ::geteuid();
    options.expectedGroup = ::getegid();
    options.exactMode = exactMode;
    options.forbiddenMode = 0022;
    return options;
}

void initializeRuntimePaths(const fs::path& root) {
    auto paths = fic::core::FicProductPaths::production();
    paths.privateBinDir = root / "bin";
    paths.configDir = root / "config";
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
    writeFile(
        paths.configDir / "IDENTITY_ACCESS.conf",
        "sssd_offline_credentials_expiration.status=ENABLE\n"
        "sssd_offline_credentials_expiration.value=30\n"
        "kerberos_ticket_lifetime.status=ENABLE\n"
        "kerberos_ticket_lifetime.value=7200\n",
        0644);
    std::string error;
    require(fic::core::FicRuntimePaths::initialize(paths, error), error);
}

fic::platform::PlatformExecutableResolver makeResolver(
    const fs::path& systemctl) {
    fic::platform::PlatformExecutables executables;
    executables.entries.push_back(
        {fic::platform::ExecutableId::Systemctl, {systemctl}});
    fic::platform::PlatformExecutableResolverOptions options;
    options.enforceTrustedOwnership = false;
    return fic::platform::PlatformExecutableResolver(
        std::move(executables), options);
}

fic::identity::sssd::SssdConfigurationOptions sssdOptions(
    const fs::path& main,
    const fs::path& root) {
    (void)root;
    // Per-test snippet topology derived from the unique main file name.
    const std::string tag = main.stem().string();
    const fs::path confd = main.parent_path() / (tag + "-conf.d");
    fs::create_directories(confd);
    ::chmod(confd.c_str(), 0755);
    fic::identity::sssd::SssdConfigurationOptions options;
    options.mainFile = secureFile(main, 0600);
    options.snippetDirectories = {confd};
    options.managedSnippetFile = confd / "zzzz-fic.conf";
    return options;
}

fic::identity::kerberos::KerberosConfigurationOptions kerberosOptions(
    const fs::path& main,
    const fs::path& root) {
    fic::identity::kerberos::KerberosConfigurationOptions options;
    options.mainFile = secureFile(main);
    (void)root;
    return options;
}

// RAII guard for the daemon journal override (per-test journal isolation).
class JournalOverride {
public:
    explicit JournalOverride(const fs::path& path) {
        fic::rollback::DaemonMutationJournal::instance().setOverridePath(
            path);
    }
    ~JournalOverride() {
        fic::rollback::DaemonMutationJournal::instance().resetOverride();
    }
};

std::size_t activeRecordCount(
    const PolicyRef& policyRef) {
    std::string error;
    auto* journal =
        fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, "journal must be usable");
    return journal->activeRecords(policyRef).size();
}

const fic::rollback::MutationRecord& singleActiveRecord(
    const PolicyRef& policyRef) {
    std::string error;
    auto* journal =
        fic::rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, "journal must be usable");
    const auto records = journal->activeRecords(policyRef);
    require(records.size() == 1, "expected exactly one active record");
    return journal->records().back();
}

SssdRollbackOptions sssdRollbackOptions(
    const fs::path& main,
    const fs::path& root,
    const fic::platform::PlatformExecutableResolver& resolver,
    fic::identity::sssd::SssdCommandRunner runner) {
    SssdRollbackOptions options;
    options.configuration = sssdOptions(main, root);
    options.executables = &resolver;
    options.runner = std::move(runner);
    return options;
}

fic::rollback::RollbackExecutorDeps sssdExecutorDeps(
    const SssdRollbackOptions& options) {
    fic::rollback::RollbackExecutorDeps deps;
    deps.sssdOptions = [options]() { return options; };
    return deps;
}

fic::rollback::RollbackExecutorDeps kerberosExecutorDeps(
    const fic::identity::kerberos::KerberosConfigurationOptions& options) {
    fic::rollback::RollbackExecutorDeps deps;
    deps.kerberosOptions = [options]() {
        KerberosRollbackOptions value;
        value.configuration = options;
        return value;
    };
    return deps;
}

const PolicyRef kSssdPolicyRef{
    "IDENTITY_ACCESS", "SSSD", "sssd_offline_credentials_expiration"};
const PolicyRef kKerberosPolicyRef{
    "IDENTITY_ACCESS", "KERBEROS", "kerberos_ticket_lifetime"};
constexpr const char* kSssdResource = "pam/offline_credentials_expiration";
constexpr const char* kKerberosResource = "libdefaults/ticket_lifetime";

ProcessResult okResult() {
    ProcessResult result;
    result.started = true;
    result.exitCode = 0;
    return result;
}

void testSssdPolicyRestartsActiveService(const fs::path& root) {
    const fs::path main = root / "system/sssd-success.conf";
    const std::string original = "[pam]\noffline_credentials_expiration = 0\n";
    writeFile(main, original, 0600);
    const fs::path systemctl = root / "bin/systemctl";
    writeFile(systemctl, "test executable\n", 0755);
    auto resolver = makeResolver(systemctl);
    std::vector<std::vector<std::string>> calls;
    auto runner = [&calls](const std::string&,
                           const std::vector<std::string>& arguments,
                           const ProcessOptions&) {
        calls.push_back(arguments);
        return okResult();
    };
    JournalOverride journalGuard(root / "journals/sssd-success.json");
    SssdOfflineCredentialsExpirationPolicy policy(
        sssdOptions(main, root), resolver, {"sssd.service"}, runner);
    require(policy.apply(), "SSSD policy failed");
    // The foreign main configuration must remain byte-for-byte unchanged.
    require(readFile(main) == original,
            "SSSD policy must never modify the foreign sssd.conf");
    const fs::path dropIn = main.parent_path() / (main.stem().string() + "-conf.d/zzzz-fic.conf");
    require(readFile(dropIn).find("offline_credentials_expiration = 30") !=
                std::string::npos,
            "SSSD policy did not install the FIC-owned drop-in");
    require(calls.size() == 3 && calls[1].front() == "restart",
            "SSSD policy did not inspect, restart and verify the service");
    // Provenance: a single Applied record.
    const auto& record = singleActiveRecord(kSssdPolicyRef);
    require(record.status == fic::rollback::MutationStatus::Applied,
            "SSSD policy must commit the Applied provenance");
    require(record.resource == kSssdResource,
            "SSSD journal record identity mismatch");
}

void testSssdPolicyRollsBackAfterRestartFailure(const fs::path& root) {
    const fs::path main = root / "system/sssd-rollback.conf";
    const std::string original =
        "[pam]\noffline_credentials_expiration = 7\n";
    writeFile(main, original, 0600);
    const fs::path systemctl = root / "bin/systemctl";
    auto resolver = makeResolver(systemctl);
    int restartCalls = 0;
    auto runner = [&restartCalls](const std::string&,
                                  const std::vector<std::string>& arguments,
                                  const ProcessOptions&) {
        ProcessResult result = okResult();
        if (!arguments.empty() && arguments.front() == "restart" &&
            restartCalls++ == 0) {
            result.exitCode = 1;
        }
        return result;
    };
    JournalOverride journalGuard(root / "journals/sssd-rollback.json");
    SssdOfflineCredentialsExpirationPolicy policy(
        sssdOptions(main, root), resolver, {"sssd.service"}, runner);
    require(!policy.apply(), "SSSD restart failure must fail the policy");
    // The transaction compensated the persistent mutation: the FIC-owned
    // drop-in is gone and the foreign file is untouched.
    require(readFile(main) == original,
            "SSSD restart failure did not keep the foreign file untouched");
    require(!fs::exists(main.parent_path() / (main.stem().string() + "-conf.d/zzzz-fic.conf")),
            "SSSD compensation did not remove the FIC-created drop-in");
    // Full compensation completed: the fresh Prepared record was discarded,
    // so no provenance is lost and nothing stays pending.
    require(activeRecordCount(kSssdPolicyRef) == 0,
            "fully compensated SSSD failure must not leave a pending record");
}

void testSssdCrashWindowPreparedRemainsRecoverable(const fs::path& root) {
    // Simulate a crash AFTER the drop-in was installed but BEFORE the
    // journal was committed: a Prepared record stays active and the
    // rollback executor must still release the ownership.
    const fs::path main = root / "system/sssd-crash.conf";
    writeFile(main, "[pam]\noffline_credentials_expiration = 7\n", 0600);
    const fs::path systemctl = root / "bin/systemctl";
    writeFile(systemctl, "test executable\n", 0755);
    auto resolver = makeResolver(systemctl);
    auto runner = [](const std::string&,
                     const std::vector<std::string>&,
                     const ProcessOptions&) { return okResult(); };
    JournalOverride journalGuard(root / "journals/sssd-crash.json");
    {
        // Install the drop-in without any journal record (as the policy
        // would have done just before committing Applied).
        fic::identity::sssd::SssdConfiguration configuration(
            sssdOptions(main, root));
        auto prepared = configuration.prepareManagedSnippetValue(
            "pam", "offline_credentials_expiration", "30");
        require(prepared.ok(), "drop-in install must prepare");
        std::string error;
        require(fic::identity::executePreparedFileChange(
                    std::move(prepared.change), error),
                error);
        fic::rollback::MutationId id = 0;
        require(fic::rollback::recordPreparedMutation(
                    kSssdPolicyRef,
                    kSssdResource,
                    fic::rollback::UndoAction{
                        fic::rollback::MutationBackend::Sssd,
                        fic::rollback::UndoRemoveSssdManagedSetting{
                            "pam", "offline_credentials_expiration", "30"}},
                    id, error),
                error);
    }
    require(activeRecordCount(kSssdPolicyRef) == 1,
            "the crash-window Prepared record must remain active");
    const auto rollbackDeps = sssdExecutorDeps(sssdRollbackOptions(
        main, root, resolver, runner));
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        kSssdPolicyRef, kSssdResource, rollbackDeps);
    require(report.rollbackCompleted(),
            "the crash-window Prepared record must stay recoverable");
    require(!fs::exists(main.parent_path() / (main.stem().string() + "-conf.d/zzzz-fic.conf")),
            "the FIC-created drop-in must be released");
    require(readFile(main) == "[pam]\noffline_credentials_expiration = 7\n",
            "the foreign value must become effective naturally");
    require(activeRecordCount(kSssdPolicyRef) == 0,
            "the resolved record must be RolledBack");
}

void testSssdDisableRollsBackManagedSetting(const fs::path& root) {
    // Foreign 7 -> FIC 30 -> disable: the FIC drop-in is removed, the main
    // file is untouched and the foreign value becomes effective naturally.
    const fs::path main = root / "system/sssd-disable.conf";
    const std::string original = "[pam]\noffline_credentials_expiration = 7\n";
    writeFile(main, original, 0600);
    const fs::path systemctl = root / "bin/systemctl";
    writeFile(systemctl, "test executable\n", 0755);
    auto resolver = makeResolver(systemctl);
    auto runner = [](const std::string&,
                     const std::vector<std::string>&,
                     const ProcessOptions&) { return okResult(); };
    JournalOverride journalGuard(root / "journals/sssd-disable.json");
    {
        SssdOfflineCredentialsExpirationPolicy policy(
            sssdOptions(main, root), resolver, {"sssd.service"}, runner);
        require(policy.apply(), "SSSD apply failed");
    }
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        kSssdPolicyRef, kSssdResource,
        sssdExecutorDeps(sssdRollbackOptions(main, root, resolver, runner)));
    require(report.status == fic::rollback::RollbackStatus::Success,
            "SSSD disable rollback must succeed: " + report.message);
    require(!fs::exists(main.parent_path() / (main.stem().string() + "-conf.d/zzzz-fic.conf")),
            "the semantically empty FIC drop-in must be removed");
    require(readFile(main) == original,
            "SSSD rollback must never touch the foreign sssd.conf");
    fic::identity::sssd::SssdConfiguration configuration(
        sssdOptions(main, root));
    std::optional<std::string> effective;
    std::string error;
    require(configuration.tryGetEffectiveValue(
                "pam", "offline_credentials_expiration", effective, error),
            error);
    require(effective.has_value() && *effective == "7",
            "the previous foreign value must become effective again");
    require(activeRecordCount(kSssdPolicyRef) == 0,
            "the rolled back record must be resolved");
}

void testSssdOriginalTargetMissingRollback(const fs::path& root) {
    // No foreign value at all: after disable the effective value returns to
    // missing.
    const fs::path main = root / "system/sssd-missing.conf";
    writeFile(main, "[pam]\nother_option = 1\n", 0600);
    const fs::path systemctl = root / "bin/systemctl";
    writeFile(systemctl, "test executable\n", 0755);
    auto resolver = makeResolver(systemctl);
    auto runner = [](const std::string&,
                     const std::vector<std::string>&,
                     const ProcessOptions&) { return okResult(); };
    JournalOverride journalGuard(root / "journals/sssd-missing.json");
    {
        SssdOfflineCredentialsExpirationPolicy policy(
            sssdOptions(main, root), resolver, {"sssd.service"}, runner);
        require(policy.apply(), "SSSD apply failed");
    }
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        kSssdPolicyRef, kSssdResource,
        sssdExecutorDeps(sssdRollbackOptions(main, root, resolver, runner)));
    require(report.rollbackCompleted(), "SSSD disable rollback must succeed");
    require(!fs::exists(main.parent_path() / (main.stem().string() + "-conf.d/zzzz-fic.conf")),
            "the FIC drop-in must be removed");
    fic::identity::sssd::SssdConfiguration configuration(
        sssdOptions(main, root));
    std::optional<std::string> effective;
    std::string error;
    require(configuration.tryGetEffectiveValue(
                "pam", "offline_credentials_expiration", effective, error),
            error);
    require(!effective.has_value(),
            "the effective value must return to missing");
}

void testSssdDoesNotStartInactiveService(const fs::path& root) {
    const fs::path main = root / "system/sssd-inactive.conf";
    const std::string original = "[pam]\noffline_credentials_expiration = 0\n";
    writeFile(main, original, 0600);
    const fs::path systemctl = root / "bin/systemctl";
    auto resolver = makeResolver(systemctl);
    int calls = 0;
    auto runner = [&calls](const std::string&,
                           const std::vector<std::string>& arguments,
                           const ProcessOptions&) {
        ++calls;
        require(arguments.front() == "is-active",
                "inactive SSSD service was started or restarted");
        ProcessResult result = okResult();
        result.exitCode = 3;
        return result;
    };
    JournalOverride journalGuard(root / "journals/sssd-inactive.json");
    SssdOfflineCredentialsExpirationPolicy policy(
        sssdOptions(main, root), resolver, {"sssd.service"}, runner);
    require(policy.apply(), "SSSD policy failed for an inactive service");
    require(calls == 1, "inactive SSSD service received an unexpected command");
    require(readFile(main) == original,
            "SSSD policy must never modify the foreign sssd.conf");
    require(readFile(main.parent_path() / (main.stem().string() + "-conf.d/zzzz-fic.conf"))
                    .find("offline_credentials_expiration = 30") !=
                std::string::npos,
            "SSSD policy did not persist the FIC-owned drop-in");
}

void testSssdExternalDriftConflict(const fs::path& root) {
    // FIC-owned value externally changed 30 -> 40: rollback must Conflict
    // and never overwrite the file.
    const fs::path main = root / "system/sssd-drift.conf";
    writeFile(main, "[pam]\noffline_credentials_expiration = 7\n", 0600);
    const fs::path systemctl = root / "bin/systemctl";
    writeFile(systemctl, "test executable\n", 0755);
    auto resolver = makeResolver(systemctl);
    auto runner = [](const std::string&,
                     const std::vector<std::string>&,
                     const ProcessOptions&) { return okResult(); };
    JournalOverride journalGuard(root / "journals/sssd-drift.json");
    {
        SssdOfflineCredentialsExpirationPolicy policy(
            sssdOptions(main, root), resolver, {"sssd.service"}, runner);
        require(policy.apply(), "SSSD apply failed");
    }
    const fs::path dropIn = main.parent_path() / (main.stem().string() + "-conf.d/zzzz-fic.conf");
    writeFile(dropIn,
              "# FIC managed configuration\n[pam]\n"
              "offline_credentials_expiration = 40\n",
              0600);
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        kSssdPolicyRef, kSssdResource,
        sssdExecutorDeps(sssdRollbackOptions(main, root, resolver, runner)));
    require(report.status == fic::rollback::RollbackStatus::Conflict,
            "external FIC-owned drift must Conflict");
    require(!report.rollbackCompleted(),
            "a Conflict must refuse the policy disable");
    require(readFile(dropIn).find("offline_credentials_expiration = 40") !=
                std::string::npos,
            "the drifted file must never be overwritten");
    require(activeRecordCount(kSssdPolicyRef) == 1,
            "the drifted record must stay active");
}

void testSssdConflictingLaterSnippetFailsApply(const fs::path& root) {
    // A foreign snippet sorting after zzzz-fic.conf defines the target
    // option: apply must fail closed without touching foreign files.
    const fs::path main = root / "system/sssd-conflict.conf";
    writeFile(main, "[pam]\noffline_credentials_expiration = 7\n", 0600);
    const fs::path confd = main.parent_path() / (main.stem().string() + "-conf.d");
    const fs::path foreign = confd / "zzzzzz-foreign.conf";
    const std::string foreignContent =
        "[pam]\noffline_credentials_expiration = 99\n";
    writeFile(foreign, foreignContent, 0600);
    const fs::path systemctl = root / "bin/systemctl";
    writeFile(systemctl, "test executable\n", 0755);
    auto resolver = makeResolver(systemctl);
    auto runner = [](const std::string&,
                     const std::vector<std::string>&,
                     const ProcessOptions&) { return okResult(); };
    JournalOverride journalGuard(root / "journals/sssd-conflict.json");
    SssdOfflineCredentialsExpirationPolicy policy(
        sssdOptions(main, root), resolver, {"sssd.service"}, runner);
    require(!policy.apply(),
            "a conflicting later snippet must fail the apply closed");
    require(!fs::exists(confd / "zzzz-fic.conf"),
            "the FIC drop-in must not be created");
    require(readFile(foreign) == foreignContent,
            "foreign snippets must never be modified");
    require(activeRecordCount(kSssdPolicyRef) == 0,
            "a failed closed preflight must not leave provenance");
}

void testSssdActiveValueChangeKeepsSingleRecord(const fs::path& root) {
    // 30 -> 60: ownership-safe release of the old mutation, then a fresh
    // apply; exactly one active logical mutation must exist.
    const fs::path main = root / "system/sssd-value-change.conf";
    writeFile(main, "[pam]\noffline_credentials_expiration = 7\n", 0600);
    const fs::path systemctl = root / "bin/systemctl";
    writeFile(systemctl, "test executable\n", 0755);
    auto resolver = makeResolver(systemctl);
    auto runner = [](const std::string&,
                     const std::vector<std::string>&,
                     const ProcessOptions&) { return okResult(); };
    JournalOverride journalGuard(root / "journals/sssd-change.json");
    {
        SssdOfflineCredentialsExpirationPolicy policy(
            sssdOptions(main, root), resolver, {"sssd.service"}, runner);
        require(policy.apply(), "SSSD apply 30 failed");
        require(activeRecordCount(kSssdPolicyRef) == 1,
                "the first apply must leave one active record");
        setPolicyValues(root, "60", "7200");
        // A fresh policy object re-reads the (changed) module config.
        SssdOfflineCredentialsExpirationPolicy policy2(
            sssdOptions(main, root), resolver, {"sssd.service"}, runner);
        require(policy2.apply(), "SSSD apply 60 failed");
    }
    require(activeRecordCount(kSssdPolicyRef) == 1,
            "an active value change must never duplicate provenance");
    const auto& record = singleActiveRecord(kSssdPolicyRef);
    const auto* undo =
        std::get_if<fic::rollback::UndoRemoveSssdManagedSetting>(
            &record.undo.payload);
    require(undo != nullptr && undo->appliedValue == "60",
            "the active record must carry the fresh applied value");
    require(readFile(main.parent_path() / (main.stem().string() + "-conf.d/zzzz-fic.conf"))
                    .find("offline_credentials_expiration = 60") !=
                std::string::npos,
            "the drop-in must carry the new value");
}

void testSssdRestartLikeJournalReloadKeepsRollback(const fs::path& root) {
    // A restart-like journal reload (production reopen through the
    // singleton) must not lose provenance: the disable still rolls the
    // mutation back.
    const fs::path main = root / "system/sssd-reload.conf";
    writeFile(main, "[pam]\noffline_credentials_expiration = 7\n", 0600);
    const fs::path systemctl = root / "bin/systemctl";
    writeFile(systemctl, "test executable\n", 0755);
    auto resolver = makeResolver(systemctl);
    auto runner = [](const std::string&,
                     const std::vector<std::string>&,
                     const ProcessOptions&) { return okResult(); };
    const fs::path journalPath = root / "journals/sssd-reload.json";
    {
        JournalOverride journalGuard(journalPath);
        SssdOfflineCredentialsExpirationPolicy policy(
            sssdOptions(main, root), resolver, {"sssd.service"}, runner);
        require(policy.apply(), "SSSD apply failed");
        require(activeRecordCount(kSssdPolicyRef) == 1,
                "the applied record must be active");
    }
    {
        // Reopen through the production path (setOverridePath forces the
        // singleton to re-open via initializeOrLoad).
        JournalOverride journalGuard(journalPath);
        require(activeRecordCount(kSssdPolicyRef) == 1,
                "the Applied record must survive a restart-like reload");
        const auto report = fic::rollback::rollbackPolicyBeforeDisable(
            kSssdPolicyRef, kSssdResource,
            sssdExecutorDeps(
                sssdRollbackOptions(main, root, resolver, runner)));
        require(report.rollbackCompleted(),
                "the reload journal must still roll the mutation back");
        require(!fs::exists(main.parent_path() / (main.stem().string() + "-conf.d/zzzz-fic.conf")),
                "the FIC drop-in must be removed after reload rollback");
    }
}

void testKerberosTicketLifetimePolicy(const fs::path& root) {
    // Foreign 8h -> FIC 36000s -> disable: the EXACT original raw line is
    // restored; no whole-file snapshot is used, only the journal payload.
    const fs::path main = root / "system/krb5.conf";
    const std::string original = "[libdefaults]\n    ticket_lifetime = 8h\n";
    writeFile(main, original, 0644);
    JournalOverride journalGuard(root / "journals/kerberos-restore.json");
    setPolicyValues(root, "30", "36000");
    {
        KerberosTicketLifetimePolicy policy(kerberosOptions(main, root));
        require(policy.apply(), "Kerberos ticket lifetime policy failed");
        require(readFile(main) ==
                    "[libdefaults]\n    ticket_lifetime = 36000s\n",
                "Kerberos policy wrote an unexpected duration");
    }
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        kKerberosPolicyRef, kKerberosResource,
        kerberosExecutorDeps(kerberosOptions(main, root)));
    require(report.status == fic::rollback::RollbackStatus::Success,
            "Kerberos disable rollback must succeed: " + report.message);
    require(readFile(main) == original,
            "the exact original raw line must be restored");
    require(activeRecordCount(kKerberosPolicyRef) == 0,
            "the rolled back record must be resolved");
}

void testKerberosMissingTargetRollback(const fs::path& root) {
    // The relation did not exist before FIC: disable removes it again.
    const fs::path main = root / "system/krb5-missing.conf";
    writeFile(main, "[libdefaults]\nother = 1\n", 0644);
    JournalOverride journalGuard(root / "journals/kerberos-missing.json");
    setPolicyValues(root, "30", "36000");
    {
        KerberosTicketLifetimePolicy policy(kerberosOptions(main, root));
        require(policy.apply(), "Kerberos apply failed");
        require(readFile(main).find("ticket_lifetime = 36000s") !=
                    std::string::npos,
                "the relation must be created");
    }
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        kKerberosPolicyRef, kKerberosResource,
        kerberosExecutorDeps(kerberosOptions(main, root)));
    require(report.rollbackCompleted(), "Kerberos disable must succeed");
    require(readFile(main) == "[libdefaults]\nother = 1\n",
            "the FIC relation must be removed exactly");
}

void testKerberosCreatedSectionRemoved(const fs::path& root) {
    // [libdefaults] did not exist: apply creates section+relation, disable
    // removes the relation AND the provably empty FIC-created section.
    const fs::path main = root / "system/krb5-section.conf";
    writeFile(main, "[logging]\n default = FILE\n", 0644);
    JournalOverride journalGuard(root / "journals/kerberos-section.json");
    setPolicyValues(root, "30", "36000");
    {
        KerberosTicketLifetimePolicy policy(kerberosOptions(main, root));
        require(policy.apply(), "Kerberos apply failed");
        require(readFile(main).find("[libdefaults]") != std::string::npos,
                "the FIC-created section must exist after apply");
    }
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        kKerberosPolicyRef, kKerberosResource,
        kerberosExecutorDeps(kerberosOptions(main, root)));
    require(report.rollbackCompleted(), "Kerberos disable must succeed");
    const std::string restored = readFile(main);
    require(restored.find("[libdefaults]") == std::string::npos &&
                restored.find("ticket_lifetime") == std::string::npos,
            "the empty FIC-created section must be removed");
    require(restored.find("[logging]") != std::string::npos &&
                restored.find(" default = FILE") != std::string::npos,
            "the foreign sections must be preserved");
}

void testKerberosDriftConflict(const fs::path& root) {
    // 8h -> FIC 36000s -> admin 2h: rollback must Conflict and preserve 2h.
    const fs::path main = root / "system/krb5-drift.conf";
    writeFile(main, "[libdefaults]\nticket_lifetime = 8h\n", 0644);
    JournalOverride journalGuard(root / "journals/kerberos-drift.json");
    setPolicyValues(root, "30", "36000");
    {
        KerberosTicketLifetimePolicy policy(kerberosOptions(main, root));
        require(policy.apply(), "Kerberos apply failed");
    }
    writeFile(main, "[libdefaults]\nticket_lifetime = 2h\n", 0644);
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        kKerberosPolicyRef, kKerberosResource,
        kerberosExecutorDeps(kerberosOptions(main, root)));
    require(report.status == fic::rollback::RollbackStatus::Conflict,
            "administrator drift must Conflict");
    require(!report.rollbackCompleted(),
            "a Conflict must refuse the policy disable");
    require(readFile(main) == "[libdefaults]\nticket_lifetime = 2h\n",
            "the administrator value 2h must be preserved");
}

void testKerberosForeignIncludeConflict(const fs::path& root) {
    // The target appears in a foreign include AFTER the apply: rollback
    // must Conflict; foreign include files are never modified.
    const fs::path main = root / "system/krb5-include.conf";
    writeFile(main, "[libdefaults]\nticket_lifetime = 8h\n", 0644);
    JournalOverride journalGuard(root / "journals/kerberos-include.json");
    setPolicyValues(root, "30", "36000");
    {
        KerberosTicketLifetimePolicy policy(kerberosOptions(main, root));
        require(policy.apply(), "Kerberos apply failed");
    }
    const fs::path includeDir = root / "etc/krb5.conf.d";
    fs::create_directories(includeDir);
    ::chmod(includeDir.c_str(), 0755);
    const fs::path includeFile = includeDir / "10-foreign.conf";
    const std::string includeContent = "[libdefaults]\nticket_lifetime = 1h\n";
    writeFile(includeFile, includeContent, 0644);
    // Declare the include in the root document (append as an admin would).
    {
        std::ofstream output(main, std::ios::binary | std::ios::app);
        require(output.is_open(), "could not append include directive");
        output << "include " << includeFile.string() << "\n";
    }
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        kKerberosPolicyRef, kKerberosResource,
        kerberosExecutorDeps(kerberosOptions(main, root)));
    require(report.status == fic::rollback::RollbackStatus::Conflict,
            "a foreign include definition must fail the rollback closed");
    require(readFile(includeFile) == includeContent,
            "foreign include files must never be modified");
}

void testKerberosDuplicateTargetFailsApply(const fs::path& root) {
    const fs::path main = root / "system/krb5-duplicate.conf";
    writeFile(
        main,
        "[libdefaults]\nticket_lifetime = 8h\nticket_lifetime = 12h\n",
        0644);
    JournalOverride journalGuard(root / "journals/kerberos-duplicate.json");
    setPolicyValues(root, "30", "36000");
    KerberosTicketLifetimePolicy policy(kerberosOptions(main, root));
    require(!policy.apply(), "a duplicate target must fail the apply closed");
    require(activeRecordCount(kKerberosPolicyRef) == 0,
            "a failed closed preflight must not leave provenance");
}

void testKerberosMarkersRestoredExactly(const fs::path& root) {
    // Indentation and key-final/value-final '*' markers must be preserved
    // through the apply and restored exactly on disable.
    const fs::path main = root / "system/krb5-markers.conf";
    const std::string original = "[libdefaults]\n  ticket_lifetime* = 8h*\n";
    writeFile(main, original, 0644);
    JournalOverride journalGuard(root / "journals/kerberos-markers.json");
    setPolicyValues(root, "30", "36000");
    {
        KerberosTicketLifetimePolicy policy(kerberosOptions(main, root));
        require(policy.apply(), "Kerberos apply failed");
        require(readFile(main) ==
                    "[libdefaults]\n  ticket_lifetime* = 36000s*\n",
                "the markers and indentation must survive the apply");
    }
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        kKerberosPolicyRef, kKerberosResource,
        kerberosExecutorDeps(kerberosOptions(main, root)));
    require(report.rollbackCompleted(), "Kerberos disable must succeed");
    require(readFile(main) == original,
            "the exact raw line with markers must be restored");
}

void testKerberosActiveValueTransition(const fs::path& root) {
    // 36000 -> 7200: no duplicate active records; the before-state of the
    // fresh mutation is the restored foreign line.
    const fs::path main = root / "system/krb5-transition.conf";
    const std::string original = "[libdefaults]\nticket_lifetime = 8h\n";
    writeFile(main, original, 0644);
    JournalOverride journalGuard(root / "journals/kerberos-change.json");
    {
        setPolicyValues(root, "30", "36000");
        KerberosTicketLifetimePolicy policy(kerberosOptions(main, root));
        require(policy.apply(), "Kerberos apply 36000 failed");
        require(activeRecordCount(kKerberosPolicyRef) == 1,
                "the first apply must leave one active record");
        setPolicyValues(root, "30", "7200");
        // A fresh policy object re-reads the (changed) module config.
        KerberosTicketLifetimePolicy policy2(kerberosOptions(main, root));
        require(policy2.apply(), "Kerberos apply 7200 failed");
    }
    require(activeRecordCount(kKerberosPolicyRef) == 1,
            "an active value transition must never duplicate provenance");
    const auto& record = singleActiveRecord(kKerberosPolicyRef);
    const auto* undo =
        std::get_if<fic::rollback::UndoRestoreKerberosScalar>(
            &record.undo.payload);
    require(undo != nullptr && undo->appliedValue == "7200s" &&
                undo->beforeKind ==
                    fic::rollback::KerberosBeforeKind::Present &&
                undo->beforeRawLine == "ticket_lifetime = 8h",
            "the fresh record must carry the restored before-state");
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        kKerberosPolicyRef, kKerberosResource,
        kerberosExecutorDeps(kerberosOptions(main, root)));
    require(report.rollbackCompleted(), "Kerberos disable must succeed");
    require(readFile(main) == original, "the 8h line must be restored");
}

void testKerberosCasRacePreservesForeignChange(const fs::path& root) {
    // The file changes after read but before write: the CAS commit must
    // fail and the foreign modification must survive.
    const fs::path main = root / "system/krb5-cas.conf";
    writeFile(main, "[libdefaults]\nticket_lifetime = 8h\n", 0644);
    fic::identity::kerberos::KerberosConfiguration configuration(
        kerberosOptions(main, root));
    auto prepared = configuration.prepareSetScalar(
        "libdefaults", "ticket_lifetime", "36000s");
    require(prepared.ok(), "prepare must succeed");
    // External (administrator) modification in the prepare->commit window.
    writeFile(main, "[libdefaults]\nticket_lifetime = 2h\n", 0644);
    std::string error;
    require(!fic::identity::executePreparedFileChange(
                std::move(prepared.change), error),
            "the CAS commit must fail on an external change");
    require(readFile(main) == "[libdefaults]\nticket_lifetime = 2h\n",
            "the foreign modification must survive");
}

} // namespace

int main() {
    const fs::path root = fs::temp_directory_path() /
        ("fic-identity-policy-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root);
    fs::create_directories(root / "journals");
    ::chmod(root.c_str(), 0755);
    try {
        initializeRuntimePaths(root);
        testSssdPolicyRestartsActiveService(root);
        testSssdPolicyRollsBackAfterRestartFailure(root);
        testSssdCrashWindowPreparedRemainsRecoverable(root);
        testSssdDisableRollsBackManagedSetting(root);
        testSssdOriginalTargetMissingRollback(root);
        testSssdDoesNotStartInactiveService(root);
        testSssdExternalDriftConflict(root);
        testSssdConflictingLaterSnippetFailsApply(root);
        testSssdActiveValueChangeKeepsSingleRecord(root);
        testSssdRestartLikeJournalReloadKeepsRollback(root);
        testKerberosTicketLifetimePolicy(root);
        testKerberosMissingTargetRollback(root);
        testKerberosCreatedSectionRemoved(root);
        testKerberosDriftConflict(root);
        testKerberosForeignIncludeConflict(root);
        testKerberosDuplicateTargetFailsApply(root);
        testKerberosMarkersRestoredExactly(root);
        testKerberosActiveValueTransition(root);
        testKerberosCasRacePreservesForeignChange(root);
    } catch (const std::exception& error) {
        std::cerr << "IdentityConcretePoliciesTests failed: "
                  << error.what() << '\n';
        fs::remove_all(root);
        return 1;
    }
    fs::remove_all(root);
    std::cout << "IdentityConcretePoliciesTests passed\n";
    return 0;
}
