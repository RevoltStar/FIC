#include "modules/identity_access/kerberos/policies/KerberosTicketLifetimePolicy.h"
#include "modules/identity_access/sssd/policies/SssdOfflineCredentialsExpirationPolicy.h"

#include "modules/identity_access/composite/ConfigurationTransaction.h"
#include "modules/identity_access/shared/configuration/PreparedFileChange.h"
#include "modules/identity_access/sssd/SssdConfiguration.h"
#include "rollback/DaemonMutationJournal.h"
#include "rollback/MutationRecord.h"
#include "rollback/RollbackExecutor.h"

#include <fic/core/runtime/FicRuntimePaths.h>
#include <fic/core/fs/AtomicFileWriter.h>

#include <filesystem>
#include <fstream>
#include <functional>
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

fs::path sssdDropInPath(const fs::path& main) {
    return main.parent_path() / (main.stem().string() + "-conf.d/zzzz-fic.conf");
}

void testSssdRollbackRetryCompletesRuntimeReconciliation(
    const fs::path& root) {
    // Regression: rollback #1 removes the FIC option but the SSSD restart
    // fails -> RollbackFailed stays active. Rollback #2 finds the option
    // absent, MUST still run the mandatory runtime reconciliation and only
    // then complete the lifecycle (record RolledBack).
    const fs::path main = root / "system/sssd-retry-runtime.conf";
    const std::string original =
        "[pam]\noffline_credentials_expiration = 7\n";
    writeFile(main, original, 0600);
    const fs::path systemctl = root / "bin/systemctl";
    writeFile(systemctl, "test executable\n", 0755);
    auto resolver = makeResolver(systemctl);
    int restartCalls = 0;
    bool failNextRestart = false;
    auto runner = [&](const std::string&,
                      const std::vector<std::string>& arguments,
                      const ProcessOptions&) {
        if (!arguments.empty() && arguments.front() == "restart") {
            ++restartCalls;
            if (failNextRestart) {
                failNextRestart = false;
                ProcessResult failure;
                failure.started = true;
                failure.exitCode = 1;
                failure.standardError = "simulated restart failure";
                return failure;
            }
        }
        return okResult();
    };
    JournalOverride journalGuard(root / "journals/sssd-retry-runtime.json");
    SssdOfflineCredentialsExpirationPolicy policy(
        sssdOptions(main, root), resolver, {"sssd.service"}, runner);
    require(policy.apply(), "SSSD apply failed");
    // Rollback #1: source removal succeeds, restart fails.
    failNextRestart = true;
    const auto first = fic::rollback::rollbackPolicyBeforeDisable(
        kSssdPolicyRef, kSssdResource,
        sssdExecutorDeps(sssdRollbackOptions(main, root, resolver, runner)));
    require(!first.rollbackCompleted(),
            "a failed runtime reconciliation must not complete the rollback");
    require(first.status == fic::rollback::RollbackStatus::Failed,
            "restart failure must be RollbackFailed, got: " + first.message);
    require(activeRecordCount(kSssdPolicyRef) == 1,
            "the record must stay active after the failed reconciliation");
    require(!fs::exists(sssdDropInPath(main)),
            "the FIC option/drop-in must be removed by the first attempt");
    const int restartsAfterFirst = restartCalls;
    require(restartsAfterFirst >= 1,
            "the first rollback must have attempted a restart");
    const auto second = fic::rollback::rollbackPolicyBeforeDisable(
        kSssdPolicyRef, kSssdResource,
        sssdExecutorDeps(sssdRollbackOptions(main, root, resolver, runner)));
    require(second.rollbackCompleted(),
            "the retry must complete the rollback: " + second.message);
    require(activeRecordCount(kSssdPolicyRef) == 0,
            "the record must be RolledBack after the retry");
    require(restartCalls > restartsAfterFirst,
            "the retry MUST re-run the runtime reconciliation (restart)");
    require(readFile(main) == original,
            "the foreign sssd.conf must remain untouched");
}

void testSssdPreparedCrashRecoveryCompletesApplied(const fs::path& root) {
    // Regression: Prepared persisted + drop-in installed + crash BEFORE the
    // runtime reconciliation and BEFORE Applied. A daemon-style journal
    // reopen + same-value apply must run the mandatory runtime
    // reconciliation, re-prove the AFTER state and promote the SAME
    // MutationId Prepared -> Applied; exactly one active record remains.
    const fs::path main = root / "system/sssd-prepared-recovery.conf";
    writeFile(main, "[pam]\noffline_credentials_expiration = 7\n", 0600);
    const fs::path systemctl = root / "bin/systemctl";
    writeFile(systemctl, "test executable\n", 0755);
    auto resolver = makeResolver(systemctl);
    int restartCalls = 0;
    auto runner = [&restartCalls](const std::string&,
                                  const std::vector<std::string>& arguments,
                                  const ProcessOptions&) {
        if (!arguments.empty() && arguments.front() == "restart") {
            ++restartCalls;
        }
        return okResult();
    };
    const fs::path journalPath = root / "journals/sssd-prepared-recovery.json";
    JournalOverride journalGuard(journalPath);
    // Simulate the crash window: drop-in installed, Prepared record
    // persisted, runtime reconciliation and Applied never happened.
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
                kSssdPolicyRef, kSssdResource,
                fic::rollback::UndoAction{
                    fic::rollback::MutationBackend::Sssd,
                    fic::rollback::UndoRemoveSssdManagedSetting{
                        "pam", "offline_credentials_expiration", "30"}},
                id, error),
            error);
    const auto& recordBefore = singleActiveRecord(kSssdPolicyRef);
    require(recordBefore.status == fic::rollback::MutationStatus::Prepared,
            "the crash-window record must be Prepared");
    const auto idBefore = recordBefore.id;
    {
        // Daemon-style reopen: a second override forces initializeOrLoad.
        JournalOverride reopenGuard(journalPath);
        setPolicyValues(root, "30", "7200");
        SssdOfflineCredentialsExpirationPolicy recoveryPolicy(
            sssdOptions(main, root), resolver, {"sssd.service"}, runner);
        require(recoveryPolicy.apply(), "the recovery apply must succeed");
        require(restartCalls == 1,
                "Prepared recovery must restart exactly once");
        const auto& record = singleActiveRecord(kSssdPolicyRef);
        require(record.id == idBefore,
                "recovery must reuse the SAME MutationId");
        require(record.status == fic::rollback::MutationStatus::Applied,
                "the SAME record must become Applied");
        require(readFile(sssdDropInPath(main)).find(
                    "offline_credentials_expiration = 30") !=
                std::string::npos,
                "the FIC drop-in must still carry the applied value");
        require(activeRecordCount(kSssdPolicyRef) == 1,
                "exactly one active record after recovery");
    }
}

void testSssdApplyAbsentSourceReconcilesRuntime(const fs::path& root) {
    const fs::path systemctl = root / "bin/systemctl";
    writeFile(systemctl, "test executable\n", 0755);
    auto resolver = makeResolver(systemctl);
    const std::vector<fic::rollback::MutationStatus> states = {
        fic::rollback::MutationStatus::Prepared,
        fic::rollback::MutationStatus::Applied,
        fic::rollback::MutationStatus::RollbackFailed};
    for (std::size_t index = 0; index < states.size(); ++index) {
        const fs::path main = root / "system" /
            ("sssd-absent-apply-" + std::to_string(index) + ".conf");
        writeFile(main, "[pam]\noffline_credentials_expiration = 7\n", 0600);
        JournalOverride guard(root / "journals" /
            ("sssd-absent-apply-" + std::to_string(index) + ".json"));
        fic::rollback::MutationId id = 0;
        std::string error;
        require(fic::rollback::recordPreparedMutation(
                    kSssdPolicyRef, kSssdResource,
                    fic::rollback::UndoAction{
                        fic::rollback::MutationBackend::Sssd,
                        fic::rollback::UndoRemoveSssdManagedSetting{
                            "pam", "offline_credentials_expiration", "30"}},
                    id, error), error);
        auto* journal =
            fic::rollback::DaemonMutationJournal::instance().tryGet(error);
        require(journal != nullptr, "journal must be usable");
        if (states[index] != fic::rollback::MutationStatus::Prepared) {
            require(journal->setStatus(id, states[index], error), error);
        }
        int restarts = 0;
        bool failRestart = true;
        auto runner = [&](const std::string&,
                          const std::vector<std::string>& arguments,
                          const ProcessOptions&) {
            if (!arguments.empty() && arguments.front() == "restart") {
                ++restarts;
                if (restarts <= 2) {
                    require(singleActiveRecord(kSssdPolicyRef).id == id,
                            "old provenance must stay active until runtime is reconciled");
                }
                if (failRestart) {
                    ProcessResult failed = okResult();
                    failed.exitCode = 1;
                    return failed;
                }
            }
            return okResult();
        };
        setPolicyValues(root, "30", "7200");
        // A staging-shaped artifact for a different managed basename must
        // not block release of this exact FIC-owned path.
        if (index == 0) {
            writeFile(
                sssdDropInPath(main).parent_path() /
                    "other.conf.fic-removing-1-1",
                "unrelated staging object\n", 0600);
        }
        SssdOfflineCredentialsExpirationPolicy policy(
            sssdOptions(main, root), resolver, {"sssd.service"}, runner);
        require(!policy.apply(), "runtime failure must fail apply closed");
        require(restarts == 1, "absent source must still trigger restart");
        require(singleActiveRecord(kSssdPolicyRef).id == id,
                "failed runtime reconciliation must retain provenance");
        failRestart = false;
        require(policy.apply(), "runtime retry should permit fresh apply");
        require(restarts >= 2, "retry must reconcile runtime again");
        bool oldRolledBack = false;
        for (const auto& record : journal->records()) {
            if (record.id == id) {
                oldRolledBack = record.status ==
                    fic::rollback::MutationStatus::RolledBack;
            }
        }
        require(oldRolledBack,
                "old record must be RolledBack only after runtime success");
    }
}

void testSssdForeignReplacementBetweenProofAndRemovalSurvives(
    const fs::path& root) {
    // Regression (TOCTOU): FIC proves zzzz-fic.conf, then a foreign actor
    // atomically replaces it BEFORE the removal step. The removal must fail
    // closed and the foreign replacement must survive byte-exact.
    const fs::path main = root / "system/sssd-race-removal.conf";
    writeFile(main, "[pam]\noffline_credentials_expiration = 7\n", 0600);
    const fs::path systemctl = root / "bin/systemctl";
    writeFile(systemctl, "test executable\n", 0755);
    auto resolver = makeResolver(systemctl);
    auto runner = [](const std::string&,
                     const std::vector<std::string>&,
                     const ProcessOptions&) { return okResult(); };
    JournalOverride journalGuard(root / "journals/sssd-race-removal.json");
    {
        SssdOfflineCredentialsExpirationPolicy policy(
            sssdOptions(main, root), resolver, {"sssd.service"}, runner);
        require(policy.apply(), "SSSD apply failed");
    }
    const std::string foreignReplacement =
        "# foreign replacement\n[pam]\n"
        "offline_credentials_expiration = 55\n";
    const fs::path staged =
        sssdDropInPath(main).string() + ".foreign-staged";
    {
        std::ofstream output(staged, std::ios::binary | std::ios::trunc);
        require(output.is_open(), "could not stage the foreign file");
        output << foreignReplacement;
    }
    ::chmod(staged.c_str(), 0600);
    fic::identity::sssd::setManagedSnippetRemovalRaceHookForTests(
        [&main, staged]() {
            ::rename(staged.c_str(), sssdDropInPath(main).c_str());
        });
    int restoreBarriers = 0;
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [&](const std::string& path) {
            if (path == sssdDropInPath(main).string()) {
                ++restoreBarriers;
            }
            return true;
        });
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        kSssdPolicyRef, kSssdResource,
        sssdExecutorDeps(sssdRollbackOptions(main, root, resolver, runner)));
    fic::identity::sssd::setManagedSnippetRemovalRaceHookForTests(nullptr);
    AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
    require(restoreBarriers >= 1,
            "restored foreign replacement requires a directory barrier");
    require(!report.rollbackCompleted(),
            "a foreign replacement must fail the removal closed");
    require(report.status == fic::rollback::RollbackStatus::Failed ||
                report.status == fic::rollback::RollbackStatus::Conflict,
            "the foreign replacement must be refused");
    require(readFile(sssdDropInPath(main)) == foreignReplacement,
            "the foreign replacement must survive byte-exact");
    require(activeRecordCount(kSssdPolicyRef) == 1,
            "the record must stay active after the failed removal");
}

void testSssdDoubleReplacementPreservesBothForeignObjects(
    const fs::path& root) {
    const fs::path main = root / "system/sssd-double-replacement.conf";
    writeFile(main, "[pam]\noffline_credentials_expiration = 7\n", 0600);
    const fs::path systemctl = root / "bin/systemctl";
    writeFile(systemctl, "test executable\n", 0755);
    auto resolver = makeResolver(systemctl);
    auto runner = [](const std::string&,
                     const std::vector<std::string>&,
                     const ProcessOptions&) { return okResult(); };
    JournalOverride guard(root / "journals/sssd-double-replacement.json");
    setPolicyValues(root, "30", "7200");
    SssdOfflineCredentialsExpirationPolicy policy(
        sssdOptions(main, root), resolver, {"sssd.service"}, runner);
    require(policy.apply(), "initial SSSD apply must succeed");
    const fs::path dropIn = sssdDropInPath(main);
    const std::string b = "[pam]\noffline_credentials_expiration = 40\n";
    const std::string c = "[pam]\noffline_credentials_expiration = 50\n";
    fs::path staged;
    fic::identity::sssd::setManagedSnippetRemovalRaceHookForTests(
        [&]() {
            const fs::path replacement = dropIn.string() + ".replacement";
            writeFile(replacement, b, 0600);
            require(::rename(replacement.c_str(), dropIn.c_str()) == 0,
                    "could not install foreign B");
        });
    fic::identity::sssd::setManagedSnippetStagedRaceHookForTests(
        [&](const fs::path& privatePath) {
            staged = privatePath;
            writeFile(dropIn, c, 0600);
        });
    int stagedBarriers = 0;
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [&](const std::string& path) {
            if (path == dropIn.string()) {
                ++stagedBarriers;
            }
            return true;
        });
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        kSssdPolicyRef, kSssdResource,
        sssdExecutorDeps(sssdRollbackOptions(main, root, resolver, runner)));
    fic::identity::sssd::setManagedSnippetRemovalRaceHookForTests(nullptr);
    fic::identity::sssd::setManagedSnippetStagedRaceHookForTests(nullptr);
    AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
    require(stagedBarriers >= 1,
            "B-staged/C-at-source arrangement requires a directory barrier");
    require(!report.rollbackCompleted(), "double replacement must fail closed");
    require(readFile(dropIn) == c, "foreign C must not be overwritten by B");
    require(!staged.empty() && readFile(staged) == b,
            "foreign B must remain staged byte-exact");
    require(activeRecordCount(kSssdPolicyRef) == 1,
            "double replacement must retain provenance");
}

void testSssdForeignRestoreFsyncFailureKeepsProvenance(
    const fs::path& root) {
    const fs::path main = root / "system/sssd-restore-fsync.conf";
    writeFile(main, "[pam]\noffline_credentials_expiration = 7\n", 0600);
    const fs::path systemctl = root / "bin/systemctl";
    writeFile(systemctl, "test executable\n", 0755);
    auto resolver = makeResolver(systemctl);
    int restarts = 0;
    auto runner = [&](const std::string&,
                      const std::vector<std::string>& arguments,
                      const ProcessOptions&) {
        if (!arguments.empty() && arguments.front() == "restart") {
            ++restarts;
        }
        return okResult();
    };
    const fs::path journalPath = root / "journals/sssd-restore-fsync.json";
    JournalOverride guard(journalPath);
    setPolicyValues(root, "30", "7200");
    SssdOfflineCredentialsExpirationPolicy policy(
        sssdOptions(main, root), resolver, {"sssd.service"}, runner);
    require(policy.apply(), "initial SSSD apply must succeed");
    const fs::path dropIn = sssdDropInPath(main);
    const std::string foreign =
        "[pam]\noffline_credentials_expiration = 40\n";
    fic::identity::sssd::setManagedSnippetRemovalRaceHookForTests(
        [&]() {
            const fs::path replacement = dropIn.string() + ".replacement";
            writeFile(replacement, foreign, 0600);
            require(::rename(replacement.c_str(), dropIn.c_str()) == 0,
                    "could not install foreign replacement");
        });
    fs::path staged;
    fic::identity::sssd::setManagedSnippetStagedRaceHookForTests(
        [&](const fs::path& privatePath) { staged = privatePath; });
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [&](const std::string& path) { return path != dropIn.string(); });
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        kSssdPolicyRef, kSssdResource,
        sssdExecutorDeps(sssdRollbackOptions(main, root, resolver, runner)));
    AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
    fic::identity::sssd::setManagedSnippetRemovalRaceHookForTests(nullptr);
    fic::identity::sssd::setManagedSnippetStagedRaceHookForTests(nullptr);
    require(!report.rollbackCompleted(),
            "failed restore fsync must not complete rollback");
    require(report.message.find("directory state indeterminate") !=
                std::string::npos,
            "failed restore fsync must report indeterminate directory state");
    require(readFile(dropIn) == foreign,
            "foreign replacement must remain untouched");
    require(activeRecordCount(kSssdPolicyRef) == 1,
            "failed restore fsync must retain provenance");

    // Model the admissible post-crash directory state: the unconfirmed
    // restore is lost, while B remains under the ignored staging name.
    require(!staged.empty() && !fs::exists(staged),
            "successful restore must have consumed the staging path");
    writeFile(staged, foreign, 0600);
    require(fs::remove(dropIn), "could not model absent source after crash");
    const int restartsBeforeRetry = restarts;
    {
        JournalOverride reopen(journalPath);
        SssdOfflineCredentialsExpirationPolicy recoveryPolicy(
            sssdOptions(main, root), resolver, {"sssd.service"}, runner);
        require(!recoveryPolicy.apply(),
                "apply must not treat staged B as completed release");
        const auto retry = fic::rollback::rollbackPolicyBeforeDisable(
            kSssdPolicyRef, kSssdResource,
            sssdExecutorDeps(sssdRollbackOptions(
                main, root, resolver, runner)));
        require(!retry.rollbackCompleted(),
                "disable must not close staged-B provenance");
        require(retry.message.find("staged removal artifact") !=
                    std::string::npos,
                "disable must report the exact staged-source conflict");
        require(activeRecordCount(kSssdPolicyRef) == 1,
                "journal reopen must retain active provenance");
    }
    require(restarts == restartsBeforeRetry,
            "staged B must be detected before runtime reconciliation");
    require(readFile(staged) == foreign && !fs::exists(dropIn),
            "retry must not forget or mutate staged foreign B");
}

void testSssdStagingCollisionDoesNotReplaceObject(const fs::path& root) {
    const fs::path main = root / "system/sssd-staging-collision.conf";
    const fs::path dropIn = sssdDropInPath(main);
    writeFile(main, "[pam]\noffline_credentials_expiration = 7\n", 0600);
    const std::string owned =
        "# FIC managed configuration\n[pam]\n"
        "offline_credentials_expiration = 30\n";
    writeFile(dropIn, owned, 0600);
    fic::identity::sssd::SssdConfiguration configuration(
        sssdOptions(main, root));
    auto prepared = configuration.prepareManagedSnippetRemoval(
        "pam", "offline_credentials_expiration");
    require(prepared.ok(), "collision removal must prepare");
    fs::path occupied;
    const std::string foreign = "foreign staging object\n";
    fic::identity::sssd::setManagedSnippetBeforeStageHookForTests(
        [&](const fs::path& privatePath) {
            occupied = privatePath;
            writeFile(privatePath, foreign, 0600);
        });
    const auto result = prepared.change->commitPersistent();
    fic::identity::sssd::setManagedSnippetBeforeStageHookForTests(nullptr);
    require(!result.ok, "occupied private target must fail closed");
    require(readFile(dropIn) == owned,
            "staging collision must leave the owned source untouched");
    require(!occupied.empty() && readFile(occupied) == foreign,
            "staging collision must not replace the foreign object");
}

void testSssdReusedDriftAfterProofSurvives(const fs::path& root) {
    const fs::path main = root / "system/sssd-reused-drift.conf";
    writeFile(main, "[pam]\noffline_credentials_expiration = 7\n", 0600);
    const fs::path systemctl = root / "bin/systemctl";
    writeFile(systemctl, "test executable\n", 0755);
    auto resolver = makeResolver(systemctl);
    const fs::path dropIn = sssdDropInPath(main);
    const std::string foreign =
        "# foreign edit\n[pam]\noffline_credentials_expiration = 40\n";
    int restarts = 0;
    auto runner = [&](const std::string&,
                      const std::vector<std::string>& arguments,
                      const ProcessOptions&) {
        if (!arguments.empty() && arguments.front() == "restart") {
            ++restarts;
        }
        return okResult();
    };
    JournalOverride guard(root / "journals/sssd-reused-drift.json");
    setPolicyValues(root, "30", "7200");
    SssdOfflineCredentialsExpirationPolicy policy(
        sssdOptions(main, root), resolver, {"sssd.service"}, runner);
    require(policy.apply(), "initial SSSD apply must succeed");
    const int firstRestarts = restarts;
    require(policy.apply(), "unchanged Applied reapply must succeed");
    require(restarts == firstRestarts,
            "unchanged Applied reapply must not restart SSSD");
    SssdOfflineCredentialsExpirationPolicy::setReusedProofHookForTests(
        [&]() { writeFile(dropIn, foreign, 0600); });
    const bool applied = policy.apply();
    SssdOfflineCredentialsExpirationPolicy::setReusedProofHookForTests(nullptr);
    require(!applied, "post-proof drift must fail reused apply closed");
    require(restarts == firstRestarts,
            "drifted Applied reapply must not restart SSSD");
    require(readFile(dropIn) == foreign,
            "reused apply must not restore 30 over foreign 40");
    require(activeRecordCount(kSssdPolicyRef) == 1,
            "drift must retain active provenance");
}

// Wrapper that fails verifyPersistent() so the transaction executes the
// full compensation path (persistent rollback) of the inner change.
class VerifyFailingChange
    : public fic::identity::PreparedConfigurationChange {
public:
    explicit VerifyFailingChange(
        std::unique_ptr<fic::identity::PreparedConfigurationChange> inner)
        : inner_(std::move(inner)) {}
    std::string id() const override { return inner_->id(); }
    bool needsCommit() const noexcept override { return inner_->needsCommit(); }
    bool needsActivation() const noexcept override { return false; }
    fic::identity::ConfigurationStepResult commitPersistent() override {
        return inner_->commitPersistent();
    }
    fic::identity::ConfigurationStepResult verifyPersistent() override {
        return fic::identity::ConfigurationStepResult::failure(
            "simulated verification failure");
    }
    fic::identity::ConfigurationStepResult activate() override {
        return fic::identity::ConfigurationStepResult::success(false);
    }
    fic::identity::ConfigurationStepResult verifyEffective() override {
        return fic::identity::ConfigurationStepResult::success(false);
    }
    fic::identity::ConfigurationStepResult rollbackPersistent() override {
        return inner_->rollbackPersistent();
    }
    fic::identity::ConfigurationStepResult restoreRuntimeAfterRollback()
        override {
        return fic::identity::ConfigurationStepResult::success(false);
    }
    fic::identity::ConfigurationStepResult verifyRollback() override {
        return inner_->verifyRollback();
    }

private:
    std::unique_ptr<fic::identity::PreparedConfigurationChange> inner_;
};

void testSssdCompensationRecreateOnlyOnProvenMissing(const fs::path& root) {
    // Regression: the removal committed, then verification failed and the
    // compensation ran against the PROVEN-MISSING target: the original
    // content must be exclusively recreated byte-exact.
    const fs::path main = root / "system/sssd-compensation-missing.conf";
    const std::string dropInContent =
        "# FIC managed configuration\n[pam]\n"
        "offline_credentials_expiration = 30\n";
    const fs::path dropIn = sssdDropInPath(main);
    fs::create_directories(dropIn.parent_path());
    writeFile(main, "[pam]\noffline_credentials_expiration = 7\n", 0600);
    writeFile(dropIn, dropInContent, 0600);
    fic::identity::sssd::SssdConfiguration configuration(
        sssdOptions(main, root));
    auto prepared = configuration.prepareManagedSnippetRemoval(
        "pam", "offline_credentials_expiration");
    require(prepared.ok(), "removal must prepare");
    std::string error;
    require(!fic::identity::executePreparedFileChange(
                std::make_unique<VerifyFailingChange>(
                    std::move(prepared.change)),
                error),
            "the simulated verification failure must fail the transaction");
    require(fs::exists(dropIn),
            "the compensation must recreate the drop-in");
    require(readFile(dropIn) == dropInContent,
            "the recreated content must be byte-exact");
    struct stat recreated {};
    require(::stat(dropIn.c_str(), &recreated) == 0,
            "the recreated drop-in must be readable");
    require(recreated.st_uid == ::geteuid() &&
                recreated.st_gid == ::getegid() &&
                (recreated.st_mode & 07777) == 0600,
            "exclusive recreate must install the expected metadata");
}

void testSssdRemovalAndCompensationDurability(const fs::path& root) {
    const fs::path main = root / "system/sssd-durability.conf";
    const fs::path dropIn = sssdDropInPath(main);
    const std::string content =
        "# FIC managed configuration\n[pam]\n"
        "offline_credentials_expiration = 30\n";
    writeFile(main, "[pam]\noffline_credentials_expiration = 7\n", 0600);
    writeFile(dropIn, content, 0600);
    fic::identity::sssd::SssdConfiguration configuration(
        sssdOptions(main, root));
    auto prepareRemoval = [&]() {
        auto prepared = configuration.prepareManagedSnippetRemoval(
            "pam", "offline_credentials_expiration");
        require(prepared.ok(), "durability removal must prepare");
        return std::move(prepared.change);
    };
    int barriers = 0;
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [&](const std::string& path) {
            if (path == dropIn.string()) {
                ++barriers;
                return barriers != 1;
            }
            return true;
        });
    auto removalFailure = fic::identity::executePreparedFileChangeDetailed(
        prepareRemoval());
    AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
    require(removalFailure.status ==
                fic::identity::PreparedChangeExecutionStatus::Compensated,
            "non-durable removal must be compensated, not committed");
    require(barriers == 2,
            "both removal and compensation must reach a directory barrier");
    require(readFile(dropIn) == content,
            "compensation after removal fsync failure must restore bytes");

    barriers = 0;
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [&](const std::string& path) {
            if (path == dropIn.string()) {
                ++barriers;
                return barriers != 2;
            }
            return true;
        });
    auto compensationFailure = fic::identity::executePreparedFileChangeDetailed(
        std::make_unique<VerifyFailingChange>(prepareRemoval()));
    AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
    require(compensationFailure.status ==
                fic::identity::PreparedChangeExecutionStatus::CompensationFailed,
            "non-durable recreate must not count as Compensated");
    require(barriers == 2, "recreate must reach the directory barrier");
    require(readFile(dropIn) == content,
            "failed durability confirmation must not rewrite content");
}

void testSssdRemovalFsyncFailureKeepsJournalActive(const fs::path& root) {
    const fs::path main = root / "system/sssd-removal-fsync-journal.conf";
    writeFile(main, "[pam]\noffline_credentials_expiration = 7\n", 0600);
    const fs::path systemctl = root / "bin/systemctl";
    writeFile(systemctl, "test executable\n", 0755);
    auto resolver = makeResolver(systemctl);
    auto runner = [](const std::string&,
                     const std::vector<std::string>&,
                     const ProcessOptions&) { return okResult(); };
    JournalOverride guard(root / "journals/sssd-removal-fsync-journal.json");
    setPolicyValues(root, "30", "7200");
    SssdOfflineCredentialsExpirationPolicy policy(
        sssdOptions(main, root), resolver, {"sssd.service"}, runner);
    require(policy.apply(), "SSSD apply must create provenance");
    const fs::path dropIn = sssdDropInPath(main);
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [&](const std::string& path) { return path != dropIn.string(); });
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        kSssdPolicyRef, kSssdResource,
        sssdExecutorDeps(sssdRollbackOptions(main, root, resolver, runner)));
    AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
    require(!report.rollbackCompleted(),
            "non-durable removal must not complete rollback");
    require(activeRecordCount(kSssdPolicyRef) == 1,
            "non-durable removal must keep provenance active");
}

void testSssdCompensationNeverOverwritesForeignFile(const fs::path& root) {
    // Regression: after the removal committed, a foreign actor created a NEW
    // file at the drop-in path. The compensation must refuse to overwrite
    // it; the foreign content must survive byte-exact.
    const fs::path main = root / "system/sssd-compensation-foreign.conf";
    const std::string foreignContent =
        "# foreign new file\n[pam]\n"
        "offline_credentials_expiration = 88\n";
    const fs::path dropIn = sssdDropInPath(main);
    fs::create_directories(dropIn.parent_path());
    writeFile(main, "[pam]\noffline_credentials_expiration = 7\n", 0600);
    writeFile(dropIn,
              "# FIC managed configuration\n[pam]\n"
              "offline_credentials_expiration = 30\n",
              0600);
    fic::identity::sssd::SssdConfiguration configuration(
        sssdOptions(main, root));
    auto prepared = configuration.prepareManagedSnippetRemoval(
        "pam", "offline_credentials_expiration");
    require(prepared.ok(), "removal must prepare");
    // A foreign file appears in the commit->compensation window.
    class ForeignHook final : public VerifyFailingChange {
    public:
        ForeignHook(
            std::unique_ptr<fic::identity::PreparedConfigurationChange> inner,
            fs::path path)
            : VerifyFailingChange(std::move(inner)), path_(std::move(path)) {}
        void setForeign(const std::string* content) { content_ = content; }
        fic::identity::ConfigurationStepResult verifyPersistent() override {
            // Model the foreign creation exactly after the commit.
            writeFile(path_, *content_, 0600);
            return VerifyFailingChange::verifyPersistent();
        }

    private:
        fs::path path_;
        const std::string* content_ = nullptr;
    };
    auto failing = std::make_unique<ForeignHook>(
        std::move(prepared.change), dropIn);
    failing->setForeign(&foreignContent);
    std::string error;
    require(!fic::identity::executePreparedFileChange(
                std::move(failing), error),
            "the transaction must fail");
    require(fs::exists(dropIn), "the foreign file must still exist");
    require(readFile(dropIn) == foreignContent,
            "the foreign content must survive byte-exact");
}

void testSssdCompensationRefusesUnsafeTarget(const fs::path& root) {
    // Regression: a foreign SYMLINK occupies the drop-in path after the
    // removal commit. The compensation must fail closed and leave the
    // symlink untouched.
    const fs::path main = root / "system/sssd-compensation-symlink.conf";
    const fs::path dropIn = sssdDropInPath(main);
    fs::create_directories(dropIn.parent_path());
    writeFile(main, "[pam]\noffline_credentials_expiration = 7\n", 0600);
    writeFile(dropIn,
              "# FIC managed configuration\n[pam]\n"
              "offline_credentials_expiration = 30\n",
              0600);
    fic::identity::sssd::SssdConfiguration configuration(
        sssdOptions(main, root));
    auto prepared = configuration.prepareManagedSnippetRemoval(
        "pam", "offline_credentials_expiration");
    require(prepared.ok(), "removal must prepare");
    class SymlinkHook final : public VerifyFailingChange {
    public:
        SymlinkHook(
            std::unique_ptr<fic::identity::PreparedConfigurationChange> inner,
            fs::path path)
            : VerifyFailingChange(std::move(inner)), path_(std::move(path)) {}
        fic::identity::ConfigurationStepResult verifyPersistent() override {
            const fs::path target = path_.string() + ".foreign-target";
            writeFile(target, "foreign target\n", 0600);
            require(::symlink(target.c_str(), path_.c_str()) == 0,
                    "could not create the foreign symlink");
            return VerifyFailingChange::verifyPersistent();
        }

    private:
        fs::path path_;
    };
    std::string error;
    require(!fic::identity::executePreparedFileChange(
                std::make_unique<SymlinkHook>(std::move(prepared.change),
                                              dropIn),
                error),
            "the transaction must fail");
    require(fs::is_symlink(fs::symlink_status(dropIn)),
            "the foreign symlink must survive untouched");
}

void testKerberosNoActiveRecordIsNothingToDo(const fs::path& root) {
    // Regression: a legitimate no-op apply (foreign value already equals the
    // desired value) creates NO journal record; the disable must then be
    // NothingToDo (allowed) and the file must stay byte-for-byte unchanged.
    const fs::path main = root / "system/krb5-noop.conf";
    const std::string original = "[libdefaults]\nticket_lifetime = 36000s\n";
    writeFile(main, original, 0644);
    JournalOverride journalGuard(root / "journals/kerberos-noop.json");
    setPolicyValues(root, "30", "36000");
    {
        KerberosTicketLifetimePolicy policy(kerberosOptions(main, root));
        require(policy.apply(), "the no-op Kerberos apply must succeed");
    }
    require(activeRecordCount(kKerberosPolicyRef) == 0,
            "a no-op apply must not create a journal record");
    const auto report = fic::rollback::rollbackPolicyBeforeDisable(
        kKerberosPolicyRef, kKerberosResource,
        kerberosExecutorDeps(kerberosOptions(main, root)));
    require(report.status == fic::rollback::RollbackStatus::NothingToDo,
            "no active record means FIC owns nothing: NothingToDo, got: " +
                report.message);
    require(report.rollbackCompleted(),
            "the disable must be allowed without active records");
    require(readFile(main) == original,
            "the foreign Kerberos profile must stay byte-for-byte unchanged");
}

void testKerberosRetryAfterCompletedRollbackIsNothingToDo(
    const fs::path& root) {
    // Regression: rollback completed and the journal record is RolledBack,
    // but the crash happened BEFORE the policy status update. The repeated
    // disable must be NothingToDo (allowed) and the restored 8h must stay
    // byte-exact.
    const fs::path main = root / "system/krb5-retry.conf";
    const std::string original = "[libdefaults]\nticket_lifetime = 8h\n";
    writeFile(main, original, 0644);
    JournalOverride journalGuard(root / "journals/kerberos-retry.json");
    setPolicyValues(root, "30", "36000");
    {
        KerberosTicketLifetimePolicy policy(kerberosOptions(main, root));
        require(policy.apply(), "Kerberos apply failed");
    }
    const auto first = fic::rollback::rollbackPolicyBeforeDisable(
        kKerberosPolicyRef, kKerberosResource,
        kerberosExecutorDeps(kerberosOptions(main, root)));
    require(first.rollbackCompleted(), "the first rollback must succeed");
    require(readFile(main) == original, "the 8h line must be restored");
    const auto second = fic::rollback::rollbackPolicyBeforeDisable(
        kKerberosPolicyRef, kKerberosResource,
        kerberosExecutorDeps(kerberosOptions(main, root)));
    require(second.status == fic::rollback::RollbackStatus::NothingToDo,
            "the repeated disable must be NothingToDo, got: " +
                second.message);
    require(second.rollbackCompleted(),
            "the repeated disable must be allowed");
    require(readFile(main) == original,
            "the 8h value must be preserved byte-exact");
}

void testKerberosPreparedCrashRecoveryCompletesApplied(const fs::path& root) {
    // Regression: Prepared journal + krb5.conf already carries the applied
    // value + crash before the journal commit. A daemon-style journal reopen
    // + same-value apply must perform the full fresh graph proof and promote
    // the SAME MutationId Prepared -> Applied.
    const fs::path main = root / "system/krb5-prepared-recovery.conf";
    writeFile(main, "[libdefaults]\nticket_lifetime = 36000s\n", 0644);
    const fs::path journalPath =
        root / "journals/kerberos-prepared-recovery.json";
    JournalOverride journalGuard(journalPath);
    setPolicyValues(root, "30", "36000");
    fic::rollback::MutationId id = 0;
    std::string error;
    require(fic::rollback::recordPreparedMutation(
                kKerberosPolicyRef, kKerberosResource,
                fic::rollback::UndoAction{
                    fic::rollback::MutationBackend::Kerberos,
                    fic::rollback::UndoRestoreKerberosScalar{
                        "libdefaults", "ticket_lifetime", "36000s",
                        fic::rollback::KerberosBeforeKind::Missing, "",
                        false}},
                id, error),
            error);
    const auto& recordBefore = singleActiveRecord(kKerberosPolicyRef);
    require(recordBefore.status == fic::rollback::MutationStatus::Prepared,
            "the crash-window record must be Prepared");
    const auto idBefore = recordBefore.id;
    {
        JournalOverride reopenGuard(journalPath);
        setPolicyValues(root, "30", "36000");
        KerberosTicketLifetimePolicy policy(kerberosOptions(main, root));
        require(policy.apply(), "the recovery apply must succeed");
        const auto& record = singleActiveRecord(kKerberosPolicyRef);
        require(record.id == idBefore,
                "recovery must reuse the SAME MutationId");
        require(record.status == fic::rollback::MutationStatus::Applied,
                "the SAME record must become Applied");
        require(readFile(main) == "[libdefaults]\nticket_lifetime = 36000s\n",
                "the profile must keep the applied value");
        require(activeRecordCount(kKerberosPolicyRef) == 1,
                "exactly one active record after recovery");
    }
}

void testKerberosAppliedSameValueStaysApplied(const fs::path& root) {
    // Regression: a same-value re-apply under an Applied record keeps the
    // existing idempotency (no status transition, no duplicate provenance).
    const fs::path main = root / "system/krb5-applied-same.conf";
    writeFile(main, "[libdefaults]\nticket_lifetime = 8h\n", 0644);
    JournalOverride journalGuard(root / "journals/kerberos-applied-same.json");
    setPolicyValues(root, "30", "36000");
    KerberosTicketLifetimePolicy policy(kerberosOptions(main, root));
    require(policy.apply(), "the first apply must succeed");
    const auto& record = singleActiveRecord(kKerberosPolicyRef);
    require(record.status == fic::rollback::MutationStatus::Applied,
            "the first apply must commit Applied");
    const auto id = record.id;
    require(policy.apply(), "the same-value re-apply must succeed");
    const auto& recordAfter = singleActiveRecord(kKerberosPolicyRef);
    require(recordAfter.id == id,
            "the same-value re-apply must not create new provenance");
    require(recordAfter.status == fic::rollback::MutationStatus::Applied,
            "the Applied record must stay Applied");
}

void testKerberosReusedDriftAfterProofSurvives(const fs::path& root) {
    const fs::path main = root / "system/krb5-reused-drift.conf";
    writeFile(main, "[libdefaults]\nticket_lifetime = 8h\n", 0644);
    JournalOverride guard(root / "journals/krb5-reused-drift.json");
    setPolicyValues(root, "30", "36000");
    KerberosTicketLifetimePolicy policy(kerberosOptions(main, root));
    require(policy.apply(), "initial Kerberos apply must succeed");
    const std::string foreign =
        "[libdefaults]\nticket_lifetime = 40h\n";
    KerberosTicketLifetimePolicy::setReusedProofHookForTests(
        [&]() { writeFile(main, foreign, 0644); });
    const bool applied = policy.apply();
    KerberosTicketLifetimePolicy::setReusedProofHookForTests(nullptr);
    require(!applied, "post-proof drift must fail reused apply closed");
    require(readFile(main) == foreign,
            "reused apply must not overwrite foreign Kerberos edit");
    require(activeRecordCount(kKerberosPolicyRef) == 1,
            "drift must retain Kerberos provenance");
}

void testKerberosPreparedPromotionCannotOverwriteDrift(
    const fs::path& root) {
    const fs::path main = root / "system/krb5-prepared-reused-drift.conf";
    writeFile(main, "[libdefaults]\nticket_lifetime = 36000s\n", 0644);
    JournalOverride guard(root / "journals/krb5-prepared-reused-drift.json");
    fic::rollback::MutationId id = 0;
    std::string error;
    require(fic::rollback::recordPreparedMutation(
                kKerberosPolicyRef, kKerberosResource,
                fic::rollback::UndoAction{
                    fic::rollback::MutationBackend::Kerberos,
                    fic::rollback::UndoRestoreKerberosScalar{
                        "libdefaults", "ticket_lifetime", "36000s",
                        fic::rollback::KerberosBeforeKind::Present,
                        "ticket_lifetime = 8h", true}},
                id, error), error);
    setPolicyValues(root, "30", "36000");
    const std::string foreign =
        "[libdefaults]\nticket_lifetime = 40h\n";
    KerberosTicketLifetimePolicy::setReusedProofHookForTests(
        [&]() { writeFile(main, foreign, 0644); });
    KerberosTicketLifetimePolicy policy(kerberosOptions(main, root));
    const bool applied = policy.apply();
    KerberosTicketLifetimePolicy::setReusedProofHookForTests(nullptr);
    require(!applied, "post-promotion drift must fail apply closed");
    require(readFile(main) == foreign,
            "Prepared promotion must not authorize a second writer");
    const auto& record = singleActiveRecord(kKerberosPolicyRef);
    require(record.id == id &&
                record.status == fic::rollback::MutationStatus::Applied,
            "Prepared should be promoted only by its first AFTER proof");
}

void testKerberosRollbackFailedIsNotPromoted(const fs::path& root) {
    // Regression: a RollbackFailed record is never silently promoted to
    // Applied. A same-value apply must fail closed and keep the record
    // exactly as it is.
    const fs::path main = root / "system/krb5-rollback-failed.conf";
    writeFile(main, "[libdefaults]\nticket_lifetime = 36000s\n", 0644);
    const fs::path journalPath = root / "journals/kerberos-rf.json";
    JournalOverride journalGuard(journalPath);
    setPolicyValues(root, "30", "36000");
    fic::rollback::MutationId id = 0;
    std::string error;
    require(fic::rollback::recordPreparedMutation(
                kKerberosPolicyRef, kKerberosResource,
                fic::rollback::UndoAction{
                    fic::rollback::MutationBackend::Kerberos,
                    fic::rollback::UndoRestoreKerberosScalar{
                        "libdefaults", "ticket_lifetime", "36000s",
                        fic::rollback::KerberosBeforeKind::Present,
                        "ticket_lifetime = 8h", true}},
                id, error),
            error);
    require(fic::rollback::commitMutation(id, error), error);
    {
        auto* journal =
            fic::rollback::DaemonMutationJournal::instance().tryGet(error);
        require(journal != nullptr, "journal must be usable");
        require(journal->setStatus(
                    id, fic::rollback::MutationStatus::RollbackFailed, error),
                error);
    }
    const auto& record = singleActiveRecord(kKerberosPolicyRef);
    require(record.status == fic::rollback::MutationStatus::RollbackFailed,
            "the record must be RollbackFailed");
    require(record.id == id, "the record id must match");
    {
        JournalOverride reopenGuard(journalPath);
        setPolicyValues(root, "30", "36000");
        KerberosTicketLifetimePolicy policy(kerberosOptions(main, root));
        require(!policy.apply(),
                "a same-value apply must fail closed on RollbackFailed");
        const auto& recordAfter = singleActiveRecord(kKerberosPolicyRef);
        require(recordAfter.id == id,
                "the RollbackFailed record must stay the same record");
        require(recordAfter.status ==
                    fic::rollback::MutationStatus::RollbackFailed,
                "the record must stay RollbackFailed (never promoted)");
        require(readFile(main) == "[libdefaults]\nticket_lifetime = 36000s\n",
                "the failed apply must not mutate the file");
    }
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
        testSssdRollbackRetryCompletesRuntimeReconciliation(root);
        testSssdPreparedCrashRecoveryCompletesApplied(root);
        testSssdApplyAbsentSourceReconcilesRuntime(root);
        testSssdForeignReplacementBetweenProofAndRemovalSurvives(root);
        testSssdDoubleReplacementPreservesBothForeignObjects(root);
        testSssdForeignRestoreFsyncFailureKeepsProvenance(root);
        testSssdStagingCollisionDoesNotReplaceObject(root);
        testSssdReusedDriftAfterProofSurvives(root);
        testSssdCompensationRecreateOnlyOnProvenMissing(root);
        testSssdRemovalAndCompensationDurability(root);
        testSssdRemovalFsyncFailureKeepsJournalActive(root);
        testSssdCompensationNeverOverwritesForeignFile(root);
        testSssdCompensationRefusesUnsafeTarget(root);
        testSssdDisableRollsBackManagedSetting(root);
        testSssdOriginalTargetMissingRollback(root);
        testSssdDoesNotStartInactiveService(root);
        testSssdExternalDriftConflict(root);
        testSssdConflictingLaterSnippetFailsApply(root);
        testSssdActiveValueChangeKeepsSingleRecord(root);
        testSssdRestartLikeJournalReloadKeepsRollback(root);
        testKerberosTicketLifetimePolicy(root);
        testKerberosNoActiveRecordIsNothingToDo(root);
        testKerberosRetryAfterCompletedRollbackIsNothingToDo(root);
        testKerberosPreparedCrashRecoveryCompletesApplied(root);
        testKerberosAppliedSameValueStaysApplied(root);
        testKerberosReusedDriftAfterProofSurvives(root);
        testKerberosPreparedPromotionCannotOverwriteDrift(root);
        testKerberosRollbackFailedIsNotPromoted(root);
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
