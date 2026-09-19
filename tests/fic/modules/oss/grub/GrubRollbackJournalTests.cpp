#include "modules/oss/grub/Grub.h"
#include "modules/oss/grub/GrubConfiguration.h"
#include "modules/oss/grub/GrubManagedBlock.h"
#include "modules/oss/grub/GrubManagedConfig.h"
#include "modules/oss/grub/GrubRollback.h"
#include "platform/PlatformExecutableResolver.h"
#include "rollback/DaemonMutationJournal.h"
#include "rollback/MutationJournal.h"

#include <fic/core/integrity/CommandHashStore.h>
#include <fic/core/runtime/FicRuntimePaths.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;
namespace rollback = fic::rollback;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void writeFile(const fs::path& path,
               const std::string& content,
               mode_t mode = 0644) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(output.is_open(), "could not write " + path.string());
    output << content;
    output.close();
    require(::chmod(path.c_str(), mode) == 0,
            "could not chmod " + path.string());
}

std::string readFile(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    require(input.is_open(), "could not read " + path.string());
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
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
        paths.configDir / "AUDIT.conf",
        "_schema_version=1\n"
        "log_level.status=ENABLE\n"
        "log_level.value=ERROR\n");

    std::string error;
    require(fic::core::FicRuntimePaths::initialize(paths, error), error);
    rollback::DaemonMutationJournal::instance().setOverridePath(
        root / "data" / "mutation-journal.json");
}

class JournalOverride {
public:
    explicit JournalOverride(fs::path path)
        : path_(std::move(path)) {
        fs::create_directories(path_.parent_path());
        rollback::DaemonMutationJournal::instance().setOverridePath(path_);
    }

    ~JournalOverride() {
        rollback::DaemonMutationJournal::instance().resetOverride();
    }

private:
    fs::path path_;
};

rollback::MutationJournal* testJournal() {
    std::string error;
    auto* journal = rollback::DaemonMutationJournal::instance().tryGet(error);
    require(journal != nullptr, error);
    return journal;
}

fic::platform::PlatformExecutableResolver makeResolver(
    const fs::path& executable) {
    fic::platform::PlatformExecutables executables;
    executables.entries.push_back(
        {fic::platform::ExecutableId::UpdateGrub, {executable}});
    fic::platform::PlatformExecutableResolverOptions options;
    options.enforceTrustedOwnership = false;
    return fic::platform::PlatformExecutableResolver(
        std::move(executables), options);
}

ProcessResult successfulProcess() {
    ProcessResult result;
    result.started = true;
    result.exitCode = 0;
    return result;
}

ProcessResult failedProcess(const std::string& error = "injected failure") {
    ProcessResult result;
    result.started = true;
    result.exitCode = 1;
    result.standardError = error;
    return result;
}

GrubCommandRunner countingRebuildRunner(std::size_t& calls) {
    return [&calls](const std::string&, const std::vector<std::string>&,
                    const ProcessOptions&) {
        ++calls;
        return successfulProcess();
    };
}

void setPolicyConfig(const fs::path& root,
                     const std::vector<std::pair<std::string, std::string>>&
                         policies) {
    std::string content = "_schema_version=1\n";
    for (const auto& policy : policies) {
        content += policy.first + ".status=ENABLE\n";
        content += policy.first + ".value=" + policy.second + "\n";
    }
    writeFile(root / "config/OSS.conf", content);
}

fic::platform::GrubPlatformConfig altConfig(const fs::path& shared) {
    fic::platform::GrubPlatformConfig config;
    config.topology =
        fic::platform::GrubConfigTopology::SharedDefaultsFile;
    config.sharedDefaultsPath = shared;
    config.rebuildArguments = {"-o", "/etc/grub.cfg"};
    return config;
}

fic::platform::GrubPlatformConfig debianConfig(const fs::path& managed,
                                               const fs::path& base) {
    fic::platform::GrubPlatformConfig config;
    config.topology =
        fic::platform::GrubConfigTopology::OwnedDefaultsDropIn;
    config.managedConfigPath = managed;
    config.baseDefaultsPath = base;
    return config;
}

class JournalGrubPolicy final : public Grub {
public:
    JournalGrubPolicy(
        fic::platform::GrubPlatformConfig platformConfig,
        const fic::platform::PlatformExecutableResolver& executables,
        std::string key,
        std::string policyName,
        std::vector<std::string> allowedValues =
            std::vector<std::string>{"expected", "0", "5", "quiet"})
        : Grub(std::move(platformConfig), executables, false),
          key_(std::move(key)) {
        this->policyName = std::move(policyName);
        this->policyTypeValue =
            std::make_unique<PossibleListPolicyTypeValue>(allowedValues);
    }

    PolicyRef ref() const { return this->policyRef(); }

private:
    std::string key_;

    bool applyGrub(const std::string& expectedValue) override {
        return this->applyGrubValue(key_, expectedValue);
    }
};

rollback::UndoAction grubUndo(const std::string& key,
                              const std::string& appliedValue) {
    return rollback::UndoAction{
        rollback::MutationBackend::Grub,
        rollback::UndoRemoveGrubManagedSetting{key, appliedValue}};
}

rollback::MutationRecord preparedGrubRecord(
    const PolicyRef& policy,
    const std::string& key,
    const rollback::UndoRemoveGrubManagedSetting& undo) {
    rollback::MutationRecord record;
    record.policy = policy;
    record.resource = key;
    record.undo = rollback::UndoAction{
        rollback::MutationBackend::Grub, undo};
    return record;
}

std::size_t activeCount(const PolicyRef& policy) {
    return testJournal()->activeRecords(policy).size();
}

GrubRollbackOptions rollbackOptions(
    fic::platform::GrubPlatformConfig platform,
    const fic::platform::PlatformExecutableResolver& executables,
    GrubCommandRunner runner = {}) {
    GrubRollbackOptions options;
    options.platform = std::move(platform);
    options.executables = &executables;
    options.enforceOwnership = false;
    options.runner = std::move(runner);
    return options;
}

// Debian managed drop-in location helpers: the grub.d directory must exist
// and be safe before GrubManagedConfig accepts the topology.
fs::path dropInDirectory(const fs::path& testCase) {
    return testCase / "etc/default/grub.d";
}

fs::path dropInPath(const fs::path& testCase) {
    return dropInDirectory(testCase) / "zzzz-fic.cfg";
}

void prepareDebianTopology(const fs::path& testCase,
                           const std::string& baseContent = "GRUB_TIMEOUT=5\n") {
    fs::create_directories(dropInDirectory(testCase));
    writeFile(testCase / "etc/default/grub", baseContent);
}

// ALT apply + journal lifecycle: Prepared -> Applied, idempotent apply
// without a new record, drift fail closed.
void testAltApplyJournalLifecycle(const fs::path& root,
                                  const fs::path& rebuildExecutable) {
    JournalOverride journalOverride(
        root / "alt-lifecycle" / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(rebuildExecutable);
    const fs::path shared = root / "alt-lifecycle/etc/sysconfig/grub2";
    const std::string foreign = "GRUB_TIMEOUT=5\n";
    writeFile(shared, foreign);
    setPolicyConfig(root, {{"grub_test_policy", "expected"}});
    JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                             "grub_test_policy");

    require(policy.apply(), "ALT apply with journal must succeed");
    require(activeCount(policy.ref()) == 1,
            "changed source must create exactly one journal record");
    const std::vector<rollback::MutationRecord> appliedRecords =
        testJournal()->activeRecords(policy.ref());
    const rollback::MutationRecord& record = appliedRecords[0];
    require(record.status == rollback::MutationStatus::Applied &&
                record.resource == "GRUB_TIMEOUT",
            "applied ALT mutation must be journaled as Applied");
    const auto* undo =
        std::get_if<rollback::UndoRemoveGrubManagedSetting>(
            &record.undo.payload);
    require(undo != nullptr && undo->key == "GRUB_TIMEOUT" &&
                undo->appliedValue == "expected" &&
                record.undo.backend == rollback::MutationBackend::Grub,
            "GRUB undo payload must carry key + appliedValue only");
    require(readFile(shared) ==
                foreign + "\n" +
                    "# FIC_GRUB_BLOCK_BEGIN version=1\n"
                    "GRUB_TIMEOUT=\"expected\"\n"
                    "# FIC_GRUB_BLOCK_END\n",
            "ALT apply must append the FIC block to the foreign bytes");

    // Repeated compliant apply: no new records, no source change.
    JournalGrubPolicy repeat(altConfig(shared), resolver, "GRUB_TIMEOUT",
                             "grub_test_policy");
    require(repeat.apply(), "repeated ALT apply must succeed");
    require(activeCount(policy.ref()) == 1,
            "repeated compliant apply must not create new journal records");
    require(readFile(shared).substr(0, foreign.size()) == foreign,
            "foreign bytes must stay byte-exact across applies");

    // Drift: the managed value changed externally -> fail closed.
    writeFile(
        shared,
        foreign +
            "# FIC_GRUB_BLOCK_BEGIN version=1\n"
            "GRUB_TIMEOUT=\"5\"\n"
            "# FIC_GRUB_BLOCK_END\n");
    JournalGrubPolicy drift(altConfig(shared), resolver, "GRUB_TIMEOUT",
                            "grub_test_policy");
    require(!drift.apply(),
            "external managed value drift must fail the apply");
    require(activeCount(policy.ref()) == 1,
            "drift must not resolve the journal record");
}

// P1 regression: an applied policy value of "" is a legitimate durable
// state (grub_cmdline_linux=""). The Applied journal record must carry an
// EMPTY applied value and the record must survive a restart-like reload:
// the loader must not treat an empty applied_value as malformed.
void testEmptyPolicyValueAppliedSurvivesRestartLikeReload(
    const fs::path& root, const fs::path& rebuildExecutable) {
    const fs::path journalPath =
        root / "cmdline-empty" / "data" / "mutation-journal.json";
    JournalOverride journalOverride(journalPath);
    const auto resolver = makeResolver(rebuildExecutable);
    const fs::path shared = root / "cmdline-empty/etc/sysconfig/grub2";
    const std::string foreign = "GRUB_CMDLINE_LINUX=\"$local\"\n";
    writeFile(shared, foreign);
    setPolicyConfig(root, {{"grub_test_policy", ""}});
    JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_CMDLINE_LINUX",
                             "grub_test_policy",
                             std::vector<std::string>{""});

    require(policy.apply(), "apply of an empty policy value must succeed");
    require(activeCount(policy.ref()) == 1,
            "empty-value apply must create exactly one journal record");
    const std::vector<rollback::MutationRecord> appliedRecords =
        testJournal()->activeRecords(policy.ref());
    const rollback::MutationRecord& record = appliedRecords[0];
    require(record.status == rollback::MutationStatus::Applied &&
                record.resource == "GRUB_CMDLINE_LINUX",
            "empty-value apply must be journaled as Applied");
    const auto* undo =
        std::get_if<rollback::UndoRemoveGrubManagedSetting>(
            &record.undo.payload);
    require(undo != nullptr && undo->key == "GRUB_CMDLINE_LINUX" &&
                undo->appliedValue.empty(),
            "the Applied record must carry an EMPTY applied value");
    require(readFile(shared) ==
                foreign + "\n" +
                    "# FIC_GRUB_BLOCK_BEGIN version=1\n"
                    "GRUB_CMDLINE_LINUX=\"\"\n"
                    "# FIC_GRUB_BLOCK_END\n",
            "empty-value apply must write an empty assigned managed value");

    // Restart-like reload, part 1 (raw document): a fresh raw journal
    // object must load the persistent document carrying the empty applied
    // value without failing closed.
    rollback::MutationJournal reloaded(journalPath);
    std::string error;
    require(reloaded.load(error), error);
    require(reloaded.records().size() == 1,
            "empty-value Applied record must survive restart-like reload");
    const rollback::MutationRecord& reloadedRecord = reloaded.records().front();
    require(reloadedRecord.status == rollback::MutationStatus::Applied,
            "reloaded record must keep the Applied status");
    const auto* reloadedUndo =
        std::get_if<rollback::UndoRemoveGrubManagedSetting>(
            &reloadedRecord.undo.payload);
    require(reloadedUndo != nullptr &&
                reloadedUndo->key == "GRUB_CMDLINE_LINUX" &&
                reloadedUndo->appliedValue.empty(),
            "reloaded payload must keep the EMPTY applied value");

    // Restart-like reload, part 2 (production daemon path): CLOSE the
    // singleton journal (setOverridePath resets the cached instance) and
    // reopen the SAME journal file through the production startup path
    // (tryGet -> open -> initializeOrLoad). The record with the EMPTY
    // applied value must survive this real daemon-style reopen and remain
    // the single active record BEFORE the next apply.
    rollback::DaemonMutationJournal::instance().setOverridePath(journalPath);
    rollback::MutationJournal* reopened = testJournal();
    require(reopened != nullptr,
            "daemon-style reopen must produce an operational journal");
    require(reopened->records().size() == 1,
            "daemon-style reopen must see exactly one record");
    const rollback::MutationRecord& reopenedRecord =
        reopened->records().front();
    require(reopenedRecord.status == rollback::MutationStatus::Applied &&
                reopenedRecord.resource == "GRUB_CMDLINE_LINUX",
            "daemon-style reopen must keep the record Applied");
    const auto* reopenedUndo =
        std::get_if<rollback::UndoRemoveGrubManagedSetting>(
            &reopenedRecord.undo.payload);
    require(reopenedUndo != nullptr &&
                reopenedUndo->key == "GRUB_CMDLINE_LINUX" &&
                reopenedUndo->appliedValue.empty(),
            "daemon-style reopen must keep the EMPTY applied value");

    // Repeated apply after the REAL restart: idempotent through the
    // reopened singleton journal, still exactly one record.
    JournalGrubPolicy repeat(altConfig(shared), resolver,
                             "GRUB_CMDLINE_LINUX", "grub_test_policy",
                             std::vector<std::string>{""});
    require(repeat.apply(),
            "repeated empty-value apply after restart must succeed");
    require(activeCount(policy.ref()) == 1,
            "repeated empty-value apply must not create new records");
}

// ALT value change: the old FIC ownership is released through the SAME
// backend operation used by rollback, the old record resolved, then the new
// value applied with a fresh record.
void testAltValueChange(const fs::path& root,
                        const fs::path& rebuildExecutable) {
    JournalOverride journalOverride(
        root / "alt-value-change" / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(rebuildExecutable);
    const fs::path shared = root / "alt-value-change/etc/sysconfig/grub2";
    const std::string foreign = "GRUB_TIMEOUT=5\n";
    writeFile(shared, foreign);
    setPolicyConfig(root, {{"grub_test_policy", "expected"}});
    JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                             "grub_test_policy");
    require(policy.apply(), "initial ALT apply must succeed");

    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    JournalGrubPolicy changed(altConfig(shared), resolver, "GRUB_TIMEOUT",
                              "grub_test_policy");
    require(changed.apply(), "ALT value change apply must succeed");
    require(readFile(shared) ==
                foreign + "\n" +
                    "# FIC_GRUB_BLOCK_BEGIN version=1\n"
                    "GRUB_TIMEOUT=\"0\"\n"
                    "# FIC_GRUB_BLOCK_END\n",
            "value change must rewrite the managed block to the new value");
    const std::vector<rollback::MutationRecord> records =
        testJournal()->activeRecords(policy.ref());
    require(records.size() == 1 &&
                records[0].status == rollback::MutationStatus::Applied,
            "value change must leave exactly one active Applied record");
    const auto* undo =
        std::get_if<rollback::UndoRemoveGrubManagedSetting>(
            &records[0].undo.payload);
    require(undo != nullptr && undo->appliedValue == "0",
            "the active record must fingerprint the NEW applied value");
    require(testJournal()->records().size() == 2,
            "the OLD applied record must be resolved, not rewritten");
}

// Prepared crash recovery (ALT topology), case A: Prepared + source AFTER
// -> rebuild + commit Applied.
void testAltPreparedRecoveryAfter(const fs::path& root,
                                  const fs::path& rebuildExecutable) {
    setPolicyConfig(root, {{"grub_test_policy", "expected"}});
    JournalOverride journalOverride(
        root / "alt-recovery-a" / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(rebuildExecutable);
    const fs::path shared = root / "alt-recovery-a/etc/sysconfig/grub2";
    const std::string foreign = "GRUB_TIMEOUT=5\n";
    writeFile(shared, foreign);
    JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                             "grub_test_policy");
    rollback::MutationId id = 0;
    std::string error;
    rollback::MutationRecord prepared = preparedGrubRecord(
            policy.ref(), "GRUB_TIMEOUT",
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require(testJournal()->prepareMutation(prepared, id, error),
                error);
    writeFile(
        shared,
        foreign +
            "# FIC_GRUB_BLOCK_BEGIN version=1\n"
            "GRUB_TIMEOUT=\"expected\"\n"
            "# FIC_GRUB_BLOCK_END\n");
    require(policy.apply(), "Prepared AFTER recovery apply must succeed");
    const std::vector<rollback::MutationRecord> records =
        testJournal()->activeRecords(policy.ref());
    const rollback::MutationRecord& record = records[0];
    require(record.status == rollback::MutationStatus::Applied,
            "Prepared AFTER must be committed to Applied");
}

// Prepared crash recovery (ALT topology), case B: Prepared + source BEFORE
// (block gone) -> rebuild + discard, then the regular apply installs the
// value with a fresh record.
void testAltPreparedRecoveryBefore(const fs::path& root,
                                   const fs::path& rebuildExecutable) {
    setPolicyConfig(root, {{"grub_test_policy", "expected"}});
    JournalOverride journalOverride(
        root / "alt-recovery-b" / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(rebuildExecutable);
    const fs::path shared = root / "alt-recovery-b/etc/sysconfig/grub2";
    const std::string foreign = "GRUB_TIMEOUT=5\n";
    writeFile(shared, foreign);
    JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                             "grub_test_policy");
    rollback::MutationId id = 0;
    std::string error;
    rollback::MutationRecord prepared = preparedGrubRecord(
            policy.ref(), "GRUB_TIMEOUT",
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require(testJournal()->prepareMutation(prepared, id, error),
                error);
    require(policy.apply(), "Prepared BEFORE recovery apply must succeed");
    require(readFile(shared).find(kGrubBlockBeginMarker) !=
                std::string::npos,
            "regular apply must install the managed block");
    require(activeCount(policy.ref()) == 1 &&
                testJournal()->activeRecords(policy.ref())[0].status ==
                    rollback::MutationStatus::Applied,
            "stale Prepared must be discarded and replaced by the new "
            "Applied record");
}

// Prepared crash recovery (ALT topology), case C: Prepared + source DRIFT
// -> fail closed, the record stays active.
void testAltPreparedRecoveryDrift(const fs::path& root,
                                  const fs::path& rebuildExecutable) {
    setPolicyConfig(root, {{"grub_test_policy", "expected"}});
    JournalOverride journalOverride(
        root / "alt-recovery-c" / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(rebuildExecutable);
    const fs::path shared = root / "alt-recovery-c/etc/sysconfig/grub2";
    const std::string foreign = "GRUB_TIMEOUT=5\n";
    writeFile(shared, foreign);
    JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                             "grub_test_policy");
    rollback::MutationId id = 0;
    std::string error;
    rollback::MutationRecord prepared = preparedGrubRecord(
            policy.ref(), "GRUB_TIMEOUT",
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require(testJournal()->prepareMutation(prepared, id, error),
                error);
    writeFile(
        shared,
        foreign +
            "# FIC_GRUB_BLOCK_BEGIN version=1\n"
            "GRUB_TIMEOUT=\"manual\"\n"
            "# FIC_GRUB_BLOCK_END\n");
    require(!policy.apply(), "Prepared DRIFT must fail closed");
    require(activeCount(policy.ref()) == 1,
            "Prepared DRIFT must keep the record active");
}

// ALT rollback lifecycle via RollbackExecutor: success, missing key ->
// NothingToDo with a mandatory rebuild, concurrent drift -> Conflict with
// the source untouched, crash-after-source-rollback -> one rebuild, and
// multiple policies coexisting in one block.
void testAltRollbackLifecycle(const fs::path& root,
                              const fs::path& rebuildExecutable) {
    const auto resolver = makeResolver(rebuildExecutable);

    // Success: Applied record + matching source -> release + rebuild.
    {
        JournalOverride journalOverride(
            root / "alt-rollback-success" / "data" / "mutation-journal.json");
        const fs::path shared =
            root / "alt-rollback-success/etc/sysconfig/grub2";
        const std::string foreign = "GRUB_DISABLE_RECOVERY=false\n";
        writeFile(shared, foreign);
        JournalGrubPolicy policy(altConfig(shared), resolver,
                                 "GRUB_DISABLE_RECOVERY",
                                 "grub_test_policy");
        rollback::MutationId id = 0;
        std::string error;
        rollback::MutationRecord prepared = preparedGrubRecord(
            policy.ref(), "GRUB_DISABLE_RECOVERY",
            rollback::UndoRemoveGrubManagedSetting{"GRUB_DISABLE_RECOVERY", "true"});
        require(testJournal()->prepareMutation(prepared, id, error),
                error);
        writeFile(shared,
                  foreign + "\n" +
                      "# FIC_GRUB_BLOCK_BEGIN version=1\n"
                      "GRUB_DISABLE_RECOVERY=\"true\"\n"
                      "# FIC_GRUB_BLOCK_END\n");
        std::size_t rebuilds = 0;
        auto options = rollbackOptions(altConfig(shared), resolver,
                                countingRebuildRunner(
                                    rebuilds));
        const auto outcome =
            undoGrubManagedSetting(
            options,
            rollback::UndoRemoveGrubManagedSetting{"GRUB_DISABLE_RECOVERY", "true"});
        require(outcome.ok,
            "ALT rollback of the last FIC key must succeed");
        require(readFile(shared) == foreign,
                "rollback must release FIC ownership byte-exactly");
        require(rebuilds == 1,
                "ALT rollback must run exactly one mandatory rebuild");
    }

    // Missing key: no FIC block at all -> mandatory rebuild + NothingToDo.
    {
        JournalOverride journalOverride(
            root / "alt-rollback-missing" / "data" / "mutation-journal.json");
        const fs::path shared =
            root / "alt-rollback-missing/etc/sysconfig/grub2";
        writeFile(shared, "GRUB_TIMEOUT=5\n");
        JournalGrubPolicy policy(altConfig(shared), resolver,
                                 "GRUB_TIMEOUT", "grub_test_policy");
        rollback::MutationId id = 0;
        std::string error;
        rollback::MutationRecord prepared = preparedGrubRecord(
            policy.ref(), "GRUB_TIMEOUT",
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require(testJournal()->prepareMutation(prepared, id, error),
                error);
        std::size_t rebuilds = 0;
        auto options = rollbackOptions(
            altConfig(shared), resolver, countingRebuildRunner(rebuilds));
        const auto outcome =
            undoGrubManagedSetting(
            options,
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require(outcome.nothingToDo,
                "already-released ALT key must report NothingToDo");
        require(rebuilds == 1,
                "NothingToDo must still run the mandatory rebuild");
    }
}

// ALT rollback after external release / drift: a block without the key is
// NothingToDo (with a mandatory rebuild, foreign bytes untouched); a block
// holding another value under the same key is a fail-closed Conflict.
void testAltRollbackConflict(const fs::path& root,
                             const fs::path& rebuildExecutable) {
    JournalOverride journalOverride(
        root / "alt-rollback-conflict" / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(rebuildExecutable);
    const fs::path shared = root / "alt-rollback-conflict/etc/sysconfig/grub2";
    const std::string foreign = "GRUB_TIMEOUT=5\n";
    writeFile(shared, foreign);
    JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                             "grub_test_policy");
    rollback::MutationId id = 0;
    std::string error;
    rollback::MutationRecord prepared = preparedGrubRecord(
            policy.ref(), "GRUB_TIMEOUT",
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require(testJournal()->prepareMutation(prepared, id, error),
                error);

    // Concurrent release: the key left the FIC block, another policy's key
    // stayed, a foreign assignment reappeared outside the block.
    writeFile(shared,
              foreign +
                  "# FIC_GRUB_BLOCK_BEGIN version=1\n"
                  "GRUB_DISABLE_RECOVERY=\"true\"\n"
                  "# FIC_GRUB_BLOCK_END\n"
                  "GRUB_TIMEOUT=2\n");
    const std::string drifted = readFile(shared);
    std::size_t rebuilds = 0;
    auto options = rollbackOptions(altConfig(shared), resolver,
                                   countingRebuildRunner(rebuilds));
    const auto outcome =
            undoGrubManagedSetting(
            options,
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
    require(outcome.nothingToDo,
            "externally released key must report NothingToDo");
    require(readFile(shared) == drifted,
            "NothingToDo must leave the source file untouched");
    require(rebuilds == 1,
            "NothingToDo must still run the mandatory rebuild");

    // Value drift inside the block: fail-closed Conflict.
    writeFile(shared,
              foreign +
                  "# FIC_GRUB_BLOCK_BEGIN version=1\n"
                  "GRUB_TIMEOUT=\"manual\"\n"
                  "# FIC_GRUB_BLOCK_END\n");
    const std::string conflicted = readFile(shared);
    std::size_t conflictRebuilds = 0;
    auto conflictOptions =
        rollbackOptions(altConfig(shared), resolver,
                        countingRebuildRunner(conflictRebuilds));
    const auto conflictOutcome =
        undoGrubManagedSetting(
            conflictOptions,
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
    require(conflictOutcome.conflict,
            "value drift inside the FIC block must report Conflict");
    require(readFile(shared) == conflicted,
            "Conflict must leave the source file untouched");
    require(conflictRebuilds == 0, "Conflict must not rebuild");
}


// ALT crash-after-source-rollback: the managed value was already removed
// (release done) but the record is still Applied -> recovery through
// apply() must be release-only + a single rebuild, and the record must be
// resolved as RolledBack.
// Fix #4 regression: the ALT idempotent apply path must re-prove the loaded
// snapshot (targetStateMatches) before the mandatory rebuild; an external
// writer racing after load() must fail the apply closed with the external
// bytes preserved and no journal record.
void testAltIdempotentApplyStaleSnapshot(const fs::path& root,
                                         const fs::path& rebuildExecutable) {
    setPolicyConfig(root, {{"grub_test_policy", "expected"}});
    JournalOverride journalOverride(
        root / "alt-idempotent-race" / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(rebuildExecutable);
    const fs::path shared = root / "alt-idempotent-race/etc/sysconfig/grub2";
    const std::string foreign = "GRUB_TIMEOUT=5\n";
    writeFile(shared, foreign);
    JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                             "grub_test_policy");
    require(policy.apply(), "initial apply must succeed");
    require(activeCount(policy.ref()) == 1,
            "the applied mutation must stay active for the idempotent case");
    const std::string external = "EXTERNAL=1\n";
    setGrubPostLoadMutationHookForTests(
        [&shared, &external](const std::string&) {
            writeFile(shared, external);
        });
    require(!policy.apply(),
            "idempotent apply after external replacement must fail closed");
    require(readFile(shared) == external,
            "the external write must survive the failed idempotent apply "
            "byte-exact");
    require(activeCount(policy.ref()) == 1,
            "the idempotent ownership proof must not resolve the record");
}

void testAltCrashAfterSourceRollback(const fs::path& root,
                                     const fs::path& rebuildExecutable) {
    JournalOverride journalOverride(
        root / "alt-crash-after-rollback" / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(rebuildExecutable);
    const fs::path shared =
        root / "alt-crash-after-rollback/etc/sysconfig/grub2";
    const std::string foreign = "GRUB_TIMEOUT=5\n";
    writeFile(shared, foreign);
    JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                             "grub_test_policy");
    require(policy.apply(), "initial apply must succeed");
    // Simulate a crash after the source release but before record resolution.
    writeFile(shared, foreign);
    std::size_t rebuilds = 0;
    auto options = rollbackOptions(altConfig(shared), resolver,
                                   countingRebuildRunner(rebuilds));
    const auto outcome =
            undoGrubManagedSetting(
            options,
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
    require(outcome.nothingToDo,
            "completed source release must report NothingToDo");
    require(rebuilds == 1,
            "crash recovery must run exactly one rebuild");
}


// Debian apply + journal lifecycle: drop-in creation is journaled as
// Applied; idempotent apply adds no records.
void testDebianApplyJournalLifecycle(const fs::path& root,
                                     const fs::path& rebuildExecutable) {
    JournalOverride journalOverride(
        root / "deb-lifecycle" / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(rebuildExecutable);
    const fs::path testCase = root / "deb-lifecycle";
    const fs::path managed = dropInPath(testCase);
    prepareDebianTopology(testCase);
    setPolicyConfig(root, {{"grub_test_policy", "expected"}});
    JournalGrubPolicy policy(debianConfig(managed, testCase / "etc/default/grub"), resolver,
                             "GRUB_TIMEOUT", "grub_test_policy");
    require(policy.apply(), "Debian apply with journal must succeed");
    require(activeCount(policy.ref()) == 1,
            "Debian drop-in creation must create one journal record");
    const std::vector<rollback::MutationRecord> records =
        testJournal()->activeRecords(policy.ref());
    const rollback::MutationRecord& record = records[0];
    require(record.status == rollback::MutationStatus::Applied &&
                record.resource == "GRUB_TIMEOUT",
            "Debian apply must be journaled as Applied");
    require(readFile(managed) ==
                "# Managed by FIC. Do not edit.\n\n"
                "GRUB_TIMEOUT=\"expected\"\n",
            "Debian drop-in must use the canonical managed format");

    JournalGrubPolicy repeat(debianConfig(managed, testCase / "etc/default/grub"), resolver,
                             "GRUB_TIMEOUT", "grub_test_policy");
    require(repeat.apply(), "repeated Debian apply must succeed");
    require(activeCount(policy.ref()) == 1,
            "repeated compliant Debian apply must not create records");
    require(readFile(managed) ==
                "# Managed by FIC. Do not edit.\n\n"
                "GRUB_TIMEOUT=\"expected\"\n",
            "repeated apply must keep the canonical drop-in content");
}

// Debian prepared crash recovery: AFTER commits, missing drop-in (BEFORE)
// reconciles and discards, value drift fails closed.
void testDebianPreparedRecovery(const fs::path& root,
                                const fs::path& rebuildExecutable) {
    setPolicyConfig(root, {{"grub_test_policy", "expected"}});
    const auto resolver = makeResolver(rebuildExecutable);
    const std::string expectedDropIn =
        "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"expected\"\n";

    // A: Prepared + drop-in AFTER -> rebuild + commit Applied.
    {
        JournalOverride journalOverride(
            root / "deb-recovery-a" / "data" / "mutation-journal.json");
        const fs::path testCase = root / "deb-recovery-a";
            const fs::path managed = dropInPath(testCase);
            prepareDebianTopology(testCase);
        writeFile(managed, expectedDropIn);
        JournalGrubPolicy policy(debianConfig(managed, testCase / "etc/default/grub"), resolver,
                                 "GRUB_TIMEOUT", "grub_test_policy");
        rollback::MutationId id = 0;
        std::string error;
        rollback::MutationRecord prepared = preparedGrubRecord(
            policy.ref(), "GRUB_TIMEOUT",
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require(testJournal()->prepareMutation(prepared, id, error),
                error);
        require(policy.apply(), "Debian Prepared AFTER must recover");
        require(testJournal()->activeRecords(policy.ref())[0].status ==
                    rollback::MutationStatus::Applied,
                "Debian Prepared AFTER must be committed to Applied");
    }

    // B: Prepared + missing drop-in (BEFORE) -> discard + fresh install.
    {
        JournalOverride journalOverride(
            root / "deb-recovery-b" / "data" / "mutation-journal.json");
        const fs::path testCase = root / "deb-recovery-b";
            const fs::path managed = dropInPath(testCase);
            prepareDebianTopology(testCase);
        JournalGrubPolicy policy(debianConfig(managed, testCase / "etc/default/grub"), resolver,
                                 "GRUB_TIMEOUT", "grub_test_policy");
        rollback::MutationId id = 0;
        std::string error;
        rollback::MutationRecord prepared = preparedGrubRecord(
            policy.ref(), "GRUB_TIMEOUT",
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require(testJournal()->prepareMutation(prepared, id, error),
                error);
        require(policy.apply(), "Debian Prepared BEFORE must recover");
        require(readFile(managed) == expectedDropIn,
                "regular apply must install the managed drop-in");
        require(activeCount(policy.ref()) == 1 &&
                    testJournal()->activeRecords(policy.ref())[0].status ==
                        rollback::MutationStatus::Applied,
                "stale Prepared must be discarded and replaced");
    }

    // C: Prepared + external value drift -> fail closed.
    {
        JournalOverride journalOverride(
            root / "deb-recovery-c" / "data" / "mutation-journal.json");
        const fs::path testCase = root / "deb-recovery-c";
            const fs::path managed = dropInPath(testCase);
            prepareDebianTopology(testCase);
        writeFile(managed,
                  "# Managed by FIC. Do not edit.\n\n"
                  "GRUB_TIMEOUT=\"manual\"\n");
        JournalGrubPolicy policy(debianConfig(managed, testCase / "etc/default/grub"), resolver,
                                 "GRUB_TIMEOUT", "grub_test_policy");
        rollback::MutationId id = 0;
        std::string error;
        rollback::MutationRecord prepared = preparedGrubRecord(
            policy.ref(), "GRUB_TIMEOUT",
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require(testJournal()->prepareMutation(prepared, id, error),
                error);
        require(!policy.apply(), "Debian Prepared DRIFT must fail closed");
        require(activeCount(policy.ref()) == 1,
                "Debian Prepared DRIFT must keep the record active");
    }
}


// Debian rollback lifecycle via GrubRollback: success with drop-in removal,
// multi-key coexistence, missing drop-in -> NothingToDo with rebuild,
// value drift -> Conflict with the source untouched.
void testDebianRollbackLifecycle(const fs::path& root,
                                 const fs::path& rebuildExecutable) {
    const auto resolver = makeResolver(rebuildExecutable);
    const fs::path baseTemplate = root / "deb-base/grub";
    writeFile(baseTemplate, "GRUB_TIMEOUT=5\n");

    // Success: the last FIC key is removed and the canonical header-only
    // empty drop-in is retained (no unlink race).
    {
        JournalOverride journalOverride(
            root / "deb-rollback-success" / "data" / "mutation-journal.json");
        const fs::path testCase = root / "deb-rollback-success";
            const fs::path managed = dropInPath(testCase);
            prepareDebianTopology(testCase);
        writeFile(managed,
                  "# Managed by FIC. Do not edit.\n\n"
                  "GRUB_TIMEOUT=\"expected\"\n");
        JournalGrubPolicy policy(debianConfig(managed, baseTemplate),
                                 resolver, "GRUB_TIMEOUT",
                                 "grub_test_policy");
        rollback::MutationId id = 0;
        std::string error;
        rollback::MutationRecord prepared = preparedGrubRecord(
            policy.ref(), "GRUB_TIMEOUT",
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require(testJournal()->prepareMutation(prepared, id, error),
                error);
        std::size_t rebuilds = 0;
        auto options = rollbackOptions(debianConfig(managed, baseTemplate),
                                       resolver,
                                       countingRebuildRunner(rebuilds));
        const auto outcome =
            undoGrubManagedSetting(
            options,
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require(outcome.ok,
                "Debian rollback of the last FIC key must succeed");
        require(fs::exists(managed),
                "the canonical empty drop-in must be retained");
        require(readFile(managed) == "# Managed by FIC. Do not edit.\n\n",
                "the retained empty drop-in must be the canonical header-only "
                "form");
        require(rebuilds == 1,
                "Debian rollback must run exactly one mandatory rebuild");
    }

    // Multi-key: rolling back one key keeps the other policy's entry.
    {
        JournalOverride journalOverride(
            root / "deb-rollback-multi" / "data" / "mutation-journal.json");
        const fs::path testCase = root / "deb-rollback-multi";
            const fs::path managed = dropInPath(testCase);
            prepareDebianTopology(testCase);
        writeFile(managed,
                  "# Managed by FIC. Do not edit.\n\n"
                  "GRUB_DISABLE_RECOVERY=\"true\"\n"
                  "GRUB_TIMEOUT=\"expected\"\n");
        JournalGrubPolicy policy(debianConfig(managed, baseTemplate),
                                 resolver, "GRUB_TIMEOUT",
                                 "grub_test_policy");
        rollback::MutationId id = 0;
        std::string error;
        rollback::MutationRecord prepared = preparedGrubRecord(
            policy.ref(), "GRUB_TIMEOUT",
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require(testJournal()->prepareMutation(prepared, id, error),
                error);
        auto options = rollbackOptions(debianConfig(managed, baseTemplate),
                                       resolver);
        const auto outcome =
            undoGrubManagedSetting(
            options,
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require(outcome.ok,
                "Debian rollback of one key among several must succeed");
        require(readFile(managed) ==
                    "# Managed by FIC. Do not edit.\n\n"
                    "GRUB_DISABLE_RECOVERY=\"true\"\n",
                "the other policy's entry must stay in the drop-in");
    }
}


// Debian rollback: missing artifact -> NothingToDo with a mandatory
// rebuild; value drift -> Conflict with no rebuild and no source change.
void testDebianRollbackNothingToDoAndConflict(
    const fs::path& root, const fs::path& rebuildExecutable) {
    const auto resolver = makeResolver(rebuildExecutable);
    const fs::path baseTemplate = root / "deb-base/grub";

    // Missing drop-in -> NothingToDo + rebuild.
    {
        JournalOverride journalOverride(
            root / "deb-rollback-missing" / "data" / "mutation-journal.json");
        const fs::path testCase = root / "deb-rollback-missing";
            const fs::path managed = dropInPath(testCase);
            prepareDebianTopology(testCase);
        JournalGrubPolicy policy(debianConfig(managed, baseTemplate),
                                 resolver, "GRUB_TIMEOUT",
                                 "grub_test_policy");
        rollback::MutationId id = 0;
        std::string error;
        rollback::MutationRecord prepared = preparedGrubRecord(
            policy.ref(), "GRUB_TIMEOUT",
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require(testJournal()->prepareMutation(prepared, id, error),
                error);
        std::size_t rebuilds = 0;
        auto options = rollbackOptions(debianConfig(managed, baseTemplate),
                                       resolver,
                                       countingRebuildRunner(rebuilds));
        const auto outcome =
            undoGrubManagedSetting(
            options,
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require(outcome.nothingToDo,
                "missing Debian drop-in must report NothingToDo");
        require(rebuilds == 1,
                "NothingToDo must still run the mandatory rebuild");
    }

    // Value drift -> Conflict, source untouched, no rebuild.
    {
        JournalOverride journalOverride(
            root / "deb-rollback-conflict" / "data" / "mutation-journal.json");
        const fs::path testCase = root / "deb-rollback-conflict";
            const fs::path managed = dropInPath(testCase);
            prepareDebianTopology(testCase);
        writeFile(managed,
                  "# Managed by FIC. Do not edit.\n\n"
                  "GRUB_TIMEOUT=\"manual\"\n");
        JournalGrubPolicy policy(debianConfig(managed, baseTemplate),
                                 resolver, "GRUB_TIMEOUT",
                                 "grub_test_policy");
        rollback::MutationId id = 0;
        std::string error;
        rollback::MutationRecord prepared = preparedGrubRecord(
            policy.ref(), "GRUB_TIMEOUT",
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require(testJournal()->prepareMutation(prepared, id, error),
                error);
        std::size_t rebuilds = 0;
        auto options = rollbackOptions(debianConfig(managed, baseTemplate),
                                       resolver,
                                       countingRebuildRunner(rebuilds));
        const auto outcome =
            undoGrubManagedSetting(
            options,
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require(outcome.conflict,
                "Debian value drift must report Conflict");
        require(readFile(managed) ==
                    "# Managed by FIC. Do not edit.\n\n"
                    "GRUB_TIMEOUT=\"manual\"\n",
                "Conflict must leave the drop-in untouched");
        require(rebuilds == 0, "Conflict must not rebuild");
    }
}


// Rebuild failure during rollback: the source is compensated back to the
// pre-rollback FIC-owned state, a compensation rebuild is attempted, and
// the failure is reported (journal stays active via the executor).
void testRollbackRebuildFailureCompensation(
    const fs::path& root, const fs::path& rebuildExecutable) {
    const auto resolver = makeResolver(rebuildExecutable);
    const fs::path baseTemplate = root / "deb-base/grub";

    // ALT topology: block restored byte-exactly after failed rebuild.
    {
        JournalOverride journalOverride(
            root / "alt-rebuild-failure" / "data" / "mutation-journal.json");
        const fs::path shared =
            root / "alt-rebuild-failure/etc/sysconfig/grub2";
        const std::string foreign = "GRUB_TIMEOUT=5\n";
        const std::string owned = foreign +
            "# FIC_GRUB_BLOCK_BEGIN version=1\n"
            "GRUB_TIMEOUT=\"expected\"\n"
            "# FIC_GRUB_BLOCK_END\n";
        writeFile(shared, owned);
        JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                                 "grub_test_policy");
        rollback::MutationId id = 0;
        std::string error;
        rollback::MutationRecord prepared = preparedGrubRecord(
            policy.ref(), "GRUB_TIMEOUT",
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require(testJournal()->prepareMutation(prepared, id, error),
                error);
        std::size_t rebuilds = 0;
        GrubCommandRunner failingRunner =
            [&rebuilds](const std::string&, const std::vector<std::string>&,
                        const ProcessOptions&) {
                ++rebuilds;
                return failedProcess();
            };
        auto options =
            rollbackOptions(altConfig(shared), resolver, failingRunner);
        const auto outcome =
            undoGrubManagedSetting(
            options,
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require((!outcome.ok && !outcome.conflict && !outcome.nothingToDo),
                "failed ALT rebuild must report Failure");
        require(readFile(shared) == owned,
                "ALT compensation must restore the pre-rollback FIC block");
        require(rebuilds == 2,
                "ALT rollback must attempt the compensation rebuild");
    }

    // Debian topology: drop-in restored after failed rebuild.
    {
        JournalOverride journalOverride(
            root / "deb-rebuild-failure" / "data" / "mutation-journal.json");
        const fs::path testCase = root / "deb-rebuild-failure";
            const fs::path managed = dropInPath(testCase);
            prepareDebianTopology(testCase);
        const std::string owned =
            "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"expected\"\n";
        writeFile(managed, owned);
        JournalGrubPolicy policy(debianConfig(managed, baseTemplate),
                                 resolver, "GRUB_TIMEOUT",
                                 "grub_test_policy");
        rollback::MutationId id = 0;
        std::string error;
        rollback::MutationRecord prepared = preparedGrubRecord(
            policy.ref(), "GRUB_TIMEOUT",
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require(testJournal()->prepareMutation(prepared, id, error),
                error);
        std::size_t rebuilds = 0;
        GrubCommandRunner failingRunner =
            [&rebuilds](const std::string&, const std::vector<std::string>&,
                        const ProcessOptions&) {
                ++rebuilds;
                return failedProcess();
            };
        auto options =
            rollbackOptions(debianConfig(managed, baseTemplate), resolver,
                            failingRunner);
        const auto outcome =
            undoGrubManagedSetting(
            options,
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
        require((!outcome.ok && !outcome.conflict && !outcome.nothingToDo),
                "failed Debian rebuild must report Failure");
        require(readFile(managed) == owned,
                "Debian compensation must restore the managed drop-in");
        require(rebuilds == 2,
                "Debian rollback must attempt the compensation rebuild");
    }
}

// Writes a custom rebuild script and seeds its sha256 into the command
// hash store (the store file is plain text; saveHash() cannot be used in
// the unit-test environment because of its root-ownership requirements).
void seedRebuildExecutable(const fs::path& root,
                           const fs::path& script,
                           const std::string& content) {
    writeFile(script, content, 0755);
    const fs::path digestFile = root / "data/last-digest.txt";
    const std::string command =
        "sha256sum " + script.string() + " > " + digestFile.string();
    require(std::system(command.c_str()) == 0,
            "sha256sum must be available for the GRUB journal tests");
    const std::string digestLine = readFile(digestFile);
    require(digestLine.size() >= 64 && digestLine[64] == ' ',
            "unexpected sha256sum output for " + script.string());
    std::ofstream hashFile(root / "data/commandhash.txt",
                           std::ios::binary | std::ios::app);
    require(hashFile.is_open(), "could not append to commandhash.txt");
    hashFile << script.string() << "=" << digestLine.substr(0, 64) << "\n";
}

// A: journal reconciliation with UNSAFE base defaults (P0): the mandatory
// rebuild never runs, the journal record is not resolved and the managed
// source is untouched — for a symlinked base defaults file and for a
// group/world-writable base defaults file.
void testDebianReconciliationUnsafeBaseDefaults(
    const fs::path& root, const fs::path&) {
    setPolicyConfig(root, {{"grub_test_policy", "expected"}});
    const fs::path marker = root / "rebuild-marker.log";
    const fs::path markerScript = root / "bin/update-grub-marker";
    seedRebuildExecutable(
        root, markerScript,
        "#!/bin/sh\necho called >> " + marker.string() + "\nexit 0\n");
    const auto markerResolver = makeResolver(markerScript);

    const auto runCase = [&](const fs::path& testCase,
                             const std::function<void(const fs::path&)>&
                                 prepareBase,
                             const std::string& description) {
        JournalOverride journalOverride(
            testCase / "data" / "mutation-journal.json");
        fs::create_directories(dropInDirectory(testCase));
        prepareBase(testCase);
        const fs::path managed = dropInPath(testCase);
        const std::string owned =
            "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"expected\"\n";
        writeFile(managed, owned);
        JournalGrubPolicy policy(
            debianConfig(managed, testCase / "etc/default/grub"),
            markerResolver, "GRUB_TIMEOUT", "grub_test_policy");
        rollback::MutationId id = 0;
        std::string error;
        rollback::MutationRecord prepared = preparedGrubRecord(
            policy.ref(), "GRUB_TIMEOUT",
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT",
                                                   "expected"});
        require(testJournal()->prepareMutation(prepared, id, error), error);

        require(!policy.apply(),
                description + " must fail the reconciliation apply");
        require(!fs::exists(marker),
                description + " must not run the mandatory rebuild");
        require(activeCount(policy.ref()) == 1,
                description + " must not resolve the journal record");
        const std::vector<rollback::MutationRecord> records =
            testJournal()->activeRecords(policy.ref());
        require(records[0].status == rollback::MutationStatus::Prepared,
                description + " must leave the record Prepared");
        require(readFile(managed) == owned,
                description + " must not touch the managed source");
    };

    runCase(
        root / "deb-reconcile-symlink-base",
        [](const fs::path& testCase) {
            writeFile(testCase / "base-target", "GRUB_TIMEOUT=5\n");
            fs::create_symlink(testCase / "base-target",
                               testCase / "etc/default/grub");
        },
        "a symlinked base defaults file");
    runCase(
        root / "deb-reconcile-writable-base",
        [](const fs::path& testCase) {
            writeFile(testCase / "etc/default/grub", "GRUB_TIMEOUT=5\n",
                      0666);
        },
        "a group/world-writable base defaults file");
}

// B: ALT apply stale-read race (single-snapshot CAS): an external writer
// racing between the FIC snapshot and the atomic CAS write must fail the
// apply, keep the external bytes byte-exact and leave the journal empty.
void testAltApplyStaleReadCasRace(const fs::path& root,
                                  const fs::path& rebuildExecutable) {
    setPolicyConfig(root, {{"grub_test_policy", "expected"}});
    JournalOverride journalOverride(
        root / "alt-apply-race" / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(rebuildExecutable);
    const fs::path shared = root / "alt-apply-race/etc/sysconfig/grub2";
    const std::string foreign = "GRUB_TIMEOUT=5\n";
    writeFile(shared, foreign);
    JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                             "grub_test_policy");
    const std::string external = "EXTERNAL=1\n";
    setGrubSharedPreWriteHookForTests(
        [&shared, &external] { writeFile(shared, external); });
    require(!policy.apply(), "stale-read CAS race must fail the ALT apply");
    require(readFile(shared) == external,
            "the external write must survive the failed apply byte-exact");
    require(activeCount(policy.ref()) == 0,
            "a failed CAS apply must discard the Prepared record");
}

// C: ALT rollback stale-read race: an external writer racing between the
// rollback snapshot and the CAS removal write must fail the rollback
// without a rebuild, leaving the external bytes byte-exact.
void testAltRollbackStaleReadCasRace(const fs::path& root,
                                     const fs::path& rebuildExecutable) {
    JournalOverride journalOverride(
        root / "alt-rollback-race" / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(rebuildExecutable);
    const fs::path shared = root / "alt-rollback-race/etc/sysconfig/grub2";
    const std::string foreign = "GRUB_TIMEOUT=5\n";
    writeFile(shared,
              foreign + "\n" +
                  "# FIC_GRUB_BLOCK_BEGIN version=1\n"
                  "GRUB_TIMEOUT=\"expected\"\n"
                  "# FIC_GRUB_BLOCK_END\n");
    std::size_t rebuilds = 0;
    auto options = rollbackOptions(altConfig(shared), resolver,
                                   countingRebuildRunner(rebuilds));
    const std::string external = "EXTERNAL=2\n";
    setGrubSharedPreWriteHookForTests(
        [&shared, &external] { writeFile(shared, external); });
    const auto outcome = undoGrubManagedSetting(
        options,
        rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "expected"});
    require((!outcome.ok && !outcome.conflict && !outcome.nothingToDo),
            "stale-read CAS race must fail the ALT rollback");
    require(readFile(shared) == external,
            "the external write must survive the failed rollback byte-exact");
    require(rebuilds == 0, "a failed CAS rollback must not rebuild");
}

// D: unsafe managed artifacts (a symlink or a directory occupying the
// managed path) must NOT be treated as Missing/NothingToDo: fail closed as
// a conflict, never rebuild, never touch the foreign artifact.
void testUnsafeManagedArtifactsAreNotMissing(
    const fs::path& root, const fs::path& rebuildExecutable) {
    const auto resolver = makeResolver(rebuildExecutable);

    // ALT: symlink occupying the shared defaults path.
    {
        const fs::path testCase = root / "alt-unsafe-link";
        const fs::path shared = testCase / "etc/sysconfig/grub2";
        fs::create_directories(shared.parent_path());
        writeFile(testCase / "foreign-target", "GRUB_TIMEOUT=5\n");
        fs::create_symlink(testCase / "foreign-target", shared);
        std::size_t rebuilds = 0;
        auto options = rollbackOptions(altConfig(shared), resolver,
                                       countingRebuildRunner(rebuilds));
        const auto outcome = undoGrubManagedSetting(
            options,
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT",
                                                   "expected"});
        require(outcome.conflict,
                "a symlinked ALT shared file must NOT be NothingToDo");
        require(rebuilds == 0, "an unsafe ALT artifact must not rebuild");
        require(fs::is_symlink(shared),
                "an unsafe ALT artifact must not be replaced");
    }

    // ALT: directory occupying the shared defaults path.
    {
        const fs::path testCase = root / "alt-unsafe-directory";
        const fs::path shared = testCase / "etc/sysconfig/grub2";
        fs::create_directories(shared);
        std::size_t rebuilds = 0;
        auto options = rollbackOptions(altConfig(shared), resolver,
                                       countingRebuildRunner(rebuilds));
        const auto outcome = undoGrubManagedSetting(
            options,
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT",
                                                   "expected"});
        require(outcome.conflict,
                "a directory ALT shared path must NOT be NothingToDo");
        require(rebuilds == 0,
                "a directory ALT shared path must not rebuild");
        require(fs::is_directory(shared) && !fs::is_symlink(shared),
                "a directory occupying the ALT path must not be replaced");
    }

    // Debian: symlink occupying the managed drop-in path.
    {
        const fs::path testCase = root / "deb-unsafe-link";
        JournalOverride journalOverride(
            testCase / "data" / "mutation-journal.json");
        fs::create_directories(dropInDirectory(testCase));
        const fs::path managed = dropInPath(testCase);
        writeFile(testCase / "foreign-target", "GRUB_TIMEOUT=5\n");
        fs::create_symlink(testCase / "foreign-target", managed);
        std::size_t rebuilds = 0;
        auto options = rollbackOptions(
            debianConfig(managed, testCase / "etc/default/grub"), resolver,
            countingRebuildRunner(rebuilds));
        const auto outcome = undoGrubManagedSetting(
            options,
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT",
                                                   "expected"});
        require(outcome.conflict,
                "a symlinked Debian drop-in must NOT be NothingToDo");
        require(rebuilds == 0, "an unsafe Debian drop-in must not rebuild");
        require(fs::is_symlink(managed),
                "an unsafe Debian drop-in must not be replaced");
    }

    // Debian: directory occupying the managed drop-in path.
    {
        const fs::path testCase = root / "deb-unsafe-directory";
        JournalOverride journalOverride(
            testCase / "data" / "mutation-journal.json");
        fs::create_directories(dropInPath(testCase));
        const fs::path managed = dropInPath(testCase);
        std::size_t rebuilds = 0;
        auto options = rollbackOptions(
            debianConfig(managed, testCase / "etc/default/grub"), resolver,
            countingRebuildRunner(rebuilds));
        const auto outcome = undoGrubManagedSetting(
            options,
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT",
                                                   "expected"});
        require(outcome.conflict,
                "a directory Debian drop-in path must NOT be NothingToDo");
        require(rebuilds == 0,
                "a directory Debian drop-in path must not rebuild");
        require(fs::is_directory(managed) && !fs::is_symlink(managed),
                "a directory occupying the drop-in path must not be "
                "replaced");
    }
}

// F: post-rebuild proof of the NORMAL apply (changed and idempotent, both
// topologies) and the neutral compensation of an initially missing Debian
// drop-in. A successful rebuild never proves managed-state compliance: the
// fake update-grub scripts below mutate the managed source DURING the
// rebuild, deterministically, without timing races.

// T1: Debian initially-missing apply + failed rebuild — the compensation
// leaves the canonical header-only FIC-owned drop-in (physical absence is
// never restored by unlink), the proven compensation reports Compensated
// and the Prepared record is discarded.
void testDebianInitiallyMissingCompensationRetainsDropIn(
    const fs::path& root) {
    const fs::path testCase = root / "deb-created-compensation";
    prepareDebianTopology(testCase);
    const fs::path managed = dropInPath(testCase);
    const fs::path failScript = root / "bin/update-grub-deb-fail";
    seedRebuildExecutable(root, failScript, "#!/bin/sh\nexit 1\n");
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(failScript);
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    JournalGrubPolicy policy(
        debianConfig(managed, testCase / "etc/default/grub"), resolver,
        "GRUB_TIMEOUT", "grub_test_policy");
    require(!policy.apply(),
            "initially-missing Debian apply must fail on the injected "
            "rebuild failure");
    require(fs::exists(managed) &&
                readFile(managed) ==
                    GrubManagedConfig::canonicalEmptyContent(),
            "compensation must retain the canonical header-only FIC "
            "drop-in instead of the physical absence");
    // The rebuild script fails for BOTH the primary and the compensating
    // rebuild: the source is restored (canonical empty), but the derived
    // grub.cfg state is unresolved — the transaction is NOT fully
    // compensated and the Prepared provenance must stay active so the next
    // recovery performs the mandatory reconciliation rebuild.
    const std::vector<rollback::MutationRecord> records =
        testJournal()->activeRecords(policy.ref());
    require(records.size() == 1 &&
                records[0].status == rollback::MutationStatus::Prepared,
            "canonical empty compensation with a failed compensating "
            "rebuild must keep the Prepared record active");
}

// T2: Debian initially-missing apply, the failing rebuild concurrently
// REPLACES the FIC-created drop-in with a new inode — the compensation
// must not remove or overwrite the external state, the source is
// Indeterminate and the Prepared record stays active.
void testDebianInitiallyMissingCompensationConcurrentReplacement(
    const fs::path& root) {
    const fs::path testCase = root / "deb-created-replacement";
    prepareDebianTopology(testCase);
    const fs::path managed = dropInPath(testCase);
    const std::string external =
        "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"5\"\n";
    const fs::path replaceScript = root / "bin/update-grub-deb-replace";
    seedRebuildExecutable(
        root, replaceScript,
        "#!/bin/sh\ncat > " + managed.string() +
            ".external <<'FIC_EOF'\n" + external +
            "FIC_EOF\nmv " + managed.string() + ".external " +
            managed.string() + "\nexit 1\n");
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(replaceScript);
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    JournalGrubPolicy policy(
        debianConfig(managed, testCase / "etc/default/grub"), resolver,
        "GRUB_TIMEOUT", "grub_test_policy");
    require(!policy.apply(),
            "apply must fail when the created drop-in is concurrently "
            "replaced before compensation");
    require(readFile(managed) == external,
            "the external replacement must be preserved byte-exact");
    const std::vector<rollback::MutationRecord> records =
        testJournal()->activeRecords(policy.ref());
    require(records.size() == 1 &&
                records[0].status == rollback::MutationStatus::Prepared,
            "unproven compensation must keep the Prepared record active");
    const auto* undo = std::get_if<rollback::UndoRemoveGrubManagedSetting>(
        &records[0].undo.payload);
    require(undo != nullptr && undo->key == "GRUB_TIMEOUT" &&
                undo->appliedValue == "0",
            "the Prepared payload must stay key + desired appliedValue");
}

// T3: ALT changed apply — the rebuild script rewrites the FIC block to
// another value DURING the rebuild; the fresh post-rebuild proof must fail
// the apply, keep the Prepared record active and preserve the external
// state without any compensation overwrite.
void testAltChangedApplyDriftDuringRebuild(const fs::path& root) {
    const fs::path testCase = root / "alt-apply-drift";
    const fs::path shared = testCase / "etc/sysconfig/grub2";
    const std::string foreign = "GRUB_TIMEOUT=5\n";
    writeFile(shared, foreign);
    const std::string drifted = foreign + "\n" +
        "# FIC_GRUB_BLOCK_BEGIN version=1\n"
        "GRUB_TIMEOUT=\"5\"\n"
        "# FIC_GRUB_BLOCK_END\n";
    const fs::path driftScript = root / "bin/update-grub-alt-apply-drift";
    seedRebuildExecutable(
        root, driftScript,
        "#!/bin/sh\ncat > " + shared.string() + " <<'FIC_EOF'\n" +
            drifted + "FIC_EOF\nexit 0\n");
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(driftScript);
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                             "grub_test_policy");
    require(!policy.apply(),
            "ALT changed apply must fail when the FIC block drifts during "
            "the rebuild");
    require(readFile(shared) == drifted,
            "the drifted external state must be preserved unchanged");
    const std::vector<rollback::MutationRecord> records =
        testJournal()->activeRecords(policy.ref());
    require(records.size() == 1 &&
                records[0].status == rollback::MutationStatus::Prepared,
            "post-rebuild drift must keep the Prepared record active");
    const auto* undo = std::get_if<rollback::UndoRemoveGrubManagedSetting>(
        &records[0].undo.payload);
    require(undo != nullptr && undo->key == "GRUB_TIMEOUT" &&
                undo->appliedValue == "0",
            "the Prepared payload must keep the desired appliedValue");
}

// T4: Debian changed apply — the rebuild script rewrites the managed
// drop-in DURING the rebuild, valid FIC-owned content with another value
// and malformed content alike; both must fail closed, keep the Prepared
// record active and preserve the external bytes.
void testDebianChangedApplyDriftDuringRebuild(const fs::path& root) {
    // Valid FIC-owned drop-in with another value.
    {
        const fs::path testCase = root / "deb-apply-drift";
        prepareDebianTopology(testCase);
        const fs::path managed = dropInPath(testCase);
        const std::string drifted =
            "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"5\"\n";
        const fs::path driftScript =
            root / "bin/update-grub-deb-apply-drift";
        seedRebuildExecutable(
            root, driftScript,
            "#!/bin/sh\ncat > " + managed.string() + " <<'FIC_EOF'\n" +
                drifted + "FIC_EOF\nexit 0\n");
        JournalOverride journalOverride(
            testCase / "data" / "mutation-journal.json");
        const auto resolver = makeResolver(driftScript);
        setPolicyConfig(root, {{"grub_test_policy", "0"}});
        JournalGrubPolicy policy(
            debianConfig(managed, testCase / "etc/default/grub"), resolver,
            "GRUB_TIMEOUT", "grub_test_policy");
        require(!policy.apply(),
                "Debian changed apply must fail when the drop-in drifts "
                "during the rebuild");
        require(readFile(managed) == drifted,
                "the drifted external state must be preserved unchanged");
        const std::vector<rollback::MutationRecord> records =
            testJournal()->activeRecords(policy.ref());
        require(records.size() == 1 &&
                    records[0].status == rollback::MutationStatus::Prepared,
                "post-rebuild drift must keep the Prepared record active");
        const auto* undo =
            std::get_if<rollback::UndoRemoveGrubManagedSetting>(
                &records[0].undo.payload);
        require(undo != nullptr && undo->key == "GRUB_TIMEOUT" &&
                    undo->appliedValue == "0",
                "the Prepared payload must keep the desired appliedValue");
    }
    // Malformed drop-in written during the rebuild.
    {
        const fs::path testCase = root / "deb-apply-drift-malformed";
        prepareDebianTopology(testCase);
        const fs::path managed = dropInPath(testCase);
        const std::string malformed =
            "GRUB_TIMEOUT=\"5\nthis is not a config\n";
        const fs::path driftScript =
            root / "bin/update-grub-deb-apply-drift-malformed";
        seedRebuildExecutable(
            root, driftScript,
            "#!/bin/sh\ncat > " + managed.string() + " <<'FIC_EOF'\n" +
                malformed + "FIC_EOF\nexit 0\n");
        JournalOverride journalOverride(
            testCase / "data" / "mutation-journal.json");
        const auto resolver = makeResolver(driftScript);
        setPolicyConfig(root, {{"grub_test_policy", "0"}});
        JournalGrubPolicy policy(
            debianConfig(managed, testCase / "etc/default/grub"), resolver,
            "GRUB_TIMEOUT", "grub_test_policy");
        require(!policy.apply(),
                "Debian changed apply must fail when the drop-in becomes "
                "malformed during the rebuild");
        require(readFile(managed) == malformed,
                "the malformed external state must be preserved unchanged");
        const std::vector<rollback::MutationRecord> records =
            testJournal()->activeRecords(policy.ref());
        require(records.size() == 1 &&
                    records[0].status == rollback::MutationStatus::Prepared,
                "post-rebuild invalid source must keep the Prepared record "
                "active");
    }
}

// T5: ALT idempotent apply — the rebuild script rewrites the already
// compliant FIC block DURING the rebuild; the fresh post-rebuild proof
// must fail the apply without creating any journal record.
void testAltIdempotentDriftDuringRebuild(const fs::path& root) {
    const fs::path testCase = root / "alt-idempotent-drift";
    const fs::path shared = testCase / "etc/sysconfig/grub2";
    const std::string initial =
        "GRUB_TIMEOUT=5\n"
        "\n"
        "# FIC_GRUB_BLOCK_BEGIN version=1\n"
        "GRUB_TIMEOUT=\"0\"\n"
        "# FIC_GRUB_BLOCK_END\n";
    writeFile(shared, initial);
    const std::string drifted =
        "GRUB_TIMEOUT=5\n"
        "\n"
        "# FIC_GRUB_BLOCK_BEGIN version=1\n"
        "GRUB_TIMEOUT=\"5\"\n"
        "# FIC_GRUB_BLOCK_END\n";
    const fs::path driftScript =
        root / "bin/update-grub-alt-idempotent-drift";
    seedRebuildExecutable(
        root, driftScript,
        "#!/bin/sh\ncat > " + shared.string() + " <<'FIC_EOF'\n" +
            drifted + "FIC_EOF\nexit 0\n");
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(driftScript);
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                             "grub_test_policy");
    require(!policy.apply(),
            "ALT idempotent apply must fail when the block drifts during "
            "the rebuild");
    require(readFile(shared) == drifted,
            "the drifted external state must be preserved unchanged");
    require(activeCount(policy.ref()) == 0,
            "idempotent drift must not create a journal record");
}

// T6: Debian idempotent apply — the rebuild script rewrites the already
// compliant drop-in DURING the rebuild; the fresh post-rebuild proof must
// fail the apply without creating a Prepared record.
void testDebianIdempotentDriftDuringRebuild(const fs::path& root) {
    const fs::path testCase = root / "deb-idempotent-drift";
    prepareDebianTopology(testCase);
    const fs::path managed = dropInPath(testCase);
    const std::string initial =
        "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"0\"\n";
    writeFile(managed, initial);
    const std::string drifted =
        "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"5\"\n";
    const fs::path driftScript =
        root / "bin/update-grub-deb-idempotent-drift";
    seedRebuildExecutable(
        root, driftScript,
        "#!/bin/sh\ncat > " + managed.string() + " <<'FIC_EOF'\n" +
            drifted + "FIC_EOF\nexit 0\n");
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(driftScript);
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    JournalGrubPolicy policy(
        debianConfig(managed, testCase / "etc/default/grub"), resolver,
        "GRUB_TIMEOUT", "grub_test_policy");
    require(!policy.apply(),
            "Debian idempotent apply must fail when the drop-in drifts "
            "during the rebuild");
    require(readFile(managed) == drifted,
            "the drifted external state must be preserved unchanged");
    require(activeCount(policy.ref()) == 0,
            "idempotent drift must not create a journal record");
}

// E: post-rebuild re-proof (fail closed): a mandatory reconciliation
// rebuild that itself corrupts the managed source must leave the journal
// record active and fail the apply — for both ALT and Debian topologies.
void testReconciliationDriftAfterRebuild(const fs::path& root) {
    setPolicyConfig(root, {{"grub_test_policy", "expected"}});

    // ALT: the fake update-grub rewrites the FIC block value to "manual".
    {
        const fs::path testCase = root / "alt-rebuild-drift";
        const fs::path shared = testCase / "etc/sysconfig/grub2";
        const std::string driftedContent =
            "GRUB_TIMEOUT=5\n"
            "\n"
            "# FIC_GRUB_BLOCK_BEGIN version=1\n"
            "GRUB_TIMEOUT=\"manual\"\n"
            "# FIC_GRUB_BLOCK_END\n";
        writeFile(shared,
                  "GRUB_TIMEOUT=5\n"
                  "\n"
                  "# FIC_GRUB_BLOCK_BEGIN version=1\n"
                  "GRUB_TIMEOUT=\"expected\"\n"
                  "# FIC_GRUB_BLOCK_END\n");
        const fs::path driftScript = root / "bin/update-grub-alt-drift";
        seedRebuildExecutable(
            root, driftScript,
            "#!/bin/sh\ncat > " + shared.string() + " <<'FIC_EOF'\n" +
                driftedContent + "FIC_EOF\nexit 0\n");
        JournalOverride journalOverride(
            testCase / "data" / "mutation-journal.json");
        const auto resolver = makeResolver(driftScript);
        JournalGrubPolicy policy(altConfig(shared), resolver,
                                 "GRUB_TIMEOUT", "grub_test_policy");
        rollback::MutationId id = 0;
        std::string error;
        rollback::MutationRecord prepared = preparedGrubRecord(
            policy.ref(), "GRUB_TIMEOUT",
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT",
                                                   "expected"});
        require(testJournal()->prepareMutation(prepared, id, error), error);

        require(!policy.apply(),
                "ALT rebuild drift must fail the reconciliation apply");
        require(readFile(shared) == driftedContent,
                "ALT rebuild drift must prove the rebuild ran");
        require(activeCount(policy.ref()) == 1,
                "ALT rebuild drift must keep the journal record active");
        const std::vector<rollback::MutationRecord> records =
            testJournal()->activeRecords(policy.ref());
        require(records[0].status == rollback::MutationStatus::Prepared,
                "ALT rebuild drift must not commit the record");
    }

    // Debian: the fake update-grub rewrites the managed drop-in value.
    {
        const fs::path testCase = root / "deb-rebuild-drift";
        prepareDebianTopology(testCase);
        const fs::path managed = dropInPath(testCase);
        const std::string driftedContent =
            "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"manual\"\n";
        writeFile(managed,
                  "# Managed by FIC. Do not edit.\n\n"
                  "GRUB_TIMEOUT=\"expected\"\n");
        const fs::path driftScript = root / "bin/update-grub-deb-drift";
        seedRebuildExecutable(
            root, driftScript,
            "#!/bin/sh\ncat > " + managed.string() + " <<'FIC_EOF'\n" +
                driftedContent + "FIC_EOF\nexit 0\n");
        JournalOverride journalOverride(
            testCase / "data" / "mutation-journal.json");
        const auto resolver = makeResolver(driftScript);
        JournalGrubPolicy policy(
            debianConfig(managed, testCase / "etc/default/grub"), resolver,
            "GRUB_TIMEOUT", "grub_test_policy");
        rollback::MutationId id = 0;
        std::string error;
        rollback::MutationRecord prepared = preparedGrubRecord(
            policy.ref(), "GRUB_TIMEOUT",
            rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT",
                                                   "expected"});
        require(testJournal()->prepareMutation(prepared, id, error), error);

        require(!policy.apply(),
                "Debian rebuild drift must fail the reconciliation apply");
        require(readFile(managed) == driftedContent,
                "Debian rebuild drift must prove the rebuild ran");
        require(activeCount(policy.ref()) == 1,
                "Debian rebuild drift must keep the journal record active");
        const std::vector<rollback::MutationRecord> records =
            testJournal()->activeRecords(policy.ref());
        require(records[0].status == rollback::MutationStatus::Prepared,
                "Debian rebuild drift must not commit the record");
    }
}


} // namespace

// T2b: ALT changed apply — the rebuild script APPENDS a foreign assignment
// AFTER the FIC block (valid block, foreign tail). The post-rebuild proof
// must reject the non-EOF placement (Ineffective), fail the apply and keep
// the Prepared record active; the appended external bytes stay preserved.
void testAltChangedForeignTailDuringRebuild(const fs::path& root) {
    const fs::path testCase = root / "alt-apply-foreign-tail";
    const fs::path shared = testCase / "etc/sysconfig/grub2";
    writeFile(shared, "FOO=bar\n");
    const std::string installed =
        "FOO=bar\n"
        "\n"
        "# FIC_GRUB_BLOCK_BEGIN version=1\n"
        "GRUB_TIMEOUT=\"0\"\n"
        "# FIC_GRUB_BLOCK_END\n";
    const std::string drifted = installed + "GRUB_TIMEOUT=5\n";
    const fs::path driftScript = root / "bin/update-grub-alt-foreign-tail";
    seedRebuildExecutable(
        root, driftScript,
        "#!/bin/sh\necho 'GRUB_TIMEOUT=5' >> " + shared.string() +
            "\nexit 0\n");
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(driftScript);
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                             "grub_test_policy");
    require(!policy.apply(),
            "ALT changed apply must fail when a foreign tail appears "
            "during the rebuild");
    require(readFile(shared) == drifted,
            "the appended external bytes must be preserved unchanged");
    const std::vector<rollback::MutationRecord> records =
        testJournal()->activeRecords(policy.ref());
    require(records.size() == 1 &&
                records[0].status == rollback::MutationStatus::Prepared,
            "non-EOF post-rebuild placement must keep Prepared active");
}

// T3b: ALT idempotent apply — the rebuild script appends a foreign
// assignment after the compliant EOF block; the fresh post-rebuild proof
// must reject the placement without creating any journal record.
void testAltIdempotentForeignTailDuringRebuild(const fs::path& root) {
    const fs::path testCase = root / "alt-idempotent-foreign-tail";
    const fs::path shared = testCase / "etc/sysconfig/grub2";
    const std::string initial =
        "GRUB_TIMEOUT=5\n"
        "\n"
        "# FIC_GRUB_BLOCK_BEGIN version=1\n"
        "GRUB_TIMEOUT=\"0\"\n"
        "# FIC_GRUB_BLOCK_END\n";
    writeFile(shared, initial);
    const std::string drifted = initial + "GRUB_TIMEOUT=5\n";
    const fs::path driftScript =
        root / "bin/update-grub-alt-idem-foreign-tail";
    seedRebuildExecutable(
        root, driftScript,
        "#!/bin/sh\necho 'GRUB_TIMEOUT=5' >> " + shared.string() +
            "\nexit 0\n");
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(driftScript);
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                             "grub_test_policy");
    require(!policy.apply(),
            "ALT idempotent apply must fail when a foreign tail appears "
            "during the rebuild");
    require(readFile(shared) == drifted,
            "the appended external tail must be preserved unchanged");
    require(activeCount(policy.ref()) == 0,
            "idempotent foreign tail must not create a journal record");
}

// T1: a valid same-value block displaced from EOF is NOT compliant — the
// apply must create Prepared BEFORE the relocation, relocate the proven
// block to EOF through the journaled changed path, preserve the foreign
// bytes in order and commit Applied only after the successful rebuild and
// fresh EOF proof.
void testAltSameValueNotEofRelocation(const fs::path& root,
                                      const fs::path& rebuildExecutable) {
    const fs::path testCase = root / "alt-same-value-not-eof";
    const fs::path shared = testCase / "etc/sysconfig/grub2";
    writeFile(shared,
              "FOO=bar\n"
              "\n"
              "# FIC_GRUB_BLOCK_BEGIN version=1\n"
              "GRUB_TIMEOUT=\"0\"\n"
              "# FIC_GRUB_BLOCK_END\n"
              "GRUB_TIMEOUT=5\n");
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(rebuildExecutable);
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                             "grub_test_policy");
    // Prove the ordering invariant: when the relocation CAS write happens,
    // the Prepared record must already exist — no unjournaled relocation.
    setGrubSharedPreWriteHookForTests([&policy]() {
        const std::vector<rollback::MutationRecord> records =
            testJournal()->activeRecords(policy.ref());
        require(records.size() == 1 &&
                    records[0].status == rollback::MutationStatus::Prepared,
                "the relocation write must be preceded by a Prepared "
                "journal record");
    });
    struct ClearHook {
        ~ClearHook() { setGrubSharedPreWriteHookForTests({}); }
    } clearHook;
    require(policy.apply(),
            "same-value non-EOF block must trigger a journaled relocation");
    require(
        readFile(shared) ==
            "FOO=bar\n"
            "\n"
            "GRUB_TIMEOUT=5\n"
            "\n"
            "# FIC_GRUB_BLOCK_BEGIN version=1\n"
            "GRUB_TIMEOUT=\"0\"\n"
            "# FIC_GRUB_BLOCK_END\n",
        "relocation must preserve foreign bytes in order and place the "
        "block at EOF");
    const std::vector<rollback::MutationRecord> records =
        testJournal()->activeRecords(policy.ref());
    require(records.size() == 1 &&
                records[0].status == rollback::MutationStatus::Applied,
            "exactly one active Applied record must remain after the "
            "relocation");
    const auto* undo = std::get_if<rollback::UndoRemoveGrubManagedSetting>(
        &records[0].undo.payload);
    require(undo != nullptr && undo->key == "GRUB_TIMEOUT" &&
                undo->appliedValue == "0",
            "the relocation journal payload must record the applied value");
}

// T4: rollback ownership release does NOT require EOF placement — a valid
// block holding the recorded value but displaced by a foreign tail is
// proven FIC-owned; only the block (and the FIC-owned separator) is
// removed, the foreign tail survives byte-exact.
void testAltRollbackNonEofOwnedBlock(const fs::path& root,
                                     const fs::path& rebuildExecutable) {
    JournalOverride journalOverride(
        root / "alt-rollback-not-eof" / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(rebuildExecutable);
    const fs::path shared =
        root / "alt-rollback-not-eof/etc/sysconfig/grub2";
    writeFile(shared,
              "FOO=bar\n"
              "\n"
              "# FIC_GRUB_BLOCK_BEGIN version=1\n"
              "GRUB_TIMEOUT=\"0\"\n"
              "# FIC_GRUB_BLOCK_END\n"
              "GRUB_TIMEOUT=5\n");
    JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                             "grub_test_policy");
    rollback::MutationId id = 0;
    std::string error;
    rollback::MutationRecord prepared = preparedGrubRecord(
        policy.ref(), "GRUB_TIMEOUT",
        rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "0"});
    require(testJournal()->prepareMutation(prepared, id, error), error);
    std::size_t rebuilds = 0;
    auto options = rollbackOptions(altConfig(shared), resolver,
                                   countingRebuildRunner(rebuilds));
    const auto outcome = undoGrubManagedSetting(
        options,
        rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "0"});
    require(outcome.ok,
            "rollback of a valid non-EOF owned block must succeed");
    require(readFile(shared) == "FOO=bar\n\nGRUB_TIMEOUT=5\n",
            "rollback must remove only the FIC block and preserve the "
            "foreign tail byte-exact");
    require(rebuilds == 1,
            "rollback must run exactly one mandatory rebuild");
}

// T5 + T7: Debian double rebuild failure (existing drop-in compensation
// topology). The source is restored byte-exact but the compensating
// rebuild fails too: the transaction is NOT fully compensated, the
// Prepared record stays active. The next apply with a working rebuild
// classifies BEFORE, runs the mandatory reconciliation rebuild, discards
// the stale Prepared and performs a fresh successful apply.
void testDebianDoubleRebuildFailureKeepsPrepared(const fs::path& root) {
    const fs::path testCase = root / "deb-double-failure";
    prepareDebianTopology(testCase);
    const fs::path managed = dropInPath(testCase);
    const std::string original =
        "# Managed by FIC. Do not edit.\n\nGRUB_CMDLINE_LINUX=\"quiet\"\n";
    writeFile(managed, original);
    const fs::path failScript = root / "bin/update-grub-deb-double-fail";
    seedRebuildExecutable(root, failScript, "#!/bin/sh\nexit 1\n");
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    const auto failResolver = makeResolver(failScript);
    {
        JournalGrubPolicy policy(
            debianConfig(managed, testCase / "etc/default/grub"),
            failResolver, "GRUB_TIMEOUT", "grub_test_policy");
        require(!policy.apply(),
                "double rebuild failure must fail the apply");
        require(readFile(managed) == original,
                "the source must be restored byte-exact after compensation");
        const std::vector<rollback::MutationRecord> records =
            testJournal()->activeRecords(policy.ref());
        require(records.size() == 1 &&
                    records[0].status == rollback::MutationStatus::Prepared,
                "source restored + failed compensating rebuild must keep "
                "the Prepared record active");
    }
    const fs::path okScript = root / "bin/update-grub-deb-double-recover";
    seedRebuildExecutable(root, okScript, "#!/bin/sh\nexit 0\n");
    const auto okResolver = makeResolver(okScript);
    {
        JournalGrubPolicy policy(
            debianConfig(managed, testCase / "etc/default/grub"),
            okResolver, "GRUB_TIMEOUT", "grub_test_policy");
        require(policy.apply(),
                "recovery must complete the mandatory rebuild and a fresh "
                "apply");
        require(
            readFile(managed) ==
                "# Managed by FIC. Do not edit.\n\n"
                "GRUB_CMDLINE_LINUX=\"quiet\"\nGRUB_TIMEOUT=\"0\"\n",
            "recovery must install the desired value");
        const std::vector<rollback::MutationRecord> records =
            testJournal()->activeRecords(policy.ref());
        require(records.size() == 1 &&
                    records[0].status == rollback::MutationStatus::Applied,
                "exactly one active Applied record must remain");
    }
}

// T6 + T8: ALT double rebuild failure over the shared managed block —
// same recovery semantics: byte-exact source restore, Prepared stays
// active, the retry resolves the stale record via the BEFORE mandatory
// rebuild and finishes with exactly one Applied record.
void testAltDoubleRebuildFailureKeepsPrepared(const fs::path& root) {
    const fs::path testCase = root / "alt-double-failure";
    const fs::path shared = testCase / "etc/sysconfig/grub2";
    const std::string foreign = "FOO=bar\n";
    writeFile(shared, foreign);
    const fs::path failScript = root / "bin/update-grub-alt-double-fail";
    seedRebuildExecutable(root, failScript, "#!/bin/sh\nexit 1\n");
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    const auto failResolver = makeResolver(failScript);
    {
        JournalGrubPolicy policy(altConfig(shared), failResolver,
                                 "GRUB_TIMEOUT", "grub_test_policy");
        require(!policy.apply(),
                "double rebuild failure must fail the apply");
        require(readFile(shared) == foreign,
                "the source must be restored byte-exact BEFORE");
        const std::vector<rollback::MutationRecord> records =
            testJournal()->activeRecords(policy.ref());
        require(records.size() == 1 &&
                    records[0].status == rollback::MutationStatus::Prepared,
                "source restored + failed compensating rebuild must keep "
                "the Prepared record active");
    }
    const fs::path okScript = root / "bin/update-grub-alt-double-recover";
    seedRebuildExecutable(root, okScript, "#!/bin/sh\nexit 0\n");
    const auto okResolver = makeResolver(okScript);
    {
        JournalGrubPolicy policy(altConfig(shared), okResolver,
                                 "GRUB_TIMEOUT", "grub_test_policy");
        require(policy.apply(),
                "recovery must complete the mandatory rebuild and a fresh "
                "apply");
        require(
            readFile(shared) ==
                "FOO=bar\n"
                "\n"
                "# FIC_GRUB_BLOCK_BEGIN version=1\n"
                "GRUB_TIMEOUT=\"0\"\n"
                "# FIC_GRUB_BLOCK_END\n",
            "recovery must install the desired value at EOF");
        const std::vector<rollback::MutationRecord> records =
            testJournal()->activeRecords(policy.ref());
        require(records.size() == 1 &&
                    records[0].status == rollback::MutationStatus::Applied,
                "exactly one active Applied record must remain");
    }
}

// T9: initially-missing Debian drop-in — FIC creates the desired drop-in,
// the primary rebuild fails, the compensation installs the canonical
// header-only drop-in (never an unlink) and the compensating rebuild fails
// too: Prepared stays active. The next recovery classifies BEFORE (the
// neutral canonical state), discards the stale record and applies fresh.
void testDebianInitiallyMissingCompensationPendingRebuild(
    const fs::path& root) {
    const fs::path testCase = root / "deb-created-pending";
    prepareDebianTopology(testCase);
    const fs::path managed = dropInPath(testCase);
    require(!fs::exists(managed),
            "precondition: the drop-in must be initially missing");
    const fs::path failScript = root / "bin/update-grub-deb-created-fail";
    seedRebuildExecutable(root, failScript, "#!/bin/sh\nexit 1\n");
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    const auto failResolver = makeResolver(failScript);
    {
        JournalGrubPolicy policy(
            debianConfig(managed, testCase / "etc/default/grub"),
            failResolver, "GRUB_TIMEOUT", "grub_test_policy");
        require(!policy.apply(),
                "double rebuild failure must fail the apply");
        require(fs::exists(managed),
                "the canonical empty compensation must retain the drop-in");
        require(readFile(managed) ==
                    GrubManagedConfig::canonicalEmptyContent(),
                "the compensation must install the canonical empty "
                "drop-in");
        const std::vector<rollback::MutationRecord> records =
            testJournal()->activeRecords(policy.ref());
        require(records.size() == 1 &&
                    records[0].status == rollback::MutationStatus::Prepared,
                "canonical empty compensation + failed compensating "
                "rebuild must keep Prepared active");
    }
    const fs::path okScript = root / "bin/update-grub-deb-created-ok";
    seedRebuildExecutable(root, okScript, "#!/bin/sh\nexit 0\n");
    const auto okResolver = makeResolver(okScript);
    {
        JournalGrubPolicy policy(
            debianConfig(managed, testCase / "etc/default/grub"),
            okResolver, "GRUB_TIMEOUT", "grub_test_policy");
        require(policy.apply(),
                "recovery from the canonical empty state must succeed");
        require(readFile(managed) ==
                    "# Managed by FIC. Do not edit.\n\nGRUB_TIMEOUT=\"0\"\n",
                "recovery must install the desired value");
        const std::vector<rollback::MutationRecord> records =
            testJournal()->activeRecords(policy.ref());
        require(records.size() == 1 &&
                    records[0].status == rollback::MutationStatus::Applied,
                "exactly one active Applied record must remain");
    }
}

// ---------------------------------------------------------------------------
// Provenance-safe repair lifecycle: a repair operation must never destroy
// pre-existing active provenance. Fresh Prepared and reused active
// provenance are different lifecycle cases.

// T1: existing Applied + same-value non-EOF repair SUCCEEDS — the SAME
// record id is reused (Applied → Prepared → Applied), never duplicated
// and never discarded; the foreign tail survives before the relocated
// block.
void testExistingAppliedSameValueRepairSucceeds(
    const fs::path& root, const fs::path& rebuildExecutable) {
    const fs::path testCase = root / "alt-repair-applied-success";
    const fs::path shared = testCase / "etc/sysconfig/grub2";
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(rebuildExecutable);
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    writeFile(shared, "GRUB_TIMEOUT=5\n");
    rollback::MutationId appliedId = 0;
    {
        JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                                 "grub_test_policy");
        require(policy.apply(), "initial apply must succeed");
        const std::vector<rollback::MutationRecord> records =
            testJournal()->activeRecords(policy.ref());
        require(records.size() == 1 &&
                    records[0].status == rollback::MutationStatus::Applied,
                "initial apply must leave exactly one Applied record");
        appliedId = records[0].id;
    }
    const std::string nonEof =
        "GRUB_TIMEOUT=5\n"
        "\n"
        "# FIC_GRUB_BLOCK_BEGIN version=1\n"
        "GRUB_TIMEOUT=\"0\"\n"
        "# FIC_GRUB_BLOCK_END\n"
        "GRUB_TIMEOUT=5\n";
    writeFile(shared, nonEof);
    {
        JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                                 "grub_test_policy");
        setGrubSharedPreWriteHookForTests([&policy, appliedId]() {
            const std::vector<rollback::MutationRecord> records =
                testJournal()->activeRecords(policy.ref());
            require(records.size() == 1 && records[0].id == appliedId &&
                        records[0].status ==
                            rollback::MutationStatus::Prepared,
                    "the repair must reuse the SAME active record as "
                    "Prepared before the relocation write");
        });
        struct ClearHook {
            ~ClearHook() { setGrubSharedPreWriteHookForTests({}); }
        } clearHook;
        require(policy.apply(),
                "same-value repair of a non-EOF owned block must succeed");
    }
    require(
        readFile(shared) ==
            "GRUB_TIMEOUT=5\n"
            "\n"
            "GRUB_TIMEOUT=5\n"
            "\n"
            "# FIC_GRUB_BLOCK_BEGIN version=1\n"
            "GRUB_TIMEOUT=\"0\"\n"
            "# FIC_GRUB_BLOCK_END\n",
        "the relocation must preserve the foreign bytes in order and "
        "place the block at EOF");
    const std::vector<rollback::MutationRecord> records =
        testJournal()->records();
    require(records.size() == 1 && records[0].id == appliedId &&
                records[0].status == rollback::MutationStatus::Applied,
            "the SAME MutationId must survive Applied → Prepared → "
            "Applied with no second record");
    const auto* undo = std::get_if<rollback::UndoRemoveGrubManagedSetting>(
        &records[0].undo.payload);
    require(undo != nullptr && undo->key == "GRUB_TIMEOUT" &&
                undo->appliedValue == "0",
            "the reused record payload must stay intact");
}

// T2: existing Applied + relocation pre-write CAS failure — the existing
// provenance must NOT be deleted: the record is restored to Applied and
// the racing external bytes survive byte-exact.
void testExistingAppliedRelocationCasFailureRestoresProvenance(
    const fs::path& root, const fs::path& rebuildExecutable) {
    const fs::path testCase = root / "alt-repair-cas-failure";
    const fs::path shared = testCase / "etc/sysconfig/grub2";
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(rebuildExecutable);
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    writeFile(shared, "GRUB_TIMEOUT=5\n");
    rollback::MutationId appliedId = 0;
    {
        JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                                 "grub_test_policy");
        require(policy.apply(), "initial apply must succeed");
        appliedId = testJournal()->activeRecords(policy.ref())[0].id;
    }
    const std::string nonEof =
        "GRUB_TIMEOUT=5\n"
        "\n"
        "# FIC_GRUB_BLOCK_BEGIN version=1\n"
        "GRUB_TIMEOUT=\"0\"\n"
        "# FIC_GRUB_BLOCK_END\n"
        "GRUB_TIMEOUT=5\n";
    writeFile(shared, nonEof);
    const std::string external = nonEof + "EXTERNAL=1\n";
    {
        JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                                 "grub_test_policy");
        setGrubSharedPreWriteHookForTests(
            [&shared, &external] { writeFile(shared, external); });
        struct ClearHook {
            ~ClearHook() { setGrubSharedPreWriteHookForTests({}); }
        } clearHook;
        require(!policy.apply(),
                "the CAS-race repair must fail the apply");
    }
    require(readFile(shared) == external,
            "the racing external write must survive byte-exact");
    const std::vector<rollback::MutationRecord> records =
        testJournal()->records();
    require(records.size() == 1 && records[0].id == appliedId &&
                records[0].status == rollback::MutationStatus::Applied,
            "a failed relocation must restore the pre-repair Applied "
            "record, never discard it");
}

// T3 (main regression): existing Applied + relocation installed + primary
// rebuild failure + SUCCESSFUL full compensation — the record must be
// restored to Applied, never discarded (previously the provenance was
// lost by the generic discard path).
void testExistingAppliedFullCompensationRestoresApplied(
    const fs::path& root) {
    const fs::path testCase = root / "alt-repair-compensated";
    const fs::path shared = testCase / "etc/sysconfig/grub2";
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    const fs::path okScript = root / "bin/update-grub-repair-ok";
    seedRebuildExecutable(root, okScript, "#!/bin/sh\nexit 0\n");
    // Stateful rebuild script: invocation 2 (the primary rebuild after the
    // relocation write) fails; the reconciliation rebuild (1) and the
    // compensating rebuild (3) succeed.
    const fs::path repairScript = root / "bin/update-grub-repair-comp";
    const fs::path counter = testCase / "rebuild-count";
    seedRebuildExecutable(
        root, repairScript,
        "#!/bin/sh\n"
        "C=\"" + counter.string() + "\"\n"
        "N=$(cat \"$C\" 2>/dev/null || echo 0)\n"
        "N=$((N+1))\n"
        "echo \"$N\" > \"$C\"\n"
        "[ \"$N\" -ne 2 ]\n");
    const auto okResolver = makeResolver(okScript);
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    writeFile(shared, "GRUB_TIMEOUT=5\n");
    rollback::MutationId appliedId = 0;
    {
        JournalGrubPolicy policy(altConfig(shared), okResolver,
                                 "GRUB_TIMEOUT", "grub_test_policy");
        require(policy.apply(), "initial apply must succeed");
        appliedId = testJournal()->activeRecords(policy.ref())[0].id;
    }
    const std::string nonEof =
        "GRUB_TIMEOUT=5\n"
        "\n"
        "# FIC_GRUB_BLOCK_BEGIN version=1\n"
        "GRUB_TIMEOUT=\"0\"\n"
        "# FIC_GRUB_BLOCK_END\n"
        "GRUB_TIMEOUT=5\n";
    writeFile(shared, nonEof);
    const auto repairResolver = makeResolver(repairScript);
    {
        JournalGrubPolicy policy(altConfig(shared), repairResolver,
                                 "GRUB_TIMEOUT", "grub_test_policy");
        require(!policy.apply(),
                "primary rebuild failure must fail the repair");
    }
    require(readFile(shared) == nonEof,
            "full compensation must restore the exact pre-repair "
            "non-EOF source");
    const std::vector<rollback::MutationRecord> records =
        testJournal()->records();
    require(records.size() == 1 && records[0].id == appliedId &&
                records[0].status == rollback::MutationStatus::Applied,
            "a fully compensated repair must restore the pre-repair "
            "Applied record instead of discarding it");
}

// T4: previous Prepared survives a fully compensated repair — restored to
// Prepared, not promoted and not discarded.
void testExistingPreparedSurvivesCompensatedRepair(const fs::path& root) {
    const fs::path testCase = root / "alt-repair-prepared-compensated";
    const fs::path shared = testCase / "etc/sysconfig/grub2";
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    const fs::path okScript = root / "bin/update-grub-prepared-ok";
    seedRebuildExecutable(root, okScript, "#!/bin/sh\nexit 0\n");
    const fs::path repairScript = root / "bin/update-grub-prepared-comp";
    const fs::path counter = testCase / "rebuild-count";
    seedRebuildExecutable(
        root, repairScript,
        "#!/bin/sh\n"
        "C=\"" + counter.string() + "\"\n"
        "N=$(cat \"$C\" 2>/dev/null || echo 0)\n"
        "N=$((N+1))\n"
        "echo \"$N\" > \"$C\"\n"
        "[ \"$N\" -ne 2 ]\n");
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    const auto repairResolver = makeResolver(repairScript);
    JournalGrubPolicy policy(altConfig(shared), repairResolver,
                             "GRUB_TIMEOUT", "grub_test_policy");
    rollback::MutationId id = 0;
    std::string error;
    rollback::MutationRecord prepared = preparedGrubRecord(
        policy.ref(), "GRUB_TIMEOUT",
        rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "0"});
    require(testJournal()->prepareMutation(prepared, id, error), error);
    const std::string nonEof =
        "GRUB_TIMEOUT=5\n"
        "\n"
        "# FIC_GRUB_BLOCK_BEGIN version=1\n"
        "GRUB_TIMEOUT=\"0\"\n"
        "# FIC_GRUB_BLOCK_END\n"
        "GRUB_TIMEOUT=5\n";
    writeFile(shared, nonEof);
    require(!policy.apply(),
            "the compensated repair must fail the apply");
    require(readFile(shared) == nonEof,
            "full compensation must restore the exact pre-repair source");
    const std::vector<rollback::MutationRecord> records =
        testJournal()->records();
    require(records.size() == 1 && records[0].id == id &&
                records[0].status == rollback::MutationStatus::Prepared,
            "previous Prepared must survive a fully compensated repair");
}

// T5: previous RollbackFailed survives a fully compensated repair — the
// pre-repair status AND the previous error message are restored.
void testExistingRollbackFailedSurvivesCompensatedRepair(
    const fs::path& root) {
    const fs::path testCase = root / "alt-repair-rollbackfailed";
    const fs::path shared = testCase / "etc/sysconfig/grub2";
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    const fs::path repairScript = root / "bin/update-grub-rbfail-comp";
    const fs::path counter = testCase / "rebuild-count";
    seedRebuildExecutable(
        root, repairScript,
        "#!/bin/sh\n"
        "C=\"" + counter.string() + "\"\n"
        "N=$(cat \"$C\" 2>/dev/null || echo 0)\n"
        "N=$((N+1))\n"
        "echo \"$N\" > \"$C\"\n"
        "[ \"$N\" -ne 2 ]\n");
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    const auto repairResolver = makeResolver(repairScript);
    JournalGrubPolicy policy(altConfig(shared), repairResolver,
                             "GRUB_TIMEOUT", "grub_test_policy");
    rollback::MutationId id = 0;
    std::string error;
    rollback::MutationRecord prepared = preparedGrubRecord(
        policy.ref(), "GRUB_TIMEOUT",
        rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "0"});
    require(testJournal()->prepareMutation(prepared, id, error), error);
    const std::string previousError = "rollback failed earlier";
    require(testJournal()->setStatusWithMessage(
                id, rollback::MutationStatus::RollbackFailed, previousError,
                error),
            error);
    const std::string nonEof =
        "GRUB_TIMEOUT=5\n"
        "\n"
        "# FIC_GRUB_BLOCK_BEGIN version=1\n"
        "GRUB_TIMEOUT=\"0\"\n"
        "# FIC_GRUB_BLOCK_END\n"
        "GRUB_TIMEOUT=5\n";
    writeFile(shared, nonEof);
    require(!policy.apply(),
            "the compensated repair must fail the apply");
    require(readFile(shared) == nonEof,
            "full compensation must restore the exact pre-repair source");
    const std::vector<rollback::MutationRecord> records =
        testJournal()->records();
    require(records.size() == 1 && records[0].id == id &&
                records[0].status ==
                    rollback::MutationStatus::RollbackFailed &&
                records[0].error == previousError,
            "previous RollbackFailed must be restored with its error "
            "message after a fully compensated repair");
}

// T6: pending repair (CompensatedPendingRebuild) must stay Prepared — NOT
// restored to the old Applied status and not discarded; the retry
// recovery finishes with exactly one Applied record for the SAME id.
void testExistingAppliedPendingRepairStaysPrepared(const fs::path& root) {
    const fs::path testCase = root / "alt-repair-pending";
    const fs::path shared = testCase / "etc/sysconfig/grub2";
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    const fs::path okScript = root / "bin/update-grub-pending-ok";
    seedRebuildExecutable(root, okScript, "#!/bin/sh\nexit 0\n");
    // Invocation 1 (the reconciliation rebuild) succeeds; invocations 2
    // (the primary rebuild after relocation) and 3 (the compensating
    // rebuild) fail → CompensatedPendingRebuild.
    const fs::path repairScript = root / "bin/update-grub-pending-fail";
    const fs::path counter = testCase / "rebuild-count";
    seedRebuildExecutable(
        root, repairScript,
        "#!/bin/sh\n"
        "C=\"" + counter.string() + "\"\n"
        "N=$(cat \"$C\" 2>/dev/null || echo 0)\n"
        "N=$((N+1))\n"
        "echo \"$N\" > \"$C\"\n"
        "[ \"$N\" -lt 2 ]\n");
    const auto okResolver = makeResolver(okScript);
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    writeFile(shared, "GRUB_TIMEOUT=5\n");
    rollback::MutationId appliedId = 0;
    {
        JournalGrubPolicy policy(altConfig(shared), okResolver,
                                 "GRUB_TIMEOUT", "grub_test_policy");
        require(policy.apply(), "initial apply must succeed");
        appliedId = testJournal()->activeRecords(policy.ref())[0].id;
    }
    const std::string nonEof =
        "GRUB_TIMEOUT=5\n"
        "\n"
        "# FIC_GRUB_BLOCK_BEGIN version=1\n"
        "GRUB_TIMEOUT=\"0\"\n"
        "# FIC_GRUB_BLOCK_END\n"
        "GRUB_TIMEOUT=5\n";
    writeFile(shared, nonEof);
    const auto repairResolver = makeResolver(repairScript);
    {
        JournalGrubPolicy policy(altConfig(shared), repairResolver,
                                 "GRUB_TIMEOUT", "grub_test_policy");
        require(!policy.apply(), "the pending repair must fail the apply");
    }
    require(readFile(shared) == nonEof,
            "the source compensation must restore the pre-repair source");
    {
        const std::vector<rollback::MutationRecord> records =
            testJournal()->records();
        require(records.size() == 1 && records[0].id == appliedId &&
                    records[0].status ==
                        rollback::MutationStatus::Prepared,
                "CompensatedPendingRebuild must keep the reused record "
                "Prepared (recovery is still required)");
    }
    {
        JournalGrubPolicy policy(altConfig(shared), okResolver,
                                 "GRUB_TIMEOUT", "grub_test_policy");
        require(policy.apply(), "the recovery retry must succeed");
    }
    require(
        readFile(shared) ==
            "GRUB_TIMEOUT=5\n"
            "\n"
            "GRUB_TIMEOUT=5\n"
            "\n"
            "# FIC_GRUB_BLOCK_BEGIN version=1\n"
            "GRUB_TIMEOUT=\"0\"\n"
            "# FIC_GRUB_BLOCK_END\n",
        "the recovery retry must complete the relocation to EOF");
    const std::vector<rollback::MutationRecord> records =
        testJournal()->records();
    require(records.size() == 1 && records[0].id == appliedId &&
                records[0].status == rollback::MutationStatus::Applied,
            "the retry must finish with exactly one Applied record for "
            "the same logical provenance");
}

// T7: Ineffective Prepared is NOT promoted to Applied by the
// reconciliation — the record must still be Prepared immediately before
// the relocation write; only the successful repair (relocation + rebuild
// + fresh EOF proof) commits Applied.
void testIneffectivePreparedNotPromotedBeforeRelocation(
    const fs::path& root, const fs::path& rebuildExecutable) {
    const fs::path testCase = root / "alt-repair-no-promotion";
    const fs::path shared = testCase / "etc/sysconfig/grub2";
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(rebuildExecutable);
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                             "grub_test_policy");
    rollback::MutationId id = 0;
    std::string error;
    rollback::MutationRecord prepared = preparedGrubRecord(
        policy.ref(), "GRUB_TIMEOUT",
        rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "0"});
    require(testJournal()->prepareMutation(prepared, id, error), error);
    writeFile(shared,
              "GRUB_TIMEOUT=5\n"
              "\n"
              "# FIC_GRUB_BLOCK_BEGIN version=1\n"
              "GRUB_TIMEOUT=\"0\"\n"
              "# FIC_GRUB_BLOCK_END\n"
              "GRUB_TIMEOUT=5\n");
    setGrubSharedPreWriteHookForTests([&policy, id]() {
        const std::vector<rollback::MutationRecord> records =
            testJournal()->activeRecords(policy.ref());
        require(records.size() == 1 && records[0].id == id &&
                    records[0].status ==
                        rollback::MutationStatus::Prepared,
                "Ineffective Prepared must NOT be promoted to Applied "
                "before the relocation write");
    });
    struct ClearHook {
        ~ClearHook() { setGrubSharedPreWriteHookForTests({}); }
    } clearHook;
    require(policy.apply(), "the effective repair must succeed");
    const std::vector<rollback::MutationRecord> records =
        testJournal()->records();
    require(records.size() == 1 && records[0].id == id &&
                records[0].status == rollback::MutationStatus::Applied,
            "the repair must commit Applied on the SAME record after the "
            "fresh EOF proof");
}

// T8: Ineffective + value change releases the old ownership WITHOUT an
// intermediate durable Applied promotion, then the fresh value mutation
// leaves exactly one active Applied record for the new value.
void testIneffectiveValueChangeReleasesOwnershipWithoutPromotion(
    const fs::path& root, const fs::path& rebuildExecutable) {
    const fs::path testCase = root / "alt-repair-value-change";
    const fs::path shared = testCase / "etc/sysconfig/grub2";
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(rebuildExecutable);
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                             "grub_test_policy");
    rollback::MutationId oldId = 0;
    std::string error;
    rollback::MutationRecord prepared = preparedGrubRecord(
        policy.ref(), "GRUB_TIMEOUT",
        rollback::UndoRemoveGrubManagedSetting{"GRUB_TIMEOUT", "0"});
    require(testJournal()->prepareMutation(prepared, oldId, error), error);
    writeFile(shared,
              "GRUB_TIMEOUT=5\n"
              "\n"
              "# FIC_GRUB_BLOCK_BEGIN version=1\n"
              "GRUB_TIMEOUT=\"0\"\n"
              "# FIC_GRUB_BLOCK_END\n"
              "GRUB_TIMEOUT=5\n");
    setPolicyConfig(root, {{"grub_test_policy", "5"}});
    JournalGrubPolicy changed(altConfig(shared), resolver, "GRUB_TIMEOUT",
                              "grub_test_policy");
    require(changed.apply(),
            "Ineffective + value change must release the old ownership "
            "and apply the new value");
    require(readFile(shared) ==
                "GRUB_TIMEOUT=5\n"
                "\n"
                "GRUB_TIMEOUT=5\n"
                "\n"
                "# FIC_GRUB_BLOCK_BEGIN version=1\n"
                "GRUB_TIMEOUT=\"5\"\n"
                "# FIC_GRUB_BLOCK_END\n",
            "the old block must be released and the new value installed "
            "at EOF");
    const std::vector<rollback::MutationRecord> records =
        testJournal()->records();
    require(records.size() == 2,
            "the old record must be resolved, not rewritten");
    const rollback::MutationRecord* oldRecord = nullptr;
    const rollback::MutationRecord* activeApplied = nullptr;
    for (const rollback::MutationRecord& record : records) {
        if (record.id == oldId) {
            oldRecord = &record;
        } else if (record.status == rollback::MutationStatus::Applied) {
            activeApplied = &record;
        }
    }
    require(oldRecord != nullptr &&
                oldRecord->status == rollback::MutationStatus::RolledBack,
            "the old record must go straight to RolledBack without an "
            "intermediate durable Applied promotion");
    const auto* oldUndo =
        std::get_if<rollback::UndoRemoveGrubManagedSetting>(
            &oldRecord->undo.payload);
    require(oldUndo != nullptr && oldUndo->appliedValue == "0",
            "the old record payload must stay untouched");
    require(activeApplied != nullptr &&
                activeApplied->id != oldId &&
                testJournal()->activeRecords(prepared.policy).size() == 1,
            "exactly one active Applied record must remain for the new "
            "value");
    const auto* newUndo =
        std::get_if<rollback::UndoRemoveGrubManagedSetting>(
            &activeApplied->undo.payload);
    require(newUndo != nullptr && newUndo->appliedValue == "5",
            "the new record must fingerprint the new applied value");
}

// Wrong-resource provenance is never reused by payload key: a GRUB active
// record for a DIFFERENT journal resource (consistent payload, key
// GRUB_DISABLE_RECOVERY) does not become the repair Prepared record for a
// GRUB_TIMEOUT apply. The apply falls back to a fresh Prepared record for
// its own resource; the foreign-resource record is only touched by the
// normal stale-recovery path (its payload is never rewritten).
void testWrongResourceRecordIsNotReusedByPayloadKey(
    const fs::path& root, const fs::path& rebuildExecutable) {
    const fs::path testCase = root / "alt-wrong-resource-not-reused";
    const fs::path shared = testCase / "etc/sysconfig/grub2";
    JournalOverride journalOverride(
        testCase / "data" / "mutation-journal.json");
    const auto resolver = makeResolver(rebuildExecutable);
    setPolicyConfig(root, {{"grub_test_policy", "0"}});
    JournalGrubPolicy policy(altConfig(shared), resolver, "GRUB_TIMEOUT",
                             "grub_test_policy");
    rollback::MutationId foreignId = 0;
    std::string error;
    rollback::MutationRecord foreign = preparedGrubRecord(
        policy.ref(), "GRUB_DISABLE_RECOVERY",
        rollback::UndoRemoveGrubManagedSetting{"GRUB_DISABLE_RECOVERY",
                                               "true"});
    require(testJournal()->prepareMutation(foreign, foreignId, error), error);
    require(testJournal()->setStatus(
                foreignId, rollback::MutationStatus::Applied, error),
            error);
    writeFile(shared, "GRUB_TIMEOUT=5\n");
    require(policy.apply(),
            "apply must fall back to a fresh record instead of reusing a "
            "wrong-resource record");
    const std::vector<rollback::MutationRecord> records =
        testJournal()->records();
    require(records.size() == 2,
            "a fresh record must be created for the applied resource");
    bool freshTimeoutApplied = false;
    for (const rollback::MutationRecord& record : records) {
        const auto* undo = std::get_if<rollback::UndoRemoveGrubManagedSetting>(
            &record.undo.payload);
        require(undo != nullptr, "grub payload must survive");
        if (record.id == foreignId) {
            // The foreign-resource record may only be resolved by the
            // normal stale-recovery path; its payload must never be
            // rewritten to serve a different resource.
            require(record.resource == "GRUB_DISABLE_RECOVERY" &&
                        undo->key == "GRUB_DISABLE_RECOVERY" &&
                        undo->appliedValue == "true",
                    "the wrong-resource record payload must stay untouched");
        } else {
            require(record.resource == "GRUB_TIMEOUT" &&
                        record.status == rollback::MutationStatus::Applied,
                    "the fresh record for GRUB_TIMEOUT must end Applied");
            freshTimeoutApplied = true;
        }
    }
    require(freshTimeoutApplied,
            "exactly one new Applied record for GRUB_TIMEOUT must exist");
}

int main() {
    try {
        const fs::path root = fs::temp_directory_path() /
            "fic-grub-rollback-journal-tests";
        fs::remove_all(root);
        fs::create_directories(root);

        const fs::path rebuildExecutable = root / "bin/update-grub";
        writeFile(rebuildExecutable, "#!/bin/sh\nexit 0\n", 0755);

        initializeRuntimePaths(root);

        // Pre-seed the command hash store with the sha256 of the fake
        // rebuild script ("#!/bin/sh\nexit 0\n") so that the
        // VerifiedProcessExecutor fallback accepts it without chown.
        writeFile(
            root / "data/commandhash.txt",
            rebuildExecutable.string() +
                "=306c6ca7407560340797866e077e053627ad409277d1b9da58106fce4cf"
                "717cb\n");

        testAltApplyJournalLifecycle(root, rebuildExecutable);
        testEmptyPolicyValueAppliedSurvivesRestartLikeReload(
            root, rebuildExecutable);
        testAltValueChange(root, rebuildExecutable);
        testAltPreparedRecoveryAfter(root, rebuildExecutable);
        testAltPreparedRecoveryBefore(root, rebuildExecutable);
        testAltPreparedRecoveryDrift(root, rebuildExecutable);
        testAltRollbackLifecycle(root, rebuildExecutable);
        testAltRollbackConflict(root, rebuildExecutable);
        testAltCrashAfterSourceRollback(root, rebuildExecutable);
        testDebianApplyJournalLifecycle(root, rebuildExecutable);
        testDebianPreparedRecovery(root, rebuildExecutable);
        testDebianRollbackLifecycle(root, rebuildExecutable);
        testDebianRollbackNothingToDoAndConflict(root, rebuildExecutable);
        testRollbackRebuildFailureCompensation(root, rebuildExecutable);
        testDebianReconciliationUnsafeBaseDefaults(root, rebuildExecutable);
        testAltApplyStaleReadCasRace(root, rebuildExecutable);
        testAltRollbackStaleReadCasRace(root, rebuildExecutable);
        testAltIdempotentApplyStaleSnapshot(root, rebuildExecutable);
        testUnsafeManagedArtifactsAreNotMissing(root, rebuildExecutable);
        testDebianInitiallyMissingCompensationRetainsDropIn(root);
        testDebianInitiallyMissingCompensationConcurrentReplacement(root);
        testAltChangedApplyDriftDuringRebuild(root);
        testAltChangedForeignTailDuringRebuild(root);
        testDebianChangedApplyDriftDuringRebuild(root);
        testAltIdempotentDriftDuringRebuild(root);
        testAltIdempotentForeignTailDuringRebuild(root);
        testDebianIdempotentDriftDuringRebuild(root);
        testReconciliationDriftAfterRebuild(root);
        testAltSameValueNotEofRelocation(root, rebuildExecutable);
        testAltRollbackNonEofOwnedBlock(root, rebuildExecutable);
        testDebianDoubleRebuildFailureKeepsPrepared(root);
        testAltDoubleRebuildFailureKeepsPrepared(root);
        testDebianInitiallyMissingCompensationPendingRebuild(root);
        testExistingAppliedSameValueRepairSucceeds(root, rebuildExecutable);
        testExistingAppliedRelocationCasFailureRestoresProvenance(
            root, rebuildExecutable);
        testExistingAppliedFullCompensationRestoresApplied(root);
        testExistingPreparedSurvivesCompensatedRepair(root);
        testExistingRollbackFailedSurvivesCompensatedRepair(root);
        testExistingAppliedPendingRepairStaysPrepared(root);
        testIneffectivePreparedNotPromotedBeforeRelocation(
            root, rebuildExecutable);
        testIneffectiveValueChangeReleasesOwnershipWithoutPromotion(
            root, rebuildExecutable);
        testWrongResourceRecordIsNotReusedByPayloadKey(root, rebuildExecutable);
    } catch (const std::exception& exception) {
        std::cerr << "GrubRollbackJournalTests failed: " << exception.what()
                  << std::endl;
        return 1;
    }
    std::cout << "GrubRollbackJournalTests passed" << std::endl;
    return 0;
}

