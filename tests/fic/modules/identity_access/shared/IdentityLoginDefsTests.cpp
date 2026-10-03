#include "modules/identity_access/shared/login_defs/IdentityLoginDefsManagedConfig.h"
#include "modules/identity_access/shared/login_defs/IdentityLoginDefsManagedTransaction.h"
#include "rollback/DaemonMutationJournal.h"
#include "rollback/RollbackExecutor.h"

#include <fic/core/runtime/FicRuntimePaths.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <utility>
#include <vector>

namespace {
namespace fs = std::filesystem;
using namespace fic::identity::login_defs;
using fic::rollback::MutationBackend;
using fic::rollback::MutationJournal;
using fic::rollback::MutationRecord;
using fic::rollback::MutationStatus;
using fic::rollback::RollbackEnrollment;

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
        root / "data/identity-login-defs-mutations.json");
}

void useJournal(const fs::path& root, const std::string& name) {
    fic::rollback::DaemonMutationJournal::instance().setOverridePath(
        root / ("data/" + name + ".json"));
}

const std::string kForeign =
    "# login.defs foreign header\nPASS_MAX_DAYS 99999\nPASS_WARN_AGE 7\n"
    "UID_MIN 1000\nUID_MAX 60000\n";

PolicyRef aging(const char* policy) {
    return {"IDENTITY_ACCESS", "PASSWORD_AGING", policy};
}

PolicyRef creation(const char* policy) {
    return {"IDENTITY_ACCESS", "USER_CREATION", policy};
}

bool containsSubBlock(const std::string& content, const PolicyRef& policy,
                      const std::string& line) {
    const std::string begin = std::string(kPolicyBegin) +
        policy.moduleName + "/" + policy.submoduleName + "/" +
        policy.policyName + "@";
    const std::string end = std::string(kPolicyEnd) +
        policy.moduleName + "/" + policy.submoduleName + "/" +
        policy.policyName + "@";
    const std::size_t at = content.find(begin);
    return at != std::string::npos &&
        content.find(end, at) != std::string::npos &&
        content.find("\n" + line + "\n", at) < content.find(end, at);
}

MutationJournal& journal() {
    std::string error;
    auto* instance = fic::rollback::DaemonMutationJournal::instance().tryGet(
        error);
    if (instance == nullptr) throw std::runtime_error(error);
    return *instance;
}

void testEffectiveReader() {
    std::string error;
    std::optional<std::string> value;
    require(effectiveValue("PASS_MIN_DAYS 0\n    PASS_MIN_DAYS 3\n",
                "PASS_MIN_DAYS", value, error) &&
                value.has_value() && *value == "3",
            "leading-space assignment was not authoritative (last-wins)");
    require(effectiveValue("PASS_MIN_DAYS 0\n\tPASS_MIN_DAYS 5\n",
                "PASS_MIN_DAYS", value, error) && *value == "5",
            "leading-tab assignment was not authoritative (last-wins)");
    require(effectiveValue("# PASS_MIN_DAYS 9\nPASS_MIN_DAYS 1\n",
                "PASS_MIN_DAYS", value, error) && *value == "1",
            "comment was treated as an assignment");
    require(effectiveValue("PASS_MIN_DAYS 1\nPASS_MIN_DAYS   \n",
                "PASS_MIN_DAYS", value, error) && *value == "1",
            "no-value assignment replaced an earlier effective value");
    require(effectiveValue("OTHER foo\n\n   \nPASS_WARN_AGE 12\n",
                "PASS_WARN_AGE", value, error) && *value == "12",
            "blank/other lines broke the effective read");
    require(!effectiveValue("PASS_MIN_DAYS 1 2\n", "PASS_MIN_DAYS", value,
                error) && !error.empty(),
            "malformed target-like assignment was not fail-closed");
    error.clear();
    require(!effectiveValue("PASS_MIN_DAYS # none\n", "PASS_MIN_DAYS", value,
                error),
            "comment-only value was accepted");
    error.clear();
    require(effectiveValue("UID_MIN\n", "UID_MIN", value, error) &&
                !value.has_value(),
            "bare key without value was treated as an assignment");
}

void testPolicyTable() {
    std::string error;
    PolicyRoute route;
    require(policyRoute("/etc/login.defs", aging("password_max_age_days"),
                route, error) &&
                route.key == "PASS_MAX_DAYS" && route.path == "/etc/login.defs",
            error);
    error.clear();
    require(!policyRoute("/etc/login.defs",
                {"IDENTITY_ACCESS", "PASSWORD_AGING", "unknown_policy"},
                route, error),
            "unknown policy was routed");
    error.clear();
    require(validatePolicyValue(creation("user_create_home"), "yes", error) &&
                validatePolicyValue(creation("user_create_home"), "no", error),
            error);
    error.clear();
    require(validatePolicyValue(aging("password_min_age_days"), "0", error) &&
                !validatePolicyValue(aging("password_min_age_days"), "-1",
                    error),
            "PASS_MIN_DAYS value domain is wrong");
    error.clear();
    require(validatePolicyValue(aging("password_max_age_days"), "-1", error) &&
                validatePolicyValue(aging("password_expiration_warning_days"),
                    "-1", error),
            "unlimited PASS values were rejected");
    error.clear();
    require(validatePolicyValue(aging("regular_user_uid_min"), "4294967295",
                error),
            "full uid_t range was rejected");
    error.clear();
    require(!validatePolicyValue(aging("regular_user_uid_max"), "4294967296",
                error),
            "value beyond uid_t was accepted");
    error.clear();
    require(!validatePolicyValue(aging("password_min_age_days"), "007", error),
            "non-canonical decimal was accepted");
    error.clear();
    require(!validatePolicyValue(creation("user_create_home"), "maybe", error),
            "non-boolean CREATE_HOME value was accepted");
    error.clear();
}

void testGrammar() {
    const std::string ref0 = "IDENTITY_ACCESS/USER_CREATION/user_create_home";
    const std::string ref1 =
        "IDENTITY_ACCESS/PASSWORD_AGING/password_min_age_days";
    const std::string container =
        std::string("# before\n") + kBlockBegin + "\n" +
        canonicalPolicyBlock(ref0, "CREATE_HOME", "no") +
        canonicalPolicyBlock(ref1, "PASS_MIN_DAYS", "3") + kBlockEnd + "\n";
    ManagedConfigModel model;
    std::string error;
    require(parseManagedConfig("foreign\n" + container, model, error), error);
    require(model.blockPresent && model.policies.size() == 2 &&
                model.policies[0].policyRef == ref0 &&
                model.policies[0].key == "CREATE_HOME" &&
                model.policies[0].value == "no",
            "valid container was not parsed");
    require(model.policies[0].raw == canonicalPolicyBlock(ref0,
                "CREATE_HOME", "no"),
            "sub-block raw was not preserved byte-exact");

    const auto expectParseFailure = [&](const std::string& content,
                                        const std::string& label) {
        ManagedConfigModel broken;
        std::string brokenError;
        require(!parseManagedConfig(content, broken, brokenError) &&
                    !brokenError.empty(),
            label);
    };
    expectParseFailure(std::string(kBlockBegin) + "\n" +
                           canonicalPolicyBlock(ref0, "CREATE_HOME", "no") +
                           canonicalPolicyBlock(ref0, "CREATE_HOME", "yes") +
                           kBlockEnd + "\n",
        "duplicate policy sub-block was accepted");
    expectParseFailure(std::string(kBlockBegin) + "\n" + kPolicyBegin + ref0 +
                           "@\n" + kPolicyEnd + ref0 + "@\n" + kBlockEnd + "\n",
        "empty sub-block was accepted");
    expectParseFailure(std::string(kBlockBegin) + "\n" + kPolicyBegin + ref0 +
                           "@\nCREATE_HOME no\nCREATE_HOME yes\n" +
                           kPolicyEnd + ref0 + "@\n" + kBlockEnd + "\n",
        "second assignment was accepted");
    expectParseFailure(
        std::string(kBlockBegin) + "\nforeign line\n" + kBlockEnd + "\n",
        "foreign content inside the container was accepted");
    expectParseFailure("#@FIC_UNKNOWN_MARKER@\n",
        "unknown FIC marker was accepted");
    expectParseFailure(
        std::string(kBlockBegin) + "\n" + kPolicyBegin + ref0 + "@\n",
        "dangling marker was accepted");
}

void testValueValidation() {
    std::string error;
    require(validatePolicyValue(aging("regular_user_uid_min"), "4294967295",
                error),
            "full uid_t range was rejected");
    error.clear();
    require(!validatePolicyValue(aging("password_min_age_days"), "007", error),
            "non-canonical decimal was accepted");
    error.clear();
    require(!validatePolicyValue(aging("password_max_age_days"), "1 ", error),
            "value with trailing whitespace was accepted");
    error.clear();
    require(!validatePolicyValue(creation("user_create_home"), "maybe", error),
            "non-boolean CREATE_HOME value was accepted");
}

void testApplyLifecycle(const fs::path& root) {
    useJournal(root, "login-defs-lifecycle");
    const fs::path path = root / "etc/login.defs";
    writeFile(path, kForeign);
    std::string error;
    auto& j = journal();

    // Multi-policy shared container: one FIC block for two submodules.
    require(applyManagedPolicy(path.string(), creation("user_create_home"),
                "no", j, {}, error), error);
    require(applyManagedPolicy(path.string(), aging("password_min_age_days"),
                "1", j, {}, error), error);
    const std::string applied = readFile(path);
    require(applied.rfind(kForeign) == 0,
            "foreign bytes changed during apply");
    require(applied.find(std::string(kBlockBegin)) != std::string::npos &&
                applied.rfind(std::string(kBlockEnd) + "\n") ==
                    applied.size() - std::string(kBlockEnd).size() - 1,
            "container is not at the logical EOF");
    require(containsSubBlock(applied, creation("user_create_home"),
                "CREATE_HOME no") &&
                containsSubBlock(applied, aging("password_min_age_days"),
                    "PASS_MIN_DAYS 1"),
            "shared container does not hold both policy sub-blocks");
    require(j.activeRecords(creation("user_create_home")).size() == 1 &&
                j.activeRecords(aging("password_min_age_days")).size() == 1,
            "apply did not record Applied provenance");

    // Refresh A->B is ONE physical replacement.
    int writes = 0;
    setBeforeIdentityLoginDefsWriteHookForTests([&] { ++writes; });
    require(applyManagedPolicy(path.string(), aging("password_min_age_days"),
                "3", j, {}, error), error);
    setBeforeIdentityLoginDefsWriteHookForTests({});
    require(writes == 1, "refresh A->B was not one atomic replacement");
    const std::string refreshed = readFile(path);
    require(containsSubBlock(refreshed, aging("password_min_age_days"),
                "PASS_MIN_DAYS 3") &&
                refreshed.find("PASS_MIN_DAYS 1") == std::string::npos,
            "refresh did not replace the owned line");
    ManagedConfigModel model;
    require(parseManagedConfig(refreshed, model, error), error);
    require(model.policies.size() == 2 &&
                model.policies[0].raw == canonicalPolicyBlock(
                    "IDENTITY_ACCESS/USER_CREATION/user_create_home",
                    "CREATE_HOME", "no"),
            "peer sub-block was not preserved byte-for-byte");

    // Idempotent no-op performs no physical write.
    const std::string beforeNoop = readFile(path);
    setBeforeIdentityLoginDefsWriteHookForTests(
        [&] { require(false, "no-op performed a physical write"); });
    require(applyManagedPolicy(path.string(), aging("password_min_age_days"),
                "3", j, {}, error), error);
    setBeforeIdentityLoginDefsWriteHookForTests({});
    require(readFile(path) == beforeNoop, "no-op changed the file");

    // Compliant foreign state is never adopted (no container, no record).
    writeFile(path, "PASS_MIN_DAYS 3\nPASS_MAX_DAYS 99999\n");
    useJournal(root, "login-defs-foreign");
    auto& foreignJournal = journal();
    require(applyManagedPolicy(path.string(), aging("password_min_age_days"),
                "3", foreignJournal, {}, error), error);
    require(readFile(path) == "PASS_MIN_DAYS 3\nPASS_MAX_DAYS 99999\n",
            "compliant foreign state was adopted into FIC ownership");
    require(foreignJournal.activeRecords(aging("password_min_age_days"))
                    .empty(),
            "compliant foreign state was journaled");
}

void testReleaseAndRelations(const fs::path& root) {
    useJournal(root, "login-defs-release");
    const fs::path path = root / "etc/login.defs";
    std::string error;

    writeFile(path,
        "PASS_MAX_DAYS 99999\nPASS_WARN_AGE 7\nUID_MIN 1000\nUID_MAX 60000\n");
    auto& j = journal();
    require(applyManagedPolicy(path.string(), creation("user_create_home"),
                "no", j, {}, error), error);
    require(applyManagedPolicy(path.string(), aging("password_min_age_days"),
                "1", j, {}, error), error);
    const auto minRecords = j.activeRecords(aging("password_min_age_days"));
    require(minRecords.size() == 1, "min provenance missing");
    require(releaseManagedPolicy(path.string(), minRecords.front(), j, {},
                error) == ReleaseStatus::Success, error);
    const std::string released = readFile(path);
    require(released.find("PASS_MIN_DAYS") == std::string::npos &&
                containsSubBlock(released, creation("user_create_home"),
                    "CREATE_HOME no"),
            "release damaged peer ownership or lost owned state");

    const auto homeRecords = j.activeRecords(creation("user_create_home"));
    require(homeRecords.size() == 1, "home provenance missing");
    require(releaseManagedPolicy(path.string(), homeRecords.front(), j, {},
                error) == ReleaseStatus::Success, error);
    const std::string emptied = readFile(path);
    require(emptied ==
                "PASS_MAX_DAYS 99999\nPASS_WARN_AGE 7\nUID_MIN 1000\n"
                "UID_MAX 60000\n",
        "last policy release did not remove the whole container");
    require(releaseManagedPolicy(path.string(), homeRecords.front(), j, {},
                error) == ReleaseStatus::NothingToDo,
        "second release after removal was not NothingToDo");

    // Rollback candidate relation validation: releasing the FIC
    // PASS_MAX_DAYS value would resurrect an invalid foreign relation.
    writeFile(path,
        "PASS_MIN_DAYS 10\nPASS_MAX_DAYS 5\nPASS_WARN_AGE 7\n"
        "UID_MIN 1000\nUID_MAX 60000\n");
    useJournal(root, "login-defs-release-relation");
    auto& relationJournal = journal();
    require(applyManagedPolicy(path.string(), aging("password_max_age_days"),
                "90", relationJournal, {}, error), error);
    const auto maxRecords =
        relationJournal.activeRecords(aging("password_max_age_days"));
    require(maxRecords.size() == 1, "max provenance missing");
    const std::string beforeFailedRelease = readFile(path);
    require(releaseManagedPolicy(path.string(), maxRecords.front(),
                relationJournal, {}, error) == ReleaseStatus::Conflict,
            "invalid rollback relation was accepted");
    require(readFile(path) == beforeFailedRelease,
            "failed relation release changed the file");
}

void testDriftAndOrphans(const fs::path& root) {
    useJournal(root, "login-defs-drift");
    const fs::path path = root / "etc/login.defs";
    writeFile(path, kForeign);
    std::string error;
    auto& j = journal();
    require(applyManagedPolicy(path.string(), aging("password_min_age_days"),
                "1", j, {}, error), error);

    // Manual edit of the FIC-owned line: apply fails closed, file untouched.
    std::string drifted = readFile(path);
    const std::size_t at = drifted.find("\nPASS_MIN_DAYS 1\n");
    require(at != std::string::npos, "owned line missing");
    drifted.replace(at, std::string("\nPASS_MIN_DAYS 1\n").size(),
        "\nPASS_MIN_DAYS 9\n");
    writeFile(path, drifted);
    const std::string beforeApply = readFile(path);
    require(!applyManagedPolicy(path.string(), aging("password_min_age_days"),
                "3", j, {}, error) && readFile(path) == beforeApply,
            "manual FIC body edit was overwritten");

    // Orphan same-policy sub-block without provenance.
    useJournal(root, "login-defs-orphan");
    auto& orphanJournal = journal();
    const std::string orphan = kForeign + std::string(kBlockBegin) + "\n" +
        canonicalPolicyBlock("IDENTITY_ACCESS/PASSWORD_AGING/"
                             "password_min_age_days",
            "PASS_MIN_DAYS", "3") + kBlockEnd + "\n";
    writeFile(path, orphan);
    require(!applyManagedPolicy(path.string(), aging("password_min_age_days"),
                "3", orphanJournal, {}, error),
            "orphan ownership was adopted");
    std::string inspectError;
    require(inspectUnrecordedState(path.string(),
                aging("password_min_age_days"), inspectError) ==
                InspectStatus::Conflict,
            "orphan sub-block was not reported as Conflict");

    // Clean file: no-record inspection is NothingToDo.
    writeFile(path, kForeign);
    inspectError.clear();
    require(inspectUnrecordedState(path.string(),
                aging("password_min_age_days"), inspectError) ==
                InspectStatus::NothingToDo,
            inspectError);
    // Malformed container fails closed.
    writeFile(path, std::string(kBlockBegin) + "\nbroken\n");
    require(inspectUnrecordedState(path.string(),
                aging("password_min_age_days"), inspectError) ==
                InspectStatus::Conflict,
            "malformed container was accepted");
}

void testCrashRecovery(const fs::path& root) {
    const fs::path path = root / "etc/login.defs";
    const std::string ref =
        "IDENTITY_ACCESS/PASSWORD_AGING/password_min_age_days";

    // Fresh Prepared never written -> discarded on the next apply.
    useJournal(root, "login-defs-crash-fresh");
    writeFile(path, kForeign);
    std::string error;
    auto& j = journal();
    MutationRecord record;
    record.policy = aging("password_min_age_days");
    record.resource = path.string();
    record.undo = {MutationBackend::IdentityLoginDefs,
        fic::rollback::UndoRemoveIdentityLoginDefsManagedPolicy{
            "password_min_age_days", path.string(), "PASS_MIN_DAYS",
            "PASS_MIN_DAYS 1", ""}};
    fic::rollback::MutationId id = 0;
    require(j.prepareMutation(record, id, error), error);
    require(applyManagedPolicy(path.string(), aging("password_min_age_days"),
                "1", j, {}, error), error);
    const auto records = j.activeRecords(aging("password_min_age_days"));
    require(records.size() == 1 &&
                records.front().status == MutationStatus::Applied,
            "fresh Prepared was not recovered into Applied");

    // Prepared at the durable TARGET (crash after the write) -> completed
    // without another physical write.
    useJournal(root, "login-defs-crash-target");
    writeFile(path, kForeign + std::string(kBlockBegin) + "\n" +
            canonicalPolicyBlock(ref, "PASS_MIN_DAYS", "3") + kBlockEnd +
            "\n");
    auto& targetJournal = journal();
    record = MutationRecord{};
    record.policy = aging("password_min_age_days");
    record.resource = path.string();
    record.undo = {MutationBackend::IdentityLoginDefs,
        fic::rollback::UndoRemoveIdentityLoginDefsManagedPolicy{
            "password_min_age_days", path.string(), "PASS_MIN_DAYS",
            "PASS_MIN_DAYS 3", ""}};
    require(targetJournal.prepareMutation(record, id, error), error);
    setBeforeIdentityLoginDefsWriteHookForTests(
        [&] { require(false, "recovery performed a physical write"); });
    require(applyManagedPolicy(path.string(), aging("password_min_age_days"),
                "3", targetJournal, {}, error), error);
    setBeforeIdentityLoginDefsWriteHookForTests({});
    const auto targetRecords =
        targetJournal.activeRecords(aging("password_min_age_days"));
    require(targetRecords.size() == 1 &&
                targetRecords.front().status == MutationStatus::Applied,
            "durable target Prepared was not completed");

    // Refresh Prepared sitting on the PREVIOUS side -> the refresh continues.
    useJournal(root, "login-defs-crash-refresh");
    writeFile(path, kForeign);
    auto& refreshJournal = journal();
    require(applyManagedPolicy(path.string(), aging("password_min_age_days"),
                "1", refreshJournal, {}, error), error);
    record = MutationRecord{};
    record.policy = aging("password_min_age_days");
    record.resource = path.string();
    record.undo = {MutationBackend::IdentityLoginDefs,
        fic::rollback::UndoRemoveIdentityLoginDefsManagedPolicy{
            "password_min_age_days", path.string(), "PASS_MIN_DAYS",
            "PASS_MIN_DAYS 5", "PASS_MIN_DAYS 1"}};
    require(refreshJournal.prepareMutation(record, id, error), error);
    require(applyManagedPolicy(path.string(), aging("password_min_age_days"),
                "5", refreshJournal, {}, error), error);
    const auto refreshRecords =
        refreshJournal.activeRecords(aging("password_min_age_days"));
    require(refreshRecords.size() == 1 &&
                refreshRecords.front().status == MutationStatus::Applied &&
                std::get_if<
                    fic::rollback::UndoRemoveIdentityLoginDefsManagedPolicy>(
                    &refreshRecords.front().undo.payload)
                    ->previousAppliedLine == "PASS_MIN_DAYS 1",
            "prepared refresh did not carry the previous side to Applied");

    // Unresolved refresh on a third physical state fails closed.
    writeFile(path, kForeign);
    useJournal(root, "login-defs-crash-third");
    auto& thirdJournal = journal();
    require(applyManagedPolicy(path.string(), aging("password_min_age_days"),
                "1", thirdJournal, {}, error), error);
    record = MutationRecord{};
    record.policy = aging("password_min_age_days");
    record.resource = path.string();
    record.undo = {MutationBackend::IdentityLoginDefs,
        fic::rollback::UndoRemoveIdentityLoginDefsManagedPolicy{
            "password_min_age_days", path.string(), "PASS_MIN_DAYS",
            "PASS_MIN_DAYS 5", "PASS_MIN_DAYS 1"}};
    require(thirdJournal.prepareMutation(record, id, error), error);
    std::string tampered = readFile(path);
    tampered.replace(tampered.find("\nPASS_MIN_DAYS 1\n"),
        std::string("\nPASS_MIN_DAYS 1\n").size(), "\nPASS_MIN_DAYS 7\n");
    writeFile(path, tampered);
    require(!applyManagedPolicy(path.string(), aging("password_min_age_days"),
                "5", thirdJournal, {}, error),
            "third-state unresolved Prepared was not fail-closed");
}

void testCasAndCompensation(const fs::path& root) {
    const fs::path path = root / "etc/login.defs";

    // CAS race: an external writer between capture and install fails the
    // apply without touching the winner's content; fresh provenance is
    // discarded.
    useJournal(root, "login-defs-cas");
    writeFile(path, kForeign);
    std::string error;
    auto& j = journal();
    setBeforeIdentityLoginDefsWriteHookForTests([&] {
        writeFile(path, "PASS_MAX_DAYS 1\n");
    });
    require(!applyManagedPolicy(path.string(), aging("password_min_age_days"),
                "1", j, {}, error),
            "concurrent replacement bypassed CAS");
    setBeforeIdentityLoginDefsWriteHookForTests({});
    require(readFile(path) == "PASS_MAX_DAYS 1\n",
            "CAS failure overwrote the external writer");
    require(j.activeRecords(aging("password_min_age_days")).empty(),
            "failed fresh apply kept provenance");

    // Compensation failure leaves recoverable Prepared provenance: tamper
    // the installed state before the postcondition verify, then prove the
    // durable-target recovery path.
    useJournal(root, "login-defs-compensation");
    writeFile(path, kForeign);
    auto& compensationJournal = journal();
    setAfterIdentityLoginDefsWriteHookForTests([&] {
        std::string content = readFile(path);
        content.insert(0, "PASS_WARN_AGE 42\n");
        writeFile(path, content);
    });
    require(!applyManagedPolicy(path.string(), aging("password_min_age_days"),
                "1", compensationJournal, {}, error),
            "tampered postcondition was accepted");
    setAfterIdentityLoginDefsWriteHookForTests({});
    const auto pending =
        compensationJournal.activeRecords(aging("password_min_age_days"));
    require(pending.size() == 1 &&
                pending.front().status == MutationStatus::Prepared,
            "compensation failure did not keep recoverable provenance");
    // The physical write did actually land: restore the exact durable target
    // state and prove the crash-after-write recovery completes the record.
    std::string healed = readFile(path);
    healed.erase(0, std::string("PASS_WARN_AGE 42\n").size());
    writeFile(path, healed);
    require(applyManagedPolicy(path.string(), aging("password_min_age_days"),
                "1", compensationJournal, {}, error), error);
    const auto healedRecords =
        compensationJournal.activeRecords(aging("password_min_age_days"));
    require(healedRecords.size() == 1 &&
                healedRecords.front().status == MutationStatus::Applied,
            "durable-target recovery did not complete the transaction");
}

void testJournalGuards(const fs::path& root) {
    const fs::path path = root / "etc/login.defs";
    const auto makePayload = [&](const std::string& target,
                                 const std::string& previous) {
        return fic::rollback::UndoRemoveIdentityLoginDefsManagedPolicy{
            "password_min_age_days", path.string(), "PASS_MIN_DAYS", target,
            previous};
    };
    const auto makeRecord = [&](const std::string& target,
                                const std::string& previous) {
        MutationRecord record;
        record.policy = aging("password_min_age_days");
        record.resource = path.string();
        record.undo = {MutationBackend::IdentityLoginDefs,
            makePayload(target, previous)};
        return record;
    };

    useJournal(root, "login-defs-journal");
    writeFile(path, kForeign);
    std::string error;
    auto& j = journal();

    // A fresh record must not claim a previous applied line.
    fic::rollback::MutationId id = 0;
    require(!j.prepareMutation(makeRecord("PASS_MIN_DAYS 1",
              "PASS_MIN_DAYS 0"), id, error),
        "fresh record with previous state was accepted");

    // Applied provenance: refresh must carry the currently owned line as
    // the previous state.
    require(j.prepareMutation(makeRecord("PASS_MIN_DAYS 1", ""), id, error),
        error);
    require(j.setStatus(id, MutationStatus::Applied, error), error);
    require(!j.prepareMutation(makeRecord("PASS_MIN_DAYS 5",
              "PASS_MIN_DAYS 9"), id, error),
        "refresh with a foreign previous state was accepted");
    require(j.prepareMutation(makeRecord("PASS_MIN_DAYS 5",
              "PASS_MIN_DAYS 1"), id, error), error);

    // Unresolved Prepared must be recovered, never silently replaced.
    require(!j.prepareMutation(makeRecord("PASS_MIN_DAYS 7", ""), id, error),
        "unresolved Prepared was replaced by ordinary apply");

    // Durable previous-side normalization.
    require(j.normalizeIdentityLoginDefsPreparedToProvenState(id,
                "PASS_MIN_DAYS 1", error), error);
    const auto normalized = j.activeRecords(aging("password_min_age_days"));
    require(normalized.size() == 1 &&
                normalized.front().status == MutationStatus::Prepared &&
                normalized.front().undo.backend ==
                    MutationBackend::IdentityLoginDefs,
            error);
    const auto* payload = std::get_if<
        fic::rollback::UndoRemoveIdentityLoginDefsManagedPolicy>(
        &normalized.front().undo.payload);
    require(payload != nullptr && payload->appliedLine == "PASS_MIN_DAYS 1" &&
                payload->previousAppliedLine.empty(),
            "normalization did not collapse the transition to the "
            "proven state");

    // Round-trip through the persistent document (write/read parity).
    require(j.setStatus(id, MutationStatus::Applied, error), error);
    const fs::path journalPath = root / "data/login-defs-journal.json";
    MutationJournal reloader(journalPath);
    std::string reloadError;
    require(reloader.load(reloadError), reloadError);
    const auto records = reloader.activeRecords(aging("password_min_age_days"));
    require(records.size() == 1 &&
                records.front().status == MutationStatus::Applied &&
                records.front().undo.backend ==
                    MutationBackend::IdentityLoginDefs &&
                std::get_if<
                    fic::rollback::UndoRemoveIdentityLoginDefsManagedPolicy>(
                    &records.front().undo.payload)->appliedLine ==
                    "PASS_MIN_DAYS 1",
            "identity_login_defs payload did not survive a journal reload");

    // Corrupted persisted values fail closed on load.
    std::string document = readFile(journalPath);
    const std::size_t at = document.find("PASS_MIN_DAYS 1");
    require(at != std::string::npos, "applied line missing from document");
    document.replace(at, std::string("PASS_MIN_DAYS 1").size(),
        "PASS_MIN_DAYS 0001");
    writeFile(journalPath, document, 0600);
    MutationJournal validator(journalPath);
    std::string loadError;
    require(!validator.load(loadError) && !loadError.empty(),
            "corrupted canonical value was accepted on load");
}

void testRollbackExecutorIntegration(const fs::path& root) {
    const fs::path path = root / "etc/login.defs";

    // Static enrollment matrix: five scalars Supported, two operational
    // NotEnrolled, unknown Unsupported.
    require(fic::rollback::rollbackEnrollment(aging("password_min_age_days")) ==
                RollbackEnrollment::Supported &&
                fic::rollback::rollbackEnrollment(
                    aging("password_max_age_days")) ==
                    RollbackEnrollment::Supported &&
                fic::rollback::rollbackEnrollment(
                    aging("password_expiration_warning_days")) ==
                    RollbackEnrollment::Supported &&
                fic::rollback::rollbackEnrollment(
                    aging("regular_user_uid_min")) ==
                    RollbackEnrollment::Supported &&
                fic::rollback::rollbackEnrollment(
                    aging("regular_user_uid_max")) ==
                    RollbackEnrollment::Supported,
            "scalar PASSWORD_AGING enrollment is wrong");
    require(fic::rollback::rollbackEnrollment(
                aging("password_aging_apply_to_existing_accounts")) ==
                RollbackEnrollment::NotEnrolled &&
                fic::rollback::rollbackEnrollment(
                    aging("password_aging_enforce_for_root")) ==
                    RollbackEnrollment::NotEnrolled,
            "operational PASSWORD_AGING enrollment is wrong");
    require(fic::rollback::rollbackEnrollment(
                aging("password_aging_unknown")) ==
                RollbackEnrollment::Unsupported,
            "unknown PASSWORD_AGING enrollment is wrong");

    // Executor dispatch: rollback releases the FIC sub-block through the
    // journal record and preserves peer ownership.
    useJournal(root, "login-defs-executor");
    writeFile(path, kForeign);
    std::string error;
    auto& j = journal();
    require(applyManagedPolicy(path.string(), creation("user_create_home"),
                "no", j, {}, error), error);
    require(applyManagedPolicy(path.string(), aging("password_min_age_days"),
                "1", j, {}, error), error);
    fic::rollback::RollbackExecutorDeps deps;
    deps.userCreationPlatform.loginDefsPath = path;
    deps.passwordAgingPlatform.loginDefsPath = path;
    deps.passwordAgingPlatform.missingKeySemantics.minDays = -1;
    deps.passwordAgingPlatform.missingKeySemantics.maxDays = -1;
    const fic::rollback::RollbackReport report = fic::rollback::
        rollbackPolicyBeforeDisable(aging("password_min_age_days"),
            "PASS_MIN_DAYS", deps);
    require(report.rollbackCompleted() &&
                report.outcomes.size() == 1 &&
                report.outcomes.front().status ==
                    fic::rollback::RollbackStatus::Success,
            report.message);
    const std::string rolledBack = readFile(path);
    require(rolledBack.find("PASS_MIN_DAYS") == std::string::npos &&
                containsSubBlock(rolledBack, creation("user_create_home"),
                    "CREATE_HOME no"),
            "executor rollback damaged the shared container");
    require(j.activeRecords(aging("password_min_age_days")).empty(),
            "rolled back record is still active");

    // No-record rollback of a clean file is NothingToDo.
    writeFile(path, kForeign);
    const fic::rollback::RollbackReport noRecord = fic::rollback::
        rollbackPolicyBeforeDisable(aging("password_min_age_days"),
            "PASS_MIN_DAYS", deps);
    require(noRecord.rollbackCompleted() &&
                noRecord.status == fic::rollback::RollbackStatus::NothingToDo,
            noRecord.message);
}

} // namespace

int main() {
    const std::unique_ptr<fs::path> created = [] {
        const std::string base = (fs::temp_directory_path() /
            "fic-identity-login-defs-tests-XXXXXX").string();
        std::vector<char> buffer(base.begin(), base.end());
        buffer.push_back('\0');
        const char* result = ::mkdtemp(buffer.data());
        if (result == nullptr) return std::unique_ptr<fs::path>();
        return std::make_unique<fs::path>(result);
    }();
    require(created != nullptr, "cannot create unique test directory");
    const fs::path& root = *created;

    try {
        initializePaths(root);
        testEffectiveReader();
        testPolicyTable();
        testGrammar();
        testValueValidation();
        testApplyLifecycle(root);
        testReleaseAndRelations(root);
        testDriftAndOrphans(root);
        testCrashRecovery(root);
        testCasAndCompensation(root);
        testJournalGuards(root);
        testRollbackExecutorIntegration(root);
    } catch (const std::exception& error) {
        std::cerr << "IdentityLoginDefsTests failed: " << error.what() << '\n';
        return 1;
    }
    std::cout << "IdentityLoginDefsTests passed\n";
    return 0;
}