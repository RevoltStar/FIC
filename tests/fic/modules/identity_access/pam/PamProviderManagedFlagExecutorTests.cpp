// Step 7E: PamProviderManagedFlagExecutor lifecycle tests.
#include "modules/identity_access/pam/PamProviderManagedFlagExecutor.h"

#include "modules/identity_access/pam/PamProviderManagedBlock.h"
#include "modules/identity_access/pam/PamProviderManagedBlockFile.h"
#include "platform/PlatformProfile.h"
#include "rollback/MutationJournal.h"
#include "rollback/MutationRecord.h"

#include <sys/stat.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace fic::identity::pam;
using fic::platform::PamProviderKind;
using fic::rollback::MutationId;
using fic::rollback::MutationJournal;
using fic::rollback::MutationRecord;
using fic::rollback::MutationStatus;
using fic::rollback::UndoAction;
using fic::rollback::UndoRemovePamProviderManagedFlag;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class TempDir {
public:
    TempDir() {
        char pattern[] = "/tmp/fic-pam-flag-executor-XXXXXX";
        char* created = ::mkdtemp(pattern);
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        directory = created;
    }
    ~TempDir() {
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
    }
    std::filesystem::path directory;
};

std::string readFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

void writeFile(const std::filesystem::path& path, const std::string& content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << content;
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

std::size_t countOccurrences(const std::string& haystack,
    const std::string& needle) {
    std::size_t count = 0;
    std::size_t from = 0;
    while ((from = haystack.find(needle, from)) != std::string::npos) {
        ++count;
        ++from;
    }
    return count;
}

std::string replaceAll(std::string text, const std::string& from,
    const std::string& to) {
    std::size_t position = 0;
    while ((position = text.find(from, position)) != std::string::npos) {
        text.replace(position, from.size(), to);
        position += to.size();
    }
    return text;
}

std::vector<PamProviderSuppressedLine> wrappersOf(const std::string& content) {
    auto parse = parsePamProviderManagedBlock(content);
    require(parse.ok,
        "strict parse failed (test bug or drift): " + parse.error);
    return parse.view.suppressions;
}

const PamProviderManagedEntry* entryOf(const std::string& content,
    const std::string& policy, const std::string& key) {
    auto parse = parsePamProviderManagedBlock(content);
    require(parse.ok,
        "strict parse failed (test bug or drift): " + parse.error);
    for (const auto& entry : parse.view.entries) {
        if (entry.policy == policy && entry.managedKey == key) {
            return &entry;
        }
    }
    return nullptr;
}

struct Harness {
    TempDir temp;
    std::filesystem::path journalPath;
    std::filesystem::path configPath = temp.directory / "faillock.conf";
    std::filesystem::path pwqualityConfigPath =
        temp.directory / "pwquality.conf";
    MutationJournal journal;
    std::string error;
    // The exact flag states the semantic postcondition was asked to prove,
    // in order (the DURABLE journal target first during recovery — §45).
    std::vector<bool> verifiedStates;
    // States whose semantic proof must fail (injected).
    std::set<bool> failSemanticFor;

    explicit Harness(std::filesystem::path journalFile =
                         std::filesystem::path{})
        : journalPath(journalFile.empty()
                  ? temp.directory / "mutations.json"
                  : std::move(journalFile)),
          journal(journalPath) {
        require(journal.load(error), "journal load failed: " + error);
    }

    PamProviderManagedFlagRequest faillockRequest(
        const std::string& policyName, const std::string& key,
        bool expectedEnabled) const {
        PamProviderManagedFlagRequest request;
        request.policyName = policyName;
        request.provider = PamProviderKind::PamFaillock;
        request.providerName = "pam_faillock";
        request.managedKey = key;
        request.expectedEnabled = expectedEnabled;
        request.configPath = configPath;
        request.placement = PamProviderBlockPlacementRequest::End;
        return request;
    }

    PamProviderManagedFlagRequest pwqualityRequest(
        const std::string& policyName, const std::string& key,
        bool expectedEnabled) const {
        PamProviderManagedFlagRequest request;
        request.policyName = policyName;
        request.provider = PamProviderKind::PamPwquality;
        request.providerName = "pam_pwquality";
        request.managedKey = key;
        request.expectedEnabled = expectedEnabled;
        request.configPath = pwqualityConfigPath;
        request.placement = PamProviderBlockPlacementRequest::End;
        return request;
    }

    bool apply(const PamProviderManagedFlagRequest& request,
        PamProviderManagedEntryOutcome& outcome) {
        verifiedStates.clear();
        error.clear();
        return PamProviderManagedFlagExecutor::apply(request, journal,
            [this](bool expectedEnabled, std::string& semanticError) {
                if (failSemanticFor.count(expectedEnabled) != 0) {
                    semanticError = "injected semantic failure";
                    return false;
                }
                verifiedStates.push_back(expectedEnabled);
                return true;
            },
            outcome, error);
    }

    bool apply(const PamProviderManagedFlagRequest& request) {
        PamProviderManagedEntryOutcome outcome;
        return this->apply(request, outcome);
    }

    std::vector<MutationRecord> flagRecords(const std::string& policyName) {
        return journal.activeRecords({"IDENTITY_ACCESS", "PAM", policyName});
    }

    MutationRecord soleFlagRecord(const std::string& policyName,
        const std::string& context) {
        auto records = flagRecords(policyName);
        require(records.size() == 1,
            context + ": expected exactly one flag record, got " +
                std::to_string(records.size()));
        return records.front();
    }

    static const UndoRemovePamProviderManagedFlag& flagPayload(
        const MutationRecord& record) {
        const auto* payload = std::get_if<UndoRemovePamProviderManagedFlag>(
            &record.undo.payload);
        require(payload != nullptr, "flag payload expected");
        return *payload;
    }
};

MutationRecord makeFlagRecord(const PamProviderManagedFlagRequest& request,
    bool appliedEnabled, std::optional<bool> previousEnabled,
    const std::vector<std::string>& suppressionIds,
    const std::vector<std::string>& previousSuppressionIds) {
    UndoRemovePamProviderManagedFlag payload;
    payload.policyName = request.policyName;
    payload.providerName = request.providerName;
    payload.configPath = request.configPath.string();
    payload.managedKey = request.managedKey;
    payload.appliedEnabled = appliedEnabled;
    payload.previousAppliedEnabled = previousEnabled;
    payload.placement =
        request.placement == PamProviderBlockPlacementRequest::Beginning
        ? fic::rollback::PamProviderBlockPlacementContract::Beginning
        : fic::rollback::PamProviderBlockPlacementContract::End;
    payload.suppressionIds = suppressionIds;
    payload.previousSuppressionIds = previousSuppressionIds;

    MutationRecord record;
    record.policy = {"IDENTITY_ACCESS", "PAM", request.policyName};
    record.resource = request.configPath.string();
    record.undo = UndoAction{fic::rollback::MutationBackend::Pam, payload};
    return record;
}

// ---------------------------------------------------------------------------
// §62–§64 + §70a: byte-exact suppression wrapper round trips (block layer).
// ---------------------------------------------------------------------------

void testWrapperRoundTripByteExact() {
    struct Case {
        const char* name;
        const char* providerName;
        const char* key;
        std::string content;
    };
    const std::vector<Case> cases{
        {"indentation + inline comment", "pam_faillock", "even_deny_root",
            "  even_deny_root   # root lockout\n"},
        {"SET false form", "pam_pwquality", "enforce_for_root",
            "enforce_for_root=0\n"},
        {"uppercase icase form", "pam_pwquality", "enforce_for_root",
            "ENFORCE_FOR_ROOT\n"},
        {"no final LF", "pam_pwquality", "enforce_for_root",
            "enforce_for_root"},
        {"CRLF terminator", "pam_pwquality", "enforce_for_root",
            "enforce_for_root=0\r\n"},
    };
    for (const auto& testCase : cases) {
        TempDir temp;
        const std::filesystem::path configPath =
            temp.directory / "provider.conf";
        writeFile(configPath, testCase.content);

        PamProviderFlagSpec disable;
        disable.provider = testCase.providerName;
        disable.policy = "flag_policy";
        disable.managedKey = testCase.key;
        disable.enabled = false;
        disable.mutationId = 7;
        // One id per active occurrence; the fixture has exactly one.
        disable.createSuppressionIds = {
            nextPamProviderSuppressionId({})};
        auto wrapped = setPamProviderManagedFlagTransition(
            readFile(configPath), disable,
            PamProviderBlockPlacementRequest::End);
        require(wrapped.ok &&
                wrapped.outcome ==
                    PamProviderFlagMutationResult::Outcome::Committed,
            std::string(testCase.name) +
                ": wrap transition refused: " + wrapped.error);

        auto wrappers = wrappersOf(wrapped.content);
        require(wrappers.size() == 1,
            std::string(testCase.name) + ": expected exactly one wrapper");
        const std::string& raw = wrappers.front().rawLine;
        const bool rawByteExact = raw == testCase.content ||
            (testCase.content.rfind(raw, 0) == 0 &&
                testCase.content.size() - raw.size() <= 2 &&
                testCase.content.find_first_not_of("\r\n", raw.size()) ==
                    std::string::npos);
        require(rawByteExact,
            std::string(testCase.name) +
                ": embedded raw line must be byte-exact (modulo the "
                "terminator); got [" +
                raw + "]");

        PamProviderFlagSpec enable;
        enable.provider = testCase.providerName;
        enable.policy = "flag_policy";
        enable.managedKey = testCase.key;
        enable.enabled = true;
        enable.mutationId = 7;
        // An enabled target releases everything: the keep set must be
        // EMPTY (kept wrappers are only defined for disabled targets).
        enable.keepSuppressionIds = {};
        auto unwrapped = setPamProviderManagedFlagTransition(
            wrapped.content, enable, PamProviderBlockPlacementRequest::End);
        require(unwrapped.ok,
            std::string(testCase.name) +
                ": unwrap transition refused: " + unwrapped.error);

        // The FIC block stays (ownership is independent of the flag state);
        // the foreign area must be byte-exactly restored ahead of it.
        require(unwrapped.content.rfind(testCase.content, 0) == 0,
            std::string(testCase.name) +
                ": unwrap must restore the foreign line byte-exact; got [" +
                unwrapped.content + "] expected prefix [" +
                testCase.content + "]");
        require(wrappersOf(unwrapped.content).empty(),
            std::string(testCase.name) +
                ": enabled target must release every wrapper");
    }
}

void testFaillockKeyMatchingCaseSensitive() {
    TempDir temp;
    const std::filesystem::path configPath = temp.directory / "faillock.conf";
    // EVEN_DENY_ROOT is NOT an active occurrence for pam_faillock (upstream
    // case-sensitive matching) — the disable transition must leave it
    // byte-exact and require no suppression ids.
    const std::string content = "EVEN_DENY_ROOT=1\ndeny = 5\n";
    writeFile(configPath, content);

    PamProviderFlagSpec spec;
    spec.provider = "pam_faillock";
    spec.policy = "failed_authentication_enforce_for_root";
    spec.managedKey = "even_deny_root";
    spec.enabled = false;
    spec.mutationId = 3;
    auto result = setPamProviderManagedFlagTransition(readFile(configPath),
        spec, PamProviderBlockPlacementRequest::End);
    require(result.ok,
        "case-variant faillock line must not need suppression: " +
            result.error);
    require(result.content.rfind("EVEN_DENY_ROOT=1\n", 0) == 0,
        "case-variant faillock line must stay byte-exact");
    require(wrappersOf(result.content).empty(),
        "case-variant faillock line must never be wrapped");
}

// ---------------------------------------------------------------------------
// §11 + §68: suppression-wrapper grammar and transition refusal matrix.
// ---------------------------------------------------------------------------

void testFlagGrammarValidation() {
    // Canonical sentinel body: accepted for the owned key, refused for a
    // foreign key, refused with any extra field.
    std::string key;
    require(parseCanonicalPamProviderFlagDisabledBody(
                "# FIC_PAM_FLAG_DISABLED version=1 key=even_deny_root",
                key) &&
            key == "even_deny_root",
        "canonical disabled sentinel body must parse");
    require(pamProviderManagedEntryKindForBody(
                "# FIC_PAM_FLAG_DISABLED version=1 key=other_key",
                "even_deny_root") == std::nullopt,
        "a wrong-key sentinel must not prove the owned entry kind");
    require(pamProviderManagedEntryKindForBody(
                "# FIC_PAM_FLAG_DISABLED version=1 key=even_deny_root extra",
                "even_deny_root") == std::nullopt,
        "an extra-field sentinel must fail closed");
    require(pamProviderManagedEntryKindForBody("even_deny_root",
                "even_deny_root") ==
                PamProviderManagedEntryKind::FlagEnabled,
        "the bare managed key is the canonical enabled body");

    // Wrapper grammar: the embedded raw line must prove as an active
    // same-key occurrence under the provider key semantics.
    const std::string wrapper = pamProviderSuppressionWrapperLine(
        "pam_pwquality", "password_quality_enforce_for_root",
        "enforce_for_root", 5, "s1", "enforce_for_root=0");
    PamProviderSuppressedLine parsed;
    std::string parseError;
    require(parsePamProviderSuppressionWrapper(wrapper, parsed, parseError),
        "canonical wrapper must parse: " + parseError);
    require(parsed.rawLine == "enforce_for_root=0" &&
            parsed.suppressionId == "s1" && parsed.mutationId == 5 &&
            parsed.provider == "pam_pwquality",
        "canonical wrapper fields must round trip");
    const std::string wrongKeyWrapper = pamProviderSuppressionWrapperLine(
        "pam_pwquality", "password_quality_enforce_for_root",
        "enforce_for_root", 5, "s1", "minlen = 8");
    require(!parsePamProviderSuppressionWrapper(wrongKeyWrapper, parsed,
                parseError),
        "a wrapper whose raw line proves a different key must fail " +
            std::string("closed: ") + parseError);
    require(!parsePamProviderSuppressionWrapper(
                pamProviderSuppressionWrapperLine("pam_pwquality",
                    "password_quality_enforce_for_root", "enforce_for_root",
                    5, "s1", ""),
                parsed, parseError),
        "an empty raw line must fail closed");
    require(!parsePamProviderSuppressionWrapper(
                pamProviderSuppressionWrapperLine("pam_pwquality",
                    "password_quality_enforce_for_root", "enforce_for_root",
                    5, "bad id!", "enforce_for_root"),
                parsed, parseError),
        "an invalid suppression id token must fail closed");

    // Duplicate suppression ids in one file are a parse-level failure.
    {
        TempDir temp;
        const std::filesystem::path configPath =
            temp.directory / "faillock.conf";
        const std::string w1 = pamProviderSuppressionWrapperLine(
            "pam_faillock", "failed_authentication_enforce_for_root",
            "even_deny_root", 4, "s1", "even_deny_root");
        const std::string w2 = pamProviderSuppressionWrapperLine(
            "pam_faillock", "failed_authentication_enforce_for_root",
            "even_deny_root", 4, "s1", "even_deny_root=0");
        writeFile(configPath, w1 + "\n" + w2 + "\n");
        auto parse = parsePamProviderManagedBlock(readFile(configPath));
        require(!parse.ok,
            "duplicate suppression ids in one file must fail closed");
    }

    // A canonical wrapper INSIDE the managed block is a parse-level
    // failure (wrappers are parsed outside the block only).
    {
        TempDir temp;
        const std::filesystem::path configPath =
            temp.directory / "faillock.conf";
        const std::string wrapper = pamProviderSuppressionWrapperLine(
            "pam_faillock", "failed_authentication_enforce_for_root",
            "even_deny_root", 4, "s1", "even_deny_root");
        writeFile(configPath,
            "# FIC_PAM_PROVIDER_BLOCK_BEGIN version=1 provider=pam_faillock "
            "lead=newline\n"
            "# FIC_PAM_ENTRY_BEGIN version=1 "
            "policy=failed_authentication_enforce_for_root mutation=4\n"
            "# FIC_PAM_FLAG_DISABLED version=1 key=even_deny_root\n"
            "# FIC_PAM_ENTRY_END\n" +
                wrapper + "\n"
                          "# FIC_PAM_PROVIDER_BLOCK_END\n");
        PamProviderFlagSpec spec;
        spec.provider = "pam_faillock";
        spec.policy = "failed_authentication_enforce_for_root";
        spec.managedKey = "even_deny_root";
        spec.enabled = true;
        spec.mutationId = 4;
        spec.keepSuppressionIds = {"s1"};
        auto result = setPamProviderManagedFlagTransition(
            readFile(configPath), spec,
            PamProviderBlockPlacementRequest::End);
        require(!result.ok,
            "a wrapper inside the managed block must fail closed: " +
                result.error);
    }

    // Unknown reserved FIC-like markers fail the strict parse.
    {
        TempDir temp;
        const std::filesystem::path configPath =
            temp.directory / "faillock.conf";
        writeFile(configPath,
            "# FIC_PAM_FUTURE_MARKER version=1 x=y\neven_deny_root\n");
        PamProviderFlagSpec spec;
        spec.provider = "pam_faillock";
        spec.policy = "failed_authentication_enforce_for_root";
        spec.managedKey = "even_deny_root";
        spec.enabled = false;
        spec.mutationId = 1;
        spec.createSuppressionIds = {"s1"};
        auto result = setPamProviderManagedFlagTransition(
            readFile(configPath), spec,
            PamProviderBlockPlacementRequest::End);
        require(!result.ok,
            "an unknown reserved FIC-like marker must fail closed");
    }

    // Insufficient or duplicate create-id sets are typed refusals.
    {
        TempDir temp;
        const std::filesystem::path configPath =
            temp.directory / "faillock.conf";
        writeFile(configPath, "even_deny_root\neven_deny_root=0\n");
        PamProviderFlagSpec shortage;
        shortage.provider = "pam_faillock";
        shortage.policy = "failed_authentication_enforce_for_root";
        shortage.managedKey = "even_deny_root";
        shortage.enabled = false;
        shortage.mutationId = 1;
        shortage.createSuppressionIds = {"s1"}; // two occurrences, one id
        auto result = setPamProviderManagedFlagTransition(
            readFile(configPath), shortage,
            PamProviderBlockPlacementRequest::End);
        require(!result.ok,
            "a create-id shortage must be a typed refusal: " + result.error);

        PamProviderFlagSpec duplicated = shortage;
        duplicated.createSuppressionIds = {"s1", "s1"};
        result = setPamProviderManagedFlagTransition(readFile(configPath),
            duplicated, PamProviderBlockPlacementRequest::End);
        require(!result.ok,
            "duplicate create ids must be a typed refusal: " + result.error);
    }
}

// ---------------------------------------------------------------------------
// §30–§33: journal payload round trip, validation, retry identity.
// ---------------------------------------------------------------------------

void testJournalFlagPayloadRoundTrip() {
    TempDir temp;
    const std::filesystem::path journalPath =
        temp.directory / "mutations.json";
    const std::filesystem::path configPath = temp.directory / "faillock.conf";
    PamProviderManagedFlagRequest request;
    request.policyName = "failed_authentication_enforce_for_root";
    request.providerName = "pam_faillock";
    request.managedKey = "even_deny_root";
    request.configPath = configPath;

    // Fresh transition (previous = none) with a non-empty target set.
    {
        MutationJournal journal(journalPath);
        std::string error;
        require(journal.load(error), error);
        MutationId id = 0;
        require(journal.prepareMutation(
                    makeFlagRecord(request, /*appliedEnabled=*/false,
                        /*previous=*/std::nullopt, {"s1", "s2"}, {}),
                    id, error),
            error);
        require(journal.setStatus(id, MutationStatus::Applied, error), error);
    }
    // Restart: every payload field must survive the exact write/read parity.
    {
        MutationJournal journal(journalPath);
        std::string error;
        require(journal.load(error), error);
        auto records = journal.activeRecords(
            {"IDENTITY_ACCESS", "PAM",
                "failed_authentication_enforce_for_root"});
        require(records.size() == 1, "round trip: one record expected");
        const UndoRemovePamProviderManagedFlag payload = Harness::flagPayload(records.front());
        require(payload.policyName == request.policyName &&
                payload.providerName == "pam_faillock" &&
                payload.configPath == configPath.string() &&
                payload.managedKey == "even_deny_root" &&
                payload.appliedEnabled == false &&
                !payload.previousAppliedEnabled.has_value() &&
                payload.suppressionIds ==
                    std::vector<std::string>{"s1", "s2"} &&
                payload.previousSuppressionIds.empty(),
            "flag payload round trip must be field-exact");

        // Disabled provenance refresh (false→false, §72): the target set
        // grows; the currently owned set is carried as provenance.
        MutationId refreshed = 0;
        require(journal.prepareMutation(
                    makeFlagRecord(request, /*appliedEnabled=*/false,
                        /*previous=*/false, {"s1", "s2", "s3"}, {"s1", "s2"}),
                    refreshed, error),
            error);
        require(refreshed == records.front().id,
            "refresh must reuse the active record id");
        require(journal.setStatus(refreshed, MutationStatus::Applied, error),
            error);
    }
    {
        MutationJournal journal(journalPath);
        std::string error;
        require(journal.load(error), error);
        auto records = journal.activeRecords(
            {"IDENTITY_ACCESS", "PAM",
                "failed_authentication_enforce_for_root"});
        require(records.size() == 1, "refresh: same-record update expected");
        const UndoRemovePamProviderManagedFlag payload = Harness::flagPayload(records.front());
        require(payload.appliedEnabled == false &&
                payload.previousAppliedEnabled.has_value() &&
                *payload.previousAppliedEnabled == false &&
                payload.suppressionIds ==
                    std::vector<std::string>{"s1", "s2", "s3"} &&
                payload.previousSuppressionIds ==
                    std::vector<std::string>{"s1", "s2"},
            "flag refresh payload round trip must be field-exact");
    }
}

void testJournalFlagPayloadValidationFailure() {
    TempDir temp;
    const std::filesystem::path journalPath =
        temp.directory / "mutations.json";
    const std::filesystem::path configPath = temp.directory / "faillock.conf";
    PamProviderManagedFlagRequest request;
    request.policyName = "failed_authentication_enforce_for_root";
    request.providerName = "pam_faillock";
    request.managedKey = "even_deny_root";
    request.configPath = configPath;
    {
        MutationJournal journal(journalPath);
        std::string error;
        require(journal.load(error), error);
        MutationId id = 0;
        require(journal.prepareMutation(
                    makeFlagRecord(request, false, std::nullopt, {"s1"}, {}),
                    id, error),
            error);
    }
    const std::string document = readFile(journalPath);
    require(!document.empty(), "journal document expected");
    require(contains(document, "\"previous_applied_enabled\": \"none\""),
        "previous_applied_enabled must always be materialized (write/read "
        "parity)");

    // Unknown previous_applied_enabled values fail closed on load.
    const std::string corruptedDocument = replaceAll(document,
        "\"previous_applied_enabled\": \"none\"",
        "\"previous_applied_enabled\": \"bogus\"");
    require(corruptedDocument != document, "corruption must be applied");
    const std::filesystem::path corrupted = temp.directory / "bad.json";
    writeFile(corrupted, corruptedDocument);
    MutationJournal journal(corrupted);
    std::string error;
    require(!journal.load(error),
        "unknown previous_applied_enabled must fail closed");
    require(contains(error, "previous_applied_enabled"),
        "the load error must name the field: " + error);
}

void testJournalExactPreparedRetryIdentity() {
    TempDir temp;
    const std::filesystem::path journalPath =
        temp.directory / "mutations.json";
    const std::filesystem::path configPath = temp.directory / "faillock.conf";
    PamProviderManagedFlagRequest request;
    request.policyName = "failed_authentication_enforce_for_root";
    request.providerName = "pam_faillock";
    request.managedKey = "even_deny_root";
    request.configPath = configPath;

    MutationJournal journal(journalPath);
    std::string error;
    require(journal.load(error), error);

    const auto record = makeFlagRecord(
        request, false, std::nullopt, {"s1", "s2"}, {});
    MutationId first = 0;
    require(journal.prepareMutation(record, first, error), error);
    // Exact same transition: idempotent re-prepare keeps the record id.
    MutationId retry = 0;
    require(journal.prepareMutation(record, retry, error), error);
    require(first == retry, "exact Prepared retry must reuse the record id");

    // ANY change of the durable target (state or id set) conflicts with an
    // unresolved Prepared transition (Step 7E §31).
    const std::vector<MutationRecord> conflicts{
        makeFlagRecord(request, true, std::nullopt, {}, {}),     // target
        makeFlagRecord(request, false, std::nullopt, {"s1"}, {}), // id set
        makeFlagRecord(request, false, false, {"s1", "s2"}, {}), // previous
    };
    for (const auto& conflict : conflicts) {
        MutationId ignored = 0;
        require(!journal.prepareMutation(conflict, ignored, error),
            "a changed Prepared flag transition must be rejected: " + error);
    }
}

// ---------------------------------------------------------------------------
// §66–§75: executor lifecycle (faillock primary, End placement).
// ---------------------------------------------------------------------------

const char* kFlagPolicy = "failed_authentication_enforce_for_root";

void testFailClosedOnAbsentPrimary() {
    Harness harness;
    for (const bool desired : {true, false}) {
        auto request = harness.faillockRequest(kFlagPolicy, "even_deny_root",
            desired);
        require(!harness.apply(request),
            "an absent primary must fail closed for desired=" +
                std::string(desired ? "true" : "false") + ": " +
                harness.error);
        require(harness.flagRecords(kFlagPolicy).empty(),
            "the refused apply must prepare NO journal records");
    }
}

void testFreshApplyAndNoOpLifecycle() {
    Harness harness;
    writeFile(harness.configPath, "deny = 5\nunlock_time = 30\n");

    // §70 fresh true: foreign active occurrences stay untouched (true is
    // effective regardless of foreign lines).
    auto enable = harness.faillockRequest(kFlagPolicy, "even_deny_root",
        true);
    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(enable, outcome),
        std::string("fresh apply must be Applied: ") + harness.error);
    const std::string enabledContent = readFile(harness.configPath);
    require(enabledContent.rfind("deny = 5\nunlock_time = 30\n", 0) == 0,
        "foreign lines must stay byte-exact under a fresh enabled apply");
    const auto* enabledEntry = entryOf(enabledContent, kFlagPolicy,
        "even_deny_root");
    require(enabledEntry != nullptr &&
            enabledEntry->kind == PamProviderManagedEntryKind::FlagEnabled,
        "the enabled entry must be the bare managed key");
    require(wrappersOf(enabledContent).empty(),
        "an enabled fresh apply must not create suppression wrappers");
    const MutationRecord enableRecord =
        harness.soleFlagRecord(kFlagPolicy, "fresh enable");
    const UndoRemovePamProviderManagedFlag enablePayload =
        Harness::flagPayload(enableRecord);
    require(enablePayload.appliedEnabled &&
            !enablePayload.previousAppliedEnabled.has_value() &&
            enablePayload.suppressionIds.empty(),
        "fresh enable payload provenance");

    // §69 fresh false with zero foreign occurrences: sentinel entry only.
    auto disable = harness.faillockRequest(kFlagPolicy, "even_deny_root",
        false);
    require(harness.apply(disable, outcome),
        std::string("fresh disable must apply: ") + harness.error);
    const std::string disabledContent = readFile(harness.configPath);
    require(contains(disabledContent,
                "# FIC_PAM_FLAG_DISABLED version=1 key=even_deny_root"),
        "the disabled entry must be the canonical sentinel");
    require(wrappersOf(disabledContent).empty(),
        "no foreign occurrences means no wrappers");
    const MutationRecord disableRecord =
        harness.soleFlagRecord(kFlagPolicy, "fresh disable");
    require(disableRecord.id == enableRecord.id,
        "the flag lifecycle must reuse ONE active record (§71)");
    const UndoRemovePamProviderManagedFlag disablePayload =
        Harness::flagPayload(disableRecord);
    require(!disablePayload.appliedEnabled &&
            disablePayload.previousAppliedEnabled.has_value() &&
            *disablePayload.previousAppliedEnabled == true,
        "the toggle must carry the previous enabled state as provenance");

    // Idempotent repeat: exact journal + physical state → AppliedNoOp,
    // byte-identical file.
    require(harness.apply(disable, outcome),
        std::string("the disabled repeat must apply: ") + harness.error);
    require(outcome == PamProviderManagedEntryOutcome::AppliedNoOp,
        "an exact disabled repeat must be a no-op");
    require(readFile(harness.configPath) == disabledContent,
        "a no-op repeat must not touch the file");
}

void testSameIdToggleReleasesWrappersByteExact() {
    Harness harness;
    const std::string original = "  even_deny_root # root lock\n";
    writeFile(harness.configPath, original);

    // Disable: the foreign line is wrapped in place (§69).
    auto disable = harness.faillockRequest(kFlagPolicy, "even_deny_root",
        false);
    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(disable, outcome), harness.error);
    const std::string wrapped = readFile(harness.configPath);
    auto wrappers = wrappersOf(wrapped);
    require(wrappers.size() == 1 &&
            wrappers.front().rawLine == "  even_deny_root # root lock",
        "disable must wrap the foreign line byte-exact");
    require(wrappers.front().suppressionId == "s1",
        "the first suppression id must be s1");

    // Enable (§42): wrappers are released; the foreign line returns
    // byte-exact to its physical position; the record id is stable.
    auto enable = harness.faillockRequest(kFlagPolicy, "even_deny_root",
        true);
    require(harness.apply(enable, outcome), harness.error);
    require(outcome == PamProviderManagedEntryOutcome::Applied,
        "a state toggle is a physical mutation (Applied)");
    const std::string released = readFile(harness.configPath);
    require(released.rfind(original, 0) == 0,
        "enable must release wrappers byte-exact; got [" + released + "]");
    require(wrappersOf(released).empty(),
        "enabled state must not own wrappers");
    const MutationRecord record =
        harness.soleFlagRecord(kFlagPolicy, "toggle");
    const UndoRemovePamProviderManagedFlag payload = Harness::flagPayload(record);
    require(payload.appliedEnabled &&
            payload.previousAppliedEnabled.has_value() &&
            *payload.previousAppliedEnabled == false &&
            payload.previousSuppressionIds ==
                std::vector<std::string>{"s1"} &&
            payload.suppressionIds.empty(),
        "the false→true toggle must carry the exact wrapper provenance");

    // Disable again: same record id, the suppression id namespace restarts
    // at s1 (the file no longer carries wrappers).
    require(harness.apply(disable, outcome), harness.error);
    wrappers = wrappersOf(readFile(harness.configPath));
    require(wrappers.size() == 1 &&
            wrappers.front().suppressionId == "s1" &&
            wrappers.front().rawLine == "  even_deny_root # root lock",
        "the second disable must re-wrap byte-exact with a fresh s1");
    const MutationRecord record2 =
        harness.soleFlagRecord(kFlagPolicy, "second disable");
    require(record2.id == record.id,
        "toggles must never mint a new record id (§71)");
}

void testNewForeignLineWhileDisabled() {
    Harness harness;
    writeFile(harness.configPath, "even_deny_root\n");
    auto disable = harness.faillockRequest(kFlagPolicy, "even_deny_root",
        false);
    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(disable, outcome), harness.error);
    require(wrappersOf(readFile(harness.configPath)).size() == 1 &&
            wrappersOf(readFile(harness.configPath))
                    .front()
                    .suppressionId == "s1",
        "the first foreign line must be wrapped as s1");

    // §72/§39: a new foreign line while disabled → NEW id, old ids stable.
    // The new line is added to the foreign area; the wrapped line and the
    // FIC block stay untouched.
    writeFile(harness.configPath,
        "even_deny_root = 0 # admin re-added\n" + readFile(harness.configPath));
    require(harness.apply(disable, outcome), harness.error);
    require(outcome == PamProviderManagedEntryOutcome::Applied,
        "wrapping a new foreign line is a physical mutation");
    require(readFile(harness.configPath).size() < 4096,
        "the mutated file must stay small (got " +
            std::to_string(readFile(harness.configPath).size()) + " bytes)");
    const std::vector<PamProviderSuppressedLine> refreshedWrappers =
        wrappersOf(readFile(harness.configPath));
    auto wrappers = wrappersOf(readFile(harness.configPath));
    require(wrappers.size() == 2, "both foreign lines must be wrapped");
    require(wrappers[0].suppressionId == "s2" &&
            wrappers[0].rawLine == "even_deny_root = 0 # admin re-added",
        "the new foreign line must get the next suppression id s2");
    require(wrappers[1].suppressionId == "s1" &&
            wrappers[1].rawLine == "even_deny_root",
        "the old wrapper must stay byte-exact and stable");
    const UndoRemovePamProviderManagedFlag payload = Harness::flagPayload(
        harness.soleFlagRecord(kFlagPolicy, "new line while disabled"));
    {
        std::string ids;
        for (const auto& id : payload.suppressionIds) {
            ids += id + ",";
        }
        std::string previous;
        for (const auto& id : payload.previousSuppressionIds) {
            previous += id + ",";
        }
        require(payload.suppressionIds ==
                    std::vector<std::string>{"s1", "s2"} &&
                payload.previousSuppressionIds ==
                    std::vector<std::string>{"s1"},
            "the journal must record the exact target and previous id sets "
            "(got target=[" +
                ids + "] previous=[" + previous + "] enabled=" +
                std::string(payload.appliedEnabled ? "true" : "false") + ")");
    }
}

void testAdminRemovesWrapperSubset() {
    Harness harness;
    writeFile(harness.configPath, "even_deny_root\neven_deny_root=0\n");
    auto disable = harness.faillockRequest(kFlagPolicy, "even_deny_root",
        false);
    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(disable, outcome), harness.error);
    const std::string wrapped = readFile(harness.configPath);
    require(wrappersOf(wrapped).size() == 2, "two wrappers expected");

    // §73: the admin removes the s2 wrapper AND its foreign line entirely
    // (the line is gone, not unwrapped). The provenance subset is
    // canonicalized; the surviving wrapper is never reconstructed.
    const std::size_t s2 = wrapped.find("suppression=s2");
    require(s2 != std::string::npos, "s2 wrapper expected");
    const std::size_t lineStart = wrapped.rfind('\n', s2) + 1;
    const std::size_t lineEnd = wrapped.find('\n', s2);
    writeFile(harness.configPath,
        wrapped.substr(0, lineStart) + wrapped.substr(lineEnd + 1));
    require(harness.apply(disable, outcome), harness.error);
    const UndoRemovePamProviderManagedFlag payload = Harness::flagPayload(
        harness.soleFlagRecord(kFlagPolicy, "removed wrapper subset"));
    require(payload.suppressionIds == std::vector<std::string>{"s1"},
        "the payload provenance must canonicalize to the proven subset");
    auto wrappers = wrappersOf(readFile(harness.configPath));
    require(wrappers.size() == 1 && wrappers.front().suppressionId == "s1",
        "the surviving wrapper must stay byte-exact");
}

void testAdminManuallyUnwrapsWhileDisabled() {
    Harness harness;
    writeFile(harness.configPath, "even_deny_root # first\n");
    auto disable = harness.faillockRequest(kFlagPolicy, "even_deny_root",
        false);
    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(disable, outcome), harness.error);

    // §74: the admin manually unwraps the line (restores the foreign
    // bytes at the wrapper's physical position, block untouched). The
    // disabled refresh re-wraps it under a NEW id — the journal is never
    // a backup manifest.
    {
        const std::string wrappedContent = readFile(harness.configPath);
        const std::size_t wrapperStart =
            wrappedContent.find("# FIC_PAM_SUPPRESS version=1");
        require(wrapperStart != std::string::npos,
            "the wrapper line expected");
        const std::size_t wrapperEnd =
            wrappedContent.find('\n', wrapperStart);
        writeFile(harness.configPath,
            wrappedContent.substr(0, wrapperStart) + "even_deny_root # first" +
                wrappedContent.substr(wrapperEnd));
    }
    require(harness.apply(disable, outcome), harness.error);
    auto wrappers = wrappersOf(readFile(harness.configPath));
    require(wrappers.size() == 1 &&
            wrappers.front().suppressionId == "s2" &&
            wrappers.front().rawLine == "even_deny_root # first",
        "the manually unwrapped line must be re-wrapped under the next "
        "namespace id (the released s1 stays reserved by the journal)");
    const UndoRemovePamProviderManagedFlag payload = Harness::flagPayload(
        harness.soleFlagRecord(kFlagPolicy, "manual unwrap"));
    require(payload.suppressionIds == std::vector<std::string>{"s2"} &&
            payload.previousSuppressionIds ==
                std::vector<std::string>{"s1"},
        "the provenance must track the current wrapper and the released "
        "previous set");
}

void testFreshApplyRefusesPreExistingEntry() {
    Harness harness;
    // §67: a physically present (policy, key) entry without journal
    // provenance is never adopted by a fresh transaction.
    writeFile(harness.configPath,
        "# FIC_PAM_PROVIDER_BLOCK_BEGIN version=1 provider=pam_faillock "
        "lead=newline\n"
        "# FIC_PAM_ENTRY_BEGIN version=1 policy=" +
            std::string(kFlagPolicy) + " mutation=7\n"
            "# FIC_PAM_FLAG_DISABLED version=1 key=even_deny_root\n"
            "# FIC_PAM_ENTRY_END\n"
            "# FIC_PAM_PROVIDER_BLOCK_END\n");
    auto enable = harness.faillockRequest(kFlagPolicy, "even_deny_root",
        true);
    require(!harness.apply(enable),
        "a fresh transaction must refuse an unproven pre-existing entry: " +
            harness.error);
    require(harness.flagRecords(kFlagPolicy).empty(),
        "the refused fresh apply must prepare NO journal records");
    require(contains(readFile(harness.configPath), "mutation=7"),
        "the refused fresh apply must not touch the file");
}

void testForeignWrapperProvenanceFailsClosed() {
    Harness harness;
    writeFile(harness.configPath, "even_deny_root\n");
    auto disable = harness.faillockRequest(kFlagPolicy, "even_deny_root",
        false);
    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(disable, outcome), harness.error);

    // §41/§68: a CANONICAL wrapper of this policy carrying a foreign
    // mutation id is an unproven provenance conflict; the refresh must
    // fail closed and never silently adopt or re-id it.
    auto wrappers = wrappersOf(readFile(harness.configPath));
    const std::string canonicalForge = pamProviderSuppressionWrapperLine(
        "pam_faillock", kFlagPolicy, "even_deny_root", 999, "s1",
        wrappers.front().rawLine);
    writeFile(harness.configPath, canonicalForge + "\n");
    require(!harness.apply(disable),
        "a foreign-mutation wrapper of this policy must fail closed: " +
            harness.error);
}

void testMetadataPreservation() {
    Harness harness;
    writeFile(harness.configPath, "even_deny_root\n");
    ::chmod(harness.configPath.c_str(), 0640);
    auto disable = harness.faillockRequest(kFlagPolicy, "even_deny_root",
        false);
    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(disable, outcome), harness.error);
    struct ::stat info;
    require(::stat(harness.configPath.c_str(), &info) == 0, "stat failed");
    require((info.st_mode & 07777) == 0640,
        "the physical mutation must preserve the existing file mode (§65)");
}

void testSemanticFailureKeepsPreparedThenRecovers() {
    Harness harness;
    writeFile(harness.configPath, "even_deny_root\n");
    auto enable = harness.faillockRequest(kFlagPolicy, "even_deny_root",
        true);
    harness.failSemanticFor.insert(true);

    // §46: the semantic postcondition of the DURABLE target fails — the
    // physical state is already committed and the record stays Prepared
    // (provenance is never discarded; crash recovery completes it).
    PamProviderManagedEntryOutcome outcome;
    require(!harness.apply(enable, outcome),
        "an injected semantic failure must fail the apply: " + harness.error);
    const MutationRecord prepared =
        harness.soleFlagRecord(kFlagPolicy, "semantic failure");
    require(prepared.status == MutationStatus::Prepared,
        "the record must stay recoverable (Prepared)");
    require(entryOf(readFile(harness.configPath), kFlagPolicy,
                "even_deny_root") != nullptr,
        "the physical transition is already durable");

    // §75: a retry with a working semantic postcondition recovers the
    // SAME record id (durable target first, then the current desired).
    harness.failSemanticFor.clear();
    require(harness.apply(enable, outcome), harness.error);
    require(outcome == PamProviderManagedEntryOutcome::Applied,
        "recovery completes the durable target as Applied");
    require(harness.verifiedStates ==
                std::vector<bool>{true},
        "recovery must prove the DURABLE target first");
    const MutationRecord recovered =
        harness.soleFlagRecord(kFlagPolicy, "recovery");
    require(recovered.id == prepared.id &&
            recovered.status == MutationStatus::Applied,
        "recovery must complete the SAME record id");
}

void testDesiredChangedDuringRecovery() {
    Harness harness;
    writeFile(harness.configPath, "even_deny_root\n");
    auto enable = harness.faillockRequest(kFlagPolicy, "even_deny_root",
        true);
    harness.failSemanticFor.insert(true);
    PamProviderManagedEntryOutcome outcome;
    require(!harness.apply(enable, outcome), harness.error);
    harness.failSemanticFor.clear();

    // §45/§76: the admin's desired value changed while the transition was
    // unresolved. Recovery proves the DURABLE target (enabled) first, then
    // reconciles the CURRENT desired value (disabled) under the SAME id.
    auto disable = harness.faillockRequest(kFlagPolicy, "even_deny_root",
        false);
    require(harness.apply(disable, outcome), harness.error);
    require(outcome == PamProviderManagedEntryOutcome::Applied,
        "the desired reconciliation is a physical mutation");
    require(harness.verifiedStates == std::vector<bool>{true, false},
        "the semantic callback must receive the durable target first, "
        "then the current desired value");
    const std::string finalContent = readFile(harness.configPath);
    require(contains(finalContent,
                "# FIC_PAM_FLAG_DISABLED version=1 key=even_deny_root"),
        "the final state must be the disabled sentinel");
    auto wrappers = wrappersOf(finalContent);
    require(wrappers.size() == 1 &&
            wrappers.front().rawLine == "even_deny_root" &&
            wrappers.front().suppressionId == "s1",
        "the still-present foreign line must be wrapped for the "
        "disabled state");
    const MutationRecord record =
        harness.soleFlagRecord(kFlagPolicy, "desired changed");
    const UndoRemovePamProviderManagedFlag payload = Harness::flagPayload(record);
    require(!payload.appliedEnabled &&
            payload.previousAppliedEnabled.has_value() &&
            *payload.previousAppliedEnabled == true,
        "the reconciliation must carry the completed durable state as "
        "previous provenance");
}

void testPwqualityIcaseLifecycle() {
    Harness harness;
    writeFile(harness.pwqualityConfigPath, "ENFORCE_FOR_ROOT = 0\n");
    auto request = harness.pwqualityRequest(
        "password_quality_enforce_for_root", "enforce_for_root", false);
    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(request, outcome), harness.error);
    auto wrappers = wrappersOf(readFile(harness.pwqualityConfigPath));
    require(wrappers.size() == 1 &&
            wrappers.front().rawLine == "ENFORCE_FOR_ROOT = 0",
        "the pwquality icase foreign line must be wrapped byte-exact");
    // Repeat: exact disabled state → no-op.
    require(harness.apply(request, outcome), harness.error);
    require(outcome == PamProviderManagedEntryOutcome::AppliedNoOp,
        "the pwquality disabled repeat must be a no-op");
}

void testRestartRefreshFromPersistedJournal() {
    Harness harness;
    writeFile(harness.configPath, "even_deny_root\n");
    auto disable = harness.faillockRequest(kFlagPolicy, "even_deny_root",
        false);
    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(disable, outcome), harness.error);
    const std::string persistedContent = readFile(harness.configPath);
    const MutationId persistedId =
        harness.soleFlagRecord(kFlagPolicy, "restart").id;

    // A "daemon restart": a fresh executor against the PERSISTED journal,
    // same primary path (absolute path provenance is part of the record
    // identity — a moved config path is a fail-closed conflict).
    Harness restarted(harness.journalPath);
    auto disableAgain = restarted.faillockRequest(kFlagPolicy,
        "even_deny_root", false);
    disableAgain.configPath = harness.configPath;
    require(restarted.apply(disableAgain, outcome), restarted.error);
    require(outcome == PamProviderManagedEntryOutcome::AppliedNoOp,
        "a restart refresh of the exact state must be a no-op");
    require(readFile(harness.configPath) == persistedContent,
        "a restart no-op must not touch the file");
    require(restarted.soleFlagRecord(kFlagPolicy, "restart").id ==
            persistedId,
        "the restart must reuse the persisted record id");
}

// ---------------------------------------------------------------------------
// Step 7E follow-up §78: fresh transactions never adopt or silently use
// orphan FIC-owned physical state (managed entry AND suppression wrappers)
// without an active journal record proving ownership.
// ---------------------------------------------------------------------------

// Forge one byte-canonical suppression wrapper of the flag identity with
// valid non-zero ids and a valid embedded raw active occurrence.
std::string forgeWrapperLine(const std::string& rawLine,
    std::uint64_t mutationId, const std::string& suppressionId) {
    return pamProviderSuppressionWrapperLine("pam_faillock", kFlagPolicy,
        "even_deny_root", mutationId, suppressionId, rawLine);
}

// Physical state: existing primary, NO managed flag entry, ONE canonical
// suppression wrapper of the SAME (provider, policy, managed key) with a
// valid mutation id and a valid embedded raw active occurrence — but NO
// active journal record (orphan FIC provenance).
void writeOrphanWrapperState(const Harness& harness) {
    const std::string rawLine = "even_deny_root # admin";
    const std::string forged = forgeWrapperLine(rawLine, 4, "s7");
    std::string parseError;
    PamProviderSuppressedLine probe;
    require(parsePamProviderSuppressionWrapper(forged, probe, parseError),
        "test bug: the forged wrapper must parse canonically: " + parseError);
    writeFile(harness.configPath, rawLine + "\n" + forged + "\n");
}

void testFreshDesiredFalseRefusesOrphanWrapper() {
    Harness harness;
    writeOrphanWrapperState(harness);
    const std::string original = readFile(harness.configPath);

    // §78: a fresh disabled transaction must fail closed BEFORE any journal
    // prepare: the orphan wrapper is FIC provenance no active record proves.
    auto disable = harness.faillockRequest(kFlagPolicy, "even_deny_root",
        false);
    require(!harness.apply(disable),
        "a fresh disable must refuse an orphan suppression wrapper of the "
            "same identity: " + harness.error);
    require(contains(harness.error, "orphan FIC PAM suppression wrapper") &&
            contains(harness.error, "s7"),
        "the diagnostic must name the unproven/orphan provenance: " +
            harness.error);
    require(harness.flagRecords(kFlagPolicy).empty(),
        "the refused fresh apply must prepare NO journal records");
    require(readFile(harness.configPath) == original,
        "the refused fresh apply must leave the config byte-identical");
    auto wrappers = wrappersOf(readFile(harness.configPath));
    require(wrappers.size() == 1 && wrappers.front().suppressionId == "s7" &&
            wrappers.front().mutationId == 4,
        "the existing orphan wrapper must stay unchanged");
    require(entryOf(readFile(harness.configPath), kFlagPolicy,
                "even_deny_root") == nullptr,
        "no new managed flag entry must appear");
}

void testFreshDesiredTrueRefusesOrphanWrapper() {
    Harness harness;
    writeOrphanWrapperState(harness);
    const std::string original = readFile(harness.configPath);

    // §78: a fresh ENABLED transaction must also fail closed — it has no
    // right to silently keep or unwrap a foreign/orphan FIC wrapper.
    auto enable = harness.faillockRequest(kFlagPolicy, "even_deny_root",
        true);
    require(!harness.apply(enable),
        "a fresh enable must refuse an orphan suppression wrapper of the "
            "same identity: " + harness.error);
    require(contains(harness.error, "orphan FIC PAM suppression wrapper"),
        "the diagnostic must name the unproven/orphan provenance: " +
            harness.error);
    require(harness.flagRecords(kFlagPolicy).empty(),
        "the refused fresh apply must prepare NO journal records");
    require(readFile(harness.configPath) == original,
        "the refused fresh apply must leave the config byte-identical");
    require(wrappersOf(readFile(harness.configPath)).size() == 1,
        "the existing orphan wrapper must stay unchanged (no silent "
            "unwrap)");
    require(entryOf(readFile(harness.configPath), kFlagPolicy,
                "even_deny_root") == nullptr,
        "no new managed flag entry must appear");
}

// §41: with an ACTIVE journal record, a canonical wrapper of the same
// identity carrying a DIFFERENT mutation id stays a distinct fail-closed
// conflict for ANY desired state (never rewritten, never unwrapped, never
// re-id'd) — separate from the fresh orphan case.
void testDifferentMutationIdWrapperFailsClosedForAnyDesired() {
    Harness harness;
    writeFile(harness.configPath, "even_deny_root # admin\n");
    auto disable = harness.faillockRequest(kFlagPolicy, "even_deny_root",
        false);
    PamProviderManagedEntryOutcome outcome;
    require(harness.apply(disable, outcome), harness.error);
    const MutationId activeId =
        harness.soleFlagRecord(kFlagPolicy, "active record").id;
    require(activeId != 0, "an active record id is expected");
    require(wrappersOf(readFile(harness.configPath)).size() == 1 &&
                wrappersOf(readFile(harness.configPath))
                        .front()
                        .mutationId == activeId,
        "the owned wrapper must carry the active record id");

    // Foreign mutation id Y != X on the same identity: the disabled
    // sentinel entry of the SAME record stays physically present, so the
    // refusal is the foreign-mutation-id conflict (not entry drift).
    const std::string forgedState =
        forgeWrapperLine("even_deny_root # admin", activeId + 1, "s9") +
        "\n"
        "# FIC_PAM_PROVIDER_BLOCK_BEGIN version=1 provider=pam_faillock "
        "lead=newline\n"
        "# FIC_PAM_ENTRY_BEGIN version=1 policy=" +
        std::string(kFlagPolicy) + " mutation=" +
        std::to_string(activeId) +
        "\n"
        "# FIC_PAM_FLAG_DISABLED version=1 key=even_deny_root\n"
        "# FIC_PAM_ENTRY_END\n"
        "# FIC_PAM_PROVIDER_BLOCK_END\n";
    writeFile(harness.configPath, forgedState);

    require(!harness.apply(disable),
        "a foreign-mutation wrapper must fail closed for desired=false: " +
            harness.error);
    require(contains(harness.error, "foreign mutation id"),
        "the diagnostic must name the foreign mutation id: " + harness.error);
    require(readFile(harness.configPath) == forgedState,
        "the foreign wrapper must stay unchanged (no rewrite/unwrap/re-id)");
    const MutationRecord after =
        harness.soleFlagRecord(kFlagPolicy, "foreign mutation id");
    require(after.id == activeId && after.status == MutationStatus::Applied,
        "the refused apply must never rewrite the journal record");

    auto enable = harness.faillockRequest(kFlagPolicy, "even_deny_root",
        true);
    require(!harness.apply(enable),
        "a foreign-mutation wrapper must fail closed for desired=true: " +
            harness.error);
    require(contains(harness.error, "foreign mutation id"),
        "the diagnostic must name the foreign mutation id: " + harness.error);
    require(readFile(harness.configPath) == forgedState,
        "the foreign wrapper must stay unchanged for desired=true");
}

} // namespace

int main() {
    const std::pair<const char*, void (*)()> tests[] = {
        {"testWrapperRoundTripByteExact", testWrapperRoundTripByteExact},
        {"testFaillockKeyMatchingCaseSensitive",
            testFaillockKeyMatchingCaseSensitive},
        {"testFlagGrammarValidation", testFlagGrammarValidation},
        {"testJournalFlagPayloadRoundTrip", testJournalFlagPayloadRoundTrip},
        {"testJournalFlagPayloadValidationFailure",
            testJournalFlagPayloadValidationFailure},
        {"testJournalExactPreparedRetryIdentity",
            testJournalExactPreparedRetryIdentity},
        {"testFailClosedOnAbsentPrimary", testFailClosedOnAbsentPrimary},
        {"testFreshApplyAndNoOpLifecycle", testFreshApplyAndNoOpLifecycle},
        {"testSameIdToggleReleasesWrappersByteExact",
            testSameIdToggleReleasesWrappersByteExact},
        {"testNewForeignLineWhileDisabled",
            testNewForeignLineWhileDisabled},
        {"testAdminRemovesWrapperSubset", testAdminRemovesWrapperSubset},
        {"testAdminManuallyUnwrapsWhileDisabled",
            testAdminManuallyUnwrapsWhileDisabled},
        {"testFreshApplyRefusesPreExistingEntry",
            testFreshApplyRefusesPreExistingEntry},
        {"testForeignWrapperProvenanceFailsClosed",
            testForeignWrapperProvenanceFailsClosed},
        {"testMetadataPreservation", testMetadataPreservation},
        {"testSemanticFailureKeepsPreparedThenRecovers",
            testSemanticFailureKeepsPreparedThenRecovers},
        {"testDesiredChangedDuringRecovery",
            testDesiredChangedDuringRecovery},
        {"testPwqualityIcaseLifecycle", testPwqualityIcaseLifecycle},
        {"testRestartRefreshFromPersistedJournal",
            testRestartRefreshFromPersistedJournal},
        {"testFreshDesiredFalseRefusesOrphanWrapper",
            testFreshDesiredFalseRefusesOrphanWrapper},
        {"testFreshDesiredTrueRefusesOrphanWrapper",
            testFreshDesiredTrueRefusesOrphanWrapper},
        {"testDifferentMutationIdWrapperFailsClosedForAnyDesired",
            testDifferentMutationIdWrapperFailsClosedForAnyDesired},
    };
    for (const auto& test : tests) {
        try {
            test.second();
        } catch (const std::exception& exception) {
            std::cerr << "pam_provider_managed_flag_executor_tests failed in "
                      << test.first << ": " << exception.what() << std::endl;
            return 1;
        }
    }
    std::cout << "pam_provider_managed_flag_executor_tests: ok" << std::endl;
    return 0;
}
