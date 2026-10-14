#include "modules/dac/sudo/SudoersAuthenticationTransaction.h"
#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/integrity/ContentDigest.h>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <nlohmann/json.hpp>
using namespace fic::sudoers;
using namespace fic::rollback;
namespace {
void require(bool ok, const std::string& why) { if (!ok) throw std::runtime_error(why); }
std::string read(const std::filesystem::path& p) { std::ifstream file(p); return {std::istreambuf_iterator<char>(file), {}}; }
void put(const std::filesystem::path& p, const std::string& text) { std::ofstream file(p); file << text; }
struct Fixture {
    std::filesystem::path root;
    SudoersConfigurationOptions options;
    MutationJournal journal;
    bool scoped = false;
    AuthenticationHooks hooks;
    Fixture(int n) : root(std::filesystem::temp_directory_path() / ("fic-auth-" + std::to_string(getpid()) + "-" + std::to_string(n))), journal(root / "journal.json") {
        std::filesystem::create_directories(root / "sudoers.d");
        options.mainPath = root / "sudoers"; options.managedPath = root / "sudoers.d/99-fic.conf"; options.enforceOwnership = false;
        put(options.mainPath, "@includedir " + (root / "sudoers.d").string() + "\n");
        std::string error; require(journal.load(error), error);
        hooks.requestedScopedState = [&](bool& requested, std::string&) { requested = scoped; return true; };
    }
    ~Fixture() { AtomicFileWriter::setDirectoryFsyncHookForTests({}); std::filesystem::remove_all(root); }
    AuthenticationTransaction transaction() { return {options, journal, hooks}; }
    MutationRecord record() { auto records = journal.activeRecords({"DAC", "SudoEdit", kAuthenticationPolicy}); require(records.size() == 1, "one active record expected"); return records[0]; }
    UndoReleaseSudoAuthentication payload() { return std::get<UndoReleaseSudoAuthentication>(record().undo.payload); }
};
}
int main() {
    int cases = 0;
    try {
        {
            Fixture f(cases++); const auto path = f.root / "sudoers.d/rules";
            const std::string original = "alice ALL=(root) NOEXEC: NOPASSWD: /bin/echo allowed, \\\r\n\t/bin/true";
            put(path, original); auto result = f.transaction().reconcile(); require(result.ok, result.message);
            const auto id = f.record().id; auto proofs = f.payload().targetProofs;
            result = f.transaction().reconcile(); require(result.ok && !result.changed && f.record().id == id, result.message);
            put(f.root / "sudoers.d/second", "Defaults !authenticate\n");
            result = f.transaction().reconcile(); require(result.ok && f.record().id == id && f.payload().targetProofs.size() == proofs.size() + 1, result.message);
            MutationJournal reloaded(f.root / "journal.json"); std::string e; require(reloaded.load(e), e);
            result = f.transaction().release(f.payload()); require(result.ok && read(path) == original && read(f.root / "sudoers.d/second") == "Defaults !authenticate\n", result.message);
            require(f.journal.setStatus(id, MutationStatus::RolledBack, e), e);
            require(f.transaction().verifyOwnership(e), e);
        }
        {
            Fixture f(cases++); auto a = f.root / "sudoers.d/a", b = f.root / "sudoers.d/b";
            put(a, "alice ALL=NOPASSWD: /bin/true\n"); put(b, "bob ALL=UNKNOWN: NOPASSWD: /bin/false\n");
            const auto before = read(a); auto result = f.transaction().reconcile();
            require(!result.ok && read(a) == before && f.journal.records().empty(), "unsupported preflight mutated files/journal");
        }
        {
            Fixture f(cases++); auto path = f.root / "sudoers.d/rules";
            put(path, "Defaults:alice !authenticate\n"); auto result = f.transaction().reconcile(); require(result.ok, result.message);
            f.scoped = true; const auto before = read(path); result = f.transaction().release(f.payload());
            require(!result.ok && result.conflict && read(path) == before, "requested scoped policy without own record was ignored");
            std::string e; require(!f.transaction().verifyOwnership(e, true), "nested scope ownership allowed");
            SudoersConfiguration configuration(f.options); require(configuration.load(e), e);
            ScopedDefaultsTransaction scopeTransaction(configuration, std::string(kScopedDefaultsPolicyName));
            const auto plan = scopeTransaction.plan({});
            const auto refused = scopeTransaction.apply(plan.fresh, {});
            require(!refused.ok() && refused.operation.conflict && read(path) == before,
                "scoped mechanical transaction nested an independent auth frame");
            f.scoped = false; require(f.transaction().release(f.payload()).ok, "release after intent change");
        }
        {
            Fixture f(cases++); auto path = f.root / "sudoers.d/rules";
            put(path, "alice ALL=NOPASSWD: /bin/echo allowed\n"); auto result = f.transaction().reconcile(); require(result.ok, result.message);
            const auto original = read(path); auto changed = original; changed.replace(changed.rfind("allowed"), 7, "ALL"); put(path, changed);
            result = f.transaction().release(f.payload()); require(!result.ok && read(path) == changed, "drift overwritten");
            put(path, original); put(f.root / "sudoers.d/copy", original);
            result = f.transaction().release(f.payload()); require(!result.ok && read(path) == original, "duplicate ownership accepted");
        }
        {
            Fixture f(cases++); auto a = f.root / "sudoers.d/a", b = f.root / "sudoers.d/b";
            const std::string original = "alice ALL=NOPASSWD: /bin/true\n"; put(a, original); put(b, original);
            bool injected = false;
            f.hooks.beforeWrite = [&](const auto& path) { if (path == b && !injected) { injected = true; put(b, original + "# concurrent\n"); } };
            auto result = f.transaction().reconcile();
            require(!result.ok && read(a) == original && read(b) == original + "# concurrent\n", "selective compensation failed");
            require(f.journal.activeRecords({"DAC", "SudoEdit", kAuthenticationPolicy}).empty(), "fresh compensation lost discard proof");
        }
        for (const std::string phase : {"prepared", "file", "postcondition"}) {
            Fixture f(cases++); auto a = f.root / "sudoers.d/a", b = f.root / "sudoers.d/b";
            const std::string original = "alice ALL=NOPASSWD: /bin/true\n"; put(a, original); put(b, original);
            f.hooks.checkpoint = [&](const char* p) { if (phase == p) throw std::runtime_error("simulated process stop"); };
            try { f.transaction().reconcile(); } catch (const std::runtime_error&) {}
            const auto id = f.record().id; f.hooks.checkpoint = {};
            auto result = f.transaction().reconcile(); require(result.ok, result.message);
            if (phase == "postcondition") require(f.record().id == id, "completed target recovery changed journal identity");
            result = f.transaction().release(f.payload()); require(result.ok && read(a) == original && read(b) == original, result.message);
        }
        {
            Fixture f(cases++); auto path = f.root / "sudoers.d/rules";
            put(path, "alice ALL=NOPASSWD: /bin/true\n"); require(f.transaction().reconcile().ok, "initial apply");
            const auto payload = f.payload(); std::filesystem::remove(path);
            auto result = f.transaction().release(payload); require(result.ok && result.targetMissing && !std::filesystem::exists(path), result.message);
        }
        {
            Fixture f(cases++); const auto path = f.root / "sudoers.d/rules";
            const std::string original = "alice ALL=NOPASSWD: /bin/true\n";
            put(path, original);
            AtomicFileWriter::setDirectoryFsyncHookForTests([&](const std::string& name) { return name != (f.root / "journal.json").string(); });
            const auto result = f.transaction().reconcile();
            require(!result.ok && read(path) == original, "journal durability failure mutated sudoers");
            AtomicFileWriter::setDirectoryFsyncHookForTests({});
            std::string error; require(f.journal.load(error), error);
            require(f.transaction().reconcile().ok, "durable journal recovery failed");
        }
        {
            Fixture f(cases++); auto path = f.root / "sudoers.d/rules";
            put(path, "alice ALL=NOPASSWD: /bin/true\n");
            require(f.transaction().reconcile().ok, "initial apply");
            const auto id = f.record().id;
            auto second = f.root / "sudoers.d/second"; put(second, "Defaults !authenticate\n");
            f.hooks.checkpoint = [](const char* phase) { if (std::string(phase) == "prepared") throw std::runtime_error("stop refresh"); };
            try { f.transaction().reconcile(); } catch (const std::runtime_error&) {}
            f.hooks.checkpoint = {};
            require(f.transaction().reconcile().ok && f.record().id == id, "refresh recovery lost previous ownership or id");
            auto payload = f.payload();
            f.hooks.checkpoint = [](const char* phase) { if (std::string(phase) == "release_file") throw std::runtime_error("stop release"); };
            try { f.transaction().release(payload); } catch (const std::runtime_error&) {}
            f.hooks.checkpoint = {};
            auto result = f.transaction().release(payload);
            require(result.ok && read(path) == "alice ALL=NOPASSWD: /bin/true\n" && read(second) == "Defaults !authenticate\n", result.message);
        }
        {
            Fixture f(cases++); const auto path = f.root / "sudoers.d/rules";
            put(path, "alice ALL=NOPASSWD: /bin/true\n"); require(f.transaction().reconcile().ok, "initial apply");
            const auto payload = f.payload();
            const auto owned = read(path);
            put(f.options.mainPath, "root ALL=ALL\n");
            put(path, owned + "# detached foreign comment\n");
            auto result = f.transaction().release(payload);
            require(result.ok && read(path) == "alice ALL=NOPASSWD: /bin/true\n# detached foreign comment\n", "detached proof path not released selectively");
        }
        {
            Fixture f(cases++); const auto path = f.root / "sudoers.d/rules";
            put(path, "Defaults:alice !authenticate\n");
            auto lines = splitPhysicalLines(read(path)); auto id = generateSudoWrapperMutationId(0);
            auto digest = SudoDisabledWrapper{{}, {}, lines}.payloadDigest();
            disableSudoEntry(lines, 0, 1, std::string(kScopedDefaultsPolicyName), id);
            put(path, joinPhysicalLines(lines));
            SudoScopedDefaultsWrapperProof proof{id, canonicalizeSudoProofPath(path), digest};
            MutationRecord record;
            record.policy = {"DAC", "SudoEdit", std::string(kScopedDefaultsPolicyName)};
            record.resource = std::string(kScopedDefaultsResource); record.undo.backend = MutationBackend::Sudo;
            record.undo.payload = UndoReleaseSudoScopedDefaults{std::string(kScopedDefaultsPolicyName), {}, {proof}};
            MutationId recordId; std::string error;
            require(f.journal.prepareMutation(record, recordId, error) && f.journal.setStatus(recordId, MutationStatus::Applied, error), error);
            const auto result = f.transaction().reconcile(); require(result.ok && !result.changed, result.message);
            require(f.journal.activeRecords({"DAC", "SudoEdit", kAuthenticationPolicy}).empty(), "no-op auth invented ownership");
            SudoersConfiguration config(f.options); require(config.load(error), error);
            require(!guardScopedAuthenticationRelease(config, {proof}, true, error), "requested authentication without journal did not protect scope release");
        }
        {
            Fixture f(cases++); auto path = f.root / "sudoers.d/rules";
            put(path, "alice ALL=NOPASSWD: /bin/true\n"); require(f.transaction().reconcile().ok, "initial apply");
            const auto document = nlohmann::json::parse(read(f.root / "journal.json"));
            for (int mutation = 0; mutation < 7; ++mutation) {
                auto corrupted = document;
                auto& record = corrupted["records"][0]; auto& proof = record["undo"]["target_proofs"][0];
                if (mutation == 0) proof["replacement_digest"] = "invalid";
                if (mutation == 1) proof.erase("original_digest");
                if (mutation == 2) proof["canonical_path"] = "relative/sudoers";
                if (mutation == 3) record["policy"]["policy"] = "sudo_timeout";
                if (mutation == 4) record["undo"].erase("previous_proofs");
                if (mutation == 5) record["undo"]["target_proofs"].push_back(proof);
                if (mutation == 6) record["resource"] = "passwd_tries";
                put(f.root / "journal.json", corrupted.dump());
                MutationJournal loaded(f.root / "journal.json"); std::string error;
                require(!loaded.load(error), "malformed authentication provenance admitted on load");
            }
            put(f.root / "journal.json", document.dump());
            auto invalid = f.record();
            auto payload = std::get<UndoReleaseSudoAuthentication>(invalid.undo.payload);
            payload.targetProofs[0].replacementDigest = "invalid"; invalid.undo.payload = payload;
            MutationId id; std::string error;
            require(!f.journal.prepareMutation(invalid, id, error), "writer accepted payload rejected by reader");
        }
        {
            Fixture f(cases++); const auto path = f.root / "sudoers.d/rules";
            const auto untouched = f.options.mainPath;
            put(path, "alice ALL=NOPASSWD: /bin/true\n");
            f.hooks.checkpoint = [&](const char* phase) {
                if (std::string(phase) == "file") put(untouched, read(untouched) + "# concurrent topology-source change\n");
            };
            const auto result = f.transaction().reconcile();
            require(!result.ok && read(path) == "alice ALL=NOPASSWD: /bin/true\n" &&
                read(untouched).find("concurrent topology-source change") != std::string::npos,
                "foreign drift in an unmodified graph source was accepted or overwritten");
        }
        {
            Fixture f(cases++); const auto a = f.root / "sudoers.d/a", b = f.root / "sudoers.d/b";
            const std::string original = "alice ALL=NOPASSWD: /bin/true\n"; put(a, original); put(b, original);
            const auto validator = f.root / "mock-validator";
            put(validator, "#!/bin/sh\nif /bin/grep -q '#@FIC_AUTH_ACTIVE' '" + a.string() + "' '" + b.string() + "'; then exit 1; fi\nexit 0\n");
            std::filesystem::permissions(validator, std::filesystem::perms::owner_all);
            f.options.validatorPath = validator; f.options.verifyValidatorHash = false;
            const auto result = f.transaction().reconcile();
            require(!result.ok && read(a) == original && read(b) == original &&
                f.journal.activeRecords({"DAC", "SudoEdit", kAuthenticationPolicy}).empty(),
                "native candidate rejection blocked safe selective compensation: " + result.message);
        }
        {
            Fixture f(cases++); auto path = f.root / "sudoers.d/rules";
            const std::string original = "alice ALL=NOPASSWD: /bin/true";
            put(path, original); require(f.transaction().reconcile().ok, "initial apply");
            const auto owned = read(path); put(path, owned + "# concurrent suffix\n");
            const auto foreign = read(path); auto result = f.transaction().release(f.payload());
            require(!result.ok && result.conflict && read(path) == foreign,
                "unterminated original restored into foreign suffix");
            put(path, owned); result = f.transaction().release(f.payload());
            require(result.ok && read(path) == original, result.message);
        }
        std::cout << "Authentication lifecycle cases=" << cases << " PASS\n";
    } catch (const std::exception& e) { std::cerr << "FAIL after case " << cases << ": " << e.what() << '\n'; return 1; }
    return 0;
}
