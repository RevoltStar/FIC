#include "modules/dac/sudo/SudoersGlobalDefaultsTransaction.h"
#include "modules/dac/sudo/SudoersManagedInclude.h"

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <unistd.h>
#include <fic/core/fs/AtomicFileWriter.h>

using namespace fic::sudoers;
using namespace fic::rollback;

namespace {
void require(bool ok, const std::string& error) {
    if (!ok) throw std::runtime_error(error);
}
std::string read(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
void write(const std::filesystem::path& path, const std::string& bytes) {
    AtomicWriteOptions options;
    options.createIfMissing = true;
    options.rejectSymlink = true;
    std::string error;
    require(AtomicFileWriter::write(path.string(), bytes, options, &error), error);
}

struct Crash {};
void providerWitnessDrift(const std::filesystem::path& root) {
    std::filesystem::create_directories(root / "sudoers.d");
    SudoersConfigurationOptions options;
    options.mainPath = root / "sudoers";
    options.managedPath = root / "sudoers.d/99-fic.conf";
    options.enforceOwnership = false;
    const std::string original = "root ALL=(ALL) ALL\n";
    write(options.mainPath, original);
    bool unchanged = true;
    options.verifyProviderUnchanged = [&unchanged](std::string& error) {
        if (!unchanged) error = "fixture provider changed";
        return unchanged;
    };
    MutationJournal journal(root / "journal.json");
    std::string error;
    require(journal.load(error), error);
    const PolicyRef identity{"DAC", "SudoEdit", "sudo_passwd_tries"};
    const auto failed = GlobalDefaultsTransaction(options, journal, [&](auto phase) {
        if (phase == GlobalDefaultsPhase::OwnedFileInstalled) unchanged = false;
    }).reconcile(identity, "passwd_tries", "Defaults passwd_tries=3", "3");
    require(!failed.ok && read(options.mainPath) == original,
            "changed provider was allowed to connect owned file");
    const auto prepared = journal.activeRecords(identity);
    require(prepared.size() == 1 && prepared.front().status == MutationStatus::Prepared,
            "provider drift lost durable unresolved provenance");
    unchanged = true;
    const auto recovered = GlobalDefaultsTransaction(options, journal).reconcile(
        identity, "passwd_tries", "Defaults passwd_tries=3", "3");
    require(recovered.ok && journal.activeRecords(identity).front().id == prepared.front().id,
            "provider-drift recovery lost ownership identity: " + recovered.message);
    std::cout << "provider witness recheck before include installation PASS\n";
}
void duplicateIncludeRelease(const std::filesystem::path& root) {
    std::filesystem::create_directories(root / "sudoers.d");
    SudoersConfigurationOptions options;
    options.mainPath = root / "sudoers";
    options.managedPath = root / "sudoers.d/99-fic.conf";
    options.enforceOwnership = false;
    const std::string original = "root ALL=(ALL) ALL\n";
    write(options.mainPath, original);
    MutationJournal journal(root / "journal.json");
    std::string error;
    require(journal.load(error), error);
    const PolicyRef identity{"DAC", "SudoEdit", "sudo_passwd_tries"};
    GlobalDefaultsTransaction transaction(options, journal);
    auto applied = transaction.reconcile(identity, "passwd_tries", "Defaults passwd_tries=3", "3");
    require(applied.ok, applied.message);
    const auto id = journal.activeRecords(identity).front().id;
    const std::string duplicate = "@include " + options.managedPath.string() + "\n";
    write(options.mainPath, original + duplicate + managedIncludeBlock(options.managedPath));
    applied = transaction.reconcile(identity, "passwd_tries", "Defaults passwd_tries=3", "3");
    require(applied.ok, "duplicate explicit include rejected without semantic proof: " + applied.message);
    const auto released = transaction.release(journal.activeRecords(identity).front());
    require(!released.ok && released.conflict, "connected owned file was deleted");
    require(read(options.mainPath) == original + duplicate,
            "last release removed a foreign include");
    require(std::filesystem::exists(options.managedPath) &&
            read(options.managedPath).find("Defaults ") == std::string::npos,
            "connected container was not retained inert");
    require(journal.setStatus(id, MutationStatus::RollbackFailed, error), error);
    // Administrator resolves the foreign connection; retry may then release
    // the inert owned container using its original durable provenance.
    write(options.mainPath, original);
    const auto retried = transaction.release(journal.activeRecords(identity).front());
    require(retried.ok, retried.message);
    require(journal.setStatus(id, MutationStatus::RolledBack, error), error);
    require(!std::filesystem::exists(options.managedPath) && read(options.mainPath) == original,
            "duplicate-include resolution did not complete safely");
    std::cout << "duplicate include apply and connected-container release conflict PASS\n";
}
void changedRequestRecovery(const std::filesystem::path& root) {
    const PolicyRef tries{"DAC", "SudoEdit", "sudo_passwd_tries"};
    const PolicyRef timeout{"DAC", "SudoEdit", "sudo_timeout"};
    unsigned scenarios = 0;
    for (const bool otherPolicy : {false, true}) {
        for (const auto cut : {GlobalDefaultsPhase::Prepared,
                               GlobalDefaultsPhase::OwnedFileInstalled,
                               GlobalDefaultsPhase::IncludeInstalled}) {
            const auto fixture = root / std::to_string(++scenarios);
            std::filesystem::create_directories(fixture / "sudoers.d");
            SudoersConfigurationOptions options;
            options.mainPath = fixture / "sudoers";
            options.managedPath = fixture / "sudoers.d/99-fic.conf";
            options.enforceOwnership = false;
            write(options.mainPath, "root ALL=(ALL) ALL\n");
            const auto path = fixture / "journal.json";
            MutationJournal journal(path);
            std::string error;
            require(journal.load(error), error);
            bool interrupted = false;
            try {
                GlobalDefaultsTransaction(options, journal, [cut](auto phase) {
                    if (phase == cut) throw Crash{};
                }).reconcile(tries, "passwd_tries", "Defaults passwd_tries=3", "3");
            } catch (const Crash&) { interrupted = true; }
            require(interrupted, "changed-request crash boundary was not reached");
            const auto id = journal.activeRecords(tries).front().id;
            MutationJournal restarted(path);
            require(restarted.load(error), error);
            const auto recovered = GlobalDefaultsTransaction(options, restarted).reconcile(
                otherPolicy ? timeout : tries, otherPolicy ? "timestamp_timeout" : "passwd_tries",
                otherPolicy ? "Defaults timestamp_timeout=5" : "Defaults passwd_tries=4",
                otherPolicy ? "5" : "4");
            require(recovered.ok, recovered.message);
            const auto records = restarted.activeRecords(tries);
            require(records.size() == 1 && records.front().id == id &&
                    records.front().status == MutationStatus::Applied,
                    "changed request lost or duplicated interrupted ownership");
            const auto& payload = std::get<UndoReleaseSudoGlobalDefault>(records.front().undo.payload);
            require(payload.previousLine.empty(), "Applied retained stale transition evidence");
            require(read(options.managedPath).find(otherPolicy ? "passwd_tries=3" : "passwd_tries=4")
                        != std::string::npos, "interrupted target was not safely reconciled");
            require(restarted.activeRecords(timeout).size() == (otherPolicy ? 1u : 0u),
                    "different-policy request has incorrect ownership");
        }
    }
    std::cout << scenarios << " changed-request recovery scenarios PASS\n";
}
void crashRecovery(const std::filesystem::path& root) {
    const PolicyRef identity{"DAC", "SudoEdit", "sudo_passwd_tries"};
    unsigned scenarios = 0;
    const std::vector<GlobalDefaultsPhase> applyCuts{
        GlobalDefaultsPhase::BeforePrepared, GlobalDefaultsPhase::Prepared,
        GlobalDefaultsPhase::OwnedFileInstalled, GlobalDefaultsPhase::IncludeInstalled,
        GlobalDefaultsPhase::PostconditionVerified};
    for (const bool refresh : {false, true}) {
        for (const auto cut : applyCuts) {
            const auto fixture = root / std::to_string(++scenarios);
            std::filesystem::create_directories(fixture / "sudoers.d");
            SudoersConfigurationOptions options;
            options.mainPath = fixture / "sudoers";
            options.managedPath = fixture / "sudoers.d/99-fic.conf";
            options.enforceOwnership = false;
            const auto journalPath = fixture / "journal.json";
            const std::string foreign = "# foreign\r\nroot ALL=(ALL) ALL\n";
            write(options.mainPath, foreign);
            MutationJournal journal(journalPath);
            std::string error;
            require(journal.load(error), error);
            MutationId previousId = 0;
            if (refresh) {
                const auto result = GlobalDefaultsTransaction(options, journal).reconcile(
                    identity, "passwd_tries", "Defaults passwd_tries=3", "3");
                require(result.ok, result.message);
                previousId = journal.activeRecords(identity).front().id;
            }
            bool interrupted = false;
            try {
                GlobalDefaultsTransaction(options, journal, [cut](auto phase) {
                    if (phase == cut) throw Crash{};
                }).reconcile(identity, "passwd_tries", "Defaults passwd_tries=4", "4");
            } catch (const Crash&) { interrupted = true; }
            require(interrupted, "apply crash boundary was not reached");
            const auto before = journal.activeRecords(identity);
            require(before.size() <= 1, "crash duplicated active ownership");
            if (!refresh && cut == GlobalDefaultsPhase::BeforePrepared) {
                require(before.empty() && !std::filesystem::exists(options.managedPath),
                        "mutation happened before Prepared");
                require(read(options.mainPath) == foreign, "main changed before Prepared");
            } else {
                require(before.size() == 1, "crash lost provenance");
                if (cut != GlobalDefaultsPhase::BeforePrepared)
                    require(before.front().status == MutationStatus::Prepared, "crash incorrectly committed");
            }
            MutationJournal restarted(journalPath);
            require(restarted.load(error), error);
            auto recovered = GlobalDefaultsTransaction(options, restarted).reconcile(
                identity, "passwd_tries", "Defaults passwd_tries=4", "4");
            require(recovered.ok, recovered.message);
            const auto active = restarted.activeRecords(identity);
            require(active.size() == 1 && active.front().status == MutationStatus::Applied,
                    "recovery did not prove Applied exactly once");
            if (previousId) require(active.front().id == previousId, "refresh lost original mutation ID");
            if (!before.empty()) require(active.front().id == before.front().id, "Prepared recovery minted a new ID");
        }
    }
    for (const auto cut : {GlobalDefaultsPhase::OwnedFileInstalled, GlobalDefaultsPhase::InertFileInstalled,
                           GlobalDefaultsPhase::IncludeReleased, GlobalDefaultsPhase::FileReleased}) {
        const auto fixture = root / std::to_string(++scenarios);
        std::filesystem::create_directories(fixture / "sudoers.d");
        SudoersConfigurationOptions options;
        options.mainPath = fixture / "sudoers";
        options.managedPath = fixture / "sudoers.d/99-fic.conf";
        options.enforceOwnership = false;
        const std::string foreign = "# original without terminal newline";
        write(options.mainPath, foreign);
        const auto journalPath = fixture / "journal.json";
        MutationJournal journal(journalPath);
        std::string error;
        require(journal.load(error), error);
        auto applied = GlobalDefaultsTransaction(options, journal).reconcile(
            identity, "passwd_tries", "Defaults passwd_tries=3", "3");
        require(applied.ok, applied.message);
        bool interrupted = false;
        try {
            GlobalDefaultsTransaction(options, journal, [cut](auto phase) {
                if (phase == cut) throw Crash{};
            }).release(journal.activeRecords(identity).front());
        } catch (const Crash&) { interrupted = true; }
        require(interrupted, "release crash boundary was not reached");
        MutationJournal restarted(journalPath);
        require(restarted.load(error), error);
        const auto owned = restarted.activeRecords(identity);
        require(owned.size() == 1, "release crash lost provenance");
        auto released = GlobalDefaultsTransaction(options, restarted).release(owned.front());
        require(released.ok, released.message);
        require(restarted.setStatus(owned.front().id, MutationStatus::RolledBack, error), error);
        require(!std::filesystem::exists(options.managedPath) && read(options.mainPath) == foreign,
                "last-owner crash recovery lost exact foreign bytes");
    }
    std::cout << scenarios << " durable-boundary crash recovery scenarios PASS\n";
}

void faultAndDrift(const std::filesystem::path& root) {
    const PolicyRef identity{"DAC", "SudoEdit", "sudo_env_reset"};
    unsigned scenarios = 0;
    for (const std::string target : {"journal", "managed", "main"}) {
        const auto fixture = root / std::to_string(++scenarios);
        std::filesystem::create_directories(fixture / "sudoers.d");
        SudoersConfigurationOptions options;
        options.mainPath = fixture / "sudoers";
        options.managedPath = fixture / "sudoers.d/99-fic.conf";
        options.enforceOwnership = false;
        const auto journalPath = fixture / "journal.json";
        const std::string foreign = "Defaults env_reset\n";
        write(options.mainPath, foreign);
        MutationJournal journal(journalPath);
        std::string error;
        require(journal.load(error), error);
        const auto failedPath = target == "journal" ? journalPath
            : target == "managed" ? options.managedPath : options.mainPath;
        AtomicFileWriter::setDirectoryFsyncHookForTests([failedPath, target](const auto& path) {
            if (path != failedPath.string()) return true;
            if (target == "main") return read(failedPath).find("#@FIC_INCLUDE_BEGIN") == std::string::npos;
            return false;
        });
        const auto failed = GlobalDefaultsTransaction(options, journal).reconcile(
            identity, "env_reset", "Defaults env_reset", "ENABLE");
        AtomicFileWriter::setDirectoryFsyncHookForTests({});
        require(!failed.ok, "failed fsync was reported as successful apply");
        if (target == "journal")
            require(!std::filesystem::exists(options.managedPath) && read(options.mainPath) == foreign,
                    "system mutation preceded durable journal");
        MutationJournal restarted(journalPath);
        require(restarted.load(error), error);
        require(restarted.activeRecords(identity).size() == 1, "fsync failure lost Prepared provenance");
        const auto id = restarted.activeRecords(identity).front().id;
        const auto recovered = GlobalDefaultsTransaction(options, restarted).reconcile(
            identity, "env_reset", "Defaults env_reset", "ENABLE");
        require(recovered.ok, recovered.message);
        require(restarted.activeRecords(identity).size() == 1 &&
                restarted.activeRecords(identity).front().id == id, "fsync retry duplicated provenance");
    }
    for (const auto cut : {GlobalDefaultsPhase::Prepared, GlobalDefaultsPhase::OwnedFileInstalled,
                           GlobalDefaultsPhase::IncludeInstalled, GlobalDefaultsPhase::PostconditionVerified}) {
        const auto fixture = root / std::to_string(++scenarios);
        std::filesystem::create_directories(fixture / "sudoers.d");
        SudoersConfigurationOptions options;
        options.mainPath = fixture / "sudoers";
        options.managedPath = fixture / "sudoers.d/99-fic.conf";
        options.enforceOwnership = false;
        write(options.mainPath, "Defaults env_reset\n");
        MutationJournal journal(fixture / "journal.json");
        std::string error;
        require(journal.load(error), error);
        const std::string replacement = "# foreign replacement\nDefaults !env_reset\n";
        const auto failed = GlobalDefaultsTransaction(options, journal, [&](auto phase) {
            if (phase == cut) write(options.managedPath, replacement);
        }).reconcile(identity, "env_reset", "Defaults env_reset", "ENABLE");
        require(!failed.ok && read(options.managedPath) == replacement,
                "drift was overwritten or reported successful");
        const auto active = journal.activeRecords(identity);
        require(active.size() == 1 && active.front().status == MutationStatus::Prepared,
                "drift resolved unresolved provenance");
        const auto retry = GlobalDefaultsTransaction(options, journal).reconcile(
            identity, "env_reset", "Defaults env_reset", "ENABLE");
        require(!retry.ok && retry.conflict && read(options.managedPath) == replacement,
                "recovery adopted a foreign replacement");
    }
    {
        const auto fixture = root / std::to_string(++scenarios);
        std::filesystem::create_directories(fixture / "sudoers.d");
        SudoersConfigurationOptions options;
        options.mainPath = fixture / "sudoers";
        options.managedPath = fixture / "sudoers.d/99-fic.conf";
        options.enforceOwnership = false;
        write(options.mainPath, "Defaults env_reset\n");
        MutationJournal journal(fixture / "journal.json");
        std::string error;
        require(journal.load(error), error);
        auto applied = GlobalDefaultsTransaction(options, journal).reconcile(
            identity, "env_reset", "Defaults env_reset", "ENABLE");
        require(applied.ok, applied.message);
        const std::string replacement = "# foreign concurrent replacement\n";
        AtomicFileWriter::setRemovePreunlinkHookForTests([&](const auto& path) {
            if (path == options.managedPath.string()) {
                std::filesystem::remove(options.managedPath);
                write(options.managedPath, replacement);
            }
        });
        const auto released = GlobalDefaultsTransaction(options, journal).release(journal.activeRecords(identity).front());
        AtomicFileWriter::setRemovePreunlinkHookForTests({});
        require(!released.ok && read(options.managedPath) == replacement,
                "conditional release deleted the substituted foreign file");
        require(journal.activeRecords(identity).size() == 1, "unlink conflict lost ownership provenance");
    }
    std::cout << scenarios << " fsync and ownership-drift scenarios PASS\n";
}
}

int main() {
    std::string pattern = "/tmp/fic-sudo-global-tests-XXXXXX";
    const char* directory = ::mkdtemp(pattern.data());
    if (!directory) return 1;
    const std::filesystem::path root(directory);
    try {
        const auto main = root / "sudoers";
        const auto managed = root / "sudoers.d/99-fic.conf";
        std::filesystem::create_directory(managed.parent_path());
        const std::string foreign = "# foreign bytes\r\nDefaults env_reset\nroot ALL=(ALL) ALL\n";
        write(main, foreign);
        SudoersConfigurationOptions options;
        options.mainPath = main;
        options.managedPath = managed;
        options.enforceOwnership = false;
        MutationJournal journal(root / "journal.json");
        std::string error;
        require(journal.load(error), error);
        GlobalDefaultsTransaction transaction(options, journal);
        const PolicyRef env{"DAC", "SudoEdit", "sudo_env_reset"};
        const PolicyRef tries{"DAC", "SudoEdit", "sudo_passwd_tries"};
        auto applied = transaction.reconcile(env, "env_reset", "Defaults env_reset", "ENABLE");
        require(applied.ok, applied.message);
        require(read(main) == foreign + managedIncludeBlock(managed), "foreign main bytes changed");
        require(journal.activeRecords(env).size() == 1, "foreign-compliant state lacks ownership");
        const auto originalId = journal.activeRecords(env).front().id;
        applied = transaction.reconcile(env, "env_reset", "Defaults env_reset", "ENABLE");
        require(applied.ok, applied.message);
        require(journal.activeRecords(env).size() == 1 &&
                journal.activeRecords(env).front().id == originalId, "reapply duplicates ownership");
        applied = transaction.reconcile(tries, "passwd_tries", "Defaults passwd_tries=4", "4");
        require(applied.ok, applied.message);
        auto released = transaction.release(journal.activeRecords(env).front());
        require(released.ok, released.message);
        require(journal.setStatus(originalId, MutationStatus::RolledBack, error), error);
        require(read(managed).find("passwd_tries=4") != std::string::npos,
                "release damaged the surviving owner");
        released = transaction.release(journal.activeRecords(tries).front());
        require(released.ok, released.message);
        require(read(main) == foreign, "last-owner release changed foreign bytes");
        require(!std::filesystem::exists(managed), "last-owner file not released");
        require(journal.setStatus(journal.activeRecords(tries).front().id,
                                  MutationStatus::RolledBack, error), error);
        write(managed, "# foreign target\nDefaults env_reset\n");
        require(transaction.verifyNoOwnedSetting("env_reset", error), error);
        write(main, foreign + managedIncludeBlock(managed));
        require(!transaction.verifyNoOwnedSetting("env_reset", error),
                "orphan include was ignored by construction/no-record verification");
        write(main, foreign);
        const auto before = read(managed);
        applied = transaction.reconcile(env, "env_reset", "Defaults env_reset", "ENABLE");
        require(!applied.ok && applied.conflict, "foreign target adopted");
        require(read(managed) == before && read(main) == foreign, "conflict mutated foreign bytes");
        std::cout << "global ownership, reapply, independent release, last-owner release, foreign conflict PASS\n";
        crashRecovery(root / "crashes");
        changedRequestRecovery(root / "changed-requests");
        duplicateIncludeRelease(root / "duplicate-include");
        providerWitnessDrift(root / "provider-witness");
        faultAndDrift(root / "faults");
        std::filesystem::remove_all(root);
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        std::filesystem::remove_all(root);
        return 1;
    }
}
