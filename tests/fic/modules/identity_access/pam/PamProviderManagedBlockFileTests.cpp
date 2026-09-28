#include "modules/identity_access/pam/PamProviderManagedBlockFile.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace {

using namespace fic::identity::pam;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        char pattern[] = "/tmp/fic-pam-provider-block-tests-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        path = created;
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }

    std::filesystem::path path;
};

std::string readFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

PamProviderEntrySpec testSpec(std::uint64_t id, const std::string& value) {
    PamProviderEntrySpec spec;
    spec.provider = "pam_faillock";
    spec.policy = "failed_authentication_attempts";
    spec.managedKey = "deny";
    spec.value = value;
    spec.mutationId = id;
    return spec;
}

PamProviderOwnershipExpectation testExpectation(std::uint64_t id,
                                                const std::string& body) {
    PamProviderOwnershipExpectation expectation;
    expectation.provider = "pam_faillock";
    expectation.policy = "failed_authentication_attempts";
    expectation.managedKey = "deny";
    expectation.body = body;
    expectation.mutationId = id;
    return expectation;
}

PamProviderContainerReadResult readContainer(
    const std::filesystem::path& path,
    PamProviderAbsentContainerDecision decision) {
    std::string error;
    return PamProviderManagedBlockFile::readForMutation(
        path, decision, error);
}

PamProviderContainerWriteResult writeContainer(
    const std::filesystem::path& path,
    bool containerWasAbsent,
    const AtomicTargetState& snapshot,
    const std::string& content) {
    std::string error;
    return PamProviderManagedBlockFile::writeMutation(
        path, containerWasAbsent, snapshot, content, error);
}

void runAllContainerTests() {
    // 47. absent + creation Unknown/Unsafe -> no file created.
    {
        TemporaryDirectory temp;
        const auto path = temp.path / "faillock.conf";
        const auto read = readContainer(
            path, PamProviderAbsentContainerDecision::FailClosed);
        require(!read.ok, "absent container must be refused (fail closed)");
        require(!read.error.empty(), "typed refusal requires a diagnostic");
        require(!std::filesystem::exists(path),
                "refused creation must not create the file");
    }

    // 48. absent + Safe -> create FIC-owned container with the block.
    {
        TemporaryDirectory temp;
        const auto path = temp.path / "faillock.conf";
        const auto read = readContainer(
            path, PamProviderAbsentContainerDecision::CreateFicOwned);
        require(read.ok &&
                    read.state == PamProviderContainerState::Absent,
                "proven absent container must be classified Absent");
        const auto mutation = setPamProviderManagedEntry(
            "", testSpec(42, "5"), PamProviderBlockPlacementRequest::End);
        require(mutation.ok, "block mutation for absent container failed");
        const auto write = writeContainer(
            path, true, read.snapshot, mutation.content);
        require(write.ok, "absent container creation failed");
        require(write.containerCreated,
                "absent container creation must report containerCreated");
        const std::string content = readFile(path);
        require(content == mutation.content,
                "created container content mismatch");
        struct ::stat st {};
        require(::stat(path.c_str(), &st) == 0, "stat of container failed");
        require((st.st_mode & 0777) == 0644,
                "FIC-created container must be 0644");
        const auto parse = parsePamProviderManagedBlock(content);
        const auto proof = provePamProviderEntryOwnership(
            parse, testExpectation(42, "deny = 5"));
        require(proof.proven, "created container entry not owned");
    }

    // 49. pre-existing empty file is NOT classified FIC-created.
    {
        TemporaryDirectory temp;
        const auto path = temp.path / "faillock.conf";
        {
            std::ofstream output(path, std::ios::binary | std::ios::trunc);
            require(output.is_open(), "fixture creation failed");
        }
        const auto read = readContainer(
            path, PamProviderAbsentContainerDecision::CreateFicOwned);
        require(read.ok &&
                    read.state == PamProviderContainerState::PreExisting,
                "existing empty file must be PreExisting");
        const auto mutation = setPamProviderManagedEntry(
            "", testSpec(42, "5"), PamProviderBlockPlacementRequest::End);
        const auto write = writeContainer(
            path, false, read.snapshot, mutation.content);
        require(write.ok && !write.containerCreated,
                "pre-existing container must never be reported created");
        require(pamProviderContainerReleaseDecision(
                    write.containerCreated, "") ==
                    PamProviderContainerReleaseDecision::RetainUnproven,
                "pre-existing empty container must never be unlinkable");
    }
}

void runAllContainerTests2() {
    // 50. FIC-created container + final entry removal + no foreign
    // content -> removable according to provenance.
    {
        TemporaryDirectory temp;
        const auto path = temp.path / "faillock.conf";
        const auto mutation = setPamProviderManagedEntry(
            "", testSpec(42, "5"), PamProviderBlockPlacementRequest::End);
        const auto write = writeContainer(path, true, {}, mutation.content);
        require(write.ok && write.containerCreated,
                "container creation failed");
        const auto removal = removePamProviderManagedEntry(
            mutation.content, testExpectation(42, "deny = 5"),
            PamProviderBlockPlacementRequest::End);
        require(removal.ok &&
                    removal.outcome ==
                        PamProviderRemovalResult::Outcome::BlockRemoved,
                "final removal must drop the block");
        require(removal.content.empty(),
                "final removal of a FIC-only container leaves empty file");
        require(pamProviderContainerReleaseDecision(
                    true, removal.content) ==
                    PamProviderContainerReleaseDecision::RemovableFicOwned,
                "FIC-created empty container must be removable");
    }

    // 51. FIC-created container + administrator foreign bytes -> block
    // removed, container/foreign bytes retained.
    {
        TemporaryDirectory temp;
        const auto path = temp.path / "faillock.conf";
        const auto mutation = setPamProviderManagedEntry(
            "", testSpec(42, "5"), PamProviderBlockPlacementRequest::End);
        require(writeContainer(path, true, {}, mutation.content).ok,
                "container creation failed");
        std::ofstream append(path, std::ios::binary | std::ios::app);
        append << "admin = 1\n";
        append.close();
        const std::string drifted = readFile(path);
        const auto read = readContainer(
            path, PamProviderAbsentContainerDecision::FailClosed);
        require(read.ok && read.content == drifted,
                "re-read of drifted container failed");
        const auto removal = removePamProviderManagedEntry(
            read.content, testExpectation(42, "deny = 5"),
            PamProviderBlockPlacementRequest::End);
        require(removal.ok, "removal with foreign tail failed");
        require(removal.content == "admin = 1\n",
                "foreign bytes must be retained when the block goes");
        require(pamProviderContainerReleaseDecision(
                    true, removal.content) ==
                    PamProviderContainerReleaseDecision::RetainForeignContent,
                "container with foreign bytes must never be unlinked");
    }

    // 52. pre-existing container is NEVER unlinked.
    {
        TemporaryDirectory temp;
        const auto path = temp.path / "faillock.conf";
        const std::string pre = "a = 1\n";
        {
            std::ofstream output(path, std::ios::binary | std::ios::trunc);
            output << pre;
        }
        const auto read = readContainer(
            path, PamProviderAbsentContainerDecision::FailClosed);
        require(read.ok, "pre-existing read failed");
        const auto add = setPamProviderManagedEntry(
            pre, testSpec(42, "5"), PamProviderBlockPlacementRequest::End);
        require(writeContainer(path, false, read.snapshot, add.content).ok,
                "pre-existing write failed");
        const auto removal = removePamProviderManagedEntry(
            add.content, testExpectation(42, "deny = 5"),
            PamProviderBlockPlacementRequest::End);
        require(removal.ok && removal.content == pre,
                "pre-existing container must be restored byte-exact");
        require(pamProviderContainerReleaseDecision(
                    false, removal.content) ==
                    PamProviderContainerReleaseDecision::RetainUnproven,
                "pre-existing container must never be classified FIC-owned");
        require(std::filesystem::exists(path),
                "pre-existing container must survive the release");
    }
}

void runAllFilesystemTests() {
    // 53. symlink refused (read and write paths).
    {
        TemporaryDirectory temp;
        const auto real = temp.path / "real.conf";
        const auto link = temp.path / "link.conf";
        {
            std::ofstream output(real, std::ios::binary | std::ios::trunc);
            output << "a = 1\n";
        }
        require(::symlink(real.c_str(), link.c_str()) == 0,
                "symlink fixture failed");
        const auto read = readContainer(
            link, PamProviderAbsentContainerDecision::CreateFicOwned);
        require(!read.ok, "symlink must be refused by the trusted read");
        const auto mutation = setPamProviderManagedEntry(
            "", testSpec(42, "5"), PamProviderBlockPlacementRequest::End);
        const auto write = writeContainer(link, true, {}, mutation.content);
        require(!write.ok, "symlink must be refused by the atomic write");
        require(std::filesystem::is_symlink(link),
                "refused write must not replace the symlink");
        require(readFile(real) == "a = 1\n",
                "symlink target must stay untouched");
    }

    // 54. non-regular target refused.
    {
        TemporaryDirectory temp;
        const auto fifo = temp.path / "fifo.conf";
        require(::mkfifo(fifo.c_str(), 0600) == 0, "fifo fixture failed");
        const auto read = readContainer(
            fifo, PamProviderAbsentContainerDecision::CreateFicOwned);
        require(!read.ok, "non-regular target must be refused");
    }

    // 55. injected durability failure does not report success.
    {
        TemporaryDirectory temp;
        const auto path = temp.path / "faillock.conf";
        AtomicFileWriter::setDirectoryFsyncHookForTests(
            [](const std::string&) { return false; });
        bool hookFailed = false;
        try {
            const auto mutation = setPamProviderManagedEntry(
                "", testSpec(42, "5"),
                PamProviderBlockPlacementRequest::End);
            const auto write =
                writeContainer(path, true, {}, mutation.content);
            hookFailed = !write.ok && !write.error.empty();
            require(!(write.ok && write.containerCreated),
                    "durability failure must never report success");
        } catch (...) {
            AtomicFileWriter::setDirectoryFsyncHookForTests({});
            throw;
        }
        AtomicFileWriter::setDirectoryFsyncHookForTests({});
        require(hookFailed,
                "injected durability failure must produce a typed error");
    }

    // 56. stale snapshot replacement is detected, nothing overwritten.
    // 57. mutation failure never produces false ownership success.
    {
        TemporaryDirectory temp;
        const auto path = temp.path / "faillock.conf";
        const std::string pre = "a = 1\n";
        {
            std::ofstream output(path, std::ios::binary | std::ios::trunc);
            output << pre;
        }
        const auto read = readContainer(
            path, PamProviderAbsentContainerDecision::FailClosed);
        require(read.ok, "snapshot read failed");
        // External writer changes the file after the snapshot was taken.
        {
            std::ofstream append(path, std::ios::binary | std::ios::app);
            append << "external = 1\n";
        }
        const std::string externallyChanged = readFile(path);
        const auto mutation = setPamProviderManagedEntry(
            externallyChanged, testSpec(42, "5"),
            PamProviderBlockPlacementRequest::End);
        require(mutation.ok, "stale-based mutation build failed");
        const auto write = writeContainer(
            path, false, read.snapshot, mutation.content);
        require(!write.ok && write.stale,
                "stale snapshot replacement must be detected");
        require(readFile(path) == externallyChanged,
                "stale write must not overwrite the file");
        // 57: after the refused mutation the physical file still has no
        // FIC entry — no false ownership success.
        const auto fresh = readContainer(
            path, PamProviderAbsentContainerDecision::FailClosed);
        require(fresh.ok, "post-refusal read failed");
        const auto parse =
            parsePamProviderManagedBlock(fresh.content);
        const auto proof = provePamProviderEntryOwnership(
            parse, testExpectation(42, "deny = 5"));
        require(!proof.proven &&
                    proof.proof == PamProviderEntryProof::Absent,
                "refused mutation must never yield ownership success");
    }
}




void runAllMetadataTests() {
    // 52b. Pre-existing administrator metadata is PRESERVED: a hardened
    // 0600 file must never be silently rewritten to 0644 by a FIC
    // mutation; uid/gid stay untouched as well.
    {
        TemporaryDirectory temp;
        const auto path = temp.path / "faillock.conf";
        const std::string pre = "a = 1\n";
        {
            std::ofstream output(path, std::ios::binary | std::ios::trunc);
            output << pre;
        }
        require(::chmod(path.c_str(), 0600) == 0, "chmod fixture failed");
        struct ::stat before {};
        require(::stat(path.c_str(), &before) == 0, "stat fixture failed");

        const auto read = readContainer(
            path, PamProviderAbsentContainerDecision::FailClosed);
        require(read.ok, "metadata snapshot read failed");
        const auto mutation = setPamProviderManagedEntry(
            pre, testSpec(42, "5"), PamProviderBlockPlacementRequest::End);
        require(mutation.ok, "metadata mutation build failed");
        const auto write =
            writeContainer(path, false, read.snapshot, mutation.content);
        require(write.ok, "metadata mutation write failed");
        struct ::stat after {};
        require(::stat(path.c_str(), &after) == 0, "post-write stat failed");
        require((after.st_mode & 07777) == (before.st_mode & 07777),
                "pre-existing file mode must be preserved (0600 stays 0600)");
        require(after.st_uid == before.st_uid && after.st_gid == before.st_gid,
                "pre-existing file owner must be preserved");
        require(readFile(path) == mutation.content,
                "metadata-preserving write content mismatch");
    }
    // 52c. Metadata changes between snapshot and write are stale-snapshot
    // replacements: refused exactly like content changes.
    {
        TemporaryDirectory temp;
        const auto path = temp.path / "faillock.conf";
        const std::string pre = "a = 1\n";
        {
            std::ofstream output(path, std::ios::binary | std::ios::trunc);
            output << pre;
        }
        const auto read = readContainer(
            path, PamProviderAbsentContainerDecision::FailClosed);
        require(read.ok, "metadata stale read failed");
        // External metadata-only change after the snapshot.
        require(::chmod(path.c_str(), 0640) == 0, "external chmod failed");
        const auto mutation = setPamProviderManagedEntry(
            pre, testSpec(42, "5"), PamProviderBlockPlacementRequest::End);
        require(mutation.ok, "metadata stale mutation build failed");
        const auto write =
            writeContainer(path, false, read.snapshot, mutation.content);
        require(!write.ok && write.stale,
                "metadata-only change must be detected as stale");
        struct ::stat st {};
        require(::stat(path.c_str(), &st) == 0, "post-refusal stat failed");
        require((st.st_mode & 07777) == 0640,
                "refused stale write must not touch the file metadata");
    }
}

} // namespace

int main() {
    try {
        runAllContainerTests();
        runAllContainerTests2();
        runAllFilesystemTests();
        runAllMetadataTests();
    } catch (const std::exception& error) {
        std::cerr << "PamProviderManagedBlockFileTests failed: "
                  << error.what() << '\n';
        return 1;
    }
    std::cout << "PamProviderManagedBlockFileTests passed\n";
    return 0;
}
