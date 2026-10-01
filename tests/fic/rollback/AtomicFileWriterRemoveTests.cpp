#include <fic/core/fs/AtomicFileWriter.h>

#include <sys/stat.h>

#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class TempDir {
public:
    TempDir() {
        char pattern[] = "/tmp/fic-atomic-remove-XXXXXX";
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

const char* kContent = "FIC block serialization\n";

AtomicTargetState capture(const std::filesystem::path& path) {
    AtomicTargetState state;
    std::string error;
    require(AtomicFileWriter::captureTargetState(path.string(), state, &error),
            "capture: " + error);
    return state;
}

void testExactSnapshotDurableDelete() {
    TempDir temp;
    const std::filesystem::path path = temp.directory / "primary.conf";
    writeFile(path, kContent);
    const AtomicTargetState snapshot = capture(path);
    AtomicRemoveResult result;
    std::string error;
    require(AtomicFileWriter::removeIfCurrentState(path.string(), snapshot,
                                                   &error, &result),
            "remove: " + error);
    require(result.removed && result.durabilityConfirmed &&
                !result.preconditionFailed,
            "exact snapshot: removed durably");
    require(!std::filesystem::exists(path), "file gone");
}

void testContentChangedPreconditionFail() {
    TempDir temp;
    const std::filesystem::path path = temp.directory / "primary.conf";
    writeFile(path, kContent);
    const AtomicTargetState snapshot = capture(path);
    writeFile(path, "admin replaced content\n");
    AtomicRemoveResult result;
    std::string error;
    require(AtomicFileWriter::removeIfCurrentState(path.string(), snapshot,
                                                   &error, &result),
            "remove: " + error);
    require(result.preconditionFailed && !result.removed,
            "content drift: precondition failed, nothing deleted");
    require(readFile(path) == "admin replaced content\n",
            "replacement untouched");
}

void testInodeReplacementPreconditionFail() {
    TempDir temp;
    const std::filesystem::path path = temp.directory / "primary.conf";
    writeFile(path, kContent);
    const AtomicTargetState snapshot = capture(path);
    // Same content under a DIFFERENT inode (rename dance): the replacement
    // must never be deleted even when it is byte-identical.
    const std::filesystem::path other = temp.directory / "other.conf";
    writeFile(other, kContent);
    std::filesystem::rename(other, path);
    AtomicRemoveResult result;
    std::string error;
    require(AtomicFileWriter::removeIfCurrentState(path.string(), snapshot,
                                                   &error, &result),
            "remove: " + error);
    require(result.preconditionFailed && !result.removed,
            "inode swap: precondition failed even with identical content");
    require(std::filesystem::exists(path), "replacement untouched");
}

void testSymlinkAndSpecialRefused() {
    TempDir temp;
    {
        const std::filesystem::path target = temp.directory / "real.conf";
        writeFile(target, kContent);
        const std::filesystem::path link = temp.directory / "link.conf";
        require(::symlink(target.c_str(), link.c_str()) == 0,
                "symlink fixture");
        const AtomicTargetState snapshot = capture(target);
        AtomicRemoveResult result;
        std::string error;
        require(AtomicFileWriter::removeIfCurrentState(link.string(), snapshot,
                                                       &error, &result),
                "remove: " + error);
        require(result.preconditionFailed && !result.removed,
                "symlink is never deleted");
        require(std::filesystem::exists(link), "link untouched");
    }
    {
        const std::filesystem::path fifo = temp.directory / "fifo";
        require(::mkfifo(fifo.c_str(), 0644) == 0, "fifo fixture");
        AtomicTargetState snapshot;
        snapshot.content = kContent;
        snapshot.mode = 0644;
        AtomicRemoveResult result;
        std::string error;
        require(AtomicFileWriter::removeIfCurrentState(fifo.string(), snapshot,
                                                       &error, &result),
                "remove: " + error);
        require(result.preconditionFailed && !result.removed,
                "non-regular target is never deleted");
    }
}

void testUnlinkSuccessFsyncFailureNotDurable() {
    TempDir temp;
    const std::filesystem::path path = temp.directory / "primary.conf";
    writeFile(path, kContent);
    const AtomicTargetState snapshot = capture(path);
    AtomicFileWriter::setDirectoryFsyncHookForTests(
        [](const std::string&) { return false; });
    AtomicRemoveResult result;
    std::string error;
    const bool ok = AtomicFileWriter::removeIfCurrentState(
        path.string(), snapshot, &error, &result);
    AtomicFileWriter::setDirectoryFsyncHookForTests(nullptr);
    require(!ok, "fsync failure is a failure");
    require(result.removed && !result.durabilityConfirmed,
            "removed=true but durability NOT confirmed");
    require(!std::filesystem::exists(path),
            "the unlink is visible in the running system");
}

void testAbsentDurabilityBarrier() {
    TempDir temp;
    const std::filesystem::path path = temp.directory / "gone.conf";
    std::string error;
    require(AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(
                path.string(), &error),
            "absence barrier: " + error);
    const std::filesystem::path present = temp.directory / "here.conf";
    writeFile(present, "x");
    require(!AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(
                present.string(), &error),
            "present target refuses the absence barrier");
    require(std::filesystem::exists(present), "present target untouched");
}

} // namespace

int main() {
    try {
        testExactSnapshotDurableDelete();
        testContentChangedPreconditionFail();
        testInodeReplacementPreconditionFail();
        testSymlinkAndSpecialRefused();
        testUnlinkSuccessFsyncFailureNotDurable();
        testAbsentDurabilityBarrier();
    } catch (const std::exception& error) {
        std::cerr << "AtomicFileWriterRemoveTests failed: " << error.what()
                  << '\n';
        return 1;
    }
    std::cout << "AtomicFileWriterRemoveTests passed\n";
    return 0;
}

