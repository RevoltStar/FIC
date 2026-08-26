#include <fic/core/config/ConfigFileHandler.h>
#include <fic/core/fs/AtomicFileWriter.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>

#include <sys/stat.h>
#include <unistd.h>

namespace {

class TempTree {
public:
    TempTree() {
        std::string pattern = "/tmp/fic-file-handler-test-XXXXXX";
        char* directory = ::mkdtemp(pattern.data());
        if (directory == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        root = directory;
    }

    ~TempTree() {
        std::error_code ignored;
        std::filesystem::remove_all(root, ignored);
    }

    std::filesystem::path root;
};

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void writeFile(const std::filesystem::path& path, const std::string& content) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream << content;
    if (!stream) {
        throw std::runtime_error("failed to write " + path.string());
    }
}

std::string readFile(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return std::string(
        std::istreambuf_iterator<char>(stream),
        std::istreambuf_iterator<char>());
}

mode_t fileMode(const std::filesystem::path& path) {
    struct stat info {};
    if (::stat(path.c_str(), &info) != 0) {
        throw std::runtime_error("stat failed for " + path.string());
    }
    return info.st_mode & 07777;
}

FileHandlerOptions enforcingOptions(mode_t mode) {
    FileHandlerOptions options;
    options.writeOptions.createIfMissing = true;
    options.writeOptions.rejectSymlink = true;
    options.writeOptions.metadataPolicy = FileMetadataPolicy::EnforceProvided;
    options.writeOptions.fileMode = mode;
    options.writeOptions.fileOwner = ::geteuid();
    options.writeOptions.fileGroup = ::getegid();
    return options;
}

void testMissingFileIsNotCreatedByDefault() {
    TempTree tree;
    const auto path = tree.root / "missing.conf";
    ConfigFileHandler config(path.string());

    require(!config.loadConfig(), "missing file must fail to load by default");
    require(!std::filesystem::exists(path), "load unexpectedly created missing file");
    require(config.setValue("key", "value"), "failed to stage a value");
    require(!config.saveFile(), "save unexpectedly created missing file");
    require(!std::filesystem::exists(path), "save unexpectedly created missing file");
}

void testExplicitCreationAndMetadataEnforcement() {
    TempTree tree;
    const auto path = tree.root / "managed.conf";
    ConfigFileHandler config(path.string(), "=", enforcingOptions(0640));

    require(config.loadConfig(), "explicitly managed file was not created");
    require(fileMode(path) == 0640, "new file mode was not enforced");
    struct stat createdInfo {};
    require(::stat(path.c_str(), &createdInfo) == 0, "stat of managed file failed");
    require(createdInfo.st_uid == ::geteuid(), "new file owner was not enforced");
    require(createdInfo.st_gid == ::getegid(), "new file group was not enforced");
    require(config.setValue("key", "value"), "failed to set managed value");
    require(config.saveFile(), "failed to save managed file");

    require(::chmod(path.c_str(), 0666) == 0, "chmod fixture failed");
    require(config.saveFile(), "failed to re-save managed file");
    require(fileMode(path) == 0640, "existing file mode was not corrected");
}

void testExistingMetadataCanBePreserved() {
    TempTree tree;
    const auto path = tree.root / "preserved.conf";
    writeFile(path, "key=old\n");
    require(::chmod(path.c_str(), 0644) == 0, "chmod fixture failed");

    FileHandlerOptions options;
    options.writeOptions.fileMode = 0600;
    options.writeOptions.metadataPolicy = FileMetadataPolicy::PreserveExisting;
    ConfigFileHandler config(path.string(), "=", options);
    require(config.loadConfig(), "failed to load existing file");
    require(config.setValue("key", "new"), "failed to update existing file");
    require(config.saveFile(), "failed to save existing file");
    require(fileMode(path) == 0644, "preserved file mode was unexpectedly changed");
}

void testSymlinkIsRejected() {
    TempTree tree;
    const auto target = tree.root / "target.conf";
    const auto link = tree.root / "link.conf";
    writeFile(target, "key=old\n");
    std::filesystem::create_symlink(target, link);

    FileHandlerOptions options;
    options.writeOptions.rejectSymlink = true;
    ConfigFileHandler config(link.string(), "=", options);
    require(!config.loadConfig(), "symlink must be rejected during load");
    require(config.setValue("key", "new"), "failed to stage symlink value");
    require(!config.saveFile(), "symlink must be rejected during save");
}

void testDeletionBetweenLoadAndSaveDoesNotRecreateFile() {
    TempTree tree;
    const auto path = tree.root / "raced.conf";
    writeFile(path, "key=old\n");

    ConfigFileHandler config(path.string());
    require(config.loadConfig(), "failed to load race fixture");
    require(config.setValue("key", "new"), "failed to stage race value");
    require(std::filesystem::remove(path), "failed to remove race fixture");
    require(!config.saveFile(), "deleted file was unexpectedly recreated");
    require(!std::filesystem::exists(path), "deleted file exists after failed save");
}

void testValueRemovalPreservesUnrelatedContent() {
    TempTree tree;
    const auto path = tree.root / "removal.conf";
    writeFile(path, "first=remove\n#first=comment\nsecond=preserve\n");

    ConfigFileHandler config(path.string());
    require(config.loadConfig(), "failed to load removal fixture");
    require(config.removeValue("first"), "failed to remove value");
    require(config.saveFile(), "failed to save value removal");

    const std::string content = readFile(path);
    require(content.find("first=remove") == std::string::npos,
            "active removed value is still present");
    require(content.find("#first=comment") != std::string::npos,
            "commented value was unexpectedly removed");
    require(content.find("second=preserve") != std::string::npos,
            "unrelated value was unexpectedly removed");
}

void testAtomicExpectedTargetIdentity() {
    TempTree tree;
    const auto path = tree.root / "identity.conf";
    writeFile(path, "old\n");
    struct stat original {};
    require(::lstat(path.c_str(), &original) == 0,
            "failed to inspect identity fixture");

    AtomicWriteOptions options;
    options.expectedTargetIdentity =
        AtomicTargetIdentity{original.st_dev, original.st_ino};
    std::string error;
    require(AtomicFileWriter::write(path.string(), "first\n", options, &error),
            "matching expected identity was rejected: " + error);

    struct stat installed {};
    require(::lstat(path.c_str(), &installed) == 0,
            "failed to inspect installed fixture");
    options.expectedTargetIdentity =
        AtomicTargetIdentity{installed.st_dev, installed.st_ino};
    const auto replacement = tree.root / "replacement.conf";
    writeFile(replacement, "replacement\n");
    std::filesystem::rename(replacement, path);
    require(!AtomicFileWriter::write(
                path.string(), "stale-writer\n", options, &error),
            "stale expected identity overwrote a replacement inode");
    require(readFile(path) == "replacement\n",
            "replacement inode content was not preserved");
}

} // namespace

int main() {
    try {
        testMissingFileIsNotCreatedByDefault();
        testExplicitCreationAndMetadataEnforcement();
        testExistingMetadataCanBePreserved();
        testSymlinkIsRejected();
        testDeletionBetweenLoadAndSaveDoesNotRecreateFile();
        testValueRemovalPreservesUnrelatedContent();
        testAtomicExpectedTargetIdentity();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
