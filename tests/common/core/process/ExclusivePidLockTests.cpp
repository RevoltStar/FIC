#include <fic/core/process/ExclusivePidLock.h>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
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
               mode_t permissions = 0644) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(output.is_open(), "could not create " + path.string());
    output << content;
    output.close();
    require(output.good(), "could not write " + path.string());
    require(::chmod(path.c_str(), permissions) == 0,
            "could not chmod " + path.string());
}

std::string readFile(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    require(input.is_open(), "could not read " + path.string());
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

struct stat fileStat(const fs::path& path) {
    struct stat result {};
    require(::lstat(path.c_str(), &result) == 0,
            "could not stat " + path.string());
    return result;
}

int descriptorForInode(const struct stat& expected) {
    for (const fs::directory_entry& entry :
         fs::directory_iterator("/proc/self/fd")) {
        const std::string name = entry.path().filename().string();
        char* end = nullptr;
        const long value = std::strtol(name.c_str(), &end, 10);
        if (end == nullptr || *end != '\0' || value < 0) {
            continue;
        }
        struct stat descriptorStat {};
        if (::fstat(static_cast<int>(value), &descriptorStat) == 0 &&
            descriptorStat.st_dev == expected.st_dev &&
            descriptorStat.st_ino == expected.st_ino) {
            return static_cast<int>(value);
        }
    }
    return -1;
}

void testSymlinkIsRejected(const fs::path& root) {
    const fs::path target = root / "lock-target";
    const fs::path link = root / "lock-link";
    writeFile(target, "unchanged", 0666);
    fs::create_symlink(target, link);

    ExclusivePidLock lock(link.string(), "", false);
    require(!lock.tryAcquire(), "PID lock followed a symlink");
    require(readFile(target) == "unchanged",
            "PID lock symlink target content changed");
    require((fileStat(target).st_mode & 07777) == 0666,
            "PID lock symlink target metadata changed");
}

void testOneInodeAndDescriptorLifetime(const fs::path& root) {
    const fs::path lockPath = root / "single-inode.lock";
    const fs::path renamedPath = root / "single-inode-renamed.lock";
    const fs::path replacementPath = lockPath;

    ExclusivePidLock lock(lockPath.string(), "", false);
    require(lock.tryAcquire(), "could not acquire PID lock");
    const struct stat lockedStat = fileStat(lockPath);
    require((lockedStat.st_mode & 07777) == 0640,
            "PID lock mode was not applied to the locked inode");
    const int lockDescriptor = descriptorForInode(lockedStat);
    require(lockDescriptor >= 0, "locked inode descriptor was not found");
    require((::fcntl(lockDescriptor, F_GETFD) & FD_CLOEXEC) != 0,
            "PID lock descriptor is not close-on-exec");

    fs::rename(lockPath, renamedPath);
    writeFile(replacementPath, "replacement", 0600);
    lock.release();

    require(readFile(replacementPath) == "replacement",
            "release truncated a replacement path inode");
    require(readFile(renamedPath).empty(),
            "release did not truncate the originally locked inode");

    fs::remove(replacementPath);
    fs::rename(renamedPath, lockPath);
    {
        ExclusivePidLock second(lockPath.string(), "", false);
        require(second.tryAcquire(),
                "descriptor ownership prevented reacquiring after release");
    }
    ExclusivePidLock third(lockPath.string(), "", false);
    require(third.tryAcquire(),
            "FileStats duplicate closed the caller-owned lock descriptor");
}
} // namespace

int main() {
    const fs::path root = fs::temp_directory_path() /
        ("fic-exclusive-lock-test-" + std::to_string(::getpid()));
    fs::remove_all(root);
    fs::create_directories(root);

    testSymlinkIsRejected(root);
    testOneInodeAndDescriptorLifetime(root);

    fs::remove_all(root);
    return 0;
}
