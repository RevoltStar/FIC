#include "service/VerifiedConfigMountSupport.h"
#include <fic/core/integrity/ContentDigest.h>
#include <fic/core/fs/FileStats.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <linux/stat.h>
#include <poll.h>
#include <sstream>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

namespace fic::service::detail {
namespace {
[[noreturn]] void fail(ActivationStatus s, const std::string& text) {
    throw Failure(s, text + ": " + std::strerror(errno));
}
std::string decode(const std::string& text) {
    std::string out;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\\') {
            if (i + 3 >= text.size() || text[i+1] < '0' || text[i+1] > '7' ||
                text[i+2] < '0' || text[i+2] > '7' || text[i+3] < '0' || text[i+3] > '7')
                throw Failure(ActivationStatus::UnsupportedConfiguration, "invalid mountinfo escape");
            out += char((text[i+1]-'0')*64 + (text[i+2]-'0')*8 + text[i+3]-'0'); i += 3;
        } else out += text[i];
    }
    return out;
}
bool cleanPath(const std::filesystem::path& p, bool absolute) {
    if (p.empty() || p.is_absolute() != absolute || p != p.lexically_normal() ||
        p.string().find('\0') != std::string::npos || p.string().find('\n') != std::string::npos ||
        p.string().find('\r') != std::string::npos || p.string().size() > 4096) return false;
    unsigned depth = 0;
    for (const auto& part : p) {
        if (part == "." || part == ".." || part.empty()) return false;
        if (++depth > 64) return false;
    }
    return !absolute || p != p.root_path();
}
Fd openRelative(int parent, const std::string& path, int flags) {
    Fd current(::openat(parent, ".", O_RDONLY|O_DIRECTORY|O_CLOEXEC));
    if (!current) fail(ActivationStatus::SnapshotFailed, "open tree root");
    if (path.empty()) return current;
    const std::filesystem::path p(path);
    for (auto it = p.begin(); it != p.end(); ++it) {
        auto next = it; ++next;
        const int use = next == p.end() ? flags : O_RDONLY|O_DIRECTORY;
        Fd opened(::openat(current.get(), it->c_str(), use|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK));
        if (!opened) fail(ActivationStatus::UnsupportedConfiguration, "open tree entry " + path);
        current = std::move(opened);
    }
    return current;
}
void noXattrs(int fd) {
    const auto count = ::flistxattr(fd, nullptr, 0);
    if (count > 0) throw Failure(ActivationStatus::UnsupportedConfiguration,
        "extended attributes/ACL/labels require an unsupported snapshot attribute contract");
    if (count < 0 && errno != ENOTSUP) fail(ActivationStatus::UnsupportedConfiguration, "list extended attributes");
}
void walk(int fd, const std::string& path, std::uint64_t mountId,
          std::uint64_t& budget, Tree& tree, unsigned depth) {
    if (depth > 64 || tree.attributes.size() >= 8192)
        throw Failure(ActivationStatus::UnsupportedConfiguration, "snapshot tree limit exceeded");
    struct stat before{};
    if (::fstat(fd, &before) != 0) fail(ActivationStatus::ChecksumMismatch, "stat tree");
    if (before.st_mode & 07000)
        throw Failure(ActivationStatus::UnsupportedConfiguration, "special permission bits are unsupported in snapshots");
    if (identity(fd).mount != mountId)
        throw Failure(ActivationStatus::UnsupportedConfiguration, "nested mount in controlled tree");
    noXattrs(fd);
    tree.attributes[path] = before;
    if (S_ISREG(before.st_mode)) {
        if (before.st_size < 0 || std::uint64_t(before.st_size) > budget)
            throw Failure(ActivationStatus::SnapshotFailed, "snapshot byte limit exceeded");
        std::string content; char buffer[16384];
        while (true) {
            const ssize_t n = ::read(fd, buffer, sizeof buffer);
            if (n < 0 && errno == EINTR) continue;
            if (n < 0) fail(ActivationStatus::ChecksumMismatch, "read controlled file");
            if (!n) break;
            if (std::uint64_t(n) > budget) throw Failure(ActivationStatus::SnapshotFailed, "snapshot byte limit exceeded");
            budget -= n; content.append(buffer, n);
        }
        tree.files[path] = std::move(content);
    } else if (S_ISDIR(before.st_mode)) {
        Fd listing(::openat(fd, ".", O_RDONLY|O_DIRECTORY|O_CLOEXEC));
        if (!listing) fail(ActivationStatus::ChecksumMismatch, "open directory listing");
        const int raw = ::dup(listing.get());
        DIR* dir = raw < 0 ? nullptr : ::fdopendir(raw);
        if (!dir) { if (raw >= 0) ::close(raw); fail(ActivationStatus::ChecksumMismatch, "read directory"); }
        std::set<std::string> names;
        errno = 0;
        while (auto* item = ::readdir(dir)) {
            const std::string name = item->d_name;
            if (name != "." && name != "..") {
                names.insert(name);
                if (names.size() > 8192) {
                    ::closedir(dir);
                    throw Failure(ActivationStatus::UnsupportedConfiguration, "snapshot directory entry limit exceeded");
                }
            }
            errno = 0;
        }
        const int readError = errno; ::closedir(dir);
        if (readError) { errno = readError; fail(ActivationStatus::ChecksumMismatch, "enumerate tree"); }
        for (const auto& name : names) {
            Fd child(::openat(fd, name.c_str(), O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC));
            if (!child) fail(ActivationStatus::UnsupportedConfiguration, "unsafe tree entry " + name);
            walk(child.get(), path.empty() ? name : path + "/" + name, mountId, budget, tree, depth + 1);
        }
    } else throw Failure(ActivationStatus::UnsupportedConfiguration, "non-regular object in controlled tree");
    struct stat after{};
    if (::fstat(fd, &after) != 0) fail(ActivationStatus::ChecksumMismatch, "recheck tree");
    if (before.st_dev != after.st_dev || before.st_ino != after.st_ino || before.st_size != after.st_size ||
        before.st_mode != after.st_mode || before.st_uid != after.st_uid || before.st_gid != after.st_gid ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
        throw Failure(ActivationStatus::ChecksumMismatch, "controlled source changed while reading");
}
void applyAttributes(int fd, const struct stat& value) {
    const timespec times[] = {value.st_atim, value.st_mtim};
    auto metadata = FileStats::fromBorrowedDescriptor(fd, "verified-config snapshot");
    const auto owner = metadata.change_owner_group(value.st_uid, value.st_gid);
    const auto permissions = metadata.change_permissions(value.st_mode & 0777);
    if (!owner || !permissions || ::futimens(fd, times))
        throw Failure(ActivationStatus::SnapshotFailed, "preserve snapshot attributes: " + owner.message + permissions.message);
}
}
Fd::~Fd() { if (fd_ >= 0) ::close(fd_); }
Fd::Fd(Fd&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
Fd& Fd::operator=(Fd&& other) noexcept {
    if (this != &other) { if (fd_ >= 0) ::close(fd_); fd_ = other.fd_; other.fd_ = -1; } return *this;
}
std::string fdPath(int fd) { return "/proc/self/fd/" + std::to_string(fd); }
bool below(const std::string& path, const std::string& parent) {
    return path.size() > parent.size() && path.compare(0, parent.size(), parent) == 0 && path[parent.size()] == '/';
}
bool mountOption(const std::string& options, const std::string& flag) {
    return ("," + options + ",").find("," + flag + ",") != std::string::npos;
}
std::vector<MountRecord> parseMountInfo(const std::string& text) {
    std::vector<MountRecord> out; std::istringstream input(text); std::string line;
    while (std::getline(input, line)) {
        std::istringstream in(line); MountRecord r; std::string field;
        if (!(in >> r.id >> r.parent >> r.device >> r.root >> r.target >> r.options))
            throw Failure(ActivationStatus::UnsupportedConfiguration, "invalid mountinfo record");
        bool separator = false;
        while (in >> field) {
            if (field == "-") { separator = true; break; }
            if (field.rfind("shared:", 0) == 0) r.shared = true;
            else if (field.rfind("master:", 0) == 0) r.slave = true;
            else if (field == "unbindable") r.unbindable = true;
            else if (field.rfind("propagate_from:", 0) != 0) r.unknownOptional = true;
        }
        if (!separator || !(in >> r.type >> r.source >> r.superOptions) || !r.id)
            throw Failure(ActivationStatus::UnsupportedConfiguration, "incomplete mountinfo record");
        r.root = decode(r.root); r.target = decode(r.target); r.source = decode(r.source);
        out.push_back(std::move(r));
    }
    if (out.empty()) throw Failure(ActivationStatus::UnsupportedConfiguration, "empty mountinfo");
    return out;
}
std::vector<MountRecord> readMountInfo() {
    std::ifstream input("/proc/self/mountinfo");
    if (!input) throw Failure(ActivationStatus::UnsupportedConfiguration, "cannot read mountinfo");
    return parseMountInfo({std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()});
}
void requireSafePublicationParent(const std::filesystem::path& target, bool missingParents,
                                  ActivationStatus failure) {
    auto parent = target.parent_path();
    if (missingParents) {
        std::error_code error;
        while (!parent.empty()) {
            const auto state = std::filesystem::symlink_status(parent, error);
            if (!error && state.type() != std::filesystem::file_type::not_found) break;
            if (error && error != std::errc::no_such_file_or_directory)
                throw Failure(failure, "cannot inspect publication parent");
            parent = parent.parent_path();
        }
    }
    auto fd = openAbsolute(parent, O_PATH|O_DIRECTORY);
    const auto id = identity(fd.get()).mount;
    for (const auto& mount : readMountInfo()) if (mount.id == id) {
        if (mount.shared || mount.unknownOptional)
            throw Failure(failure, "publication parent is shared or has unknown propagation: " + parent.string());
        return; // Private/unbindable or non-shared slave: no outward propagation.
    }
    throw Failure(failure, "publication parent mount identity unavailable");
}
void validateRequest(const ActivationRequest& r) {
    const auto invalid = [](const std::string& s) { throw Failure(ActivationStatus::UnsupportedConfiguration, s); };
    if (r.paths.empty() || r.paths.size() > 16 || r.timeout.count() <= 0 || r.timeout > std::chrono::minutes(5) ||
        !r.maxSnapshotBytes || r.maxSnapshotBytes > 64*1024*1024) invalid("invalid request limits");
    if (r.unit.size() <= 8 || r.unit.size() > 240 || r.unit.substr(r.unit.size()-8) != ".service" ||
        r.unit.front() == '-' || !std::all_of(r.unit.begin(), r.unit.end(), [](unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                   c == '_' || c == '-' || c == '.' || c == '@' || c == ':';
        })) invalid("unsupported service unit name");
    for (std::size_t i = 0; i < r.paths.size(); ++i) {
        const auto& p = r.paths[i];
        if (!cleanPath(p.path, true)) invalid("controlled path must be absolute, normalized, bounded and non-root");
        for (std::size_t j = 0; j < i; ++j)
            if (p.path == r.paths[j].path || below(p.path, r.paths[j].path) || below(r.paths[j].path, p.path))
                invalid("overlapping controlled paths");
        if (p.kind == ControlledPathKind::File) {
            if (!p.manifest.empty() || !fic::core::ContentDigest::isCanonicalSha256Hex(p.sha256)) invalid("invalid file digest/manifest");
        } else if (p.kind == ControlledPathKind::Directory) {
            if (!p.sha256.empty() || p.manifest.size() > 4096) invalid("invalid directory manifest");
            for (const auto& [name, digest] : p.manifest) {
                if (!cleanPath(name, false) || !fic::core::ContentDigest::isCanonicalSha256Hex(digest)) invalid("invalid manifest entry");
                for (auto parent = std::filesystem::path(name).parent_path(); !parent.empty(); parent = parent.parent_path())
                    if (p.manifest.count(parent.string())) invalid("manifest file/directory collision");
            }
        } else invalid("unknown controlled path kind");
    }
}
Identity identity(int fd) {
    struct stat st{}; struct statx sx{};
    if (::fstat(fd, &st) || ::syscall(SYS_statx, fd, "", AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW,
                                    STATX_MNT_ID, &sx) || !(sx.stx_mask & STATX_MNT_ID))
        fail(ActivationStatus::UnsupportedConfiguration, "statx mount identity unavailable");
    return {sx.stx_mnt_id, std::uint64_t(st.st_ino), st.st_dev, st.st_mode, st.st_uid, st.st_gid};
}
bool sameObject(const Identity& a, const Identity& b) {
    return a.inode == b.inode && a.device == b.device && a.mode == b.mode && a.uid == b.uid && a.gid == b.gid;
}
Fd openAbsolute(const std::filesystem::path& path, int flags, bool trustedParents) {
    Fd current(::open("/", O_PATH|O_DIRECTORY|O_CLOEXEC));
    const auto rel = path.relative_path();
    for (auto it = rel.begin(); it != rel.end(); ++it) {
        const auto st = identity(current.get());
        if (trustedParents && (st.uid != 0 || (st.mode & 0022)))
            throw Failure(ActivationStatus::UnsupportedConfiguration, "untrusted controlled-path parent");
        auto next = it; ++next;
        Fd child(::openat(current.get(), it->c_str(), (next == rel.end() ? flags : O_PATH|O_DIRECTORY)|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
        if (!child) fail(errno == ENOENT ? ActivationStatus::ChecksumMismatch : ActivationStatus::UnsupportedConfiguration,
                         "open controlled path " + path.string());
        current = std::move(child);
    }
    return current;
}
std::string namespaceIdentity(pid_t pid) {
    struct stat st{}; const auto p = "/proc/" + std::to_string(pid) + "/ns/mnt";
    if (::stat(p.c_str(), &st)) fail(ActivationStatus::UnsupportedConfiguration, "read mount namespace");
    return std::to_string(st.st_dev) + ":" + std::to_string(st.st_ino);
}
Tree readTree(int root, ControlledPathKind kind, std::uint64_t& budget) {
    const auto st = identity(root);
    if ((kind == ControlledPathKind::File && !S_ISREG(st.mode)) ||
        (kind == ControlledPathKind::Directory && !S_ISDIR(st.mode)))
        throw Failure(ActivationStatus::UnsupportedConfiguration, "controlled object type mismatch");
    if (::lseek(root, 0, SEEK_SET) < 0) fail(ActivationStatus::ChecksumMismatch, "rewind tree root");
    Tree tree; walk(root, "", st.mount, budget, tree, 0); return tree;
}
void verifyTree(int root, const ControlledPath& expected, std::uint64_t budget) {
    const auto tree = readTree(root, expected.kind, budget);
    FileManifest actual;
    for (const auto& [name, content] : tree.files) actual[name] = fic::core::ContentDigest::sha256Hex(content);
    const auto desired = expected.kind == ControlledPathKind::File ? FileManifest{{"", expected.sha256}} : expected.manifest;
    if (actual != desired) throw Failure(ActivationStatus::ChecksumMismatch, "snapshot does not match exact manifest");
    std::set<std::string> dirs{""};
    for (const auto& [name, _] : desired)
        for (auto p = std::filesystem::path(name).parent_path(); !p.empty(); p = p.parent_path()) dirs.insert(p.string());
    for (const auto& [name, attr] : tree.attributes)
        if (S_ISDIR(attr.st_mode) && !dirs.count(name))
            throw Failure(ActivationStatus::ChecksumMismatch, "unexpected directory outside manifest structure");
}
void copyTree(int source, int destination, const Tree& tree, ControlledPathKind kind) {
    (void)source;
    if (kind == ControlledPathKind::Directory) {
        for (const auto& [name, attr] : tree.attributes) if (!name.empty() && S_ISDIR(attr.st_mode)) {
            auto parent = openRelative(destination, std::filesystem::path(name).parent_path(), O_RDONLY|O_DIRECTORY);
            if (::mkdirat(parent.get(), std::filesystem::path(name).filename().c_str(), 0700)) fail(ActivationStatus::SnapshotFailed, "mkdir snapshot");
        }
    }
    for (const auto& [name, content] : tree.files) {
        Fd file;
        if (kind == ControlledPathKind::File) file = Fd(::dup(destination));
        else {
            auto parent = openRelative(destination, std::filesystem::path(name).parent_path(), O_RDONLY|O_DIRECTORY);
            file = Fd(::openat(parent.get(), std::filesystem::path(name).filename().c_str(), O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600));
        }
        if (!file) fail(ActivationStatus::SnapshotFailed, "create snapshot file");
        std::size_t at = 0;
        while (at < content.size()) {
            const auto n = ::write(file.get(), content.data()+at, content.size()-at);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) fail(ActivationStatus::SnapshotFailed, "write snapshot");
            at += n;
        }
        applyAttributes(file.get(), tree.attributes.at(name));
    }
    if (kind == ControlledPathKind::Directory)
        for (auto it = tree.attributes.rbegin(); it != tree.attributes.rend(); ++it) if (S_ISDIR(it->second.st_mode)) {
            auto dir = openRelative(destination, it->first, O_RDONLY|O_DIRECTORY); applyAttributes(dir.get(), it->second);
        }
}
MountObserver::MountObserver() : fd_(::open("/proc/self/mountinfo", O_RDONLY|O_CLOEXEC)) {
    if (!fd_) fail(ActivationStatus::UnsupportedConfiguration, "open mount observer");
}
bool MountObserver::changed(int timeoutMs) {
    pollfd p{fd_.get(), POLLPRI, 0}; int rc;
    do { rc = ::poll(&p, 1, timeoutMs); } while (rc < 0 && errno == EINTR);
    if (rc < 0 || (p.revents & (POLLPRI|POLLERR|POLLNVAL|POLLHUP))) changed_ = true;
    return changed_;
}
void requireReadOnly(const std::string& path, const Identity& expected,
                     const std::string& type, const std::string& source) {
    auto fd = openAbsolute(path, O_RDONLY);
    const auto observed = identity(fd.get());
    if (!sameObject(observed, expected) || observed.mount != expected.mount)
        throw Failure(ActivationStatus::InterferenceDetected, "published mount identity changed");
    bool found = false;
    for (const auto& r : readMountInfo()) if (r.id == observed.mount) {
        found = r.target == path && r.type == type && r.source == source &&
                !r.shared && !r.unknownOptional &&
                mountOption(r.options, "ro") && mountOption(r.superOptions, "ro");
    }
    if (!found) throw Failure(ActivationStatus::InterferenceDetected, "mount/superblock read-only proof failed");
}
} // namespace fic::service::detail
