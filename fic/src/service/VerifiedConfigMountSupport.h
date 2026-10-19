#pragma once
#include "service/VerifiedConfigServiceActivator.h"
#include <set>
#include <stdexcept>
#include <sys/stat.h>
#ifdef FIC_ACTIVATOR_TESTING
#include <functional>
#endif

namespace fic::service::detail {
struct Failure : std::runtime_error {
    ActivationStatus status;
    Failure(ActivationStatus s, const std::string& text) : std::runtime_error(text), status(s) {}
};
class Fd {
    int fd_ = -1;
public:
    explicit Fd(int fd = -1) : fd_(fd) {}
    ~Fd();
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& other) noexcept;
    Fd& operator=(Fd&& other) noexcept;
    int get() const { return fd_; }
    explicit operator bool() const { return fd_ >= 0; }
};
struct MountRecord {
    std::uint64_t id = 0, parent = 0;
    std::string device, root, target, options, type, source, superOptions;
    bool shared = false, slave = false, unbindable = false, unknownOptional = false;
};
std::vector<MountRecord> parseMountInfo(const std::string& text);
std::vector<MountRecord> readMountInfo();
bool mountOption(const std::string& options, const std::string& flag);
bool below(const std::string& path, const std::string& parent);
// Check the effective mount of the destination's parent, not a textual prefix.
// Missing workspace ancestors are allowed only during the initial preflight.
void requireSafePublicationParent(const std::filesystem::path& target, bool missingParents,
                                  ActivationStatus failure);
void validateRequest(const ActivationRequest& request);
struct Identity {
    std::uint64_t mount = 0, inode = 0;
    dev_t device = 0;
    mode_t mode = 0;
    uid_t uid = 0;
    gid_t gid = 0;
};
Identity identity(int fd);
bool sameObject(const Identity& a, const Identity& b);
Fd openAbsolute(const std::filesystem::path& path, int flags, bool trustedParents = true);
std::string fdPath(int fd);
std::string namespaceIdentity(pid_t pid);
struct Tree {
    std::map<std::string, std::string> files;
    std::map<std::string, struct stat> attributes;
};
Tree readTree(int root, ControlledPathKind kind, std::uint64_t& budget);
void verifyTree(int root, const ControlledPath& expected, std::uint64_t budget);
#ifdef FIC_ACTIVATOR_TESTING
struct XattrTestHooks {
    std::function<ssize_t(int, char*, std::size_t)> list;
    std::function<void(int, const std::string&)> afterInitialList, afterRead;
};
void setXattrTestHooks(XattrTestHooks hooks);
// Pure enumeration algorithm only; production walk also requires visibility.
void checkXattrListForTests(int fd);
#endif
void copyTree(int source, int destination, const Tree& tree, ControlledPathKind kind);
class MountObserver {
    Fd fd_;
    bool changed_ = false;
public:
    MountObserver();
    // Sticky: never acknowledges away a previously observed event.
    bool changed(int timeoutMs = 0);
};
void requireReadOnly(const std::string& path, const Identity& expected,
                     const std::string& type, const std::string& source);
} // namespace fic::service::detail
