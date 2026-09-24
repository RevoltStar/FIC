#include "modules/identity_access/pam/PamManagedPasswordSlotBootstrap.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <cerrno>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace fic::identity::pam {

bool PamManagedPasswordSlotBootstrapResult::complete() const {
    for (const auto& slot : slots) {
        if (slot.failed) {
            return false;
        }
    }
    return true;
}

PamManagedPasswordSlotBootstrap::PamManagedPasswordSlotBootstrap(
    std::filesystem::path configDirectory,
    const PamManagedPasswordSlotBootstrapOptions& options)
    : configDirectory_(std::move(configDirectory)), options_(options) {}

void PamManagedPasswordSlotBootstrap::setBeforeSlotWriteHookForTests(
    SlotFaultHook hook) {
    beforeWriteHook_ = std::move(hook);
}

namespace {

std::string errnoText() {
    return std::string(std::strerror(errno));
}

// Fail-closed gate: the slot's parent directory must be a PHYSICAL
// directory (no symlink anywhere in the parent chain). Walk the explicit
// components from the filesystem root with lstat (no follow).
bool verifyPhysicalParentChain(const std::filesystem::path& parent,
                               std::string& error) {
    std::filesystem::path walked;
    for (const auto& component : parent) {
        if (component == parent.root_name() || component == "/") {
            walked /= component;
            continue;
        }
        walked /= component;
        struct stat info {};
        if (::lstat(walked.c_str(), &info) != 0) {
            error = "cannot stat parent directory component " +
                walked.string() + ": " + errnoText();
            return false;
        }
        if (!S_ISDIR(info.st_mode)) {
            error = "parent directory chain component " + walked.string() +
                " is not a physical directory (symlink traversal is " +
                "refused)";
            return false;
        }
    }
    return true;
}

// Fresh post-write verification of a proven creation: identity/type,
// exact content and metadata read back from the filesystem (never from
// a retained descriptor or a writer result).
bool verifyCreatedSlot(const std::filesystem::path& path,
                       const std::string& neutralBody,
                       const PamManagedPasswordSlotBootstrapOptions& options,
                       std::string& error) {
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) {
        error = "bootstrapped slot disappeared before verification: " +
            path.string() + ": " + errnoText();
        return false;
    }
    if (S_ISLNK(info.st_mode)) {
        error = "bootstrapped slot path is a symbolic link after creation: " +
            path.string();
        return false;
    }
    if (!S_ISREG(info.st_mode)) {
        error = "bootstrapped slot path is not a regular file after " +
            std::string("creation: ") + path.string();
        return false;
    }
    if ((info.st_mode & 07777) != options.slotMode ||
        info.st_uid != options.slotOwner ||
        info.st_gid != options.slotGroup) {
        error = "bootstrapped slot metadata diverges from the expected " +
            std::string("owner/mode: ") + path.string();
        return false;
    }
    int descriptor =
        ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        error = "cannot reopen bootstrapped slot without following " +
            std::string("symlinks: ") + path.string() + ": " +
            errnoText();
        return false;
    }
    std::string content;
    char buffer[8192];
    while (true) {
        const ssize_t count = ::read(descriptor, buffer, sizeof(buffer));
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            const std::string readError = errnoText();
            ::close(descriptor);
            error = "cannot read bootstrapped slot " + path.string() +
                ": " + readError;
            return false;
        }
        if (count == 0) {
            break;
        }
        content.append(buffer, static_cast<std::size_t>(count));
    }
    ::close(descriptor);
    if (content != neutralBody) {
        error = "bootstrapped slot content diverges from the exact " +
            std::string("canonical neutral bytes: ") + path.string();
        return false;
    }
    return true;
}

} // namespace
bool PamManagedPasswordSlotBootstrap::createAbsentSlot(
    const ManagedPasswordSlotSpec& spec, const std::filesystem::path& path,
    PamManagedPasswordSlotBootstrapOutcome& outcome, std::string& error) {
    AtomicWriteOptions options;
    options.createIfMissing = true;
    options.rejectSymlink = true;
    options.exclusiveCreate = true;
    options.fileMode = options_.slotMode;
    options.fileOwner = options_.slotOwner;
    options.fileGroup = options_.slotGroup;

    const std::string neutralBody = PamManagedPasswordSlots::neutralBody();
    AtomicWriteResult writeResult;
    std::string writeError;
    if (!AtomicFileWriter::writeWithResult(
            path.string(), neutralBody, options, &writeError,
            &writeResult)) {
        outcome.failed = true;
        // Honest mutation accounting: the publish may still have
        // happened (installed==true), the RENAME_NOREPLACE fallback may
        // have published through link() while a later step failed, or a
        // racing writer may have occupied the previously absent path.
        // In every such case the physical state MAY differ from the
        // entry state of this call and is reported as Created; a clean
        // refusal (nothing appeared) keeps the entry-state accounting.
        struct stat afterStat {};
        const bool appeared = ::lstat(path.c_str(), &afterStat) == 0;
        outcome.status = writeResult.installed || appeared
            ? PamManagedPasswordSlotBootstrapStatus::Created
            : PamManagedPasswordSlotBootstrapStatus::AlreadyPresent;
        outcome.error = "exclusive creation of canonical neutral slot " +
            path.string() + " failed: " + writeError;
        error = outcome.error;
        return false;
    }

    if (!writeResult.durabilityConfirmed) {
        outcome.failed = true;
        outcome.status = PamManagedPasswordSlotBootstrapStatus::Created;
        outcome.error = "canonical neutral slot " + path.string() +
            " was created but its durability (parent directory fsync) " +
            "could not be confirmed; failing closed";
        error = outcome.error;
        return false;
    }

    if (!verifyCreatedSlot(path, neutralBody, options_, error)) {
        outcome.failed = true;
        outcome.status = PamManagedPasswordSlotBootstrapStatus::Created;
        outcome.error = error;
        return false;
    }

    outcome.status = PamManagedPasswordSlotBootstrapStatus::Created;
    error.clear();
    return true;
}
bool PamManagedPasswordSlotBootstrap::bootstrapSlot(
    const ManagedPasswordSlotSpec& spec, std::size_t slotIndex,
    PamManagedPasswordSlotBootstrapOutcome& outcome, std::string& error) {
    outcome.role = spec.role;
    outcome.path = PamManagedPasswordSlots::slotFilePath(
        spec, configDirectory_);
    outcome.status = PamManagedPasswordSlotBootstrapStatus::AlreadyPresent;
    outcome.failed = false;
    outcome.error.clear();

    if (beforeWriteHook_ && !beforeWriteHook_(slotIndex)) {
        outcome.failed = true;
        outcome.error =
            "injected failure before managed password slot bootstrap: " +
            std::string(spec.fileName);
        error = outcome.error;
        return false;
    }

    const std::filesystem::path& path = outcome.path;
    struct stat linkStat {};
    const bool occupied = ::lstat(path.c_str(), &linkStat) == 0;

    if (occupied) {
        // Existence-only contract: anything already occupying the exact
        // slot path is NEVER touched. A regular file (any content:
        // neutral, active, broken, foreign, empty) is a no-op; every
        // other object type (symlink including dangling, directory,
        // FIFO, socket, device) fails closed without following the
        // target.
        if (!S_ISREG(linkStat.st_mode)) {
            outcome.failed = true;
            if (S_ISLNK(linkStat.st_mode)) {
                outcome.error = "refusing to bootstrap managed password " +
                    std::string("slot: ") + path.string() +
                    " is a symbolic link (dangling or not); symlink " +
                    "traversal fails closed";
            } else if (S_ISDIR(linkStat.st_mode)) {
                outcome.error = "refusing to bootstrap managed password " +
                    std::string("slot: ") + path.string() +
                    " is a directory";
            } else {
                outcome.error = "refusing to bootstrap managed password " +
                    std::string("slot: ") + path.string() +
                    " is neither a regular file nor absent (special " +
                    "file fails closed)";
            }
            error = outcome.error;
            return false;
        }
        outcome.status =
            PamManagedPasswordSlotBootstrapStatus::AlreadyPresent;
        error.clear();
        return true;
    }

    // Genuinely absent: verify the parent chain, then create the exact
    // canonical neutral bytes exclusively and durably.
    const std::filesystem::path parent = path.parent_path();
    if (!verifyPhysicalParentChain(parent, error)) {
        outcome.failed = true;
        outcome.error = error;
        return false;
    }
    return createAbsentSlot(spec, path, outcome, error);
}
bool PamManagedPasswordSlotBootstrap::run(
    PamManagedPasswordSlotBootstrapResult& result, std::string& error) {
    result = PamManagedPasswordSlotBootstrapResult{};
    bool allSucceeded = true;
    const auto& slotSpecs = PamManagedPasswordSlots::slots();
    for (std::size_t index = 0; index < slotSpecs.size(); ++index) {
        PamManagedPasswordSlotBootstrapOutcome outcome;
        const bool slotSucceeded =
            bootstrapSlot(slotSpecs[index], index, outcome, error);
        if (outcome.status ==
            PamManagedPasswordSlotBootstrapStatus::Created) {
            // Monotonic changedSystemState accounting: any creation —
            // including one whose post-write proof or durability
            // confirmation failed — is a physical change relative to
            // the entry state of this call.
            result.changedSystemState = true;
        }
        result.slots.push_back(std::move(outcome));
        if (!slotSucceeded) {
            allSucceeded = false;
            break;
        }
    }
    if (allSucceeded) {
        error.clear();
    }
    return allSucceeded;
}

} // namespace fic::identity::pam