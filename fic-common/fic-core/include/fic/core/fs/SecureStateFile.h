#ifndef FIC_CORE_FS_SECURE_STATE_FILE_H
#define FIC_CORE_FS_SECURE_STATE_FILE_H

#include <fic/core/fs/AtomicFileWriter.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>

namespace fic::core {

// WHY this exists
// ---------------
// TrustedFileReader answers "can I trust this file's owner/mode". The
// incident state file additionally needs a proof chain that closes the
// read-side races a security state decision depends on:
//
//   open(O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
//     -> fstat(fd): regular file, expected owner/group/mode, size bound
//     -> bounded read THROUGH THE SAME fd (never a second open)
//     -> fstat(fd) again: same identity AND same size
//     -> parent directory proven safe
//
// Every stage runs on ONE descriptor, so there is no window where the
// pathname is resolved twice and the object could be swapped in between.
// The trailing re-fstat is what turns "we read something" into "we read a
// stable object": a concurrent in-place writer that changes the size during
// the read is reported as a race instead of being silently parsed.
struct SecureStateFileExpectation {
    std::optional<uid_t> owner;
    std::optional<gid_t> group;
    // Exact permission bits required (mode & 07777). 0 disables the check.
    mode_t exactMode = 0;
    // Permission bits that must NOT be set anywhere in the file mode.
    mode_t forbiddenMode = 0;
    // Maximum accepted content size in bytes. 0 disables the size check but
    // then maxBytes below still bounds the read.
    std::uintmax_t maxSize = 0;
    // Refuse a file with more than one hard link (no aliasing).
    bool requireSingleLink = false;
    // Require the parent directory to exist, be a real directory, and carry
    // these exact permission bits (0 disables the mode check).
    mode_t exactParentMode = 0;
    std::optional<uid_t> parentOwner;
};

enum class SecureStateReadStatus {
    // Object proven regular, metadata-proven, fully read through one fd and
    // stable across the proof. content/targetState are populated.
    Proven,
    // No object at the path (ENOENT proven through the open call).
    Missing,
    // Everything else. detail explains which proof stage failed. NEVER an
    // "assume unlocked" case: every non-Proven status is untrustworthy state.
    Unprovable
};

struct SecureStateReadResult {
    SecureStateReadStatus status = SecureStateReadStatus::Unprovable;
    std::string detail;
    // Full content, only valid for Proven.
    std::string content;
    // Identity/metadata/content snapshot built from the reading descriptor.
    // Reusable as AtomicWriteOptions::expectedTargetState and as the
    // expected state of a conditional remove, which is what makes the
    // BROKEN_STATE absence fallback safe.
    AtomicTargetState targetState;
};

// Maximum bytes a single secure read may return, independent of the
// expectation. Callers that need a smaller bound set maxSize as well.
inline constexpr std::uintmax_t SECURE_STATE_READ_HARD_MAX_BYTES = 4096;

// Reads a small security state file with the full proof chain described
// above. `expectation.maxSize` bounds the accepted object; the read itself is
// always bounded by SECURE_STATE_READ_HARD_MAX_BYTES so a hostile size can
// never turn into an unbounded allocation.
SecureStateReadResult readSecureStateFile(
    const std::filesystem::path& path,
    const SecureStateFileExpectation& expectation);

// Proves that `parent` is a real directory (not a symlink) and matches the
// parent expectations. Exposed separately because the incident state owner
// must check the parent BEFORE it is willing to act on the file, and the
// packaging lifecycle needs the same proof for its own writes.
bool proveSafeParentDirectory(
    const std::filesystem::path& parent,
    const SecureStateFileExpectation& expectation,
    std::string& detail);

} // namespace fic::core

#endif // FIC_CORE_FS_SECURE_STATE_FILE_H