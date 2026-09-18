#ifndef FIC_OSS_GRUB_MANAGED_BLOCK_H
#define FIC_OSS_GRUB_MANAGED_BLOCK_H

#include <cstddef>
#include <string>
#include <utility>
#include <vector>
#include <array>
#include <algorithm>

// FIC-owned managed block for GRUB shared defaults files (ALT p11 topology:
// /etc/sysconfig/grub2). The block is the final FIC override layer at EOF;
// shell assignment semantics make the last assignment effective, so the
// block never needs to rewrite foreign assignments. This is the GRUB-
// specific strict mini-language; the SSH marker parser is intentionally not
// reused.

// Canonical markers. The grammar is strict: any line that mentions the
// marker keywords but is not exactly the canonical marker (modulo trailing
// whitespace and CR/LF) fails closed as a foreign FIC-like malformed marker.
constexpr const char* kGrubBlockBeginMarker = "# FIC_GRUB_BLOCK_BEGIN version=1";
constexpr const char* kGrubBlockEndMarker = "# FIC_GRUB_BLOCK_END";

// FIC-supported GRUB keys in canonical render order. Shared with the
// Debian/Ubuntu managed drop-in configuration. Inline so that shared layers
// (mutation journal validation) can use them without linking module code.
inline constexpr std::array<const char*, 3> kGrubManagedKeys = {
    "GRUB_CMDLINE_LINUX",
    "GRUB_DISABLE_RECOVERY",
    "GRUB_TIMEOUT"
};

inline bool isGrubManagedKey(const std::string& key) {
    return std::any_of(
        kGrubManagedKeys.begin(), kGrubManagedKeys.end(),
        [&key](const char* allowed) { return key == allowed; });
}

inline size_t grubManagedKeyOrder(const std::string& key) {
    for (size_t index = 0; index < kGrubManagedKeys.size(); ++index) {
        if (key == kGrubManagedKeys[index]) {
            return index;
        }
    }
    return kGrubManagedKeys.size();
}

// key/value pairs kept in canonical render order.
using GrubBlockEntries = std::vector<std::pair<std::string, std::string>>;

struct GrubManagedBlockView {
    bool present = false;
    GrubBlockEntries entries;
};

struct GrubBlockParseResult {
    bool ok = false;
    GrubManagedBlockView view;
    std::string error;
};

// Strict parser of the FIC managed block inside a shared GRUB defaults file.
// The foreign part is opaque bytes and is never interpreted. Fail closed on:
// more than one block, missing BEGIN/END, nested/duplicate markers, foreign
// FIC-like malformed markers, unknown keys, duplicate keys, malformed quoted
// values, any comment, empty line, or non-assignment line inside the block.
GrubBlockParseResult parseGrubManagedBlock(const std::string& content);

// Strictly canonical managed value literal: a double-quoted shell literal
// with only \" \\ \$ \` escapes. Rejects CR, LF and NUL (injection-proof).
std::string encodeGrubManagedValue(const std::string& value);
bool decodeGrubManagedValue(const std::string& text,
                            std::string& value,
                            std::string& error);

struct GrubBlockMutationResult {
    bool ok = false;
    std::string content;
    std::string error;
};

// Sets/updates one managed key. The managed block is (re)placed at EOF; all
// foreign bytes are preserved byte-exact. The newline separating a non-empty
// foreign area from the block is FIC-owned serialization and is always
// appended (exactly one), which makes the pre-apply foreign bytes recoverable
// byte-exact on removal — including foreign content without a trailing
// newline. A block that is not at
// EOF (foreign content appended after it) is relocated to EOF: the exact
// proven block content is removed, foreign bytes keep their order, and the
// canonical block is appended.
GrubBlockMutationResult setGrubManagedBlockValue(
    const std::string& content,
    const std::string& key,
    const std::string& value);

// Removes one managed key. An empty remaining block is removed entirely
// (no empty BEGIN/END artifact); foreign content is preserved byte-exact:
// the FIC-owned separator newline before the removed block is dropped with
// it, so foreign bytes without a trailing newline are restored exactly.
// A missing key is a no-op success.
GrubBlockMutationResult removeGrubManagedBlockValue(
    const std::string& content,
    const std::string& key);

#endif // FIC_OSS_GRUB_MANAGED_BLOCK_H
