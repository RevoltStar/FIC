#pragma once

#include <cstddef>
#include <limits>
#include <string>
#include <vector>

#include "SudoersDisabledWrapper.h"

namespace fic::sudoers {

// ONE logical sudoers entry: the assembled text of a single directive together
// with the PHYSICAL span it occupies.
//
// The physical span is not decoration. Ownership, CAS, diagnostics and the
// byte-exact suppression of a FIC_SUDO_DISABLED block are all expressed in
// physical coordinates, so the assembler is the single place that decides which
// physical lines belong to one logical entry.
struct SudoLogicalEntry {
    struct SourcePosition {
        static constexpr std::size_t synthetic = std::numeric_limits<std::size_t>::max();
        std::size_t physicalLine = synthetic;
        std::size_t column = synthetic;
        bool isPhysical() const { return physicalLine != synthetic && column != synthetic; }
    };
    // Zero-based index of the first physical line, as produced by
    // splitPhysicalLines(). Callers that need a human-readable 1-based number
    // add one themselves.
    std::size_t firstPhysicalLine = 0;
    // How many consecutive physical lines this entry occupies.
    std::size_t lineCount = 1;
    // The assembled logical text, WITHOUT any terminator.
    std::string text;
    // Optional byte coordinates, one per logical character. An inserted
    // continuation separator has no physical source and cannot be rewritten.
    std::vector<SourcePosition> sourcePositions;
};

// THE single physical -> logical assembly step for sudoers.
//
// `SudoersConfiguration` uses it to build the include graph and the ordered
// line list, and `ScopedDefaultsTransaction` uses it for the snapshot-bound
// semantic proof. Sharing it is what makes parser reasoning and security proof
// structurally unable to disagree about how a continuation is read.
//
// CONTRACT (deduplicated from the previous in-parser implementation; the
// semantics are deliberately NOT improved here):
//   * a line whose trimmed form is non-empty and ends with '\' continues,
//     where "ends with a continuation" means an ODD number of trailing
//     backslashes (an even count is an escaped backslash and does not continue);
//   * the next physical line is trimmed and appended after exactly one space;
//   * the last physical line is never continued past the end of the file;
//   * a '\r' that belongs to a "\r\n" terminator is already excluded from
//     SudoPhysicalLine::text by splitPhysicalLines(), so CRLF input is handled
//     exactly like LF input and terminators are never normalized.
//
// This helper performs ONLY the physical -> logical assembly. It does not
// recognize comments, include directives, scoped Defaults or FIC wrappers:
// those stay in the existing layers that run after assembly.
std::vector<SudoLogicalEntry> assembleSudoLogicalEntries(
    const std::vector<SudoPhysicalLine>& lines,
    bool withSourcePositions = false);

// A parser supplies the exact token it recognized. The renderer must not
// infer token roles or normalize the surrounding sudoers bytes.
struct SudoTokenReplacement {
    std::size_t logicalOffset = 0;
    std::string expected;
    std::string replacement;
};

// All edits are checked before changing any physical line. Tokens spanning a
// continuation, overlapping edits and stale physical token bytes are rejected.
// The transaction must separately compare the complete document snapshot.
bool replaceSudoLogicalTokens(const SudoLogicalEntry& entry,
                              const std::vector<SudoTokenReplacement>& edits,
                              std::vector<SudoPhysicalLine>& lines,
                              std::string& error);

} // namespace fic::sudoers
