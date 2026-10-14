// Direct contract tests for the SHARED physical -> logical assembler.
//
// These expectations describe the EXISTING SudoersConfiguration behaviour,
// which this change deduplicates rather than improves. Two quirks are asserted
// on purpose, because "fixing" them would be a semantics change and is
// explicitly out of scope here:
//   1. a continuation yields TWO spaces, because the trailing backslash is
//      removed from the trimmed text while the space in front of it survives,
//      and then exactly one space is appended;
//   2. a trailing continuation on the LAST physical line is NOT continued past
//      EOF, so its backslash stays in the logical text.
//
// The primitive has its own contract, so it is tested directly instead of only
// through a lifecycle E2E: the E2E cannot express "three-line continuation" or
// "even trailing backslashes" without building a whole journal scenario around
// it, and the assembler is the single place both the parser and the
// snapshot-bound semantic proof now depend on.
#include "modules/dac/sudo/SudoersLogicalEntries.h"

#include <iostream>
#include <string>
#include <vector>

namespace {

int failures = 0;
int executed = 0;

void check(bool condition, const std::string& what) {
    if (condition) {
        return;
    }
    ++failures;
    std::cerr << "FAILED: " << what << "\n";
}

using fic::sudoers::SudoLogicalEntry;

std::vector<SudoLogicalEntry> assemble(const std::string& content) {
    return fic::sudoers::assembleSudoLogicalEntries(
        fic::sudoers::splitPhysicalLines(content));
}

// --- a single physical line stays a single logical entry ------------------

void singleLine() {
    const auto entries = assemble("Defaults:alice exempt_group=wheel\n");
    check(entries.size() == 1, "single line yields one entry");
    check(entries[0].lineCount == 1, "single line has lineCount 1");
    check(entries[0].firstPhysicalLine == 0, "single line starts at 0");
    check(entries[0].text == "Defaults:alice exempt_group=wheel",
          "single line text is preserved verbatim");
    ++executed;
}

// --- two-line continuation ------------------------------------------------

void twoLineContinuation() {
    const auto entries =
        assemble("Defaults:alice env_reset, \\\n    passwd_tries=5\n");
    check(entries.size() == 1, "a continuation yields ONE logical entry");
    check(entries[0].lineCount == 2, "the entry spans two physical lines");
    check(entries[0].firstPhysicalLine == 0, "the entry starts at line 0");
    // Faithful to the pre-existing parser: two spaces, not one.
    check(entries[0].text == "Defaults:alice env_reset,  passwd_tries=5",
          "the removed backslash leaves the space in front of it");
    ++executed;
}

// --- three-line continuation ---------------------------------------------

void threeLineContinuation() {
    const auto entries = assemble("Defaults:alice a, \\\n  b, \\\n  c\n");
    check(entries.size() == 1, "a three-line continuation yields one entry");
    check(entries[0].lineCount == 3, "the entry spans three physical lines");
    check(entries[0].text == "Defaults:alice a,  b,  c",
          "each continuation keeps the space that preceded its backslash");
    ++executed;
}

// --- odd trailing backslash continues, even does not ---------------------

void backslashParity() {
    const auto odd = assemble("Defaults:alice a \\\nb\n");
    check(odd.size() == 1 && odd[0].lineCount == 2,
          "an odd trailing backslash count continues the entry");

    // Two trailing backslashes are an ESCAPED backslash, not a continuation.
    const auto even = assemble("Defaults:alice a \\\\\nb\n");
    check(even.size() == 2, "an even trailing backslash count does NOT continue");
    check(even[0].lineCount == 1, "the even case ends after one physical line");
    ++executed;
}

// --- leading and trailing whitespace --------------------------------------

void whitespaceTrimming() {
    const auto entries = assemble("    Defaults:alice env_reset, \\\n"
                                  "\t  passwd_tries=5   \n");
    check(entries.size() == 1, "indentation does not create extra entries");
    check(entries[0].text == "Defaults:alice env_reset,  passwd_tries=5",
          "the continued line is trimmed before it is appended");
    ++executed;
}

// --- CRLF is handled exactly like LF and terminators are preserved --------

void crlfInput() {
    const auto entries =
        assemble("Defaults:alice env_reset, \\\r\n  passwd_tries=5\r\n");
    check(entries.size() == 1, "CRLF continuation yields one entry");
    check(entries[0].lineCount == 2, "the CRLF entry spans two physical lines");
    // The '\r' belongs to the terminator and must never reach the logical text.
    check(entries[0].text == "Defaults:alice env_reset,  passwd_tries=5",
          "CRLF must not leak a carriage return into the logical text");
    ++executed;
}

// --- a final entry without a terminating newline --------------------------

void noFinalNewline() {
    const auto entries = assemble("Defaults:alice a, \\\n  passwd_tries=5");
    check(entries.size() == 1, "a multiline entry without a final newline");
    check(entries[0].lineCount == 2, "it still spans two physical lines");
    check(entries[0].text == "Defaults:alice a,  passwd_tries=5",
          "the last physical line is assembled normally");

    // A trailing continuation on the LAST line is not continued past EOF, so
    // the backslash survives in the logical text.
    const auto dangling = assemble("Defaults:alice a \\\n");
    check(dangling.size() == 1, "a dangling continuation stays one entry");
    check(dangling[0].text == "Defaults:alice a \\",
          "a continuation at EOF keeps its backslash");
    ++executed;
}

// --- physical spans of several entries stay exact -------------------------

void physicalSpans() {
    const auto entries = assemble("one\nDefaults:alice a, \\\n  b\nthree\n");
    check(entries.size() == 3, "three logical entries are produced");
    check(entries[0].firstPhysicalLine == 0 && entries[0].lineCount == 1,
          "the first entry keeps its span");
    check(entries[1].firstPhysicalLine == 1 && entries[1].lineCount == 2,
          "the continuation entry keeps its two-line span");
    check(entries[2].firstPhysicalLine == 3 && entries[2].lineCount == 1,
          "the entry after a continuation starts at the right physical line");
    ++executed;
}

void physicalSourceCoordinates() {
    const auto lines = fic::sudoers::splitPhysicalLines(
        "  alice ALL=(root) NOPASSWD: /usr/bin/true, \\\r\n\t  PASSWD: /usr/bin/printf literal\r\n");
    const auto entries = fic::sudoers::assembleSudoLogicalEntries(lines, true);
    check(entries.size() == 1, "mapped continuation remains one logical entry");
    const auto& entry = entries.front();
    check(entry.sourcePositions.size() == entry.text.size(), "every logical byte has coordinates");
    unsigned synthetic = 0;
    for (std::size_t index = 0; index < entry.text.size(); ++index) {
        const auto& position = entry.sourcePositions[index];
        if (!position.isPhysical()) {
            ++synthetic;
            check(entry.text[index] == ' ', "synthetic coordinate denotes only inserted separator");
        } else {
            check(position.physicalLine < lines.size() &&
                  position.column < lines[position.physicalLine].text.size() &&
                  lines[position.physicalLine].text[position.column] == entry.text[index],
                  "source coordinate names the exact original byte");
        }
    }
    check(synthetic == 1, "exactly one synthetic continuation separator");
    const auto token = entry.text.rfind("PASSWD:");
    check(token != std::string::npos && entry.sourcePositions[token].physicalLine == 1 &&
          entry.sourcePositions[token].column == 3, "second-line tag retains tab/space source offset");
    check(fic::sudoers::assembleSudoLogicalEntries(lines).front().sourcePositions.empty(),
          "ordinary consumers do not allocate source coordinates");
    ++executed;
}

void physicalTokenReplacement() {
    using fic::sudoers::replaceSudoLogicalTokens;
    const std::string original = "alice ALL=(root) NOPASSWD: /bin/echo NOPASSWD, \\\r\n\tNOPASSWD: /bin/true";
    auto lines = fic::sudoers::splitPhysicalLines(original);
    const auto entry = fic::sudoers::assembleSudoLogicalEntries(lines, true).front();
    std::string error;
    const auto first = entry.text.find("NOPASSWD:");
    const auto last = entry.text.rfind("NOPASSWD:");
    check(replaceSudoLogicalTokens(entry, {{first, "NOPASSWD", "PASSWD"},
          {last, "NOPASSWD", "PASSWD"}}, lines, error), "two physical tag replacements accepted");
    check(fic::sudoers::joinPhysicalLines(lines) ==
          "alice ALL=(root) PASSWD: /bin/echo NOPASSWD, \\\r\n\tPASSWD: /bin/true",
          "argument bytes, CRLF, continuation and missing final LF preserved");
    lines = fic::sudoers::splitPhysicalLines(original);
    check(!replaceSudoLogicalTokens(entry, {{first, "NOPASSWD", "PASSWD"},
          {first + 1, "OPASSWD", "PASSWD"}}, lines, error), "overlapping edits refused");
    check(fic::sudoers::joinPhysicalLines(lines) == original, "rejection is atomic");
    lines[1].text.replace(1, 8, "PASSWD");
    const auto drifted = fic::sudoers::joinPhysicalLines(lines);
    check(!replaceSudoLogicalTokens(entry, {{first, "NOPASSWD", "PASSWD"},
          {last, "NOPASSWD", "PASSWD"}}, lines, error), "late physical drift refused");
    check(fic::sudoers::joinPhysicalLines(lines) == drifted, "earlier edit not applied on late drift");
    auto split = fic::sudoers::splitPhysicalLines("NOPASS\\\nWD");
    const auto splitEntry = fic::sudoers::assembleSudoLogicalEntries(split, true).front();
    check(!replaceSudoLogicalTokens(splitEntry, {{0, splitEntry.text, "PASSWD"}}, split, error),
          "synthetic continuation bytes cannot be rewritten");
    ++executed;
}

} // namespace

int main() {
    singleLine();
    twoLineContinuation();
    threeLineContinuation();
    backslashParity();
    whitespaceTrimming();
    crlfInput();
    noFinalNewline();
    physicalSpans();
    physicalSourceCoordinates();
    physicalTokenReplacement();

    std::cout << "Executed " << executed << " logical-entry contract tests\n";
    if (failures != 0) {
        std::cout << failures << " logical-entry contract checks failed\n";
        return 1;
    }
    std::cout << "Logical-entry assembler contract proven\n";
    return 0;
}
