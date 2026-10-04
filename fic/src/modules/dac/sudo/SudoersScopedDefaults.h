#ifndef FIC_SUDOERSSCOPEDDEFAULTS_H
#define FIC_SUDOERSSCOPEDDEFAULTS_H

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

// Detection of contextual/scoped sudoers Defaults entries.
//
// sudoers supports four scoping forms after the `Defaults` keyword, with NO
// whitespace allowed between the keyword and the scope character:
//
//   Defaults:user ...      Defaults@host ...
//   Defaults>runas ...     Defaults!command ...
//
// The scope target may be a plain name, a %group, a User_Alias/Host_Alias/
// Runas_Alias/Cmnd_Alias, ALL, a negation (`ALL,!root`) or a combination.
// Evaluating WHICH of them is a sudoers semantic problem (aliases, netgroups,
// negation) and is deliberately OUT of FIC's scope: for this security policy
// the mere PRESENCE of a scoped Defaults entry in the active configuration is
// the violation. That closes the P0/P1 contextual overrides and the hard P2
// alias/negation cases without building a sudoers evaluator.
namespace fic::sudoers {

// One logical (continuation-joined) sudoers entry that is a scoped Defaults.
struct ScopedDefaultsEntry {
    std::filesystem::path source;
    size_t firstLine = 0;
    // Number of physical lines the logical entry occupies (>= 1).
    size_t lineCount = 1;
    // 'Defaults' followed by one of the four scope characters.
    std::string scope;
};

// Returns the scope character (':', '@', '>' or '!') when `logicalLine` is a
// scoped Defaults entry, and an empty string otherwise. Comments and quoted
// strings cannot produce a false positive, because the keyword must be the
// first token of the entry.
std::string scopedDefaultsScope(std::string_view logicalLine);

// Human-readable "path:line" label used in diagnostics.
std::string scopedDefaultsLocation(const ScopedDefaultsEntry& entry);

} // namespace fic::sudoers

#endif // FIC_SUDOERSSCOPEDDEFAULTS_H
