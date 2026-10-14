#include "modules/dac/sudo/SudoersAuthenticationGrammar.h"
#include "modules/dac/sudo/SudoersAuthenticationWrapper.h"
#include <iostream>
#include <algorithm>
using namespace fic::sudoers;
int main() {
    int failed = 0, executed = 0;
    auto check = [&](bool ok, const char* why) { ++executed; if (!ok) { ++failed; std::cerr << why << '\n'; } };
    std::string replacement, error; bool scoped;
    const std::string original = "deploy ALL=(root:wheel) NOEXEC: INTERCEPT: SETENV: LOG_INPUT: LOG_OUTPUT: NOPASSWD: /bin/echo NOPASSWD, \\\r\n\t!/bin/false, PASSWD: /bin/true";
    check(authenticationReplacement(original, replacement, scoped, error), "typed multiline transformation");
    auto expected = original; expected.replace(expected.find("NOPASSWD:"), 8, "PASSWD");
    check(replacement == expected && !scoped, "only auth tag changed; all other bytes preserved");
    auto entries = assembleSudoLogicalEntries(splitPhysicalLines(original), true); AuthenticationRule rule;
    check(parseAuthenticationRule(entries[0], rule, error) && rule.commands.size() == 3 &&
        !rule.commands[0].passwordRequired && !rule.commands[1].passwordRequired && rule.commands[2].passwordRequired,
        "authentication inheritance and negation preserved");
    check(authenticationReplacement("Defaults:alice !authenticate, env_keep=\"NOPASSWD authenticate\"\r\n", replacement, scoped, error) &&
        scoped && replacement == "Defaults:alice authenticate, env_keep=\"NOPASSWD authenticate\"\r\n", "typed contextual Defaults");
    for (const auto& text : {"alice ALL=NOPASSWD: /bin/true : otherhost=NOPASSWD: /bin/false\n",
        "alice ALL=UNKNOWN: NOPASSWD: /bin/true\n",
        "alice ALL=NOPASSWD: /bin/echo (foo, NOPASSWD: /bin/true)\n", "alice ALL=sha256:abcd NOPASSWD: /bin/true\n",
        "alice, bob ALL=NOPASSWD: /bin/true\n", "alice ALL=NOPASSWD: /bin/echo 'words'\n"})
        check(!authenticationReplacement(text, replacement, scoped, error), "ambiguous grammar refused");
    for (const auto& text : {"alice ALL=PASSWD: /bin/echo NOPASSWD\\: argument\n",
        "Cmnd_Alias CMD = /bin/echo NOPASSWD\\: argument\n", "# NOPASSWD: /bin/true\n"}) {
        auto entry = assembleSudoLogicalEntries(splitPhysicalLines(text), true).front();
        check(parseAuthenticationRule(entry, rule, error) && rule.edits.empty(), "argument/alias/comment is not a tag");
    }
    check(authenticationReplacement("#1000 ALL=NOPASSWD: /bin/true\n", replacement, scoped, error) &&
        replacement == "#1000 ALL=PASSWD: /bin/true\n", "numeric UID is not a comment");
    check(authenticationReplacement("@account ALL=NOPASSWD: /bin/true\n", replacement, scoped, error) &&
        replacement == "@account ALL=PASSWD: /bin/true\n", "at-sign alone is not an include directive");
    auto aliasEntry = assembleSudoLogicalEntries(splitPhysicalLines("User_Alias\tUSERS = alice,bob\n"), true).front();
    check(parseAuthenticationRule(aliasEntry, rule, error) && rule.kind == AuthenticationStatement::Alias && rule.edits.empty(),
        "alias keyword whitespace and opaque members preserved");
    const auto id = generateSudoWrapperMutationId(0);
    check(authenticationReplacement(original, replacement, scoped, error), "prepare frame replacement");
    auto lines = makeAuthenticationWrapper(id, original, replacement); std::vector<AuthenticationWrapper> frames;
    check(parseAuthenticationWrappers(lines, frames, error) && frames.size() == 1 && frames[0].original == original &&
        frames[0].replacement == replacement, "canonical frame roundtrip");
    auto active = std::find_if(lines.begin(), lines.end(), [](const auto& x) { return x.text.find("deploy ALL=") == 0; });
    active->text.replace(active->text.find("NOEXEC"), 6, "EXEC");
    check(!parseAuthenticationWrappers(lines, frames, error), "permission widening refused even with valid marker id");
    check(!parseAuthenticationWrappers(splitPhysicalLines("  #@FIC_AUTH_UNKNOWN\n"), frames, error),
        "indented unknown ownership marker refused");
    std::cout << "Authentication grammar checks=" << executed << " failed=" << failed << '\n';
    return failed ? 1 : 0;
}
