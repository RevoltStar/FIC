#pragma once
#include "SudoersLogicalEntries.h"
#include <string>
#include <vector>

namespace fic::sudoers {
// Authentication is the only mutable grammar domain. Other fields retain
// their exact source spans, including command arguments and inherited tags.
enum class AuthenticationStatement { Comment, Include, Alias, Defaults, UserSpec };
struct AuthenticationCommand {
    std::string runas;
    std::vector<std::string> tags;
    std::string commandAndArguments;
    bool passwordRequired = true;
};
struct AuthenticationRule {
    AuthenticationStatement kind = AuthenticationStatement::Comment;
    std::string users;
    std::string hosts;
    bool scopedDefaults = false;
    std::vector<AuthenticationCommand> commands;
    std::vector<SudoTokenReplacement> edits;
};
// Unsupported grammar is refused, never interpreted by token substitution.
// Native syntax validation remains a separate mandatory transaction proof.
bool parseAuthenticationRule(const SudoLogicalEntry& entry,
                             AuthenticationRule& result, std::string& error);
bool authenticationReplacement(const std::string& original,
                               std::string& replacement, bool& scoped,
                               std::string& error);
}
