#ifndef SSHCONFIGSYNTAX_H
#define SSHCONFIGSYNTAX_H

#include <cstddef>
#include <string>
#include <vector>

struct SshDirective {
    std::string keyword;
    std::vector<std::string> arguments;
};

struct SshLineParseResult {
    bool ok = false;
    bool hasDirective = false;
    SshDirective directive;
    std::string error;
};

SshLineParseResult parseSshConfigLine(const std::string& line);
std::string normalizeSshKeyword(std::string keyword);
std::string joinSshArguments(const std::vector<std::string>& arguments,
                             std::size_t start = 0);

#endif // SSHCONFIGSYNTAX_H
