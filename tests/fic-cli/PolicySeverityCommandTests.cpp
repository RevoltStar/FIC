#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

// Simulates the severity command routing decision from fic-cli/src/main.cpp.
// Returns true if the "set" subcommand path should be taken.
bool is_severity_set_command(int argc, char* argv[]) {
    return argc >= 4 && std::string(argv[3]) == "set";
}

std::vector<char*> make_argv(std::vector<std::string>& values) {
    std::vector<char*> result;
    result.reserve(values.size());
    for (std::string& value : values) {
        result.push_back(value.data());
    }
    return result;
}

} // namespace

int main() {
    // fic-cli policy severity set DAC sudo_timeout HARD
    // argv[3] == "set" → set command path
    {
        std::vector<std::string> values{
            "fic-cli", "policy", "severity", "set", "DAC", "sudo_timeout",
            "HARD"};
        std::vector<char*> argv = make_argv(values);
        assert(is_severity_set_command(
                   static_cast<int>(argv.size()), argv.data()) &&
               "severity set should be detected as set command");
    }

    // fic-cli policy severity DAC sudo_timeout
    // argv[3] == "DAC" → view command path
    {
        std::vector<std::string> values{
            "fic-cli", "policy", "severity", "DAC", "sudo_timeout"};
        std::vector<char*> argv = make_argv(values);
        assert(!is_severity_set_command(
                   static_cast<int>(argv.size()), argv.data()) &&
               "severity view should not be detected as set command");
    }

    // Missing arguments: argc < 4 → not set command
    {
        std::vector<std::string> values{"fic-cli", "policy", "severity"};
        std::vector<char*> argv = make_argv(values);
        assert(!is_severity_set_command(
                   static_cast<int>(argv.size()), argv.data()) &&
               "too few arguments should not be set command");
    }

    // Wrong subcommand: argv[3] != "set" → not set command
    {
        std::vector<std::string> values{
            "fic-cli", "policy", "severity", "get", "DAC", "sudo_timeout"};
        std::vector<char*> argv = make_argv(values);
        assert(!is_severity_set_command(
                   static_cast<int>(argv.size()), argv.data()) &&
               "unknown subcommand should not be set command");
    }

    std::cout << "All cli_policy_severity_tests passed" << std::endl;
    return 0;
}