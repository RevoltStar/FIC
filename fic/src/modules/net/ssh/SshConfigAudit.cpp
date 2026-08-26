#include "modules/net/ssh/SshConfigAudit.h"
#include "modules/net/ssh/SshConfigSyntax.h"

#include <fstream>
#include <set>
#include <system_error>
#include <utility>

#include <glob.h>

namespace {

struct IncludeAuditState {
    std::set<std::filesystem::path> activeFiles;
    std::size_t filesRead = 0;
    std::vector<SshConditionalOccurrence> occurrences;
};

class ActiveFileGuard {
public:
    ActiveFileGuard(std::set<std::filesystem::path>& activeFiles,
                    std::filesystem::path identity)
        : activeFiles_(activeFiles),
          identity_(std::move(identity)) {
    }

    ~ActiveFileGuard() {
        activeFiles_.erase(identity_);
    }

private:
    std::set<std::filesystem::path>& activeFiles_;
    std::filesystem::path identity_;
};

std::filesystem::path includeIdentity(const std::filesystem::path& path) {
    std::error_code error;
    const std::filesystem::path canonical = std::filesystem::canonical(path, error);
    return error ? path.lexically_normal() : canonical;
}

bool auditConfigFile(const std::filesystem::path& path,
                     const SshConfigAuditOptions& options,
                     const std::string& expectedParameter,
                     std::string matchCondition,
                     IncludeAuditState& state,
                     std::string& error,
                     std::size_t depth) {
    if (depth > options.maximumIncludeDepth) {
        error = "SSH Include depth exceeds " +
                std::to_string(options.maximumIncludeDepth);
        return false;
    }
    if (++state.filesRead > options.maximumIncludedFiles) {
        error = "SSH Include graph exceeds " +
                std::to_string(options.maximumIncludedFiles) + " files";
        return false;
    }

    const std::filesystem::path identity = includeIdentity(path);
    if (!state.activeFiles.insert(identity).second) {
        error = "recursive SSH Include detected at " + path.string();
        return false;
    }
    ActiveFileGuard activeFileGuard(state.activeFiles, identity);

    std::ifstream stream(path);
    if (!stream.is_open()) {
        error = "failed to read SSH configuration source " + path.string();
        return false;
    }

    std::string line;
    std::size_t lineNumber = 0;
    while (std::getline(stream, line)) {
        ++lineNumber;
        const SshLineParseResult parsed = parseSshConfigLine(line);
        if (!parsed.ok) {
            error = path.string() + ":" + std::to_string(lineNumber) +
                    ": " + parsed.error;
            return false;
        }
        if (!parsed.hasDirective) {
            continue;
        }

        const std::string directive =
            normalizeSshKeyword(parsed.directive.keyword);
        if (directive == "match") {
            if (parsed.directive.arguments.empty()) {
                error = path.string() + ":" + std::to_string(lineNumber) +
                        ": empty Match condition";
                return false;
            }
            matchCondition = joinSshArguments(parsed.directive.arguments);
            continue;
        }

        if (directive == "include") {
            if (parsed.directive.arguments.empty()) {
                error = path.string() + ":" + std::to_string(lineNumber) +
                        ": empty Include directive";
                return false;
            }
            for (const std::string& include : parsed.directive.arguments) {
                if (!include.empty() && include.front() == '~') {
                    error = path.string() + ":" + std::to_string(lineNumber) +
                            ": SSH Include paths beginning with '~' are unsupported";
                    return false;
                }

                std::filesystem::path pattern = include;
                if (!pattern.is_absolute()) {
                    pattern = options.includeBasePath / pattern;
                }

                glob_t matches {};
                const int globResult = ::glob(pattern.c_str(), 0, nullptr, &matches);
                if (globResult != 0 && globResult != GLOB_NOMATCH) {
                    ::globfree(&matches);
                    error = path.string() + ":" + std::to_string(lineNumber) +
                            ": failed to expand SSH Include " + pattern.string();
                    return false;
                }
                for (std::size_t match = 0; match < matches.gl_pathc; ++match) {
                    if (!auditConfigFile(matches.gl_pathv[match],
                                         options,
                                         expectedParameter,
                                         matchCondition,
                                         state,
                                         error,
                                         depth + 1)) {
                        ::globfree(&matches);
                        return false;
                    }
                }
                ::globfree(&matches);
            }
            continue;
        }

        if (!matchCondition.empty() && directive == expectedParameter) {
            if (parsed.directive.arguments.empty()) {
                error = path.string() + ":" + std::to_string(lineNumber) +
                        ": empty conditional SSH value";
                return false;
            }
            state.occurrences.push_back({
                path,
                lineNumber,
                joinSshArguments(parsed.directive.arguments),
                matchCondition
            });
        }
    }
    if (!stream.good() && !stream.eof()) {
        error = "failed while reading SSH configuration source " + path.string();
        return false;
    }
    return true;
}

} // namespace

SshConfigAudit::SshConfigAudit(SshConfigAuditOptions options)
    : options_(std::move(options)) {
}

bool SshConfigAudit::findConditionalOccurrences(
    const std::string& parameter,
    std::vector<SshConditionalOccurrence>& occurrences,
    std::string& error
) const {
    occurrences.clear();
    if (parameter.empty()) {
        error = "SSH parameter is empty";
        return false;
    }
    if (!options_.configPath.is_absolute()) {
        error = "SSH configuration path must be absolute";
        return false;
    }
    if (!options_.includeBasePath.is_absolute()) {
        error = "SSH Include base path must be absolute";
        return false;
    }

    IncludeAuditState state;
    if (!auditConfigFile(options_.configPath,
                         options_,
                         normalizeSshKeyword(parameter),
                         {},
                         state,
                         error,
                         0)) {
        return false;
    }

    occurrences = std::move(state.occurrences);
    error.clear();
    return true;
}
