#include "modules/identity_access/submodules/sssd/SssdConfiguration.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <set>
#include <sstream>
#include <utility>

#include <sys/stat.h>

namespace fic::identity::sssd {
namespace {

struct Assignment {
    std::string section;
    std::string option;
    std::string value;
    std::size_t line = 0;
};

struct ParsedConfiguration {
    std::vector<std::string> lines;
    bool trailingNewline = false;
    std::vector<std::pair<std::string, std::size_t>> sections;
    std::vector<Assignment> assignments;
};

std::string trimCopy(std::string value) {
    const auto first = std::find_if_not(
        value.begin(), value.end(), [](unsigned char character) {
            return std::isspace(character) != 0;
        });
    if (first == value.end()) {
        return {};
    }
    const auto last = std::find_if_not(
        value.rbegin(), value.rend(), [](unsigned char character) {
            return std::isspace(character) != 0;
        }).base();
    return std::string(first, last);
}

bool validSection(const std::string& section) {
    return !section.empty() &&
        section.find_first_of("[]\r\n") == std::string::npos;
}

bool validOption(const std::string& option) {
    return !option.empty() &&
        std::all_of(option.begin(), option.end(), [](unsigned char character) {
            return std::isalnum(character) != 0 || character == '_' ||
                character == '-';
        });
}

bool validValue(const std::string& value) {
    return value.find_first_of("\r\n") == std::string::npos;
}

ParsedConfiguration splitDocument(const std::string& content) {
    ParsedConfiguration result;
    result.trailingNewline = !content.empty() && content.back() == '\n';
    std::istringstream input(content);
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        result.lines.push_back(std::move(line));
    }
    return result;
}

std::string joinDocument(const ParsedConfiguration& document) {
    std::string result;
    for (std::size_t index = 0; index < document.lines.size(); ++index) {
        if (index != 0) {
            result.push_back('\n');
        }
        result += document.lines[index];
    }
    if (document.trailingNewline && !document.lines.empty()) {
        result.push_back('\n');
    }
    return result;
}

bool parseConfiguration(const std::string& content,
                        ParsedConfiguration& result,
                        std::string& error) {
    result = splitDocument(content);
    std::string currentSection;
    for (std::size_t index = 0; index < result.lines.size(); ++index) {
        const std::string trimmed = trimCopy(result.lines[index]);
        if (trimmed.empty() || trimmed.front() == '#' ||
            trimmed.front() == ';') {
            continue;
        }
        if (trimmed.front() == '[') {
            if (trimmed.size() < 3 || trimmed.back() != ']') {
                error = "invalid SSSD section header at line " +
                    std::to_string(index + 1);
                return false;
            }
            currentSection = trimCopy(
                trimmed.substr(1, trimmed.size() - 2));
            if (!validSection(currentSection)) {
                error = "invalid SSSD section name at line " +
                    std::to_string(index + 1);
                return false;
            }
            result.sections.emplace_back(currentSection, index);
            continue;
        }
        if (currentSection.empty()) {
            error = "SSSD option appears before a section at line " +
                std::to_string(index + 1);
            return false;
        }
        const std::size_t equals = trimmed.find('=');
        if (equals == std::string::npos) {
            error = "invalid SSSD option at line " +
                std::to_string(index + 1);
            return false;
        }
        const std::string option = trimCopy(trimmed.substr(0, equals));
        const std::string value = trimCopy(trimmed.substr(equals + 1));
        if (!validOption(option) || !validValue(value)) {
            error = "invalid SSSD assignment at line " +
                std::to_string(index + 1);
            return false;
        }
        result.assignments.push_back(
            {currentSection, option, value, index});
    }
    return true;
}

SecureConfigurationFileOptions optionsForPath(
    const SecureConfigurationFileOptions& base,
    const std::filesystem::path& path) {
    auto result = base;
    result.path = path;
    return result;
}

bool listSnippetFiles(const SssdConfigurationOptions& options,
                      std::vector<std::filesystem::path>& files,
                      std::string& error) {
    files.clear();
    for (const auto& directory : options.snippetDirectories) {
        struct stat status {};
        if (::lstat(directory.c_str(), &status) != 0) {
            if (errno == ENOENT) {
                continue;
            }
            error = "could not inspect SSSD snippet directory: " +
                directory.string();
            return false;
        }
        if (!verifySecureConfigurationDirectory(
                directory, options.mainFile, error)) {
            return false;
        }
        std::vector<std::filesystem::path> directoryFiles;
        std::error_code iteratorError;
        for (std::filesystem::directory_iterator iterator(directory, iteratorError);
             !iteratorError && iterator != std::filesystem::directory_iterator();
             iterator.increment(iteratorError)) {
            const std::string name = iterator->path().filename().string();
            if (!name.empty() && name.front() != '.' &&
                iterator->path().extension() == ".conf") {
                directoryFiles.push_back(iterator->path());
            }
        }
        if (iteratorError) {
            error = "could not enumerate SSSD snippet directory " +
                directory.string() + ": " + iteratorError.message();
            return false;
        }
        std::sort(directoryFiles.begin(), directoryFiles.end());
        files.insert(files.end(), directoryFiles.begin(), directoryFiles.end());
    }
    return true;
}

bool readAndParse(const SecureConfigurationFileOptions& options,
                  ParsedConfiguration& parsed,
                  std::string& error) {
    ConfigurationFileSnapshot snapshot;
    if (!readSecureConfigurationFile(options, snapshot, error)) {
        return false;
    }
    if (!parseConfiguration(snapshot.content, parsed, error)) {
        error += " in " + options.path.string();
        return false;
    }
    return true;
}

bool validateSettings(const std::vector<SssdSetting>& settings,
                      std::string& error) {
    if (settings.empty()) {
        error = "SSSD edit contains no settings";
        return false;
    }
    std::set<std::pair<std::string, std::string>> unique;
    for (const auto& setting : settings) {
        if (!validSection(setting.section) || !validOption(setting.option) ||
            !validValue(setting.value)) {
            error = "invalid SSSD setting";
            return false;
        }
        if (!unique.emplace(setting.section, setting.option).second) {
            error = "duplicate SSSD edit for [" + setting.section + "]/" +
                setting.option;
            return false;
        }
    }
    return true;
}

bool snippetsOverride(const SssdConfigurationOptions& options,
                      const std::vector<SssdSetting>& settings,
                      std::string& error) {
    std::vector<std::filesystem::path> snippets;
    if (!listSnippetFiles(options, snippets, error)) {
        return false;
    }
    for (const auto& path : snippets) {
        ParsedConfiguration parsed;
        if (!readAndParse(optionsForPath(options.mainFile, path), parsed, error)) {
            return false;
        }
        for (const auto& assignment : parsed.assignments) {
            const auto match = std::find_if(
                settings.begin(), settings.end(), [&](const SssdSetting& setting) {
                    return setting.section == assignment.section &&
                        setting.option == assignment.option;
                });
            if (match != settings.end()) {
                error = "SSSD setting [" + assignment.section + "]/" +
                    assignment.option + " is owned by snippet " + path.string();
                return false;
            }
        }
    }
    return true;
}

bool applyOneSetting(std::string& content,
                     const SssdSetting& setting,
                     std::string& error) {
    ParsedConfiguration parsed;
    if (!parseConfiguration(content, parsed, error)) {
        return false;
    }

    bool found = false;
    for (const auto& assignment : parsed.assignments) {
        if (assignment.section != setting.section ||
            assignment.option != setting.option) {
            continue;
        }
        const std::string& current = parsed.lines[assignment.line];
        const std::size_t indentationEnd = current.find_first_not_of(" \t");
        const std::string indentation = indentationEnd == std::string::npos
            ? std::string()
            : current.substr(0, indentationEnd);
        parsed.lines[assignment.line] = indentation + setting.option +
            " = " + setting.value;
        found = true;
    }

    if (!found) {
        auto section = std::find_if(
            parsed.sections.rbegin(),
            parsed.sections.rend(),
            [&](const auto& entry) { return entry.first == setting.section; });
        if (section == parsed.sections.rend()) {
            if (!parsed.lines.empty() && !parsed.lines.back().empty()) {
                parsed.lines.push_back({});
            }
            parsed.lines.push_back("[" + setting.section + "]");
            parsed.lines.push_back(setting.option + " = " + setting.value);
            parsed.trailingNewline = true;
        } else {
            std::size_t insertAt = section->second + 1;
            for (const auto& assignment : parsed.assignments) {
                if (assignment.section == setting.section &&
                    assignment.line >= section->second) {
                    insertAt = std::max(insertAt, assignment.line + 1);
                }
            }
            parsed.lines.insert(
                parsed.lines.begin() + static_cast<std::ptrdiff_t>(insertAt),
                setting.option + " = " + setting.value);
        }
    }
    content = joinDocument(parsed);
    return true;
}

bool verifyExpectedValues(const SssdConfigurationOptions& options,
                          const std::vector<SssdSetting>& settings,
                          const std::string& mainContent,
                          std::string& error) {
    ParsedConfiguration parsed;
    if (!parseConfiguration(mainContent, parsed, error)) {
        return false;
    }
    for (const auto& setting : settings) {
        bool found = false;
        for (const auto& assignment : parsed.assignments) {
            if (assignment.section == setting.section &&
                assignment.option == setting.option) {
                found = true;
                if (assignment.value != setting.value) {
                    error = "unexpected SSSD value for [" + setting.section +
                        "]/" + setting.option;
                    return false;
                }
            }
        }
        if (!found) {
            error = "missing SSSD value for [" + setting.section + "]/" +
                setting.option;
            return false;
        }
    }
    return snippetsOverride(options, settings, error);
}

} // namespace

SssdConfigurationOptions SssdConfigurationOptions::production() {
    SssdConfigurationOptions options;
    options.mainFile.path = "/etc/sssd/sssd.conf";
    options.mainFile.expectedOwner = 0;
    options.mainFile.expectedGroup = 0;
    options.mainFile.exactMode = 0600;
    options.mainFile.forbiddenMode = 0022;
    options.snippetDirectories = {"/etc/sssd/conf.d"};
    return options;
}

SssdConfiguration::SssdConfiguration(SssdConfigurationOptions options)
    : options_(std::move(options)) {
}

bool SssdConfiguration::tryGetEffectiveValue(
    const std::string& section,
    const std::string& option,
    std::optional<std::string>& value,
    std::string& error) const {
    if (!validSection(section) || !validOption(option)) {
        error = "invalid SSSD lookup";
        return false;
    }
    ConfigurationFileSnapshot mainSnapshot;
    if (!readSecureConfigurationFile(options_.mainFile, mainSnapshot, error)) {
        return false;
    }
    ParsedConfiguration mainParsed;
    if (!parseConfiguration(mainSnapshot.content, mainParsed, error)) {
        return false;
    }
    value.reset();
    for (const auto& assignment : mainParsed.assignments) {
        if (assignment.section == section && assignment.option == option) {
            value = assignment.value;
        }
    }

    std::vector<std::filesystem::path> snippets;
    if (!listSnippetFiles(options_, snippets, error)) {
        return false;
    }
    for (const auto& path : snippets) {
        ParsedConfiguration parsed;
        if (!readAndParse(optionsForPath(options_.mainFile, path), parsed, error)) {
            return false;
        }
        for (const auto& assignment : parsed.assignments) {
            if (assignment.section == section && assignment.option == option) {
                value = assignment.value;
            }
        }
    }
    return true;
}

ConfigurationPreparationResult SssdConfiguration::prepareSetValue(
    const std::string& section,
    const std::string& option,
    const std::string& value) const {
    return prepareSetValues({{section, option, value}});
}

ConfigurationPreparationResult SssdConfiguration::prepareSetValues(
    const std::vector<SssdSetting>& settings) const {
    std::string error;
    if (!validateSettings(settings, error)) {
        return {nullptr, std::move(error)};
    }
    ConfigurationFileSnapshot original;
    if (!readSecureConfigurationFile(options_.mainFile, original, error)) {
        return {nullptr, std::move(error)};
    }
    ParsedConfiguration parsed;
    if (!parseConfiguration(original.content, parsed, error)) {
        return {nullptr, std::move(error)};
    }
    if (!snippetsOverride(options_, settings, error)) {
        return {nullptr, std::move(error)};
    }

    std::string candidate = original.content;
    for (const auto& setting : settings) {
        if (!applyOneSetting(candidate, setting, error)) {
            return {nullptr, std::move(error)};
        }
    }
    if (!verifyExpectedValues(options_, settings, candidate, error)) {
        return {nullptr, std::move(error)};
    }

    const auto verifier = [options = options_, settings](
        const std::string& content,
        std::string& verifyError) {
        return verifyExpectedValues(options, settings, content, verifyError);
    };
    return {
        makePreparedFileChange(
            "sssd:" + options_.mainFile.path.string(),
            options_.mainFile,
            std::move(original),
            std::move(candidate),
            verifier),
        {}};
}

bool SssdConfiguration::setValue(const std::string& section,
                                 const std::string& option,
                                 const std::string& value,
                                 std::string& error) const {
    return setValues({{section, option, value}}, error);
}

bool SssdConfiguration::setValues(
    const std::vector<SssdSetting>& settings,
    std::string& error) const {
    auto prepared = prepareSetValues(settings);
    if (!prepared.ok()) {
        error = std::move(prepared.error);
        return false;
    }
    return executePreparedFileChange(std::move(prepared.change), error);
}

} // namespace fic::identity::sssd
