#include "modules/identity_access/submodules/kerberos/KerberosConfiguration.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <set>
#include <sstream>
#include <utility>

#include <sys/stat.h>

namespace fic::identity::kerberos {
namespace {

enum class DirectiveKind {
    Include,
    IncludeDirectory
};

struct Directive {
    DirectiveKind kind;
    std::filesystem::path path;
    std::size_t line = 0;
};

struct Relation {
    std::string section;
    std::string name;
    std::string value;
    std::size_t line = 0;
    bool keyFinal = false;
    bool valueFinal = false;
};

struct ParsedProfile {
    std::vector<std::string> lines;
    bool trailingNewline = false;
    std::vector<std::pair<std::string, std::size_t>> sections;
    std::vector<Relation> relations;
    std::vector<Directive> directives;
};

struct ProfileDocument {
    std::filesystem::path path;
    ParsedProfile parsed;
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
        section.find_first_of("[]*#;\r\n") == std::string::npos;
}

bool validRelation(const std::string& relation) {
    return !relation.empty() &&
        relation.find_first_of("=*#;[]\r\n{} \t") == std::string::npos;
}

bool validValue(const std::string& value) {
    return !value.empty() &&
        value.find_first_of("\r\n") == std::string::npos;
}

ParsedProfile splitDocument(const std::string& content) {
    ParsedProfile result;
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

std::string joinDocument(const ParsedProfile& document) {
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

bool parseDirective(const std::string& trimmed,
                    DirectiveKind& kind,
                    std::filesystem::path& path) {
    const std::size_t separator = trimmed.find_first_of(" \t");
    if (separator == std::string::npos) {
        return false;
    }
    const std::string directive = trimmed.substr(0, separator);
    if (directive == "includedir") {
        kind = DirectiveKind::IncludeDirectory;
        path = trimCopy(trimmed.substr(separator + 1));
        return true;
    }
    if (directive == "include") {
        kind = DirectiveKind::Include;
        path = trimCopy(trimmed.substr(separator + 1));
        return true;
    }
    return false;
}

bool parseProfile(const std::string& content,
                  ParsedProfile& result,
                  std::string& error) {
    result = splitDocument(content);
    std::string currentSection;
    std::size_t subsectionDepth = 0;
    for (std::size_t index = 0; index < result.lines.size(); ++index) {
        const std::string trimmed = trimCopy(result.lines[index]);
        if (trimmed.empty() || trimmed.front() == '#' ||
            trimmed.front() == ';') {
            continue;
        }

        const std::size_t directiveSeparator = trimmed.find_first_of(" \t");
        if (subsectionDepth == 0 && directiveSeparator != std::string::npos &&
            trimmed.substr(0, directiveSeparator) == "module") {
            error = "Kerberos module profiles are not editable safely (line " +
                std::to_string(index + 1) + ")";
            return false;
        }

        DirectiveKind directiveKind = DirectiveKind::Include;
        std::filesystem::path directivePath;
        if (subsectionDepth == 0 &&
            parseDirective(trimmed, directiveKind, directivePath)) {
            if (directivePath.empty() || !directivePath.is_absolute()) {
                error = "Kerberos include path must be absolute at line " +
                    std::to_string(index + 1);
                return false;
            }
            result.directives.push_back({directiveKind, directivePath, index});
            continue;
        }

        if (subsectionDepth == 0 && trimmed.front() == '[') {
            std::string header = trimmed;
            if (!header.empty() && header.back() == '*') {
                header.pop_back();
                header = trimCopy(header);
            }
            if (header.size() < 3 || header.front() != '[' ||
                header.back() != ']') {
                error = "invalid Kerberos section header at line " +
                    std::to_string(index + 1);
                return false;
            }
            currentSection = trimCopy(header.substr(1, header.size() - 2));
            if (!validSection(currentSection)) {
                error = "invalid Kerberos section at line " +
                    std::to_string(index + 1);
                return false;
            }
            result.sections.emplace_back(currentSection, index);
            continue;
        }

        if (trimmed == "}" || trimmed == "}*") {
            if (subsectionDepth == 0) {
                error = "unexpected Kerberos subsection end at line " +
                    std::to_string(index + 1);
                return false;
            }
            --subsectionDepth;
            continue;
        }

        if (currentSection.empty()) {
            error = "Kerberos relation appears before a section at line " +
                std::to_string(index + 1);
            return false;
        }
        const std::size_t equals = trimmed.find('=');
        if (equals == std::string::npos) {
            error = "invalid Kerberos relation at line " +
                std::to_string(index + 1);
            return false;
        }
        std::string name = trimCopy(trimmed.substr(0, equals));
        std::string value = trimCopy(trimmed.substr(equals + 1));
        bool keyFinal = false;
        if (!name.empty() && name.back() == '*') {
            keyFinal = true;
            name.pop_back();
            name = trimCopy(name);
        }
        if (!validRelation(name) || value.empty()) {
            error = "invalid Kerberos assignment at line " +
                std::to_string(index + 1);
            return false;
        }
        if (value == "{") {
            ++subsectionDepth;
            continue;
        }
        bool valueFinal = false;
        if (!value.empty() && value.back() == '*') {
            valueFinal = true;
            value.pop_back();
            value = trimCopy(value);
        }
        if (!validValue(value)) {
            error = "invalid Kerberos scalar at line " +
                std::to_string(index + 1);
            return false;
        }
        if (subsectionDepth == 0) {
            result.relations.push_back(
                {currentSection, name, value, index, keyFinal, valueFinal});
        }
    }
    if (subsectionDepth != 0) {
        error = "unterminated Kerberos subsection";
        return false;
    }
    return true;
}

SecureConfigurationFileOptions optionsForPath(
    const SecureConfigurationFileOptions& base,
    const std::filesystem::path& path) {
    auto result = base;
    result.path = path;
    result.exactMode.reset();
    return result;
}

bool validIncludedName(const std::string& name) {
    if (name.empty() || name.front() == '.') {
        return false;
    }
    if (name.size() > 5 && name.substr(name.size() - 5) == ".conf") {
        return true;
    }
    return std::all_of(name.begin(), name.end(), [](unsigned char character) {
        return std::isalnum(character) != 0 || character == '-' ||
            character == '_';
    });
}

class ProfileGraphLoader {
public:
    ProfileGraphLoader(const KerberosConfigurationOptions& options,
                       const std::string* rootOverride)
        : options_(options), rootOverride_(rootOverride) {
    }

    bool load(std::vector<ProfileDocument>& documents, std::string& error) {
        documents.clear();
        documents_ = &documents;
        return loadFile(options_.mainFile.path, 0, true, error);
    }

private:
    bool loadFile(const std::filesystem::path& path,
                  std::size_t depth,
                  bool root,
                  std::string& error) {
        if (depth > options_.maximumIncludeDepth) {
            error = "Kerberos include depth limit exceeded";
            return false;
        }
        if (documents_->size() >= options_.maximumFiles) {
            error = "Kerberos include file limit exceeded";
            return false;
        }
        const std::string key = path.lexically_normal().string();
        if (!active_.insert(key).second) {
            error = "Kerberos include cycle at " + path.string();
            return false;
        }

        std::string content;
        if (root && rootOverride_ != nullptr) {
            content = *rootOverride_;
        } else {
            ConfigurationFileSnapshot snapshot;
            if (!readSecureConfigurationFile(
                    optionsForPath(options_.mainFile, path), snapshot, error)) {
                active_.erase(key);
                return false;
            }
            content = std::move(snapshot.content);
        }
        ParsedProfile parsed;
        if (!parseProfile(content, parsed, error)) {
            error += " in " + path.string();
            active_.erase(key);
            return false;
        }
        documents_->push_back({path, parsed});
        const auto directives = parsed.directives;
        for (const auto& directive : directives) {
            if (directive.kind == DirectiveKind::Include) {
                if (!loadFile(directive.path, depth + 1, false, error)) {
                    active_.erase(key);
                    return false;
                }
                continue;
            }
            if (!verifySecureConfigurationDirectory(
                    directive.path, options_.mainFile, error)) {
                active_.erase(key);
                return false;
            }
            std::vector<std::filesystem::path> includedFiles;
            std::error_code iteratorError;
            for (std::filesystem::directory_iterator iterator(
                     directive.path, iteratorError);
                 !iteratorError &&
                     iterator != std::filesystem::directory_iterator();
                 iterator.increment(iteratorError)) {
                if (validIncludedName(iterator->path().filename().string())) {
                    includedFiles.push_back(iterator->path());
                }
            }
            if (iteratorError) {
                error = "could not enumerate Kerberos includedir " +
                    directive.path.string() + ": " + iteratorError.message();
                active_.erase(key);
                return false;
            }
            std::sort(includedFiles.begin(), includedFiles.end());
            for (const auto& included : includedFiles) {
                if (!loadFile(included, depth + 1, false, error)) {
                    active_.erase(key);
                    return false;
                }
            }
        }
        active_.erase(key);
        return true;
    }

    const KerberosConfigurationOptions& options_;
    const std::string* rootOverride_;
    std::vector<ProfileDocument>* documents_ = nullptr;
    std::set<std::string> active_;
};

bool validateSettings(const std::vector<KerberosScalarSetting>& settings,
                      std::string& error) {
    if (settings.empty()) {
        error = "Kerberos edit contains no settings";
        return false;
    }
    std::set<std::pair<std::string, std::string>> unique;
    for (const auto& setting : settings) {
        if (!validSection(setting.section) ||
            !validRelation(setting.relation) || !validValue(setting.value) ||
            setting.value == "{") {
            error = "invalid Kerberos scalar setting";
            return false;
        }
        if (!unique.emplace(setting.section, setting.relation).second) {
            error = "duplicate Kerberos edit for [" + setting.section +
                "]/" + setting.relation;
            return false;
        }
    }
    return true;
}

bool externalDefinitionsAbsent(
    const std::vector<ProfileDocument>& documents,
    const std::vector<KerberosScalarSetting>& settings,
    std::string& error) {
    for (std::size_t index = 1; index < documents.size(); ++index) {
        for (const auto& relation : documents[index].parsed.relations) {
            const auto match = std::find_if(
                settings.begin(),
                settings.end(),
                [&](const KerberosScalarSetting& setting) {
                    return setting.section == relation.section &&
                        setting.relation == relation.name;
                });
            if (match != settings.end()) {
                error = "Kerberos relation [" + relation.section + "]/" +
                    relation.name + " is also defined in " +
                    documents[index].path.string();
                return false;
            }
        }
    }
    return true;
}

bool applyOneSetting(std::string& content,
                     const KerberosScalarSetting& setting,
                     std::string& error) {
    ParsedProfile parsed;
    if (!parseProfile(content, parsed, error)) {
        return false;
    }
    bool found = false;
    for (const auto& relation : parsed.relations) {
        if (relation.section != setting.section ||
            relation.name != setting.relation) {
            continue;
        }
        const std::string& current = parsed.lines[relation.line];
        const std::size_t indentationEnd = current.find_first_not_of(" \t");
        const std::string indentation = indentationEnd == std::string::npos
            ? std::string()
            : current.substr(0, indentationEnd);
        parsed.lines[relation.line] = indentation + setting.relation +
            (relation.keyFinal ? "*" : "") + " = " + setting.value +
            (relation.valueFinal ? "*" : "");
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
            parsed.lines.push_back(setting.relation + " = " + setting.value);
            parsed.trailingNewline = true;
        } else {
            std::size_t insertAt = parsed.lines.size();
            for (const auto& candidateSection : parsed.sections) {
                if (candidateSection.second > section->second) {
                    insertAt = candidateSection.second;
                    break;
                }
            }
            parsed.lines.insert(
                parsed.lines.begin() + static_cast<std::ptrdiff_t>(insertAt),
                setting.relation + " = " + setting.value);
        }
    }
    content = joinDocument(parsed);
    return true;
}

bool verifyExpectedValues(
    const KerberosConfigurationOptions& options,
    const std::vector<KerberosScalarSetting>& settings,
    const std::string& mainContent,
    std::string& error) {
    std::vector<ProfileDocument> documents;
    ProfileGraphLoader loader(options, &mainContent);
    if (!loader.load(documents, error) ||
        !externalDefinitionsAbsent(documents, settings, error)) {
        return false;
    }
    const auto& root = documents.front().parsed;
    for (const auto& setting : settings) {
        bool found = false;
        for (const auto& relation : root.relations) {
            if (relation.section == setting.section &&
                relation.name == setting.relation) {
                found = true;
                if (relation.value != setting.value) {
                    error = "unexpected Kerberos value for [" +
                        setting.section + "]/" + setting.relation;
                    return false;
                }
            }
        }
        if (!found) {
            error = "missing Kerberos value for [" + setting.section +
                "]/" + setting.relation;
            return false;
        }
    }
    return true;
}

} // namespace

KerberosConfigurationOptions KerberosConfigurationOptions::production() {
    KerberosConfigurationOptions options;
    options.mainFile.path = "/etc/krb5.conf";
    options.mainFile.expectedOwner = 0;
    options.mainFile.expectedGroup = 0;
    options.mainFile.exactMode.reset();
    options.mainFile.forbiddenMode = 0022;
    return options;
}

KerberosConfiguration::KerberosConfiguration(
    KerberosConfigurationOptions options)
    : options_(std::move(options)) {
}

bool KerberosConfiguration::tryGetScalarValue(
    const std::string& section,
    const std::string& relation,
    std::optional<std::string>& value,
    std::string& error) const {
    if (!validSection(section) || !validRelation(relation)) {
        error = "invalid Kerberos lookup";
        return false;
    }
    std::vector<ProfileDocument> documents;
    ProfileGraphLoader loader(options_, nullptr);
    if (!loader.load(documents, error)) {
        return false;
    }
    value.reset();
    for (const auto& document : documents) {
        for (const auto& candidate : document.parsed.relations) {
            if (candidate.section != section || candidate.name != relation) {
                continue;
            }
            if (value.has_value() && *value != candidate.value) {
                error = "ambiguous Kerberos scalar [" + section + "]/" +
                    relation;
                return false;
            }
            value = candidate.value;
        }
    }
    return true;
}

ConfigurationPreparationResult KerberosConfiguration::prepareSetScalar(
    const std::string& section,
    const std::string& relation,
    const std::string& value) const {
    return prepareSetScalars({{section, relation, value}});
}

ConfigurationPreparationResult KerberosConfiguration::prepareSetScalars(
    const std::vector<KerberosScalarSetting>& settings) const {
    std::string error;
    if (!validateSettings(settings, error)) {
        return {nullptr, std::move(error)};
    }
    ConfigurationFileSnapshot original;
    if (!readSecureConfigurationFile(options_.mainFile, original, error)) {
        return {nullptr, std::move(error)};
    }
    std::vector<ProfileDocument> documents;
    ProfileGraphLoader loader(options_, &original.content);
    if (!loader.load(documents, error) ||
        !externalDefinitionsAbsent(documents, settings, error)) {
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
            "kerberos:" + options_.mainFile.path.string(),
            options_.mainFile,
            std::move(original),
            std::move(candidate),
            verifier),
        {}};
}

bool KerberosConfiguration::setScalar(const std::string& section,
                                      const std::string& relation,
                                      const std::string& value,
                                      std::string& error) const {
    return setScalars({{section, relation, value}}, error);
}

bool KerberosConfiguration::setScalars(
    const std::vector<KerberosScalarSetting>& settings,
    std::string& error) const {
    auto prepared = prepareSetScalars(settings);
    if (!prepared.ok()) {
        error = std::move(prepared.error);
        return false;
    }
    return executePreparedFileChange(std::move(prepared.change), error);
}

} // namespace fic::identity::kerberos
