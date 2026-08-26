#include "modules/identity_access/nss/NssConfiguration.h"

#include <algorithm>
#include <cctype>
#include <set>
#include <sstream>
#include <utility>

namespace fic::identity::nss {
namespace {

struct DatabaseEntry {
    std::string database;
    std::vector<NssService> services;
    std::size_t line = 0;
};

struct ParsedConfiguration {
    std::vector<std::string> lines;
    bool trailingNewline = false;
    std::vector<DatabaseEntry> entries;
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

bool validIdentifier(const std::string& value) {
    return !value.empty() &&
        std::all_of(value.begin(), value.end(), [](unsigned char character) {
            return std::isalnum(character) != 0 || character == '_' ||
                character == '-' || character == '.';
        });
}

bool actionsEqual(const NssAction& left, const NssAction& right) {
    return left.negated == right.negated && left.status == right.status &&
        left.result == right.result;
}

bool servicesEqual(const std::vector<NssService>& left,
                   const std::vector<NssService>& right) {
    if (left.size() != right.size()) {
        return false;
    }
    for (std::size_t index = 0; index < left.size(); ++index) {
        if (left[index].name != right[index].name ||
            left[index].actions.size() != right[index].actions.size()) {
            return false;
        }
        for (std::size_t action = 0;
             action < left[index].actions.size(); ++action) {
            if (!actionsEqual(
                    left[index].actions[action], right[index].actions[action])) {
                return false;
            }
        }
    }
    return true;
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

bool parseActionBlock(const std::string& block,
                      std::vector<NssAction>& actions,
                      std::string& error) {
    std::istringstream input(block);
    std::string expression;
    while (input >> expression) {
        NssAction action;
        if (!expression.empty() && expression.front() == '!') {
            action.negated = true;
            expression.erase(expression.begin());
        }
        const std::size_t equals = expression.find('=');
        if (equals == std::string::npos ||
            expression.find('=', equals + 1) != std::string::npos) {
            error = "invalid NSS action expression";
            return false;
        }
        action.status = expression.substr(0, equals);
        action.result = expression.substr(equals + 1);
        if (!validIdentifier(action.status) ||
            !validIdentifier(action.result)) {
            error = "invalid NSS action identifier";
            return false;
        }
        actions.push_back(std::move(action));
    }
    if (actions.empty()) {
        error = "empty NSS action block";
        return false;
    }
    return true;
}

bool parseServiceSpecification(const std::string& specification,
                               std::vector<NssService>& services,
                               std::string& error) {
    std::size_t position = 0;
    while (position < specification.size()) {
        while (position < specification.size() &&
               std::isspace(
                   static_cast<unsigned char>(specification[position])) != 0) {
            ++position;
        }
        if (position == specification.size()) {
            break;
        }
        if (specification[position] == '[') {
            if (services.empty()) {
                error = "NSS action block appears before a service";
                return false;
            }
            const std::size_t end = specification.find(']', position + 1);
            if (end == std::string::npos) {
                error = "unterminated NSS action block";
                return false;
            }
            std::vector<NssAction> actions;
            if (!parseActionBlock(
                    specification.substr(position + 1, end - position - 1),
                    actions,
                    error)) {
                return false;
            }
            services.back().actions.insert(
                services.back().actions.end(), actions.begin(), actions.end());
            position = end + 1;
            continue;
        }
        const std::size_t begin = position;
        while (position < specification.size() &&
               std::isspace(
                   static_cast<unsigned char>(specification[position])) == 0 &&
               specification[position] != '[') {
            if (specification[position] == ']') {
                error = "unexpected NSS action block terminator";
                return false;
            }
            ++position;
        }
        const std::string service = specification.substr(begin, position - begin);
        if (!validIdentifier(service)) {
            error = "invalid NSS service name: " + service;
            return false;
        }
        services.push_back({service, {}});
    }
    if (services.empty()) {
        error = "NSS database has no services";
        return false;
    }
    return true;
}

bool parseConfiguration(const std::string& content,
                        ParsedConfiguration& result,
                        std::string& error) {
    result = splitDocument(content);
    for (std::size_t index = 0; index < result.lines.size(); ++index) {
        std::string active = result.lines[index];
        const std::size_t comment = active.find('#');
        if (comment != std::string::npos) {
            active.erase(comment);
        }
        active = trimCopy(std::move(active));
        if (active.empty()) {
            continue;
        }
        const std::size_t colon = active.find(':');
        if (colon == std::string::npos ||
            active.find(':', colon + 1) != std::string::npos) {
            error = "invalid NSS database entry at line " +
                std::to_string(index + 1);
            return false;
        }
        const std::string database = trimCopy(active.substr(0, colon));
        if (!validIdentifier(database)) {
            error = "invalid NSS database name at line " +
                std::to_string(index + 1);
            return false;
        }
        std::vector<NssService> services;
        if (!parseServiceSpecification(
                active.substr(colon + 1), services, error)) {
            error += " at line " + std::to_string(index + 1);
            return false;
        }
        result.entries.push_back({database, std::move(services), index});
    }
    return true;
}

std::string serializeServices(const std::vector<NssService>& services) {
    std::string result;
    for (const auto& service : services) {
        if (!result.empty()) {
            result.push_back(' ');
        }
        result += service.name;
        if (!service.actions.empty()) {
            result += " [";
            for (std::size_t index = 0; index < service.actions.size(); ++index) {
                if (index != 0) {
                    result.push_back(' ');
                }
                if (service.actions[index].negated) {
                    result.push_back('!');
                }
                result += service.actions[index].status + "=" +
                    service.actions[index].result;
            }
            result.push_back(']');
        }
    }
    return result;
}

bool validateServices(const std::vector<NssService>& services,
                      std::string& error) {
    if (services.empty()) {
        error = "NSS service list is empty";
        return false;
    }
    for (const auto& service : services) {
        if (!validIdentifier(service.name)) {
            error = "invalid NSS service name";
            return false;
        }
        for (const auto& action : service.actions) {
            if (!validIdentifier(action.status) ||
                !validIdentifier(action.result)) {
                error = "invalid NSS action";
                return false;
            }
        }
    }
    return true;
}

bool validateSettings(const std::vector<NssDatabaseSetting>& settings,
                      std::string& error) {
    if (settings.empty()) {
        error = "NSS edit contains no databases";
        return false;
    }
    std::set<std::string> unique;
    for (const auto& setting : settings) {
        if (!validIdentifier(setting.database) ||
            !validateServices(setting.services, error)) {
            return false;
        }
        if (!unique.insert(setting.database).second) {
            error = "duplicate NSS database edit: " + setting.database;
            return false;
        }
    }
    return true;
}

bool applyOneSetting(std::string& content,
                     const NssDatabaseSetting& setting,
                     std::string& error) {
    ParsedConfiguration parsed;
    if (!parseConfiguration(content, parsed, error)) {
        return false;
    }
    const std::string specification = serializeServices(setting.services);
    bool found = false;
    for (const auto& entry : parsed.entries) {
        if (entry.database != setting.database) {
            continue;
        }
        const std::string& current = parsed.lines[entry.line];
        const std::size_t indentationEnd = current.find_first_not_of(" \t");
        const std::string indentation = indentationEnd == std::string::npos
            ? std::string()
            : current.substr(0, indentationEnd);
        const std::size_t comment = current.find('#');
        const std::string suffix = comment == std::string::npos
            ? std::string()
            : " " + current.substr(comment);
        parsed.lines[entry.line] = indentation + setting.database + ": " +
            specification + suffix;
        found = true;
    }
    if (!found) {
        parsed.lines.push_back(setting.database + ": " + specification);
        parsed.trailingNewline = true;
    }
    content = joinDocument(parsed);
    return true;
}

bool verifyExpectedValues(const std::vector<NssDatabaseSetting>& settings,
                          const std::string& content,
                          std::string& error) {
    ParsedConfiguration parsed;
    if (!parseConfiguration(content, parsed, error)) {
        return false;
    }
    for (const auto& setting : settings) {
        bool found = false;
        for (const auto& entry : parsed.entries) {
            if (entry.database == setting.database) {
                found = true;
                if (!servicesEqual(entry.services, setting.services)) {
                    error = "unexpected NSS service list for " +
                        setting.database;
                    return false;
                }
            }
        }
        if (!found) {
            error = "missing NSS database: " + setting.database;
            return false;
        }
    }
    return true;
}

} // namespace

NssConfigurationOptions NssConfigurationOptions::production() {
    NssConfigurationOptions options;
    options.mainFile.path = "/etc/nsswitch.conf";
    options.mainFile.expectedOwner = 0;
    options.mainFile.expectedGroup = 0;
    options.mainFile.exactMode.reset();
    options.mainFile.forbiddenMode = 0022;
    return options;
}

NssConfiguration::NssConfiguration(NssConfigurationOptions options)
    : options_(std::move(options)) {
}

bool NssConfiguration::tryGetServices(
    const std::string& database,
    std::optional<std::vector<NssService>>& services,
    std::string& error) const {
    if (!validIdentifier(database)) {
        error = "invalid NSS database lookup";
        return false;
    }
    ConfigurationFileSnapshot snapshot;
    if (!readSecureConfigurationFile(options_.mainFile, snapshot, error)) {
        return false;
    }
    ParsedConfiguration parsed;
    if (!parseConfiguration(snapshot.content, parsed, error)) {
        return false;
    }
    services.reset();
    for (const auto& entry : parsed.entries) {
        if (entry.database != database) {
            continue;
        }
        if (services.has_value() &&
            !servicesEqual(*services, entry.services)) {
            error = "ambiguous NSS database: " + database;
            return false;
        }
        services = entry.services;
    }
    return true;
}

ConfigurationPreparationResult NssConfiguration::prepareSetServices(
    const std::string& database,
    const std::vector<NssService>& services) const {
    return prepareSetDatabases({{database, services}});
}

ConfigurationPreparationResult NssConfiguration::prepareSetDatabases(
    const std::vector<NssDatabaseSetting>& settings) const {
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
    std::string candidate = original.content;
    for (const auto& setting : settings) {
        if (!applyOneSetting(candidate, setting, error)) {
            return {nullptr, std::move(error)};
        }
    }
    if (!verifyExpectedValues(settings, candidate, error)) {
        return {nullptr, std::move(error)};
    }
    const auto verifier = [settings](const std::string& content,
                                     std::string& verifyError) {
        return verifyExpectedValues(settings, content, verifyError);
    };
    return {
        makePreparedFileChange(
            "nss:" + options_.mainFile.path.string(),
            options_.mainFile,
            std::move(original),
            std::move(candidate),
            verifier),
        {}};
}

bool NssConfiguration::setServices(
    const std::string& database,
    const std::vector<NssService>& services,
    std::string& error) const {
    return setDatabases({{database, services}}, error);
}

bool NssConfiguration::setDatabases(
    const std::vector<NssDatabaseSetting>& settings,
    std::string& error) const {
    auto prepared = prepareSetDatabases(settings);
    if (!prepared.ok()) {
        error = std::move(prepared.error);
        return false;
    }
    return executePreparedFileChange(std::move(prepared.change), error);
}

} // namespace fic::identity::nss
