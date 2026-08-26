#include "modules/identity_access/user_creation/configuration/AdduserConfigFileHandler.h"

#include <algorithm>
#include <cctype>
#include <utility>

namespace fic::identity {
namespace {

std::string trimCopy(std::string value) {
    const auto notSpace = [](unsigned char character) {
        return std::isspace(character) == 0;
    };
    value.erase(value.begin(),
                std::find_if(value.begin(), value.end(), notSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(),
                value.end());
    return value;
}

std::string canonicalKey(std::string key) {
    std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return key;
}

bool parseAssignmentValue(const std::string& input, std::string& value) {
    std::string remainder = trimCopy(input);
    if (remainder.empty()) {
        value.clear();
        return true;
    }
    if (remainder.front() == '\'' || remainder.front() == '"') {
        const char quote = remainder.front();
        const std::size_t close = remainder.find(quote, 1);
        if (close == std::string::npos) return false;
        const std::string suffix = trimCopy(remainder.substr(close + 1));
        if (!suffix.empty() && suffix.front() != '#') return false;
        value = remainder.substr(1, close - 1);
        return value.find(quote) == std::string::npos;
    }
    const std::size_t comment = remainder.find('#');
    if (comment != std::string::npos) remainder.erase(comment);
    value = trimCopy(remainder);
    return true;
}

} // namespace

AdduserConfigFileHandler::AdduserConfigFileHandler(
    const std::string& path,
    FileHandlerOptions options)
    : ConfigFileHandler(path, "=", std::move(options)) {
}

bool AdduserConfigFileHandler::loadConfig() {
    if (!FileHandler::loadFile()) return false;
    config_.clear();
    occurrences_.clear();

    for (std::size_t index = 0; index < original_lines_.size(); ++index) {
        const std::string& line = original_lines_[index];
        std::size_t cursor = line.find_first_not_of(" \t\r\n");
        if (cursor == std::string::npos || line[cursor] == '#') continue;
        const std::size_t keyStart = cursor;
        while (cursor < line.size() &&
               std::isspace(static_cast<unsigned char>(line[cursor])) == 0 &&
               line[cursor] != '=' && line[cursor] != '#') {
            ++cursor;
        }
        if (cursor == keyStart) continue;
        const std::string key = canonicalKey(
            line.substr(keyStart, cursor - keyStart));

        Occurrence occurrence;
        occurrence.line = index;
        while (cursor < line.size() &&
               std::isspace(static_cast<unsigned char>(line[cursor])) != 0) {
            ++cursor;
        }
        if (cursor < line.size() && line[cursor] == '=') {
            occurrence.valid = parseAssignmentValue(
                line.substr(cursor + 1), occurrence.value);
        }
        occurrences_[key].push_back(occurrence);
    }

    for (const auto& [key, entries] : occurrences_) {
        if (entries.size() == 1 && entries.front().valid) {
            config_[key] = entries.front().value;
        }
    }
    return true;
}

AdduserConfigValue AdduserConfigFileHandler::lookup(
    const std::string& parameter) const {
    const auto found = occurrences_.find(canonicalKey(parameter));
    if (found == occurrences_.end()) return {};
    if (found->second.size() != 1) {
        return {AdduserConfigValueState::Duplicate, {}};
    }
    if (!found->second.front().valid) {
        return {AdduserConfigValueState::Malformed, {}};
    }
    return {AdduserConfigValueState::Unique, found->second.front().value};
}

std::string AdduserConfigFileHandler::getValue(
    const std::string& parameter) const {
    const AdduserConfigValue result = lookup(parameter);
    return result.state == AdduserConfigValueState::Unique ? result.value : "";
}

bool AdduserConfigFileHandler::setCanonicalValue(
    const std::string& parameter,
    const std::string& value,
    bool quoted) {
    const std::string key = canonicalKey(parameter);
    const AdduserConfigValue current = lookup(key);
    if (current.state == AdduserConfigValueState::Duplicate ||
        current.state == AdduserConfigValueState::Malformed) {
        return false;
    }
    const std::string line = parameter + "=" +
        (quoted ? "\"" + value + "\"" : value);
    if (current.state == AdduserConfigValueState::Missing) {
        original_lines_.push_back(line);
    } else {
        original_lines_[occurrences_.at(key).front().line] = line;
    }
    return true;
}

bool AdduserConfigFileHandler::setSupplementaryGroups(
    bool enabled,
    const std::vector<std::string>& groups) {
    const auto enabledValue = lookup("ADD_EXTRA_GROUPS");
    const auto groupsValue = lookup("EXTRA_GROUPS");
    const auto ambiguous = [](AdduserConfigValueState state) {
        return state == AdduserConfigValueState::Duplicate ||
            state == AdduserConfigValueState::Malformed;
    };
    if (ambiguous(enabledValue.state) || ambiguous(groupsValue.state) ||
        (enabled && groups.empty()) || (!enabled && !groups.empty())) {
        return false;
    }
    if (!setCanonicalValue("ADD_EXTRA_GROUPS", enabled ? "1" : "0", false)) {
        return false;
    }
    if (!enabled) return true;

    std::string joined;
    for (std::size_t i = 0; i < groups.size(); ++i) {
        if (i != 0) joined += ' ';
        joined += groups[i];
    }
    return setCanonicalValue("EXTRA_GROUPS", joined, true);
}

bool AdduserConfigFileHandler::saveAndReload() {
    return saveFile() && loadConfig();
}

} // namespace fic::identity
