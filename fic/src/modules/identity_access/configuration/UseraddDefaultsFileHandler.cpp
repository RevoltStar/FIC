#include "modules/identity_access/configuration/UseraddDefaultsFileHandler.h"

#include <cctype>
#include <utility>

namespace fic::identity {
namespace {

bool isKeyCharacter(char character) {
    return character != '=' &&
        std::isspace(static_cast<unsigned char>(character)) == 0;
}

} // namespace

UseraddDefaultsFileHandler::UseraddDefaultsFileHandler(
    const std::string& path,
    FileHandlerOptions options)
    : ConfigFileHandler(path, "=", std::move(options)) {
}

bool UseraddDefaultsFileHandler::loadConfig() {
    if (!FileHandler::loadFile()) return false;
    config_.clear();
    occurrences_.clear();

    for (std::size_t index = 0; index < original_lines_.size(); ++index) {
        const std::string& line = original_lines_[index];
        std::size_t first = line.find_first_not_of(" \t\r\n");
        if (first == std::string::npos || line[first] == '#') continue;

        std::size_t keyEnd = first;
        while (keyEnd < line.size() && isKeyCharacter(line[keyEnd])) ++keyEnd;
        if (keyEnd == first) continue;
        const std::string key = line.substr(first, keyEnd - first);

        Occurrence occurrence;
        occurrence.line = index;
        if (first == 0 && keyEnd < line.size() && line[keyEnd] == '=') {
            occurrence.value = line.substr(keyEnd + 1);
            occurrence.valid = !occurrence.value.empty() &&
                occurrence.value.front() != '#' &&
                occurrence.value.find_first_of(" \t\r\n") ==
                    std::string::npos;
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

UseraddDefaultsValue UseraddDefaultsFileHandler::lookup(
    const std::string& parameter) const {
    const auto found = occurrences_.find(parameter);
    if (found == occurrences_.end()) return {};
    if (found->second.size() != 1) {
        return {UseraddDefaultsValueState::Duplicate, {}};
    }
    if (!found->second.front().valid) {
        return {UseraddDefaultsValueState::Malformed, {}};
    }
    return {UseraddDefaultsValueState::Unique, found->second.front().value};
}

std::string UseraddDefaultsFileHandler::getValue(
    const std::string& parameter) const {
    const UseraddDefaultsValue result = lookup(parameter);
    return result.state == UseraddDefaultsValueState::Unique ? result.value : "";
}

bool UseraddDefaultsFileHandler::setValue(
    const std::string& parameter,
    const std::string& value) {
    if (parameter.empty() || value.empty() ||
        value.find_first_of(" \t\r\n") != std::string::npos) {
        return false;
    }
    const UseraddDefaultsValue current = lookup(parameter);
    if (current.state == UseraddDefaultsValueState::Duplicate ||
        current.state == UseraddDefaultsValueState::Malformed) {
        return false;
    }
    if (current.state == UseraddDefaultsValueState::Missing) {
        original_lines_.push_back(parameter + "=" + value);
    } else {
        original_lines_[occurrences_.at(parameter).front().line] =
            parameter + "=" + value;
    }
    return true;
}

bool UseraddDefaultsFileHandler::removeValue(const std::string& parameter) {
    if (parameter.empty()) return false;
    const UseraddDefaultsValue current = lookup(parameter);
    if (current.state == UseraddDefaultsValueState::Duplicate ||
        current.state == UseraddDefaultsValueState::Malformed) {
        return false;
    }
    if (current.state == UseraddDefaultsValueState::Missing) return true;
    const std::size_t removedLine =
        occurrences_.at(parameter).front().line;
    original_lines_.erase(
        original_lines_.begin() +
        static_cast<std::ptrdiff_t>(removedLine));
    occurrences_.erase(parameter);
    for (auto& [key, entries] : occurrences_) {
        (void)key;
        for (Occurrence& occurrence : entries) {
            if (occurrence.line > removedLine) --occurrence.line;
        }
    }
    config_.erase(parameter);
    return true;
}

bool UseraddDefaultsFileHandler::saveAndReload() {
    return saveFile() && loadConfig();
}

} // namespace fic::identity
