#include "modules/identity_access/submodules/password_aging/LoginDefsFileHandler.h"

#include <cctype>
#include <sstream>
#include <utility>

namespace fic::identity::password_aging {

LoginDefsFileHandler::LoginDefsFileHandler(
    const std::string& path,
    FileHandlerOptions options)
    : ConfigFileHandler(path, " ", std::move(options)) {
}

bool LoginDefsFileHandler::loadConfig() {
    if (!FileHandler::loadFile()) {
        return false;
    }
    config_.clear();
    occurrences_.clear();

    for (std::size_t index = 0; index < original_lines_.size(); ++index) {
        const std::string& original = original_lines_[index];
        std::size_t first = original.find_first_not_of(" \t\r\n");
        if (first == std::string::npos || original[first] == '#') {
            continue;
        }

        std::size_t keyEnd = first;
        while (keyEnd < original.size() &&
               !std::isspace(static_cast<unsigned char>(original[keyEnd]))) {
            ++keyEnd;
        }
        const std::string key = original.substr(first, keyEnd - first);
        if (key.empty()) {
            continue;
        }

        Occurrence occurrence;
        occurrence.line = index;
        std::size_t valueStart = original.find_first_not_of(" \t\r\n", keyEnd);
        if (valueStart != std::string::npos) {
            std::size_t valueEnd = valueStart;
            while (valueEnd < original.size() &&
                   !std::isspace(static_cast<unsigned char>(original[valueEnd]))) {
                ++valueEnd;
            }
            const std::string trailing = original.substr(valueEnd);
            const std::size_t trailingToken =
                trailing.find_first_not_of(" \t\r\n");
            occurrence.valid = trailingToken == std::string::npos ||
                trailing[trailingToken] == '#';
            occurrence.value = original.substr(valueStart, valueEnd - valueStart);
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

LoginDefsValue LoginDefsFileHandler::lookup(
    const std::string& parameter) const {
    const auto found = occurrences_.find(parameter);
    if (found == occurrences_.end()) {
        return {};
    }
    if (found->second.size() > 1) {
        return {LoginDefsValueState::Duplicate, {}};
    }
    if (!found->second.front().valid) {
        return {LoginDefsValueState::Malformed, {}};
    }
    return {LoginDefsValueState::Unique, found->second.front().value};
}

std::string LoginDefsFileHandler::getValue(
    const std::string& parameter) const {
    const LoginDefsValue result = lookup(parameter);
    return result.state == LoginDefsValueState::Unique ? result.value : "";
}

bool LoginDefsFileHandler::setValue(
    const std::string& parameter,
    const std::string& value) {
    if (parameter.empty() || value.empty()) {
        return false;
    }
    const LoginDefsValue current = lookup(parameter);
    if (current.state == LoginDefsValueState::Duplicate ||
        current.state == LoginDefsValueState::Malformed) {
        return false;
    }
    if (current.state == LoginDefsValueState::Missing) {
        original_lines_.push_back(parameter + " " + value);
    } else {
        original_lines_[occurrences_.at(parameter).front().line] =
            parameter + " " + value;
    }
    return true;
}

bool LoginDefsFileHandler::saveAndReload() {
    return saveFile() && loadConfig();
}

} // namespace fic::identity::password_aging
