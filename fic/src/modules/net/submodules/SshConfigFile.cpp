#include "modules/net/submodules/SshConfigFile.h"
#include "modules/net/submodules/SshConfigSyntax.h"

#include <iostream>

SshConfigFileHandler::SshConfigFileHandler(const std::string& filepath)
    : FileHandler(filepath, " ") {
}

bool SshConfigFileHandler::findFirstMatchLine(std::size_t& line) const {
    for (std::size_t index = 0; index < original_lines_.size(); ++index) {
        const SshLineParseResult parsed = parseSshConfigLine(original_lines_[index]);
        if (!parsed.ok) {
            return false;
        }
        if (!parsed.hasDirective) {
            continue;
        }
        if (normalizeSshKeyword(parsed.directive.keyword) == "match") {
            line = index;
            return true;
        }
    }

    line = original_lines_.size();
    return true;
}

bool SshConfigFileHandler::loadConfig() {
    if (!FileHandler::loadFile()) {
        return false;
    }

    config_.clear();
    canonicalNames_.clear();

    std::size_t globalEnd = 0;
    if (!findFirstMatchLine(globalEnd)) {
        return false;
    }
    for (std::size_t index = 0; index < globalEnd; ++index) {
        const SshLineParseResult parsed = parseSshConfigLine(original_lines_[index]);
        if (!parsed.ok) {
            return false;
        }
        if (!parsed.hasDirective) {
            continue;
        }

        const std::string normalizedParameter =
            normalizeSshKeyword(parsed.directive.keyword);
        if (config_.find(normalizedParameter) != config_.end()) {
            continue;
        }

        config_[normalizedParameter] = joinSshArguments(parsed.directive.arguments);
        canonicalNames_[normalizedParameter] = parsed.directive.keyword;
    }

    return true;
}

std::string SshConfigFileHandler::getValue(const std::string& parameter) const {
    const auto found = config_.find(normalizeSshKeyword(parameter));
    return found != config_.end() ? found->second : "";
}

bool SshConfigFileHandler::isParameterExists(const std::string& parameter) const {
    return config_.find(normalizeSshKeyword(parameter)) != config_.end();
}

bool SshConfigFileHandler::setValue(const std::string& parameter,
                                    const std::string& value) {
    const std::string normalizedParameter = normalizeSshKeyword(parameter);
    if (normalizedParameter.empty()) {
        return false;
    }

    const std::string canonicalParameter =
        canonicalNames_.count(normalizedParameter) > 0
            ? canonicalNames_[normalizedParameter]
            : parameter;
    const std::string newLine = canonicalParameter + " " + value;
    std::size_t globalEnd = 0;
    if (!findFirstMatchLine(globalEnd)) {
        return false;
    }

    bool updated = false;
    for (std::size_t index = 0; index < globalEnd; ++index) {
        const SshLineParseResult parsed = parseSshConfigLine(original_lines_[index]);
        if (!parsed.ok) {
            return false;
        }
        if (!parsed.hasDirective ||
            normalizeSshKeyword(parsed.directive.keyword) != normalizedParameter) {
            continue;
        }

        if (!updated) {
            original_lines_[index] = newLine;
            updated = true;
        } else {
            original_lines_[index] = "#" + original_lines_[index];
        }
    }

    if (!updated) {
        original_lines_.insert(original_lines_.begin() + globalEnd, newLine);
    }

    config_[normalizedParameter] = value;
    canonicalNames_[normalizedParameter] = canonicalParameter;
    return true;
}

void SshConfigFileHandler::printConfig() const {
    std::cout << "SSH configuration parameters:\n";
    for (const auto& pair : config_) {
        const auto canonical = canonicalNames_.find(pair.first);
        const std::string parameter =
            canonical != canonicalNames_.end() ? canonical->second : pair.first;
        std::cout << "  '" << parameter << "':'" << pair.second << "'\n";
    }
}
