#include "modules/net/submodules/Ssh.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <sstream>

SshConfigFileHandler::SshConfigFileHandler(const std::string& filepath)
    : FileHandler(filepath, " ") {
}

std::string SshConfigFileHandler::trimCopy(std::string value) {
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
    value.erase(std::find_if(value.rbegin(), value.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), value.end());
    return value;
}

std::string SshConfigFileHandler::toLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool SshConfigFileHandler::isCommentOrEmpty(const std::string& line) {
    std::string trimmed = trimCopy(line);
    return trimmed.empty() || trimmed[0] == '#';
}

std::string SshConfigFileHandler::stripInlineComment(const std::string& line) {
    bool inSingleQuotes = false;
    bool inDoubleQuotes = false;

    for (size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (c == '\'' && !inDoubleQuotes) {
            inSingleQuotes = !inSingleQuotes;
            continue;
        }
        if (c == '"' && !inSingleQuotes) {
            inDoubleQuotes = !inDoubleQuotes;
            continue;
        }
        if (c == '#' && !inSingleQuotes && !inDoubleQuotes) {
            return line.substr(0, i);
        }
    }

    return line;
}

bool SshConfigFileHandler::parseDirective(const std::string& line, std::string& parameter, std::string& value) {
    std::string cleaned = trimCopy(stripInlineComment(line));
    if (cleaned.empty()) {
        return false;
    }

    std::istringstream stream(cleaned);
    if (!(stream >> parameter)) {
        return false;
    }

    std::getline(stream, value);
    value = trimCopy(value);
    return !parameter.empty();
}

size_t SshConfigFileHandler::findFirstMatchLine() const {
    for (size_t i = 0; i < original_lines_.size(); ++i) {
        if (isCommentOrEmpty(original_lines_[i])) {
            continue;
        }

        std::string parameter;
        std::string value;
        if (parseDirective(original_lines_[i], parameter, value) && toLower(parameter) == "match") {
            return i;
        }
    }

    return original_lines_.size();
}

bool SshConfigFileHandler::loadConfig() {
    if (!this->FileHandler::loadFile()) {
        return false;
    }

    config_.clear();
    canonicalNames_.clear();

    const size_t globalEnd = findFirstMatchLine();
    for (size_t i = 0; i < globalEnd; ++i) {
        if (isCommentOrEmpty(original_lines_[i])) {
            continue;
        }

        std::string parameter;
        std::string value;
        if (!parseDirective(original_lines_[i], parameter, value)) {
            continue;
        }

        const std::string normalizedParameter = toLower(parameter);
        if (config_.find(normalizedParameter) != config_.end()) {
            original_lines_[i] = "#" + original_lines_[i];
            continue;
        }

        config_[normalizedParameter] = value;
        canonicalNames_[normalizedParameter] = parameter;
    }

    return true;
}

std::string SshConfigFileHandler::getValue(const std::string& parameter) const {
    const auto it = config_.find(toLower(parameter));
    return it != config_.end() ? it->second : "";
}

bool SshConfigFileHandler::isParameterExists(const std::string& parameter) const {
    return config_.find(toLower(parameter)) != config_.end();
}

bool SshConfigFileHandler::setValue(const std::string& parameter, const std::string& value) {
    const std::string normalizedParameter = toLower(parameter);
    if (normalizedParameter.empty()) {
        return false;
    }

    const std::string canonicalParameter = canonicalNames_.count(normalizedParameter) > 0
        ? canonicalNames_[normalizedParameter]
        : parameter;
    const std::string newLine = canonicalParameter + " " + value;
    const size_t globalEnd = findFirstMatchLine();

    bool updated = false;
    for (size_t i = 0; i < globalEnd; ++i) {
        if (isCommentOrEmpty(original_lines_[i])) {
            continue;
        }

        std::string currentParameter;
        std::string currentValue;
        if (!parseDirective(original_lines_[i], currentParameter, currentValue)) {
            continue;
        }

        if (toLower(currentParameter) != normalizedParameter) {
            continue;
        }

        if (!updated) {
            original_lines_[i] = newLine;
            updated = true;
        } else {
            original_lines_[i] = "#" + original_lines_[i];
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
    std::cout << "SSH configuration parameters:" << "\n";
    for (const auto& pair : config_) {
        const auto canonicalIt = canonicalNames_.find(pair.first);
        const std::string parameter = canonicalIt != canonicalNames_.end() ? canonicalIt->second : pair.first;
        std::cout << "  '" << parameter << "':'" << pair.second << "'\n";
    }
}

Ssh::~Ssh() {
}

const std::string Ssh::sshPath="/home/MFC.LOCAL/poroshinmi/openssh-test.txt";

std::unique_ptr<SshConfigFileHandler> Ssh::sshConfig =
        std::make_unique<SshConfigFileHandler>(Ssh::sshPath);

Ssh::Ssh()
    : Net(){
    this->submoduleName = "SshEdit";
}

bool Ssh::check_and_fix() {
    if (this->sshParameter.empty()) {
        this->log("SSH parameter is not configured for policy " + this->policyName, logLevel::FATAL);
        return false;
    }

    if (!this->sshConfig->loadConfig()) {
        this->log("Failed to load sshd_config", logLevel::ERROR);
        return false;
    }

    const std::optional valueOpt = this->getValue();
    if(!valueOpt){
        return false;
    }
    const std::string expectedValue = *valueOpt;
    if (expectedValue.empty() || expectedValue == "[NO VALUE SET]") {
        this->log("Reference value for policy " + this->policyName + " is empty", logLevel::ERROR);
        return false;
    }

    const std::string currentValue = this->sshConfig->getValue(this->sshParameter);
    if (currentValue == expectedValue) {
        this->log("No deviations found for SSH parameter " + this->sshParameter, logLevel::INFO);
        return true;
    }

    this->log("Detected deviation for SSH parameter '" + this->sshParameter + "'. Current:'" +
              currentValue + "' Expected:'" + expectedValue + "'", logLevel::WARN);

    if (!this->sshConfig->setValue(this->sshParameter, expectedValue)) {
        this->log("Failed to update SSH parameter " + this->sshParameter, logLevel::ERROR);
        return false;
    }

    if (!this->sshConfig->saveFile()) {
        this->log("Failed to save sshd_config", logLevel::ERROR);
        return false;
    }

    this->log("SSH parameter deviation was fixed", logLevel::INFO);
    return true;
}
