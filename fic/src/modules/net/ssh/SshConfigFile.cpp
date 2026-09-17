#include "modules/net/ssh/SshConfigFile.h"

#include "modules/net/ssh/SshConfigSyntax.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <iostream>
#include <vector>

namespace {

// Splits exact file content into lines (getline-equivalent: the trailing
// newline does not produce an extra empty line).
std::vector<std::string> splitConfigLines(const std::string& content) {
    std::vector<std::string> lines;
    std::string current;
    for (const char character : content) {
        if (character == '\n') {
            lines.push_back(current);
            current.clear();
        } else {
            current.push_back(character);
        }
    }
    if (!current.empty()) {
        lines.push_back(current);
    }
    return lines;
}

} // namespace

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
    lastLoadMarkerMalformed_ = false;
    // Single optimistic snapshot: identity, metadata and content are read
    // through the same descriptor, so the parsed representation and the
    // conditional-save precondition always describe the same file state.
    AtomicTargetState snapshot;
    std::string snapshotError;
    if (!AtomicFileWriter::captureTargetState(
            filepath_, snapshot, &snapshotError)) {
        std::cerr << "Error: could not capture sshd_config snapshot: "
                  << snapshotError << std::endl;
        return false;
    }

    original_lines_ = splitConfigLines(snapshot.content);
    loadSnapshot_ = std::move(snapshot);

    // Fail closed on broken FIC marker structure: a malformed managed block
    // or disabled-line wrapper can never be attributed and must block every
    // FIC mutation of the file until resolved.
    SshManagedModel managedModel;
    std::string modelError;
    const SshManagedParseStatus status =
        parseSshManagedModel(original_lines_, managedModel, modelError);
    if (status != SshManagedParseStatus::Ok) {
        std::cerr << "Error: invalid FIC markers in sshd_config: " << modelError
                  << std::endl;
        lastLoadMarkerMalformed_ = true;
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
    (void)parameter;
    (void)value;
    return false;
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