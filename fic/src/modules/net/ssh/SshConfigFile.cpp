#include "modules/net/ssh/SshConfigFile.h"
#include "modules/net/ssh/SshConfigSyntax.h"

#include <cstdint>
#include <iostream>

namespace {

// Deterministic 64-bit FNV-1a fingerprint of the global section. Only drift
// detection depends on it: a fingerprint mismatch fails rollback closed, it
// is never used to reconstruct content.
std::string fingerprintLines(const std::vector<std::string>& lines,
                             std::size_t end) {
    std::uint64_t hash = 1469598103934665603ULL;
    const auto mix = [&hash](const std::string& text) {
        for (const char character : text) {
            hash ^= static_cast<std::uint8_t>(character);
            hash *= 1099511628211ULL;
        }
        hash ^= static_cast<std::uint8_t>('\n');
        hash *= 1099511628211ULL;
    };
    for (std::size_t index = 0; index < end && index < lines.size(); ++index) {
        mix(lines[index]);
    }
    static const char digits[] = "0123456789abcdef";
    std::string result(16, '0');
    for (int offset = 0; offset < 16; ++offset) {
        result[15 - offset] = digits[(hash >> (offset * 4)) & 0xF];
    }
    return result;
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

bool SshConfigFileHandler::planSetValue(const std::string& parameter,
                                        const std::string& value,
                                        SshDirectiveMutationPlan& plan) const {
    const std::string normalizedParameter = normalizeSshKeyword(parameter);
    if (normalizedParameter.empty()) {
        return false;
    }

    const auto canonicalIt = canonicalNames_.find(normalizedParameter);
    const std::string canonicalParameter =
        canonicalIt != canonicalNames_.end() ? canonicalIt->second : parameter;
    const std::string newLine = canonicalParameter + " " + value;

    std::size_t globalEnd = 0;
    if (!findFirstMatchLine(globalEnd)) {
        return false;
    }

    plan = SshDirectiveMutationPlan{};
    plan.parameter = normalizedParameter;
    plan.canonicalParameter = canonicalParameter;
    plan.appliedValue = value;

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
            fic::rollback::SshLineReverseEdit edit;
            edit.globalLineIndex = index;
            edit.beforeLine = original_lines_[index];
            edit.afterLine = newLine;
            plan.reverseEdits.push_back(std::move(edit));
            updated = true;
        } else {
            fic::rollback::SshLineReverseEdit edit;
            edit.globalLineIndex = index;
            edit.beforeLine = original_lines_[index];
            edit.afterLine = "#" + original_lines_[index];
            plan.reverseEdits.push_back(std::move(edit));
        }
    }

    if (!updated) {
        // The directive does not exist yet: FIC will insert the line before
        // the first Match (or at the end of the file). Rollback removes it.
        fic::rollback::SshLineReverseEdit edit;
        edit.globalLineIndex = globalEnd;
        edit.beforeLine = std::nullopt;
        edit.afterLine = newLine;
        plan.reverseEdits.push_back(std::move(edit));
    }

    // Fingerprint of the post-mutation global section, computed in memory
    // before anything touches the disk.
    std::vector<std::string> postMutationLines(
        original_lines_.begin(),
        original_lines_.begin() + static_cast<std::ptrdiff_t>(globalEnd));
    for (const fic::rollback::SshLineReverseEdit& edit : plan.reverseEdits) {
        if (edit.beforeLine.has_value()) {
            postMutationLines[edit.globalLineIndex] = edit.afterLine;
        } else {
            postMutationLines.insert(
                postMutationLines.begin() +
                    static_cast<std::ptrdiff_t>(edit.globalLineIndex),
                edit.afterLine);
        }
    }
    plan.appliedGlobalSectionFingerprint =
        fingerprintLines(postMutationLines, postMutationLines.size());
    return true;
}

bool SshConfigFileHandler::applyReverseEdits(
    const std::vector<fic::rollback::SshLineReverseEdit>& edits,
    std::string& error) {
    std::size_t globalEnd = 0;
    if (!findFirstMatchLine(globalEnd)) {
        error = "Не удалось выделить global section sshd_config";
        return false;
    }

    // Validate everything first (fail closed): the current global section
    // must exactly match the recorded after-state before any change.
    for (const fic::rollback::SshLineReverseEdit& edit : edits) {
        if (edit.globalLineIndex >= globalEnd ||
            edit.globalLineIndex >= original_lines_.size()) {
            error = "Записанная SSH-мутация указывает на строку за пределами "
                    "текущего global section";
            return false;
        }
        if (original_lines_[edit.globalLineIndex] != edit.afterLine) {
            error = "Строка " +
                    std::to_string(edit.globalLineIndex) +
                    " sshd_config не соответствует зафиксированному состоянию";
            return false;
        }
    }

    // Apply from the bottom so insertions and removals keep indices valid.
    for (auto it = edits.rbegin(); it != edits.rend(); ++it) {
        if (it->beforeLine.has_value()) {
            original_lines_[it->globalLineIndex] = *it->beforeLine;
        } else {
            original_lines_.erase(
                original_lines_.begin() +
                static_cast<std::ptrdiff_t>(it->globalLineIndex));
        }
    }
    return true;
}

std::string SshConfigFileHandler::globalSectionFingerprint() const {
    std::size_t globalEnd = 0;
    if (!findFirstMatchLine(globalEnd)) {
        return {};
    }
    return fingerprintLines(original_lines_, globalEnd);
}

bool SshConfigFileHandler::setValue(const std::string& parameter,
                                    const std::string& value) {
    SshDirectiveMutationPlan plan;
    if (!planSetValue(parameter, value, plan)) {
        return false;
    }

    for (const fic::rollback::SshLineReverseEdit& edit : plan.reverseEdits) {
        if (edit.beforeLine.has_value()) {
            original_lines_[edit.globalLineIndex] = edit.afterLine;
        } else {
            original_lines_.insert(
                original_lines_.begin() +
                    static_cast<std::ptrdiff_t>(edit.globalLineIndex),
                edit.afterLine);
        }
    }

    config_[plan.parameter] = plan.appliedValue;
    canonicalNames_[plan.parameter] = plan.canonicalParameter;
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
