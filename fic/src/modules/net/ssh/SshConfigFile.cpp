#include "modules/net/ssh/SshConfigFile.h"
#include "modules/net/ssh/SshConfigSyntax.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <iostream>

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

    config_.clear();
    canonicalNames_.clear();
    original_lines_ = splitConfigLines(snapshot.content);
    loadSnapshot_ = std::move(snapshot);

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

    std::size_t occurrenceIndex = 0;
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
        fic::rollback::SshDirectiveOccurrenceMutation occurrence;
        occurrence.occurrenceIndex = occurrenceIndex++;
        occurrence.beforeLine = original_lines_[index];
        occurrence.afterLine = updated ? "#" + original_lines_[index] : newLine;
        updated = true;
        plan.occurrences.push_back(std::move(occurrence));
        plan.occurrenceLineIndices.push_back(index);
    }

    if (!updated) {
        // The directive does not exist yet: FIC will insert the line before
        // the first Match (or at the end of the file). Rollback removes it.
        fic::rollback::SshDirectiveOccurrenceMutation occurrence;
        occurrence.occurrenceIndex = 0;
        occurrence.beforeLine = std::nullopt;
        occurrence.afterLine = newLine;
        plan.occurrences.push_back(std::move(occurrence));
        plan.occurrenceLineIndices.push_back(globalEnd);
    }

    return true;
}

std::size_t SshConfigFileHandler::countExactLines(const std::string& text,
                                                  std::size_t globalEnd) const {
    std::size_t count = 0;
    for (std::size_t index = 0; index < globalEnd && index < original_lines_.size();
         ++index) {
        if (original_lines_[index] == text) {
            ++count;
        }
    }
    return count;
}

std::size_t SshConfigFileHandler::countParameterDirectives(
    const std::string& normalizedParameter,
    std::size_t globalEnd,
    bool& parseError) const {
    std::size_t count = 0;
    for (std::size_t index = 0; index < globalEnd && index < original_lines_.size();
         ++index) {
        const SshLineParseResult parsed = parseSshConfigLine(original_lines_[index]);
        if (!parsed.ok) {
            parseError = true;
            return 0;
        }
        if (parsed.hasDirective &&
            normalizeSshKeyword(parsed.directive.keyword) == normalizedParameter) {
            ++count;
        }
    }
    return count;
}

SshMutationState SshConfigFileHandler::classifyRecordedMutation(
    const fic::rollback::UndoRestoreSshDirective& undo,
    std::vector<std::size_t>& afterLineIndices,
    std::string& error) const {
    afterLineIndices.clear();
    std::size_t globalEnd = 0;
    if (!findFirstMatchLine(globalEnd)) {
        error = "Не удалось выделить global section sshd_config";
        return SshMutationState::Conflict;
    }

    // Mutation-local matching: only the state each recorded occurrence
    // actually controls is inspected. Unrelated global-section lines (other
    // FIC SSH policies, comments, external edits of other directives) are
    // irrelevant, and everything after the first Match is never considered.
    bool anyAfter = false;
    bool anyBefore = false;
    for (const fic::rollback::SshDirectiveOccurrenceMutation& occurrence :
         undo.occurrences) {
        const std::size_t afterCount = countExactLines(occurrence.afterLine, globalEnd);
        if (occurrence.beforeLine.has_value()) {
            const std::size_t beforeCount =
                countExactLines(*occurrence.beforeLine, globalEnd);
            if (afterCount == 1 && beforeCount == 0) {
                anyAfter = true;
            } else if (beforeCount == 1 && afterCount == 0) {
                anyBefore = true;
            } else {
                error = "Записанное состояние директивы '" + undo.parameter +
                        "' в sshd_config не соответствует ни AFTER-, ни "
                        "BEFORE-состоянию FIC-мутации";
                return SshMutationState::Conflict;
            }
        } else {
            // FIC inserted the line: exactly one copy must exist for AFTER.
            if (afterCount == 1) {
                anyAfter = true;
            } else if (afterCount == 0) {
                // Inserted line absent: BEFORE only when the directive is
                // completely absent from the global section; any other
                // representation of the keyword is external drift (Conflict).
                bool parseError = false;
                const std::size_t directiveCount = countParameterDirectives(
                    undo.parameter, globalEnd, parseError);
                if (parseError || directiveCount != 0) {
                    error = "Вставленная FIC директива '" + undo.parameter +
                            "' изменена внешним образом; откат отменён";
                    return SshMutationState::Conflict;
                }
                anyBefore = true;
            } else {
                error = "Строка вставленной FIC директивы '" + undo.parameter +
                        "' присутствует в sshd_config неоднозначно";
                return SshMutationState::Conflict;
            }
        }
    }

    if (anyAfter && anyBefore) {
        error = "Состояние директивы '" + undo.parameter +
                "' в sshd_config частично соответствует AFTER- и частично "
                "BEFORE-состоянию FIC-мутации";
        return SshMutationState::Conflict;
    }

    if (anyBefore) {
        return SshMutationState::Before;
    }

    // Every occurrence is in its AFTER state; capture the exact current line
    // index of each occurrence for the reverse application.
    for (const fic::rollback::SshDirectiveOccurrenceMutation& occurrence :
         undo.occurrences) {
        bool found = false;
        for (std::size_t index = 0;
             index < globalEnd && index < original_lines_.size(); ++index) {
            if (original_lines_[index] == occurrence.afterLine) {
                afterLineIndices.push_back(index);
                found = true;
                break;
            }
        }
        if (!found) {
            error = "Не удалось найти записанную строку FIC-мутации '" +
                    undo.parameter + "' в sshd_config";
            return SshMutationState::Conflict;
        }
    }
    return SshMutationState::After;
}

bool SshConfigFileHandler::applyRecordedReverseEdits(
    const fic::rollback::UndoRestoreSshDirective& undo,
    const std::vector<std::size_t>& afterLineIndices,
    std::string& error) {
    if (afterLineIndices.size() != undo.occurrences.size()) {
        error = "Число индексов отката не соответствует записанной SSH-мутации";
        return false;
    }
    // Fail closed before changing anything.
    for (std::size_t position = 0; position < undo.occurrences.size(); ++position) {
        const std::size_t index = afterLineIndices[position];
        if (index >= original_lines_.size() ||
            original_lines_[index] != undo.occurrences[position].afterLine) {
            error = "Строка " + std::to_string(index) +
                    " sshd_config не соответствует зафиксированному "
                    "AFTER-состоянию";
            return false;
        }
    }
    // Apply from the bottom so removals keep indices valid.
    for (std::size_t position = undo.occurrences.size(); position-- > 0;) {
        const fic::rollback::SshDirectiveOccurrenceMutation& occurrence =
            undo.occurrences[position];
        const std::size_t index = afterLineIndices[position];
        if (occurrence.beforeLine.has_value()) {
            original_lines_[index] = *occurrence.beforeLine;
        } else {
            original_lines_.erase(
                original_lines_.begin() + static_cast<std::ptrdiff_t>(index));
        }
    }
    return true;
}

bool SshConfigFileHandler::setValue(const std::string& parameter,
                                    const std::string& value) {
    SshDirectiveMutationPlan plan;
    if (!planSetValue(parameter, value, plan)) {
        return false;
    }

    // Apply the planned in-memory edits from the bottom so insertions and
    // removals keep the remaining indices valid.
    for (std::size_t position = plan.occurrences.size(); position-- > 0;) {
        const std::size_t index = plan.occurrenceLineIndices[position];
        if (plan.occurrences[position].beforeLine.has_value()) {
            original_lines_[index] = plan.occurrences[position].afterLine;
        } else {
            original_lines_.insert(
                original_lines_.begin() + static_cast<std::ptrdiff_t>(index),
                plan.occurrences[position].afterLine);
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
