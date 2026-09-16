#include "modules/net/ssh/SshConfigFile.h"
#include "modules/net/ssh/SshConfigSyntax.h"

#include <fic/core/fs/AtomicFileWriter.h>

#include <algorithm>
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

namespace {

// Mutation-local projection of the target resource over an arbitrary line
// vector: every global-section line that is an active directive of the target
// keyword or exactly matches a recorded BEFORE/AFTER line, in file order,
// paired with its line index. Used by the production classification and by
// the plan-identity preflight (planner → classifier invariant).
bool buildProjectionForLines(
    const std::vector<std::string>& lines,
    const std::string& normalizedParameter,
    const std::vector<std::string>& recordedLines,
    std::vector<std::pair<std::size_t, std::string>>& projection,
    std::string& error) {
    projection.clear();
    std::size_t globalEnd = lines.size();
    for (std::size_t index = 0; index < lines.size(); ++index) {
        const SshLineParseResult parsed = parseSshConfigLine(lines[index]);
        if (!parsed.ok) {
            error = "Не удалось разобрать строку " + std::to_string(index + 1) +
                    " sshd_config";
            return false;
        }
        if (parsed.hasDirective &&
            normalizeSshKeyword(parsed.directive.keyword) == "match") {
            globalEnd = index;
            break;
        }
    }
    for (std::size_t index = 0; index < globalEnd && index < lines.size();
         ++index) {
        const std::string& line = lines[index];
        const SshLineParseResult parsed = parseSshConfigLine(line);
        if (!parsed.ok) {
            error = "Не удалось разобрать строку " + std::to_string(index + 1) +
                    " sshd_config";
            return false;
        }
        const bool keywordDirective = parsed.hasDirective &&
            normalizeSshKeyword(parsed.directive.keyword) == normalizedParameter;
        const bool recordedLine =
            std::find(recordedLines.begin(), recordedLines.end(), line) !=
            recordedLines.end();
        if (keywordDirective || recordedLine) {
            projection.emplace_back(index, line);
        }
    }
    return true;
}

// Production classification algorithm over an arbitrary line vector: the
// whole ordered mutation-local projection is compared against the recorded
// BEFORE and AFTER sequences. Both SshConfigFileHandler::
// classifyRecordedMutation() and validatePlannedRollbackIdentity() MUST use
// exactly this implementation (a planner and its rollback proof may never
// diverge).
SshMutationState classifyLinesAgainstMutation(
    const std::vector<std::string>& lines,
    const fic::rollback::UndoRestoreSshDirective& undo,
    std::vector<std::size_t>* afterLineIndices,
    std::string& error) {
    if (afterLineIndices != nullptr) {
        afterLineIndices->clear();
    }

    // The recorded mutation as whole ordered BEFORE and AFTER sequences of
    // the target resource projection. Identical line texts across
    // occurrences and before/after collisions between occurrences are
    // expressed exactly by the sequences; there is no per-occurrence
    // independent line counting.
    std::vector<std::string> beforeSequence;
    std::vector<std::string> afterSequence;
    std::vector<std::string> recordedLines;
    beforeSequence.reserve(undo.occurrences.size());
    afterSequence.reserve(undo.occurrences.size());
    for (const fic::rollback::SshDirectiveOccurrenceMutation& occurrence :
         undo.occurrences) {
        if (occurrence.beforeLine.has_value()) {
            beforeSequence.push_back(*occurrence.beforeLine);
            if (std::find(recordedLines.begin(), recordedLines.end(),
                          *occurrence.beforeLine) == recordedLines.end()) {
                recordedLines.push_back(*occurrence.beforeLine);
            }
        }
        afterSequence.push_back(occurrence.afterLine);
        if (std::find(recordedLines.begin(), recordedLines.end(),
                      occurrence.afterLine) == recordedLines.end()) {
            recordedLines.push_back(occurrence.afterLine);
        }
    }

    std::vector<std::pair<std::size_t, std::string>> projection;
    if (!buildProjectionForLines(
            lines, undo.parameter, recordedLines, projection, error)) {
        return SshMutationState::Conflict;
    }

    const auto sameSequence =
        [&projection](const std::vector<std::string>& sequence) {
            if (projection.size() != sequence.size()) {
                return false;
            }
            for (std::size_t index = 0; index < sequence.size(); ++index) {
                if (projection[index].second != sequence[index]) {
                    return false;
                }
            }
            return true;
        };

    if (sameSequence(afterSequence)) {
        if (afterLineIndices != nullptr) {
            for (const auto& entry : projection) {
                afterLineIndices->push_back(entry.first);
            }
        }
        return SshMutationState::After;
    }
    if (sameSequence(beforeSequence)) {
        return SshMutationState::Before;
    }

    if (projection.size() != beforeSequence.size() &&
        projection.size() != afterSequence.size()) {
        error = "Число вхождений директивы '" + undo.parameter +
                "' в sshd_config не соответствует записанной FIC-мутации "
                "(structural drift / untracked SSH directive occurrence)";
    } else {
        error = "Состояние директивы '" + undo.parameter +
                "' в sshd_config не соответствует ни AFTER-, ни "
                "BEFORE-состоянию FIC-мутации";
    }
    return SshMutationState::Conflict;
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
        occurrence.beforeLine = std::nullopt;
        occurrence.afterLine = newLine;
        plan.occurrences.push_back(std::move(occurrence));
        plan.occurrenceLineIndices.push_back(globalEnd);
    }

    return true;
}

SshMutationState SshConfigFileHandler::classifyRecordedMutation(
    const fic::rollback::UndoRestoreSshDirective& undo,
    std::vector<std::size_t>& afterLineIndices,
    std::string& error) const {
    // The exact same production algorithm the plan-identity preflight uses;
    // a planner and its rollback proof may never diverge.
    return classifyLinesAgainstMutation(
        original_lines_, undo, &afterLineIndices, error);
}

bool SshConfigFileHandler::validatePlannedRollbackIdentity(
    const SshDirectiveMutationPlan& plan, std::string& error) const {
    // Simulate the exact edits setValue() will perform on an in-memory copy
    // of the loaded snapshot (bottom-up, so insertions keep indices valid).
    std::vector<std::string> simulated = original_lines_;
    for (std::size_t position = plan.occurrences.size(); position-- > 0;) {
        const std::size_t index = plan.occurrenceLineIndices[position];
        const fic::rollback::SshDirectiveOccurrenceMutation& occurrence =
            plan.occurrences[position];
        if (occurrence.beforeLine.has_value()) {
            simulated[index] = occurrence.afterLine;
        } else {
            simulated.insert(
                simulated.begin() + static_cast<std::ptrdiff_t>(index),
                occurrence.afterLine);
        }
    }

    // The rollback proof must hold BEFORE the journal record and the system
    // write: the resulting state must be classified by the production
    // classifier as the recorded AFTER state. Otherwise (for example when a
    // pre-existing foreign line collides exactly with a planned
    // FIC-generated comment) the mutation would be ambiguous from the very
    // first moment and is refused here.
    fic::rollback::UndoRestoreSshDirective simulatedUndo{
        plan.parameter, plan.appliedValue, plan.occurrences};
    std::string classifyError;
    if (classifyLinesAgainstMutation(
            simulated, simulatedUndo, nullptr, classifyError) !=
        SshMutationState::After) {
        error = "Запланированная SSH-мутация '" + plan.parameter +
                "' создаёт состояние, которое rollback-классификатор не "
                "сможет однозначно сопоставить с записанным AFTER (" +
                classifyError + "); применение отменено, файл и journal "
                "не изменены";
        return false;
    }
    return true;
}

bool SshConfigFileHandler::matchRecordedMutationForRepair(
    const fic::rollback::UndoRestoreSshDirective& undo,
    std::vector<std::optional<std::size_t>>& slotLineIndices,
    bool& needsWrite,
    std::string& error) const {
    slotLineIndices.clear();
    needsWrite = false;

    std::vector<std::string> recordedLines;
    for (const fic::rollback::SshDirectiveOccurrenceMutation& occurrence :
         undo.occurrences) {
        if (occurrence.beforeLine.has_value() &&
            std::find(recordedLines.begin(), recordedLines.end(),
                      *occurrence.beforeLine) == recordedLines.end()) {
            recordedLines.push_back(*occurrence.beforeLine);
        }
        if (std::find(recordedLines.begin(), recordedLines.end(),
                      occurrence.afterLine) == recordedLines.end()) {
            recordedLines.push_back(occurrence.afterLine);
        }
    }

    std::vector<std::pair<std::size_t, std::string>> projection;
    if (!buildProjectionForLines(
            original_lines_, undo.parameter, recordedLines, projection, error)) {
        return false;
    }

    const bool singleInsertion = undo.occurrences.size() == 1 &&
        !undo.occurrences.front().beforeLine.has_value();
    if (singleInsertion) {
        // BEFORE state: the keyword is completely absent, so re-inserting
        // the recorded line reproduces exactly the recorded mutation — the
        // existing provenance fully covers it.
        if (projection.empty()) {
            slotLineIndices.push_back(std::nullopt);
            needsWrite = true;
            return true;
        }
        // AFTER state: the single inserted line is present.
        if (projection.size() == 1 &&
            projection.front().second == undo.occurrences.front().afterLine) {
            slotLineIndices.push_back(projection.front().first);
            return true;
        }
        error = "structural drift / untracked SSH directive occurrence '" +
                undo.parameter + "': повторное применение отменено, файл не "
                "изменён";
        return false;
    }

    if (projection.size() != undo.occurrences.size()) {
        error = "structural drift / untracked SSH directive occurrence '" +
                undo.parameter + "': число вхождений в sshd_config не "
                "соответствует записанной мутации; повторное применение "
                "отменено, файл не изменён";
        return false;
    }

    for (std::size_t slot = 0; slot < undo.occurrences.size(); ++slot) {
        const fic::rollback::SshDirectiveOccurrenceMutation& occurrence =
            undo.occurrences[slot];
        const std::size_t lineIndex = projection[slot].first;
        const std::string& line = projection[slot].second;
        if (line == occurrence.afterLine) {
            slotLineIndices.push_back(lineIndex);
            continue;
        }
        // A drifted slot FIC owns: only an active directive of the same
        // keyword may be repaired to the recorded AFTER representation.
        // Anything else (commented-out lines, foreign text, parse failures)
        // is unattributable drift and fails closed.
        const SshLineParseResult parsed = parseSshConfigLine(line);
        if (!parsed.ok) {
            error = "Не удалось разобрать строку " +
                    std::to_string(lineIndex + 1) + " sshd_config";
            return false;
        }
        if (occurrence.beforeLine.has_value() && parsed.hasDirective &&
            normalizeSshKeyword(parsed.directive.keyword) == undo.parameter) {
            slotLineIndices.push_back(lineIndex);
            needsWrite = true;
            continue;
        }
        error = "structural drift / untracked SSH directive occurrence '" +
                undo.parameter + "': вхождение '" + line +
                "' не может быть сопоставлено записанной мутации; повторное "
                "применение отменено, файл не изменён";
        return false;
    }
    return true;
}



bool SshConfigFileHandler::applyRecordedRepairEdits(
    const fic::rollback::UndoRestoreSshDirective& undo,
    const std::vector<std::optional<std::size_t>>& slotLineIndices,
    std::string& error) {
    if (slotLineIndices.size() != undo.occurrences.size()) {
        error = "Число индексов ремонта не соответствует записанной SSH-мутации";
        return false;
    }
    // Fail closed before changing anything: every concrete slot must either
    // be already in the AFTER state or be an active directive FIC owns.
    for (std::size_t position = 0; position < undo.occurrences.size(); ++position) {
        const std::optional<std::size_t>& index = slotLineIndices[position];
        const fic::rollback::SshDirectiveOccurrenceMutation& occurrence =
            undo.occurrences[position];
        if (!index.has_value()) {
            if (occurrence.beforeLine.has_value()) {
                error = "Слот ремонта не соответствует записанной SSH-мутации";
                return false;
            }
            continue;
        }
        if (*index >= original_lines_.size() ||
            original_lines_[*index] == occurrence.afterLine) {
            continue;
        }
        const SshLineParseResult parsed = parseSshConfigLine(original_lines_[*index]);
        if (!occurrence.beforeLine.has_value() || !parsed.ok ||
            !parsed.hasDirective) {
            error = "Строка " + std::to_string(*index) +
                    " sshd_config не может быть отремонтирована до "
                    "зафиксированного AFTER-состояния";
            return false;
        }
    }
    // Apply from the bottom so insertions keep the remaining indices valid.
    for (std::size_t position = undo.occurrences.size(); position-- > 0;) {
        const fic::rollback::SshDirectiveOccurrenceMutation& occurrence =
            undo.occurrences[position];
        const std::optional<std::size_t>& index = slotLineIndices[position];
        if (!index.has_value()) {
            std::size_t insertAt = 0;
            if (!findFirstMatchLine(insertAt)) {
                error = "Не удалось выделить global section sshd_config";
                return false;
            }
            if (insertAt > original_lines_.size()) {
                insertAt = original_lines_.size();
            }
            original_lines_.insert(
                original_lines_.begin() +
                    static_cast<std::ptrdiff_t>(insertAt),
                occurrence.afterLine);
        } else if (original_lines_[*index] != occurrence.afterLine) {
            original_lines_[*index] = occurrence.afterLine;
        }
    }
    return true;
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
