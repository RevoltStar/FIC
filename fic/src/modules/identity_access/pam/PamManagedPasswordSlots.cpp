#include "modules/identity_access/pam/PamManagedPasswordSlots.h"

#include <charconv>

namespace fic::identity::pam {
namespace {

// Exact canonical neutral body of every FIC managed password slot
// (Step 1, decision C): one comment line, zero PAM rules, trailing
// newline is part of the canonical bytes.
constexpr const char* kNeutralBody =
    "# FIC managed password slot: state=neutral\n";

constexpr const char* kQualityBodyLine =
    "password requisite pam_pwquality.so retry=3";

constexpr std::uint64_t kMarkerVersion = 1;

struct ParsedMarker {
    std::uint64_t mutationId = 0;
    ManagedPasswordCapability capability =
        ManagedPasswordCapability::PasswordQuality;
    ManagedPasswordSlotRole slot = ManagedPasswordSlotRole::Quality;
};

bool parseUnsignedFull(const std::string& text, std::uint64_t& value) {
    if (text.empty()) {
        return false;
    }
    const char* first = text.data();
    const char* last = first + text.size();
    const auto result = std::from_chars(first, last, value);
    return result.ec == std::errc{} && result.ptr == last;
}

// Full decimal parse of an unsigned module-argument value. Overflow,
// empty input and trailing garbage fail; a leading '+'/'-' is rejected
// by from_chars for unsigned types, so any rejected input yields false.
bool parseUnsignedArgument(const std::string& text, unsigned& value) {
    if (text.empty()) {
        return false;
    }
    const char* first = text.data();
    const char* last = first + text.size();
    const auto result = std::from_chars(first, last, value);
    return result.ec == std::errc{} && result.ptr == last;
}

std::string tagName(const ManagedPasswordSlotSpec& spec) {
    return "FIC managed password slot " + std::string(spec.fileName);
}

const char* capabilityToken(ManagedPasswordCapability capability) {
    return capability == ManagedPasswordCapability::PasswordQuality
        ? "enable_password_quality"
        : "enable_password_history";
}

// Strict single-space field separator for marker lines. Any other
// whitespace (tabs, runs of spaces) means the line is not canonical.
bool splitOnSingleSpaces(
    const std::string& line,
    std::vector<std::string>& tokens) {
    tokens.clear();
    std::size_t start = 0;
    while (true) {
        const std::size_t space = line.find(' ', start);
        if (space == std::string::npos) {
            tokens.push_back(line.substr(start));
            break;
        }
        if (space == start) {
            return false;
        }
        tokens.push_back(line.substr(start, space - start));
        start = space + 1;
    }
    return !tokens.empty() && !tokens.back().empty();
}

// Exact token sequence:
//   #@FIC_PAM_SLOT_BEGIN version=1 capability=<cap> mutation=<id> slot=<slot>
// Key order is canonical; extra, missing or duplicated fields fail.
bool parseBeginMarker(
    const std::string& line,
    const ManagedPasswordSlotSpec& spec,
    ParsedMarker& marker,
    std::string& error) {
    std::vector<std::string> tokens;
    if (!splitOnSingleSpaces(line, tokens)) {
        error = tagName(spec) +
            ": marker line must use single-space separators";
        return false;
    }
    if (tokens.size() != 5 ||
        tokens[0] != "#@FIC_PAM_SLOT_BEGIN" ||
        tokens[1] != "version=1") {
        error = tagName(spec) + ": malformed BEGIN marker";
        return false;
    }
    if (tokens[2] !=
        "capability=" + std::string(capabilityToken(spec.capability))) {
        error = tagName(spec) + ": BEGIN marker declares wrong capability";
        return false;
    }
    if (tokens[4] != "slot=" + std::string(spec.fileName)) {
        error = tagName(spec) + ": BEGIN marker names another slot";
        return false;
    }
    if (tokens[3].rfind("mutation=", 0) != 0 ||
        !parseUnsignedFull(tokens[3].substr(9), marker.mutationId) ||
        marker.mutationId == 0) {
        error = tagName(spec) + ": invalid mutation id in BEGIN marker";
        return false;
    }
    marker.capability = spec.capability;
    marker.slot = spec.role;
    return true;
}

// Exact token sequence:
//   #@FIC_PAM_SLOT_END capability=<cap> mutation=<id> slot=<slot>
bool parseEndMarker(
    const std::string& line,
    const ManagedPasswordSlotSpec& spec,
    const ParsedMarker& begin,
    std::string& error) {
    std::vector<std::string> tokens;
    if (!splitOnSingleSpaces(line, tokens)) {
        error = tagName(spec) +
            ": marker line must use single-space separators";
        return false;
    }
    if (tokens.size() != 4 || tokens[0] != "#@FIC_PAM_SLOT_END") {
        error = tagName(spec) + ": malformed END marker";
        return false;
    }
    if (tokens[1] !=
        "capability=" + std::string(capabilityToken(spec.capability))) {
        error = tagName(spec) + ": END marker declares wrong capability";
        return false;
    }
    if (tokens[3] != "slot=" + std::string(spec.fileName)) {
        error = tagName(spec) + ": END marker names another slot";
        return false;
    }
    std::uint64_t mutationId = 0;
    if (tokens[2].rfind("mutation=", 0) != 0 ||
        !parseUnsignedFull(tokens[2].substr(9), mutationId) ||
        mutationId != begin.mutationId) {
        error = tagName(spec) + ": END marker mutation id mismatch";
        return false;
    }
    return true;
}

std::string markerBodyLine(
    ManagedPasswordSlotRole role,
    const ManagedPwhistorySlotOptions& options) {
    std::string line;
    switch (role) {
    case ManagedPasswordSlotRole::Quality:
        line = kQualityBodyLine;
        return line;
    case ManagedPasswordSlotRole::HistoryNormal:
        line = "password requisite pam_pwhistory.so use_authtok";
        break;
    case ManagedPasswordSlotRole::HistoryInitial:
        line = "password requisite pam_pwhistory.so";
        break;
    }
    // Canonical argument order (task section 34; Step 1, decision J):
    // use_authtok, remember=N, enforce_for_root.
    if (options.remember.has_value()) {
        line += " remember=" + std::to_string(*options.remember);
    }
    if (options.enforceForRoot) {
        line += " enforce_for_root";
    }
    return line;
}

// Strictly parses a whitespace-separated PAM rule body into
// facility/control/module/arguments. No comments, no continuation
// lines: a managed slot body is a single physical line.
bool parseRuleTokens(
    const std::string& line,
    std::vector<std::string>& tokens,
    std::string& error) {
    std::istringstream input(line);
    std::string token;
    while (input >> token) {
        tokens.push_back(token);
    }
    if (tokens.empty()) {
        error = "empty PAM rule";
        return false;
    }
    for (const auto& candidate : tokens) {
        if (candidate.find('#') != std::string::npos) {
            error = "comments are not allowed in a managed slot body";
            return false;
        }
    }
    return true;
}

// Parses the argument tail of a canonical pwhistory rule. Grammar is an
// exact allowlist in canonical order:
//   [use_authtok] [remember=<unsigned>] [enforce_for_root]
// Case variants, unknown arguments, duplicates and reordered arguments
// are rejected: semantic PAM equivalence is not physical FIC ownership.
bool parsePwhistoryArguments(
    ManagedPasswordSlotRole role,
    const std::vector<std::string>& arguments,
    ManagedPwhistorySlotOptions& options,
    std::string& error) {
    std::size_t index = 0;
    const bool useAuthtokAllowed =
        role == ManagedPasswordSlotRole::HistoryNormal;
    if (useAuthtokAllowed && index < arguments.size() &&
        arguments[index] == "use_authtok") {
        ++index;
    }
    if (index < arguments.size() &&
        arguments[index].rfind("remember=", 0) == 0) {
        unsigned remember = 0;
        if (!parseUnsignedArgument(arguments[index].substr(9), remember)) {
            error = "invalid or duplicate remember argument";
            return false;
        }
        options.remember = remember;
        ++index;
    }
    if (index < arguments.size() && arguments[index] == "enforce_for_root") {
        options.enforceForRoot = true;
        ++index;
    }
    if (index != arguments.size()) {
        error = "unknown, duplicate or reordered pam_pwhistory argument " +
            arguments[index];
        return false;
    }
    if (useAuthtokAllowed) {
        // history-normal: use_authtok MUST be present exactly once. The
        // canonical-order walk above can only have consumed it from the
        // first argument position, so reaching here without it means it
        // is missing or duplicated.
        if (!(arguments.size() > 0 &&
                arguments.front() == "use_authtok")) {
            error = "history-normal slot requires use_authtok exactly once";
            return false;
        }
    } else if (role == ManagedPasswordSlotRole::HistoryInitial) {
        for (const auto& argument : arguments) {
            if (argument == "use_authtok") {
                error = "history-initial slot must not use use_authtok";
                return false;
            }
        }
    }
    return true;
}

// Parses the single PAM rule line of an active body. After the typed
// validation the line must equal the canonical rendering exactly:
// reordered arguments or different whitespace would otherwise be
// accepted as owned state.
bool parseBodyLine(
    const ManagedPasswordSlotSpec& spec,
    const std::string& line,
    ManagedPwhistorySlotOptions& options,
    std::string& error) {
    std::vector<std::string> tokens;
    if (!parseRuleTokens(line, tokens, error)) {
        error = tagName(spec) + ": " + error;
        return false;
    }
    if (tokens.size() < 3) {
        error = tagName(spec) + ": PAM rule is too short";
        return false;
    }
    if (tokens[0] != "password") {
        error = tagName(spec) + ": wrong PAM facility " + tokens[0];
        return false;
    }
    if (tokens[1] != "requisite") {
        error = tagName(spec) + ": wrong PAM control " + tokens[1];
        return false;
    }
    const std::string& module = tokens[2];
    switch (spec.role) {
    case ManagedPasswordSlotRole::Quality:
        if (module != "pam_pwquality.so") {
            error = tagName(spec) + ": wrong provider module " + module;
            return false;
        }
        if (tokens.size() != 4 || tokens[3] != "retry=3") {
            error = tagName(spec) +
                ": quality slot must carry exactly retry=3";
            return false;
        }
        break;
    case ManagedPasswordSlotRole::HistoryNormal:
    case ManagedPasswordSlotRole::HistoryInitial:
        if (module != "pam_pwhistory.so") {
            error = tagName(spec) + ": wrong provider module " + module;
            return false;
        }
        if (!parsePwhistoryArguments(
                spec.role,
                std::vector<std::string>(tokens.begin() + 3, tokens.end()),
                options,
                error)) {
            error = tagName(spec) + ": " + error;
            return false;
        }
        break;
    }
    const std::string canonical = markerBodyLine(spec.role, options);
    if (line != canonical) {
        error = tagName(spec) +
            ": modified managed slot body (canonical order required)";
        return false;
    }
    return true;
}

bool parseActiveContent(
    const ManagedPasswordSlotSpec& spec,
    const std::string& content,
    ManagedPasswordSlotInspection& inspection,
    std::string& error) {
    std::vector<std::string> lines;
    {
        std::size_t start = 0;
        while (start <= content.size()) {
            const std::size_t newline = content.find('\n', start);
            if (newline == std::string::npos) {
                lines.push_back(content.substr(start));
                break;
            }
            lines.push_back(content.substr(start, newline - start));
            start = newline + 1;
        }
    }
    if (lines.back().empty()) {
        lines.pop_back();
    } else {
        error = tagName(spec) + ": missing final newline";
        return false;
    }
    if (lines.size() != 3) {
        error = tagName(spec) +
            ": active slot must contain exactly BEGIN, rule and END lines";
        return false;
    }
    ParsedMarker marker;
    if (!parseBeginMarker(lines[0], spec, marker, error)) {
        return false;
    }
    ManagedPwhistorySlotOptions options;
    if (!parseBodyLine(spec, lines[1], options, error)) {
        return false;
    }
    if (!parseEndMarker(lines[2], spec, marker, error)) {
        return false;
    }
    inspection.state = ManagedPasswordSlotState::Active;
    inspection.observedRole = spec.role;
    inspection.capability = spec.capability;
    inspection.mutationId = marker.mutationId;
    if (spec.role != ManagedPasswordSlotRole::Quality) {
        inspection.pwhistoryOptions = options;
    }
    return true;
}

} // namespace

namespace {

const std::vector<ManagedPasswordSlotSpec>& buildSlots() {
    static const std::vector<ManagedPasswordSlotSpec> slots{{
        {ManagedPasswordSlotRole::Quality,
         "fic-password-quality",
         ManagedPasswordCapability::PasswordQuality},
        {ManagedPasswordSlotRole::HistoryNormal,
         "fic-password-history",
         ManagedPasswordCapability::PasswordHistory},
        {ManagedPasswordSlotRole::HistoryInitial,
         "fic-password-history-initial",
         ManagedPasswordCapability::PasswordHistory}
    }};
    return slots;
}

} // namespace

const ManagedPasswordSlotSpec& PamManagedPasswordSlots::qualitySlot() {
    return buildSlots()[0];
}

const ManagedPasswordSlotSpec&
PamManagedPasswordSlots::historyNormalSlot() {
    return buildSlots()[1];
}

const ManagedPasswordSlotSpec&
PamManagedPasswordSlots::historyInitialSlot() {
    return buildSlots()[2];
}

const std::vector<ManagedPasswordSlotSpec>&
PamManagedPasswordSlots::slots() {
    return buildSlots();
}

std::string PamManagedPasswordSlots::capabilityName(
    ManagedPasswordCapability capability) {
    return capabilityToken(capability);
}

std::string PamManagedPasswordSlots::slotName(
    ManagedPasswordSlotRole role) {
    switch (role) {
    case ManagedPasswordSlotRole::Quality:
        return "quality";
    case ManagedPasswordSlotRole::HistoryNormal:
        return "history";
    case ManagedPasswordSlotRole::HistoryInitial:
        return "history-initial";
    }
    return {};
}

std::filesystem::path PamManagedPasswordSlots::slotFilePath(
    const ManagedPasswordSlotSpec& spec,
    const std::filesystem::path& configDirectory) {
    return configDirectory / spec.fileName;
}

std::string PamManagedPasswordSlots::neutralBody() {
    return kNeutralBody;
}

std::string PamManagedPasswordSlots::renderNeutral(
    const ManagedPasswordSlotSpec& spec) {
    (void)spec;
    return kNeutralBody;
}

std::string PamManagedPasswordSlots::renderActiveQuality(
    std::uint64_t mutationId) {
    const std::string id = std::to_string(mutationId);
    return "#@FIC_PAM_SLOT_BEGIN version=1 "
        "capability=enable_password_quality mutation=" + id +
        " slot=fic-password-quality\n" +
        kQualityBodyLine +
        "\n#@FIC_PAM_SLOT_END capability=enable_password_quality mutation=" +
        id + " slot=fic-password-quality\n";
}

std::string PamManagedPasswordSlots::renderActiveHistoryNormal(
    std::uint64_t mutationId,
    const ManagedPwhistorySlotOptions& options) {
    return renderActive(historyNormalSlot(), mutationId, options);
}

std::string PamManagedPasswordSlots::renderActiveHistoryInitial(
    std::uint64_t mutationId,
    const ManagedPwhistorySlotOptions& options) {
    return renderActive(historyInitialSlot(), mutationId, options);
}

std::string PamManagedPasswordSlots::renderActive(
    const ManagedPasswordSlotSpec& spec,
    std::uint64_t mutationId,
    const ManagedPwhistorySlotOptions& options) {
    const std::string id = std::to_string(mutationId);
    const std::string capability = capabilityToken(spec.capability);
    const std::string slot = std::string(spec.fileName);
    return "#@FIC_PAM_SLOT_BEGIN version=1 capability=" + capability +
        " mutation=" + id + " slot=" + slot + "\n" +
        markerBodyLine(spec.role, options) +
        "\n#@FIC_PAM_SLOT_END capability=" + capability +
        " mutation=" + id + " slot=" + slot + "\n";
}

bool PamManagedPasswordSlots::inspectContent(
    const ManagedPasswordSlotSpec& spec,
    const std::optional<std::string>& content,
    ManagedPasswordSlotInspection& inspection,
    std::string& error) {
    inspection = ManagedPasswordSlotInspection{};
    inspection.role = spec.role;
    inspection.capability = spec.capability;
    inspection.observedRole = spec.role;
    if (!content.has_value()) {
        // A missing slot file is Unavailable and is NEVER Neutral: PAM
        // treats a missing include target as a silent no-op, so physical
        // ownership requires the canonical file to exist.
        inspection.state = ManagedPasswordSlotState::Unavailable;
        inspection.error = tagName(spec) + ": slot file is missing";
        error = inspection.error;
        return false;
    }
    if (*content == kNeutralBody) {
        inspection.state = ManagedPasswordSlotState::Neutral;
        inspection.capability = spec.capability;
        error.clear();
        return true;
    }
    // Everything else must match the exact canonical active grammar or
    // the file is broken: no permissive "marker found somewhere" mode.
    if (!parseActiveContent(spec, *content, inspection, error)) {
        inspection = ManagedPasswordSlotInspection{};
        inspection.role = spec.role;
        inspection.capability = spec.capability;
        inspection.observedRole = spec.role;
        inspection.state = ManagedPasswordSlotState::Broken;
        inspection.error = tagName(spec) + ": " + error;
        error = inspection.error;
        return false;
    }
    error.clear();
    return true;
}

bool PamManagedPasswordSlots::inspectHistoryPair(
    const ManagedPasswordSlotInspection& normal,
    const ManagedPasswordSlotInspection& initial,
    ManagedHistoryPairInspection& pair,
    std::string& error) {
    pair = ManagedHistoryPairInspection{};
    const bool normalNeutral =
        normal.state == ManagedPasswordSlotState::Neutral;
    const bool initialNeutral =
        initial.state == ManagedPasswordSlotState::Neutral;
    const bool normalActive = normal.state == ManagedPasswordSlotState::Active;
    const bool initialActive =
        initial.state == ManagedPasswordSlotState::Active;
    if (normalNeutral && initialNeutral) {
        pair.state = ManagedHistoryPairState::Neutral;
        error.clear();
        return true;
    }
    if (normalActive && initialActive) {
        if (normal.mutationId != initial.mutationId) {
            pair.state = ManagedHistoryPairState::Broken;
            pair.error =
                "history slot mutation ids diverge: " +
                std::to_string(normal.mutationId) + " vs " +
                std::to_string(initial.mutationId);
            error = pair.error;
            return false;
        }
        if (normal.observedRole != ManagedPasswordSlotRole::HistoryNormal ||
            initial.observedRole !=
                ManagedPasswordSlotRole::HistoryInitial) {
            pair.state = ManagedHistoryPairState::Broken;
            pair.error = "history slot roles diverge";
            error = pair.error;
            return false;
        }
        const auto& normalOptions = normal.pwhistoryOptions;
        const auto& initialOptions = initial.pwhistoryOptions;
        if (!normalOptions.has_value() || !initialOptions.has_value() ||
            !(*normalOptions == *initialOptions)) {
            pair.state = ManagedHistoryPairState::Broken;
            pair.error =
                "history slot managed options diverge between normal and "
                "initial slots";
            error = pair.error;
            return false;
        }
        pair.state = ManagedHistoryPairState::Active;
        pair.mutationId = normal.mutationId;
        pair.options = normalOptions;
        error.clear();
        return true;
    }
    pair.state = ManagedHistoryPairState::Broken;
    if (normal.state == ManagedPasswordSlotState::Unavailable ||
        initial.state == ManagedPasswordSlotState::Unavailable) {
        pair.error =
            "history pair incomplete: one of the history slot files is "
            "missing (missing is never neutral)";
    } else {
        pair.error =
            "history pair is inconsistent: slots must be both neutral or "
            "both active";
    }
    error = pair.error;
    return false;
}

} // namespace fic::identity::pam
