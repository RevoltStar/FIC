#include "modules/identity_access/pam/PwhistoryConfigFile.h"

#include <fic/core/fs/TrustedFileReader.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <set>
#include <sstream>
#include <string_view>

#include <sys/stat.h>
#include <unistd.h>

namespace fic::identity::pam {
namespace {

// Line length bound: PAM getline() reads unbounded lines, but an
// unreasonably long line in a security configuration is malformed input —
// the evaluator fails closed on it (conservative bound, not an upstream
// limit).
constexpr std::size_t MaximumPwhistoryLineLength = 4096;

std::string lowercaseCopy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char character) {
                       return static_cast<char>(std::tolower(character));
                   });
    return value;
}

bool parseUnsignedInteger(const std::string& value, int& parsed)
{
    errno = 0;
    char* end = nullptr;
    const long candidate = std::strtol(value.c_str(), &end, 10);
    if (errno != 0 || value.empty() || end == value.c_str() || *end != '\0' ||
        candidate < 0 || candidate > INT_MAX) {
        return false;
    }
    parsed = static_cast<int>(candidate);
    return true;
}

// ASCII-only case-insensitive comparison helpers. Upstream Linux-PAM
// matches PAM module option NAMES case-insensitively (strcasecmp /
// pam_str_skip_icase_prefix); the comparison is deliberately ASCII-only —
// no locale-dependent semantics beyond the plain ASCII PAM option
// contract.
char asciiLower(char character)
{
    return character >= 'A' && character <= 'Z'
        ? static_cast<char>(character - 'A' + 'a')
        : character;
}

bool asciiEqualsIgnoreCase(std::string_view left, std::string_view right)
{
    if (left.size() != right.size()) {
        return false;
    }
    for (std::size_t index = 0; index < left.size(); ++index) {
        if (asciiLower(left[index]) != asciiLower(right[index])) {
            return false;
        }
    }
    return true;
}

bool asciiStartsWithIgnoreCase(std::string_view value,
                               std::string_view prefix)
{
    if (value.size() < prefix.size()) {
        return false;
    }
    return asciiEqualsIgnoreCase(value.substr(0, prefix.size()), prefix);
}

bool applyPamArguments(const std::vector<std::string>& arguments,
                       const std::filesystem::path& source,
                       std::size_t line,
                       PwhistoryEffectiveState& state,
                       std::string& error);

// Validity of ONE classified argv token beyond its semantic kind:
//   * Valid — the token matches the upstream syntax of its kind;
//   * MalformedKnown — the token NAMES a known option but with a syntax
//     that upstream would NOT accept for that kind (the presence flags
//     debug / enforce_for_root are whole-token options upstream:
//     strcasecmp(argv, "debug"); any valued form, including an EMPTY
//     assignment "debug=", is a different token and is rejected
//     fail-closed instead of being silently applied as the flag).
enum class PwhistoryPamArgumentValidity {
    Valid,
    MalformedKnown
};

bool evaluateTopology(const fic::platform::PamProviderConfigTopology& topology,
                      PwhistoryEffectiveState& state,
                      std::string& error,
                      const std::string* managedSkipKey = nullptr);

// One config-file line under pam_modutil_search_key semantics. Returns:
//   * true with matchedKey empty for comments/blank lines;
//   * true with matchedKey set when the line carries an ACTIVE directive
//     (the raw key casing is NOT canonicalized — foreign bytes stay
//     foreign; the case-insensitive comparison happens on a lowercase
//     copy);
//   * false for a malformed active directive (fail closed).
bool parseConfigLine(const std::string& raw,
                     std::string& matchedKey,
                     std::string& value,
                     std::string& error)
{
    matchedKey.clear();
    value.clear();

    std::string line = raw;
    // Upstream: strchr(cp, '#') truncates the rest of the line.
    const std::size_t comment = line.find('#');
    if (comment != std::string::npos) {
        line.erase(comment);
    }
    // Upstream: skip leading spaces/tabs; skip empty lines.
    std::size_t start = 0;
    while (start < line.size() &&
           std::isspace(static_cast<unsigned char>(line[start])) != 0) {
        ++start;
    }
    if (start == line.size()) {
        return true;
    }

    // Upstream: strsep(&cp, " \t=") — the key ends at the FIRST space,
    // tab or '='.
    std::size_t keyEnd = start;
    while (keyEnd < line.size() &&
           std::isspace(static_cast<unsigned char>(line[keyEnd])) == 0 &&
           line[keyEnd] != '=') {
        ++keyEnd;
    }
    const std::string key =
        lowercaseCopy(line.substr(start, keyEnd - start));
    if (key.empty()) {
        error = "malformed pwhistory directive";
        return false;
    }

    // Upstream: skip spaces/tabs/'=' separators after the key token.
    std::size_t valueStart = keyEnd;
    while (valueStart < line.size() &&
           (std::isspace(static_cast<unsigned char>(line[valueStart])) != 0 ||
            line[valueStart] == '=')) {
        ++valueStart;
    }
    // Trailing whitespace is format noise (upstream %u/strtol tolerate
    // it); it is not part of the value.
    std::size_t valueEnd = line.size();
    while (valueEnd > valueStart &&
           std::isspace(static_cast<unsigned char>(line[valueEnd - 1])) != 0) {
        --valueEnd;
    }

    matchedKey = key;
    value = line.substr(valueStart, valueEnd - valueStart);
    return true;
}

// Applies one ACTIVE config directive (first match per key wins — the
// caller tracks which keys were already set).
bool applyConfigParameter(const std::string& key,
                          const std::string& value,
                          PwhistoryEffectiveState& state,
                          std::string& error)
{
    if (key == "debug") {
        // Presence flag upstream (value ignored).
        state.debug = true;
        return true;
    }
    if (key == "enforce_for_root") {
        // Presence flag upstream (value ignored — pwhistory_config.c
        // enables it whenever the key search returns a value).
        state.enforceForRoot = true;
        return true;
    }
    if (key == "remember" || key == "retry") {
        int parsed = 0;
        if (!parseUnsignedInteger(value, parsed)) {
            error = "invalid unsigned integer value for pwhistory option " +
                key;
            return false;
        }
        if (key == "remember") {
            state.remember = parsed;
        } else {
            state.retry = parsed;
        }
        return true;
    }
    if (key == "file") {
        // Upstream: a relative path is logged and IGNORED (the built-in
        // opasswd default stays effective) — mirror that effective
        // behavior instead of failing the whole evaluation.
        if (!value.empty() && value.front() == '/') {
            state.file = value;
        }
        return true;
    }
    // Unknown keys are inert for pam_pwhistory: it reads only the known
    // keys through pam_modutil_search_key and never fails on others.
    return true;
}

// PAM argv application (parse_option order: argv is parsed AFTER the
// config file, so argv values OVERRIDE config values). The argv set has
// already passed the strict duplicate/uniqueness validation
// (validatePwhistoryPamArguments) BEFORE any state mutation, so the
// upstream last-wins semantics are modeled here only for the validated
// single-occurrence-per-kind set.
bool applyPamArguments(const std::vector<std::string>& arguments,
                       const std::filesystem::path& source,
                       std::size_t line,
                       PwhistoryEffectiveState& state,
                       std::string& error)
{
    for (const auto& argument : arguments) {
        // Upstream pam_pwhistory.c: strcasecmp(argv, "try_first_pass") /
        // strcasecmp(argv, "use_first_pass") / strcasecmp(argv,
        // "use_authtok") — the WHOLE argument token is compared
        // case-insensitively, so a valued variant ("use_authtok=x") is
        // NOT accepted here and stays a fail-closed unknown argument.
        if (asciiEqualsIgnoreCase(argument, "try_first_pass") ||
            asciiEqualsIgnoreCase(argument, "use_first_pass") ||
            asciiEqualsIgnoreCase(argument, "use_authtok")) {
            continue;
        }
        // Upstream: pam_str_skip_icase_prefix(argv, "authtok_type=") —
        // case-insensitive value prefix.
        if (asciiStartsWithIgnoreCase(argument, "authtok_type=")) {
            continue;
        }
        // Upstream pwhistory_config.c selection is CASE-SENSITIVE:
        // pam_str_skip_prefix(argv[i], "conf=") — NOT the icase variant.
        // "CONF=..." is therefore never a config selector here; it falls
        // through and fails closed as an unknown PAM argument.
        if (argument.compare(0, 5, "conf=") == 0) {
            // The config FILE selection is a separate external contract
            // (verifyExternalConfigContract); the evaluator itself always
            // evaluates the capability-controlled topology.
            continue;
        }
        const std::size_t equals = argument.find('=');
        // Upstream pam_pwhistory.c: strcasecmp(argv, "debug") /
        // strcasecmp(argv, "enforce_for_root") — the presence flags are
        // WHOLE-TOKEN options compared case-insensitively. A valued form
        // ("debug=x", "DEBUG=x", "enforce_for_root=", ...) is NOT the
        // flag; the strict argv validation
        // (validatePwhistoryPamArguments) has already rejected every such
        // token before this application pass, and any valued token that
        // still reaches this point fails closed as an unknown argument
        // below.
        if (asciiEqualsIgnoreCase(argument, "debug")) {
            state.debug = true;
            continue;
        }
        if (asciiEqualsIgnoreCase(argument, "enforce_for_root")) {
            state.enforceForRoot = true;
            continue;
        }
        // Assignment-like options are matched CASE-INSENSITIVELY on the
        // lowercase name copy, mirroring the upstream
        // pam_str_skip_icase_prefix parser for remember=/retry=/file=.
        // The compare keeps the RAW name for diagnostics.
        const std::string name = lowercaseCopy(
            equals == std::string::npos ? argument
                                        : argument.substr(0, equals));
        const std::string value = equals == std::string::npos
            ? std::string{}
            : argument.substr(equals + 1);
        if (name == "remember" || name == "retry") {
            int parsed = 0;
            if (!parseUnsignedInteger(value, parsed)) {
                error = source.string() + ":" + std::to_string(line) +
                    ": invalid pwhistory argument " + argument;
                return false;
            }
            if (name == "remember") {
                // Upstream clamps the argv remember into [0, 400].
                state.remember = std::min(std::max(parsed, 0), 400);
            } else {
                // Upstream clamps a negative retry back to 1.
                state.retry = std::max(parsed, 1);
            }
            continue;
        }
        if (name == "file") {
            if (value.empty() || value.front() != '/') {
                error = source.string() + ":" + std::to_string(line) +
                    ": pwhistory file path should be absolute: " + argument;
                return false;
            }
            state.file = value;
            continue;
        }
        // Unknown module arguments would be silently ignored upstream;
        // FIC fails closed (ambiguous PAM stack input).
        error = source.string() + ":" + std::to_string(line) +
            ": unknown pwhistory PAM argument " + argument;
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Step 7D follow-up: strict duplicate-argv contract.
//
// Upstream pam_pwhistory.c applies duplicate argv keys last-wins
// (parse_option per token); the effective result of "remember=10
// remember=20" is 20. FIC rejects such an invocation BEFORE any state
// evaluation instead: every KNOWN pam_pwhistory option is classified
// into ONE semantic kind, and each kind may occur at most once per PAM
// rule invocation. Option NAMES are matched case-insensitively like
// upstream, so case variants and identical duplicates of the same kind
// fail closed alike — an identical effective result does not make the
// input unambiguous.
//
// The "conf=" selector is NOT part of this case-insensitive option
// contract: upstream selects the config file through the CASE-SENSITIVE
// pam_str_skip_prefix("conf="), so conf= uniqueness stays governed by
// the external config contract (verifyExternalConfigContract), and an
// uppercase "CONF=..." is an unknown pwhistory argument — never a
// second selector.
// ---------------------------------------------------------------------------
enum class PwhistoryPamArgumentKind {
    TryFirstPass,
    UseFirstPass,
    UseAuthtok,
    AuthtokType,
    Debug,
    EnforceForRoot,
    Remember,
    Retry,
    File,
    Conf,
    Unknown
};

const char* pwhistoryPamArgumentKindName(PwhistoryPamArgumentKind kind)
{
    switch (kind) {
    case PwhistoryPamArgumentKind::TryFirstPass:
        return "try_first_pass";
    case PwhistoryPamArgumentKind::UseFirstPass:
        return "use_first_pass";
    case PwhistoryPamArgumentKind::UseAuthtok:
        return "use_authtok";
    case PwhistoryPamArgumentKind::AuthtokType:
        return "authtok_type";
    case PwhistoryPamArgumentKind::Debug:
        return "debug";
    case PwhistoryPamArgumentKind::EnforceForRoot:
        return "enforce_for_root";
    case PwhistoryPamArgumentKind::Remember:
        return "remember";
    case PwhistoryPamArgumentKind::Retry:
        return "retry";
    case PwhistoryPamArgumentKind::File:
        return "file";
    case PwhistoryPamArgumentKind::Conf:
        return "conf";
    case PwhistoryPamArgumentKind::Unknown:
        break;
    }
    return "unknown";
}

// Classifies ONE raw argv token into its semantic kind and validity. The
// known-kind set mirrors the upstream pam_pwhistory.c / pwhistory_config.c
// option parser:
//   * whole-token options: try_first_pass / use_first_pass /
//     use_authtok / debug / enforce_for_root (strcasecmp — icase);
//   * value-prefixed options: authtok_type= / remember= / retry= /
//     file= (pam_str_skip_icase_prefix — icase);
//   * conf= (pam_str_skip_prefix — CASE-SENSITIVE).
// The presence flags debug / enforce_for_root are WHOLE-TOKEN options
// upstream: only the exact (case-insensitive) token is a valid flag
// occurrence. A valued form ("debug=x", "enforce_for_root=", ...) names
// the flag kind but is reported as MalformedKnown so the uniqueness
// contract rejects it fail-closed with a dedicated diagnostic BEFORE any
// state evaluation — it must never be applied as an enabled flag.
// Valueless remember/retry/file tokens likewise stay inside their kind
// (the application pass rejects them as invalid values), so a SINGLE such
// token keeps its original diagnostic and only a genuine DUPLICATE is
// reported by the uniqueness contract first.
bool classifyPwhistoryPamArgument(const std::string& argument,
                                  PwhistoryPamArgumentKind& kind,
                                  PwhistoryPamArgumentValidity& validity)
{
    validity = PwhistoryPamArgumentValidity::Valid;
    if (asciiEqualsIgnoreCase(argument, "try_first_pass")) {
        kind = PwhistoryPamArgumentKind::TryFirstPass;
        return true;
    }
    if (asciiEqualsIgnoreCase(argument, "use_first_pass")) {
        kind = PwhistoryPamArgumentKind::UseFirstPass;
        return true;
    }
    if (asciiEqualsIgnoreCase(argument, "use_authtok")) {
        kind = PwhistoryPamArgumentKind::UseAuthtok;
        return true;
    }
    if (asciiStartsWithIgnoreCase(argument, "authtok_type=")) {
        kind = PwhistoryPamArgumentKind::AuthtokType;
        return true;
    }
    if (asciiEqualsIgnoreCase(argument, "debug")) {
        kind = PwhistoryPamArgumentKind::Debug;
        return true;
    }
    if (asciiStartsWithIgnoreCase(argument, "debug=")) {
        kind = PwhistoryPamArgumentKind::Debug;
        validity = PwhistoryPamArgumentValidity::MalformedKnown;
        return true;
    }
    if (asciiEqualsIgnoreCase(argument, "enforce_for_root")) {
        kind = PwhistoryPamArgumentKind::EnforceForRoot;
        return true;
    }
    if (asciiStartsWithIgnoreCase(argument, "enforce_for_root=")) {
        kind = PwhistoryPamArgumentKind::EnforceForRoot;
        validity = PwhistoryPamArgumentValidity::MalformedKnown;
        return true;
    }
    if (asciiStartsWithIgnoreCase(argument, "remember=") ||
        asciiEqualsIgnoreCase(argument, "remember")) {
        kind = PwhistoryPamArgumentKind::Remember;
        return true;
    }
    if (asciiStartsWithIgnoreCase(argument, "retry=") ||
        asciiEqualsIgnoreCase(argument, "retry")) {
        kind = PwhistoryPamArgumentKind::Retry;
        return true;
    }
    if (asciiStartsWithIgnoreCase(argument, "file=") ||
        asciiEqualsIgnoreCase(argument, "file")) {
        kind = PwhistoryPamArgumentKind::File;
        return true;
    }
    // CASE-SENSITIVE upstream config selector (pam_str_skip_prefix):
    // "CONF=..." is NOT a conf= token; it stays unknown and fails
    // closed below.
    if (argument.compare(0, 5, "conf=") == 0) {
        kind = PwhistoryPamArgumentKind::Conf;
        return true;
    }
    return false;
}

bool validatePwhistoryPamArguments(
    const std::vector<std::string>& arguments,
    const std::filesystem::path& source,
    std::size_t line,
    std::string& error)
{
    std::set<PwhistoryPamArgumentKind> seenKinds;
    for (const auto& argument : arguments) {
        PwhistoryPamArgumentKind kind = PwhistoryPamArgumentKind::Unknown;
        PwhistoryPamArgumentValidity validity =
            PwhistoryPamArgumentValidity::Valid;
        if (!classifyPwhistoryPamArgument(argument, kind, validity)) {
            // Unknown tokens keep the application-pass diagnostic (the
            // evaluator would fail closed with the same message).
            error = source.string() + ":" + std::to_string(line) +
                ": unknown pwhistory PAM argument " + argument;
            return false;
        }
        // conf= uniqueness is a SEPARATE case-sensitive external-config
        // contract (verifyExternalConfigContract), not part of this
        // case-insensitive pwhistory option contract.
        if (kind == PwhistoryPamArgumentKind::Conf) {
            continue;
        }
        // A token that NAMES a known option but carries a value forbidden
        // by the upstream whole-token flag syntax (debug=x, DEBUG=x,
        // debug=, enforce_for_root=, EnFoRcE_FoR_RoOt=yes, ...) is
        // rejected fail-closed BEFORE the duplicate check and BEFORE any
        // state evaluation — it must never be applied as an enabled flag.
        if (validity == PwhistoryPamArgumentValidity::MalformedKnown) {
            error = source.string() + ":" + std::to_string(line) +
                ": pwhistory PAM flag " + argument +
                " must not have a value";
            return false;
        }
        if (!seenKinds.insert(kind).second) {
            error = source.string() + ":" + std::to_string(line) +
                ": duplicate pwhistory PAM argument " +
                pwhistoryPamArgumentKindName(kind);
            return false;
        }
    }
    error.clear();
    return true;
}

bool evaluateFile(const std::filesystem::path& path,
                  PwhistoryEffectiveState& state,
                  std::string& error,
                  // Managed BOF override (prospective FIC entry): the key
                  // is skipped everywhere in the existing file because
                  // the FIC first-match entry will precede all of it.
                  const std::string* managedSkipKey = nullptr)
{
    fic::core::TrustedFileReadOptions options;
    options.expectedOwner = ::geteuid();
    options.forbiddenMode = S_IWGRP | S_IWOTH;
    options.requiredAnyMode = S_IRUSR | S_IRGRP | S_IROTH;
    std::string content;
    int systemError = 0;
    if (!fic::core::readTrustedFile(
            path, options, content, error, nullptr, {}, &systemError)) {
        if (systemError == ENOENT) {
            error = "pwhistory configuration file does not exist: " +
                path.string();
        }
        return false;
    }
    std::istringstream input(content);
    std::string line;
    std::size_t lineNumber = 0;
    // pam_modutil_search_key reads EVERY key independently top-to-bottom
    // and stops at the FIRST case-insensitive match: later occurrences of
    // an already-set key are inert (first-match, never last-match).
    std::set<std::string> seenKeys;
    while (std::getline(input, line)) {
        ++lineNumber;
        if (line.size() >= MaximumPwhistoryLineLength) {
            error = path.string() + ":" + std::to_string(lineNumber) +
                ": pwhistory configuration line is too long";
            return false;
        }
        std::string key;
        std::string value;
        std::string lineError;
        if (!parseConfigLine(line, key, value, lineError)) {
            error = path.string() + ":" + std::to_string(lineNumber) +
                ": " + lineError;
            return false;
        }
        if (key.empty()) {
            continue;
        }
        if (managedSkipKey != nullptr && key == *managedSkipKey) {
            continue;
        }
        if (seenKeys.count(key) != 0) {
            continue;
        }
        if (!applyConfigParameter(key, value, state, lineError)) {
            error = path.string() + ":" + std::to_string(lineNumber) +
                ": " + lineError;
            return false;
        }
        seenKeys.insert(key);
    }
    return true;
}

bool evaluateTopology(const fic::platform::PamProviderConfigTopology& topology,
                      PwhistoryEffectiveState& state,
                      std::string& error,
                      const std::string* managedSkipKey)
{
    if (!topology.primaryPath.has_value()) {
        // Defaults-only evaluation (upstream: an explicitly selected conf=
        // file that does not exist yields the built-in defaults). The
        // caller owns the missing-default-primary vendor-fallback policy.
        return true;
    }
    // A MISSING default primary is NOT an empty config: upstream falls
    // back to the VENDOR pwhistory.conf, which FIC cannot prove. Fail
    // closed (the absent-container decision of the executor refuses
    // creation for the same reason).
    return evaluateFile(
        *topology.primaryPath, state, error, managedSkipKey);
}

} // namespace

bool PwhistoryConfigEvaluator::validatePamArguments(
    const std::vector<std::string>& arguments,
    const std::filesystem::path& source,
    std::size_t line,
    std::string& error)
{
    return validatePwhistoryPamArguments(arguments, source, line, error);
}

namespace {

bool pwhistoryFlagKindFor(const std::string& flag,
                          PwhistoryPamArgumentKind& kind)
{
    if (asciiEqualsIgnoreCase(flag, "debug")) {
        kind = PwhistoryPamArgumentKind::Debug;
        return true;
    }
    if (asciiEqualsIgnoreCase(flag, "enforce_for_root")) {
        kind = PwhistoryPamArgumentKind::EnforceForRoot;
        return true;
    }
    return false;
}

} // namespace

void PwhistoryConfigEvaluator::scanFlagArguments(
    const std::vector<std::string>& arguments,
    const std::string& flag,
    PwhistoryFlagArgumentScan& scan)
{
    scan = PwhistoryFlagArgumentScan{};
    PwhistoryPamArgumentKind flagKind = PwhistoryPamArgumentKind::Unknown;
    if (!pwhistoryFlagKindFor(flag, flagKind)) {
        return;
    }
    for (const auto& argument : arguments) {
        PwhistoryPamArgumentKind kind = PwhistoryPamArgumentKind::Unknown;
        PwhistoryPamArgumentValidity validity =
            PwhistoryPamArgumentValidity::Valid;
        if (!classifyPwhistoryPamArgument(argument, kind, validity) ||
            kind != flagKind) {
            // Unknown tokens and other options are not this flag's
            // business (unknown-argv rejection belongs to
            // validatePamArguments).
            continue;
        }
        if (validity == PwhistoryPamArgumentValidity::MalformedKnown) {
            // A valued form names the flag but is NOT a flag occurrence;
            // it is reported separately so the preflight rejects it
            // fail-closed.
            if (scan.valuedArgument.empty()) {
                scan.valuedArgument = argument;
            }
            continue;
        }
        if (scan.occurrences == 0) {
            scan.firstArgument = argument;
        }
        ++scan.occurrences;
    }
}

bool PwhistoryEffectiveState::managedValue(const std::string& option,
                                           std::string& value,
                                           std::string& error) const
{
    if (option == "remember") {
        value = std::to_string(remember);
        return true;
    }
    if (option == "retry") {
        value = std::to_string(retry);
        return true;
    }
    error = "unsupported managed pwhistory option " + option;
    return false;
}

bool PwhistoryConfigEvaluator::evaluateInvocation(
    const std::vector<std::string>& arguments,
    const std::filesystem::path& source,
    std::size_t line,
    const fic::platform::PamProviderConfigTopology& topology,
    PwhistoryEffectiveState& state,
    std::string& error)
{
    error.clear();
    state = PwhistoryEffectiveState{};
    // The strict duplicate/uniqueness argv contract runs BEFORE any
    // state evaluation: an ambiguous argv set is rejected as a whole
    // instead of being partially applied (fail closed, deterministic).
    if (!validatePwhistoryPamArguments(arguments, source, line, error)) {
        return false;
    }
    if (!evaluateTopology(topology, state, error)) {
        return false;
    }
    return applyPamArguments(arguments, source, line, state, error);
}

bool PwhistoryConfigEvaluator::evaluateInvocationWithManagedOption(
    const std::vector<std::string>& arguments,
    const std::filesystem::path& source,
    std::size_t line,
    const fic::platform::PamProviderConfigTopology& topology,
    const std::string& option,
    const std::string& expectedValue,
    PwhistoryEffectiveState& state,
    std::string& error)
{
    error.clear();
    state = PwhistoryEffectiveState{};
    // Same strict argv contract BEFORE the prospective BOF state is
    // evaluated: a duplicate argv (e.g. "remember=10 REMEMBER=20" under
    // a managed remember option) fails closed instead of being silently
    // modeled as the upstream last-wins effective value.
    if (!validatePwhistoryPamArguments(arguments, source, line, error)) {
        return false;
    }
    // BOF placement model: the managed entry is evaluated FIRST (it will
    // be the first matching key in the file), and every foreign
    // occurrence of the managed key in the existing file is overridden
    // (skipped) by it.
    const std::string managedSkipKey = lowercaseCopy(option);
    if (!applyConfigParameter(
            managedSkipKey, expectedValue, state, error)) {
        return false;
    }
    if (!evaluateTopology(topology, state, error, &managedSkipKey)) {
        return false;
    }
    return applyPamArguments(arguments, source, line, state, error);
}

} // namespace fic::identity::pam

