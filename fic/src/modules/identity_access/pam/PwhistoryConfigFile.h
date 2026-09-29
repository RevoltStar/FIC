#ifndef FIC_IDENTITY_ACCESS_PAM_PWHISTORY_CONFIG_FILE_H
#define FIC_IDENTITY_ACCESS_PAM_PWHISTORY_CONFIG_FILE_H

#include "platform/PlatformProfile.h"

#include <filesystem>
#include <string>

namespace fic::identity::pam {

// Step 7D: effective state of pam_pwhistory for ONE PAM stack invocation,
// modeled after the upstream Linux-PAM sources:
//
//   modules/pam_pwhistory/pam_pwhistory.c:
//     options.remember = 10; options.tries = 1;   (defaults, BEFORE config)
//     parse_config_file(...)                       (config file)
//     parse_option(...) per argv                   (argv LAST-WINS)
//
//   modules/pam_pwhistory/pwhistory_config.c:
//     conf= argv selects the config file; without it the default
//     /etc/security/pwhistory.conf is used; an ENOENT default file falls
//     back to the VENDOR copy (a missing primary is therefore NEVER an
//     empty config). Keys are read independently through
//     pam_modutil_search_key(), so for EVERY key the FIRST occurrence in
//     the file wins. "debug" and "enforce_for_root" are PRESENCE flags in
//     the config file (any first matching key enables them, the value is
//     ignored upstream); "remember"/"retry" are unsigned integers; "file"
//     requires an absolute path (a relative value is ignored upstream and
//     the default opasswd path stays effective).
//
//   libpam/pam_modutil_searchkey.c (pam_modutil_search_key):
//     top-to-bottom line scan; '#' truncates the rest of the line;
//     leading whitespace is skipped; empty lines are skipped; the key is
//     the first token delimited by space/tab/'='; the comparison is
//     CASE-INSENSITIVE (strcasecmp); the search STOPS at the first
//     matching key (first-match, not last-match).
struct PwhistoryEffectiveState {
    // Upstream defaults (pam_pwhistory.c): remember=10, retry=1.
    int remember = 10;
    int retry = 1;
    bool enforceForRoot = false;
    bool debug = false;
    // Effective history file; empty means the built-in opasswd default.
    std::string file;

    bool managedValue(const std::string& option,
                      std::string& value,
                      std::string& error) const;
};

// Result of scanning ONE PAM rule argv for a pwhistory presence flag
// (debug / enforce_for_root) under the upstream case-insensitive
// WHOLE-TOKEN semantics (strcasecmp over the whole token).
struct PwhistoryFlagArgumentScan {
    // Number of exact case-insensitive whole-token occurrences of the
    // flag ("debug", "EnFoRcE_FoR_RoOt", ...).
    std::size_t occurrences = 0;
    // RAW first occurrence token (for diagnostics).
    std::string firstArgument;
    // First token that NAMES the flag but carries a value ("debug=x",
    // "EnFoRcE_FoR_RoOt="); empty when every token naming the flag is a
    // valid valueless occurrence.
    std::string valuedArgument;
};

class PwhistoryConfigEvaluator {
public:
    // FIC strict duplicate-argv contract (Step 7D follow-up): every KNOWN
    // pam_pwhistory option (try_first_pass / use_first_pass / use_authtok /
    // authtok_type= / debug / enforce_for_root / remember= / retry= /
    // file=) may occur AT MOST ONCE per one PAM rule invocation. Option
    // NAMES are matched case-insensitively like upstream, so
    // "remember=10 remember=20", "remember=10 REMEMBER=20" and the
    // identical duplicate "remember=10 REMEMBER=10" all fail closed —
    // the upstream last-wins effective result is never treated as a
    // proof of unambiguity. Unknown argv tokens fail closed as well.
    //
    // Whole-token presence flags (Step 7D semantic cleanup): upstream
    // matches "debug" and "enforce_for_root" with strcasecmp over the
    // WHOLE token, so they are valid ONLY as valueless tokens
    // (case-insensitive: "debug", "DEBUG", "EnFoRcE_FoR_RoOt", ...).
    // ANY valued form, including an empty assignment ("debug=x",
    // "DEBUG=x", "debug=", "enforce_for_root=", "enforce_for_root=yes"),
    // is rejected fail-closed by this validation with a dedicated
    // diagnostic BEFORE any state evaluation.
    //
    // The "conf=" selector is NOT part of this case-insensitive option
    // contract: upstream selects the config file through the CASE-
    // SENSITIVE pam_str_skip_prefix("conf="), so conf= uniqueness stays
    // governed by the external config contract
    // (PamProviderInspector::verifyExternalConfigContract) and an
    // uppercase "CONF=..." is an unknown pwhistory argument, never a
    // second selector.
    static bool validatePamArguments(
        const std::vector<std::string>& arguments,
        const std::filesystem::path& source,
        std::size_t line,
        std::string& error);

    // Typed pwhistory flag scan (Step 7D semantic cleanup): classifies the
    // argv tokens of ONE PAM rule against a pwhistory presence flag
    // (debug / enforce_for_root) using the SAME case-insensitive
    // whole-token semantics as validatePamArguments /
    // evaluateInvocation. The typed provider preflight
    // (pwhistoryCanApplyFlag) uses it to see case-variant flag overrides
    // ("EnFoRcE_FoR_RoOt") that the generic case-sensitive argv helper
    // cannot observe. Unknown tokens are IGNORED here: the unknown-argv
    // rejection is owned by validatePamArguments.
    // The flag parameter is matched case-insensitively against the
    // known flag names; an unknown flag name yields an empty scan.
    static void scanFlagArguments(
        const std::vector<std::string>& arguments,
        const std::string& flag,
        PwhistoryFlagArgumentScan& scan);

    // Evaluates the REAL config topology (primary file first-match parse,
    // then the PAM argv of one provider rule). Fails closed on a missing
    // primary (vendor fallback cannot be proven), on malformed KNOWN
    // directives and on unknown PAM arguments (stricter than the upstream
    // silent-ignore, per the FIC ambiguous-input policy). The strict
    // duplicate-argv validation (validatePamArguments) runs BEFORE any
    // state evaluation, so the evaluator stays deterministic and never
    // applies a partially evaluated ambiguous argv set.
    static bool evaluateInvocation(
        const std::vector<std::string>& arguments,
        const std::filesystem::path& source,
        std::size_t line,
        const fic::platform::PamProviderConfigTopology& topology,
        PwhistoryEffectiveState& state,
        std::string& error);

    // Prospective preflight model (Step 7D §10): evaluates the state as it
    // WOULD be after FIC prepends its managed BOF entry "<option> =
    // <expectedValue>" to the primary. Under the upstream first-match
    // semantics the FIC BOF entry outranks every later foreign assignment
    // of the same key, so current foreign values are NOT a rejection
    // reason — only PAM argv overrides and unsafe/broken inputs are.
    static bool evaluateInvocationWithManagedOption(
        const std::vector<std::string>& arguments,
        const std::filesystem::path& source,
        std::size_t line,
        const fic::platform::PamProviderConfigTopology& topology,
        const std::string& option,
        const std::string& expectedValue,
        PwhistoryEffectiveState& state,
        std::string& error);
};

} // namespace fic::identity::pam

#endif // FIC_IDENTITY_ACCESS_PAM_PWHISTORY_CONFIG_FILE_H
