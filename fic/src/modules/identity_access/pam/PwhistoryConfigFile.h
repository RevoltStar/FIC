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

class PwhistoryConfigEvaluator {
public:
    // Evaluates the REAL config topology (primary file first-match parse,
    // then the PAM argv of one provider rule). Fails closed on a missing
    // primary (vendor fallback cannot be proven), on malformed KNOWN
    // directives and on unknown PAM arguments (stricter than the upstream
    // silent-ignore, per the FIC ambiguous-input policy).
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
