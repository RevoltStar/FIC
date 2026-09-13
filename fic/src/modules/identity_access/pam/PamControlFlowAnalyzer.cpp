#include "modules/identity_access/pam/PamControlFlowAnalyzer.h"
#include "modules/identity_access/pam/PamOptionFile.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <utility>

namespace fic::identity::pam {
namespace {

constexpr std::size_t kMaximumSymbolicStates = 8192;
constexpr std::size_t kMaximumSymbolicTransitions = 250000;
constexpr std::size_t kMaximumTraceSteps = 256;

enum class Impression {
    Undefined,
    Positive,
    Negative
};

enum class ActionKind {
    Ignore,
    Bad,
    Die,
    Ok,
    Done,
    Reset,
    Jump
};

enum class PamModuleRole {
    CredentialAuthenticator,
    Auxiliary,
    Gate,
    Enforcement,
    TrustedAuthenticator,
    Unknown
};

struct ControlAction {
    ActionKind kind = ActionKind::Bad;
    std::size_t jump = 0;
};

struct ParsedControl {
    std::map<std::string, ControlAction> actions;
    ControlAction defaultAction;
};

struct TrustedAuthenticationBypassEvidence {
    std::string service;
    std::string module;
    fic::platform::PamTrustedAuthenticationBypassReason reason =
        fic::platform::PamTrustedAuthenticationBypassReason::
            AlreadyPrivilegedCaller;
    std::filesystem::path source;
    std::size_t line = 0;
};

struct TrustedAuthenticationExclusionEvidence {
    std::string service;
    std::string module;
    fic::platform::PamTrustedAuthenticationExclusionReason reason =
        fic::platform::PamTrustedAuthenticationExclusionReason::
            ExplicitSubjectExclusion;
    std::string excludedUser;
    std::filesystem::path source;
    std::size_t line = 0;
};

struct Evidence {
    bool providerReached = false;
    bool providerSucceeded = false;
    bool preauthSucceeded = false;
    bool preauthDenied = false;
    bool preauthFailedClosed = false;
    bool authfailReached = false;
    bool authsuccSucceeded = false;
    bool authsuccDenied = false;
    bool accountSucceeded = false;
    bool authenticationSuccessObserved = false;
    bool authenticationFailureObserved = false;
    std::optional<TrustedAuthenticationBypassEvidence>
        trustedAuthenticationBypass;
    std::optional<TrustedAuthenticationExclusionEvidence>
        trustedAuthenticationExclusion;
};

struct ExecutionState {
    Impression impression = Impression::Undefined;
    std::string status = "perm_denied";
    Evidence evidence;
    std::vector<PamFlowStep> trace;
    bool traceTruncated = false;
};

struct ExecutionBudget {
    std::size_t transitions = 0;
};

std::string lowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) {
                       return static_cast<char>(std::tolower(c));
                   });
    return value;
}

std::string moduleBaseName(const PamRule& rule) {
    return std::filesystem::path(rule.module).filename().string();
}

const fic::platform::PamTrustedAuthenticationExclusionRule*
matchingTrustedAuthenticationExclusion(
    const PamRule& rule,
    const std::string& service,
    const fic::platform::PamPlatformConfig& platformConfig) {
    const std::string module = moduleBaseName(rule);
    const auto matched = std::find_if(
        platformConfig.trustedAuthenticationExclusions.begin(),
        platformConfig.trustedAuthenticationExclusions.end(),
        [&](const auto& candidate) {
            const bool controlMatches =
                candidate.control == rule.control ||
                (!candidate.enforcedControl.empty() &&
                 candidate.enforcedControl == rule.control);
            return candidate.service == service &&
                candidate.module == module &&
                controlMatches &&
                candidate.arguments == rule.arguments &&
                (!candidate.source.has_value() ||
                 candidate.source->lexically_normal() ==
                     rule.source.lexically_normal());
        });
    return matched == platformConfig.trustedAuthenticationExclusions.end()
        ? nullptr
        : &*matched;
}

const std::vector<std::string>& allReturnCodes() {
    static const std::vector<std::string> values = {
        "success", "open_err", "symbol_err", "service_err",
        "system_err", "buf_err", "perm_denied", "auth_err",
        "cred_insufficient", "authinfo_unavail", "user_unknown",
        "maxtries", "new_authtok_reqd", "acct_expired", "session_err",
        "cred_unavail", "cred_expired", "cred_err", "no_module_data",
        "conv_err", "authtok_err", "authtok_recover_err",
        "authtok_lock_busy", "authtok_disable_aging", "try_again",
        "ignore", "abort", "authtok_expired", "module_unknown",
        "bad_item", "conv_again", "incomplete"
    };
    return values;
}

bool knownReturnCode(const std::string& value) {
    const auto& values = allReturnCodes();
    return std::find(values.begin(), values.end(), value) != values.end();
}

std::optional<ControlAction> parseAction(const std::string& token) {
    const std::string action = lowerCopy(token);
    if (action == "ignore") {
        return ControlAction{ActionKind::Ignore, 0};
    }
    if (action == "bad") {
        return ControlAction{ActionKind::Bad, 0};
    }
    if (action == "die") {
        return ControlAction{ActionKind::Die, 0};
    }
    if (action == "ok") {
        return ControlAction{ActionKind::Ok, 0};
    }
    if (action == "done") {
        return ControlAction{ActionKind::Done, 0};
    }
    if (action == "reset") {
        return ControlAction{ActionKind::Reset, 0};
    }
    if (action.empty() ||
        !std::all_of(action.begin(), action.end(), [](unsigned char c) {
            return std::isdigit(c) != 0;
        })) {
        return std::nullopt;
    }
    try {
        const unsigned long parsed = std::stoul(action);
        if (parsed == 0) {
            return ControlAction{ActionKind::Ignore, 0};
        }
        if (parsed > kMaximumSymbolicStates) {
            return std::nullopt;
        }
        return ControlAction{ActionKind::Jump,
                             static_cast<std::size_t>(parsed)};
    } catch (...) {
        return std::nullopt;
    }
}

bool parseControl(const PamRule& rule,
                  ParsedControl& parsed,
                  std::string& error) {
    parsed = ParsedControl{};
    const std::string control = lowerCopy(rule.control);
    const auto setSimple = [&](ActionKind success, ActionKind failure) {
        parsed.defaultAction = ControlAction{failure, 0};
        parsed.actions["success"] = ControlAction{success, 0};
        parsed.actions["new_authtok_reqd"] = ControlAction{success, 0};
    };
    if (control == "required") {
        setSimple(ActionKind::Ok, ActionKind::Bad);
        return true;
    }
    if (control == "requisite") {
        setSimple(ActionKind::Ok, ActionKind::Die);
        return true;
    }
    if (control == "sufficient") {
        setSimple(ActionKind::Done, ActionKind::Ignore);
        return true;
    }
    if (control == "optional") {
        setSimple(ActionKind::Ok, ActionKind::Ignore);
        return true;
    }
    if (control.size() < 2 || control.front() != '[' ||
        control.back() != ']') {
        error = rule.source.string() + ":" + std::to_string(rule.line) +
            ": unsupported PAM control: " + rule.control;
        return false;
    }

    parsed.defaultAction = ControlAction{ActionKind::Bad, 0};
    std::istringstream input(control.substr(1, control.size() - 2));
    std::string assignment;
    std::set<std::string> assigned;
    while (input >> assignment) {
        const auto equals = assignment.find('=');
        if (equals == std::string::npos || equals == 0 ||
            equals + 1 >= assignment.size()) {
            error = rule.source.string() + ":" + std::to_string(rule.line) +
                ": malformed extended PAM control: " + rule.control;
            return false;
        }
        const std::string result = assignment.substr(0, equals);
        const std::string actionText = assignment.substr(equals + 1);
        if ((result != "default" && !knownReturnCode(result)) ||
            !assigned.insert(result).second) {
            error = rule.source.string() + ":" + std::to_string(rule.line) +
                ": unsupported or duplicate PAM result in control: " + result;
            return false;
        }
        const auto action = parseAction(actionText);
        if (!action.has_value()) {
            error = rule.source.string() + ":" + std::to_string(rule.line) +
                ": unsupported PAM action in control: " + actionText;
            return false;
        }
        if (result == "default") {
            parsed.defaultAction = *action;
        } else {
            parsed.actions[result] = *action;
        }
    }
    if (assigned.empty()) {
        error = rule.source.string() + ":" + std::to_string(rule.line) +
            ": empty extended PAM control";
        return false;
    }
    return true;
}

std::vector<std::string> moduleOutcomes(
    const PamRule& rule,
    const std::string& service,
    const fic::platform::PamPlatformConfig& platformConfig) {
    const std::string module = moduleBaseName(rule);
    if (module == "pam_permit.so") {
        return {"success"};
    }
    if (module == "pam_deny.so") {
        if (rule.group == PamManagementGroup::Password) {
            return {"authtok_err"};
        }
        return {"auth_err"};
    }
    if (module == "pam_rootok.so") {
        return {"success", "auth_err"};
    }
    if (module == "pam_succeed_if.so") {
        // The exact platform contract makes this a typed two-way subject
        // predicate rather than an arbitrary gate.  Its arguments are known
        // to be syntactically valid and the display manager supplies PAM_USER,
        // so model the two semantic outcomes: admitted subject vs excluded
        // subject.  Unknown pam_succeed_if rules remain nondeterministic over
        // PAM_SERVICE_ERR as before.
        if (matchingTrustedAuthenticationExclusion(
                rule, service, platformConfig) != nullptr) {
            return {"success", "auth_err"};
        }
        return {"success", "auth_err", "service_err"};
    }
    if (module == "pam_faillock.so") {
        return {"success", "auth_err", "buf_err", "conv_err",
                "incomplete", "ignore"};
    }
    if (module == "pam_pwquality.so") {
        return {"success", "authtok_err", "authtok_recover_err",
                "authtok_lock_busy", "user_unknown", "maxtries",
                "try_again", "incomplete"};
    }
    if (module == "pam_passwdqc.so") {
        return {"success", "authtok_err", "authtok_recover_err",
                "authtok_lock_busy", "user_unknown", "maxtries"};
    }
    if (module == "pam_pwhistory.so") {
        return {"success", "system_err", "authtok_err",
                "authtok_recover_err", "authtok_lock_busy",
                "user_unknown", "maxtries", "try_again", "incomplete",
                "ignore"};
    }
    if (module == "pam_tcb.so") {
        // ALT p11 pam0_tcb-1.2-alt2, pam_tcb/pam_unix_auth.c: the auth
        // entry point obtains the user/token and calls _unix_verify_password.
        // PAM_NEW_AUTHTOK_REQD is returned only by pam_sm_acct_mgmt(), not by
        // pam_sm_authenticate(). Keep management-group contracts separate.
        if (rule.group == PamManagementGroup::Auth) {
            return {"success", "abort", "system_err", "buf_err",
                    "conv_err", "incomplete", "user_unknown", "auth_err",
                    "authtok_err", "authinfo_unavail"};
        }
        if (rule.group == PamManagementGroup::Account) {
            return {"success", "abort", "user_unknown", "authinfo_unavail",
                    "cred_insufficient", "acct_expired",
                    "new_authtok_reqd"};
        }
    }
    if (module == "pam_gnome_keyring.so" &&
        rule.group == PamManagementGroup::Auth) {
        // GNOME Keyring 48 gkr-pam-module.c consumes PAM_AUTHTOK to unlock the
        // login keyring; it does not authenticate the login password.
        return {"success", "service_err", "authtok_recover_err",
                "system_err", "buf_err", "bad_item"};
    }
    if (module == "pam_unix.so") {
        if (rule.group == PamManagementGroup::Password) {
            return {"success", "authtok_err", "authtok_recover_err",
                    "authtok_lock_busy", "authtok_disable_aging",
                    "user_unknown", "maxtries", "try_again",
                    "incomplete"};
        }
        return {"success", "auth_err", "user_unknown", "maxtries",
                "authinfo_unavail", "cred_insufficient", "incomplete"};
    }
    // Unknown modules are deliberately nondeterministic. This is what makes
    // an early sufficient/done/jump path fail closed instead of being assumed
    // harmless.
    return allReturnCodes();
}

bool hasArgument(const PamRule& rule, const std::string& argument) {
    return std::find(rule.arguments.begin(), rule.arguments.end(), argument) !=
        rule.arguments.end();
}

bool authenticationFailureResult(const std::string& result) {
    static const std::set<std::string> failures = {
        "auth_err", "cred_insufficient", "authinfo_unavail",
        "user_unknown", "maxtries"
    };
    return failures.find(result) != failures.end();
}

PamModuleRole moduleRole(const std::string& module) {
    static const std::set<std::string> credentialAuthenticators = {
        "pam_ccreds.so", "pam_krb5.so", "pam_ldap.so", "pam_pkcs11.so",
        "pam_sss.so", "pam_tcb.so", "pam_unix.so", "pam_userpass.so",
        "pam_winbind.so"
    };
    static const std::set<std::string> gates = {
        "pam_access.so", "pam_deny.so", "pam_env.so", "pam_faildelay.so",
        "pam_nologin.so", "pam_securetty.so", "pam_sepermit.so",
        "pam_shells.so", "pam_succeed_if.so", "pam_time.so",
        "pam_wheel.so"
    };
    static const std::set<std::string> auxiliaries = {
        "pam_gnome_keyring.so"
    };
    if (credentialAuthenticators.find(module) !=
        credentialAuthenticators.end()) {
        return PamModuleRole::CredentialAuthenticator;
    }
    if (gates.find(module) != gates.end()) {
        return PamModuleRole::Gate;
    }
    if (auxiliaries.find(module) != auxiliaries.end()) {
        return PamModuleRole::Auxiliary;
    }
    if (module == "pam_faillock.so") {
        return PamModuleRole::Enforcement;
    }
    if (module == "pam_rootok.so") {
        return PamModuleRole::TrustedAuthenticator;
    }
    return PamModuleRole::Unknown;
}

void recordEvidence(ExecutionState& state,
                    const PamRule& rule,
                    const std::string& result,
                    PamProviderKind provider) {
    const std::string module = moduleBaseName(rule);
    const bool expectedProvider = module == pamProviderModuleName(provider);
    if (expectedProvider) {
        state.evidence.providerReached = true;
        if (result == "success") {
            state.evidence.providerSucceeded = true;
        }
    }

    if (provider == PamProviderKind::PamFaillock && expectedProvider) {
        if (rule.group == PamManagementGroup::Account && result == "success") {
            state.evidence.accountSucceeded = true;
        } else if (hasArgument(rule, "preauth")) {
            state.evidence.preauthSucceeded |= result == "success";
            state.evidence.preauthDenied |= result == "auth_err";
        } else if (hasArgument(rule, "authfail")) {
            state.evidence.authfailReached = true;
        } else if (hasArgument(rule, "authsucc")) {
            if (result == "success") {
                state.evidence.authsuccSucceeded = true;
            } else if (result != "ignore") {
                state.evidence.authsuccDenied = true;
            }
        }
        return;
    }

    const PamModuleRole role = moduleRole(module);
    if (rule.group == PamManagementGroup::Auth && !expectedProvider &&
        (role == PamModuleRole::CredentialAuthenticator ||
         role == PamModuleRole::Unknown)) {
        state.evidence.authenticationSuccessObserved |= result == "success";
        state.evidence.authenticationFailureObserved |=
            authenticationFailureResult(result);
    } else if (rule.group == PamManagementGroup::Auth &&
               role == PamModuleRole::TrustedAuthenticator) {
        state.evidence.authenticationSuccessObserved |= result == "success";
    }
}

void recordProviderFailClosedEvidence(
    ExecutionState& state,
    const PamRule& rule,
    const std::string& result,
    const ControlAction& action,
    PamProviderKind provider) {
    if (provider != PamProviderKind::PamFaillock ||
        moduleBaseName(rule) != "pam_faillock.so" ||
        !hasArgument(rule, "preauth") || result == "success" ||
        result == "new_authtok_reqd" || result == "auth_err") {
        return;
    }
    state.evidence.preauthFailedClosed |=
        action.kind == ActionKind::Bad || action.kind == ActionKind::Die;
}

void recordTrustedAuthenticationBypass(
    ExecutionState& state,
    const PamRule& rule,
    const std::string& result,
    const ControlAction& action,
    const std::string& service,
    const fic::platform::PamPlatformConfig& platformConfig) {
    if (rule.group != PamManagementGroup::Auth || result != "success" ||
        action.kind != ActionKind::Done) {
        return;
    }
    const std::string module = moduleBaseName(rule);
    const auto matched = std::find_if(
        platformConfig.trustedAuthenticationBypasses.begin(),
        platformConfig.trustedAuthenticationBypasses.end(),
        [&](const auto& candidate) {
            return candidate.service == service &&
                candidate.module == module &&
                (candidate.control.empty() ||
                 candidate.control == rule.control) &&
                (candidate.arguments.empty() ||
                 candidate.arguments == rule.arguments) &&
                (!candidate.source.has_value() ||
                 candidate.source->lexically_normal() ==
                     rule.source.lexically_normal());
        });
    if (matched == platformConfig.trustedAuthenticationBypasses.end()) {
        return;
    }
    state.evidence.trustedAuthenticationBypass =
        TrustedAuthenticationBypassEvidence{
            service, module, matched->reason, rule.source, rule.line};
}

void recordTrustedAuthenticationExclusion(
    ExecutionState& state,
    const PamRule& rule,
    const std::string& result,
    const ControlAction& action,
    const std::string& service,
    const fic::platform::PamPlatformConfig& platformConfig) {
    if (rule.group != PamManagementGroup::Auth || result != "auth_err" ||
        (action.kind != ActionKind::Bad &&
         action.kind != ActionKind::Die)) {
        return;
    }
    const auto* matched = matchingTrustedAuthenticationExclusion(
        rule, service, platformConfig);
    if (matched == nullptr || matched->excludedUser.empty()) {
        return;
    }
    state.evidence.trustedAuthenticationExclusion =
        TrustedAuthenticationExclusionEvidence{
            service, moduleBaseName(rule), matched->reason,
            matched->excludedUser, rule.source, rule.line};
}

std::string actionName(const ControlAction& action) {
    switch (action.kind) {
    case ActionKind::Ignore:
        return "ignore";
    case ActionKind::Bad:
        return "bad";
    case ActionKind::Die:
        return "die";
    case ActionKind::Ok:
        return "ok";
    case ActionKind::Done:
        return "done";
    case ActionKind::Reset:
        return "reset";
    case ActionKind::Jump:
        return "jump " + std::to_string(action.jump);
    }
    return "unknown";
}

bool sameTrustedAuthenticationBypass(
    const std::optional<TrustedAuthenticationBypassEvidence>& left,
    const std::optional<TrustedAuthenticationBypassEvidence>& right) {
    if (left.has_value() != right.has_value()) {
        return false;
    }
    return !left.has_value() ||
        (left->service == right->service &&
         left->module == right->module &&
         left->reason == right->reason &&
         left->source == right->source &&
         left->line == right->line);
}

bool sameTrustedAuthenticationExclusion(
    const std::optional<TrustedAuthenticationExclusionEvidence>& left,
    const std::optional<TrustedAuthenticationExclusionEvidence>& right) {
    if (left.has_value() != right.has_value()) {
        return false;
    }
    return !left.has_value() ||
        (left->service == right->service &&
         left->module == right->module &&
         left->reason == right->reason &&
         left->excludedUser == right->excludedUser &&
         left->source == right->source &&
         left->line == right->line);
}

bool sameState(const ExecutionState& left, const ExecutionState& right) {
    const auto& a = left.evidence;
    const auto& b = right.evidence;
    return left.impression == right.impression && left.status == right.status &&
        a.providerReached == b.providerReached &&
        a.providerSucceeded == b.providerSucceeded &&
        a.preauthSucceeded == b.preauthSucceeded &&
        a.preauthDenied == b.preauthDenied &&
        a.preauthFailedClosed == b.preauthFailedClosed &&
        a.authfailReached == b.authfailReached &&
        a.authsuccSucceeded == b.authsuccSucceeded &&
        a.authsuccDenied == b.authsuccDenied &&
        a.accountSucceeded == b.accountSucceeded &&
        a.authenticationSuccessObserved == b.authenticationSuccessObserved &&
        a.authenticationFailureObserved == b.authenticationFailureObserved &&
        sameTrustedAuthenticationBypass(
            a.trustedAuthenticationBypass,
            b.trustedAuthenticationBypass) &&
        sameTrustedAuthenticationExclusion(
            a.trustedAuthenticationExclusion,
            b.trustedAuthenticationExclusion);
}

bool addUnique(std::vector<ExecutionState>& states,
               ExecutionState state,
               std::string& error) {
    if (std::any_of(states.begin(), states.end(), [&](const auto& existing) {
            return sameState(existing, state);
        })) {
        return true;
    }
    if (states.size() >= kMaximumSymbolicStates) {
        error = "PAM symbolic state limit exceeded";
        return false;
    }
    states.push_back(std::move(state));
    return true;
}

bool stackSucceeded(const ExecutionState& state) {
    return state.impression == Impression::Positive &&
        state.status == "success";
}

bool executeStack(const std::vector<PamStackEntry>& entries,
                  const ExecutionState& initial,
                  PamProviderKind provider,
                  const std::string& service,
                  const fic::platform::PamPlatformConfig& platformConfig,
                  std::vector<ExecutionState>& completed,
                  std::string& error,
                  ExecutionBudget& budget,
                  std::size_t depth = 0) {
    if (depth > 32) {
        error = "PAM substack depth limit exceeded";
        return false;
    }
    std::vector<std::vector<ExecutionState>> pending(entries.size() + 1);
    pending.front().push_back(initial);

    for (std::size_t index = 0; index < entries.size(); ++index) {
        for (const auto& incoming : pending[index]) {
            const auto& entry = entries[index];
            if (entry.isSubstack()) {
                ExecutionState nestedInitial = incoming;
                PamFlowStep boundary;
                boundary.source = entry.rule.source;
                boundary.line = entry.rule.line;
                boundary.module = "substack " + entry.rule.includeTarget;
                boundary.control = "substack";
                boundary.action = "enter";
                if (nestedInitial.trace.size() < kMaximumTraceSteps) {
                    nestedInitial.trace.push_back(std::move(boundary));
                } else {
                    nestedInitial.traceTruncated = true;
                }
                std::vector<ExecutionState> nestedCompleted;
                if (!executeStack(
                        entry.substack,
                        nestedInitial,
                        provider,
                        service,
                        platformConfig,
                        nestedCompleted,
                        error,
                        budget,
                        depth + 1)) {
                    return false;
                }
                for (auto& state : nestedCompleted) {
                    if (!addUnique(pending[index + 1], std::move(state), error)) {
                        return false;
                    }
                }
                continue;
            }

            ParsedControl control;
            if (!parseControl(entry.rule, control, error)) {
                return false;
            }
            for (const auto& result : moduleOutcomes(
                     entry.rule, service, platformConfig)) {
                if (++budget.transitions > kMaximumSymbolicTransitions) {
                    error = "PAM symbolic transition limit exceeded";
                    return false;
                }
                ExecutionState state = incoming;
                recordEvidence(state, entry.rule, result, provider);
                const auto found = control.actions.find(result);
                const ControlAction action = found == control.actions.end()
                    ? control.defaultAction
                    : found->second;
                recordProviderFailClosedEvidence(
                    state, entry.rule, result, action, provider);
                recordTrustedAuthenticationExclusion(
                    state, entry.rule, result, action, service,
                    platformConfig);
                if (state.trace.size() < kMaximumTraceSteps) {
                    state.trace.push_back({
                        entry.rule.source,
                        entry.rule.line,
                        entry.rule.module,
                        result,
                        entry.rule.control,
                        actionName(action)
                    });
                } else {
                    state.traceTruncated = true;
                }

                bool terminate = false;
                switch (action.kind) {
                case ActionKind::Reset:
                    state.impression = initial.impression;
                    state.status = initial.status;
                    break;
                case ActionKind::Ok:
                case ActionKind::Done:
                    if (state.impression == Impression::Undefined ||
                        (state.impression == Impression::Positive &&
                         state.status == "success")) {
                        if (result != "ignore") {
                            state.impression = Impression::Positive;
                            state.status = result;
                        }
                    }
                    terminate = action.kind == ActionKind::Done &&
                        state.impression == Impression::Positive;
                    break;
                case ActionKind::Bad:
                case ActionKind::Die:
                    if (state.impression != Impression::Negative) {
                        state.impression = Impression::Negative;
                        state.status = result == "ignore"
                            ? "perm_denied"
                            : result;
                    }
                    terminate = action.kind == ActionKind::Die;
                    break;
                case ActionKind::Ignore:
                    break;
                case ActionKind::Jump: {
                    const std::size_t next = index + 1 + action.jump;
                    if (next > entries.size()) {
                        state.impression = Impression::Negative;
                        state.status = "perm_denied";
                        terminate = true;
                    } else if (!addUnique(
                                   pending[next], std::move(state), error)) {
                        return false;
                    }
                    if (!terminate) {
                        continue;
                    }
                    break;
                }
                }

                if (terminate && stackSucceeded(state)) {
                    recordTrustedAuthenticationBypass(
                        state,
                        entry.rule,
                        result,
                        action,
                        service,
                        platformConfig);
                }
                if (terminate) {
                    if (!addUnique(completed, std::move(state), error)) {
                        return false;
                    }
                } else if (!addUnique(
                               pending[index + 1], std::move(state), error)) {
                    return false;
                }
            }
        }
    }

    for (auto& state : pending.back()) {
        if (!addUnique(completed, std::move(state), error)) {
            return false;
        }
    }
    return true;
}

bool stackHasFaillockRole(const std::vector<PamStackEntry>& entries,
                          const std::string& role,
                          PamManagementGroup group) {
    for (const auto& entry : entries) {
        if (entry.isSubstack()) {
            if (stackHasFaillockRole(entry.substack, role, group)) {
                return true;
            }
            continue;
        }
        if (entry.rule.group != group ||
            moduleBaseName(entry.rule) != "pam_faillock.so") {
            continue;
        }
        if (group == PamManagementGroup::Account ||
            hasArgument(entry.rule, role)) {
            return true;
        }
    }
    return false;
}

PamFlowViolation violationForState(PamFlowViolationKind kind,
                                   const PamEffectiveStack& stack,
                                   const std::string& message,
                                   const ExecutionState& state) {
    return {kind,
            stack.service,
            stack.group,
            message,
            state.trace,
            state.traceTruncated};
}

void addFirstViolation(PamControlFlowAnalysis& analysis,
                       PamFlowViolation violation) {
    const bool duplicate = std::any_of(
        analysis.violations.begin(), analysis.violations.end(),
        [&](const PamFlowViolation& existing) {
            return existing.kind == violation.kind &&
                existing.service == violation.service &&
                existing.group == violation.group;
        });
    if (!duplicate) {
        analysis.violations.push_back(std::move(violation));
    }
}

void addAcceptedTrustedAuthenticationBypass(
    PamControlFlowAnalysis& analysis,
    const ExecutionState& state) {
    if (!state.evidence.trustedAuthenticationBypass.has_value()) {
        return;
    }
    const auto& evidence = *state.evidence.trustedAuthenticationBypass;
    const bool duplicate = std::any_of(
        analysis.acceptedTrustedAuthenticationBypasses.begin(),
        analysis.acceptedTrustedAuthenticationBypasses.end(),
        [&](const auto& existing) {
            return existing.service == evidence.service &&
                existing.module == evidence.module &&
                existing.reason == evidence.reason &&
                existing.source == evidence.source &&
                existing.line == evidence.line;
        });
    if (!duplicate) {
        analysis.acceptedTrustedAuthenticationBypasses.push_back({
            evidence.service,
            evidence.module,
            evidence.reason,
            evidence.source,
            evidence.line,
            state.trace,
            state.traceTruncated
        });
    }
}

void addAcceptedTrustedAuthenticationExclusion(
    PamControlFlowAnalysis& analysis,
    const ExecutionState& state) {
    if (!state.evidence.trustedAuthenticationExclusion.has_value()) {
        return;
    }
    const auto& evidence = *state.evidence.trustedAuthenticationExclusion;
    const bool duplicate = std::any_of(
        analysis.acceptedTrustedAuthenticationExclusions.begin(),
        analysis.acceptedTrustedAuthenticationExclusions.end(),
        [&](const auto& existing) {
            return existing.service == evidence.service &&
                existing.module == evidence.module &&
                existing.reason == evidence.reason &&
                existing.excludedUser == evidence.excludedUser &&
                existing.source == evidence.source &&
                existing.line == evidence.line;
        });
    if (!duplicate) {
        analysis.acceptedTrustedAuthenticationExclusions.push_back({
            evidence.service,
            evidence.module,
            evidence.reason,
            evidence.excludedUser,
            evidence.source,
            evidence.line,
            state.trace,
            state.traceTruncated
        });
    }
}

bool pamFaillockRootLockoutEnabled(
    const fic::platform::PamPlatformConfig& platformConfig,
    bool& enabled,
    std::string& error) {
    const auto capability = std::find_if(
        platformConfig.capabilities.begin(),
        platformConfig.capabilities.end(),
        [](const auto& candidate) {
            return candidate.capability ==
                       fic::platform::PamCapability::AuthenticationLockout &&
                candidate.provider == fic::platform::PamProviderKind::PamFaillock;
        });
    if (capability == platformConfig.capabilities.end() ||
        capability->configPath.empty()) {
        error = "pam_faillock root-lockout state cannot be determined: "
                "the platform has no canonical faillock configuration path";
        return false;
    }

    std::string enabledError;
    if (PamOptionFile::hasFlag(
            capability->configPath, "even_deny_root", true, enabledError)) {
        enabled = true;
        error.clear();
        return true;
    }
    std::string disabledError;
    if (PamOptionFile::hasFlag(
            capability->configPath, "even_deny_root", false, disabledError)) {
        enabled = false;
        error.clear();
        return true;
    }
    error = "could not determine pam_faillock even_deny_root state: " +
        (disabledError.empty() ? enabledError : disabledError);
    return false;
}

bool analyzePasswordStack(const PamEffectiveStack& stack,
                          PamProviderKind provider,
                          const fic::platform::PamPlatformConfig& platformConfig,
                          PamControlFlowAnalysis& analysis,
                          std::string& error) {
    std::vector<ExecutionState> states;
    ExecutionBudget budget;
    if (!executeStack(
            stack.entries,
            ExecutionState{},
            provider,
            stack.service,
            platformConfig,
            states,
            error,
            budget)) {
        return false;
    }
    const auto successful = std::find_if(
        states.begin(), states.end(), stackSucceeded);
    if (successful == states.end()) {
        addFirstViolation(analysis, violationForState(
            PamFlowViolationKind::UnsupportedControlFlow,
            stack,
            "no successful password-change path can be proven",
            states.empty() ? ExecutionState{} : states.front()));
        return true;
    }
    for (const auto& state : states) {
        if (stackSucceeded(state) && !state.evidence.providerSucceeded) {
            addFirstViolation(analysis, violationForState(
                PamFlowViolationKind::PasswordEnforcementBypass,
                stack,
                "successful password-change path bypasses " +
                    pamProviderName(provider),
                state));
        }
    }
    return true;
}

bool analyzeFaillockStack(PamConfiguration& configuration,
                          const fic::platform::PamPlatformConfig& platformConfig,
                          const std::string& service,
                          PamControlFlowAnalysis& analysis,
                          std::string& error) {
    PamEffectiveStack authStack;
    if (!configuration.buildEffectiveStack(
            service, PamManagementGroup::Auth, authStack, error)) {
        return false;
    }
    std::vector<ExecutionState> authStates;
    ExecutionBudget authBudget;
    if (!executeStack(
            authStack.entries,
            ExecutionState{},
            PamProviderKind::PamFaillock,
            service,
            platformConfig,
            authStates,
            error,
            authBudget)) {
        return false;
    }
    const bool authsuccTopology = stackHasFaillockRole(
        authStack.entries, "authsucc", PamManagementGroup::Auth);
    const bool accountTopology = !authsuccTopology;
    // Invariant: pam_faillock authfail accounting must run only after
    // authentication failure can no longer be recovered by another
    // credential provider. A credential authenticator placed after the
    // authfail rule can never run: an earlier provider's success jumps
    // past the remainder of the primary block, and a failure reaches the
    // authfail rule first, which terminates the stack.
    const auto authfailIndex = std::find_if(
        authStack.entries.begin(), authStack.entries.end(),
        [](const PamStackEntry& entry) {
            const PamRule& rule = entry.rule;
            return rule.group == PamManagementGroup::Auth &&
                moduleBaseName(rule) == "pam_faillock.so" &&
                hasArgument(rule, "authfail");
        });
    if (authfailIndex != authStack.entries.end()) {
        const auto lateProvider = std::find_if(
            std::next(authfailIndex), authStack.entries.end(),
            [](const PamStackEntry& entry) {
                return entry.rule.group == PamManagementGroup::Auth &&
                    moduleRole(moduleBaseName(entry.rule)) ==
                    PamModuleRole::CredentialAuthenticator;
            });
        if (lateProvider != authStack.entries.end()) {
            PamFlowViolation violation;
            violation.kind = PamFlowViolationKind::ProviderUnreachable;
            violation.service = service;
            violation.group = PamManagementGroup::Auth;
            violation.message =
                "credential provider " +
                moduleBaseName(lateProvider->rule) +
                " follows the pam_faillock authfail accounting rule and can "
                "never be reached; authentication failure would be accounted "
                "even though it is still recoverable by this provider";
            violation.path.push_back({
                lateProvider->rule.source,
                lateProvider->rule.line,
                lateProvider->rule.module,
                "unreachable",
                lateProvider->rule.control,
                "unreachable"
            });
            addFirstViolation(analysis, std::move(violation));
        }
    }
    // A positive termination with PAM_NEW_AUTHTOK_REQD is a successful
    // authentication outcome (the stack asks for a token update), not a
    // failed one; unknown Additional modules may legitimately end such a
    // path, so the faillock classification must not treat it as a failure.
    const auto terminatedPositively = [](const ExecutionState& state) {
        return state.impression == Impression::Positive &&
            (state.status == "success" ||
             state.status == "new_authtok_reqd");
    };
    const auto successful = std::find_if(
        authStates.begin(), authStates.end(), terminatedPositively);
    if (successful == authStates.end()) {
        addFirstViolation(analysis, violationForState(
            PamFlowViolationKind::UnsupportedControlFlow,
            authStack,
            "no successful authentication path can be proven",
            authStates.empty() ? ExecutionState{} : authStates.front()));
    }

    for (const auto& state : authStates) {
        if (terminatedPositively(state)) {
            if (state.evidence.trustedAuthenticationBypass.has_value()) {
                addAcceptedTrustedAuthenticationBypass(analysis, state);
                continue;
            }
            if (authsuccTopology &&
                state.evidence.authenticationFailureObserved &&
                state.evidence.authfailReached) {
                addFirstViolation(analysis, violationForState(
                    PamFlowViolationKind::RecoverableFailureAccounting,
                    authStack,
                    "authentication failure was accounted by pam_faillock "
                    "authfail but the stack still terminated successfully",
                    state));
                continue;
            }
            if (authsuccTopology && state.evidence.authsuccDenied) {
                addFirstViolation(analysis, violationForState(
                    PamFlowViolationKind::AuthenticationBypass,
                    authStack,
                    "successful authentication path bypasses the pam_faillock "
                    "authsucc lockout denial",
                    state));
                continue;
            }
            if ((state.evidence.authenticationFailureObserved &&
                 !state.evidence.authenticationSuccessObserved) ||
                !state.evidence.providerReached ||
                // preauth_required topologies deliberately let a locked
                // user finish the authentication phase (preauth denied,
                // stack continues); the denial is enforced by the
                // separately verified account phase, so an auth-phase
                // success after a preauth denial is not a bypass.
                (accountTopology && !state.evidence.preauthSucceeded &&
                 !state.evidence.preauthDenied)) {
                addFirstViolation(analysis, violationForState(
                    PamFlowViolationKind::AuthenticationBypass,
                    authStack,
                    "successful authentication path bypasses the pam_faillock "
                    "lockout check",
                    state));
            } else if (authsuccTopology &&
                       !state.evidence.authsuccSucceeded) {
                addFirstViolation(analysis, violationForState(
                    PamFlowViolationKind::SuccessAccountingBypass,
                    authStack,
                    "successful authentication path bypasses pam_faillock "
                    "authsucc accounting",
                    state));
            }
        } else if (authsuccTopology && state.evidence.authsuccSucceeded &&
                   state.impression == Impression::Negative) {
            const auto& exclusion =
                state.evidence.trustedAuthenticationExclusion;
            if (exclusion.has_value() && exclusion->excludedUser == "root") {
                bool rootLockoutEnabled = false;
                if (!pamFaillockRootLockoutEnabled(
                        platformConfig, rootLockoutEnabled, error)) {
                    return false;
                }
                if (!rootLockoutEnabled) {
                    addAcceptedTrustedAuthenticationExclusion(analysis, state);
                    continue;
                }
                addFirstViolation(analysis, violationForState(
                    PamFlowViolationKind::PrematureSuccessAccounting,
                    authStack,
                    "pam_faillock authsucc reset the root tally on a path "
                    "that the PAM service explicitly excludes from "
                    "successful authentication while even_deny_root is "
                    "enabled",
                    state));
                continue;
            }
            addFirstViolation(analysis, violationForState(
                PamFlowViolationKind::PrematureSuccessAccounting,
                authStack,
                "pam_faillock authsucc success accounting happened on a "
                "path that finally failed authentication",
                state));
        } else if (state.evidence.authenticationFailureObserved &&
                   !state.evidence.authenticationSuccessObserved &&
                   !state.evidence.authfailReached &&
                   !state.evidence.preauthDenied &&
                   !state.evidence.preauthFailedClosed) {
            addFirstViolation(analysis, violationForState(
                PamFlowViolationKind::FailureAccountingBypass,
                authStack,
                "failed authentication path bypasses pam_faillock authfail "
                "accounting",
                state));
        }
    }

    if (!accountTopology) {
        return true;
    }

    PamEffectiveStack accountStack;
    if (!configuration.buildEffectiveStack(
            service, PamManagementGroup::Account, accountStack, error)) {
        return false;
    }
    std::vector<ExecutionState> accountStates;
    ExecutionBudget accountBudget;
    if (!executeStack(
            accountStack.entries,
            ExecutionState{},
            PamProviderKind::PamFaillock,
            service,
            platformConfig,
            accountStates,
            error,
            accountBudget)) {
        return false;
    }
    const auto accountSuccess = std::find_if(
        accountStates.begin(), accountStates.end(), stackSucceeded);
    if (accountSuccess == accountStates.end()) {
        addFirstViolation(analysis, violationForState(
            PamFlowViolationKind::UnsupportedControlFlow,
            accountStack,
            "no successful account-management path can be proven",
            accountStates.empty() ? ExecutionState{} : accountStates.front()));
        return true;
    }
    for (const auto& state : accountStates) {
        if (stackSucceeded(state) && !state.evidence.accountSucceeded) {
            addFirstViolation(analysis, violationForState(
                PamFlowViolationKind::SuccessAccountingBypass,
                accountStack,
                "successful account path bypasses pam_faillock success "
                "accounting",
                state));
        }
    }
    return true;
}

} // namespace

std::optional<fic::platform::PamFaillockStrategy>
detectPamFaillockStrategy(const PamEffectiveStack& authStack,
                          std::string& error) {
    std::vector<const PamRule*> faillockRules;
    std::vector<const PamStackEntry*> pending;
    for (const auto& entry : authStack.entries) {
        pending.push_back(&entry);
    }
    while (!pending.empty()) {
        const PamStackEntry* entry = pending.back();
        pending.pop_back();
        if (entry->isSubstack()) {
            for (const auto& child : entry->substack) {
                pending.push_back(&child);
            }
            continue;
        }
        const PamRule& rule = entry->rule;
        if (rule.includeKind != PamIncludeKind::None ||
            moduleBaseName(rule) != "pam_faillock.so" ||
            rule.group != PamManagementGroup::Auth) {
            continue;
        }
        faillockRules.push_back(&rule);
    }

    std::vector<const PamRule*> preauthRules;
    std::vector<const PamRule*> authfailRules;
    std::vector<const PamRule*> authsuccRules;
    for (const PamRule* rule : faillockRules) {
        if (hasArgument(*rule, "preauth")) {
            preauthRules.push_back(rule);
        } else if (hasArgument(*rule, "authfail")) {
            authfailRules.push_back(rule);
        } else if (hasArgument(*rule, "authsucc")) {
            authsuccRules.push_back(rule);
        } else {
            error = "unrecognized pam_faillock authentication rule without "
                "preauth/authfail/authsucc role";
            return std::nullopt;
        }
    }

    if (authfailRules.empty()) {
        error = "pam_faillock topology has no authfail accounting rule";
        return std::nullopt;
    }

    if (preauthRules.size() > 1 || authsuccRules.size() > 1) {
        error = "ambiguous pam_faillock topology with duplicated "
            "preauth or authsucc rules";
        return std::nullopt;
    }

    if (!preauthRules.empty()) {
        if (!authsuccRules.empty()) {
            error = "ambiguous pam_faillock topology combines preauth and "
                "authsucc strategies";
            return std::nullopt;
        }
        const std::string& control = preauthRules.front()->control;
        if (control == "requisite") {
            error.clear();
            return fic::platform::PamFaillockStrategy::PreauthRequisite;
        }
        if (control == "required") {
            error.clear();
            return fic::platform::PamFaillockStrategy::PreauthRequired;
        }
        error = "unsupported pam_faillock preauth control: " + control;
        return std::nullopt;
    }

    if (!authsuccRules.empty()) {
        error.clear();
        return fic::platform::PamFaillockStrategy::Authsucc;
    }

    error = "pam_faillock topology has neither preauth nor authsucc rules";
    return std::nullopt;
}

bool PamControlFlowAnalyzer::analyze(
    PamConfiguration& configuration,
    const fic::platform::PamPlatformConfig& platformConfig,
    const std::string& service,
    PamCapability capability,
    PamProviderKind provider,
    PamControlFlowAnalysis& analysis,
    std::string& error) {
    analysis = PamControlFlowAnalysis{};
    bool analyzed = false;
    if (capability == PamCapability::AuthenticationLockout) {
        analyzed = analyzeFaillockStack(
            configuration, platformConfig, service, analysis, error);
    } else {
        PamEffectiveStack stack;
        if (!configuration.buildEffectiveStack(
                service, PamManagementGroup::Password, stack, error)) {
            return false;
        }
        analyzed = analyzePasswordStack(
            stack, provider, platformConfig, analysis, error);
    }
    if (!analyzed) {
        PamFlowViolation violation;
        violation.kind = PamFlowViolationKind::UnsupportedControlFlow;
        violation.service = service;
        violation.group = capability == PamCapability::AuthenticationLockout
            ? PamManagementGroup::Auth
            : PamManagementGroup::Password;
        violation.message = error;
        analysis.violations.push_back(std::move(violation));
        analysis.effective = false;
        return true;
    }
    analysis.effective = analysis.violations.empty();
    error.clear();
    return true;
}

std::string pamFlowViolationKindName(PamFlowViolationKind kind) {
    switch (kind) {
    case PamFlowViolationKind::ProviderUnreachable:
        return "provider_unreachable";
    case PamFlowViolationKind::AuthenticationBypass:
        return "authentication_bypass";
    case PamFlowViolationKind::PasswordEnforcementBypass:
        return "password_enforcement_bypass";
    case PamFlowViolationKind::FailureAccountingBypass:
        return "failure_accounting_bypass";
    case PamFlowViolationKind::RecoverableFailureAccounting:
        return "recoverable_failure_accounting";
    case PamFlowViolationKind::SuccessAccountingBypass:
        return "success_accounting_bypass";
    case PamFlowViolationKind::PrematureSuccessAccounting:
        return "premature_success_accounting";
    case PamFlowViolationKind::UnsupportedControlFlow:
        return "unsupported_control_flow";
    }
    return "unknown";
}

std::string formatPamFlowViolation(const PamFlowViolation& violation) {
    std::string formatted = pamFlowViolationKindName(violation.kind) +
        " for PAM service " + violation.service + " (" +
        pamManagementGroupName(violation.group) + "): " + violation.message;
    for (const auto& step : violation.path) {
        formatted += "\n  " + step.source.string() + ":" +
            std::to_string(step.line) + " " + step.module;
        if (!step.result.empty()) {
            formatted += " -> PAM_";
            std::string upper = step.result;
            std::transform(upper.begin(), upper.end(), upper.begin(),
                           [](unsigned char c) {
                               return static_cast<char>(std::toupper(c));
                           });
            formatted += upper;
        }
        if (!step.control.empty()) {
            formatted += " control=" + step.control;
        }
        if (!step.action.empty()) {
            formatted += " action=" + step.action;
        }
    }
    if (violation.pathTruncated) {
        formatted += "\n  ... PAM flow trace truncated ...";
    }
    return formatted;
}

} // namespace fic::identity::pam
