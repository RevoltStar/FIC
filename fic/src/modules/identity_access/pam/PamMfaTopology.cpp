#include "modules/identity_access/pam/PamMfaTopology.h"

#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamControlFlowAnalyzer.h"
#include "modules/identity_access/sssd/SssdConfiguration.h"

#include <fic/core/fs/RootControlledDirectory.h>
#include <fic/core/fs/SecureStateFile.h>

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace fic::identity::pam {
namespace {

namespace fs = std::filesystem;
using fic::core::SecureStateReadStatus;
constexpr char store[] = "/etc/security/fic-mfa";
constexpr char google[] = "pam_google_authenticator.so";

bool reject(std::string& error, const std::string& reason) {
    error = reason;
    return false;
}

fic::core::SecureStateReadResult readTrusted(const fs::path& file, mode_t mode,
                                             std::uintmax_t limit, std::string& error) {
    const int fd = fic::core::openRootControlledDirectory(file.parent_path(), error);
    if (fd < 0) return {};
    ::close(fd);
    fic::core::SecureStateFileExpectation expectation;
    expectation.owner = 0;
    expectation.forbiddenMode = 0022;
    expectation.parentOwner = 0;
    expectation.exactMode = mode;
    expectation.requireSingleLink = true;
    return fic::core::readSecureFileBounded(file, expectation, limit);
}

bool trustedModule(const fic::platform::PamPlatformConfig& pam,
                   const std::string& module, std::string& error) {
    for (const auto& directory : pam.moduleDirectories) {
        std::error_code ec;
        const auto real = fs::canonical(directory, ec);
        if (ec) continue;
        const int fd = fic::core::openRootControlledDirectory(real, error);
        if (fd < 0) return false;
        struct stat info {};
        const int rc = ::fstatat(fd, module.c_str(), &info, AT_SYMLINK_NOFOLLOW);
        const int saved = errno;
        ::close(fd);
        if (rc == 0 && S_ISREG(info.st_mode) && info.st_uid == 0 &&
            (info.st_mode & 0022) == 0) return true;
        if (rc == 0 || saved != ENOENT) break;
    }
    return reject(error, "missing or untrusted PAM module: " + module);
}

bool base32(char c) { return (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7'); }

bool proveTotpStore(std::string& error) {
    const int fd = fic::core::openRootControlledDirectory(store, error);
    if (fd < 0) return false;
    struct stat info {};
    const bool privateStore = ::fstat(fd, &info) == 0 && (info.st_mode & 07777) == 0700;
    ::close(fd);
    if (!privateStore) return reject(error, "Google TOTP directory must be root-private");
    std::error_code ec;
    fs::directory_iterator it(store, ec), end;
    unsigned files = 0;
    for (; !ec && it != end; it.increment(ec)) {
        if (++files > 4096) return reject(error, "Google TOTP inventory limit exceeded");
        const auto name = it->path().filename().string();
        if (name.rfind("totp-", 0) != 0 || name.size() == 5)
            return reject(error, "unexpected file in Google TOTP directory");
        const auto credential = readTrusted(it->path(), 0600, 1024, error);
        if (credential.status != SecureStateReadStatus::Proven)
            return reject(error, "Google TOTP credential metadata is unproven");
        const auto first = credential.content.find('\n');
        if (first == std::string::npos || first != 32 ||
            !std::all_of(credential.content.begin(), credential.content.begin() + first, base32) ||
            credential.content.substr(first + 1) != "\" TOTP_AUTH\n")
            return reject(error, "unsupported Google credential format (TOTP-only required)");
    }
    return !ec || reject(error, "Google TOTP directory inventory is unproven");
}

bool proveSssdPasswordConfiguration(std::string& error) {
    using namespace fic::identity::sssd;
    auto options = SssdConfigurationOptions::production();
    // Debian 13's sssd.service adds group read permission at startup.
    // Both owner and group still have to be root.
    options.mainFile.exactMode = std::nullopt;
    options.mainFile.forbiddenMode = 07137;
    SssdConfiguration configuration(std::move(options));
    std::optional<std::string> domain;
    if (!configuration.tryGetEffectiveValue("sssd", "domains", domain, error))
        return false;
    if (!domain || domain->empty() ||
        domain->find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") !=
            std::string::npos)
        return reject(error, "MFA requires one explicitly configured SSSD LDAP domain");
    const std::string section = "domain/" + *domain;
    const auto equals = [&](const std::string& group, const char* key, const char* expected) {
        std::optional<std::string> value;
        if (!configuration.tryGetEffectiveValue(group, key, value, error)) return false;
        return value.value_or("") == expected ||
               reject(error, "SSSD password route requires " + group + "/" + key + "=" + expected);
    };
    const auto hasLockedNssPassword = [&](const std::string& group) {
        std::optional<std::string> value;
        if (!configuration.tryGetEffectiveValue(group, "pwfield", value, error)) return false;
        // The remote LDAP default is "*". pam_unix must not consume a hash
        // from the SSSD passwd record or follow its field into shadow.
        return !value || *value == "*" ||
               reject(error, "SSSD password route requires " + group + "/pwfield=*");
    };
    return equals("sssd", "default_domain_suffix", "") &&
           equals("sssd", "full_name_format", "") &&
           equals("sssd", "re_expression", "") &&
           equals("pam", "pam_app_services", "") &&
           equals("pam", "pam_cert_auth", "false") &&
           equals("pam", "pam_passkey_auth", "false") &&
           equals(section, "id_provider", "ldap") &&
           equals(section, "auth_provider", "ldap") &&
           equals(section, "subdomains_provider", "none") &&
           equals(section, "use_fully_qualified_names", "true") &&
           hasLockedNssPassword("nss") &&
           hasLockedNssPassword(section) &&
           equals(section, "full_name_format", "") &&
           equals(section, "re_expression", "") &&
           equals(section, "cache_credentials", "false") &&
           equals(section, "cached_auth_timeout", "0") &&
           equals(section, "ldap_id_use_start_tls", "true") &&
           equals(section, "ldap_tls_reqcert", "demand") &&
           equals(section, "ldap_auth_disable_tls_never_use_in_production", "");
}

bool proveIdentitySources(bool sssd, std::string& error) {
    const auto nss = readTrusted("/etc/nsswitch.conf", 0, 16384, error);
    if (nss.status != SecureStateReadStatus::Proven)
        return reject(error, "MFA NSS configuration cannot be proven");
    std::istringstream lines(nss.content);
    std::string line;
    unsigned passwdRules = 0, shadowRules = 0;
    while (std::getline(lines, line)) {
        line.resize(std::min(line.size(), line.find('#')));
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::istringstream left(line.substr(0, colon));
        std::string key, extra;
        if (!(left >> key) || (left >> extra) || (key != "passwd" && key != "shadow")) continue;
        std::istringstream right(line.substr(colon + 1));
        std::vector<std::string> services;
        for (std::string value; right >> value;) services.push_back(std::move(value));
        if (key == "passwd") {
            ++passwdRules;
            // NSS systemd can return UserDB identities with qualified names,
            // including on fallback after a miss from sss.
            if (sssd && std::find(services.begin(), services.end(), "systemd") != services.end())
                return reject(error, "unsupported NSS passwd route for MFA: systemd can overlap the SSSD namespace");
            if ((!sssd && services != std::vector<std::string>{"files"} &&
                 services != std::vector<std::string>{"files", "systemd"}) ||
                (sssd && services != std::vector<std::string>{"files", "sss"}))
                return reject(error, "unsupported NSS passwd route for MFA");
        } else {
            ++shadowRules;
            // Keep the mixed-route Unix credential source restricted to files.
            if (services != std::vector<std::string>{"files"} &&
                (sssd || services != std::vector<std::string>{"files", "systemd"}))
                return reject(error, "unsupported NSS shadow route for MFA");
        }
    }
    return (passwdRules == 1 && shadowRules == 1) ||
           reject(error, "ambiguous NSS configuration for MFA");
}

bool supportedUnix(const PamRule& rule) {
    return std::all_of(rule.arguments.begin(), rule.arguments.end(), [](const auto& option) {
        return option == "nullok" || option == "nullok_secure" || option == "nullresetok" ||
               option == "try_first_pass" || option == "use_first_pass";
    });
}

bool matchesScope(const fic::platform::PamPlatformConfig& pam, const std::string& service) {
    return std::any_of(pam.scopes.begin(), pam.scopes.end(), [&](const auto& scope) {
        return scope.scope == fic::platform::PamScope::EffectiveAuthenticationStack &&
               std::find(scope.services.begin(), scope.services.end(), service) != scope.services.end();
    });
}

bool proveSources(const PamEffectiveStack& stack, const fs::path& pamDir,
                  const fs::path& service, std::string& error) {
    const std::set<std::string> inertSources{"common-account", "common-password", "common-session"};
    bool commonIncluded = false;
    for (const auto& file : stack.sourceFiles) {
        const auto name = file.filename().string();
        if (file.parent_path() != pamDir ||
            (file != service && name != "common-auth" && name != mfaSlotName &&
             inertSources.count(name) == 0 &&
             name != "fic-empty-password" && name != "fic-faillock-preauth" &&
             name != "fic-faillock-authfail" && name != "fic-faillock-authsucc"))
            return reject(error, "unexpected MFA PAM include source: " + file.string());
        const auto source = readTrusted(file, 0, 1024 * 1024, error);
        std::vector<PamRule> rules;
        if (source.status != SecureStateReadStatus::Proven ||
            !PamConfiguration::parseRulesContent(file, source.content, rules, error))
            return reject(error, "untrusted or invalid MFA PAM source: " + file.string());
        for (const auto& rule : rules) {
            if (inertSources.count(name) &&
                (rule.group == PamManagementGroup::Auth ||
                 rule.includeKind == PamIncludeKind::IncludeAll))
                return reject(error, "unexpected auth rule in non-auth PAM source");
            if (file == service && rule.includeKind == PamIncludeKind::IncludeAll &&
                inertSources.count(rule.includeTarget)) continue;
            if (rule.includeKind == PamIncludeKind::None ||
                (rule.group != PamManagementGroup::Auth &&
                 rule.includeKind != PamIncludeKind::IncludeAll)) continue;
            if (file == service && !commonIncluded && rule.includeTarget == "common-auth" &&
                rule.includeKind != PamIncludeKind::Substack) {
                commonIncluded = true;
                continue;
            }
            if (name == "common-auth" &&
                ((rule.includeKind == PamIncludeKind::Substack &&
                  (rule.includeTarget == mfaSlotName || rule.includeTarget == "fic-empty-password")) ||
                 (rule.includeKind == PamIncludeKind::Include &&
                  (rule.includeTarget == "fic-faillock-preauth" ||
                   rule.includeTarget == "fic-faillock-authfail" ||
                   rule.includeTarget == "fic-faillock-authsucc")))) continue;
            return reject(error, "unexpected MFA PAM include directive");
        }
    }
    return commonIncluded || reject(error, "PAM service does not use common-auth");
}

bool checkRule(const PamRule& rule, const fs::path& primary, const fs::path& service,
               unsigned& unixCount, unsigned& sssCount) {
    const auto source = rule.source.filename().string();
    if (rule.module == "pam_unix.so" && rule.source == primary) {
        ++unixCount;
        return supportedUnix(rule);
    }
    if (rule.module == "pam_sss.so" && rule.source == primary) {
        ++sssCount;
        return rule.arguments == std::vector<std::string>{"use_first_pass"};
    }
    if (rule.module == "pam_deny.so" && rule.arguments.empty()) return true;
    if (rule.source == primary)
        return rule.module == "pam_permit.so" && rule.arguments.empty();
    if (source == "fic-empty-password")
        return (rule.module == "pam_localuser.so" && rule.arguments.empty()) ||
               (rule.module == "pam_unix.so" &&
                rule.arguments == std::vector<std::string>{"use_first_pass"});
    if (rule.module == "pam_faillock.so")
        return (source == "fic-faillock-preauth" && rule.arguments == std::vector<std::string>{"preauth"}) ||
               (source == "fic-faillock-authfail" && rule.arguments == std::vector<std::string>{"authfail"}) ||
               (source == "fic-faillock-authsucc" && rule.arguments == std::vector<std::string>{"authsucc"});
    return rule.source == service &&
           (rule.module == "pam_faildelay.so" || rule.module == "pam_nologin.so" ||
            rule.module == "pam_group.so" || rule.module == "pam_env.so" ||
            rule.module == "pam_rootok.so");
}

} // namespace

bool buildDebian13MfaTopology(const std::vector<PamMfaFactor>& factors,
                             PamMfaTopology& topology, std::string& error) {
    topology = {};
    if (factors != std::vector<PamMfaFactor>{PamMfaFactor::GoogleTotp})
        return reject(error, "unsupported Debian 13 MFA factor set");
    topology.profile = "Name: FIC mandatory MFA hook\nDefault: no\nPriority: -100002\n"
                       "Auth-Type: Additional\nAuth:\n    substack fic-mfa\n";
    topology.neutralSlot = mfaNeutralSlot;
    topology.requiredSlot = mfaRequiredSlot;
    error.clear();
    return true;
}

bool verifyDebian13Mfa(const fic::platform::PlatformProfile& platform,
                      const std::string& service, PamMfaProofTarget target,
                      std::string& error) {
    error.clear();
    const auto& pam = platform.pam;
    if (platform.id != "debian-13" || pam.configDirectories.empty() || !matchesScope(pam, service))
        return reject(error, "unsupported Debian 13 MFA PAM service");
    if (service.empty() || fs::path(service).filename() != service || service == "." || service == "..")
        return reject(error, "invalid MFA PAM service name");
    const auto directory = pam.configDirectories.front();
    const auto primary = directory / "common-auth";
    const auto serviceFile = directory / service;
    const auto factor = directory / mfaSlotName;
    PamMfaTopology topology;
    if (!buildDebian13MfaTopology({PamMfaFactor::GoogleTotp}, topology, error)) return false;
    const auto actual = readTrusted(factor, 0, 4096, error);
    const bool candidate = target == PamMfaProofTarget::Candidate;
    if (actual.status != SecureStateReadStatus::Proven ||
        actual.content != (candidate ? topology.neutralSlot : topology.requiredSlot))
        return reject(error, "MFA slot has unsupported or untrusted content");

    PamConfiguration configuration(pam);
    PamEffectiveStack stack;
    if (!configuration.buildEffectiveStack(service, PamManagementGroup::Auth, stack, error) ||
        !proveSources(stack, directory, serviceFile, error)) return false;
    unsigned unixCount = 0, sssCount = 0, guards = 0, hooks = 0;
    std::set<std::string> modules{google, "pam_succeed_if.so"};
    for (auto& entry : stack.entries) {
        const auto& rule = entry.rule;
        if (!entry.isSubstack()) {
            if (!checkRule(rule, primary, serviceFile, unixCount, sssCount))
                return reject(error, "unsupported MFA authentication rule: " + rule.module);
            modules.insert(rule.module);
            continue;
        }
        if (rule.source != primary || entry.substack.empty())
            return reject(error, "unexpected MFA substack placement");
        if (rule.includeTarget == mfaSlotName) {
            if (++hooks != 1) return reject(error, "duplicate MFA substack");
            if (!matchesMfaSlotRules(entry.substack, factor, actual.content))
                return reject(error, "effective MFA slot differs from the trusted snapshot");
            if (candidate) {
                std::vector<PamRule> rules;
                if (!PamConfiguration::parseRulesContent(factor, topology.requiredSlot, rules, error))
                    return false;
                entry.substack.clear();
                for (auto& parsed : rules) entry.substack.push_back({std::move(parsed), {}});
            }
        } else if (rule.includeTarget == "fic-empty-password" && ++guards == 1) {
            for (const auto& child : entry.substack) {
                if (child.isSubstack() || child.rule.source != directory / "fic-empty-password" ||
                    !checkRule(child.rule, primary, serviceFile, unixCount, sssCount))
                    return reject(error, "unsupported empty-password substack");
                modules.insert(child.rule.module);
            }
        } else {
            return reject(error, "unexpected or duplicate PAM substack");
        }
    }
    if (unixCount != 1 || sssCount > 1 || hooks != 1)
        return reject(error, "MFA requires one Unix Primary and one factor substack");
    for (const auto& module : modules)
        if (!trustedModule(pam, module, error)) return false;
    if (!proveIdentitySources(sssCount != 0, error) ||
        (sssCount && !proveSssdPasswordConfiguration(error))) return false;
    const auto passwd = readTrusted("/etc/passwd", 0, 1024 * 1024, error);
    if (passwd.status != SecureStateReadStatus::Proven)
        return reject(error, "local account namespace cannot be proven");
    if (sssCount) {
        std::istringstream accounts(passwd.content);
        std::string line;
        while (std::getline(accounts, line)) {
            const auto end = line.find(':');
            if (end == std::string::npos || line.substr(0, end).find('@') != std::string::npos)
                return reject(error, "local account overlaps the qualified SSSD namespace");
        }
    }
    return proveTotpStore(error) &&
           proveMfaAuthenticationPaths(stack, pam, primary, factor, sssCount != 0, error);
}

} // namespace fic::identity::pam
