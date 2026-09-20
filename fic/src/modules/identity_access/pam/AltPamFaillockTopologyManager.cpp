#include "modules/identity_access/pam/AltPamFaillockTopologyManager.h"

#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamConfiguration.h"
#include "modules/identity_access/pam/PamPlatformComposition.h"

#include <fic/core/process/ExclusivePidLock.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <optional>
#include <set>
#include <sstream>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fic::identity::pam {
namespace {

struct PhysicalLine {
    std::string text;
    std::string ending;
};

struct TargetSnapshot {
    std::string content;
    dev_t device = 0;
    ino_t inode = 0;
};

enum class ManagedState {
    Absent,
    Present,
    Broken
};

struct ManagedInspection {
    ManagedState state = ManagedState::Absent;
    std::set<std::size_t> blockLines;
    std::set<std::size_t> ruleLines;
    std::optional<std::string> originalAuthLine;
    // Topology strategy proven by the managed block markers. Set only when
    // the inspection proves exactly one supported strategy.
    std::optional<fic::platform::PamFaillockStrategy> strategy;
};

using ManagedTargetRole =
    fic::platform::PamManagedTopologyTargetRole;

bool managesAccount(ManagedTargetRole role) {
    return role == ManagedTargetRole::AuthenticationAndAccount;
}

struct ManagedTargetState {
    fic::platform::PamManagedTopologyTarget target;
    TargetSnapshot snapshot;
    std::vector<PhysicalLine> lines;
    std::vector<PamRule> rules;
    ManagedInspection managed;
    std::string candidate;
};

struct BlockSpec {
    const char* begin;
    const char* rule;
    const char* end;
};

constexpr BlockSpec kSimpleBlocks[] = {
    {AltPamFaillockTopologyManager::AUTHFAIL_BEGIN,
     AltPamFaillockTopologyManager::AUTHFAIL_RULE,
     AltPamFaillockTopologyManager::AUTHFAIL_END},
    {AltPamFaillockTopologyManager::ACCOUNT_BEGIN,
     AltPamFaillockTopologyManager::ACCOUNT_RULE,
     AltPamFaillockTopologyManager::ACCOUNT_END},
    {AltPamFaillockTopologyManager::AUTHSUCC_BEGIN,
     AltPamFaillockTopologyManager::AUTHSUCC_RULE,
     AltPamFaillockTopologyManager::AUTHSUCC_END}
};

std::string hexEncode(const std::string& value) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string encoded;
    encoded.reserve(value.size() * 2);
    for (unsigned char byte : value) {
        encoded.push_back(digits[byte >> 4]);
        encoded.push_back(digits[byte & 0x0f]);
    }
    return encoded;
}

bool hexDecode(const std::string& encoded,
               std::string& value,
               std::string& error) {
    auto digit = [](char character) -> int {
        if (character >= '0' && character <= '9') return character - '0';
        if (character >= 'a' && character <= 'f') return character - 'a' + 10;
        return -1;
    };
    if (encoded.empty() || encoded.size() % 2 != 0) {
        error = "invalid encoded original pam_tcb rule";
        return false;
    }
    value.clear();
    value.reserve(encoded.size() / 2);
    for (std::size_t index = 0; index < encoded.size(); index += 2) {
        const int high = digit(encoded[index]);
        const int low = digit(encoded[index + 1]);
        if (high < 0 || low < 0) {
            error = "invalid encoded original pam_tcb rule";
            value.clear();
            return false;
        }
        value.push_back(static_cast<char>((high << 4) | low));
    }
    return true;
}

std::string canonicalSufficientAuthenticator(const PamRule& rule) {
    std::string result = "auth\tsufficient\t" + rule.module;
    for (const std::string& argument : rule.arguments) {
        result += " " + argument;
    }
    return result;
}

std::string canonicalJumpAuthenticator(const PamRule& rule) {
    std::string result = std::string(
        AltPamFaillockTopologyManager::AUTHSUCC_ANCHOR_RULE_PREFIX) +
        rule.module;
    for (const std::string& argument : rule.arguments) {
        result += " " + argument;
    }
    return result;
}

bool parseSingleAuthenticator(const std::filesystem::path& source,
                              const std::string& content,
                              PamRule& rule,
                              std::string& error) {
    std::vector<PamRule> rules;
    if (!PamConfiguration::parseRulesContent(source, content, rules, error) ||
        rules.size() != 1 || rules.front().group != PamManagementGroup::Auth ||
        rules.front().includeKind != PamIncludeKind::None ||
        std::filesystem::path(rules.front().module).filename() != "pam_tcb.so") {
        if (error.empty()) {
            error = "managed original authentication rule is not one auth pam_tcb.so rule";
        }
        return false;
    }
    rule = std::move(rules.front());
    return true;
}

std::string errnoText() {
    return std::strerror(errno);
}

std::string moduleBaseName(const PamRule& rule) {
    return std::filesystem::path(rule.module).filename().string();
}

std::vector<PhysicalLine> splitLines(const std::string& content) {
    std::vector<PhysicalLine> lines;
    std::size_t offset = 0;
    while (offset < content.size()) {
        const std::size_t newline = content.find('\n', offset);
        if (newline == std::string::npos) {
            lines.push_back({content.substr(offset), {}});
            break;
        }
        std::string text = content.substr(offset, newline - offset);
        std::string ending = "\n";
        if (!text.empty() && text.back() == '\r') {
            text.pop_back();
            ending = "\r\n";
        }
        lines.push_back({std::move(text), std::move(ending)});
        offset = newline + 1;
    }
    return lines;
}

std::string renderLines(const std::vector<PhysicalLine>& lines) {
    std::string result;
    for (const auto& line : lines) {
        result += line.text;
        result += line.ending;
    }
    return result;
}

bool inspectManagedBlocks(const std::vector<PhysicalLine>& lines,
                          ManagedTargetRole role,
                          ManagedInspection& inspection,
                          std::string& error) {
    inspection = ManagedInspection{};
    std::size_t presentBlocks = 0;
    bool authfailPresent = false;
    bool accountPresent = false;
    bool authsuccRulePresent = false;

    std::vector<std::size_t> preauthBegins;
    std::vector<std::size_t> preauthEnds;
    std::vector<std::size_t> authsuccAnchorBegins;
    std::vector<std::size_t> authsuccAnchorEnds;
    std::vector<std::size_t> originalMarkers;
    const std::string preauthRequisiteRule(
        AltPamFaillockTopologyManager::PREAUTH_RULE_REQUISITE);
    const std::string preauthRequiredRule(
        AltPamFaillockTopologyManager::PREAUTH_RULE_REQUIRED);
    for (std::size_t index = 0; index < lines.size(); ++index) {
        if (lines[index].text == AltPamFaillockTopologyManager::PREAUTH_BEGIN) {
            preauthBegins.push_back(index);
        }
        if (lines[index].text == AltPamFaillockTopologyManager::PREAUTH_END) {
            preauthEnds.push_back(index);
        }
        if (lines[index].text ==
                AltPamFaillockTopologyManager::AUTHSUCC_ANCHOR_BEGIN) {
            authsuccAnchorBegins.push_back(index);
        }
        if (lines[index].text ==
                AltPamFaillockTopologyManager::AUTHSUCC_ANCHOR_END) {
            authsuccAnchorEnds.push_back(index);
        }
        if (lines[index].text.compare(
                0,
                std::strlen(
                    AltPamFaillockTopologyManager::ORIGINAL_AUTH_PREFIX),
                AltPamFaillockTopologyManager::ORIGINAL_AUTH_PREFIX) == 0) {
            originalMarkers.push_back(index);
        }
    }
    if (preauthBegins.size() + authsuccAnchorBegins.size() > 1) {
        inspection.state = ManagedState::Broken;
        error = "FIC pam_faillock topology combines preauth and authsucc "
            "strategies";
        return false;
    }
    if (!preauthBegins.empty() || !preauthEnds.empty()) {
        ++presentBlocks;
        if (preauthBegins.size() != 1 || preauthEnds.size() != 1 ||
            preauthBegins.front() + 4 != preauthEnds.front()) {
            inspection.state = ManagedState::Broken;
            error = "partial, duplicated, or modified FIC pam_faillock preauth block";
            return false;
        }
        const std::size_t begin = preauthBegins.front();
        const std::string& preauthRule = lines[begin + 1].text;
        if ((preauthRule != preauthRequisiteRule &&
             preauthRule != preauthRequiredRule) ||
            lines[begin + 2].text.compare(
                0,
                std::strlen(AltPamFaillockTopologyManager::ORIGINAL_AUTH_PREFIX),
                AltPamFaillockTopologyManager::ORIGINAL_AUTH_PREFIX) != 0) {
            inspection.state = ManagedState::Broken;
            error = "modified FIC pam_faillock preauth block content";
            return false;
        }
        inspection.strategy =
            preauthRule == preauthRequisiteRule
                ? std::optional<fic::platform::PamFaillockStrategy>(
                      fic::platform::PamFaillockStrategy::PreauthRequisite)
                : std::optional<fic::platform::PamFaillockStrategy>(
                      fic::platform::PamFaillockStrategy::PreauthRequired);
        const std::string encoded = lines[begin + 2].text.substr(
            std::strlen(AltPamFaillockTopologyManager::ORIGINAL_AUTH_PREFIX));
        std::string original;
        if (!hexDecode(encoded, original, error)) {
            inspection.state = ManagedState::Broken;
            return false;
        }
        PamRule originalRule;
        PamRule managedRule;
        const std::filesystem::path markerSource("<FIC-pam-faillock-marker>");
        if (!parseSingleAuthenticator(
                markerSource, original, originalRule, error) ||
            (originalRule.control != "required" &&
             originalRule.control != "sufficient") ||
            !parseSingleAuthenticator(
                markerSource, lines[begin + 3].text + "\n", managedRule, error) ||
            managedRule.control != "sufficient" ||
            managedRule.module != originalRule.module ||
            managedRule.arguments != originalRule.arguments ||
            lines[begin + 3].text !=
                canonicalSufficientAuthenticator(originalRule)) {
            inspection.state = ManagedState::Broken;
            if (error.empty()) {
                error = "modified FIC-managed pam_tcb authentication rule";
            }
            return false;
        }
        for (std::size_t index = begin; index <= preauthEnds.front(); ++index) {
            inspection.blockLines.insert(index + 1);
        }
        inspection.ruleLines.insert(begin + 2);
        inspection.originalAuthLine = std::move(original);
    }
    if (!authsuccAnchorBegins.empty() || !authsuccAnchorEnds.empty()) {
        ++presentBlocks;
        if (authsuccAnchorBegins.size() != 1 ||
            authsuccAnchorEnds.size() != 1 ||
            authsuccAnchorBegins.front() + 3 !=
                authsuccAnchorEnds.front()) {
            inspection.state = ManagedState::Broken;
            error = "partial, duplicated, or modified FIC pam_faillock "
                "authsucc anchor block";
            return false;
        }
        const std::size_t begin = authsuccAnchorBegins.front();
        if (lines[begin + 1].text.compare(
                0,
                std::strlen(AltPamFaillockTopologyManager::ORIGINAL_AUTH_PREFIX),
                AltPamFaillockTopologyManager::ORIGINAL_AUTH_PREFIX) != 0) {
            inspection.state = ManagedState::Broken;
            error = "modified FIC pam_faillock authsucc anchor block content";
            return false;
        }
        inspection.strategy =
            fic::platform::PamFaillockStrategy::Authsucc;
        const std::string encoded = lines[begin + 1].text.substr(
            std::strlen(AltPamFaillockTopologyManager::ORIGINAL_AUTH_PREFIX));
        std::string original;
        if (!hexDecode(encoded, original, error)) {
            inspection.state = ManagedState::Broken;
            return false;
        }
        PamRule originalRule;
        PamRule managedRule;
        const std::filesystem::path markerSource("<FIC-pam-faillock-marker>");
        if (!parseSingleAuthenticator(
                markerSource, original, originalRule, error) ||
            (originalRule.control != "required" &&
             originalRule.control != "sufficient") ||
            !parseSingleAuthenticator(
                markerSource, lines[begin + 2].text + "\n", managedRule, error) ||
            managedRule.module != originalRule.module ||
            managedRule.arguments != originalRule.arguments ||
            lines[begin + 2].text !=
                canonicalJumpAuthenticator(originalRule)) {
            inspection.state = ManagedState::Broken;
            if (error.empty()) {
                error = "modified FIC-managed pam_tcb authentication rule";
            }
            return false;
        }
        for (std::size_t index = begin;
                index <= authsuccAnchorEnds.front(); ++index) {
            inspection.blockLines.insert(index + 1);
        }
        inspection.ruleLines.insert(begin + 2);
        inspection.originalAuthLine = std::move(original);
    }

    for (const BlockSpec& block : kSimpleBlocks) {
        std::vector<std::size_t> begins;
        std::vector<std::size_t> ends;
        for (std::size_t index = 0; index < lines.size(); ++index) {
            if (lines[index].text == block.begin) {
                begins.push_back(index);
            }
            if (lines[index].text == block.end) {
                ends.push_back(index);
            }
        }
        if (begins.empty() && ends.empty()) {
            continue;
        }
        ++presentBlocks;
        authfailPresent = authfailPresent ||
            std::strcmp(block.begin,
                        AltPamFaillockTopologyManager::AUTHFAIL_BEGIN) == 0;
        accountPresent = accountPresent ||
            std::strcmp(block.begin,
                        AltPamFaillockTopologyManager::ACCOUNT_BEGIN) == 0;
        authsuccRulePresent = authsuccRulePresent ||
            std::strcmp(block.begin,
                        AltPamFaillockTopologyManager::AUTHSUCC_BEGIN) == 0;
        if (begins.size() != 1 || ends.size() != 1 ||
            begins.front() + 2 != ends.front() ||
            lines[begins.front() + 1].text != block.rule) {
            inspection.state = ManagedState::Broken;
            error = "partial, duplicated, or modified FIC pam_faillock block: " +
                std::string(block.begin);
            return false;
        }
        for (std::size_t index = begins.front(); index <= ends.front(); ++index) {
            inspection.blockLines.insert(index + 1);
        }
        inspection.ruleLines.insert(begins.front() + 2);
    }
    for (const auto& line : lines) {
        if (line.text.find("FIC pam_faillock") != std::string::npos &&
            line.text != AltPamFaillockTopologyManager::PREAUTH_BEGIN &&
            line.text != AltPamFaillockTopologyManager::PREAUTH_END &&
            line.text != AltPamFaillockTopologyManager::AUTHSUCC_ANCHOR_BEGIN &&
            line.text != AltPamFaillockTopologyManager::AUTHSUCC_ANCHOR_END &&
            std::none_of(std::begin(kSimpleBlocks), std::end(kSimpleBlocks),
                [&line](const BlockSpec& block) {
                    return line.text == block.begin || line.text == block.end;
                })) {
            inspection.state = ManagedState::Broken;
            error = "unrecognized FIC pam_faillock marker";
            return false;
        }
    }
    const std::size_t expectedOriginalMarkers =
        preauthBegins.empty() && authsuccAnchorBegins.empty() ? 0U : 1U;
    if (originalMarkers.size() != expectedOriginalMarkers) {
        inspection.state = ManagedState::Broken;
        error = "orphaned or duplicated FIC original pam_tcb marker";
        return false;
    }
    if (presentBlocks == 0) {
        inspection.state = ManagedState::Absent;
        inspection.strategy.reset();
        error.clear();
        return true;
    }
    const bool preauthStrategy = preauthBegins.size() == 1;
    const bool authsuccStrategy = authsuccAnchorBegins.size() == 1;
    // authsucc strategy has no account pam_faillock rule by design; the
    // original account pam_tcb anchor stays untouched.
    const bool expectedAccount = managesAccount(role) && !authsuccStrategy;
    const std::size_t expectedBlocks =
        (preauthStrategy || authsuccStrategy ? 1U : 0U) + 1U +
        (authsuccStrategy ? 1U : 0U) + (expectedAccount ? 1U : 0U);
    if (presentBlocks != expectedBlocks ||
        !(preauthStrategy || authsuccStrategy) ||
        !authfailPresent ||
        authsuccRulePresent != authsuccStrategy ||
        accountPresent != expectedAccount) {
        inspection.state = ManagedState::Broken;
        error = "incomplete FIC pam_faillock managed topology";
        return false;
    }
    if (preauthStrategy && authsuccRulePresent) {
        inspection.state = ManagedState::Broken;
        error = "FIC pam_faillock topology combines preauth and authsucc "
            "strategies";
        return false;
    }
    inspection.state = ManagedState::Present;
    error.clear();
    return true;
}

bool parseTarget(const std::filesystem::path& path,
                 const std::string& content,
                 std::vector<PamRule>& rules,
                 std::string& error) {
    return PamConfiguration::parseRulesContent(path, content, rules, error);
}

bool hasExternalFaillock(const std::vector<PamRule>& rules,
                         const ManagedInspection& managed) {
    return std::any_of(rules.begin(), rules.end(),
        [&managed](const PamRule& rule) {
            return moduleBaseName(rule) == "pam_faillock.so" &&
                managed.ruleLines.find(rule.line) == managed.ruleLines.end();
        });
}

enum class ExternalFaillockGraphState { Clear, Present, Error };

ExternalFaillockGraphState inspectExternalFaillockInRelevantGraph(
    const fic::platform::PamPlatformConfig& platformConfig,
    const std::vector<ManagedTargetState>& managedTargets,
    std::string& error) {
    PamConfiguration configuration(platformConfig);
    const fic::platform::PamCapabilityConfig* capability = nullptr;
    const std::vector<std::string>* configuredServices = nullptr;
    if (!resolveCapability(
            platformConfig, PamCapability::AuthenticationLockout,
            capability, configuredServices, error)) {
        return ExternalFaillockGraphState::Error;
    }
    std::vector<std::string> services;
    if (!configuration.existingServices(
            *configuredServices, services, error)) {
        return ExternalFaillockGraphState::Error;
    }
    if (services.empty()) {
        error = "none of the configured PAM authentication services exists";
        return ExternalFaillockGraphState::Error;
    }
    for (const std::string& service : services) {
        for (const PamManagementGroup group : {
                 PamManagementGroup::Auth, PamManagementGroup::Account}) {
            std::vector<PamRule> rules;
            if (!configuration.collectRules(
                    service, group, rules, error)) {
                return ExternalFaillockGraphState::Error;
            }
            for (const PamRule& rule : rules) {
                if (moduleBaseName(rule) != "pam_faillock.so") {
                    continue;
                }
                const bool owned = std::any_of(
                    managedTargets.begin(), managedTargets.end(),
                    [&rule](const ManagedTargetState& target) {
                        return rule.source.lexically_normal() ==
                                target.target.path.lexically_normal() &&
                            target.managed.ruleLines.find(rule.line) !=
                                target.managed.ruleLines.end();
                    });
                if (!owned) {
                    error = "external pam_faillock topology is effective for PAM "
                        "service " + service + " at " + rule.source.string() +
                        ":" + std::to_string(rule.line);
                    return ExternalFaillockGraphState::Present;
                }
            }
        }
    }
    error.clear();
    return ExternalFaillockGraphState::Clear;
}

bool inspectSecureTarget(const std::filesystem::path& path,
                         TargetSnapshot& snapshot,
                         std::string& error) {
    struct stat linkInfo {};
    if (::lstat(path.c_str(), &linkInfo) != 0) {
        error = "could not inspect PAM topology target " + path.string() +
            ": " + errnoText();
        return false;
    }
    if (S_ISLNK(linkInfo.st_mode)) {
        error = "refusing symbolic-link PAM topology target: " + path.string();
        return false;
    }
    if (!S_ISREG(linkInfo.st_mode)) {
        error = "PAM topology target is not a regular file: " + path.string();
        return false;
    }
    if (linkInfo.st_uid != ::geteuid()) {
        error = "PAM topology target is not owned by the current privileged user: " +
            path.string();
        return false;
    }
    if ((linkInfo.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        error = "PAM topology target is writable by group or others: " +
            path.string();
        return false;
    }

    int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        error = "could not securely open PAM topology target " + path.string() +
            ": " + errnoText();
        return false;
    }
    struct stat openedInfo {};
    if (::fstat(descriptor, &openedInfo) != 0 ||
        openedInfo.st_dev != linkInfo.st_dev || openedInfo.st_ino != linkInfo.st_ino ||
        !S_ISREG(openedInfo.st_mode)) {
        const std::string detail = errno == 0 ? "target changed during open" : errnoText();
        ::close(descriptor);
        error = "could not verify opened PAM topology target " + path.string() +
            ": " + detail;
        return false;
    }
    snapshot.content.clear();
    char buffer[4096];
    for (;;) {
        const ssize_t count = ::read(descriptor, buffer, sizeof(buffer));
        if (count > 0) {
            snapshot.content.append(buffer, static_cast<std::size_t>(count));
            continue;
        }
        if (count == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        const std::string detail = errnoText();
        ::close(descriptor);
        error = "could not read PAM topology target " + path.string() +
            ": " + detail;
        return false;
    }
    if (::close(descriptor) != 0) {
        error = "could not close PAM topology target " + path.string() +
            ": " + errnoText();
        return false;
    }
    snapshot.device = openedInfo.st_dev;
    snapshot.inode = openedInfo.st_ino;
    error.clear();
    return true;
}

bool targetStillMatches(const std::filesystem::path& path,
                        const TargetSnapshot& snapshot,
                        std::string& error) {
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_dev != snapshot.device || info.st_ino != snapshot.inode) {
        error = "PAM topology target changed before atomic write: " + path.string();
        return false;
    }
    return true;
}

AtomicWriteOptions writeOptionsForSnapshot(
    const AtomicWriteOptions& base,
    const TargetSnapshot& snapshot) {
    AtomicWriteOptions result = base;
    result.expectedTargetIdentity =
        AtomicTargetIdentity{snapshot.device, snapshot.inode};
    return result;
}

PhysicalLine generatedLine(std::string text) {
    return {std::move(text), "\n"};
}

void appendBlock(std::vector<PhysicalLine>& output, const BlockSpec& block) {
    output.push_back(generatedLine(block.begin));
    output.push_back(generatedLine(block.rule));
    output.push_back(generatedLine(block.end));
}

const char* preauthRuleForStrategy(
    fic::platform::PamFaillockStrategy strategy) {
    return strategy == fic::platform::PamFaillockStrategy::PreauthRequired
        ? AltPamFaillockTopologyManager::PREAUTH_RULE_REQUIRED
        : AltPamFaillockTopologyManager::PREAUTH_RULE_REQUISITE;
}

void appendPreauthBlock(std::vector<PhysicalLine>& output,
                        fic::platform::PamFaillockStrategy strategy,
                        const PhysicalLine& original,
                        const PamRule& authRule) {
    output.push_back(generatedLine(
        AltPamFaillockTopologyManager::PREAUTH_BEGIN));
    output.push_back(generatedLine(
        preauthRuleForStrategy(strategy)));
    output.push_back(generatedLine(
        std::string(AltPamFaillockTopologyManager::ORIGINAL_AUTH_PREFIX) +
        hexEncode(original.text + original.ending)));
    output.push_back(generatedLine(
        canonicalSufficientAuthenticator(authRule)));
    output.push_back(generatedLine(
        AltPamFaillockTopologyManager::PREAUTH_END));
}

void appendAuthsuccAnchorBlock(std::vector<PhysicalLine>& output,
                               const PhysicalLine& original,
                               const PamRule& authRule) {
    output.push_back(generatedLine(
        AltPamFaillockTopologyManager::AUTHSUCC_ANCHOR_BEGIN));
    output.push_back(generatedLine(
        std::string(AltPamFaillockTopologyManager::ORIGINAL_AUTH_PREFIX) +
        hexEncode(original.text + original.ending)));
    output.push_back(generatedLine(
        canonicalJumpAuthenticator(authRule)));
    output.push_back(generatedLine(
        AltPamFaillockTopologyManager::AUTHSUCC_ANCHOR_END));
}

bool findAnchors(const std::vector<PamRule>& rules,
                 const std::vector<PhysicalLine>& lines,
                 ManagedTargetRole role,
                 std::size_t& authLine,
                 std::size_t& accountLine,
                 std::string& error) {
    std::vector<const PamRule*> authCandidates;
    std::vector<const PamRule*> accountCandidates;
    for (const auto& rule : rules) {
        if (rule.includeKind != PamIncludeKind::None ||
            moduleBaseName(rule) != "pam_tcb.so") {
            continue;
        }
        if (rule.group == PamManagementGroup::Auth) {
            authCandidates.push_back(&rule);
        } else if (rule.group == PamManagementGroup::Account) {
            accountCandidates.push_back(&rule);
        }
    }
    if (authCandidates.size() != 1) {
        error = "expected exactly one local auth pam_tcb.so anchor, found " +
            std::to_string(authCandidates.size());
        return false;
    }
    const std::size_t expectedAccountAnchors = managesAccount(role) ? 1U : 0U;
    if (accountCandidates.size() != expectedAccountAnchors) {
        error = "expected " + std::to_string(expectedAccountAnchors) +
            " local account pam_tcb.so anchor(s), found " +
            std::to_string(accountCandidates.size());
        return false;
    }
    const PamRule& auth = *authCandidates.front();
    // The authsucc strategy replaces the plain anchor with the canonical
    // jump authenticator (success skips the authfail accounting into the
    // authsucc rule), so its exact control is a valid anchor control too.
    const std::string authsuccAnchorControl = "[success=1 default=bad]";
    if ((auth.control != "required" && auth.control != "sufficient" &&
         auth.control != authsuccAnchorControl) ||
        (managesAccount(role) &&
         accountCandidates.front()->control != "required")) {
        error = "unsupported pam_tcb.so control topology in ALT local stack";
        return false;
    }
    accountLine = managesAccount(role) ? accountCandidates.front()->line : 0;
    if (auth.line == 0 || auth.line > lines.size() ||
        (managesAccount(role) &&
         (accountLine == 0 || accountLine > lines.size())) ||
        (!lines[auth.line - 1].text.empty() &&
         lines[auth.line - 1].text.back() == '\\') ||
        (managesAccount(role) &&
         !lines[accountLine - 1].text.empty() &&
         lines[accountLine - 1].text.back() == '\\')) {
        error = "unsupported continued or invalid pam_tcb.so anchor line";
        return false;
    }
    authLine = auth.line;
    return true;
}

bool verifyManagedPlacement(const std::vector<PamRule>& rules,
                            const std::vector<PhysicalLine>& lines,
                            ManagedTargetRole role,
                            const ManagedInspection& managed,
                            std::string& error) {
    std::size_t authLine = 0;
    std::size_t accountLine = 0;
    if (!findAnchors(rules, lines, role, authLine, accountLine, error)) {
        return false;
    }
    const auto preauth = std::find_if(
        lines.begin(), lines.end(), [](const PhysicalLine& line) {
            return line.text ==
                AltPamFaillockTopologyManager::PREAUTH_BEGIN;
        });
    const auto authsuccAnchor = std::find_if(
        lines.begin(), lines.end(), [](const PhysicalLine& line) {
            return line.text ==
                AltPamFaillockTopologyManager::AUTHSUCC_ANCHOR_BEGIN;
        });
    const auto authfail = std::find_if(
        lines.begin(), lines.end(), [](const PhysicalLine& line) {
            return line.text ==
                AltPamFaillockTopologyManager::AUTHFAIL_BEGIN;
        });
    const auto account = std::find_if(
        lines.begin(), lines.end(), [](const PhysicalLine& line) {
            return line.text ==
                AltPamFaillockTopologyManager::ACCOUNT_BEGIN;
        });
    const bool authsucc = managed.strategy ==
        std::optional<fic::platform::PamFaillockStrategy>(
            fic::platform::PamFaillockStrategy::Authsucc);
    const bool needsAccountBlock = managesAccount(role) && !authsucc;
    const auto primary = authsucc ? authsuccAnchor : preauth;
    if (primary == lines.end() || authfail == lines.end() ||
        (authsucc ? preauth != lines.end() : authsuccAnchor != lines.end()) ||
        (needsAccountBlock ? account == lines.end()
                           : account != lines.end())) {
        error = "complete FIC pam_faillock markers are missing or mixed "
            "strategies are present";
        return false;
    }
    const std::size_t primaryIndex =
        static_cast<std::size_t>(std::distance(lines.begin(), primary));
    const std::size_t authfailIndex =
        static_cast<std::size_t>(std::distance(lines.begin(), authfail));
    if (authsucc) {
        // anchor block: begin, original marker, replacement, end
        if (authLine != primaryIndex + 3 ||
            authfailIndex != primaryIndex + 4) {
            error = "FIC pam_faillock blocks are not at the required "
                "pam_tcb anchors";
            return false;
        }
        const auto authsuccRule = std::find_if(
            lines.begin(), lines.end(), [](const PhysicalLine& line) {
                return line.text ==
                    AltPamFaillockTopologyManager::AUTHSUCC_BEGIN;
            });
        if (authsuccRule == lines.end() ||
            static_cast<std::size_t>(
                std::distance(lines.begin(), authsuccRule)) !=
                authfailIndex + 3) {
            error = "FIC pam_faillock authsucc rule block is not at the "
                "required position";
            return false;
        }
    } else {
        // preauth block: begin, rule, original marker, replacement, end
        if (authLine != primaryIndex + 4 ||
            authfailIndex != primaryIndex + 5) {
            error = "FIC pam_faillock blocks are not at the required "
                "pam_tcb anchors";
            return false;
        }
        if (needsAccountBlock) {
            const std::size_t accountIndex =
                static_cast<std::size_t>(
                    std::distance(lines.begin(), account));
            if (accountLine != accountIndex + 4) {
                error = "FIC pam_faillock account block is not at the "
                    "required pam_tcb anchor";
                return false;
            }
        }
    }
    error.clear();
    return true;
}

bool verifyNoExecutableAuthTail(
    const std::vector<PamRule>& rules,
    const std::vector<PhysicalLine>& lines,
    ManagedTargetRole role,
    const ManagedInspection& managed,
    std::string& error) {
    std::size_t authLine = 0;
    std::size_t accountLine = 0;
    if (!findAnchors(rules, lines, role, authLine, accountLine, error)) {
        return false;
    }
    (void)accountLine;
    for (const PamRule& rule : rules) {
        if (rule.group == PamManagementGroup::Auth && rule.line > authLine &&
            managed.ruleLines.find(rule.line) == managed.ruleLines.end()) {
            error = "executable auth rule follows the pam_tcb.so anchor at " +
                rule.source.string() + ":" + std::to_string(rule.line);
            return false;
        }
    }
    error.clear();
    return true;
}

std::string buildEnabledContent(
    fic::platform::PamFaillockStrategy strategy,
    const std::vector<PhysicalLine>& lines,
    const std::vector<PamRule>& rules,
    ManagedTargetRole role,
    std::size_t authLine,
    std::size_t accountLine) {
    std::vector<PhysicalLine> output;
    output.reserve(lines.size() + 12);
    const auto authRule = std::find_if(
        rules.begin(), rules.end(), [authLine](const PamRule& rule) {
            return rule.line == authLine &&
                rule.group == PamManagementGroup::Auth &&
                moduleBaseName(rule) == "pam_tcb.so";
        });
    for (std::size_t line = 1; line <= lines.size(); ++line) {
        if (line == authLine) {
            if (strategy == fic::platform::PamFaillockStrategy::Authsucc) {
                appendAuthsuccAnchorBlock(output, lines[line - 1], *authRule);
                appendBlock(output, kSimpleBlocks[0]);
                appendBlock(output, kSimpleBlocks[2]);
                continue;
            }
            appendPreauthBlock(output, strategy, lines[line - 1], *authRule);
            appendBlock(output, kSimpleBlocks[0]);
            continue;
        }
        if (managesAccount(role) &&
            strategy != fic::platform::PamFaillockStrategy::Authsucc &&
            line == accountLine) {
            appendBlock(output, kSimpleBlocks[1]);
        }
        output.push_back(lines[line - 1]);
    }
    return renderLines(output);
}

std::string buildDisabledContent(const std::vector<PhysicalLine>& lines,
                                 const ManagedInspection& managed) {
    std::string output;
    for (std::size_t line = 1; line <= lines.size(); ++line) {
        // Both the preauth block and the authsucc anchor block carry the
        // hex-encoded original pam_tcb authentication rule; either marker
        // restores it byte-for-byte. Skipping this for the authsucc anchor
        // would delete the original authentication rule on disable or on
        // any transition away from the authsucc strategy.
        if (lines[line - 1].text ==
                AltPamFaillockTopologyManager::PREAUTH_BEGIN ||
            lines[line - 1].text ==
                AltPamFaillockTopologyManager::AUTHSUCC_ANCHOR_BEGIN) {
            output += managed.originalAuthLine.value_or("");
        }
        if (managed.blockLines.find(line) == managed.blockLines.end()) {
            output += lines[line - 1].text;
            output += lines[line - 1].ending;
        }
    }
    return output;
}

bool parseAndInspect(const std::filesystem::path& path,
                     const std::string& content,
                     ManagedTargetRole role,
                     std::vector<PhysicalLine>& lines,
                     std::vector<PamRule>& rules,
                     ManagedInspection& managed,
                     std::string& error) {
    lines = splitLines(content);
    if (!parseTarget(path, content, rules, error)) {
        return false;
    }
    return inspectManagedBlocks(lines, role, managed, error);
}

bool loadManagedTargets(
    const fic::platform::PamCapabilityConfig& capability,
    std::vector<ManagedTargetState>& targets,
    std::string& error) {
    targets.clear();
    targets.reserve(capability.managedTopologyTargets.size());
    for (const auto& configured : capability.managedTopologyTargets) {
        ManagedTargetState target;
        target.target = configured;
        if (!inspectSecureTarget(configured.path, target.snapshot, error) ||
            !parseAndInspect(
                configured.path, target.snapshot.content, configured.role,
                target.lines, target.rules, target.managed, error)) {
            error = "could not inspect managed PAM target " +
                configured.path.string() + ": " + error;
            return false;
        }
        targets.push_back(std::move(target));
    }
    error.clear();
    return true;
}

bool validatePresentTarget(const ManagedTargetState& target,
                           std::string& error) {
    if (target.managed.state != ManagedState::Present) {
        error = "managed PAM target is not enabled: " +
            target.target.path.string();
        return false;
    }
    if (hasExternalFaillock(target.rules, target.managed)) {
        error = "FIC pam_faillock blocks coexist with external topology in " +
            target.target.path.string();
        return false;
    }
    if (!verifyManagedPlacement(
            target.rules, target.lines, target.target.role,
            target.managed, error)) {
        error = "FIC pam_faillock placement is invalid in " +
            target.target.path.string() + ": " + error;
        return false;
    }
    if (!verifyNoExecutableAuthTail(
            target.rules, target.lines, target.target.role,
            target.managed, error)) {
        error = "FIC pam_faillock target has an unsafe auth tail in " +
            target.target.path.string() + ": " + error;
        return false;
    }
    error.clear();
    return true;
}

bool prepareEnabledCandidate(ManagedTargetState& target,
                             fic::platform::PamFaillockStrategy strategy,
                             std::string& error) {
    if (target.managed.state != ManagedState::Absent) {
        error = "managed PAM target is not disabled: " +
            target.target.path.string();
        return false;
    }
    if (hasExternalFaillock(target.rules, target.managed)) {
        error = "external pam_faillock topology already exists in " +
            target.target.path.string() + "; FIC will not take ownership";
        return false;
    }
    std::size_t authLine = 0;
    std::size_t accountLine = 0;
    if (!findAnchors(
            target.rules, target.lines, target.target.role,
            authLine, accountLine, error) ||
        !verifyNoExecutableAuthTail(
            target.rules, target.lines, target.target.role,
            target.managed, error)) {
        error = "unsafe ALT local authentication topology in " +
            target.target.path.string() + ": " + error;
        return false;
    }
    target.candidate = buildEnabledContent(
        strategy, target.lines, target.rules, target.target.role,
        authLine, accountLine);
    ManagedTargetState checked;
    checked.target = target.target;
    checked.snapshot.content = target.candidate;
    if (!parseAndInspect(
            checked.target.path, checked.snapshot.content,
            checked.target.role, checked.lines, checked.rules,
            checked.managed, error) ||
        !validatePresentTarget(checked, error)) {
        error = "generated PAM topology is invalid for " +
            target.target.path.string() + ": " + error;
        return false;
    }
    error.clear();
    return true;
}

bool buildTransitionCandidate(
    ManagedTargetState& target,
    fic::platform::PamFaillockStrategy strategy,
    std::string& error) {
    if (target.managed.state != ManagedState::Present) {
        error = "managed PAM target is not enabled: " +
            target.target.path.string();
        return false;
    }
    // Strip the currently enabled FIC blocks, restoring the original
    // pam_tcb anchor, then rebuild the topology with the requested strategy.
    const std::string stripped = buildDisabledContent(
        target.lines, target.managed);
    ManagedTargetState rebuilt;
    rebuilt.target = target.target;
    rebuilt.snapshot.content = stripped;
    if (!parseAndInspect(
            rebuilt.target.path, stripped, rebuilt.target.role,
            rebuilt.lines, rebuilt.rules, rebuilt.managed, error) ||
        rebuilt.managed.state != ManagedState::Absent) {
        error = "could not restore the original PAM topology for a strategy "
            "transition in " + target.target.path.string() + ": " + error;
        return false;
    }
    if (!prepareEnabledCandidate(rebuilt, strategy, error)) {
        error = "could not build the requested pam_faillock strategy "
            "topology in " + target.target.path.string() + ": " + error;
        return false;
    }
    target.candidate = rebuilt.candidate;
    return true;
}

bool restoreOriginalTargets(
    const std::vector<ManagedTargetState>& originals,
    const AltPamFaillockTopologyOptions& options,
    const std::string& failure,
    std::string& error,
    std::size_t targetCount = std::numeric_limits<std::size_t>::max()) {
    std::string rollbackFailures;
    const std::size_t restoreCount = std::min(targetCount, originals.size());
    for (std::size_t index = restoreCount; index > 0; --index) {
        const auto& original = originals[index - 1];
        TargetSnapshot current;
        std::string targetError;
        if (!inspectSecureTarget(
                original.target.path, current, targetError)) {
            if (!rollbackFailures.empty()) rollbackFailures += "; ";
            rollbackFailures += original.target.path.string() + ": " +
                targetError;
            continue;
        }
        if (current.content != original.snapshot.content &&
            !options.writer(
                original.target.path.string(), original.snapshot.content,
                writeOptionsForSnapshot(options.writeOptions, current),
                &targetError)) {
            if (!rollbackFailures.empty()) rollbackFailures += "; ";
            rollbackFailures += original.target.path.string() +
                ": rollback write failed: " + targetError;
            continue;
        }
        TargetSnapshot restored;
        std::vector<PhysicalLine> restoredLines;
        std::vector<PamRule> restoredRules;
        ManagedInspection restoredManaged;
        if (!inspectSecureTarget(
                original.target.path, restored, targetError) ||
            restored.content != original.snapshot.content ||
            !parseAndInspect(
                original.target.path, restored.content,
                original.target.role, restoredLines, restoredRules,
                restoredManaged, targetError)) {
            if (!rollbackFailures.empty()) rollbackFailures += "; ";
            rollbackFailures += original.target.path.string() +
                ": rollback verification failed: " + targetError;
        }
    }
    if (!rollbackFailures.empty()) {
        error = failure + "; CRITICAL: rollback failed: " + rollbackFailures +
            "; PAM configuration may be inconsistent";
        return false;
    }
    error = failure + "; original PAM configuration restored";
    return false;
}

bool writeCandidates(
    const std::vector<ManagedTargetState>& targets,
    const AltPamFaillockTopologyOptions& options,
    const std::string& action,
    std::string& error) {
    for (std::size_t index = 0; index < targets.size(); ++index) {
        const auto& target = targets[index];
        if (!targetStillMatches(
                target.target.path, target.snapshot, error)) {
            return restoreOriginalTargets(
                targets, options,
                "could not " + action + " FIC pam_faillock topology: " +
                    error,
                error, index);
        }
        std::string writeError;
        if (!options.writer(
                target.target.path.string(), target.candidate,
                writeOptionsForSnapshot(options.writeOptions, target.snapshot),
                &writeError)) {
            return restoreOriginalTargets(
                targets, options,
                "could not atomically " + action +
                    " FIC pam_faillock topology at " +
                    target.target.path.string() + ": " + writeError,
                error, index);
        }
    }
    error.clear();
    return true;
}

} // namespace

AltPamFaillockTopologyManager::AltPamFaillockTopologyManager(
    fic::platform::PamPlatformConfig platformConfig,
    AltPamFaillockTopologyOptions options)
    : platformConfig_(std::move(platformConfig)), options_(std::move(options)) {
    if (!options_.writer) {
        options_.writer = AtomicFileWriter::write;
    }
    options_.writeOptions.createIfMissing = false;
    options_.writeOptions.rejectSymlink = true;
    options_.writeOptions.exclusiveCreate = false;
}

bool AltPamFaillockTopologyManager::confirmDurable(
    std::string& error) const {
    const auto* capability = capabilityConfig(
        platformConfig_, PamCapability::AuthenticationLockout);
    if (capability == nullptr || capability->managedTopologyTargets.empty()) {
        error = "ALT pam_faillock has no managed targets for durability proof";
        return false;
    }
    std::vector<std::pair<std::filesystem::path, AtomicTargetState>> states;
    for (const auto& target : capability->managedTopologyTargets) {
        AtomicTargetState snapshot;
        if (!AtomicFileWriter::captureTargetState(
                target.path.string(), snapshot, &error) ||
            !AtomicFileWriter::ensureTargetDurableIfCurrentState(
                target.path.string(), snapshot, &error))
            return false;
        states.emplace_back(target.path, std::move(snapshot));
    }
    for (const auto& [path, snapshot] : states) {
        if (!AtomicFileWriter::targetStateMatches(
                path.string(), snapshot, &error))
            return false;
    }
    error.clear();
    return true;
}

bool AltPamFaillockTopologyManager::verifySemanticEffectiveness(
    std::string& error) const {
    if (options_.semanticVerifier) {
        return options_.semanticVerifier(error);
    }
    PamConfiguration configuration(platformConfig_);
    const auto* capability = capabilityConfig(
        platformConfig_, PamCapability::AuthenticationLockout);
    const std::vector<std::string>* configuredServices = nullptr;
    if (capability == nullptr ||
        !resolveCapability(
            platformConfig_, PamCapability::AuthenticationLockout,
            capability, configuredServices, error) ||
        configuredServices == nullptr) {
        if (error.empty()) {
            error = "ALT pam_faillock capability services are unavailable";
        }
        return false;
    }

    std::vector<std::string> services;
    for (const auto& target : capability->managedTopologyTargets) {
        if (managesAccount(target.role)) {
            services.push_back(target.path.filename().string());
        }
    }
    std::vector<std::string> existingServices;
    if (!configuration.existingServices(
            *configuredServices, existingServices, error)) {
        return false;
    }
    for (const std::string& service : existingServices) {
        std::vector<PamRule> authRules;
        if (!configuration.collectRules(
                service, PamManagementGroup::Auth, authRules, error)) {
            return false;
        }
        const bool usesAuthenticationTarget = std::any_of(
            authRules.begin(), authRules.end(),
            [&](const PamRule& rule) {
                return std::any_of(
                    capability->managedTopologyTargets.begin(),
                    capability->managedTopologyTargets.end(),
                    [&](const auto& target) {
                        return !managesAccount(target.role) &&
                            rule.source.lexically_normal() ==
                                target.path.lexically_normal();
                    });
            });
        if (usesAuthenticationTarget &&
            std::find(services.begin(), services.end(), service) ==
                services.end()) {
            services.push_back(service);
        }
    }
    if (services.empty()) {
        error = "ALT pam_faillock topology has no verification services";
        return false;
    }
    PamCapabilityVerification verification;
    if (!PamCapabilityVerifier::verify(
            configuration,
            platformConfig_,
            services,
            PamCapability::AuthenticationLockout,
            PamProviderKind::PamFaillock,
            verification)) {
        error = formatPamCapabilityVerification(verification);
        return false;
    }
    error.clear();
    return true;
}

bool AltPamFaillockTopologyManager::status(
    AltPamFaillockTopologyState& state,
    std::string& error) {
    std::optional<fic::platform::PamFaillockStrategy> strategy;
    return status(state, strategy, error);
}

bool AltPamFaillockTopologyManager::status(
    AltPamFaillockTopologyState& state,
    std::optional<fic::platform::PamFaillockStrategy>& strategy,
    std::string& error) {
    const auto* capability = capabilityConfig(
        platformConfig_, PamCapability::AuthenticationLockout);
    if (!canEnable(error) || capability == nullptr) {
        return false;
    }
    ExclusivePidLock lock(
        options_.lockFilePath.string(), options_.lockDebugLogPath.string(), false);
    if (!lock.acquire()) {
        error = "could not acquire PAM topology lock: " +
            options_.lockFilePath.string();
        return false;
    }
    std::vector<ManagedTargetState> targets;
    if (!loadManagedTargets(*capability, targets, error)) {
        return false;
    }
    const std::size_t present = static_cast<std::size_t>(std::count_if(
        targets.begin(), targets.end(), [](const ManagedTargetState& target) {
            return target.managed.state == ManagedState::Present;
        }));
    if (present == 0) {
        state = AltPamFaillockTopologyState::Disabled;
        error.clear();
        return true;
    }
    if (present != targets.size()) {
        error = "partial FIC pam_faillock topology across managed targets";
        return false;
    }
    std::optional<fic::platform::PamFaillockStrategy> detected =
        targets.front().managed.strategy;
    for (const auto& target : targets) {
        if (target.managed.strategy != detected) {
            error = "mixed FIC pam_faillock strategies across managed targets";
            return false;
        }
    }
    const auto externalGraph = inspectExternalFaillockInRelevantGraph(
        platformConfig_, targets, error);
    if (externalGraph == ExternalFaillockGraphState::Error) {
        error = "could not inspect relevant PAM graph for external "
            "pam_faillock topology: " + error;
        return false;
    }
    if (externalGraph == ExternalFaillockGraphState::Present) {
        error = "FIC pam_faillock blocks coexist with external pam_faillock "
            "topology: " + error;
        return false;
    }
    if (!verifySemanticEffectiveness(error)) {
        error = "FIC pam_faillock topology is not effective: " + error;
        return false;
    }
    strategy = detected;
    state = AltPamFaillockTopologyState::Enabled;
    return true;
}

bool AltPamFaillockTopologyManager::inspect(PamTopologyStatus& result,
                                            std::string& error)
{
    AltPamFaillockTopologyState current;
    std::optional<fic::platform::PamFaillockStrategy> strategy;
    if (!status(current, strategy, error)) {
        result = {PamTopologyState::Broken, true, {}, error};
        return false;
    }
    result.state = current == AltPamFaillockTopologyState::Enabled
        ? PamTopologyState::Enabled
        : PamTopologyState::Disabled;
    result.manageable = true;
    result.activeStrategy =
        result.state == PamTopologyState::Enabled ? strategy : std::nullopt;
    result.detail.clear();
    return true;
}

bool AltPamFaillockTopologyManager::canEnable(std::string& error) const
{
    const auto* capability = capabilityConfig(
        platformConfig_, PamCapability::AuthenticationLockout);
    if (capability == nullptr ||
        capability->topology !=
            fic::platform::PamTopologyStrategyKind::AltTcbManaged ||
        capability->managedTopologyTargets.empty() ||
        options_.lockFilePath.empty()) {
        error = "ALT pam_faillock topology is unsupported by this platform profile";
        return false;
    }
    std::set<std::filesystem::path> paths;
    std::size_t accountTargets = 0;
    for (const auto& target : capability->managedTopologyTargets) {
        if (target.path.empty() || !target.path.is_absolute() ||
            target.path.lexically_normal() != target.path ||
            !paths.insert(target.path).second) {
            error = "ALT pam_faillock topology contains an invalid or duplicate "
                "managed target";
            return false;
        }
        switch (target.role) {
        case ManagedTargetRole::Authentication:
            break;
        case ManagedTargetRole::AuthenticationAndAccount:
            ++accountTargets;
            break;
        default:
            error = "ALT pam_faillock topology contains an unsupported target role";
            return false;
        }
    }
    if (accountTargets != 1) {
        error = "ALT pam_faillock topology requires exactly one "
            "authentication-and-account target";
        return false;
    }
    error.clear();
    return true;
}

bool AltPamFaillockTopologyManager::canEnableStrategy(
    fic::platform::PamFaillockStrategy strategy,
    std::string& error) const {
    if (!canEnable(error)) {
        return false;
    }
    const auto* capability = capabilityConfig(
        platformConfig_, PamCapability::AuthenticationLockout);
    if (capability == nullptr ||
        !fic::platform::supportsPamFaillockStrategy(*capability, strategy)) {
        error = "pam_faillock strategy " +
            fic::platform::pamFaillockStrategyName(strategy) +
            " is not supported by this platform profile";
        return false;
    }
    error.clear();
    return true;
}

bool AltPamFaillockTopologyManager::enable(std::string& error) {
    const auto* capability = capabilityConfig(
        platformConfig_, PamCapability::AuthenticationLockout);
    if (!canEnable(error) || capability == nullptr) {
        return false;
    }
    return enableStrategy(capability->defaultFaillockStrategy, error);
}

bool AltPamFaillockTopologyManager::enableStrategy(
    fic::platform::PamFaillockStrategy strategy,
    std::string& error) {
    const auto* capability = capabilityConfig(
        platformConfig_, PamCapability::AuthenticationLockout);
    if (!canEnableStrategy(strategy, error) || capability == nullptr) {
        return false;
    }
    ExclusivePidLock lock(
        options_.lockFilePath.string(), options_.lockDebugLogPath.string(), false);
    if (!lock.acquire()) {
        error = "could not acquire PAM topology lock: " +
            options_.lockFilePath.string();
        return false;
    }

    std::vector<ManagedTargetState> targets;
    if (!loadManagedTargets(*capability, targets, error)) {
        return false;
    }
    const std::size_t present = static_cast<std::size_t>(std::count_if(
        targets.begin(), targets.end(), [](const ManagedTargetState& target) {
            return target.managed.state == ManagedState::Present;
        }));
    if (present != 0 && present != targets.size()) {
        error = "partial FIC pam_faillock topology across managed targets";
        return false;
    }

    const auto externalGraph = inspectExternalFaillockInRelevantGraph(
        platformConfig_, targets, error);
    if (externalGraph == ExternalFaillockGraphState::Error) {
        error = "could not inspect relevant PAM graph for external "
            "pam_faillock topology: " + error;
        return false;
    }
    if (externalGraph == ExternalFaillockGraphState::Present) {
        error = present != 0
            ? "existing FIC pam_faillock topology conflicts with external "
              "topology: " + error
            : "external pam_faillock topology already exists; FIC will not "
              "take ownership: " + error;
        return false;
    }

    if (present == targets.size()) {
        // The topology is already enabled: validate it and either accept it
        // as idempotent or perform an atomic strategy transition.
        for (const auto& target : targets) {
            if (!validatePresentTarget(target, error)) {
                return false;
            }
        }
        std::optional<fic::platform::PamFaillockStrategy> detected =
            targets.front().managed.strategy;
        for (const auto& target : targets) {
            if (target.managed.strategy != detected) {
                error = "mixed FIC pam_faillock strategies across managed "
                    "targets";
                return false;
            }
        }
        if (detected == strategy) {
            if (!verifySemanticEffectiveness(error)) {
                error = "existing FIC pam_faillock topology is not "
                    "effective: " + error;
                return false;
            }
            error.clear();
            return true;
        }

        for (auto& target : targets) {
            if (!buildTransitionCandidate(target, strategy, error)) {
                return false;
            }
        }
        if (!writeCandidates(targets, options_, "strategy transition", error)) {
            return false;
        }
        std::vector<ManagedTargetState> written;
        std::string verificationError;
        if (!loadManagedTargets(*capability, written, verificationError) ||
            written.size() != targets.size()) {
            return restoreOriginalTargets(
                targets, options_,
                "post-transition PAM verification failed: " +
                    verificationError,
                error);
        }
        for (std::size_t index = 0; index < written.size(); ++index) {
            if (written[index].snapshot.content != targets[index].candidate ||
                written[index].managed.strategy != strategy ||
                !validatePresentTarget(written[index], verificationError)) {
                return restoreOriginalTargets(
                    targets, options_,
                    "post-transition PAM verification failed: " +
                        verificationError,
                    error);
            }
        }
        const auto writtenExternal = inspectExternalFaillockInRelevantGraph(
            platformConfig_, written, verificationError);
        if (writtenExternal != ExternalFaillockGraphState::Clear ||
            !verifySemanticEffectiveness(verificationError)) {
            return restoreOriginalTargets(
                targets, options_,
                "post-transition PAM verification failed: " +
                    verificationError,
                error);
        }
        error.clear();
        return true;
    }

    for (auto& target : targets) {
        if (!prepareEnabledCandidate(target, strategy, error)) {
            return false;
        }
    }
    if (!writeCandidates(targets, options_, "enable", error)) {
        return false;
    }

    std::vector<ManagedTargetState> written;
    std::string verificationError;
    if (!loadManagedTargets(*capability, written, verificationError) ||
        written.size() != targets.size()) {
        return restoreOriginalTargets(
            targets, options_,
            "post-enable PAM verification failed: " + verificationError,
            error);
    }
    for (std::size_t index = 0; index < written.size(); ++index) {
        if (written[index].snapshot.content != targets[index].candidate ||
            written[index].managed.strategy != strategy ||
            !validatePresentTarget(written[index], verificationError)) {
            return restoreOriginalTargets(
                targets, options_,
                "post-enable PAM verification failed: " + verificationError,
                error);
        }
    }
    const auto writtenExternal = inspectExternalFaillockInRelevantGraph(
        platformConfig_, written, verificationError);
    if (writtenExternal != ExternalFaillockGraphState::Clear ||
        !verifySemanticEffectiveness(verificationError)) {
        return restoreOriginalTargets(
            targets, options_,
            "post-enable PAM verification failed: " + verificationError,
            error);
    }
    error.clear();
    return true;
}

bool AltPamFaillockTopologyManager::disable(std::string& error) {
    const auto* capability = capabilityConfig(
        platformConfig_, PamCapability::AuthenticationLockout);
    if (!canEnable(error) || capability == nullptr) {
        return false;
    }
    ExclusivePidLock lock(
        options_.lockFilePath.string(), options_.lockDebugLogPath.string(), false);
    if (!lock.acquire()) {
        error = "could not acquire PAM topology lock: " +
            options_.lockFilePath.string();
        return false;
    }

    std::vector<ManagedTargetState> targets;
    if (!loadManagedTargets(*capability, targets, error)) {
        return false;
    }
    const std::size_t present = static_cast<std::size_t>(std::count_if(
        targets.begin(), targets.end(), [](const ManagedTargetState& target) {
            return target.managed.state == ManagedState::Present;
        }));
    if (present == 0) {
        error.clear();
        return true;
    }
    if (present != targets.size()) {
        error = "partial FIC pam_faillock topology across managed targets";
        return false;
    }

    for (auto& target : targets) {
        if (!verifyManagedPlacement(
                target.rules, target.lines, target.target.role,
                target.managed, error)) {
            error = "refusing to disable invalid FIC pam_faillock placement in " +
                target.target.path.string() + ": " + error;
            return false;
        }
        target.candidate = buildDisabledContent(
            target.lines, target.managed);
        std::vector<PhysicalLine> checkedLines;
        std::vector<PamRule> checkedRules;
        ManagedInspection checkedManaged;
        if (!parseAndInspect(
                target.target.path, target.candidate, target.target.role,
                checkedLines, checkedRules, checkedManaged, error) ||
            checkedManaged.state != ManagedState::Absent) {
            error = "PAM topology after disable is invalid for " +
                target.target.path.string() + ": " + error;
            return false;
        }
    }
    if (!writeCandidates(targets, options_, "disable", error)) {
        return false;
    }

    std::vector<ManagedTargetState> written;
    std::string verificationError;
    if (!loadManagedTargets(*capability, written, verificationError) ||
        written.size() != targets.size()) {
        return restoreOriginalTargets(
            targets, options_,
            "post-disable PAM verification failed: " + verificationError,
            error);
    }
    for (std::size_t index = 0; index < written.size(); ++index) {
        if (written[index].snapshot.content != targets[index].candidate ||
            written[index].managed.state != ManagedState::Absent) {
            return restoreOriginalTargets(
                targets, options_,
                "post-disable PAM verification failed for " +
                    written[index].target.path.string(),
                error);
        }
    }
    error.clear();
    return true;
}

std::string altPamFaillockTopologyStateName(
    AltPamFaillockTopologyState state) {
    switch (state) {
    case AltPamFaillockTopologyState::Disabled:
        return "disabled";
    case AltPamFaillockTopologyState::Enabled:
        return "enabled";
    }
    return "unknown";
}

} // namespace fic::identity::pam
