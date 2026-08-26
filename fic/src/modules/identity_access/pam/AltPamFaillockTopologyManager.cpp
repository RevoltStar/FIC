#include "modules/identity_access/pam/AltPamFaillockTopologyManager.h"

#include "modules/identity_access/pam/PamCapabilityVerifier.h"
#include "modules/identity_access/pam/PamConfiguration.h"

#include <fic/core/process/ExclusivePidLock.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iterator>
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
     AltPamFaillockTopologyManager::ACCOUNT_END}
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
                          ManagedInspection& inspection,
                          std::string& error) {
    inspection = ManagedInspection{};
    std::size_t presentBlocks = 0;

    std::vector<std::size_t> preauthBegins;
    std::vector<std::size_t> preauthEnds;
    std::vector<std::size_t> originalMarkers;
    for (std::size_t index = 0; index < lines.size(); ++index) {
        if (lines[index].text == AltPamFaillockTopologyManager::PREAUTH_BEGIN) {
            preauthBegins.push_back(index);
        }
        if (lines[index].text == AltPamFaillockTopologyManager::PREAUTH_END) {
            preauthEnds.push_back(index);
        }
        if (lines[index].text.compare(
                0,
                std::strlen(
                    AltPamFaillockTopologyManager::ORIGINAL_AUTH_PREFIX),
                AltPamFaillockTopologyManager::ORIGINAL_AUTH_PREFIX) == 0) {
            originalMarkers.push_back(index);
        }
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
        if (lines[begin + 1].text !=
                AltPamFaillockTopologyManager::PREAUTH_RULE ||
            lines[begin + 2].text.compare(
                0,
                std::strlen(AltPamFaillockTopologyManager::ORIGINAL_AUTH_PREFIX),
                AltPamFaillockTopologyManager::ORIGINAL_AUTH_PREFIX) != 0) {
            inspection.state = ManagedState::Broken;
            error = "modified FIC pam_faillock preauth block content";
            return false;
        }
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
            std::none_of(std::begin(kSimpleBlocks), std::end(kSimpleBlocks),
                [&line](const BlockSpec& block) {
                    return line.text == block.begin || line.text == block.end;
                })) {
            inspection.state = ManagedState::Broken;
            error = "unrecognized FIC pam_faillock marker";
            return false;
        }
    }
    if (originalMarkers.size() != (preauthBegins.empty() ? 0 : 1)) {
        inspection.state = ManagedState::Broken;
        error = "orphaned or duplicated FIC original pam_tcb marker";
        return false;
    }
    if (presentBlocks == 0) {
        inspection.state = ManagedState::Absent;
        error.clear();
        return true;
    }
    if (presentBlocks != 3) {
        inspection.state = ManagedState::Broken;
        error = "incomplete FIC pam_faillock managed topology";
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

bool verifyNoExternalFaillockInRelevantGraph(
    const fic::platform::PamPlatformConfig& platformConfig,
    const ManagedInspection& managed,
    std::string& error) {
    PamConfiguration configuration(platformConfig);
    std::vector<std::string> services;
    if (!configuration.existingServices(
            platformConfig.authenticationServices, services, error)) {
        return false;
    }
    if (services.empty()) {
        error = "none of the configured PAM authentication services exists";
        return false;
    }
    const auto target =
        platformConfig.localAuthenticationStackPath.lexically_normal();
    for (const std::string& service : services) {
        for (const PamManagementGroup group : {
                 PamManagementGroup::Auth, PamManagementGroup::Account}) {
            std::vector<PamRule> rules;
            if (!configuration.collectRules(
                    service, group, rules, error)) {
                return false;
            }
            for (const PamRule& rule : rules) {
                if (moduleBaseName(rule) != "pam_faillock.so") {
                    continue;
                }
                const bool owned = rule.source.lexically_normal() == target &&
                    managed.ruleLines.find(rule.line) != managed.ruleLines.end();
                if (!owned) {
                    error = "external pam_faillock topology is effective for PAM "
                        "service " + service + " at " + rule.source.string() +
                        ":" + std::to_string(rule.line);
                    return false;
                }
            }
        }
    }
    error.clear();
    return true;
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

void appendPreauthBlock(std::vector<PhysicalLine>& output,
                        const PhysicalLine& original,
                        const PamRule& authRule) {
    output.push_back(generatedLine(
        AltPamFaillockTopologyManager::PREAUTH_BEGIN));
    output.push_back(generatedLine(
        AltPamFaillockTopologyManager::PREAUTH_RULE));
    output.push_back(generatedLine(
        std::string(AltPamFaillockTopologyManager::ORIGINAL_AUTH_PREFIX) +
        hexEncode(original.text + original.ending)));
    output.push_back(generatedLine(
        canonicalSufficientAuthenticator(authRule)));
    output.push_back(generatedLine(
        AltPamFaillockTopologyManager::PREAUTH_END));
}

bool findAnchors(const std::vector<PamRule>& rules,
                 const std::vector<PhysicalLine>& lines,
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
    if (accountCandidates.size() != 1) {
        error = "expected exactly one local account pam_tcb.so anchor, found " +
            std::to_string(accountCandidates.size());
        return false;
    }
    const PamRule& auth = *authCandidates.front();
    const PamRule& account = *accountCandidates.front();
    if ((auth.control != "required" && auth.control != "sufficient") ||
        account.control != "required") {
        error = "unsupported pam_tcb.so control topology in ALT local stack";
        return false;
    }
    if (auth.line == 0 || account.line == 0 || auth.line > lines.size() ||
        account.line > lines.size() ||
        (!lines[auth.line - 1].text.empty() &&
         lines[auth.line - 1].text.back() == '\\') ||
        (!lines[account.line - 1].text.empty() &&
         lines[account.line - 1].text.back() == '\\')) {
        error = "unsupported continued or invalid pam_tcb.so anchor line";
        return false;
    }
    authLine = auth.line;
    accountLine = account.line;
    return true;
}

bool verifyManagedPlacement(const std::vector<PamRule>& rules,
                            const std::vector<PhysicalLine>& lines,
                            std::string& error) {
    std::size_t authLine = 0;
    std::size_t accountLine = 0;
    if (!findAnchors(rules, lines, authLine, accountLine, error)) {
        return false;
    }
    const auto preauth = std::find_if(
        lines.begin(), lines.end(), [](const PhysicalLine& line) {
            return line.text ==
                AltPamFaillockTopologyManager::PREAUTH_BEGIN;
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
    if (preauth == lines.end() || authfail == lines.end() ||
        account == lines.end()) {
        error = "complete FIC pam_faillock markers are missing";
        return false;
    }
    const std::size_t preauthIndex =
        static_cast<std::size_t>(std::distance(lines.begin(), preauth));
    const std::size_t authfailIndex =
        static_cast<std::size_t>(std::distance(lines.begin(), authfail));
    const std::size_t accountIndex =
        static_cast<std::size_t>(std::distance(lines.begin(), account));
    if (authLine != preauthIndex + 4 ||
        authfailIndex != preauthIndex + 5 ||
        accountLine != accountIndex + 4) {
        error = "FIC pam_faillock blocks are not at the required pam_tcb anchors";
        return false;
    }
    error.clear();
    return true;
}

bool verifyNoExecutableAuthTail(
    const std::vector<PamRule>& rules,
    const std::vector<PhysicalLine>& lines,
    const ManagedInspection& managed,
    std::string& error) {
    std::size_t authLine = 0;
    std::size_t accountLine = 0;
    if (!findAnchors(rules, lines, authLine, accountLine, error)) {
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

std::string buildEnabledContent(const std::vector<PhysicalLine>& lines,
                                const std::vector<PamRule>& rules,
                                std::size_t authLine,
                                std::size_t accountLine) {
    std::vector<PhysicalLine> output;
    output.reserve(lines.size() + 10);
    const auto authRule = std::find_if(
        rules.begin(), rules.end(), [authLine](const PamRule& rule) {
            return rule.line == authLine &&
                rule.group == PamManagementGroup::Auth &&
                moduleBaseName(rule) == "pam_tcb.so";
        });
    for (std::size_t line = 1; line <= lines.size(); ++line) {
        if (line == authLine) {
            appendPreauthBlock(output, lines[line - 1], *authRule);
            appendBlock(output, kSimpleBlocks[0]);
            continue;
        }
        if (line == accountLine) {
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
        if (lines[line - 1].text ==
                AltPamFaillockTopologyManager::PREAUTH_BEGIN) {
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
                     std::vector<PhysicalLine>& lines,
                     std::vector<PamRule>& rules,
                     ManagedInspection& managed,
                     std::string& error) {
    lines = splitLines(content);
    if (!parseTarget(path, content, rules, error)) {
        return false;
    }
    return inspectManagedBlocks(lines, managed, error);
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

bool AltPamFaillockTopologyManager::verifySemanticEffectiveness(
    std::string& error) const {
    if (options_.semanticVerifier) {
        return options_.semanticVerifier(error);
    }
    PamConfiguration configuration(platformConfig_);
    PamCapabilityVerification verification;
    const std::string localService =
        platformConfig_.localAuthenticationStackPath.filename().string();
    if (localService.empty()) {
        error = "local PAM authentication stack service name is empty";
        return false;
    }
    if (!PamCapabilityVerifier::verify(
            configuration,
            platformConfig_,
            {localService},
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
    if (platformConfig_.localAuthenticationStackPath.empty() ||
        options_.lockFilePath.empty()) {
        error = "ALT pam_faillock topology is unsupported by this platform profile";
        return false;
    }
    ExclusivePidLock lock(
        options_.lockFilePath.string(), options_.lockDebugLogPath.string(), false);
    if (!lock.acquire()) {
        error = "could not acquire PAM topology lock: " +
            options_.lockFilePath.string();
        return false;
    }
    TargetSnapshot snapshot;
    if (!inspectSecureTarget(
            platformConfig_.localAuthenticationStackPath, snapshot, error)) {
        return false;
    }
    std::vector<PhysicalLine> lines;
    std::vector<PamRule> rules;
    ManagedInspection managed;
    if (!parseAndInspect(platformConfig_.localAuthenticationStackPath,
                         snapshot.content, lines, rules, managed, error)) {
        return false;
    }
    if (managed.state == ManagedState::Absent) {
        state = AltPamFaillockTopologyState::Disabled;
        error.clear();
        return true;
    }
    if (managed.state != ManagedState::Present) {
        error = "broken FIC pam_faillock managed topology";
        return false;
    }
    if (!verifyManagedPlacement(rules, lines, error)) {
        error = "FIC pam_faillock managed topology placement is invalid: " + error;
        return false;
    }
    if (!verifyNoExecutableAuthTail(rules, lines, managed, error)) {
        error = "FIC pam_faillock managed topology has unsafe auth tail: " +
            error;
        return false;
    }
    if (hasExternalFaillock(rules, managed)) {
        error = "FIC pam_faillock blocks coexist with external pam_faillock topology";
        return false;
    }
    if (!verifyNoExternalFaillockInRelevantGraph(
            platformConfig_, managed, error)) {
        error = "FIC pam_faillock blocks coexist with external pam_faillock "
            "topology: " + error;
        return false;
    }
    if (!verifySemanticEffectiveness(error)) {
        error = "FIC pam_faillock topology is not effective: " + error;
        return false;
    }
    state = AltPamFaillockTopologyState::Enabled;
    return true;
}

bool AltPamFaillockTopologyManager::enable(std::string& error) {
    if (platformConfig_.localAuthenticationStackPath.empty() ||
        options_.lockFilePath.empty()) {
        error = "ALT pam_faillock topology is unsupported by this platform profile";
        return false;
    }
    ExclusivePidLock lock(
        options_.lockFilePath.string(), options_.lockDebugLogPath.string(), false);
    if (!lock.acquire()) {
        error = "could not acquire PAM topology lock: " +
            options_.lockFilePath.string();
        return false;
    }

    const auto& path = platformConfig_.localAuthenticationStackPath;
    TargetSnapshot original;
    if (!inspectSecureTarget(path, original, error)) {
        return false;
    }
    std::vector<PhysicalLine> lines;
    std::vector<PamRule> rules;
    ManagedInspection managed;
    if (!parseAndInspect(path, original.content, lines, rules, managed, error)) {
        return false;
    }
    if (managed.state == ManagedState::Present) {
        if (hasExternalFaillock(rules, managed)) {
            error = "FIC pam_faillock blocks coexist with external topology";
            return false;
        }
        if (!verifyManagedPlacement(rules, lines, error)) {
            error = "existing FIC pam_faillock topology placement is invalid: " +
                error;
            return false;
        }
        if (!verifyNoExecutableAuthTail(rules, lines, managed, error)) {
            error = "existing FIC pam_faillock topology has unsafe auth tail: " +
                error;
            return false;
        }
        if (!verifyNoExternalFaillockInRelevantGraph(
                platformConfig_, managed, error)) {
            error = "existing FIC pam_faillock topology conflicts with external "
                "topology: " + error;
            return false;
        }
        if (!verifySemanticEffectiveness(error)) {
            error = "existing FIC pam_faillock topology is not effective: " + error;
            return false;
        }
        error.clear();
        return true;
    }
    if (managed.state != ManagedState::Absent) {
        error = "broken FIC pam_faillock managed topology";
        return false;
    }
    if (hasExternalFaillock(rules, managed)) {
        error = "external pam_faillock topology already exists; FIC will not take ownership";
        return false;
    }
    if (!verifyNoExternalFaillockInRelevantGraph(
            platformConfig_, managed, error)) {
        error = "external pam_faillock topology already exists; FIC will not "
            "take ownership: " + error;
        return false;
    }

    std::size_t authLine = 0;
    std::size_t accountLine = 0;
    if (!findAnchors(rules, lines, authLine, accountLine, error)) {
        return false;
    }
    if (!verifyNoExecutableAuthTail(rules, lines, managed, error)) {
        error = "unsafe ALT local authentication topology: " + error;
        return false;
    }
    const std::string candidate =
        buildEnabledContent(lines, rules, authLine, accountLine);
    std::vector<PamRule> candidateRules;
    if (!parseTarget(path, candidate, candidateRules, error)) {
        error = "generated PAM topology does not parse: " + error;
        return false;
    }
    if (!targetStillMatches(path, original, error)) {
        return false;
    }
    std::string writeError;
    if (!options_.writer(
            path.string(), candidate,
            writeOptionsForSnapshot(options_.writeOptions, original),
            &writeError)) {
        error = "could not atomically enable FIC pam_faillock topology: " +
            writeError;
        return false;
    }

    auto rollback = [&](const std::string& failure) -> bool {
        std::string rollbackError;
        TargetSnapshot rollbackTarget;
        if (!inspectSecureTarget(path, rollbackTarget, rollbackError)) {
            error = failure + "; CRITICAL: could not inspect rollback target: " +
                rollbackError + "; PAM configuration may be inconsistent";
            return false;
        }
        if (!options_.writer(path.string(), original.content,
                             writeOptionsForSnapshot(
                                 options_.writeOptions, rollbackTarget),
                             &rollbackError)) {
            error = failure + "; CRITICAL: rollback write failed: " + rollbackError +
                "; PAM configuration may be inconsistent";
            return false;
        }
        TargetSnapshot restored;
        std::vector<PhysicalLine> restoredLines;
        std::vector<PamRule> restoredRules;
        ManagedInspection restoredManaged;
        if (!inspectSecureTarget(path, restored, rollbackError) ||
            restored.content != original.content ||
            !parseAndInspect(path, restored.content, restoredLines, restoredRules,
                             restoredManaged, rollbackError)) {
            error = failure + "; CRITICAL: rollback verification failed: " +
                rollbackError + "; PAM configuration may be inconsistent";
            return false;
        }
        error = failure + "; original PAM configuration restored";
        return false;
    };

    TargetSnapshot written;
    std::vector<PhysicalLine> writtenLines;
    std::vector<PamRule> writtenRules;
    ManagedInspection writtenManaged;
    std::string verificationError;
    if (!inspectSecureTarget(path, written, verificationError) ||
        written.content != candidate ||
        !parseAndInspect(path, written.content, writtenLines, writtenRules,
                         writtenManaged, verificationError) ||
        writtenManaged.state != ManagedState::Present ||
        hasExternalFaillock(writtenRules, writtenManaged) ||
        !verifyManagedPlacement(
            writtenRules, writtenLines, verificationError) ||
        !verifyNoExecutableAuthTail(
            writtenRules, writtenLines, writtenManaged, verificationError) ||
        !verifyNoExternalFaillockInRelevantGraph(
            platformConfig_, writtenManaged, verificationError) ||
        !verifySemanticEffectiveness(verificationError)) {
        return rollback("post-enable PAM verification failed: " + verificationError);
    }
    error.clear();
    return true;
}

bool AltPamFaillockTopologyManager::disable(std::string& error) {
    if (platformConfig_.localAuthenticationStackPath.empty() ||
        options_.lockFilePath.empty()) {
        error = "ALT pam_faillock topology is unsupported by this platform profile";
        return false;
    }
    ExclusivePidLock lock(
        options_.lockFilePath.string(), options_.lockDebugLogPath.string(), false);
    if (!lock.acquire()) {
        error = "could not acquire PAM topology lock: " +
            options_.lockFilePath.string();
        return false;
    }
    const auto& path = platformConfig_.localAuthenticationStackPath;
    TargetSnapshot original;
    if (!inspectSecureTarget(path, original, error)) {
        return false;
    }
    std::vector<PhysicalLine> lines;
    std::vector<PamRule> rules;
    ManagedInspection managed;
    if (!parseAndInspect(path, original.content, lines, rules, managed, error)) {
        return false;
    }
    if (managed.state == ManagedState::Absent) {
        error.clear();
        return true;
    }
    if (managed.state != ManagedState::Present) {
        error = "broken FIC pam_faillock managed topology";
        return false;
    }
    if (!verifyManagedPlacement(rules, lines, error)) {
        error = "refusing to disable invalid FIC pam_faillock placement: " +
            error;
        return false;
    }
    const std::string candidate = buildDisabledContent(lines, managed);
    std::vector<PamRule> candidateRules;
    if (!parseTarget(path, candidate, candidateRules, error)) {
        error = "PAM topology after disable does not parse: " + error;
        return false;
    }
    if (!targetStillMatches(path, original, error)) {
        return false;
    }
    std::string writeError;
    if (!options_.writer(
            path.string(), candidate,
            writeOptionsForSnapshot(options_.writeOptions, original),
            &writeError)) {
        error = "could not atomically disable FIC pam_faillock topology: " +
            writeError;
        return false;
    }

    auto rollback = [&](const std::string& failure) -> bool {
        std::string rollbackError;
        TargetSnapshot rollbackTarget;
        if (!inspectSecureTarget(path, rollbackTarget, rollbackError)) {
            error = failure + "; CRITICAL: could not inspect rollback target: " +
                rollbackError + "; PAM configuration may be inconsistent";
            return false;
        }
        if (!options_.writer(path.string(), original.content,
                             writeOptionsForSnapshot(
                                 options_.writeOptions, rollbackTarget),
                             &rollbackError)) {
            error = failure + "; CRITICAL: rollback write failed: " + rollbackError +
                "; PAM configuration may be inconsistent";
            return false;
        }
        TargetSnapshot restored;
        std::vector<PhysicalLine> restoredLines;
        std::vector<PamRule> restoredRules;
        ManagedInspection restoredManaged;
        if (!inspectSecureTarget(path, restored, rollbackError) ||
            restored.content != original.content ||
            !parseAndInspect(path, restored.content, restoredLines, restoredRules,
                             restoredManaged, rollbackError) ||
            restoredManaged.state != ManagedState::Present ||
            !verifyManagedPlacement(
                restoredRules, restoredLines, rollbackError) ||
            !verifySemanticEffectiveness(rollbackError)) {
            error = failure + "; CRITICAL: rollback verification failed: " +
                rollbackError + "; PAM configuration may be inconsistent";
            return false;
        }
        error = failure + "; original PAM configuration restored";
        return false;
    };

    TargetSnapshot written;
    std::vector<PhysicalLine> writtenLines;
    std::vector<PamRule> writtenRules;
    ManagedInspection writtenManaged;
    std::string verificationError;
    if (!inspectSecureTarget(path, written, verificationError) ||
        written.content != candidate ||
        !parseAndInspect(path, written.content, writtenLines, writtenRules,
                         writtenManaged, verificationError) ||
        writtenManaged.state != ManagedState::Absent) {
        return rollback("post-disable PAM verification failed: " + verificationError);
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
