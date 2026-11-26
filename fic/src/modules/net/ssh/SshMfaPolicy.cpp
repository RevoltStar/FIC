#include "modules/net/ssh/SshMfaPolicy.h"

#include "modules/identity_access/pam/PamMfaTopology.h"
#include "modules/net/ssh/SshConfigTransaction.h"
#include "modules/net/ssh/SshConfigSyntax.h"
#include "modules/net/ssh/SshManagedBlock.h"
#include "modules/net/ssh/SshResourceLock.h"
#include "rollback/DaemonMutationJournal.h"
#include "service/ssh/SshVerifiedInputClosure.h"

#include <fic/core/config/ConfigAuthority.h>
#include <fic/core/integrity/ContentDigest.h>
#include <fic/core/runtime/FicRuntimePaths.h>
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <linux/magic.h>
#include <sys/vfs.h>

namespace fic::ssh {
namespace {

using namespace fic::service::ssh;
using namespace fic::identity::pam;
using namespace fic::rollback;
using Adapter = SshVerifiedActivationAdapter;
using Requirement = SshVerifiedActivationRequest::MfaRequirement;
constexpr char servicePath[] = "/etc/pam.d/fic-sshd-mfa";
constexpr char slotPath[] = "/etc/pam.d/fic-mfa-ssh-auth";
const PolicyRef policy{"NET", "SshEdit", sshMfaPolicy};

void require(bool condition, const std::string& error) {
    if (!condition) throw std::runtime_error(error);
}

std::string digest(const std::string& bytes) {
    return fic::core::ContentDigest::sha256Hex(bytes);
}

struct ConfiguredMfa {
    bool enabled = false;
    std::map<std::string, std::string> ordinary;
};

ConfiguredMfa configuredMfa(const std::string& path, const AtomicTargetState& generation,
                            bool hasOwnership = false) {
    std::string error;
    FileHandlerOptions options;
    options.writeOptions.rejectSymlink = true;
    ConfigFileHandler config(path, "=", options);
    require(config.loadConfig() && AtomicFileWriter::targetStateMatches(path, generation, &error),
            "trusted SSH configuration generation lost: " + error);
    const std::string statusKey = std::string(sshMfaPolicy) + ".status";
    std::istringstream lines(generation.content);
    std::string line;
    unsigned statuses = 0;
    while (std::getline(lines, line)) {
        if (line.find('#') != std::string::npos) continue;
        auto key = line.substr(0, line.find('='));
        key.erase(std::remove_if(key.begin(), key.end(),
            [](unsigned char c) { return std::isspace(c); }), key.end());
        if (key == statusKey) {
            require(line.find('=') != std::string::npos && ++statuses == 1,
                    "SSH MFA status declaration is ambiguous or malformed");
        }
    }
    // The installed default is DISABLE. Old NET.conf files may omit the new key.
    if (!config.isParameterExists(statusKey)) {
        require(!hasOwnership, "RecoveryRequired: SSH MFA status missing for active ownership");
        return {};
    }
    fic::core::ConfigAuthorityIdentity authority;
    require(path == (fic::core::FicRuntimePaths::get().configDir / "NET.conf").string() &&
            fic::core::productionConfigAuthority(authority, error) &&
            fic::core::proveConfigDirectory(std::filesystem::path(path).parent_path(), authority, error),
            "SSH MFA policy configuration is not authoritative: " + error);
    const auto trusted = fic::core::readSecureFileBounded(path, fic::core::configAuthorityExpectation(authority),
                                                        fic::core::MAX_WORKING_CONFIG_BYTES);
    require(trusted.status == fic::core::SecureStateReadStatus::Proven &&
            AtomicFileWriter::targetStateMatches(path, generation, &error) &&
            trusted.targetState.identity.inode == generation.identity.inode &&
            trusted.targetState.identity.device == generation.identity.device &&
            trusted.content == generation.content, "SSH MFA policy configuration changed or is untrusted");
    const auto status = config.getValue(statusKey);
    require(status == "ENABLE" || status == "DISABLE", "invalid SSH MFA policy status");
    ConfiguredMfa result;
    result.enabled = status == "ENABLE";
    if (result.enabled) {
        for (const auto* id : {"ssh_root_login", "ssh_pubkey_auth", "ssh_use_pam", "ssh_max_auth_tries", "ssh_port"}) {
            const auto ordinary = config.getValue(std::string(id) + ".status");
            require(ordinary.empty() || ordinary == "DISABLE" || ordinary == "ENABLE",
                    std::string("invalid SSH policy status: ") + id);
            if (ordinary == "ENABLE") result.ordinary.emplace(id, config.getValue(std::string(id) + ".value"));
        }
        service::ssh::detail::validatePolicies(result.ordinary, SshActivationIntent::ConfigurationRelease);
        for (const auto* id : {"ssh_pubkey_auth", "ssh_use_pam"}) {
            const auto selected = result.ordinary.find(id);
            require(selected == result.ordinary.end() || selected->second == "yes",
                    std::string("enabled SSH policy conflicts with required MFA: ") + id);
        }
    }
    return result;
}

Requirement discoverRequirement(const fic::platform::PlatformProfile& platform) {
    PamConfiguration config(platform.pam);
    PamEffectiveStack stack;
    std::string error;
    require(config.buildEffectiveStack("sshd", PamManagementGroup::Auth, stack, error), error);
    const auto has = [](const auto& self, const auto& entries, const std::string& module) -> bool {
        return std::any_of(entries.begin(), entries.end(), [&](const auto& entry) {
            return entry.rule.module == module || self(self, entry.substack, module);
        });
    };
    Requirement requirement;
    requirement.sssd = has(has, stack.entries, "pam_sss.so");
    if (has(has, stack.entries, "pam_faillock.so")) {
        requirement.faillock = detectPamFaillockStrategy(stack, error);
        require(requirement.faillock.has_value(), "SSH MFA faillock strategy unproven: " + error);
    }
    return requirement;
}

std::string strategy(const Requirement& requirement) {
    if (!requirement.faillock) return {};
    return *requirement.faillock == fic::platform::PamFaillockStrategy::PreauthRequired
        ? "preauth_required" : "preauth_requisite";
}

AtomicTargetState proveOwnedPam(const char* path, const SshMfaPamFile& file) {
    std::string error;
    fic::core::SecureStateFileExpectation expected;
    expected.owner = 0;
    expected.group = 0;
    expected.exactMode = 0644;
    expected.parentOwner = 0;
    expected.requireSingleLink = true;
    const auto current = fic::core::readSecureFileBounded(path, expected, 1024 * 1024);
    require(file.receipt && file.receipt->durable && current.status == fic::core::SecureStateReadStatus::Proven &&
            static_cast<std::uint64_t>(current.targetState.identity.device) == file.receipt->device &&
            static_cast<std::uint64_t>(current.targetState.identity.inode) == file.receipt->inode &&
            digest(current.content) == file.targetSha256,
            std::string("RecoveryRequired: SSH MFA ownership or content changed at ") + path);
    return current.targetState;
}

SshMfaReference ownedMfaReference(const UndoReleaseSshMfa& owned) {
    const auto service = proveOwnedPam(servicePath, owned.service);
    const auto slot = proveOwnedPam(slotPath, owned.authSlot);
    Requirement requirement{owned.sssd, std::nullopt};
    if (!owned.faillock.empty())
        requirement.faillock = owned.faillock == "preauth_required"
            ? fic::platform::PamFaillockStrategy::PreauthRequired
            : fic::platform::PamFaillockStrategy::PreauthRequisite;
    auto sources = Adapter::captureMfaPamSources(requirement);
    std::string error;
    require(AtomicFileWriter::targetStateMatches(servicePath, service, &error) &&
            AtomicFileWriter::targetStateMatches(slotPath, slot, &error), error);
    return sources;
}

}

std::optional<fic::service::ssh::SshMfaReference> requiredMfaForOperation(
    const fic::rollback::MutationJournal& journal, const std::string& path,
    const AtomicTargetState& generation) {
    const auto platform = fic::platform::makeBuildPlatformProfile();
    if (platform.id != "debian-13") return {};
    require(journal.usable(), "SSH MFA policy requires healthy journal");
    const auto active = journal.activeRecords(policy);
    const auto desired = configuredMfa(path, generation, !active.empty());
    if (active.empty() && !desired.enabled) return {};
    std::string error;
    require(journal.proveCurrentSshMfaAuthority(error), "RecoveryRequired: SSH MFA journal is unproven: " + error);
    require(active.size() == 1 && desired.enabled,
            "RecoveryRequired: SSH MFA desired state and journal ownership disagree");
    const auto* owned = std::get_if<UndoReleaseSshMfa>(&active.front().undo.payload);
    require(owned && owned->phase == SshMfaPhase::Applied,
            "RecoveryRequired: SSH MFA has an unfinished operation");
    SshConfigFileHandler config(platform.ssh.configPath.string());
    require(config.loadConfig() && planSshMfaManagedBlock(config.lines(), true, true, error),
            "RecoveryRequired: SSH MFA managed blocks are unproven: " + error);
    return ownedMfaReference(*owned);
}

bool proveSshMfaPrepareUninstall(const MutationJournal& journal, std::string& error) {
    if (!journal.proveCurrentSshMfaAuthority(error)) return false;
    const auto active = journal.activeRecords(policy);
    if (active.empty()) return true;
    const auto* owned = std::get_if<UndoReleaseSshMfa>(&active.front().undo.payload);
    if (active.size() != 1 || !owned || owned->phase != SshMfaPhase::Applied ||
        !active.front().error.empty()) {
        error = "RecoveryRequired: unfinished or ambiguous SSH MFA ownership";
        return false;
    }
    return true;
}

void proveSshMfaUninstallReleased(const MutationJournal& journal,
                                 std::optional<AtomicTargetState>& generation) {
    require(journal.activeRecords(policy).empty(), "RecoveryRequired: SSH MFA ownership is still active");
    const auto path = (fic::core::FicRuntimePaths::get().configDir / "NET.conf").string();
    std::string error;
    if (!generation) {
        AtomicTargetState first;
        require(AtomicFileWriter::captureTargetState(path, first, &error) &&
                first.owner == 0 && (first.mode & 0022) == 0, "trusted NET.conf unavailable: " + error);
        generation = std::move(first);
    }
    configuredMfa(path, *generation);
}

SshMfaPolicy::SshMfaPolicy() {
    submoduleName = "SshEdit";
    policyName = sshMfaPolicy;
    policyTypeValue = std::make_unique<FixedPolicyTypeValue>("ENABLE");
}

bool SshMfaPolicy::apply() {
    const std::lock_guard<std::mutex> lock(sshResourceMutex());
    MutationId id = 0;
    bool offeredPublication = false;
    MutationJournal* journal = nullptr;
    try {
        const auto platform = fic::platform::makeBuildPlatformProfile();
        require(platform.id == "debian-13", "SSH MFA is unsupported on this platform");
        std::string error, path;
        AtomicTargetState generation;
        require(this->isEnabled() && captureConfigurationVersion(path, generation, error), error);
        const auto desired = configuredMfa(path, generation);
        require(desired.enabled, "SSH MFA is no longer enabled in the authoritative configuration");
        journal = DaemonMutationJournal::instance().tryGet(error);
        require(journal, error);
        const auto recheck = [&] {
            require(AtomicFileWriter::targetStateMatches(path, generation, &error) &&
                    journal->proveCurrentSshMfaAuthority(error),
                    "SSH MFA policy configuration or journal changed: " + error);
        };
        recheck();
        for (const auto& record : journal->records())
            if (record.isActive() && record.policy != policy && record.undo.backend == MutationBackend::Ssh)
                require(record.status != MutationStatus::Prepared &&
                        (!std::holds_alternative<UndoRemoveSshManagedPolicy>(record.undo.payload) ||
                         !sshTransitionPending(std::get<UndoRemoveSshManagedPolicy>(record.undo.payload))),
                        "RecoveryRequired: another SSH transaction is pending");
        const auto main = platform.ssh.configPath.string();
        SshConfigFileHandler config(main);
        require(config.loadConfig() && config.loadSnapshot(), "SSH main configuration unavailable");
        const auto before = *config.loadSnapshot();
        const auto active = journal->activeRecords(policy);
        const bool alreadyOwned = !active.empty();
        if (alreadyOwned) {
            const auto reference = requiredMfaForOperation(*journal, path, generation);
            require(reference.has_value(), "SSH MFA journal ownership unproven");
            auto request = Adapter::captureReference({}, digest(before.content),
                SshActivationIntent::ConfigurationRelease, &*reference);
            const auto admission = Adapter::admitMfaPlan(request);
            recheck();
            const auto result = Adapter::releaseConfiguration(request, admission);
            require(result.success(), result.diagnostic);
            recheck();
            return true;
        }
        require(planSshMfaManagedBlock(config.lines(), false, true, error), error);
        const auto planned = config.pendingContent();
        const auto requirement = discoverRequirement(platform);
        const auto pam = Adapter::captureMfaPamSources(requirement);
        auto baseline = Adapter::captureFirstMfaReference({}, digest(before.content), pam);
        const auto admission = Adapter::admitMfaPlan(baseline);
        PamSshMfaCandidate candidate;
        require(buildDebian13SshMfaCandidate(platform, requirement.sssd, requirement.faillock, candidate, error), error);
        const auto preflight = Adapter::validateMfaPlan(baseline, admission, planned, requirement, &candidate);
        require(preflight.success(), preflight.diagnostic);
        recheck();
        require(AtomicFileWriter::targetStateMatches(main, before, &error), error);
        UndoReleaseSshMfa plan;
        plan.sssd = requirement.sssd;
        plan.faillock = strategy(requirement);
        plan.service.targetSha256 = digest(candidate.service);
        plan.authSlot.targetSha256 = digest(candidate.authSlot);
        plan.beforeSshSha256 = digest(before.content);
        plan.targetSshSha256 = digest(planned);
        require(journal->prepareSshMfa(plan, id, error), error);
        const auto firstPublicationAdmission = Adapter::admitMfaPlan(baseline);
        require(firstPublicationAdmission.service == admission.service, "SSH service changed before PAM publication");
        const auto install = [&](const char* file, const std::string& bytes, bool service) {
            recheck();
            AtomicWriteOptions options;
            options.createIfMissing = true;
            options.exclusiveCreate = true;
            options.rejectSymlink = true;
            options.fileMode = 0644;
            options.fileOwner = 0;
            options.fileGroup = 0;
            options.beforePublish = [&](const AtomicTargetState& staged, std::string& detail) {
                offeredPublication = true;
                return journal->noteSshMfaPamReceipt(id, service, staged, false, detail) &&
                       AtomicFileWriter::targetStateMatches(path, generation, &detail) &&
                       journal->proveCurrentSshMfaAuthority(detail);
            };
            AtomicWriteResult result;
            require(AtomicFileWriter::writeWithResult(file, bytes, options, &error, &result) &&
                    result.installed && result.durabilityConfirmed && result.installedTargetState, error);
            require(journal->noteSshMfaPamReceipt(id, service, *result.installedTargetState, true, error), error);
        };
        install(slotPath, candidate.authSlot, false);
        install(servicePath, candidate.service, true);
        auto staged = baseline;
        for (auto& root : staged.reference.paths)
            if (root.path == "/etc/pam.d") {
                root.manifest.emplace(mfaSshAuthSlot, plan.authSlot.targetSha256);
                root.manifest.emplace(mfaSshService, plan.service.targetSha256);
            }
        staged.observedMetadata.clear();
        const auto stagedAdmission = Adapter::admitMfaPlan(staged);
        auto metadata = staged.observedMetadata;
        metadata.erase(std::string("entry:") + slotPath);
        metadata.erase(std::string("entry:") + servicePath);
        require(metadata == baseline.observedMetadata && admission.service == stagedAdmission.service,
                "SSH/PAM baseline generation changed during PAM publication");
        const auto installedPlan = Adapter::validateMfaPlan(staged, stagedAdmission, planned, requirement);
        require(installedPlan.success(), installedPlan.diagnostic);
        recheck();
        const auto written = restoreSshConfigContentIfCurrentState(main, planned, before, error,
            [&](const AtomicTargetState&, std::string& detail) {
                return AtomicFileWriter::targetStateMatches(path, generation, &detail) &&
                       journal->proveCurrentSshMfaAuthority(detail);
            });
        if (written.installed && written.installedState)
            require(journal->noteSshMfaPublication(id, *written.installedState, written.durable, error), error);
        require(written.installed && written.durable && written.installedState, error);
        recheck();
        auto target = staged;
        target.mfa = requirement;
        target.observedMetadata.clear();
        for (auto& root : target.reference.paths)
            if (root.path == main) root.sha256 = digest(planned);
        const auto finalAdmission = Adapter::admitMfaPlan(target);
        staged.mfa = requirement;
        require(Adapter::sameInputGeneration(staged, target, true) &&
                stagedAdmission.service == finalAdmission.service, "SSH/PAM generation changed after SSH publication");
        const auto result = Adapter::releaseConfiguration(target, finalAdmission);
        require(result.success(), result.diagnostic);
        recheck();
        require(AtomicFileWriter::targetStateMatches(main, *written.installedState, &error) &&
                journal->commitSshMfaEnable(id, result.observedFacts(), error), error);
        return true;
    } catch (const std::exception& failure) {
        std::string error;
        if (id && journal && !offeredPublication && journal->abortSshMfaNoEffect(id, error)) id = 0;
        log((id ? "RecoveryRequired: " : "") + std::string(failure.what()), logLevel::ERROR);
        return false;
    }
}

namespace {

void proveSshChildrenDrained(const std::map<std::string, std::string>& service) {
    const auto pid = service.at("MainPID");
    require(!pid.empty() && pid != "0", "SSH listener identity unavailable");
    struct statfs proc {};
    require(::statfs("/proc", &proc) == 0 && proc.f_type == PROC_SUPER_MAGIC,
            "trusted SSH process inventory unavailable");
    struct stat running {}, installed {};
    require(::stat(("/proc/" + pid + "/exe").c_str(), &running) == 0 &&
            ::stat("/usr/sbin/sshd", &installed) == 0 &&
            running.st_dev == installed.st_dev && running.st_ino == installed.st_ino,
            "SSH listener executable changed before PAM detach");
    bool seenMain = false;
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        const auto name = entry.path().filename().string();
        if (name.empty() || name.find_first_not_of("0123456789") != std::string::npos) continue;
        std::ifstream comm(entry.path() / "comm");
        std::string process;
        if (!std::getline(comm, process)) {
            require(!std::filesystem::exists(entry.path()), "SSH process inventory unprovable");
            continue;
        }
        if (name == pid) seenMain = process == "sshd";
        else require(process.rfind("sshd", 0) != 0,
                     "SSH sessions or authentication children are still present");
    }
    require(seenMain, "SSH main process changed during child inventory");
}

void proveNoForeignPamReferences(const fic::platform::PamPlatformConfig& pam) {
    for (const auto& directory : pam.configDirectories) {
        std::error_code error;
        std::filesystem::directory_iterator it(directory, error);
        if (error == std::errc::no_such_file_or_directory) continue;
        require(!error, "PAM detach inventory unavailable");
        for (const auto& entry : it) {
            const auto path = entry.path();
            if (path == slotPath || path == servicePath) continue;
            require(entry.is_regular_file() && !entry.is_symlink(), "PAM detach inventory includes an unsupported path");
            fic::core::SecureStateFileExpectation expectation;
            expectation.owner = 0;
            expectation.forbiddenMode = 0022;
            expectation.parentOwner = 0;
            const auto source = fic::core::readSecureFileBounded(path, expectation, 1024 * 1024);
            require(source.status == fic::core::SecureStateReadStatus::Proven, "untrusted PAM detach source");
            std::vector<PamRule> rules;
            std::string diagnostic;
            require(PamConfiguration::parseRulesContent(path, source.content, rules, diagnostic), diagnostic);
            for (const auto& rule : rules)
                require(std::filesystem::path(rule.includeTarget).filename() != mfaSshAuthSlot &&
                        std::filesystem::path(rule.includeTarget).filename() != mfaSshService &&
                        std::filesystem::path(rule.module).filename() != "pam_fic_ssh_stage.so",
                        "foreign PAM source references dedicated SSH MFA configuration");
        }
    }
}

void proveReleasedImage(const UndoReleaseSshMfa& owned, const std::string& main) {
    std::string error;
    AtomicTargetState installed;
    require(owned.sshPublication && AtomicFileWriter::captureTargetState(main, installed, &error), error);
    const auto& receipt = *owned.sshPublication;
    require(static_cast<std::uint64_t>(installed.identity.inode) == receipt.inode &&
            static_cast<std::uint64_t>(installed.identity.device) == receipt.device &&
            installed.mode == receipt.mode && installed.owner == receipt.owner && installed.group == receipt.group &&
            digest(installed.content) == receipt.sha256,
            "RecoveryRequired: released SSH configuration changed");
    require(AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(servicePath, &error) &&
            AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(slotPath, &error), error);
}

}

SshRollbackResult releaseSshMfa(MutationJournal& journal, const SshMfaReleaseIntent& intent) {
    SshRollbackResult result;
    bool pending = false;
    const bool uninstall = intent.context == SshReleaseContext::Uninstall;
    try {
        const auto platform = fic::platform::makeBuildPlatformProfile();
        const auto main = platform.ssh.configPath.string();
        require(platform.id == "debian-13" && journal.usable(), "SSH MFA release unsupported or journal unavailable");
        const auto active = journal.activeRecords(policy);
        SshConfigFileHandler sshConfig(main);
        std::string error;
        const auto proveFence = [&] (std::string& detail) {
            return !uninstall || (intent.uninstallFence && intent.uninstallFence(detail));
        };
        require(proveFence(error), "SSH MFA uninstall fence unavailable: " + error);
        configuredMfa(intent.path, intent.generation, !active.empty());
        require(sshConfig.loadConfig() && sshConfig.loadSnapshot(), "SSH main configuration unavailable");
        if (active.empty()) {
            require(planSshMfaManagedBlock(sshConfig.lines(), false, false, error), error);
            for (const auto* path : {slotPath, servicePath})
                require(AtomicFileWriter::ensureTargetAbsentDurableIfCurrentState(path, &error),
                        "unowned dedicated PAM target: " + error);
            result.nothingToDo = true;
            return result;
        }
        require(active.size() == 1, "ambiguous SSH MFA ownership");
        const auto& record = active.front();
        const auto* owned = std::get_if<UndoReleaseSshMfa>(&record.undo.payload);
        require(owned && record.error.empty(), "SSH MFA journal provenance unavailable");
        require(journal.proveCurrentSshMfaAuthority(error), "RecoveryRequired: SSH MFA journal is unproven: " + error);
        const auto recheck = [&] {
            require(proveFence(error) &&
                    AtomicFileWriter::targetStateMatches(intent.path, intent.generation, &error),
                    "SSH MFA release authority changed: " + error);
            require(journal.proveCurrentSshMfaAuthority(error), "SSH MFA journal is unproven: " + error);
        };
        auto survivingPolicies = intent.survivingPolicies;
        if (uninstall) {
            // Saved values may differ from applied ownership. Verify the
            // actual ordinary blocks that this MFA transaction preserves.
            SshManagedModel model;
            require(parseSshManagedModel(sshConfig.lines(), model, error) == SshManagedParseStatus::Ok, error);
            for (const auto& block : model.policies) {
                if (sshPolicyDirectiveSemantics(block.name) == SshDirectiveSemantics::Unsupported) continue;
                const auto parsed = parseSshConfigLine(block.directiveLine);
                require(parsed.ok && parsed.hasDirective &&
                        normalizeSshKeyword(parsed.directive.keyword) ==
                            normalizeSshKeyword(sshPolicyDirectiveKeyword(block.name)),
                        "unproven surviving SSH block: " + block.name);
                survivingPolicies.emplace(block.name, joinSshArguments(parsed.directive.arguments));
            }
            if (owned->phase == SshMfaPhase::SshReleased) {
                pending = true;
                proveReleasedImage(*owned, main);
                auto source = Adapter::captureReference(survivingPolicies, owned->targetSshSha256,
                                                               SshActivationIntent::ConfigurationRelease);
                const auto admission = Adapter::admitMfaPlan(source);
                const auto preview = Adapter::validateReleasePlan(source, admission, sshConfig.loadSnapshot()->content);
                require(preview.success(), preview.diagnostic);
                proveSshChildrenDrained(admission.service);
                proveNoForeignPamReferences(platform.pam);
                recheck();
                const auto activated = Adapter::releaseConfiguration(source, admission);
                require(activated.success(), activated.diagnostic);
                proveSshChildrenDrained(activated.runtimeEvidence);
                recheck();
                proveNoForeignPamReferences(platform.pam);
                proveReleasedImage(*owned, main);
                require(journal.commitSshMfaUninstallRelease(record.id, error), error);
                result.ok = true;
                result.message = "verified SSH MFA package release acknowledged";
                return result;
            }
        }
        if (!uninstall && owned->phase == SshMfaPhase::AwaitingDisable) {
            proveReleasedImage(*owned, main);
            result.ok = true;
            result.message = "verified SSH MFA release awaits durable DISABLE";
            return result;
        }
        require(owned->phase == SshMfaPhase::Applied, "RecoveryRequired: unresolved SSH MFA transition");
        for (const auto& other : journal.records())
            if (other.id != record.id && other.undo.backend == MutationBackend::Ssh && other.isActive())
                require(other.status != MutationStatus::Prepared, "RecoveryRequired: another SSH operation is pending");
        const auto slot = proveOwnedPam(slotPath, owned->authSlot);
        const auto service = proveOwnedPam(servicePath, owned->service);
        const auto mfa = ownedMfaReference(*owned);
        const auto before = *sshConfig.loadSnapshot();
        require(planSshMfaManagedBlock(sshConfig.lines(), true, false, error), error);
        const auto planned = sshConfig.pendingContent();
        auto baseline = Adapter::captureReference(survivingPolicies, digest(before.content),
            SshActivationIntent::ConfigurationRelease, &mfa);
        const auto admission = Adapter::admitMfaPlan(baseline);
        proveSshChildrenDrained(admission.service);
        proveNoForeignPamReferences(platform.pam);
        const auto preview = Adapter::validateMfaPlan(baseline, admission, planned, std::nullopt);
        require(preview.success(), preview.diagnostic);
        recheck();
        auto fresh = Adapter::captureReference(survivingPolicies, digest(before.content),
            SshActivationIntent::ConfigurationRelease, &mfa);
        require(Adapter::sameInputGeneration(baseline, fresh, false), "SSH MFA release sources changed before publication");
        require(journal.beginSshMfaRelease(record.id, digest(before.content), digest(planned), error), error);
        pending = true;
        const auto written = restoreSshConfigContentIfCurrentState(main, planned, before, error,
            [&](const AtomicTargetState&, std::string& detail) {
                return proveFence(detail) && AtomicFileWriter::targetStateMatches(intent.path, intent.generation, &detail) &&
                       journal.proveCurrentSshMfaAuthority(detail);
            });
        if (!written.installed) {
            const auto failedWrite = error;
            recheck();
            if (AtomicFileWriter::ensureTargetDurableIfCurrentState(main, before, &error) &&
                journal.abortSshMfaReleaseNoEffect(record, error)) pending = false;
            throw std::runtime_error(failedWrite);
        }
        if (written.installedState)
            require(journal.noteSshMfaPublication(record.id, *written.installedState, written.durable, error), error);
        require(written.installed && written.durable && written.installedState, error);
        recheck();
        auto target = baseline;
        target.mfa.reset();
        target.observedMetadata.clear();
        for (auto& root : target.reference.paths)
            if (root.path == main) root.sha256 = digest(planned);
        const auto next = Adapter::admitMfaPlan(target);
        baseline.mfa.reset();
        require(Adapter::sameInputGeneration(baseline, target, true) && admission.service == next.service,
                "SSH MFA release input generation changed after publication");
        const auto activated = Adapter::releaseConfiguration(target, next);
        require(activated.success(), activated.diagnostic);
        recheck();
        require(journal.noteSshMfaRuntimeReleased(record.id, activated.observedFacts(), error), error);
        proveSshChildrenDrained(activated.runtimeEvidence);
        proveNoForeignPamReferences(platform.pam);
        auto final = target;
        const auto finalService = Adapter::admitMfaPlan(final);
        require(finalService.service.at("MainPID") == activated.runtimeEvidence.at("MainPID") &&
                finalService.service.at("InvocationID") == activated.runtimeEvidence.at("InvocationID"),
                "new SSH listener changed before PAM detachment");
        recheck();
        const auto remove = [&](const char* file, const AtomicTargetState& state) {
            AtomicRemoveResult deleted;
            require(AtomicFileWriter::removeIfCurrentState(file, state, &error, &deleted) &&
                    deleted.removed && deleted.durabilityConfirmed, "SSH MFA PAM detach unproven: " + error);
        };
        remove(servicePath, service);
        remove(slotPath, slot);
        recheck();
        proveNoForeignPamReferences(platform.pam);
        const auto released = journal.activeRecords(policy);
        require(released.size() == 1 && released.front().id == record.id,
                "SSH MFA release provenance disappeared");
        proveReleasedImage(std::get<UndoReleaseSshMfa>(released.front().undo.payload), main);
        require(uninstall ? journal.commitSshMfaUninstallRelease(record.id, error)
                          : journal.finishSshMfaRelease(record.id, error), error);
        result.ok = true;
        result.message = uninstall ? "verified SSH MFA package release acknowledged"
                                   : "SSH MFA disabled in verified runtime; owned PAM files released";
    } catch (const std::exception& error) {
        result.disposition = pending ? SshReleaseDisposition::RecoveryRequired : SshReleaseDisposition::None;
        result.message = (pending ? "RecoveryRequired: " : "") + std::string(error.what());
    }
    return result;
}

bool acknowledgeSshMfaDisable(MutationJournal& journal, const MutationRecord& record, std::string& error) {
    try {
        const auto* owned = std::get_if<UndoReleaseSshMfa>(&record.undo.payload);
        require(owned && owned->phase == SshMfaPhase::AwaitingDisable, "SSH MFA release has no acknowledgement proof");
        require(journal.proveCurrentSshMfaAuthority(error), "SSH MFA journal is unproven: " + error);
        proveReleasedImage(*owned, fic::platform::makeBuildPlatformProfile().ssh.configPath.string());
        return journal.acknowledgeSshMfaDisable(record.id, error);
    } catch (const std::exception& failure) {
        error = failure.what();
        return false;
    }
}

} // namespace fic::ssh
