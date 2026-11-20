#include "modules/identity_access/pam/PamEmptyPasswordLogin.h"

#include "modules/identity_access/pam/PamConfigFileTransaction.h"
#include "modules/identity_access/pam/PamControlFlowAnalyzer.h"
#include "modules/identity_access/pam/PamProviderManagedLock.h"
#include "rollback/MutationJournal.h"

#include <fic/core/fs/RootControlledDirectory.h>
#include <fic/core/fs/SecureStateFile.h>

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <iterator>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace fic::identity::pam {
namespace {
using namespace fic::rollback;

constexpr char rules[] =
    "auth [success=ignore perm_denied=1 default=die] pam_localuser.so\n"
    "auth [success=ok default=die] pam_unix.so use_first_pass\n"
    "auth optional pam_deny.so\n";

const PolicyRef policy{"IDENTITY_ACCESS", "PAM", emptyPasswordPolicy};
const std::string resource = std::string("capability/") + emptyPasswordPolicy;

std::string active(MutationId id) {
    return "# FIC empty-password slot v1 mutation=" + std::to_string(id) +
           "\n" + rules;
}

bool fail(std::string& error, const std::string& message) {
    error = message;
    return false;
}

fic::core::SecureStateReadResult readTrusted(
    const std::filesystem::path& path, std::string& error) {
    const int fd = fic::core::openRootControlledDirectory(path.parent_path(), error);
    if (fd < 0) return {};
    ::close(fd);
    fic::core::SecureStateFileExpectation expected;
    expected.owner = 0;
    expected.parentOwner = 0;
    expected.forbiddenMode = 0022;
    return fic::core::readSecureFileBounded(path, expected, 1024 * 1024);
}

bool proveSelection(const fic::platform::PamPlatformConfig& platform, std::string& error) {
    const auto state = readTrusted(platform.emptyPasswordAuthSelection, error);
    if (state.status != fic::core::SecureStateReadStatus::Proven)
        return fail(error, "untrusted pam-auth-update auth selection");
    std::istringstream lines(state.content);
    std::string line;
    unsigned selected = 0;
    while (std::getline(lines, line))
        if (line == std::string("Module: ") + emptyPasswordHook) ++selected;
    return selected == 1 || fail(error, "empty-password hook must be selected once by pam-auth-update");
}

bool proveModule(const fic::platform::PamPlatformConfig& platform, const char* module,
                 std::string& error) {
    for (const auto& directory : platform.moduleDirectories) {
        std::error_code ec;
        const auto root = std::filesystem::canonical(directory, ec);
        if (ec) continue;
        const int fd = fic::core::openRootControlledDirectory(root, error);
        if (fd < 0) return false;
        struct stat info {};
        const int status = ::fstatat(fd, module, &info, AT_SYMLINK_NOFOLLOW);
        const int saved = errno;
        ::close(fd);
        if (status == 0 && S_ISREG(info.st_mode) && info.st_uid == 0 &&
            (info.st_mode & 0022) == 0) return true;
        if (status == 0 || saved != ENOENT) break;
    }
    return fail(error, std::string("unavailable or untrusted PAM module: ") + module);
}

bool captureSlot(const fic::platform::PamPlatformConfig& platform,
                 PamConfigFileSnapshot& snapshot, std::string& error) {
    if (platform.emptyPasswordAuthSelection.empty() || platform.configDirectories.empty()) {
        return fail(error, "empty-password policy is unsupported on this platform");
    }
    const auto& directory = platform.configDirectories.front();
    const auto path = directory / emptyPasswordSlot;
    const auto trusted = readTrusted(path, error);
    if (trusted.status != fic::core::SecureStateReadStatus::Proven ||
        !PamConfigFileTransaction::capture(path, snapshot, error) ||
        !snapshot.existed || snapshot.owner != 0 || snapshot.group != 0 ||
        snapshot.mode != 0644 || snapshot.content != trusted.content ||
        snapshot.device != trusted.targetState.identity.device ||
        snapshot.inode != trusted.targetState.identity.inode) {
        return fail(error, "empty-password slot is missing, modified or untrusted: " +
                           path.string());
    }
    return true;
}

bool provenance(const MutationRecord& record) {
    const auto* undo = std::get_if<UndoDisablePamCapability>(&record.undo.payload);
    return record.id != 0 && record.undo.backend == MutationBackend::Pam &&
           record.resource == resource && undo &&
           undo->capability == emptyPasswordPolicy &&
           undo->topology == PamTopologyKind::PamAuthUpdate &&
           undo->activationIdentifiers == std::vector<std::string>{emptyPasswordHook} &&
           !undo->hadAppliedProvenance && !undo->targetStrategy && !undo->previousStrategy;
}

bool durable(const PamConfigFileSnapshot& slot, std::string& error) {
    return AtomicFileWriter::ensureTargetDurableIfCurrentState(
        slot.path.string(), {{slot.device, slot.inode}, slot.content,
                             slot.mode, slot.owner, slot.group}, &error);
}

bool publish(PamConfigFileSnapshot& slot, const std::string& candidate,
             std::string& error) {
    return PamConfigFileTransaction::mutate(slot, [&](const auto& writer, auto& detail) {
        return writer(slot.path.string(), candidate, {}, &detail);
    }, error);
}

bool supportedUnixRule(const PamRule& rule) {
    const auto supported = [](const auto& argument) {
        return argument == "nullok" || argument == "nullok_secure" ||
               argument == "nullresetok" || argument == "try_first_pass" ||
               argument == "use_first_pass";
    };
    return rule.module == "pam_unix.so" &&
           std::all_of(rule.arguments.begin(), rule.arguments.end(), supported);
}

bool generatedPrimaryJump(const PamRule& rule, std::size_t skip) {
    std::istringstream control(rule.control);
    std::string success, fallback, extra;
    return (control >> success >> fallback) &&
        success == "[success=" + std::to_string(skip) &&
        fallback == "default=ignore]" && !(control >> extra);
}

bool proveWinbindRoute(const PamEffectiveStack& stack,
                       const fic::platform::PamPlatformConfig& platform,
                       std::string& error) {
    const auto& entries = stack.entries;
    const auto isWinbind = [](const auto& entry) {
        return entry.rule.module == "pam_winbind.so";
    };
    const auto winbind = std::find_if(entries.begin(), entries.end(), isWinbind);
    if (winbind == entries.end()) return true;

    const auto primary = std::find_if(entries.begin(), winbind, [](const auto& entry) {
        return entry.rule.module == "pam_unix.so";
    });
    const auto fallback = std::find_if(winbind, entries.end(), [](const auto& entry) {
        return entry.rule.module == "pam_deny.so" && entry.rule.control == "requisite";
    });
    if (primary == winbind || fallback == entries.end() ||
        std::find_if(std::next(winbind), entries.end(), isWinbind) != entries.end()) {
        return fail(error, "unsupported Debian 13 winbind Primary order");
    }

    // winbind can canonicalize PAM_USER and handle PAM_AUTHTOK. The generated
    // Unix success edge must skip it, and both providers must jump past the
    // same generated requisite deny to the Primary success barrier.
    const auto permit = std::next(fallback);
    if (permit == entries.end() || permit->rule.module != "pam_permit.so" ||
        permit->rule.control != "required" ||
        permit->rule.source != winbind->rule.source ||
        fallback->rule.source != winbind->rule.source ||
        !generatedPrimaryJump(primary->rule, permit - primary - 1) ||
        !generatedPrimaryJump(winbind->rule, permit - winbind - 1)) {
        return fail(error, "unsupported Debian 13 winbind Primary transitions");
    }
    return proveModule(platform, "pam_winbind.so", error);
}

bool stageCandidate(std::vector<PamStackEntry>& entries,
                    const PamConfigFileSnapshot& slot,
                    const std::vector<PamStackEntry>& candidate,
                    unsigned& primaries, unsigned& hooks, unsigned& winbindRules,
                    std::string& error) {
    for (auto& entry : entries) {
        const PamRule& rule = entry.rule;
        if (entry.isSubstack() && rule.includeTarget == emptyPasswordSlot) {
            if (rule.source != slot.path.parent_path() / "common-auth" ||
                entry.substack.empty() ||
                entry.substack.front().rule.source != slot.path) {
                return fail(error, "empty-password substack does not resolve to its package slot");
            }
            ++hooks;
            if (!candidate.empty()) entry.substack = candidate;
            continue;
        }
        if (!entry.isSubstack()) {
            // These stock modules do not change identity or substitute a
            // different local password after pam_unix has authenticated.
            static const std::vector<std::string> supportedModules{
                "pam_unix.so", "pam_sss.so", "pam_permit.so", "pam_deny.so",
                "pam_faillock.so", "pam_faildelay.so", "pam_nologin.so",
                "pam_group.so", "pam_rootok.so", "pam_wheel.so", "pam_succeed_if.so",
                "pam_localuser.so", "pam_gnome_keyring.so", "pam_cap.so",
                "pam_env.so", "pam_selinux_permit.so"};
            if (rule.module == "pam_winbind.so") {
                ++winbindRules;
                const std::vector<std::string> nativeArgs{
                    "krb5_auth", "krb5_ccache_type=FILE", "cached_login", "try_first_pass"};
                if (rule.source != slot.path.parent_path() / "common-auth" ||
                    rule.arguments != nativeArgs)
                    return fail(error, "unsupported Debian 13 winbind arguments or source");
            } else if (std::find(supportedModules.begin(), supportedModules.end(), rule.module) ==
                       supportedModules.end()) {
                return fail(error, "unsupported authentication module in " +
                                   rule.source.string() + ": " + rule.module);
            }
        }
        if (rule.module == "pam_localuser.so" && !rule.arguments.empty())
            return fail(error, "unsupported local identity selector");
        if (rule.module == "pam_unix.so") {
            if (!supportedUnixRule(rule) ||
                rule.source != slot.path.parent_path() / "common-auth") {
                return fail(error, "unsupported pam_unix authentication rule in " +
                                   rule.source.string());
            }
            ++primaries;
        }
        if (rule.module == "pam_sss.so" &&
            (rule.source != slot.path.parent_path() / "common-auth" ||
             (rule.arguments != std::vector<std::string>{"use_first_pass"} &&
              rule.arguments != std::vector<std::string>{"forward_pass"}))) {
            return fail(error, "unsupported pam_sss authentication rule");
        }
        if (!stageCandidate(entry.substack, slot, candidate, primaries, hooks, winbindRules, error))
            return false;
    }
    return true;
}

bool proveGraph(const fic::platform::PamPlatformConfig& platform,
                const PamConfigFileSnapshot& slot, bool simulate,
                bool& safe, std::string& error) {
    PamConfiguration configuration(platform);
    std::vector<PamStackEntry> candidate;
    if (simulate) {
        std::vector<PamRule> parsed;
        if (!PamConfiguration::parseRulesContent(slot.path, rules, parsed, error))
            return false;
        for (auto& rule : parsed) candidate.push_back({std::move(rule), {}});
    }
    if (!proveModule(platform, "pam_unix.so", error)) return false;
    if ((simulate || slot.content != emptyPasswordNeutral) &&
        (!proveSelection(platform, error) ||
         !proveModule(platform, "pam_localuser.so", error) ||
         !proveModule(platform, "pam_deny.so", error))) return false;
    std::vector<std::string> services{"common-auth", "login"};
    for (const auto& scope : platform.scopes) {
        if (scope.scope != fic::platform::PamScope::EffectiveAuthenticationStack) continue;
        std::vector<std::string> existing;
        if (!configuration.existingServices(scope.services, existing, error)) return false;
        for (const auto& service : existing)
            if (service != "login" && service != "common-auth") services.push_back(service);
    }
    safe = true;
    unsigned commonWinbindRules = 0;
    for (const auto& service : services) {
        PamEffectiveStack stack;
        unsigned primaries = 0;
        unsigned hooks = 0;
        unsigned winbindRules = 0;
        bool serviceSafe = false;
        if (!configuration.buildEffectiveStack(service, PamManagementGroup::Auth, stack, error) ||
            !stageCandidate(stack.entries, slot, candidate, primaries, hooks, winbindRules, error)) return false;
        if (service == "common-auth") commonWinbindRules = winbindRules;
        if (winbindRules != commonWinbindRules)
            return fail(error, "winbind is outside its proven common-auth route");
        if (service == "common-auth" && winbindRules != 0) {
            const auto direct = std::count_if(stack.entries.begin(), stack.entries.end(),
                [](const auto& entry) { return entry.rule.module == "pam_winbind.so"; });
            if (winbindRules != 1 || direct != 1)
                return fail(error, "winbind must be a single direct Debian 13 Primary rule");
            if (!proveWinbindRoute(stack, platform, error)) return false;
        }
        const bool needsHook = simulate || slot.content != emptyPasswordNeutral;
        if (primaries != 1 || hooks > 1 || (needsHook && hooks != 1))
            return fail(error, "unsupported primary or empty-password hook topology in " + service);
        for (const auto& source : stack.sourceFiles)
            if (readTrusted(source, error).status != fic::core::SecureStateReadStatus::Proven)
                return fail(error, "untrusted empty-password PAM graph source: " + source.string());
        if (service == "common-auth" && needsHook) {
            // The active substack consumes a token acquired by the stock
            // primary block. Keep it after the fallback and permit barrier.
            const auto guard = std::find_if(stack.entries.begin(), stack.entries.end(),
                [](const auto& entry) { return entry.rule.includeTarget == emptyPasswordSlot; });
            const auto primary = std::find_if(stack.entries.begin(), guard,
                [](const auto& entry) { return entry.rule.module == "pam_unix.so"; });
            const auto fallback = std::find_if(primary, guard,
                [](const auto& entry) {
                    return entry.rule.module == "pam_deny.so" && entry.rule.control == "requisite";
                });
            const auto permit = std::find_if(fallback, guard,
                [](const auto& entry) {
                    return entry.rule.module == "pam_permit.so" && entry.rule.control == "required";
                });
            if (guard == stack.entries.end() || permit == guard)
                return fail(error, "empty-password hook must follow the generated primary block");
            if (std::any_of(guard, stack.entries.end(), [](const auto& entry) {
                    return entry.rule.module == "pam_sss.so";
                })) return fail(error, "pam_sss is outside the generated primary block");
        }
        if (std::any_of(stack.entries.begin(), stack.entries.end(), [](const auto& entry) {
                return entry.rule.module == "pam_sss.so";
            }) && !proveModule(platform, "pam_sss.so", error)) return false;
        if (!proveNoEmptyUnixPasswordPath(stack, platform, serviceSafe, error)) return false;
        safe &= serviceSafe;
    }
    return true;
}

bool verify(const fic::platform::PamPlatformConfig& platform,
            const PamConfigFileSnapshot& slot, bool candidate, std::string& error) {
    bool safe = false;
    return proveGraph(platform, slot, candidate, safe, error) &&
           (safe || fail(error, "a successful local blank-password path bypasses the PAM check"));
}

} // namespace

bool applyEmptyPasswordLogin(const fic::platform::PamPlatformConfig& platform,
                             MutationJournal& journal, std::string& error) {
    PamProviderManagedLock::Handle lock;
    if (!PamProviderManagedLock::acquire(lock, error)) return false;
    if (!journal.usable()) return fail(error, "empty-password journal is not usable");
    const auto records = journal.activeRecords(policy);
    if (records.size() > 1 || (!records.empty() && !provenance(records.front())))
        return fail(error, "ambiguous empty-password journal provenance");

    PamConfigFileSnapshot slot;
    if (!captureSlot(platform, slot, error)) return false;
    if (!records.empty()) {
        const auto& record = records.front();
        if (slot.content == active(record.id) &&
            (record.status == MutationStatus::Prepared ||
             record.status == MutationStatus::Applied)) {
            return verify(platform, slot, false, error) && durable(slot, error) &&
                   (record.status == MutationStatus::Applied ||
                    journal.setStatus(record.id, MutationStatus::Applied, error));
        }
        if (record.status != MutationStatus::Prepared || slot.content != emptyPasswordNeutral)
            return fail(error, "empty-password slot no longer matches its journal");
        if (!durable(slot, error) || !journal.discard(record.id, error)) return false;
    }
    if (slot.content != emptyPasswordNeutral)
        return fail(error, "unowned empty-password slot or foreign content");

    bool alreadySafe = false;
    if (!proveGraph(platform, slot, false, alreadySafe, error)) return false;
    if (alreadySafe) return true;
    if (!verify(platform, slot, true, error)) return false;

    MutationRecord prepared;
    prepared.policy = policy;
    prepared.resource = resource;
    prepared.undo.backend = MutationBackend::Pam;
    UndoDisablePamCapability undo;
    undo.capability = emptyPasswordPolicy;
    undo.topology = PamTopologyKind::PamAuthUpdate;
    undo.activationIdentifiers = {emptyPasswordHook};
    prepared.undo.payload = std::move(undo);
    MutationId id = 0;
    if (!journal.prepareMutation(std::move(prepared), id, error)) return false;

    PamConfigFileSnapshot installed;
    if (publish(slot, active(id), error) &&
        captureSlot(platform, installed, error) &&
        installed.content == active(id) &&
        verify(platform, installed, false, error) && durable(installed, error)) {
        return journal.setStatus(id, MutationStatus::Applied, error);
    }
    if (error.empty()) error = "empty-password publication was not proven";
    std::string compensation;
    if (!PamConfigFileTransaction::rollback(slot, compensation)) {
        error += "; empty-password compensation failed: " + compensation;
        return false;
    }
    PamConfigFileSnapshot restored;
    if (!captureSlot(platform, restored, compensation) ||
        restored.content != emptyPasswordNeutral || !durable(restored, compensation)) {
        error += "; Prepared retained because the neutral slot is unproven";
        if (!compensation.empty()) error += ": " + compensation;
    } else if (!journal.discard(id, compensation)) {
        error += "; " + compensation;
    }
    return false;
}

bool releaseEmptyPasswordLogin(const fic::platform::PamPlatformConfig& platform,
                               MutationId id, bool& changed, std::string& error) {
    changed = false;
    PamProviderManagedLock::Handle lock;
    PamConfigFileSnapshot slot;
    if (!PamProviderManagedLock::acquire(lock, error) ||
        !captureSlot(platform, slot, error)) return false;
    if (slot.content == emptyPasswordNeutral) return durable(slot, error);
    if (id == 0 || slot.content != active(id))
        return fail(error, "empty-password release has no matching physical witness");
    if (!publish(slot, emptyPasswordNeutral, error)) {
        std::string compensation;
        if (!PamConfigFileTransaction::rollback(slot, compensation))
            error += "; empty-password release compensation failed: " + compensation;
        return false;
    }
    PamConfigFileSnapshot released;
    if (!captureSlot(platform, released, error) || released.content != emptyPasswordNeutral)
        return fail(error, "empty-password release postcondition was not proven");
    changed = durable(released, error);
    return changed;
}

bool proveEmptyPasswordSlot(const fic::platform::PamPlatformConfig& platform,
                            const MutationJournal& journal, std::string& error) {
    PamConfigFileSnapshot slot;
    if (!captureSlot(platform, slot, error)) return false;
    const auto records = journal.activeRecords(policy);
    if (!journal.usable()) return fail(error, "empty-password journal is not usable");
    if (records.empty() && slot.content == emptyPasswordNeutral) return true;
    if (records.size() == 1 && provenance(records.front())) {
        const auto& record = records.front();
        if ((record.status == MutationStatus::Prepared &&
             slot.content == emptyPasswordNeutral) ||
            ((record.status == MutationStatus::Prepared || record.status == MutationStatus::Applied) &&
             slot.content == active(record.id))) return true;
    }
    return fail(error, "empty-password slot attach has ambiguous ownership");
}

} // namespace fic::identity::pam
