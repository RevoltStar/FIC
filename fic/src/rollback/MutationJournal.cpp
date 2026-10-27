#include "rollback/MutationJournal.h"

#include <fic/core/fs/AtomicFileWriter.h>
#include <fic/core/integrity/ContentDigest.h>
#include <modules/dac/sudo/SudoersDisabledWrapper.h>
#include <modules/dac/sudo/SudoersScopedDefaultsTransaction.h>
#include <modules/identity_access/pam/PamProviderManagedBlock.h>
#include <modules/identity_access/shared/login_defs/IdentityLoginDefsPolicySpec.h>
#include <modules/oss/grub/GrubManagedBlock.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <ctime>
#include <functional>
#include <limits>
#include <stdexcept>
#include <map>
#include <set>
#include <system_error>
#include <utility>

#include <sys/types.h>

namespace fic::rollback {

bool validateSudoGlobalDefaultPayload(const UndoReleaseSudoGlobalDefault& payload,
                                      std::string& error) {
    if ((payload.addedSeparator && (payload.separatorPrefixDigest.size() != 64 ||
         !std::all_of(payload.separatorPrefixDigest.begin(), payload.separatorPrefixDigest.end(),
                      [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }))) ||
        (!payload.addedSeparator && !payload.separatorPrefixDigest.empty())) {
        error = "Invalid SUDO include separator provenance";
        return false;
    }
    const auto validLine = [&](const std::string& line) {
        if (payload.key == "exempt_group") return line == "Defaults !exempt_group";
        if (payload.key == "env_reset")
            return line == "Defaults " + payload.key || line == "Defaults !" + payload.key;
        const std::string prefix = "Defaults " + payload.key + "=";
        if (line.compare(0, prefix.size(), prefix) != 0 || line.size() == prefix.size()) return false;
        const std::string value = line.substr(prefix.size());
        if (payload.key == "passwd_tries" || payload.key == "timestamp_timeout")
            return std::all_of(value.begin(), value.end(), [](unsigned char c) { return c >= '0' && c <= '9'; });
        if (payload.key != "secure_path") return false;
        // No additional assignment, scoped selector, comment or continuation
        // may be smuggled into an ownership proof. Native syntax and the
        // policy's secure-path validator still run independently.
        return value.find_first_of("\r\n,=#\\") == std::string::npos &&
            value.find('\0') == std::string::npos;
    };
    if (!fic::sudoers::isCanonicalSudoWrapperId(payload.containerId) ||
        !validLine(payload.appliedLine) ||
        (!payload.previousLine.empty() && !validLine(payload.previousLine))) {
        error = "Invalid SUDO global ownership payload";
        return false;
    }
    return true;
}

bool validateSudoAuthenticationPayload(const UndoReleaseSudoAuthentication& payload, std::string& error) {
    auto validate = [&](const auto& proofs) {
        std::set<std::string> ids;
        for (const auto& proof : proofs) {
            if (!fic::sudoers::isCanonicalSudoWrapperId(proof.wrapperId) ||
                !fic::sudoers::isCanonicalSudoProofPath(proof.canonicalPath) ||
                !fic::core::ContentDigest::isCanonicalSha256Hex(proof.originalDigest) ||
                !fic::core::ContentDigest::isCanonicalSha256Hex(proof.replacementDigest) ||
                !ids.insert(proof.wrapperId).second) return false;
        }
        return true;
    };
    if (payload.targetProofs.empty() || !validate(payload.previousProofs) || !validate(payload.targetProofs)) {
        error = "Invalid SUDO authentication ownership proofs"; return false;
    }
    for (const auto& proof : payload.previousProofs)
        if (std::find(payload.targetProofs.begin(), payload.targetProofs.end(), proof) == payload.targetProofs.end()) {
            error = "Authentication refresh would orphan previous ownership"; return false;
        }
    return true;
}

bool validateSudoGlobalRecord(const MutationRecord& record, std::string& error) {
    if (const auto* auth = std::get_if<UndoReleaseSudoAuthentication>(&record.undo.payload)) {
        if (record.undo.backend != MutationBackend::Sudo || record.policy.moduleName != "DAC" ||
            record.policy.submoduleName != "SudoEdit" || record.policy.policyName != fic::sudoers::kAuthenticationPolicy ||
            record.resource != fic::sudoers::kAuthenticationResource) {
            error = "SUDO authentication record identity mismatch"; return false;
        }
        return validateSudoAuthenticationPayload(*auth, error);
    }
    const auto* payload = std::get_if<UndoReleaseSudoGlobalDefault>(&record.undo.payload);
    if (!payload) return true;
    const std::map<std::string, std::string> policies{
        {"env_reset", "sudo_env_reset"}, {"passwd_tries", "sudo_passwd_tries"},
        {"secure_path", "sudo_securepath"}, {"timestamp_timeout", "sudo_timeout"},
        {"exempt_group", "sudo_exempt_group_disable"}};
    const auto route = policies.find(payload->key);
    if (route == policies.end() || record.undo.backend != MutationBackend::Sudo ||
        record.policy.moduleName != "DAC" || record.policy.submoduleName != "SudoEdit" ||
        record.policy.policyName != route->second || record.resource != payload->key) {
        error = "SUDO global record identity does not match ownership";
        return false;
    }
    return validateSudoGlobalDefaultPayload(*payload, error);
}

// Write/read parity validators for the SUDO scoped-Defaults payload: the writer
// must never persist a record the loader would reject.
bool validateSudoScopedDefaultsProof(
    const SudoScopedDefaultsWrapperProof& proof, std::string& error) {
    if (proof.wrapperId.empty()) {
        error = "SUDO scoped wrapper proof requires a non-empty wrapper id";
        return false;
    }
    if (!fic::sudoers::isCanonicalSudoWrapperId(proof.wrapperId)) {
        error = "SUDO scoped wrapper id has a non-canonical form: '" +
            proof.wrapperId + "'";
        return false;
    }
    if (!fic::sudoers::isCanonicalSudoProofPath(proof.canonicalPath)) {
        error = "SUDO scoped wrapper proof requires a canonical absolute path, "
                "got: '" + proof.canonicalPath + "'";
        return false;
    }
    if (!fic::core::ContentDigest::isCanonicalSha256Hex(proof.payloadDigest)) {
        error = "SUDO scoped wrapper proof requires a canonical sha256 payload "
                "digest, got: '" + proof.payloadDigest + "'";
        return false;
    }
    return true;
}

bool validateProofSetUnique(
    const std::vector<SudoScopedDefaultsWrapperProof>& proofs,
    const char* label,
    std::string& error) {
    std::set<std::string> seen;
    for (const SudoScopedDefaultsWrapperProof& proof : proofs) {
        if (!validateSudoScopedDefaultsProof(proof, error)) {
            return false;
        }
        if (!seen.insert(proof.wrapperId).second) {
            error = std::string(label) + " contains a duplicate wrapper id: '" +
                proof.wrapperId + "'";
            return false;
        }
    }
    return true;
}

bool validateSudoScopedDefaultsUndoPayload(
    const UndoReleaseSudoScopedDefaults& payload, std::string& error) {
    if (payload.policyName != fic::sudoers::kScopedDefaultsPolicyName) {
        error = "SUDO scoped defaults payload policy mismatch: expected '" +
            std::string(fic::sudoers::kScopedDefaultsPolicyName) + "', got '" +
            payload.policyName + "'";
        return false;
    }
    if (!validateProofSetUnique(payload.previousProofs, "previous_proofs",
                                error) ||
        !validateProofSetUnique(payload.targetProofs, "target_proofs", error)) {
        return false;
    }
    // A refresh GROWS the ownership set: every wrapper FIC owned BEFORE the
    // transition (previous) must still be owned AFTER it (target). A previous
    // proof missing from the target set would silently orphan a live wrapper,
    // so it is refused rather than guessed.
    std::map<std::string, std::pair<std::string, std::string>> targetById;
    for (const SudoScopedDefaultsWrapperProof& proof : payload.targetProofs) {
        targetById.emplace(
            proof.wrapperId,
            std::make_pair(proof.canonicalPath, proof.payloadDigest));
    }
    for (const SudoScopedDefaultsWrapperProof& proof : payload.previousProofs) {
        const auto found = targetById.find(proof.wrapperId);
        if (found == targetById.end()) {
            error = "wrapper id '" + proof.wrapperId +
                "' is claimed as previously owned but is absent from the "
                "target proofs; FIC would orphan a live wrapper (fail closed)";
            return false;
        }
        if (found->second !=
            std::make_pair(proof.canonicalPath, proof.payloadDigest)) {
            error = "wrapper id '" + proof.wrapperId +
                "' carries a different path or digest in previous and target "
                "proofs (fail closed)";
            return false;
        }
    }
    // A record that claims ownership must actually prove at least one wrapper;
    // an empty target set cannot legitimately coexist with non-empty previous.
    if (payload.previousProofs.empty() && payload.targetProofs.empty()) {
        error = "SUDO scoped-defaults record must prove at least one wrapper "
                "(fail closed)";
        return false;
    }
    return true;
}

// True when both sides of a refresh transition are identical: an unresolved
// Prepared record may only be re-prepared with the EXACT same transition.
bool sameSudoScopedDefaultsTransition(
    const UndoReleaseSudoScopedDefaults& left,
    const UndoReleaseSudoScopedDefaults& right) {
    return left.policyName == right.policyName &&
        left.previousProofs == right.previousProofs &&
        left.targetProofs == right.targetProofs;
}
namespace {

using nlohmann::json;

// PAM managed-block grammar helpers (identity/suppression tokens, canonical
// bodies) live in fic::identity::pam.
using fic::identity::pam::isValidPamProviderSuppressionId;

std::int64_t currentEpochSeconds() {
    return static_cast<std::int64_t>(::time(nullptr));
}

// Test-only seam storage (see setLoadAfterCaptureHookForTests(),
// setBeforeVirginJournalInstallHookForTests() and
// setBeforeFinalJournalProofHookForTests()).
std::function<void()>& loadAfterCaptureHook() {
    static std::function<void()> hook;
    return hook;
}

std::function<void()>& beforeVirginJournalInstallHook() {
    static std::function<void()> hook;
    return hook;
}

std::function<void()>& beforeFinalJournalProofHook() {
    static std::function<void()> hook;
    return hook;
}

bool validScopeCheckpoint(const ScopeTransitionCheckpoint& checkpoint,
                          std::string& error) {
    const std::set<std::string> known{"FLY", "GNOME", "KDE", "XFCE", "LXQT", "SDDM", "GDM", "LIGHTDM"};
    const auto valid = [&](const std::vector<std::string>& scope) {
        return std::is_sorted(scope.begin(), scope.end()) &&
            std::adjacent_find(scope.begin(), scope.end()) == scope.end() &&
            std::all_of(scope.begin(), scope.end(),
                        [&](const auto& name) { return known.count(name) != 0; });
    };
    if (!valid(checkpoint.committedScope) || !valid(checkpoint.targetScope) ||
        (checkpoint.phase != "pending" && checkpoint.phase != "failed" &&
         checkpoint.phase != "partial" && checkpoint.phase != "committed") ||
        (checkpoint.phase == "committed" && checkpoint.targetScope.empty())) {
        error = "invalid canonical graphical scope checkpoint";
        return false;
    }
    return true;
}

bool validScopeRecord(const MutationRecord& record, std::string& error) {
    const auto* checkpoint = std::get_if<ScopeTransitionCheckpoint>(&record.undo.payload);
    const bool dm = record.resource == "scope/dm";
    const PolicyRef expected{"OSS", dm ? "DisplayManager" : "DesktopEnvironment",
        dm ? "controlled_display_managers" : "controlled_desktop_environments"};
    const std::set<std::string> known = dm ? std::set<std::string>{"SDDM", "GDM", "LIGHTDM"}
        : std::set<std::string>{"FLY", "GNOME", "KDE", "XFCE", "LXQT"};
    if (record.undo.backend != MutationBackend::Scope || !checkpoint || record.policy != expected ||
        record.resource != (dm ? "scope/dm" : "scope/de") || !validScopeCheckpoint(*checkpoint, error) ||
        !std::all_of(checkpoint->committedScope.begin(), checkpoint->committedScope.end(), [&](const auto& x){return known.count(x);}) ||
        !std::all_of(checkpoint->targetScope.begin(), checkpoint->targetScope.end(), [&](const auto& x){return known.count(x);}) ||
        (record.status == MutationStatus::Applied && checkpoint->phase != "committed")) {
        error = "invalid graphical scope checkpoint identity or payload: " + error; return false;
    }
    return true;
}

bool validDmRecord(const MutationRecord& record, std::string& error) {
    const auto* p = std::get_if<UndoRemoveDisplayManagerBlock>(&record.undo.payload);
    if (!p || record.undo.backend != MutationBackend::DisplayManager ||
        record.policy != PolicyRef{"OSS", "DisplayManager", "disable_autologin"} ||
        (p->manager != "SDDM" && p->manager != "GDM" && p->manager != "LIGHTDM") ||
        record.resource != "DM/" + p->manager + "/autologin" || p->route != 0 ||
        (p->phase != "ensure" && p->phase != "release") ||
        (p->separator != "" && p->separator != "\n") ||
        (p->createdFile && !p->separator.empty()) ||
        (!p->createdFile && (p->creationDevice || p->creationInode)) ||
        (record.status == MutationStatus::Applied && p->createdFile && !p->creationInode) ||
        (p->manager != "LIGHTDM" && !p->seats.empty()) ||
        (p->manager == "LIGHTDM" && (p->seats.empty() || p->seats.size() > 128 ||
            !std::binary_search(p->seats.begin(),p->seats.end(),std::string("Seat:*")) ||
            !std::is_sorted(p->seats.begin(), p->seats.end()) ||
            std::adjacent_find(p->seats.begin(), p->seats.end()) != p->seats.end())) ||
        (record.status == MutationStatus::Applied && (!p->hadApplied || p->phase != "ensure"))) {
        error = "invalid DM block ownership identity/lifecycle"; return false;
    }
    for (const auto& seat : p->seats) {
        if ((seat != "SeatDefaults" && seat.compare(0, 5, "Seat:") != 0) || seat.size() > 128 ||
            seat.find_first_of("\r\n[]\0", 0, 5) != std::string::npos ||
            !std::all_of(seat.begin(), seat.end(), [](unsigned char c){return c >= 32 && c < 127;})) {
            error = "invalid DM seat route"; return false;
        }
    }
    return true;
}

bool validDesktopRecord(const MutationRecord& record, std::string& error) {
    if (const auto* artifact = std::get_if<UndoOwnDesktopArtifact>(&record.undo.payload)) {
        const std::set<std::string> kinds{"dconf-directory", "database-directory", "profile-directory", "source-directory", "locks-directory", "keyfile", "lockfile",
            "profile", "profile-entry", "session-group", "screensaver-group", "lockdown-group", "cache"};
        const bool directory = artifact->kind.find("-directory") != std::string::npos;
        if (record.undo.backend != MutationBackend::Desktop ||
            record.policy != PolicyRef{"OSS", "DesktopEnvironment", "screenlock_timeout"} ||
            !kinds.count(artifact->kind) || record.resource != "GNOME/artifact/" + artifact->kind ||
            (artifact->phase != "ensure" && artifact->phase != "release") ||
            (!directory && (artifact->device || artifact->inode)) ||
            (directory && artifact->hadApplied && !artifact->inode) ||
            (record.status == MutationStatus::Applied && (!artifact->hadApplied || artifact->phase != "ensure"))) {
            error = "invalid GNOME artifact creation identity/lifecycle"; return false;
        }
        return true;
    }
    const auto* scalar = std::get_if<UndoRestoreDesktopScalar>(&record.undo.payload);
    if (!scalar) { error = "missing desktop scalar payload"; return false; }
    const std::set<std::string> gnomeBooleans{
        "/org/gnome/desktop/screensaver/lock-enabled",
        "/org/gnome/desktop/lockdown/disable-lock-screen"};
    const std::set<std::string> gnomeIntegers{
        "/org/gnome/desktop/session/idle-delay",
        "/org/gnome/desktop/screensaver/lock-delay"};
    const bool fly = scalar->desktop == "FLY" &&
        scalar->setting == "themerc/Variables/ScreenSaverDelay";
    const bool gnome = scalar->desktop == "GNOME" &&
        (gnomeBooleans.count(scalar->setting) || gnomeIntegers.count(scalar->setting));
    const std::string key = fly ? "ScreenSaverDelay" :
        scalar->setting.substr(scalar->setting.find_last_of('/') + 1);
    const auto rawLine = [](const std::string& line, std::string& raw) {
        if (line.size() > 4096 || line.find('\0') != std::string::npos) return false;
        raw = line;
        if (!raw.empty() && raw.back() == '\n') raw.pop_back();
        if (!raw.empty() && raw.back() == '\r') raw.pop_back();
        return raw.find_first_of("\r\n") == std::string::npos;
    };
    const auto validLine = [&](const std::string& line, bool applied) {
        std::string raw;
        if (!rawLine(line, raw)) return false;
        if (!applied) {
            const auto equals = raw.find('=');
            if (equals == std::string::npos) return false;
            std::string left = raw.substr(0, equals);
            const auto begin = left.find_first_not_of(" \t");
            const auto end = left.find_last_not_of(" \t");
            return begin != std::string::npos &&
                left.substr(begin, end - begin + 1) == key;
        }
        const std::string prefix = key + "=";
        if (line != raw + "\n" || raw.compare(0, prefix.size(), prefix) != 0) return false;
        std::string value = raw.substr(prefix.size());
        if (gnomeBooleans.count(scalar->setting)) return value == "true" || value == "false";
        if (gnome) {
            if (value.compare(0, 7, "uint32 ") != 0) return false;
            value.erase(0, 7);
        }
        if (value.empty() || value.size() > (fly ? 4U : 10U) ||
            !std::all_of(value.begin(), value.end(), [](unsigned char c) {
                return c >= '0' && c <= '9';
            })) return false;
        const auto number = std::stoull(value);
        return value == std::to_string(number) && (fly
            ? number >= 60 && number <= 1200 && number % 60 == 0
            : number <= 0xffffffffULL);
    };
    const auto validLock = [&] {
        if (fly) return !scalar->originalLockLine;
        if (!scalar->originalLockLine) return true;
        std::string raw;
        return rawLine(*scalar->originalLockLine, raw) && raw == scalar->setting;
    };
    const auto validOwner = [](const PolicyRef& owner) {
        return owner.moduleName == "OSS" && owner.submoduleName == "DesktopEnvironment" &&
            (owner.policyName == "screenlock_timeout" ||
             owner.policyName == "disable_kde_lock_screen_media_controls");
    };
    if (record.undo.backend != MutationBackend::Desktop || !scalar ||
        record.policy != PolicyRef{"OSS", "DesktopEnvironment", "screenlock_timeout"} ||
        (!fly && !gnome) ||
        record.resource != (fly ? "FLY/" + scalar->setting : "GNOME" + scalar->setting) ||
        !validLock() ||
        (fly && (!scalar->compiledBeforeDigest.empty() || !scalar->compiledTargetDigest.empty())) ||
        (gnome && (!fic::core::ContentDigest::isCanonicalSha256Hex(scalar->compiledBeforeDigest) ||
                   !fic::core::ContentDigest::isCanonicalSha256Hex(scalar->compiledTargetDigest))) ||
        (scalar->phase != "ensure" && scalar->phase != "release") ||
        (scalar->phase == "ensure" && scalar->owners.empty()) ||
        (scalar->phase == "release" && !scalar->owners.empty()) ||
        !std::is_sorted(scalar->owners.begin(), scalar->owners.end()) ||
        std::adjacent_find(scalar->owners.begin(), scalar->owners.end()) != scalar->owners.end() ||
        !std::all_of(scalar->owners.begin(), scalar->owners.end(), validOwner) ||
        !validLine(scalar->appliedLine, true) ||
        (scalar->originalLine && !validLine(*scalar->originalLine, false)) ||
        (scalar->previousAppliedLine && !validLine(*scalar->previousAppliedLine, true)) ||
        (record.status == MutationStatus::Applied &&
         (!scalar->hadApplied || scalar->phase != "ensure"))) {
        error = "invalid desktop scalar identity, owners, phase or inverse delta";
        return false;
    }
    return true;
}

json serializeSshProjection(const SshOwnedProjection& p) {
    return {{"value",p.value},{"disabled_ids",p.disabledIds},{"ownership_version",p.ownershipVersion},
        {"wrapper_fingerprints",p.wrapperFingerprints}};
}
bool validSshProjection(const SshOwnedProjection& p,std::string& error) {
    // Schema 2 had no projection-specific size limit. Preserve its reader
    // contract rather than imposing a new limit on historical permissions.
    if(p.value.empty()||p.ownershipVersion>1||
       (p.ownershipVersion==0&&!p.wrapperFingerprints.empty())) {
        error="invalid SSH ownership projection";return false;
    }
    if(p.ownershipVersion==1) {
        if(p.value.size()>4096||p.value.find_first_of("\r\n\0",0,3)!=std::string::npos) {
            error="invalid SSH versioned value";return false;
        }
        std::set<std::string> ids;
        for(const auto& id:p.disabledIds) {
            const auto h=p.wrapperFingerprints.find(id);
            if(id.empty()||id.size()>256||!ids.insert(id).second||h==p.wrapperFingerprints.end()||
               !fic::core::ContentDigest::isCanonicalSha256Hex(h->second)) {
                error="SSH creation-bound wrapper proof incomplete/duplicated";return false;
            }
        }
        if(ids.size()!=p.wrapperFingerprints.size()){error="extra SSH wrapper fingerprint";return false;}
    }
    return true;
}
SshOwnedProjection deserializeSshProjection(const json& j) {
    if(!j.is_object()||!j.at("ownership_version").is_number_unsigned()||j.at("ownership_version")>1||
       !j.at("wrapper_fingerprints").is_object()||!j.at("disabled_ids").is_array())
        throw std::runtime_error("invalid SSH projection types/version");
    return {j.at("value").get<std::string>(),j.at("disabled_ids").get<std::vector<std::string>>(),
        j.at("ownership_version").get<std::uint32_t>(),j.at("wrapper_fingerprints").get<std::map<std::string,std::string>>()};
}
const char* sshPhaseName(SshTransitionPhase phase) {
    switch(phase) {
    case SshTransitionPhase::Prepared:return "prepared";
    case SshTransitionPhase::Published:return "published";
    case SshTransitionPhase::DurablePublished:return "durable_published";
    case SshTransitionPhase::RuntimeVerified:return "runtime_verified";
    case SshTransitionPhase::Completed:return "completed";
    case SshTransitionPhase::OfflineVerified:return "offline_verified";
    case SshTransitionPhase::ReleasedAwaitingDisable:return "released_awaiting_disable";
    }
    return "unknown";
}
json serializeSshTransition(const SshOwnershipTransition& t) {
    json publication=nullptr;
    if(t.publication) {const auto& p=*t.publication;publication={{"device",p.device},{"inode",p.inode},
        {"mode",p.mode},{"owner",p.owner},{"group",p.group},{"sha256",p.sha256},{"durable",p.durable}};}
    json encoded={{"version",t.version},{"intent",t.intent==SshTransitionIntent::Refresh?"refresh":"release"},{"sequence",t.sequence},{"phase",sshPhaseName(t.phase)},
        {"previous",serializeSshProjection(t.previous)},{"target",t.intent==SshTransitionIntent::Release?json(nullptr):serializeSshProjection(t.target)},
        {"before_sha256",t.beforeSha256},{"target_sha256",t.targetSha256},
        {"publication",publication},{"runtime_facts",t.runtimeFacts}};
    if(t.intent==SshTransitionIntent::Release) {
        encoded["file_replacement"]=t.fileReplacement;
        encoded["predecessor_status"]=mutationStatusToString(t.predecessorStatus);
        encoded["predecessor_error"]=t.predecessorError;
    }
    return encoded;
}
bool deserializeSshTransition(const json& j,SshOwnershipTransition& t,std::string& error) {
    if(!j.is_object()||!j.at("version").is_number_unsigned()||!j.at("sequence").is_number_unsigned()) {
        error="invalid SSH operation contract";return false;
    }
    if(j.at("intent")=="refresh"&&j.at("version")==1) {t.intent=SshTransitionIntent::Refresh;t.version=1;}
    else if(j.at("intent")=="release"&&j.at("version")==2) {
        t.intent=SshTransitionIntent::Release;t.version=2;
        if(!j.at("file_replacement").is_boolean()||!j.at("target").is_null()||
           !mutationStatusFromString(j.at("predecessor_status").get<std::string>(),t.predecessorStatus)) {
            error="invalid SSH release contract";return false;
        }
        t.fileReplacement=j.at("file_replacement").get<bool>();t.predecessorError=j.at("predecessor_error").get<std::string>();
    } else {error="unsupported SSH operation contract";return false;}
    t.sequence=j.at("sequence").get<std::uint64_t>();
    bool found=false;
    for(auto phase:{SshTransitionPhase::Prepared,SshTransitionPhase::Published,SshTransitionPhase::DurablePublished,
                   SshTransitionPhase::RuntimeVerified,SshTransitionPhase::Completed,SshTransitionPhase::OfflineVerified,SshTransitionPhase::ReleasedAwaitingDisable})
        if(j.at("phase")==sshPhaseName(phase)){t.phase=phase;found=true;}
    if(!found){error="unknown SSH operation phase";return false;}
    t.previous=deserializeSshProjection(j.at("previous"));
    if(t.intent==SshTransitionIntent::Refresh)t.target=deserializeSshProjection(j.at("target"));
    t.beforeSha256=j.at("before_sha256").get<std::string>();t.targetSha256=j.at("target_sha256").get<std::string>();
    t.runtimeFacts=j.at("runtime_facts").get<std::map<std::string,std::string>>();
    const auto& p=j.at("publication");
    if(!p.is_null()) {
        for(const auto* key:{"device","inode","mode","owner","group"})
            if(!p.at(key).is_number_unsigned()){error="invalid SSH publication identity";return false;}
        if(p.at("mode")>07777||p.at("owner")>std::numeric_limits<std::uint32_t>::max()||p.at("group")>std::numeric_limits<std::uint32_t>::max()||!p.at("durable").is_boolean()){error="invalid SSH publication durability";return false;}
        t.publication=SshPublicationProof{p.at("device").get<std::uint64_t>(),p.at("inode").get<std::uint64_t>(),
            p.at("mode").get<std::uint32_t>(),p.at("owner").get<std::uint32_t>(),p.at("group").get<std::uint32_t>(),
            p.at("sha256").get<std::string>(),p.at("durable").get<bool>()};
    }
    return true;
}
bool validSshRecord(const MutationRecord& record,std::string& error) {
    if(record.undo.backend!=MutationBackend::Ssh)return true;
    const auto* p=std::get_if<UndoRemoveSshManagedPolicy>(&record.undo.payload);
    if(!p||!validSshProjection(sshOwnedProjection(*p),error))return false;
    const bool identity=record.policy.moduleName=="NET"&&record.policy.submoduleName=="SshEdit"&&
        record.policy.policyName==p->policyName&&record.resource.rfind("ssh:/",0)==0;
    if(p->ownershipVersion==1&&!identity){error="invalid SSH versioned ownership identity";return false;}
    if(!p->transition)return true;
    const auto& t=*p->transition;
    const bool release=t.intent==SshTransitionIntent::Release;
    if((!release&&t.intent!=SshTransitionIntent::Refresh)||!identity||
       std::string(sshPhaseName(t.phase))=="unknown"||t.version!=(release?2u:1u)||
       !t.sequence||t.sequence!=p->operationSequence||!validSshProjection(t.previous,error)||
       !fic::core::ContentDigest::isCanonicalSha256Hex(t.beforeSha256)||
       !fic::core::ContentDigest::isCanonicalSha256Hex(t.targetSha256)||t.runtimeFacts.size()>32) {
        error="invalid SSH ownership transition/provenance";return false;
    }
    if(release) {
        if(!t.target.value.empty()||!t.target.disabledIds.empty()||t.target.ownershipVersion||!t.target.wrapperFingerprints.empty()||
           (t.predecessorStatus!=MutationStatus::Applied&&t.predecessorStatus!=MutationStatus::RollbackFailed)||
           (!t.fileReplacement&&t.beforeSha256!=t.targetSha256)||
           (t.fileReplacement&&t.beforeSha256==t.targetSha256)) {
            error="invalid SSH release previous/absent-target/publication contract";return false;
        }
    } else {
        if(!validSshProjection(t.target,error)||t.target.ownershipVersion!=1||
           (t.previous.ownershipVersion==0&&!t.previous.disabledIds.empty())||t.beforeSha256==t.targetSha256||
           !t.fileReplacement||t.predecessorStatus!=MutationStatus::Applied||!t.predecessorError.empty()||
           t.phase==SshTransitionPhase::OfflineVerified||t.phase==SshTransitionPhase::ReleasedAwaitingDisable) {
            error="invalid SSH refresh contract";return false;
        }
        for(const auto& id:t.previous.disabledIds)
            if(std::find(t.target.disabledIds.begin(),t.target.disabledIds.end(),id)==t.target.disabledIds.end()||
               t.previous.wrapperFingerprints.at(id)!=t.target.wrapperFingerprints.at(id)) {
                error="SSH refresh lost prior wrapper authority";return false;
            }
    }
    for(const auto& [key,value]:t.runtimeFacts)
        if(key.empty()||key.size()>128||value.size()>4096||value.find('\0')!=std::string::npos) {
            error="invalid SSH runtime fact";return false;
        }
    if((t.phase==SshTransitionPhase::Prepared)!=!t.publication){error="SSH publication phase/facts mismatch";return false;}
    if(t.publication) {
        const auto& pub=*t.publication;
        if(!pub.inode||pub.mode>07777||pub.sha256!=t.targetSha256||
           (t.phase==SshTransitionPhase::Published?pub.durable:!pub.durable)||
           (release&&(pub.owner!=0||(pub.mode&0022)))) {
            error="SSH publication identity/durability unproven";return false;
        }
    }
    if(t.phase==SshTransitionPhase::RuntimeVerified||t.phase==SshTransitionPhase::OfflineVerified||
       t.phase==SshTransitionPhase::ReleasedAwaitingDisable||t.phase==SshTransitionPhase::Completed) {
        for(const auto* key:{"inputs","semantics","persistent"}) {
            const auto fact=t.runtimeFacts.find(key);
            if(fact==t.runtimeFacts.end()||fact->second!="Proven"){error="SSH verified activation facts incomplete";return false;}
        }
        const bool offline=release&&t.runtimeFacts.count("offline")&&t.runtimeFacts.at("offline")=="true";
        const auto fact=[&](const char* key){const auto it=t.runtimeFacts.find(key);return it==t.runtimeFacts.end()?std::string():it->second;};
        if(fact("unit").empty()||fact("MainPID").empty()||
           (offline?(fact("MainPID")!="0"||fact("readiness")!="false"):
               (fact("InvocationID").empty()||fact("readiness")!="true"))) {
            error="SSH runtime/offline proof missing";return false;
        }
        if(release&&(fact("status")!="Success"||
           (t.phase==SshTransitionPhase::OfflineVerified&&!offline)||
           (t.phase==SshTransitionPhase::RuntimeVerified&&offline)||
           (!offline&&(fact("MainPID")=="0"||fact("MainPID").find_first_not_of("0123456789")!=std::string::npos||
               fact("InvocationID").size()!=32||fact("InvocationID").find_first_not_of("0123456789abcdef")!=std::string::npos)))) {
            error="SSH release proof kind/identity inconsistent";return false;
        }
    }
    const auto& expected=!release&&t.phase==SshTransitionPhase::Completed?t.target:t.previous;
    const bool status=t.phase==SshTransitionPhase::Completed?
        (release?record.status==MutationStatus::RolledBack:record.status!=MutationStatus::Prepared):record.status==MutationStatus::Prepared;
    if(serializeSshProjection(sshOwnedProjection(*p))!=serializeSshProjection(expected)||!status) {
        error="SSH current permission/transition phase mismatch";return false;
    }
    return true;
}

json serializeUndoAction(const UndoAction& action) {
    json value;
    value["action"] = undoActionTypeName(action);
    // The undo payload must be self-describing: deserializeUndoAction requires
    // the backend inside the undo object to validate payload/backend
    // consistency on load (fail closed).
    value["backend"] = mutationBackendToString(action.backend);
    if (const auto* dm = std::get_if<UndoRemoveDisplayManagerBlock>(&action.payload)) {
        value["manager"] = dm->manager; value["route"] = dm->route; value["seats"] = dm->seats;
        value["created_file"] = dm->createdFile; value["separator"] = dm->separator;
        value["creation_device"] = dm->creationDevice; value["creation_inode"] = dm->creationInode;
        value["had_applied"] = dm->hadApplied; value["phase"] = dm->phase;
    } else if (const auto* artifact = std::get_if<UndoOwnDesktopArtifact>(&action.payload)) {
        value["kind"] = artifact->kind; value["phase"] = artifact->phase;
        value["had_applied"] = artifact->hadApplied;
        value["device"] = artifact->device; value["inode"] = artifact->inode;
    } else if (const auto* checkpoint = std::get_if<ScopeTransitionCheckpoint>(&action.payload)) {
        value["committed_scope"] = checkpoint->committedScope;
        value["target_scope"] = checkpoint->targetScope;
        value["phase"] = checkpoint->phase;
    } else if (const auto* scalar = std::get_if<UndoRestoreDesktopScalar>(&action.payload)) {
        value["desktop"] = scalar->desktop;
        value["setting"] = scalar->setting;
        value["original_line"] = scalar->originalLine ? json(*scalar->originalLine) : json(nullptr);
        value["applied_line"] = scalar->appliedLine;
        value["previous_applied_line"] = scalar->previousAppliedLine ? json(*scalar->previousAppliedLine) : json(nullptr);
        value["owners"] = json::array();
        for (const auto& owner : scalar->owners)
            value["owners"].push_back({{"module", owner.moduleName},
                {"submodule", owner.submoduleName}, {"policy", owner.policyName}});
        value["had_applied"] = scalar->hadApplied;
        value["phase"] = scalar->phase;
        value["original_lock_line"] = scalar->originalLockLine ? json(*scalar->originalLockLine) : json(nullptr);
        value["compiled_before_digest"] = scalar->compiledBeforeDigest;
        value["compiled_target_digest"] = scalar->compiledTargetDigest;
    } else if (const auto* global = std::get_if<UndoReleaseSudoGlobalDefault>(&action.payload)) {
        value["key"] = global->key;
        value["applied_line"] = global->appliedLine;
        value["previous_line"] = global->previousLine;
        value["container_id"] = global->containerId;
        value["added_separator"] = global->addedSeparator;
        value["separator_prefix_digest"] = global->separatorPrefixDigest;
    } else if (const auto* setting =
            std::get_if<UndoRemoveManagedSetting>(&action.payload)) {
        value["key"] = setting->key;
        value["applied_value"] = setting->appliedValue;
    } else if (const auto* auth = std::get_if<UndoReleaseSudoAuthentication>(&action.payload)) {
        auto proofs = [](const auto& source) {
            json result = json::array();
            for (const auto& proof : source) result.push_back({
                {"wrapper_id", proof.wrapperId}, {"canonical_path", proof.canonicalPath},
                {"original_digest", proof.originalDigest}, {"replacement_digest", proof.replacementDigest}});
            return result;
        };
        value["previous_proofs"] = proofs(auth->previousProofs);
        value["target_proofs"] = proofs(auth->targetProofs);
    } else if (const auto* scopedDefaults =
                   std::get_if<UndoReleaseSudoScopedDefaults>(&action.payload)) {
        value["policy"] = scopedDefaults->policyName;
        const auto proofs = [](const auto& source) {
            json result = json::array();
            for (const SudoScopedDefaultsWrapperProof& proof : source) {
                result.push_back({{"wrapper_id", proof.wrapperId},
                                  {"canonical_path", proof.canonicalPath},
                                  {"payload_digest", proof.payloadDigest}});
            }
            return result;
        };
        value["previous_proofs"] = proofs(scopedDefaults->previousProofs);
        value["target_proofs"] = proofs(scopedDefaults->targetProofs);
    } else if (const auto* sshPolicy =
                   std::get_if<UndoRemoveSshManagedPolicy>(&action.payload)) {
        value["policy"] = sshPolicy->policyName;
        value["directive"] = sshPolicy->directive;
        value["applied_value"] = sshPolicy->appliedValue;
        json disabledIds = json::array();
        for (const std::string& id : sshPolicy->disabledMutationIds) {
            disabledIds.push_back(id);
        }
        value["disabled_mutation_ids"] = std::move(disabledIds);
        if(sshPolicy->ownershipVersion||sshPolicy->operationSequence||sshPolicy->transition) {
            value["ownership_version"]=sshPolicy->ownershipVersion;
            value["wrapper_fingerprints"]=sshPolicy->wrapperFingerprints;
            value["operation_sequence"]=sshPolicy->operationSequence;
        }
        if(sshPolicy->transition)value["transition"]=serializeSshTransition(*sshPolicy->transition);
    } else if (const auto* userCreation = std::get_if<
                   UndoRemoveUserCreationManagedPolicy>(&action.payload)) {
        value["policy"] = userCreation->policyName;
        value["config_kind"] = userCreation->configKind ==
                UserCreationConfigKind::UseraddDefaults ? "useradd_defaults"
            : "adduser";
        value["config_path"] = userCreation->configPath;
        const auto assignments = [](const auto& source) {
            json result = json::array();
            for (const auto& item : source)
                result.push_back({{"key", item.key}, {"line", item.appliedLine}});
            return result;
        };
        value["applied_assignments"] = assignments(
            userCreation->appliedAssignments);
        value["previous_applied_assignments"] = assignments(
            userCreation->previousAppliedAssignments);
    } else if (const auto* firewallPolicy =
                   std::get_if<UndoRemoveFirewallPolicy>(&action.payload)) {
        value["policy"] = firewallPolicy->policyName;
    } else if (const auto* grubSetting =
                   std::get_if<UndoRemoveGrubManagedSetting>(&action.payload)) {
        value["key"] = grubSetting->key;
        value["applied_value"] = grubSetting->appliedValue;
    } else if (const auto* sssdSetting = std::get_if<
                   UndoRemoveSssdManagedSetting>(&action.payload)) {
        value["section"] = sssdSetting->section;
        value["option"] = sssdSetting->option;
        value["applied_value"] = sssdSetting->appliedValue;
    } else if (const auto* kerberosScalar = std::get_if<
                   UndoRestoreKerberosScalar>(&action.payload)) {
        value["section"] = kerberosScalar->section;
        value["relation"] = kerberosScalar->relation;
        value["applied_value"] = kerberosScalar->appliedValue;
        value["before_kind"] = kerberosScalar->beforeKind ==
                KerberosBeforeKind::Present
            ? "present"
            : "missing";
        value["before_raw_line"] = kerberosScalar->beforeRawLine;
        value["section_existed_before"] = kerberosScalar->sectionExistedBefore;
    } else if (const auto* pam =
                   std::get_if<UndoDisablePamCapability>(&action.payload)) {
        value["capability"] = pam->capability;
        value["topology"] = pam->topology == PamTopologyKind::PamAuthUpdate
            ? "pam_auth_update" : "alt_tcb_managed";
        value["activation_identifiers"] = pam->activationIdentifiers;
        value["had_applied_provenance"] = pam->hadAppliedProvenance;
        value["previous_strategy"] = pam->previousStrategy
            ? nlohmann::json(*pam->previousStrategy)
            : nlohmann::json(nullptr);
        value["target_strategy"] = pam->targetStrategy
            ? nlohmann::json(*pam->targetStrategy)
            : nlohmann::json(nullptr);
        value["previous_error"] = pam->previousError;
    } else if (const auto* pamEntry = std::get_if<
                   UndoRemovePamProviderManagedEntry>(&action.payload)) {
        value["policy"] = pamEntry->policyName;
        value["provider"] = pamEntry->providerName;
        value["config_path"] = pamEntry->configPath;
        value["managed_key"] = pamEntry->managedKey;
        value["applied_body"] = pamEntry->appliedBody;
        // Always written (write/read parity): the loader requires the field
        // and fails closed when it is missing. Empty string = fresh create.
        value["previous_applied_body"] = pamEntry->previousAppliedBody;
        value["placement"] =
            pamEntry->placement ==
                    PamProviderBlockPlacementContract::Beginning
                ? "beginning"
                : "end";
    } else if (const auto* pamFlag = std::get_if<
                   UndoRemovePamProviderManagedFlag>(&action.payload)) {
        value["policy"] = pamFlag->policyName;
        value["provider"] = pamFlag->providerName;
        value["config_path"] = pamFlag->configPath;
        value["managed_key"] = pamFlag->managedKey;
        value["applied_enabled"] = pamFlag->appliedEnabled;
        // Write/read parity: ALWAYS written. "none" = fresh transition;
        // "enabled"/"disabled" = the previous FIC-owned state of a refresh.
        value["previous_applied_enabled"] =
            !pamFlag->previousAppliedEnabled.has_value()
            ? "none"
            : (*pamFlag->previousAppliedEnabled ? "enabled" : "disabled");
        value["placement"] =
            pamFlag->placement == PamProviderBlockPlacementContract::Beginning
                ? "beginning"
                : "end";
        value["suppression_ids"] = pamFlag->suppressionIds;
        value["previous_suppression_ids"] = pamFlag->previousSuppressionIds;
    } else if (const auto* pamContainer = std::get_if<
                   UndoOwnPamProviderContainer>(&action.payload)) {
        value["provider"] = pamContainer->providerName;
        value["config_path"] = pamContainer->configPath;
    } else if (const auto* loginDefs = std::get_if<
                   UndoRemoveIdentityLoginDefsManagedPolicy>(
                   &action.payload)) {
        value["policy"] = loginDefs->policyName;
        value["config_path"] = loginDefs->configPath;
        value["key"] = loginDefs->key;
        value["applied_line"] = loginDefs->appliedLine;
        // Always written (write/read parity): the loader requires the field
        // and fails closed when it is missing. Empty string = fresh create.
        value["previous_applied_line"] = loginDefs->previousAppliedLine;
    }
    return value;
}

// Shared GRUB undo-payload validation. Used by BOTH the write path
// (MutationJournal::prepareMutation) and the read path
// (deserializeUndoAction) so that the writer can never persist a record
// the loader would reject. An empty appliedValue is VALID: an applied
// policy value of "" (e.g. grub_cmdline_linux="") is a legitimate
// durable state. Only the managed-key identity and the absence of
// CR, LF and NUL in the applied value are enforced.
bool validateGrubUndoPayload(const UndoRemoveGrubManagedSetting& payload,
                             std::string& error) {
    if (payload.key.empty()) {
        error = "remove_grub_managed_setting undo requires a managed key";
        return false;
    }
    if (!isGrubManagedKey(payload.key)) {
        error = "remove_grub_managed_setting undo requires a FIC "
                "supported GRUB key, got: " +
            payload.key;
        return false;
    }
    if (payload.appliedValue.find_first_of("\r\n") != std::string::npos ||
        payload.appliedValue.find('\0') != std::string::npos) {
        error = "remove_grub_managed_setting undo applied value must not "
                "contain CR, LF or NUL";
        return false;
    }
    return true;
}

// Shared SSSD undo-payload validation. Used by BOTH the write path
// (MutationJournal::prepareMutation) and the read path
// (deserializeUndoAction) so that the writer can never persist a record
// the loader would reject. Section/option follow the SSSD configuration
// syntax rules; the applied value must be free of CR, LF and NUL.
bool validateSssdUndoPayload(const UndoRemoveSssdManagedSetting& payload,
                             std::string& error) {
    if (payload.section.empty() ||
        payload.section.find_first_of("[]\r\n") != std::string::npos) {
        error = "remove_sssd_managed_setting undo requires a valid SSSD "
                "section";
        return false;
    }
    const auto validOptionCharacter = [](unsigned char character) {
        return std::isalnum(character) != 0 || character == '_' ||
            character == '-';
    };
    if (payload.option.empty() ||
        !std::all_of(payload.option.begin(), payload.option.end(),
                     validOptionCharacter)) {
        error = "remove_sssd_managed_setting undo requires a valid SSSD "
                "option name";
        return false;
    }
    if (payload.appliedValue.find_first_of("\r\n") != std::string::npos ||
        payload.appliedValue.find('\0') != std::string::npos) {
        error = "remove_sssd_managed_setting undo applied value must not "
                "contain CR, LF or NUL";
        return false;
    }
    return true;
}

bool validatePamUndoPayload(const UndoDisablePamCapability& payload,
                            std::string& error) {
    const auto validStrategy = [](const std::optional<std::string>& value) {
        return !value || *value == "preauth_required" ||
            *value == "preauth_requisite" || *value == "authsucc";
    };
    if (!validStrategy(payload.previousStrategy) ||
        !validStrategy(payload.targetStrategy) ||
        (payload.previousStrategy &&
         (!payload.hadAppliedProvenance || !payload.targetStrategy ||
          payload.previousStrategy == payload.targetStrategy)) ||
        (payload.hadAppliedProvenance && payload.targetStrategy &&
         !payload.previousStrategy) ||
        ((payload.previousStrategy || payload.targetStrategy) &&
         payload.capability != "enable_authentication_lockout") ||
        (!payload.hadAppliedProvenance && !payload.previousError.empty())) {
        error = "invalid PAM strategy transition provenance";
        return false;
    }
    if (payload.topology != PamTopologyKind::PamAuthUpdate &&
        payload.topology != PamTopologyKind::AltTcbManaged) {
        error = "disable_pam_capability has an unknown topology kind";
        return false;
    }
    if (payload.capability != "enable_authentication_lockout" &&
        payload.capability != "enable_password_history" &&
        payload.capability != "enable_password_quality") {
        error = "disable_pam_capability requires a supported capability";
        return false;
    }
    if (payload.topology == PamTopologyKind::PamAuthUpdate &&
        payload.activationIdentifiers.empty()) {
        error = "pam_auth_update undo requires activation identifiers";
        return false;
    }
    if (payload.topology == PamTopologyKind::AltTcbManaged &&
        !payload.activationIdentifiers.empty()) {
        error = "ALT PAM undo must not contain activation identifiers";
        return false;
    }
    std::set<std::string> unique;
    for (const std::string& id : payload.activationIdentifiers) {
        if (id.empty() || id[0] == '-' ||
            !std::all_of(id.begin(), id.end(), [](unsigned char c) {
                return std::isalnum(c) != 0 || c == '-' || c == '_';
            }) || !unique.insert(id).second) {
            error = "invalid or duplicate PAM activation identifier";
            return false;
        }
    }
    return true;
}

// Shared PAM provider managed-entry undo-payload validation (write + read
// parity). Used by BOTH the write path (MutationJournal::prepareMutation)
// and the read path (deserializeUndoAction) so that the writer can never
// persist a record the loader would reject. The payload must describe a
// provable FIC-owned entry: identity tokens follow the physical marker
// grammar, the applied body is the exact canonical serialization of the
// managed key, and no field may carry CR/LF/NUL.
bool validatePamProviderManagedEntryUndoPayload(
    const UndoRemovePamProviderManagedEntry& payload,
    std::string& error) {
    const auto validToken = [](const std::string& token) {
        return isValidPamProviderIdentityToken(token);
    };
    if (!validToken(payload.policyName)) {
        error = "remove_pam_provider_managed_entry undo requires a valid "
                "FIC policy identity token";
        return false;
    }
    if (!validToken(payload.providerName)) {
        error = "remove_pam_provider_managed_entry undo requires a valid "
                "PAM provider identity token";
        return false;
    }
    if (payload.configPath.empty() || payload.configPath.front() != '/' ||
        payload.configPath.find_first_of("\r\n") != std::string::npos ||
        payload.configPath.find('\0') != std::string::npos) {
        error = "remove_pam_provider_managed_entry undo requires an "
                "absolute config path free of CR/LF/NUL";
        return false;
    }
    if (!isValidPamProviderManagedKey(payload.managedKey)) {
        error = "remove_pam_provider_managed_entry undo requires a valid "
                "managed key";
        return false;
    }
    // EXACT key match via the shared canonical validator — never a prefix
    // compare: "deny_extra = 5" must never validate against managedKey
    // "deny" (the write path must never persist what the loader/ownership
    // proof would reject).
    std::string appliedKey;
    std::string appliedValue;
    if (!parseCanonicalPamProviderEntryBody(payload.appliedBody, appliedKey,
                                            appliedValue, payload.providerName) ||
        appliedKey != payload.managedKey) {
        error = "remove_pam_provider_managed_entry undo requires a "
                "canonical applied body of exactly the managed key";
        return false;
    }
    // Durable previous→target transition of an in-place refresh: either a
    // fresh create (empty previous body) or the exact previous canonical
    // body of the SAME managed key, different from the new applied body.
    if (!payload.previousAppliedBody.empty()) {
        std::string previousKey;
        std::string previousValue;
        if (!parseCanonicalPamProviderEntryBody(
                payload.previousAppliedBody, previousKey, previousValue, payload.providerName) ||
            previousKey != payload.managedKey ||
            payload.previousAppliedBody == payload.appliedBody) {
            error = "remove_pam_provider_managed_entry undo requires an "
                    "empty (fresh create) or canonical previous applied "
                    "body of the same managed key, different from the "
                    "applied body";
            return false;
        }
    }
    switch (payload.placement) {
        case PamProviderBlockPlacementContract::Beginning:
        case PamProviderBlockPlacementContract::End:
            return true;
    }
    error = "remove_pam_provider_managed_entry undo has an unknown "
            "placement contract";
    return false;
}

// Shared PAM provider container-ownership undo-payload validation (write +
// read parity). The container provenance record proves that FIC created the
// previously absent primary configuration file; it carries only the
// provider identity and the absolute config path.
bool validatePamProviderContainerUndoPayload(
    const UndoOwnPamProviderContainer& payload,
    std::string& error) {
    if (!isValidPamProviderIdentityToken(payload.providerName)) {
        error = "own_pam_provider_container undo requires a valid PAM "
                "provider identity token";
        return false;
    }
    if (payload.configPath.empty() || payload.configPath.front() != '/' ||
        payload.configPath.find_first_of("\r\n") != std::string::npos ||
        payload.configPath.find('\0') != std::string::npos) {
        error = "own_pam_provider_container undo requires an absolute "
                "config path free of CR/LF/NUL";
        return false;
    }
    return true;
}

// Shared PAM provider set-only FLAG undo-payload validation (write + read
// parity, Step 7E §30). The payload is PROVENANCE, never a backup: only
// identity tokens, the managed key, the bool states, the placement and the
// canonical suppression id permission sets are carried. No foreign line,
// no historical config content, no whole-file snapshot is representable.
bool validatePamProviderManagedFlagUndoPayload(
    const UndoRemovePamProviderManagedFlag& payload,
    std::string& error) {
    if (!isValidPamProviderIdentityToken(payload.policyName) ||
        !isValidPamProviderIdentityToken(payload.providerName)) {
        error = "remove_pam_provider_managed_flag undo requires valid "
                "policy and provider identity tokens";
        return false;
    }
    if (!isValidPamProviderManagedKey(payload.managedKey)) {
        error = "remove_pam_provider_managed_flag undo requires a valid "
                "managed key";
        return false;
    }
    if (payload.configPath.empty() || payload.configPath.front() != '/' ||
        payload.configPath.find_first_of("\r\n") != std::string::npos ||
        payload.configPath.find('\0') != std::string::npos) {
        error = "remove_pam_provider_managed_flag undo requires an absolute "
                "config path free of CR/LF/NUL";
        return false;
    }
    const auto validateSuppressionSet =
        [&](const std::vector<std::string>& ids, const char* fieldName) {
            std::set<std::string> unique;
            for (const std::string& id : ids) {
                if (!isValidPamProviderSuppressionId(id)) {
                    error = std::string(
                                "remove_pam_provider_managed_flag undo "
                                "requires canonical suppression ids in ") +
                        fieldName + ", got: " + id;
                    return false;
                }
                if (!unique.insert(id).second) {
                    error = std::string(
                                "remove_pam_provider_managed_flag undo has "
                                "a duplicate suppression id in ") +
                        fieldName + ": " + id;
                    return false;
                }
            }
            return true;
        };
    if (!validateSuppressionSet(payload.suppressionIds,
                                "suppression_ids")) {
        return false;
    }
    if (!validateSuppressionSet(payload.previousSuppressionIds,
                                "previous_suppression_ids")) {
        return false;
    }
    // An ENABLED flag state never owns suppression wrappers: a non-empty
    // set with an enabled state is a logical contradiction.
    if (payload.appliedEnabled && !payload.suppressionIds.empty()) {
        error = "remove_pam_provider_managed_flag undo has an enabled "
                "target with a non-empty suppression id set";
        return false;
    }
    if (payload.previousAppliedEnabled.has_value() &&
        *payload.previousAppliedEnabled &&
        !payload.previousSuppressionIds.empty()) {
        error = "remove_pam_provider_managed_flag undo has an enabled "
                "previous state with a non-empty previous suppression id "
                "set";
        return false;
    }
    // A fresh transition (no previous FIC-owned state) must not carry
    // previous provenance.
    if (!payload.previousAppliedEnabled.has_value() &&
        !payload.previousSuppressionIds.empty()) {
        error = "remove_pam_provider_managed_flag undo has a fresh "
                "transition with a non-empty previous suppression id set";
        return false;
    }
    switch (payload.placement) {
        case PamProviderBlockPlacementContract::Beginning:
        case PamProviderBlockPlacementContract::End:
            return true;
    }
    error = "remove_pam_provider_managed_flag undo has an unknown "
            "placement contract";
    return false;
}

// Exact identity of one unresolved PAM provider managed-entry transition.
// A Prepared record may only be re-prepared as the EXACT same idempotent
// transition; any difference (new target body, changed placement, provider,
// managed key, previous state or policy identity) would silently replace
// durable crash-recovery provenance of a possibly already executed physical
// write. The comparison is explicit and type-safe instead of relying on
// the generic refresh path; the (policy, backend, resource) lookup already
// pins resource identity, and the remaining payload fields are compared
// here in full.
bool samePamProviderPreparedTransition(
    const UndoRemovePamProviderManagedEntry& existing,
    const UndoRemovePamProviderManagedEntry& incoming) {
    return existing.policyName == incoming.policyName &&
           existing.providerName == incoming.providerName &&
           existing.configPath == incoming.configPath &&
           existing.managedKey == incoming.managedKey &&
           existing.previousAppliedBody == incoming.previousAppliedBody &&
           existing.appliedBody == incoming.appliedBody &&
           existing.placement == incoming.placement;
}

// Exact identity of one unresolved PAM provider managed-FLAG transition
// (Step 7E §31): policy, provider, config path, managed key, target and
// previous bool states, placement and BOTH suppression id sets must match
// exactly for an idempotent Prepared retry.
bool samePamProviderPreparedFlagTransition(
    const UndoRemovePamProviderManagedFlag& existing,
    const UndoRemovePamProviderManagedFlag& incoming) {
    return existing.policyName == incoming.policyName &&
           existing.providerName == incoming.providerName &&
           existing.configPath == incoming.configPath &&
           existing.managedKey == incoming.managedKey &&
           existing.appliedEnabled == incoming.appliedEnabled &&
           existing.previousAppliedEnabled ==
               incoming.previousAppliedEnabled &&
           existing.placement == incoming.placement &&
           existing.suppressionIds == incoming.suppressionIds &&
           existing.previousSuppressionIds ==
               incoming.previousSuppressionIds;
}

// Step 7E: rollback authority over the suppression ids of ONE PAM provider
// managed-flag record. This is the SINGLE status-aware authority model,
// shared by the load-side cross-record collision check AND by
// prepareMutation() on the write path (write/read semantic parity: the
// writer refuses exactly those cross-record authority collisions that the
// loader would reject for the resulting active statuses — do NOT
// reintroduce a second, status-blind authority computation here).
//
// Status → authority (Prepared is an UNRESOLVED transition: the physical
// state may sit on either durable side, so both are potential authority):
//   * Prepared       — suppressionIds ∪ previousSuppressionIds;
//   * Applied        — suppressionIds (the previous state has been
//                      physically replaced; its ids are historical
//                      provenance, never authority);
//   * RollbackFailed — suppressionIds (the target is still the durable
//                      owned state; previous ids are historical);
//   * resolved statuses (RolledBack / Detached, i.e. !isActive()) — none:
//                      complete mutation history never conflicts.
std::vector<std::string> preparedPamFlagSuppressionAuthority(
    const UndoRemovePamProviderManagedFlag& flag) {
    std::vector<std::string> authority = flag.suppressionIds;
    authority.insert(authority.end(),
        flag.previousSuppressionIds.begin(),
        flag.previousSuppressionIds.end());
    return authority;
}

// Authority of an EXISTING record, evaluated by its ACTUAL status. For a
// Prepared record this equals preparedPamFlagSuppressionAuthority(); for
// an Applied/RollbackFailed record the previous set is already historical
// provenance. An incoming prepare must NOT be evaluated through this
// helper with a guessed status: prepareMutation persists the incoming
// transition as Prepared, so model its authority with
// preparedPamFlagSuppressionAuthority() (its FUTURE Prepared state).
// Shared with the PAM provider package preflight (single authority model,
// see the declaration in MutationJournal.h).

bool validKerberosSectionName(const std::string& section) {
    return !section.empty() &&
        section.find_first_of("[]*#;\r\n") == std::string::npos;
}

bool validKerberosRelationName(const std::string& relation) {
    return !relation.empty() &&
        relation.find_first_of("=*#;[]\r\n{} \t") == std::string::npos;
}

bool lineFreeOfControlCharacters(const std::string& line) {
    return line.find_first_of("\r\n") == std::string::npos &&
        line.find('\0') == std::string::npos;
}

bool validateUserCreationUndoPayload(
    const UndoRemoveUserCreationManagedPolicy& payload, std::string& error) {
    const std::map<std::string,
        std::pair<UserCreationConfigKind, std::vector<std::string>>> known = {
        {"user_home_base_directory", {UserCreationConfigKind::UseraddDefaults, {"HOME"}}},
        {"user_skeleton_directory", {UserCreationConfigKind::UseraddDefaults, {"SKEL"}}},
        {"user_default_shell", {UserCreationConfigKind::UseraddDefaults, {"SHELL"}}},
        {"user_default_primary_group", {UserCreationConfigKind::UseraddDefaults, {"GROUP"}}}
    };
    if (payload.policyName.empty() || payload.configPath.empty() ||
        !std::filesystem::path(payload.configPath).is_absolute()) {
        error = "USER_CREATION undo requires known policy and absolute path";
        return false;
    }
    std::vector<std::string> allowed;
    const auto found = known.find(payload.policyName);
    if (found != known.end()) {
        if (found->second.first != payload.configKind) {
            error = "USER_CREATION policy/config kind mismatch";
            return false;
        }
        allowed = found->second.second;
    } else if (payload.policyName == "user_default_supplementary_groups") {
        allowed = payload.configKind == UserCreationConfigKind::Adduser
            ? std::vector<std::string>{"ADD_EXTRA_GROUPS", "EXTRA_GROUPS"}
            : payload.configKind == UserCreationConfigKind::UseraddDefaults
                ? std::vector<std::string>{"GROUPS"} : std::vector<std::string>{};
    } else {
        error = "unknown USER_CREATION policy in undo";
        return false;
    }
    const auto validate = [&](const auto& assignments, bool allowEmpty) {
        if (!allowEmpty && assignments.empty()) return false;
        if (assignments.empty()) return allowEmpty;
        std::set<std::string> keys;
        for (const auto& assignment : assignments) {
            if (std::find(allowed.begin(), allowed.end(), assignment.key) ==
                    allowed.end() ||
                !keys.insert(assignment.key).second ||
                assignment.appliedLine.empty() ||
                !lineFreeOfControlCharacters(assignment.appliedLine)) return false;
            const std::string prefix = assignment.key + "=";
            if (assignment.appliedLine.rfind(prefix, 0) != 0) return false;
        }
        if (payload.policyName != "user_default_supplementary_groups")
            return keys == std::set<std::string>(allowed.begin(), allowed.end());
        if (payload.configKind == UserCreationConfigKind::UseraddDefaults)
            return keys == std::set<std::string>{"GROUPS"};
        return keys == std::set<std::string>{"ADD_EXTRA_GROUPS"} ||
            keys == std::set<std::string>{"ADD_EXTRA_GROUPS", "EXTRA_GROUPS"};
    };
    if (!validate(payload.appliedAssignments, false) ||
        !validate(payload.previousAppliedAssignments, true)) {
        error = "invalid USER_CREATION assignment/key/body payload";
        return false;
    }
    return true;
}

// Shared Kerberos undo-payload validation (write + read parity). The exact
// raw before line is required for Present and forbidden for Missing; the
// sectionExistedBefore flag must agree with the before kind.
bool validateKerberosUndoPayload(const UndoRestoreKerberosScalar& payload,
                                 std::string& error) {
    if (!validKerberosSectionName(payload.section)) {
        error = "restore_kerberos_scalar undo requires a valid Kerberos "
                "section";
        return false;
    }
    if (!validKerberosRelationName(payload.relation)) {
        error = "restore_kerberos_scalar undo requires a valid Kerberos "
                "relation name";
        return false;
    }
    if (payload.appliedValue.empty() ||
        !lineFreeOfControlCharacters(payload.appliedValue)) {
        error = "restore_kerberos_scalar undo requires a non-empty applied "
                "value without CR, LF or NUL";
        return false;
    }
    if (payload.beforeKind == KerberosBeforeKind::Present) {
        if (payload.beforeRawLine.empty() ||
            !lineFreeOfControlCharacters(payload.beforeRawLine)) {
            error = "restore_kerberos_scalar undo requires a non-empty raw "
                    "before line without CR, LF or NUL";
            return false;
        }
        if (!payload.sectionExistedBefore) {
            error = "restore_kerberos_scalar undo with a present relation "
                    "requires sectionExistedBefore";
            return false;
        }
    } else if (!payload.beforeRawLine.empty()) {
        error = "restore_kerberos_scalar undo with a missing relation must "
                "not carry a raw before line";
        return false;
    }
    return true;
}

// Shared /etc/login.defs undo-payload validation (write + read parity) for
// the shared IdentityLoginDefs backend. The exact policy→key→value-domain
// mapping comes from the shared IdentityLoginDefsPolicySpec table (the SAME
// single source of truth the managed-config validator and the transaction
// backend use), so a payload whose key or value domain does not match its
// policy is rejected both on write and on reload (fail closed, including
// unknown future policies).
bool validateIdentityLoginDefsUndoPayload(
    const UndoRemoveIdentityLoginDefsManagedPolicy& payload,
    std::string& error) {
    const fic::identity::login_defs::SharedLoginDefsPolicySpec* spec =
        fic::identity::login_defs::findSharedLoginDefsPolicySpec(
            payload.policyName);
    if (spec == nullptr) {
        error = "unknown policy in identity_login_defs undo";
        return false;
    }
    if (!std::filesystem::path(payload.configPath).is_absolute()) {
        error = "identity_login_defs undo requires an absolute config path";
        return false;
    }
    if (payload.appliedLine.empty() ||
        !lineFreeOfControlCharacters(payload.appliedLine) ||
        !lineFreeOfControlCharacters(payload.previousAppliedLine)) {
        error = "identity_login_defs undo requires applied lines without "
                "CR, LF or NUL";
        return false;
    }
    // Exact policy→key parity: an arbitrary key is never accepted.
    if (payload.key.empty() || payload.key != spec->key) {
        error = "identity_login_defs undo key does not match the managed " +
            std::string(spec->key) + " assignment of " + payload.policyName;
        return false;
    }
    const std::string prefix = payload.key + " ";
    const auto validateLine = [&](const std::string& line,
                                  const char* field) {
        if (line.rfind(prefix, 0) != 0) {
            error = "identity_login_defs undo " + std::string(field) +
                " must be a canonical assignment of the managed key";
            return false;
        }
        const std::string value = line.substr(prefix.size());
        std::string valueError;
        if (!fic::identity::login_defs::validateSharedLoginDefsPolicyValue(
                payload.policyName, value, valueError)) {
            error = "identity_login_defs undo " + std::string(field) +
                " carries an invalid value for " + payload.policyName + ": " +
                valueError;
            return false;
        }
        return true;
    };
    if (!validateLine(payload.appliedLine, "appliedLine")) return false;
    if (!payload.previousAppliedLine.empty() &&
        !validateLine(payload.previousAppliedLine, "previousAppliedLine")) {
        return false;
    }
    return true;
}

bool deserializeUndoAction(const json& value, UndoAction& action, std::string& error) {
    const std::string actionName = value.value("action", "");
    const std::string backendName = value.value("backend", "");
    MutationBackend backend;
    if (!mutationBackendFromString(backendName, backend)) {
        error = "unknown mutation undo backend: " + backendName;
        return false;
    }
    action.backend = backend;
    if (backend == MutationBackend::Desktop && actionName == "own_desktop_artifact") {
        if (!value.contains("kind") || !value["kind"].is_string() ||
            !value.contains("phase") || !value["phase"].is_string() ||
            !value.contains("had_applied") || !value["had_applied"].is_boolean() ||
            !value.contains("device") || !value["device"].is_number_unsigned() ||
            !value.contains("inode") || !value["inode"].is_number_unsigned()) {
            error = "malformed GNOME artifact creation payload"; return false;
        }
        action.payload = UndoOwnDesktopArtifact{value["kind"].get<std::string>(),
            value["phase"].get<std::string>(), value["had_applied"].get<bool>(),
            value["device"].get<std::uint64_t>(), value["inode"].get<std::uint64_t>()};
        return true;
    }
    if (backend == MutationBackend::Desktop && actionName == "restore_desktop_scalar") {
        for (const auto* field : {"desktop", "setting", "applied_line", "phase",
                                  "compiled_before_digest", "compiled_target_digest"}) {
            if (!value.contains(field) || !value[field].is_string()) {
                error = "malformed desktop scalar field";
                return false;
            }
        }
        for (const auto* field : {"original_line", "previous_applied_line", "original_lock_line"}) {
            if (!value.contains(field) ||
                (!value[field].is_string() && !value[field].is_null())) {
                error = "malformed optional desktop scalar line";
                return false;
            }
        }
        if (!value.contains("owners") || !value["owners"].is_array() ||
            !value.contains("had_applied") || !value["had_applied"].is_boolean()) {
            error = "malformed desktop scalar owners/progress";
            return false;
        }
        UndoRestoreDesktopScalar scalar;
        scalar.desktop = value["desktop"].get<std::string>();
        scalar.setting = value["setting"].get<std::string>();
        scalar.appliedLine = value["applied_line"].get<std::string>();
        scalar.phase = value["phase"].get<std::string>();
        scalar.compiledBeforeDigest = value["compiled_before_digest"].get<std::string>();
        scalar.compiledTargetDigest = value["compiled_target_digest"].get<std::string>();
        scalar.hadApplied = value["had_applied"].get<bool>();
        if (!value["original_line"].is_null()) scalar.originalLine = value["original_line"].get<std::string>();
        if (!value["original_lock_line"].is_null()) scalar.originalLockLine = value["original_lock_line"].get<std::string>();
        if (!value["previous_applied_line"].is_null()) scalar.previousAppliedLine = value["previous_applied_line"].get<std::string>();
        for (const auto& owner : value["owners"]) {
            if (!owner.is_object() || !owner.contains("module") || !owner["module"].is_string() ||
                !owner.contains("submodule") || !owner["submodule"].is_string() ||
                !owner.contains("policy") || !owner["policy"].is_string()) {
                error = "malformed desktop scalar owner";
                return false;
            }
            scalar.owners.push_back({owner["module"].get<std::string>(),
                owner["submodule"].get<std::string>(), owner["policy"].get<std::string>()});
        }
        action.payload = std::move(scalar);
        return true;
    }
    if (backend == MutationBackend::DisplayManager && actionName == "remove_display_manager_block") {
        for (const auto* field : {"manager", "separator", "phase"})
            if (!value.contains(field) || !value[field].is_string()) { error = "malformed DM block"; return false; }
        if (!value.contains("route") || !value["route"].is_number_unsigned() || value["route"] != 0u ||
            !value.contains("creation_device") || !value["creation_device"].is_number_unsigned() ||
            !value.contains("creation_inode") || !value["creation_inode"].is_number_unsigned() ||
            !value.contains("seats") || !value["seats"].is_array() ||
            !value.contains("created_file") || !value["created_file"].is_boolean() ||
            !value.contains("had_applied") || !value["had_applied"].is_boolean()) {
            error = "malformed DM block lifecycle"; return false;
        }
        UndoRemoveDisplayManagerBlock dm;
        dm.manager = value["manager"].get<std::string>(); dm.route = value["route"].get<unsigned>();
        dm.seats = value["seats"].get<std::vector<std::string>>();
        dm.creationDevice = value["creation_device"].get<std::uint64_t>(); dm.creationInode = value["creation_inode"].get<std::uint64_t>();
        dm.createdFile = value["created_file"].get<bool>(); dm.separator = value["separator"].get<std::string>();
        dm.hadApplied = value["had_applied"].get<bool>(); dm.phase = value["phase"].get<std::string>();
        action.payload = std::move(dm); return true;
    }
    if (backend == MutationBackend::Scope && actionName == "scope_transition_checkpoint") {
        if (!value.contains("committed_scope") || !value["committed_scope"].is_array() ||
            !value.contains("target_scope") || !value["target_scope"].is_array() ||
            !value.contains("phase") || !value["phase"].is_string()) {
            error = "malformed scope checkpoint";
            return false;
        }
        ScopeTransitionCheckpoint checkpoint;
        checkpoint.committedScope = value["committed_scope"].get<std::vector<std::string>>();
        checkpoint.targetScope = value["target_scope"].get<std::vector<std::string>>();
        checkpoint.phase = value["phase"].get<std::string>();
        if (!validScopeCheckpoint(checkpoint, error)) return false;
        action.payload = std::move(checkpoint);
        return true;
    }
    if (actionName == "disable_pam_capability" &&
        backend == MutationBackend::Pam) {
        UndoDisablePamCapability payload;
        const auto capability = value.find("capability");
        const auto topology = value.find("topology");
        const auto identifiers = value.find("activation_identifiers");
        const auto established = value.find("had_applied_provenance");
        if (capability == value.end() || !capability->is_string() ||
            topology == value.end() || !topology->is_string() ||
            identifiers == value.end() || !identifiers->is_array() ||
            established == value.end() || !established->is_boolean()) {
            error = "malformed disable_pam_capability undo";
            return false;
        }
        payload.capability = capability->get<std::string>();
        payload.hadAppliedProvenance = established->get<bool>();
        const auto previous = value.find("previous_strategy");
        const auto target = value.find("target_strategy");
        const auto previousError = value.find("previous_error");
        if (previous == value.end() || target == value.end() ||
            previousError == value.end() || !previousError->is_string() ||
            (!previous->is_null() && !previous->is_string()) ||
            (!target->is_null() && !target->is_string())) {
            error = "malformed PAM strategy transition provenance";
            return false;
        }
        if (previous->is_string())
            payload.previousStrategy = previous->get<std::string>();
        if (target->is_string())
            payload.targetStrategy = target->get<std::string>();
        payload.previousError = previousError->get<std::string>();
        if (*topology == "pam_auth_update") {
            payload.topology = PamTopologyKind::PamAuthUpdate;
        } else if (*topology == "alt_tcb_managed") {
            payload.topology = PamTopologyKind::AltTcbManaged;
        } else {
            error = "unknown PAM topology in undo";
            return false;
        }
        for (const auto& id : *identifiers) {
            if (!id.is_string()) {
                error = "PAM activation identifiers must be strings";
                return false;
            }
            payload.activationIdentifiers.push_back(id.get<std::string>());
        }
        if (!validatePamUndoPayload(payload, error)) return false;
        action.payload = std::move(payload);
        return true;
    }
    if (actionName == "release_sudo_global_default" && backend == MutationBackend::Sudo) {
        for (const auto* field : {"key", "applied_line", "previous_line", "container_id", "separator_prefix_digest"}) {
            const auto found = value.find(field);
            if (found == value.end() || !found->is_string()) {
                error = "SUDO global payload requires canonical string fields";
                return false;
            }
        }
        if (!value.contains("added_separator") || !value.at("added_separator").is_boolean()) {
            error = "SUDO global payload requires separator provenance";
            return false;
        }
        UndoReleaseSudoGlobalDefault payload;
        payload.key = value.value("key", "");
        payload.appliedLine = value.value("applied_line", "");
        payload.previousLine = value.value("previous_line", "");
        payload.containerId = value.value("container_id", "");
        payload.addedSeparator = value.value("added_separator", false);
        payload.separatorPrefixDigest = value.value("separator_prefix_digest", "");
        if (!validateSudoGlobalDefaultPayload(payload, error)) return false;
        action.payload = std::move(payload);
        return true;
    }
    if (actionName == "remove_managed_setting" &&
        (backend == MutationBackend::Sysctl || backend == MutationBackend::Sudo)) {
        UndoRemoveManagedSetting payload;
        payload.key = value.value("key", "");
        payload.appliedValue = value.value("applied_value", "");
        if (payload.key.empty() ||
            (backend == MutationBackend::Sudo && payload.appliedValue.empty())) {
            error = "remove_managed_setting undo requires a key";
            return false;
        }
        action.payload = std::move(payload);
        return true;
    }
    if (actionName == "release_sudo_authentication" && backend == MutationBackend::Sudo) {
        UndoReleaseSudoAuthentication payload;
        auto read = [&](const char* field, auto& out) {
            auto it = value.find(field);
            if (it == value.end() || !it->is_array()) { error = "Missing authentication proof array"; return false; }
            for (const auto& item : *it) {
                if (!item.is_object()) { error = "Invalid authentication proof object"; return false; }
                out.push_back({item.value("wrapper_id", ""), item.value("canonical_path", ""),
                    item.value("original_digest", ""), item.value("replacement_digest", "")});
            }
            return true;
        };
        if (!read("previous_proofs", payload.previousProofs) || !read("target_proofs", payload.targetProofs) ||
            !validateSudoAuthenticationPayload(payload, error)) return false;
        action.payload = std::move(payload); return true;
    }
    if (actionName == "release_sudo_scoped_defaults" &&
        backend == MutationBackend::Sudo) {
        UndoReleaseSudoScopedDefaults payload;
        payload.policyName = value.value("policy", "");
        const auto readProofs = [&value](const char* field,
                                         std::vector<SudoScopedDefaultsWrapperProof>& out,
                                         std::string& error) -> bool {
            const auto it = value.find(field);
            if (it == value.end()) {
                return true;
            }
            if (!it->is_array()) {
                error = std::string(field) + " must be an array";
                return false;
            }
            for (const json& item : *it) {
                if (!item.is_object()) {
                    error = std::string(field) + " entries must be objects";
                    return false;
                }
                SudoScopedDefaultsWrapperProof proof;
                proof.wrapperId = item.value("wrapper_id", "");
                proof.canonicalPath = item.value("canonical_path", "");
                proof.payloadDigest = item.value("payload_digest", "");
                if (!validateSudoScopedDefaultsProof(proof, error)) {
                    return false;
                }
                out.push_back(std::move(proof));
            }
            return true;
        };
        if (!readProofs("previous_proofs", payload.previousProofs, error) ||
            !readProofs("target_proofs", payload.targetProofs, error)) {
            return false;
        }
        if (!validateSudoScopedDefaultsUndoPayload(payload, error)) {
            return false;
        }
        action.payload = std::move(payload);
        return true;
    }
    if (actionName == "remove_ssh_managed_policy" &&
        backend == MutationBackend::Ssh) {
        // The legacy reverse-mutation SSH payload (restore_ssh_directive) is
        // intentionally not migrated: such records fail closed as unknown
        // actions and must be resolved manually.
        UndoRemoveSshManagedPolicy payload;
        payload.policyName = value.value("policy", "");
        payload.directive = value.value("directive", "");
        payload.appliedValue = value.value("applied_value", "");
        if (payload.policyName.empty() || payload.directive.empty() ||
            payload.appliedValue.empty()) {
            error = "remove_ssh_managed_policy undo requires a policy, a "
                    "directive and an applied value";
            return false;
        }
        const auto disabledIt = value.find("disabled_mutation_ids");
        if (disabledIt != value.end()) {
            if (!disabledIt->is_array()) {
                error = "disabled_mutation_ids must be an array";
                return false;
            }
            for (const json& item : *disabledIt) {
                if (!item.is_string() || item.get<std::string>().empty()) {
                    error = "disabled mutation ids must be non-empty strings";
                    return false;
                }
                payload.disabledMutationIds.push_back(item.get<std::string>());
            }
        }
        try {
        if(value.contains("ownership_version")) {
            if(!value.at("ownership_version").is_number_unsigned()||value.at("ownership_version")>1||
               !value.at("operation_sequence").is_number_unsigned()) {error="unsupported SSH ownership version";return false;}
            payload.ownershipVersion=value.at("ownership_version").get<std::uint32_t>();
            payload.wrapperFingerprints=value.at("wrapper_fingerprints").get<std::map<std::string,std::string>>();
            payload.operationSequence=value.at("operation_sequence").get<std::uint64_t>();
        } else if(value.contains("wrapper_fingerprints")||value.contains("transition")||value.contains("operation_sequence")) {
            error="SSH ownership version missing";return false;
        }
        if(value.contains("transition")) {
            SshOwnershipTransition transition;
            if(!deserializeSshTransition(value.at("transition"),transition,error))return false;
            payload.transition=std::move(transition);
        }
        } catch(const std::exception&) { error="malformed SSH typed ownership contract";return false; }
        action.payload = std::move(payload);
        return true;
    }
    if (actionName == "remove_user_creation_managed_policy" &&
        backend == MutationBackend::UserCreation) {
        UndoRemoveUserCreationManagedPolicy payload;
        payload.policyName = value.value("policy", "");
        payload.configPath = value.value("config_path", "");
        const std::string kind = value.value("config_kind", "");
        if (kind == "useradd_defaults")
            payload.configKind = UserCreationConfigKind::UseraddDefaults;
        else if (kind == "adduser")
            payload.configKind = UserCreationConfigKind::Adduser;
        else {
            error = "unknown USER_CREATION config kind";
            return false;
        }
        const auto readAssignments = [&](const char* field, auto& target) {
            const auto found = value.find(field);
            if (found == value.end() || !found->is_array()) return false;
            std::set<std::string> keys;
            for (const auto& item : *found) {
                if (!item.is_object()) return false;
                UserCreationManagedAssignment assignment{
                    item.value("key", ""), item.value("line", "")};
                if (assignment.key.empty() || assignment.appliedLine.empty() ||
                    assignment.key.find_first_of("\r\n\0") != std::string::npos ||
                    assignment.appliedLine.find_first_of("\r\n\0") != std::string::npos ||
                    !keys.insert(assignment.key).second) return false;
                target.push_back(std::move(assignment));
            }
            return !target.empty();
        };
        if (payload.policyName.empty() || payload.configPath.empty() ||
            !readAssignments("applied_assignments", payload.appliedAssignments)) {
            error = "malformed USER_CREATION ownership payload";
            return false;
        }
        const auto previous = value.find("previous_applied_assignments");
        if (previous == value.end() || !previous->is_array()) {
            error = "missing USER_CREATION previous assignments";
            return false;
        }
        if (!previous->empty() &&
            !readAssignments("previous_applied_assignments",
                             payload.previousAppliedAssignments)) {
            error = "malformed USER_CREATION previous assignments";
            return false;
        }
        if (!validateUserCreationUndoPayload(payload, error)) return false;
        action.payload = std::move(payload);
        return true;
    }
    if (actionName == "remove_identity_login_defs_managed_policy" &&
        backend == MutationBackend::IdentityLoginDefs) {
        UndoRemoveIdentityLoginDefsManagedPolicy payload;
        payload.policyName = value.value("policy", "");
        payload.configPath = value.value("config_path", "");
        payload.key = value.value("key", "");
        payload.appliedLine = value.value("applied_line", "");
        const auto previous = value.find("previous_applied_line");
        if (previous == value.end() || !previous->is_string()) {
            error = "missing identity_login_defs previous applied line";
            return false;
        }
        payload.previousAppliedLine = previous->get<std::string>();
        if (!validateIdentityLoginDefsUndoPayload(payload, error)) {
            return false;
        }
        action.payload = std::move(payload);
        return true;
    }
    if (actionName == "remove_firewall_policy" &&
        backend == MutationBackend::Firewall) {
        UndoRemoveFirewallPolicy payload;
        payload.policyName = value.value("policy", "");
        if (payload.policyName.empty()) {
            error = "remove_firewall_policy undo requires a policy";
            return false;
        }
        action.payload = std::move(payload);
        return true;
    }
    if (actionName == "remove_grub_managed_setting" &&
        backend == MutationBackend::Grub) {
        UndoRemoveGrubManagedSetting payload;
        payload.key = value.value("key", "");
        // Fail-closed STRUCTURAL parsing of applied_value: the field MUST
        // be present and MUST be a JSON string. An empty string is a VALID
        // value (e.g. grub_cmdline_linux=""), but a MISSING or non-string
        // applied_value is malformed provenance: it must never silently
        // deserialize as "" and must never escape as an uncaught JSON type
        // error. Semantic constraints (managed-key whitelist, CR/LF/NUL)
        // stay in validateGrubUndoPayload below.
        const auto appliedIt = value.find("applied_value");
        if (appliedIt == value.end() || !appliedIt->is_string()) {
            error = "remove_grub_managed_setting undo requires a string "
                    "applied_value (an empty string is valid)";
            return false;
        }
        payload.appliedValue = appliedIt->get<std::string>();
        if (!validateGrubUndoPayload(payload, error)) {
            return false;
        }
        action.payload = std::move(payload);
        return true;
    }
    if (actionName == "remove_sssd_managed_setting" &&
        backend == MutationBackend::Sssd) {
        UndoRemoveSssdManagedSetting payload;
        // Fail-closed STRUCTURAL parsing: section/option MUST be present and
        // MUST be JSON strings. A non-string must never escape as an
        // uncaught JSON type error; semantic constraints (section/option
        // syntax) stay in validateSssdUndoPayload below.
        const auto sectionIt = value.find("section");
        if (sectionIt == value.end() || !sectionIt->is_string()) {
            error = "remove_sssd_managed_setting undo requires a string "
                    "section";
            return false;
        }
        payload.section = sectionIt->get<std::string>();
        const auto optionIt = value.find("option");
        if (optionIt == value.end() || !optionIt->is_string()) {
            error = "remove_sssd_managed_setting undo requires a string "
                    "option";
            return false;
        }
        payload.option = optionIt->get<std::string>();
        // Structural parsing: applied_value MUST be present and a JSON
        // string (missing/non-string/null is malformed provenance).
        const auto appliedIt = value.find("applied_value");
        if (appliedIt == value.end() || !appliedIt->is_string()) {
            error = "remove_sssd_managed_setting undo requires a string "
                    "applied_value";
            return false;
        }
        payload.appliedValue = appliedIt->get<std::string>();
        if (!validateSssdUndoPayload(payload, error)) {
            return false;
        }
        action.payload = std::move(payload);
        return true;
    }
    if (actionName == "restore_kerberos_scalar" &&
        backend == MutationBackend::Kerberos) {
        UndoRestoreKerberosScalar payload;
        // Fail-closed STRUCTURAL parsing of the required string fields (see
        // the SSSD branch above): semantic constraints stay in
        // validateKerberosUndoPayload.
        const auto sectionIt = value.find("section");
        if (sectionIt == value.end() || !sectionIt->is_string()) {
            error = "restore_kerberos_scalar undo requires a string section";
            return false;
        }
        payload.section = sectionIt->get<std::string>();
        const auto relationIt = value.find("relation");
        if (relationIt == value.end() || !relationIt->is_string()) {
            error = "restore_kerberos_scalar undo requires a string relation";
            return false;
        }
        payload.relation = relationIt->get<std::string>();
        const auto appliedIt = value.find("applied_value");
        if (appliedIt == value.end() || !appliedIt->is_string()) {
            error = "restore_kerberos_scalar undo requires a string "
                    "applied_value";
            return false;
        }
        payload.appliedValue = appliedIt->get<std::string>();
        const auto beforeKindIt = value.find("before_kind");
        if (beforeKindIt == value.end() || !beforeKindIt->is_string()) {
            error = "restore_kerberos_scalar undo requires a string "
                    "before_kind";
            return false;
        }
        if (*beforeKindIt == "present") {
            payload.beforeKind = KerberosBeforeKind::Present;
        } else if (*beforeKindIt == "missing") {
            payload.beforeKind = KerberosBeforeKind::Missing;
        } else {
            error = "restore_kerberos_scalar undo has unknown before_kind: " +
                beforeKindIt->get<std::string>();
            return false;
        }
        const auto rawLineIt = value.find("before_raw_line");
        if (rawLineIt == value.end() || !rawLineIt->is_string()) {
            error = "restore_kerberos_scalar undo requires a string "
                    "before_raw_line";
            return false;
        }
        payload.beforeRawLine = rawLineIt->get<std::string>();
        const auto sectionExistedIt = value.find("section_existed_before");
        if (sectionExistedIt == value.end() ||
            !sectionExistedIt->is_boolean()) {
            error = "restore_kerberos_scalar undo requires a boolean "
                    "section_existed_before";
            return false;
        }
        payload.sectionExistedBefore = sectionExistedIt->get<bool>();
        if (!validateKerberosUndoPayload(payload, error)) {
            return false;
        }
        action.payload = std::move(payload);
        return true;
    }
    if (actionName == "remove_pam_provider_managed_entry" &&
        backend == MutationBackend::Pam) {
        UndoRemovePamProviderManagedEntry payload;
        // Fail-closed STRUCTURAL parsing: every field MUST be present and
        // MUST be a JSON string of the expected kind. Semantic constraints
        // (identity tokens, canonical applied body, absolute path) stay in
        // validatePamProviderManagedEntryUndoPayload.
        const auto readString = [&](const char* field,
                                    std::string& target) -> bool {
            const auto it = value.find(field);
            if (it == value.end() || !it->is_string()) {
                error = std::string(
                            "remove_pam_provider_managed_entry undo "
                            "requires a string ") +
                    field;
                return false;
            }
            target = it->get<std::string>();
            return true;
        };
        if (!readString("policy", payload.policyName) ||
            !readString("provider", payload.providerName) ||
            !readString("config_path", payload.configPath) ||
            !readString("managed_key", payload.managedKey) ||
            !readString("applied_body", payload.appliedBody)) {
            return false;
        }
        // Write/read parity: the field is ALWAYS written by
        // serializeUndoAction; a document without it is malformed (fail
        // closed). Empty string = fresh create.
        if (!readString("previous_applied_body",
                        payload.previousAppliedBody)) {
            return false;
        }
        const auto placementIt = value.find("placement");
        if (placementIt == value.end() || !placementIt->is_string()) {
            error = "remove_pam_provider_managed_entry undo requires a "
                    "string placement";
            return false;
        }
        if (*placementIt == "beginning") {
            payload.placement =
                PamProviderBlockPlacementContract::Beginning;
        } else if (*placementIt == "end") {
            payload.placement = PamProviderBlockPlacementContract::End;
        } else {
            error = "remove_pam_provider_managed_entry undo has unknown "
                    "placement: " +
                placementIt->get<std::string>();
            return false;
        }
        if (!validatePamProviderManagedEntryUndoPayload(payload, error)) {
            return false;
        }
        action.payload = std::move(payload);
        return true;
    }
    if (actionName == "remove_pam_provider_managed_flag" &&
        backend == MutationBackend::Pam) {
        // Step 7E: durable set-only flag provenance (PROVENANCE, never a
        // backup — no foreign line or historical content is representable).
        UndoRemovePamProviderManagedFlag payload;
        const auto readString = [&](const char* field,
                                    std::string& target) -> bool {
            const auto it = value.find(field);
            if (it == value.end() || !it->is_string()) {
                error = std::string(
                            "remove_pam_provider_managed_flag undo "
                            "requires a string ") +
                    field;
                return false;
            }
            target = it->get<std::string>();
            return true;
        };
        if (!readString("policy", payload.policyName) ||
            !readString("provider", payload.providerName) ||
            !readString("config_path", payload.configPath) ||
            !readString("managed_key", payload.managedKey)) {
            return false;
        }
        const auto appliedEnabledIt = value.find("applied_enabled");
        if (appliedEnabledIt == value.end() ||
            !appliedEnabledIt->is_boolean()) {
            error = "remove_pam_provider_managed_flag undo requires a "
                    "boolean applied_enabled";
            return false;
        }
        payload.appliedEnabled = appliedEnabledIt->get<bool>();
        const auto previousIt = value.find("previous_applied_enabled");
        if (previousIt == value.end() || !previousIt->is_string()) {
            error = "remove_pam_provider_managed_flag undo requires a "
                    "string previous_applied_enabled";
            return false;
        }
        if (*previousIt == "none") {
            payload.previousAppliedEnabled.reset();
        } else if (*previousIt == "enabled") {
            payload.previousAppliedEnabled = true;
        } else if (*previousIt == "disabled") {
            payload.previousAppliedEnabled = false;
        } else {
            error = "remove_pam_provider_managed_flag undo has an unknown "
                    "previous_applied_enabled: " +
                previousIt->get<std::string>();
            return false;
        }
        const auto placementIt = value.find("placement");
        if (placementIt == value.end() || !placementIt->is_string()) {
            error = "remove_pam_provider_managed_flag undo requires a "
                    "string placement";
            return false;
        }
        if (*placementIt == "beginning") {
            payload.placement =
                PamProviderBlockPlacementContract::Beginning;
        } else if (*placementIt == "end") {
            payload.placement = PamProviderBlockPlacementContract::End;
        } else {
            error = "remove_pam_provider_managed_flag undo has unknown "
                    "placement: " +
                placementIt->get<std::string>();
            return false;
        }
        const auto readIds = [&](const char* field,
                                 std::vector<std::string>& target) -> bool {
            const auto it = value.find(field);
            if (it == value.end() || !it->is_array()) {
                error = std::string(
                            "remove_pam_provider_managed_flag undo "
                            "requires a string array ") +
                    field;
                return false;
            }
            for (const auto& entry : *it) {
                if (!entry.is_string()) {
                    error = std::string(
                                "remove_pam_provider_managed_flag undo "
                                "requires string entries in ") +
                        field;
                    return false;
                }
                target.push_back(entry.get<std::string>());
            }
            return true;
        };
        if (!readIds("suppression_ids", payload.suppressionIds) ||
            !readIds("previous_suppression_ids",
                     payload.previousSuppressionIds)) {
            return false;
        }
        if (!validatePamProviderManagedFlagUndoPayload(payload, error)) {
            return false;
        }
        action.payload = std::move(payload);
        return true;
    }
    if (actionName == "own_pam_provider_container" &&
        backend == MutationBackend::Pam) {
        // Durable container-level FIC ownership provenance, independent of
        // any entry record lifecycle.
        UndoOwnPamProviderContainer payload;
        const auto readString = [&](const char* field,
                                    std::string& target) -> bool {
            const auto it = value.find(field);
            if (it == value.end() || !it->is_string()) {
                error = std::string(
                            "own_pam_provider_container undo requires a "
                            "string ") +
                    field;
                return false;
            }
            target = it->get<std::string>();
            return true;
        };
        if (!readString("provider", payload.providerName) ||
            !readString("config_path", payload.configPath)) {
            return false;
        }
        if (!validatePamProviderContainerUndoPayload(payload, error)) {
            return false;
        }
        action.payload = std::move(payload);
        return true;
    }
    error = "unknown or inconsistent undo action: " + actionName +
            " for backend " + backendName;
    return false;
}

json serializeRecord(const MutationRecord& record) {
    json value;
    value["id"] = record.id;
    value["policy"] = {
        {"module", record.policy.moduleName},
        {"submodule", record.policy.submoduleName},
        {"policy", record.policy.policyName}
    };
    value["resource"] = record.resource;
    value["backend"] = mutationBackendToString(record.undo.backend);
    value["status"] = mutationStatusToString(record.status);
    value["undo"] = serializeUndoAction(record.undo);
    value["created_at_epoch"] = record.createdAtEpoch;
    value["updated_at_epoch"] = record.updatedAtEpoch;
    value["error"] = record.error;
    return value;
}

bool deserializeRecord(const json& value, MutationRecord& record, std::string& error) {
    if (!value.is_object()) {
        error = "journal record must be an object";
        return false;
    }
    const auto idIt = value.find("id");
    if (idIt == value.end() || !idIt->is_number_unsigned()) {
        error = "journal record requires an unsigned id";
        return false;
    }
    record.id = idIt->get<MutationId>();

    const auto policyIt = value.find("policy");
    if (policyIt == value.end() || !policyIt->is_object()) {
        error = "journal record requires a policy object";
        return false;
    }
    record.policy.moduleName = policyIt->value("module", "");
    record.policy.submoduleName = policyIt->value("submodule", "");
    record.policy.policyName = policyIt->value("policy", "");
    if (record.policy.moduleName.empty() || record.policy.policyName.empty()) {
        error = "journal record policy requires module and policy names";
        return false;
    }

    record.resource = value.value("resource", "");

    const auto undoIt = value.find("undo");
    if (undoIt == value.end() || !undoIt->is_object()) {
        error = "journal record requires an undo object";
        return false;
    }
    if (!deserializeUndoAction(*undoIt, record.undo, error)) {
        return false;
    }
    if ((record.undo.backend == MutationBackend::Scope ||
         std::holds_alternative<ScopeTransitionCheckpoint>(record.undo.payload)) &&
        !validScopeRecord(record, error)) return false;
    if (!validateSudoGlobalRecord(record, error)) return false;
    // Cross-field consistency: for GRUB the record identity carries the
    // managed key. record.resource MUST equal UndoRemoveGrubManagedSetting
    // .key — a disagreement means malformed provenance, which must never
    // reach apply-time repair reuse (fail closed at load, not at apply).
    if (record.undo.backend == MutationBackend::Grub) {
        const auto* grub =
            std::get_if<UndoRemoveGrubManagedSetting>(&record.undo.payload);
        if (grub == nullptr || grub->key != record.resource) {
            error = "GRUB journal resource does not match undo key: "
                    "resource '" +
                record.resource + "'";
            return false;
        }
    }
    if (record.undo.backend == MutationBackend::Sssd) {
        const auto* sssd =
            std::get_if<UndoRemoveSssdManagedSetting>(&record.undo.payload);
        if (sssd == nullptr ||
            sssd->section + "/" + sssd->option != record.resource) {
            error = "SSSD journal resource does not match undo "
                    "section/option: resource '" +
                record.resource + "'";
            return false;
        }
    }
    if (record.undo.backend == MutationBackend::Kerberos) {
        const auto* kerberos =
            std::get_if<UndoRestoreKerberosScalar>(&record.undo.payload);
        if (kerberos == nullptr ||
            kerberos->section + "/" + kerberos->relation != record.resource) {
            error = "Kerberos journal resource does not match undo "
                    "section/relation: resource '" +
                record.resource + "'";
            return false;
        }
    }
    if (record.undo.backend == MutationBackend::Pam) {
        if (const auto* pamEntry = std::get_if<
                UndoRemovePamProviderManagedEntry>(&record.undo.payload)) {
            if (record.policy.moduleName != "IDENTITY_ACCESS" ||
                record.policy.submoduleName != "PAM" ||
                record.policy.policyName != pamEntry->policyName ||
                record.resource != pamEntry->configPath) {
                error = "PAM journal resource/policy does not match the "
                        "managed-entry undo payload";
                return false;
            }
        } else if (const auto* pamFlag = std::get_if<
                       UndoRemovePamProviderManagedFlag>(
                       &record.undo.payload)) {
            if (record.policy.moduleName != "IDENTITY_ACCESS" ||
                record.policy.submoduleName != "PAM" ||
                record.policy.policyName != pamFlag->policyName ||
                record.resource != pamFlag->configPath) {
                error = "PAM journal resource/policy does not match the "
                        "managed-flag undo payload";
                return false;
            }
        } else if (const auto* pamContainer = std::get_if<
                       UndoOwnPamProviderContainer>(&record.undo.payload)) {
            // The container provenance identity is the dedicated
            // PAM_CONTAINER submodule: it can never collide with an entry
            // record (policy, backend, resource) for the same config path.
            if (record.policy.moduleName != "IDENTITY_ACCESS" ||
                record.policy.submoduleName != "PAM_CONTAINER" ||
                record.policy.policyName != pamContainer->providerName ||
                record.resource != pamContainer->configPath) {
                error = "PAM journal resource/policy does not match the "
                        "container-ownership undo payload";
                return false;
            }
        } else {
            const auto* pam =
                std::get_if<UndoDisablePamCapability>(&record.undo.payload);
            const auto backendIt = value.find("backend");
            if (backendIt == value.end() || !backendIt->is_string() ||
                *backendIt != "pam" || pam == nullptr ||
                record.policy.moduleName != "IDENTITY_ACCESS" ||
                record.policy.submoduleName != "PAM" ||
                record.policy.policyName != pam->capability ||
                record.resource != "capability/" + pam->capability) {
                error = "PAM journal resource/policy does not match undo capability";
                return false;
            }
        }
    }
    if (record.undo.backend == MutationBackend::UserCreation) {
        const auto* payload = std::get_if<UndoRemoveUserCreationManagedPolicy>(
            &record.undo.payload);
        if (payload == nullptr || record.policy.moduleName != "IDENTITY_ACCESS" ||
            record.policy.submoduleName != "USER_CREATION" ||
            record.policy.policyName != payload->policyName ||
            record.resource != payload->configPath) {
            error = "USER_CREATION journal identity does not match payload";
            return false;
        }
    }
    if (record.undo.backend == MutationBackend::IdentityLoginDefs) {
        const auto* payload = std::get_if<
            UndoRemoveIdentityLoginDefsManagedPolicy>(&record.undo.payload);
        const auto* payloadSpec = payload == nullptr
            ? nullptr
            : fic::identity::login_defs::findSharedLoginDefsPolicySpec(
                  payload->policyName);
        if (payload == nullptr || payloadSpec == nullptr ||
            record.policy.moduleName != "IDENTITY_ACCESS" ||
            record.policy.submoduleName != payloadSpec->submodule ||
            record.policy.policyName != payload->policyName ||
            record.resource != payload->configPath) {
            error = "identity_login_defs journal identity does not match "
                    "payload";
            return false;
        }
    }

    MutationStatus status;
    if (!mutationStatusFromString(value.value("status", ""), status)) {
        error = "unknown mutation status: " + value.value("status", std::string());
        return false;
    }
    record.status = status;
    if(!validSshRecord(record,error))return false;
    if ((record.undo.backend == MutationBackend::Desktop ||
         (std::holds_alternative<UndoRestoreDesktopScalar>(record.undo.payload) ||
          std::holds_alternative<UndoOwnDesktopArtifact>(record.undo.payload))) &&
        !validDesktopRecord(record, error)) return false;
    if (record.undo.backend == MutationBackend::Scope &&
        !validScopeRecord(record, error)) return false;

    if ((record.undo.backend == MutationBackend::DisplayManager || std::holds_alternative<UndoRemoveDisplayManagerBlock>(record.undo.payload)) &&
        !validDmRecord(record, error)) return false;
    record.createdAtEpoch = value.value("created_at_epoch", std::int64_t{0});
    record.updatedAtEpoch = value.value("updated_at_epoch", std::int64_t{0});
    record.error = value.value("error", std::string());
    return true;
}

} // namespace

// See the declaration in MutationJournal.h: the single status-aware
// suppression-wrapper authority model, shared with the PAM provider
// package preflight. preparedPamFlagSuppressionAuthority() above (anonymous
// namespace) stays the internal authority computation for future-Prepared
// transitions on the write path.
std::vector<std::string> activePamFlagSuppressionAuthority(
    const MutationRecord& record,
    const UndoRemovePamProviderManagedFlag& flag) {
    if (!record.isActive()) {
        return {};
    }
    if (record.status == MutationStatus::Prepared) {
        return preparedPamFlagSuppressionAuthority(flag);
    }
    return flag.suppressionIds;
}

bool validateDisplayManagerMutationRecord(const MutationRecord& record, std::string& error) {
    return validDmRecord(record,error);
}

std::string mutationStatusToString(MutationStatus status) {
    switch (status) {
    case MutationStatus::Prepared: return "prepared";
    case MutationStatus::Applied: return "applied";
    case MutationStatus::RolledBack: return "rolled_back";
    case MutationStatus::RollbackFailed: return "rollback_failed";
    case MutationStatus::Detached: return "detached";
    }
    return "unknown";
}

bool mutationStatusFromString(const std::string& value, MutationStatus& status) {
    if (value == "prepared") { status = MutationStatus::Prepared; return true; }
    if (value == "applied") { status = MutationStatus::Applied; return true; }
    if (value == "rolled_back") { status = MutationStatus::RolledBack; return true; }
    if (value == "rollback_failed") { status = MutationStatus::RollbackFailed; return true; }
    if (value == "detached") { status = MutationStatus::Detached; return true; }
    return false;
}

std::string mutationBackendToString(MutationBackend backend) {
    switch (backend) {
    case MutationBackend::Sysctl: return "sysctl";
    case MutationBackend::Sudo: return "sudo";
    case MutationBackend::Ssh: return "ssh";
    case MutationBackend::Firewall: return "firewall";
    case MutationBackend::Grub: return "grub";
    case MutationBackend::Sssd: return "sssd";
    case MutationBackend::Kerberos: return "kerberos";
    case MutationBackend::Pam: return "pam";
    case MutationBackend::UserCreation: return "user_creation";
    case MutationBackend::IdentityLoginDefs: return "identity_login_defs";
    case MutationBackend::Scope: return "scope";
    case MutationBackend::Desktop: return "desktop";
    case MutationBackend::DisplayManager: return "display_manager";
    }
    return "unknown";
}

bool mutationBackendFromString(const std::string& value, MutationBackend& backend) {
    if (value == "sysctl") { backend = MutationBackend::Sysctl; return true; }
    if (value == "sudo") { backend = MutationBackend::Sudo; return true; }
    if (value == "ssh") { backend = MutationBackend::Ssh; return true; }
    if (value == "firewall") { backend = MutationBackend::Firewall; return true; }
    if (value == "grub") { backend = MutationBackend::Grub; return true; }
    if (value == "sssd") { backend = MutationBackend::Sssd; return true; }
    if (value == "kerberos") { backend = MutationBackend::Kerberos; return true; }
    if (value == "pam") { backend = MutationBackend::Pam; return true; }
    if (value == "user_creation") { backend = MutationBackend::UserCreation; return true; }
    if (value == "identity_login_defs") { backend = MutationBackend::IdentityLoginDefs; return true; }
    if (value == "scope") { backend = MutationBackend::Scope; return true; }
    if (value == "desktop") { backend = MutationBackend::Desktop; return true; }
    if (value == "display_manager") { backend = MutationBackend::DisplayManager; return true; }
    return false;
}

std::string undoActionTypeName(const UndoAction& action) {
    if (std::holds_alternative<UndoRemoveDisplayManagerBlock>(action.payload)) return "remove_display_manager_block";
    if (std::holds_alternative<UndoOwnDesktopArtifact>(action.payload))
        return "own_desktop_artifact";
    if (std::holds_alternative<UndoRestoreDesktopScalar>(action.payload))
        return "restore_desktop_scalar";
    if (std::holds_alternative<ScopeTransitionCheckpoint>(action.payload))
        return "scope_transition_checkpoint";
    if (std::holds_alternative<UndoReleaseSudoAuthentication>(action.payload))
        return "release_sudo_authentication";
    if (std::holds_alternative<UndoReleaseSudoGlobalDefault>(action.payload))
        return "release_sudo_global_default";
    if (std::holds_alternative<UndoRemoveManagedSetting>(action.payload)) {
        return "remove_managed_setting";
    }
    if (std::holds_alternative<UndoReleaseSudoScopedDefaults>(action.payload)) {
        return "release_sudo_scoped_defaults";
    }
    if (std::holds_alternative<UndoRemoveSshManagedPolicy>(action.payload)) {
        return "remove_ssh_managed_policy";
    }
    if (std::holds_alternative<UndoRemoveUserCreationManagedPolicy>(
            action.payload)) {
        return "remove_user_creation_managed_policy";
    }
    if (std::holds_alternative<UndoRemoveIdentityLoginDefsManagedPolicy>(
            action.payload)) {
        return "remove_identity_login_defs_managed_policy";
    }
    if (std::holds_alternative<UndoRemoveFirewallPolicy>(action.payload)) {
        return "remove_firewall_policy";
    }
    if (std::holds_alternative<UndoRemoveGrubManagedSetting>(action.payload)) {
        return "remove_grub_managed_setting";
    }
    if (std::holds_alternative<UndoRemoveSssdManagedSetting>(action.payload)) {
        return "remove_sssd_managed_setting";
    }
    if (std::holds_alternative<UndoRestoreKerberosScalar>(action.payload)) {
        return "restore_kerberos_scalar";
    }
    if (std::holds_alternative<UndoDisablePamCapability>(action.payload)) {
        return "disable_pam_capability";
    }
    if (std::holds_alternative<UndoRemovePamProviderManagedEntry>(
            action.payload)) {
        return "remove_pam_provider_managed_entry";
    }
    if (std::holds_alternative<UndoRemovePamProviderManagedFlag>(
            action.payload)) {
        return "remove_pam_provider_managed_flag";
    }
    if (std::holds_alternative<UndoOwnPamProviderContainer>(action.payload)) {
        return "own_pam_provider_container";
    }
    return "unknown";
}

MutationJournal::MutationJournal(std::filesystem::path path)
    : path_(std::move(path)) {
}

bool MutationJournal::failLoad(std::string message, std::string& error) {
    // Transactional failure: never mutate records_/nextId_/loaded_ — the
    // previous in-memory state stays for diagnostics — but revoke operational
    // trust so stale provenance cannot drive any decision.
    health_ = JournalHealth::Indeterminate;
    error = std::move(message);
    return false;
}

std::filesystem::path MutationJournal::witnessPath() const {
    return path_.string() + ".initialized";
}

bool MutationJournal::witnessIsValid(std::string& error) {
    // A valid witness requires an exact versioned document captured through
    // a regular-file descriptor (symlinks and other non-regular objects are
    // refused) AND a state-bound durability barrier: visible != durable.
    AtomicTargetState snapshot;
    std::string captureError;
    if (!AtomicFileWriter::captureTargetState(witnessPath().string(),
                                              snapshot, &captureError)) {
        error = "Initialization witness недоступен/некорректен (fail closed): " +
                captureError;
        return false;
    }
    json document;
    try {
        document = json::parse(snapshot.content);
    } catch (const json::exception& exception) {
        error = "Initialization witness повреждён (fail closed): " +
                std::string(exception.what());
        return false;
    }
    if (!document.is_object() || document.size() != 2 ||
        document.find("schema_version") == document.end() ||
        document.find("initialized") == document.end() ||
        !document["schema_version"].is_number_unsigned() ||
        document["schema_version"].get<std::uint32_t>() !=
            kWitnessSchemaVersion ||
        document["initialized"] != true) {
        error = "Initialization witness имеет неожиданное содержимое "
                "(fail closed): " +
                witnessPath().string();
        return false;
    }
    std::string durabilityError;
    if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(
            witnessPath().string(), snapshot, &durabilityError)) {
        error = "Durability initialization witness не подтверждена "
                "(fail closed): " +
                durabilityError;
        return false;
    }
    return true;
}

bool MutationJournal::createWitness(std::string& error) {
    json document;
    document["schema_version"] = kWitnessSchemaVersion;
    document["initialized"] = true;
    AtomicWriteOptions options;
    // Exclusive create: never silently replace a foreign object occupying
    // the witness path (a directory, a symlink, a malformed file, or a
    // concurrently created witness).
    options.createIfMissing = true;
    options.rejectSymlink = true;
    options.exclusiveCreate = true;
    options.fileMode = 0600;
    AtomicWriteResult result;
    if (!AtomicFileWriter::writeWithResult(witnessPath().string(),
                                           document.dump(2) + "\n", options,
                                           &error, &result)) {
        if (!result.installed) {
            // Not installed: either a race (another process created the
            // witness between the existence check and the commit) or a real
            // creation failure. Accept only a valid durable witness.
            std::string witnessError;
            if (witnessIsValid(witnessError)) {
                error.clear();
                return true;
            }
            error = "Не удалось создать initialization witness (fail closed): " +
                    error + "; " + witnessError;
            return false;
        }
        // installed != durable: the rename published the witness but the
        // parent directory fsync failed. Finish the durability transparently
        // against the exact installed state; otherwise fail closed — the
        // next startup will take the migration path (J exists + W missing).
        std::string barrierError;
        if (result.installedTargetState.has_value() &&
            AtomicFileWriter::ensureTargetDurableIfCurrentState(
                witnessPath().string(), *result.installedTargetState,
                &barrierError)) {
            error.clear();
            return true;
        }
        error = "Initialization witness записан (rename), но durability "
                "подтвердить не удалось (fail closed): " +
                barrierError;
        return false;
    }
    return true;
}

bool MutationJournal::initializeOrLoad(std::string& error) {
    if (lifecycleInitialized_) {
        // Completed witness-aware lifecycle: strict live reload. After the
        // persistent initialization the disappearance of the journal is
        // NEVER a valid empty bootstrap (follow-up 6/7 semantics) — a raw
        // reload must not bypass the persistent witness state.
        return loadExisting(error);
    }
    return initializeFresh(error);
}

bool MutationJournal::initializeFresh(std::string& error) {
    // Bounded witness-aware state table. An exclusive-create conflict means
    // another FIC instance created the journal concurrently: the state table
    // is re-classified (the file is NEVER replaced). A hostile writer racing
    // forever cannot be served forever either — after the bounded number of
    // passes the initialization fails closed with explicit diagnostics.
    constexpr int kMaxStateTablePasses = 3;
    for (int pass = 0; pass < kMaxStateTablePasses; ++pass) {
        // Persistent (journal, witness) presence probe.
        std::error_code journalProbeError;
        const std::filesystem::file_status journalStatus =
            std::filesystem::status(path_, journalProbeError);
        if (journalProbeError &&
            journalStatus.type() != std::filesystem::file_type::not_found) {
            return failLoad("Не удалось проверить наличие mutation journal " +
                                path_.string() + ": " +
                                journalProbeError.message(),
                            error);
        }
        const bool journalMissing =
            journalStatus.type() == std::filesystem::file_type::not_found ||
            !std::filesystem::exists(journalStatus);

        std::error_code witnessProbeError;
        const std::filesystem::file_status witnessStatus =
            std::filesystem::status(witnessPath(), witnessProbeError);
        if (witnessProbeError &&
            witnessStatus.type() != std::filesystem::file_type::not_found) {
            return failLoad("Не удалось проверить наличие initialization "
                            "witness " +
                                witnessPath().string() + ": " +
                                witnessProbeError.message(),
                            error);
        }
        const bool witnessMissing =
            witnessStatus.type() == std::filesystem::file_type::not_found ||
            !std::filesystem::exists(witnessStatus);

        if (journalMissing) {
            if (witnessMissing) {
                switch (bootstrapVirgin(error)) {
                    case BootstrapOutcome::Installed:
                        return true;
                    case BootstrapOutcome::ConflictJournalExists:
                        // Another instance created the journal between the
                        // probe and the exclusive install. Never assume it
                        // is our empty journal: re-evaluate the persistent
                        // state table (bounded); the journal will be loaded
                        // and validated through the normal strict rules.
                        continue;
                    case BootstrapOutcome::Failed:
                        return false;
                }
            }
            // Witness present (valid or not) while the journal is missing. A
            // valid witness means the journal lifecycle was initialized
            // before: its disappearance is provenance loss, never a virgin
            // bootstrap. An invalid witness is a persistent-state anomaly.
            // Neither may be healed automatically.
            std::string witnessError;
            if (witnessIsValid(witnessError)) {
                return failLoad(
                    "Mutation journal is missing although its persistent "
                    "initialization witness exists; rollback provenance may "
                    "have been lost; manual provenance recovery is required: " +
                        path_.string(),
                    error);
            }
            return failLoad("Persistent-state anomaly: mutation journal "
                            "отсутствует, initialization witness некорректен "
                            "(fail closed): " +
                                witnessError,
                            error);
        }
        return initializeExistingJournal(witnessMissing, error);
    }
    return failLoad("Witness-aware initialization не завершилась после "
                    "ограниченного числа попыток разрешения concurrent "
                    "bootstrap race (fail closed): " +
                        path_.string(),
                    error);
}

bool MutationJournal::validatePersistentStateReadOnly(std::string& error) {
    // Same persistent (journal, witness) presence probe as the witness-aware
    // state table of initializeOrLoad(). Read-only: a probe never mutates.
    std::error_code journalProbeError;
    const std::filesystem::file_status journalStatus =
        std::filesystem::status(path_, journalProbeError);
    if (journalProbeError &&
        journalStatus.type() != std::filesystem::file_type::not_found) {
        return failLoad("Не удалось проверить наличие mutation journal " +
                            path_.string() + ": " +
                            journalProbeError.message(),
                        error);
    }
    const bool journalMissing =
        journalStatus.type() == std::filesystem::file_type::not_found ||
        !std::filesystem::exists(journalStatus);

    std::error_code witnessProbeError;
    const std::filesystem::file_status witnessStatus =
        std::filesystem::status(witnessPath(), witnessProbeError);
    if (witnessProbeError &&
        witnessStatus.type() != std::filesystem::file_type::not_found) {
        return failLoad("Не удалось проверить наличие initialization "
                        "witness " +
                            witnessPath().string() + ": " +
                            witnessProbeError.message(),
                        error);
    }
    const bool witnessMissing =
        witnessStatus.type() == std::filesystem::file_type::not_found ||
        !std::filesystem::exists(witnessStatus);

    if (journalMissing) {
        // Nothing may be bootstrapped, healed or migrated read-only: the
        // runtime would either bootstrap a virgin journal (a write) or fail
        // closed; neither leaves usable provenance for a read-only caller.
        if (witnessMissing) {
            return failLoad(
                "Persistent-state validation (read-only): mutation journal "
                "отсутствует, initialization witness отсутствует (virgin "
                "state); read-only validation cannot bootstrap a journal "
                "(fail closed): " +
                    path_.string(),
                error);
        }
        std::string witnessError;
        if (witnessIsValid(witnessError)) {
            return failLoad(
                "Persistent-state validation (read-only): mutation journal "
                "is missing although its initialization witness exists; "
                "rollback provenance may have been lost (fail closed): " +
                    path_.string(),
                error);
        }
        return failLoad(
            "Persistent-state validation (read-only): mutation journal "
            "отсутствует, initialization witness некорректен "
            "(fail closed): " +
                witnessError,
            error);
    }

    // Journal exists. The runtime lifecycle accepts this branch only after
    // the witness is proven (normal startup) or durably created
    // (migration). The migration branch is a WRITE, which a read-only
    // validation must never perform, so the pending-migration state stays
    // indeterminate until it is completed through the normal daemon
    // lifecycle.
    if (witnessMissing) {
        return failLoad(
            "Persistent-state validation (read-only): mutation journal "
            "exists without its initialization witness (pending migration); "
            "read-only validation must not create the witness — complete "
            "the journal migration through the normal daemon lifecycle and "
            "retry (fail closed): " +
                path_.string(),
            error);
    }
    std::string witnessError;
    if (!witnessIsValid(witnessError)) {
        return failLoad(
            "Persistent-state validation (read-only): mutation journal "
            "корректен, но initialization witness некорректен "
            "(fail closed): " +
                witnessError,
            error);
    }
    // Strict existing-journal proof: identical parser/durability flow to the
    // runtime normal-startup branch; a vanished or replaced journal fails
    // closed and nothing is ever written.
    if (!loadExisting(error)) {
        return false;
    }
    lifecycleInitialized_ = true;
    error.clear();
    return true;
}

bool MutationJournal::initializeExistingJournal(bool witnessMissing,
                                                std::string& error) {
    // Journal exists: strict load only — a vanished journal inside this
    // transaction must never heal into an empty journal.
    if (witnessMissing) {
        // Migration / interrupted bootstrap:
        //   loadExisting J → create/prove W → FINAL loadExisting proof J
        // The lifecycle becomes initialized only after BOTH persistent
        // objects were proven within the same transaction.
        if (!loadExisting(error)) {
            return false;
        }
        if (!createWitness(error)) {
            // lifecycleInitialized_ stays false: the witness-aware
            // initialization did NOT complete. A retry on this object
            // re-runs the witness-aware state table (never a raw reload
            // that would bypass the witness).
            return failLoad("Не удалось создать initialization witness "
                            "после успешной proof journal (fail closed): " +
                                error,
                            error);
        }
        if (beforeFinalJournalProofHook()) {
            beforeFinalJournalProofHook()();
        }
        // Final re-proof: between the first proof and the witness creation
        // the journal may have disappeared or been replaced. This is not a
        // filesystem transaction — the known residual re-proof→fsync TOCTOU
        // after this point remains.
        if (!loadExisting(error)) {
            return false;
        }
        lifecycleInitialized_ = true;
        error.clear();
        return true;
    }
    std::string witnessError;
    if (!witnessIsValid(witnessError)) {
        return failLoad("Persistent-state anomaly: mutation journal "
                        "корректен, но initialization witness некорректен "
                        "(fail closed): " +
                            witnessError,
                        error);
    }
    // Normal startup: prove both persistent objects, then publish the
    // operational lifecycle state.
    if (!loadExisting(error)) {
        return false;
    }
    lifecycleInitialized_ = true;
    error.clear();
    return true;
}

MutationJournal::BootstrapOutcome MutationJournal::bootstrapVirgin(
    std::string& error) {
    // Virgin bootstrap: create a real schema-valid empty journal FIRST with
    // NO-REPLACE semantics (journal-before-witness ordering keeps a crash
    // between the two phases recoverable through the migration path).
    // Invariant: bootstrap code NEVER replaces an existing journal — a
    // concurrent instance's journal (already carrying provenance records)
    // must not be destroyable by our empty temp document.
    json document;
    document["schema_version"] = kSchemaVersion;
    document["next_id"] = 1;
    document["records"] = json::array();
    AtomicWriteOptions options;
    options.createIfMissing = true;
    options.rejectSymlink = true;
    // Exclusive install: no-replace semantics — the commit fails if any
    // object occupies the target at commit time.
    options.exclusiveCreate = true;
    options.fileMode = 0600;
    // Copy before invoking: the hook may reassign/clear the slot while it
    // runs; destroying the executing std::function would be UB.
    if (auto hook = beforeVirginJournalInstallHook()) {
        hook();
    }
    AtomicWriteResult result;
    if (!AtomicFileWriter::writeWithResult(path_.string(),
                                           document.dump(2) + "\n", options,
                                           &error, &result)) {
        if (!result.installed) {
            // Distinguish "target appeared due to the bootstrap race" from a
            // real filesystem failure by re-probing the path (never by errno
            // text).
            std::error_code probeError;
            const std::filesystem::file_status status =
                std::filesystem::status(path_, probeError);
            if (!probeError && std::filesystem::exists(status)) {
                // Another instance won the bootstrap race for the journal.
                // NEVER assume it is our empty journal: re-classify through
                // the state table (the journal will be loaded and validated
                // through the normal strict regular-file rules; a symlink or
                // another non-regular object fails closed there).
                return BootstrapOutcome::ConflictJournalExists;
            }
            // Not installed, target absent: nothing was published and the
            // witness was not created; the next startup retries the
            // bootstrap.
            failLoad("Не удалось создать пустой mutation journal "
                     "(fail closed): " +
                         error,
                     error);
            return BootstrapOutcome::Failed;
        }
        // installed != durable: the rename published the empty journal but
        // the parent directory fsync failed. Finish the durability
        // transparently against the exact installed state; otherwise fail
        // closed — the next startup sees J exists + W missing and takes the
        // migration path.
        std::string barrierError;
        if (!(result.installedTargetState.has_value() &&
              AtomicFileWriter::ensureTargetDurableIfCurrentState(
                  path_.string(), *result.installedTargetState,
                  &barrierError))) {
            failLoad("Пустой mutation journal записан (rename), но durability "
                     "подтвердить не удалось (fail closed): " +
                         barrierError,
                     error);
            return BootstrapOutcome::Failed;
        }
        error.clear();
    }
    if (!createWitness(error)) {
        failLoad("Не удалось создать initialization witness "
                 "(fail closed): " +
                     error,
                 error);
        return BootstrapOutcome::Failed;
    }
    // Copy before invoking: the hook may reassign/clear the slot while it
    // runs; destroying the executing std::function would be UB.
    if (auto hook = beforeFinalJournalProofHook()) {
        hook();
    }
    // Final strict proof of the freshly created pair: if the journal
    // disappeared after the witness was created, this fails closed —
    // critically NOT into an empty Healthy journal.
    if (!loadExisting(error)) {
        return BootstrapOutcome::Failed;
    }
    lifecycleInitialized_ = true;
    return BootstrapOutcome::Installed;
}

bool MutationJournal::load(std::string& error) {
    // Raw primitive: legacy bootstrap semantics (see the header comment).
    return loadImpl(MissingJournalPolicy::AllowFreshEmpty, error);
}

bool MutationJournal::loadExisting(std::string& error) {
    // Strict primitive: the journal is required to exist — a missing file is
    // ALWAYS an error here, never an empty bootstrap.
    return loadImpl(MissingJournalPolicy::RequireExisting, error);
}

bool MutationJournal::loadImpl(MissingJournalPolicy policy,
                               std::string& error) {
    std::error_code probeError;
    const std::filesystem::file_status status =
        std::filesystem::status(path_, probeError);
    if (probeError &&
        status.type() != std::filesystem::file_type::not_found) {
        return failLoad("Не удалось проверить наличие mutation journal " +
                            path_.string() + ": " + probeError.message(),
                        error);
    }
    if (status.type() == std::filesystem::file_type::not_found ||
        !std::filesystem::exists(status)) {
        // A missing journal is an empty journal ONLY for the raw legacy
        // primitive (AllowFreshEmpty) during the initial bootstrap of a
        // never-loaded journal object. The disappearance of a previously
        // known journal (loaded, or already Indeterminate) — and ANY missing
        // journal under the strict witness-aware policy — does not prove
        // that the earlier ambiguous provenance safely vanished: it must
        // fail closed instead of healing into an empty Healthy journal.
        const bool bootstrapMissing =
            policy == MissingJournalPolicy::AllowFreshEmpty &&
            !loaded_ && health_ == JournalHealth::Healthy;
        if (bootstrapMissing) {
            records_.clear();
            nextId_ = 1;
            loaded_ = true;
            error.clear();
            return true;
        }
        if (policy == MissingJournalPolicy::RequireExisting) {
            return failLoad("Mutation journal is missing (strict "
                            "existing-journal load); provenance cannot be "
                            "treated as empty: " +
                                path_.string(),
                            error);
        }
        return failLoad("Mutation journal disappeared during reload/recovery; "
                        "provenance cannot be treated as empty: " +
                            path_.string(),
                        error);
    }

    // Snapshot-bound read: capture the exact current document (identity,
    // metadata, content) through one descriptor. Parsing happens strictly
    // against snapshot.content, so a durability confirmation later in this
    // function always refers to the same bytes that were parsed.
    AtomicTargetState snapshot;
    std::string captureError;
    if (!AtomicFileWriter::captureTargetState(path_.string(), snapshot,
                                              &captureError)) {
        // The file exists but cannot be opened/read: never treat permission,
        // symlink or I/O failures as an absent journal (fail closed).
        return failLoad("Существующий mutation journal недоступен для чтения "
                        "(fail closed): " +
                            captureError,
                        error);
    }
    if (snapshot.content.empty()) {
        // An existing zero-byte journal is corrupted persistent security
        // state: fail closed instead of silently assuming an empty journal.
        // A valid empty journal must carry the schema document.
        return failLoad("Mutation journal существует, но пуст (fail closed): " +
                            path_.string(),
                        error);
    }

    // Test-only seam: an external writer may replace the journal between the
    // capture and the re-proof below; the re-proof must detect it.
    if (loadAfterCaptureHook()) {
        loadAfterCaptureHook()();
    }

    const std::string& content = snapshot.content;

    json document;
    try {
        document = json::parse(content);
    } catch (const json::exception& exception) {
        return failLoad("Mutation journal повреждён (fail closed): " +
                            std::string(exception.what()),
                        error);
    }
    if (!document.is_object()) {
        return failLoad(
            "Mutation journal должен быть JSON-объектом (fail closed)", error);
    }
    const auto schemaIt = document.find("schema_version");
    if (schemaIt == document.end() || !schemaIt->is_number_unsigned()) {
        return failLoad(
            "Mutation journal не содержит schema_version (fail closed)",
            error);
    }
    if (*schemaIt != kSchemaVersion && *schemaIt != 2) {
        return failLoad("Неподдерживаемая schema_version mutation journal: " +
                            schemaIt->dump(),
                        error);
    }
    const auto nextIdIt = document.find("next_id");
    if (nextIdIt == document.end() || !nextIdIt->is_number_unsigned()) {
        return failLoad(
            "Mutation journal не содержит корректный next_id (fail closed)",
            error);
    }
    const auto recordsIt = document.find("records");
    if (recordsIt == document.end() || !recordsIt->is_array()) {
        return failLoad(
            "Mutation journal не содержит массив records (fail closed)",
            error);
    }

    // Transactional parse: everything above worked on local state; the
    // in-memory journal is only replaced after the parsed snapshot was
    // re-proved and durably confirmed.
    std::vector<MutationRecord> parsed;
    parsed.reserve(recordsIt->size());
    for (const json& item : *recordsIt) {
        MutationRecord record;
        std::string recordError;
        if (!deserializeRecord(item, record, recordError)) {
            return failLoad("Mutation journal содержит некорректную запись "
                            "(fail closed): " +
                                recordError,
                            error);
        }
        parsed.push_back(std::move(record));
    }

    if(schemaIt->get<std::uint32_t>()==2)for(const auto& record:parsed) {
        if(const auto* ssh=std::get_if<UndoRemoveSshManagedPolicy>(&record.undo.payload);ssh&&
           (ssh->ownershipVersion||ssh->operationSequence||ssh->transition))
            return failLoad("SSH typed operations require journal schema 3",error);
    }
    const MutationId parsedNextId = nextIdIt->get<MutationId>();
    for (const MutationRecord& record : parsed) {
        if (record.id >= parsedNextId) {
            return failLoad(
                "Mutation journal содержит id без next_id (fail closed)",
                error);
        }
    }
    for (std::size_t outer = 0; outer < parsed.size(); ++outer) {
        for (std::size_t inner = outer + 1; inner < parsed.size(); ++inner) {
            if (parsed[outer].id == parsed[inner].id) {
                return failLoad(
                    "Mutation journal содержит дубликат id (fail closed)",
                    error);
            }
        }
    }
    // At most one ACTIVE record may exist for one logical mutation identity
    // (policy, backend, resource): prepareMutation() idempotent refresh and
    // all repair reuse paths rely on this invariant for unambiguous
    // provenance. Two simultaneously active records for one identity mean
    // ambiguous provenance — fail closed at load. Historical resolved
    // records (RolledBack / Detached) NEVER conflict with an active record:
    // mutation history must be preserved.
    for (std::size_t outer = 0; outer < parsed.size(); ++outer) {
        if (!parsed[outer].isActive()) {
            continue;
        }
        for (std::size_t inner = outer + 1; inner < parsed.size(); ++inner) {
            if (!parsed[inner].isActive()) {
                continue;
            }
            if (parsed[outer].policy == parsed[inner].policy &&
                parsed[outer].undo.backend == parsed[inner].undo.backend &&
                parsed[outer].resource == parsed[inner].resource) {
                return failLoad(
                    "Mutation journal содержит несколько активных записей "
                    "одного logical mutation identity (policy, backend, "
                    "resource): '" +
                        parsed[outer].resource + "' (fail closed)",
                    error);
            }
        }
    }
    // Container ownership invariant: at most ONE ACTIVE
    // own_pam_provider_container provenance may exist per physical config
    // path, regardless of provider. The generic (policy, backend, resource)
    // invariant above cannot catch two different providers claiming the
    // same file (their policy identities differ); the write path refuses
    // such a state, so the loader must reject it too (write/read semantic
    // parity) — container provenance is the authorization foundation of the
    // future unlink. Historical resolved records (RolledBack / Detached)
    // NEVER conflict with an active claim: mutation history is preserved.
    for (std::size_t outer = 0; outer < parsed.size(); ++outer) {
        if (!parsed[outer].isActive()) {
            continue;
        }
        const auto* outerContainer =
            std::get_if<UndoOwnPamProviderContainer>(
                &parsed[outer].undo.payload);
        if (outerContainer == nullptr) {
            continue;
        }
        for (std::size_t inner = outer + 1; inner < parsed.size(); ++inner) {
            if (!parsed[inner].isActive()) {
                continue;
            }
            const auto* innerContainer =
                std::get_if<UndoOwnPamProviderContainer>(
                    &parsed[inner].undo.payload);
            if (innerContainer != nullptr &&
                innerContainer->configPath == outerContainer->configPath) {
                return failLoad(
                    "Mutation journal содержит несколько активных "
                    "own_pam_provider_container provenance для одного "
                    "config path: '" +
                        outerContainer->configPath + "' (fail closed)",
                    error);
            }
        }
    }

    // Step 7E invariant: ONE suppression id may never be provable rollback
    // authority of TWO active PAM flag records of the SAME physical file.
    // Two active claims over one physical wrapper would give it ambiguous
    // rollback authority (which record releases it?), so the state is
    // journal corruption — fail closed at load (write/read semantic parity
    // with the executor's provenance proof).
    //
    // Per-record authority comes from the shared status-aware helper
    // activePamFlagSuppressionAuthority() — the single authority model
    // also enforced by prepareMutation() on the write path (see the
    // helper for the status → authority table).
    //
    // The comparison is scoped by configPath: a suppression id is a token
    // of ONE physical file namespace (Step 7E §11), so identical ids in
    // records of DIFFERENT provider primaries are independent provenance,
    // never a conflict.
    for (std::size_t outer = 0; outer < parsed.size(); ++outer) {
        if (!parsed[outer].isActive()) {
            continue;
        }
        const auto* outerFlag = std::get_if<UndoRemovePamProviderManagedFlag>(
            &parsed[outer].undo.payload);
        if (outerFlag == nullptr) {
            continue;
        }
        const std::vector<std::string> outerAuthority =
            activePamFlagSuppressionAuthority(parsed[outer], *outerFlag);
        for (std::size_t inner = outer + 1; inner < parsed.size(); ++inner) {
            if (!parsed[inner].isActive()) {
                continue;
            }
            const auto* innerFlag =
                std::get_if<UndoRemovePamProviderManagedFlag>(
                    &parsed[inner].undo.payload);
            if (innerFlag == nullptr ||
                innerFlag->configPath != outerFlag->configPath) {
                continue;
            }
            const std::vector<std::string> innerAuthority =
                activePamFlagSuppressionAuthority(parsed[inner], *innerFlag);
            for (const std::string& id : outerAuthority) {
                if (std::find(innerAuthority.begin(), innerAuthority.end(),
                              id) != innerAuthority.end()) {
                    return failLoad(
                        "Mutation journal содержит suppression id '" + id +
                            "' в нескольких активных PAM flag records для " +
                            outerFlag->configPath +
                            ": неоднозначная rollback authority (fail "
                            "closed)",
                        error);
                }
            }
        }
    }

    // The parsed document is proven, but readable != durable: the visible
    // file may still be the result of a rename whose parent directory fsync
    // never completed. Re-prove the exact captured snapshot against the
    // current path (an external writer may have replaced the journal since
    // the capture) and run the durability barrier BEFORE publishing anything.
    std::string durabilityError;
    if (!AtomicFileWriter::ensureTargetDurableIfCurrentState(
            path_.string(), snapshot, &durabilityError)) {
        // Fail closed: without the proven durability of the exact parsed
        // snapshot the journal must not become operational. The previous
        // in-memory state is left untouched; health is poisoned so that no
        // operational decision (reads included) may use ambiguous provenance
        // until a successful load() or a daemon restart.
        return failLoad("Durability mutation journal не подтверждена для "
                        "прочитанного snapshot (fail closed): " +
                            durabilityError,
                        error);
    }

    records_ = std::move(parsed);
    nextId_ = parsedNextId;
    loaded_ = true;
    // The exact captured document was parsed, re-proved against the path and
    // durably confirmed: an ambiguous earlier persistence is now resolved
    // against actual persistent state, so the journal is usable again.
    health_ = JournalHealth::Healthy;
    error.clear();
    return true;
}

MutationRecord* MutationJournal::find(MutationId id) {
    for (MutationRecord& record : records_) {
        if (record.id == id) {
            return &record;
        }
    }
    return nullptr;
}

MutationJournal::PersistOutcome MutationJournal::persist(std::string& error) {
    json document;
    document["schema_version"] = kSchemaVersion;
    document["next_id"] = nextId_;
    json records = json::array();
    for (const MutationRecord& record : records_) {
        records.push_back(serializeRecord(record));
    }
    document["records"] = std::move(records);

    AtomicWriteOptions options;
    options.createIfMissing = true;
    options.rejectSymlink = true;
    options.fileMode = 0600;
    AtomicWriteResult result;
    if (!AtomicFileWriter::writeWithResult(path_.string(), document.dump(2) + "\n",
                                           options, &error, &result)) {
        if (!result.installed) {
            // The new document was never published by rename: the persistent
            // journal definitely still holds the previous content, so the
            // caller may safely restore the in-memory state.
            return PersistOutcome::NotInstalled;
        }
        // Post-rename durability failure: the journal target already carries
        // the new document, but the rename is not crash-durable yet. Finish
        // the durability transparently instead of reporting an ambiguous
        // failure (memory=old / disk=new must never continue as normal).
        std::string barrierError;
        if (result.installedTargetState.has_value() &&
            AtomicFileWriter::ensureTargetDurableIfCurrentState(
                path_.string(), *result.installedTargetState, &barrierError)) {
            return PersistOutcome::Persisted;
        }
        error = "Mutation journal записан (rename), но durability "
                "подтвердить не удалось; journal переведён в состояние "
                "Indeterminate (fail closed до успешного reload): " +
                barrierError;
        return PersistOutcome::Indeterminate;
    }
    return PersistOutcome::Persisted;
}

bool MutationJournal::prepareMutation(MutationRecord record,
                                      MutationId& id,
                                      std::string& error) {
    if (!validateSudoGlobalRecord(record, error)||!validSshRecord(record,error)) return false;
    if(const auto* ssh=std::get_if<UndoRemoveSshManagedPolicy>(&record.undo.payload);ssh&&ssh->transition) {
        error="SSH transitions require the typed journal API";return false;
    }
    if (!loaded_) {
        error = "Mutation journal не загружен";
        return false;
    }
    if (health_ == JournalHealth::Indeterminate) {
        error = "Mutation journal в состоянии Indeterminate: результат "
                "последней persist-операции не был надёжно завершён; "
                "требуется успешный reload journal";
        return false;
    }
    if (record.policy.moduleName.empty() || record.policy.policyName.empty()) {
        error = "Mutation record требует module и policy";
        return false;
    }
    if (record.resource.empty()) {
        error = "Mutation record требует resource";
        return false;
    }
    if ((record.undo.backend == MutationBackend::Scope ||
         std::holds_alternative<ScopeTransitionCheckpoint>(record.undo.payload)) &&
        !validScopeRecord(record, error)) return false;
    if ((record.undo.backend == MutationBackend::Desktop ||
         (std::holds_alternative<UndoRestoreDesktopScalar>(record.undo.payload) ||
          std::holds_alternative<UndoOwnDesktopArtifact>(record.undo.payload))) &&
        !validDesktopRecord(record, error)) return false;
    if (record.undo.backend == MutationBackend::Desktop &&
        std::holds_alternative<UndoRestoreDesktopScalar>(record.undo.payload)) {
        const auto& incoming = std::get<UndoRestoreDesktopScalar>(record.undo.payload);
        const MutationRecord* predecessor = nullptr;
        for (const auto& existing : records_) {
            if (existing.isActive() && existing.policy == record.policy &&
                existing.undo.backend == record.undo.backend && existing.resource == record.resource)
                predecessor = &existing;
        }
        if (!predecessor) {
            if (incoming.hadApplied || incoming.previousAppliedLine || incoming.phase != "ensure") {
                error = "fresh desktop scalar must not claim previous ownership or release authority";
                return false;
            }
        } else {
            const auto& previous = std::get<UndoRestoreDesktopScalar>(predecessor->undo.payload);
            if (incoming.originalLine != previous.originalLine ||
                incoming.originalLockLine != previous.originalLockLine ||
                (previous.hadApplied && !incoming.hadApplied) ||
                (previous.phase == "release" && incoming.phase != "release") ||
                (incoming.previousAppliedLine &&
                 incoming.previousAppliedLine != previous.previousAppliedLine &&
                 *incoming.previousAppliedLine != previous.appliedLine)) {
                error = "desktop scalar refresh would lose or invent ownership provenance";
                return false;
            }
        }
    }
    if (const auto* incoming = std::get_if<UndoOwnDesktopArtifact>(&record.undo.payload)) {
        const UndoOwnDesktopArtifact* previous = nullptr;
        for (const auto& existing : records_)
            if (existing.isActive() && existing.resource == record.resource && existing.undo.backend == MutationBackend::Desktop)
                previous = std::get_if<UndoOwnDesktopArtifact>(&existing.undo.payload);
        if ((!previous && (incoming->hadApplied || incoming->phase != "ensure")) ||
            (previous && ((previous->hadApplied && (!incoming->hadApplied || incoming->device != previous->device || incoming->inode != previous->inode)) ||
                          (previous->phase == "release" && incoming->phase != "release")))) {
            error = "GNOME artifact refresh loses or invents ownership"; return false;
        }
    }
    if ((record.undo.backend == MutationBackend::DisplayManager || std::holds_alternative<UndoRemoveDisplayManagerBlock>(record.undo.payload)) &&
        !validDmRecord(record, error)) return false;
    if (const auto* incoming = std::get_if<UndoRemoveDisplayManagerBlock>(&record.undo.payload)) {
        const UndoRemoveDisplayManagerBlock* previous = nullptr;
        for (const auto& existing : records_)
            if (existing.isActive() && existing.resource == record.resource && existing.undo.backend == MutationBackend::DisplayManager)
                previous = std::get_if<UndoRemoveDisplayManagerBlock>(&existing.undo.payload);
        if ((!previous && (incoming->hadApplied || incoming->phase != "ensure" || incoming->creationDevice || incoming->creationInode)) ||
            (previous && (incoming->manager != previous->manager || incoming->route != previous->route ||
                incoming->seats != previous->seats || incoming->createdFile != previous->createdFile ||
                incoming->separator != previous->separator || (previous->hadApplied && (!incoming->hadApplied ||
                    incoming->creationDevice != previous->creationDevice || incoming->creationInode != previous->creationInode)) ||
                (previous->phase == "release" && incoming->phase != "release")))) {
            error = "DM refresh loses or invents ownership"; return false;
        }
    }
    // Record consistency before ANY refresh/insert: for GRUB the logical
    // identity carries the managed key, so the payload MUST agree with it
    // (record.resource == undo.key). The payload itself must satisfy the
    // SAME rules the loader enforces (see validateGrubUndoPayload): the
    // writer must never persist a record the loader would reject. An
    // empty appliedValue is valid (applied policy value "" is legitimate).
    // A malformed record is never silently refreshed or persisted — fail
    // closed. Other backends keep their existing semantics unchanged.
    if (record.undo.backend == MutationBackend::Grub) {
        const auto* grub =
            std::get_if<UndoRemoveGrubManagedSetting>(&record.undo.payload);
        if (grub == nullptr || grub->key != record.resource) {
            error = "GRUB mutation record требует undo key == resource ('" +
                record.resource + "'): "
                "payload не согласован с identity (fail closed)";
            return false;
        }
        if (!validateGrubUndoPayload(*grub, error)) {
            return false;
        }
    }
    if (record.undo.backend == MutationBackend::Sssd) {
        const auto* sssd =
            std::get_if<UndoRemoveSssdManagedSetting>(&record.undo.payload);
        const std::string expectedResource =
            sssd == nullptr ? std::string() : sssd->section + "/" + sssd->option;
        if (sssd == nullptr || expectedResource != record.resource) {
            error = "SSSD mutation record требует resource "
                    "'<section>/<option>', согласованный с undo payload ('" +
                record.resource + "'): payload не согласован с identity "
                "(fail closed)";
            return false;
        }
        if (!validateSssdUndoPayload(*sssd, error)) {
            return false;
        }
    }
    if (record.undo.backend == MutationBackend::Kerberos) {
        const auto* kerberos =
            std::get_if<UndoRestoreKerberosScalar>(&record.undo.payload);
        const std::string expectedResource =
            kerberos == nullptr
                ? std::string()
                : kerberos->section + "/" + kerberos->relation;
        if (kerberos == nullptr || expectedResource != record.resource) {
            error = "Kerberos mutation record требует resource "
                    "'<section>/<relation>', согласованный с undo payload ('" +
                record.resource + "'): payload не согласован с identity "
                "(fail closed)";
            return false;
        }
        if (!validateKerberosUndoPayload(*kerberos, error)) {
            return false;
        }
    }
    if (record.undo.backend == MutationBackend::Pam) {
        if (const auto* pamEntry = std::get_if<
                UndoRemovePamProviderManagedEntry>(&record.undo.payload)) {
            // The logical identity carries the managed-entry ownership
            // tuple: resource == provider config path, policy name ==
            // payload policy identity. The mutation id of this record IS
            // the physical mutation id written into the managed entry.
            const std::string expectedModule = "IDENTITY_ACCESS";
            if (record.policy.moduleName != expectedModule ||
                record.policy.submoduleName != "PAM" ||
                record.policy.policyName != pamEntry->policyName ||
                record.resource != pamEntry->configPath) {
                error = "PAM provider managed-entry mutation record identity "
                        "does not match undo payload (fail closed)";
                return false;
            }
            if (!validatePamProviderManagedEntryUndoPayload(*pamEntry,
                                                            error)) {
                return false;
            }
        } else if (const auto* pamFlag = std::get_if<
                       UndoRemovePamProviderManagedFlag>(
                       &record.undo.payload)) {
            // Step 7E: the set-only flag record carries the (policy,
            // provider, config path) ownership identity exactly like the
            // managed-entry record; the payload carries ONLY provenance
            // (bool states, placement, canonical suppression id permission
            // sets) — never foreign lines or historical content.
            if (record.policy.moduleName != "IDENTITY_ACCESS" ||
                record.policy.submoduleName != "PAM" ||
                record.policy.policyName != pamFlag->policyName ||
                record.resource != pamFlag->configPath) {
                error = "PAM provider managed-flag mutation record identity "
                        "does not match undo payload (fail closed)";
                return false;
            }
            if (!validatePamProviderManagedFlagUndoPayload(*pamFlag,
                                                           error)) {
                return false;
            }
        } else if (const auto* pamContainer = std::get_if<
                       UndoOwnPamProviderContainer>(&record.undo.payload)) {
            // Container provenance lives under the dedicated PAM_CONTAINER
            // submodule: one logical identity per (provider, config path),
            // structurally disjoint from entry and capability records.
            if (record.policy.moduleName != "IDENTITY_ACCESS" ||
                record.policy.submoduleName != "PAM_CONTAINER" ||
                record.policy.policyName != pamContainer->providerName ||
                record.resource != pamContainer->configPath) {
                error = "PAM provider container-ownership mutation record "
                        "identity does not match undo payload (fail closed)";
                return false;
            }
            if (!validatePamProviderContainerUndoPayload(*pamContainer,
                                                         error)) {
                return false;
            }
        } else {
            const auto* pam =
                std::get_if<UndoDisablePamCapability>(&record.undo.payload);
            if (pam == nullptr || record.policy.moduleName != "IDENTITY_ACCESS" ||
                record.policy.submoduleName != "PAM" ||
                record.policy.policyName != pam->capability ||
                record.resource != "capability/" + pam->capability) {
                error = "PAM mutation record identity does not match undo";
                return false;
            }
            if (!validatePamUndoPayload(*pam, error)) return false;
        }
    }
    if (record.undo.backend == MutationBackend::Sudo) {
        if (!validateSudoGlobalRecord(record, error)||!validSshRecord(record,error)) return false;
        if (const auto* auth = std::get_if<UndoReleaseSudoAuthentication>(&record.undo.payload)) {
            const bool existing = std::any_of(records_.begin(), records_.end(), [&](const auto& current) {
                return current.isActive() && current.policy == record.policy && current.resource == record.resource;
            });
            if (!existing && !auth->previousProofs.empty()) { error = "Fresh authentication record claims previous ownership"; return false; }
        }

        const auto* sudoPayload = std::get_if<UndoReleaseSudoScopedDefaults>(
            &record.undo.payload);
        if (sudoPayload != nullptr) {
            if (record.policy.moduleName != fic::sudoers::kSudoModuleName ||
                record.policy.submoduleName !=
                    fic::sudoers::kSudoSubmoduleName ||
                record.policy.policyName != sudoPayload->policyName ||
                record.resource !=
                    fic::sudoers::kScopedDefaultsResource) {
                error = "SUDO scoped-defaults mutation record identity does "
                        "not match undo payload (fail closed)";
                return false;
            }
            if (!validateSudoScopedDefaultsUndoPayload(*sudoPayload, error)) {
                return false;
            }
            const bool refreshesActiveSudoRecord = std::any_of(
                records_.begin(), records_.end(),
                [&](const MutationRecord& current) {
                    return current.isActive() &&
                        current.policy == record.policy &&
                        current.undo.backend == record.undo.backend &&
                        current.resource == record.resource;
                });
            if (!refreshesActiveSudoRecord &&
                !sudoPayload->previousProofs.empty()) {
                error = "fresh SUDO scoped-defaults mutation must not claim "
                        "previous wrapper proofs (fail closed)";
                return false;
            }
        }
    }
    if (record.undo.backend == MutationBackend::UserCreation) {
        const auto* payload = std::get_if<UndoRemoveUserCreationManagedPolicy>(
            &record.undo.payload);
        if (payload == nullptr ||
            record.policy.moduleName != "IDENTITY_ACCESS" ||
            record.policy.submoduleName != "USER_CREATION" ||
            record.policy.policyName != payload->policyName ||
            record.resource != payload->configPath) {
            error = "USER_CREATION mutation record identity/payload is invalid";
            return false;
        }
        if (!validateUserCreationUndoPayload(*payload, error)) return false;
        const bool refreshesActiveRecord = std::any_of(
            records_.begin(), records_.end(), [&](const MutationRecord& current) {
                return current.isActive() && current.policy == record.policy &&
                    current.undo.backend == record.undo.backend &&
                    current.resource == record.resource;
            });
        if (!refreshesActiveRecord &&
            !payload->previousAppliedAssignments.empty()) {
            error = "fresh USER_CREATION mutation must not claim previous "
                    "applied assignments (fail closed)";
            return false;
        }
    }
    if (record.undo.backend == MutationBackend::IdentityLoginDefs) {
        const auto* payload = std::get_if<
            UndoRemoveIdentityLoginDefsManagedPolicy>(&record.undo.payload);
        const auto* payloadSpec = payload == nullptr
            ? nullptr
            : fic::identity::login_defs::findSharedLoginDefsPolicySpec(
                  payload->policyName);
        if (payload == nullptr || payloadSpec == nullptr ||
            record.policy.moduleName != "IDENTITY_ACCESS" ||
            record.policy.submoduleName != payloadSpec->submodule ||
            record.policy.policyName != payload->policyName ||
            record.resource != payload->configPath) {
            error = "identity_login_defs mutation record identity/payload "
                    "is invalid";
            return false;
        }
        if (!validateIdentityLoginDefsUndoPayload(*payload, error)) {
            return false;
        }
        const bool refreshesActiveRecord = std::any_of(
            records_.begin(), records_.end(), [&](const MutationRecord& current) {
                return current.isActive() && current.policy == record.policy &&
                    current.undo.backend == record.undo.backend &&
                    current.resource == record.resource;
            });
        if (!refreshesActiveRecord && !payload->previousAppliedLine.empty()) {
            error = "fresh identity_login_defs mutation must not claim a "
                    "previous applied line (fail closed)";
            return false;
        }
    }

    // PAM provider lifecycle guards: provenance must never be silently
    // created, lost or duplicated by a prepare/refresh.
    if (record.undo.backend == MutationBackend::Pam) {
        bool refreshesActiveRecord = false;
        for (const MutationRecord& existing : records_) {
            if (existing.isActive() &&
                existing.policy == record.policy &&
                existing.undo.backend == record.undo.backend &&
                existing.resource == record.resource) {
                refreshesActiveRecord = true;
            }
        }
        if (const auto* pamEntry = std::get_if<
                UndoRemovePamProviderManagedEntry>(&record.undo.payload)) {
            if (!refreshesActiveRecord &&
                !pamEntry->previousAppliedBody.empty()) {
                // A previous applied body is durable provenance of an
                // EXISTING FIC-owned entry: a fresh record without an
                // active predecessor cannot legally claim it.
                error = "remove_pam_provider_managed_entry fresh record "
                        "must not claim a previous applied body (fail "
                        "closed): refresh the active record instead";
                return false;
            }
        } else if (const auto* pamFlag = std::get_if<
                       UndoRemovePamProviderManagedFlag>(
                       &record.undo.payload)) {
            // Step 7E write/read parity for the cross-record suppression-id
            // authority invariant: the writer refuses exactly those
            // cross-record authority collisions that the loader would
            // reject for the resulting active statuses. Existing records
            // are evaluated by their ACTUAL status through the shared
            // activePamFlagSuppressionAuthority() helper (the single
            // authority model of the load path); the incoming transition
            // is evaluated as the authority of its FUTURE Prepared state
            // (target ∪ previous), because this prepare persists it as
            // Prepared. The record being refreshed (same logical identity)
            // is REPLACED by this prepare, so its old authority is
            // released, not retained.
            const std::vector<std::string> incomingAuthority =
                preparedPamFlagSuppressionAuthority(*pamFlag);
            for (const MutationRecord& other : records_) {
                if (!other.isActive() ||
                    other.undo.backend != MutationBackend::Pam ||
                    other.policy == record.policy ||
                    other.resource != record.resource) {
                    continue;
                }
                const auto* otherFlag =
                    std::get_if<UndoRemovePamProviderManagedFlag>(
                        &other.undo.payload);
                if (otherFlag == nullptr ||
                    otherFlag->configPath != pamFlag->configPath) {
                    continue;
                }
                const std::vector<std::string> otherAuthority =
                    activePamFlagSuppressionAuthority(other, *otherFlag);
                for (const std::string& id : incomingAuthority) {
                    if (std::find(otherAuthority.begin(),
                                  otherAuthority.end(),
                                  id) != otherAuthority.end()) {
                        error = "suppression id '" + id +
                            "' of the prepared PAM provider managed-flag "
                            "record is already provable rollback authority "
                            "of active record " +
                            std::to_string(other.id) + " for " +
                            pamFlag->configPath + " (fail closed)";
                        return false;
                    }
                }
            }
        } else if (const auto* newContainer = std::get_if<
                       UndoOwnPamProviderContainer>(&record.undo.payload)) {
            for (const MutationRecord& other : records_) {
                const auto* container =
                    std::get_if<UndoOwnPamProviderContainer>(
                        &other.undo.payload);
                if (other.isActive() && container != nullptr &&
                    container->configPath == newContainer->configPath &&
                    other.policy != record.policy) {
                    // Only one FIC-created container provenance can exist
                    // per physical file; a second provider claim is false
                    // provenance (fail closed).
                    error = "an active own_pam_provider_container record "
                            "for another provider already exists for this "
                            "config path (fail closed): '" +
                        newContainer->configPath + "'";
                    return false;
                }
            }
        }
    }

    // Idempotency: an active record for the same (policy, backend, resource)
    // is refreshed instead of duplicated (repeated apply).
    for (MutationRecord& existing : records_) {
        if (existing.isActive() &&
            existing.policy == record.policy &&
            existing.undo.backend == record.undo.backend &&
            existing.resource == record.resource) {
            if(record.undo.backend==MutationBackend::Ssh) {
                if(existing.status==MutationStatus::Prepared && serializeUndoAction(existing.undo)==serializeUndoAction(record.undo)) {
                    id=existing.id;return true;
                }
                error="active SSH ownership requires typed transition; generic reprepare refused";return false;
            }
            if (record.undo.backend == MutationBackend::UserCreation) {
                const auto* oldUserCreation = std::get_if<
                    UndoRemoveUserCreationManagedPolicy>(
                    &existing.undo.payload);
                const auto* newUserCreation = std::get_if<
                    UndoRemoveUserCreationManagedPolicy>(
                    &record.undo.payload);
                if (oldUserCreation == nullptr || newUserCreation == nullptr ||
                    oldUserCreation->policyName !=
                        newUserCreation->policyName ||
                    oldUserCreation->configKind !=
                        newUserCreation->configKind ||
                    oldUserCreation->configPath !=
                        newUserCreation->configPath) {
                    error = "USER_CREATION refresh changed ownership identity "
                            "(fail closed)";
                    return false;
                }
                if (existing.status == MutationStatus::Prepared) {
                    if (oldUserCreation->appliedAssignments !=
                            newUserCreation->appliedAssignments ||
                        oldUserCreation->previousAppliedAssignments !=
                            newUserCreation->previousAppliedAssignments) {
                        error = "USER_CREATION refresh conflicts with an "
                                "unresolved Prepared transition (fail closed)";
                        return false;
                    }
                } else if (existing.status ==
                           MutationStatus::RollbackFailed) {
                    error = "USER_CREATION RollbackFailed provenance cannot "
                            "be refreshed by ordinary apply (fail closed)";
                    return false;
                } else if (existing.status == MutationStatus::Applied &&
                           newUserCreation->previousAppliedAssignments !=
                               oldUserCreation->appliedAssignments) {
                    error = "USER_CREATION refresh does not carry the "
                            "currently owned assignments as previous state "
                            "(fail closed)";
                    return false;
                }
            }
            if (record.undo.backend ==
                MutationBackend::IdentityLoginDefs) {
                const auto* oldLoginDefs = std::get_if<
                    UndoRemoveIdentityLoginDefsManagedPolicy>(
                    &existing.undo.payload);
                const auto* newLoginDefs = std::get_if<
                    UndoRemoveIdentityLoginDefsManagedPolicy>(
                    &record.undo.payload);
                if (oldLoginDefs == nullptr || newLoginDefs == nullptr ||
                    oldLoginDefs->policyName != newLoginDefs->policyName ||
                    oldLoginDefs->configPath != newLoginDefs->configPath ||
                    oldLoginDefs->key != newLoginDefs->key) {
                    error = "identity_login_defs refresh changed ownership "
                            "identity (fail closed)";
                    return false;
                }
                if (existing.status == MutationStatus::Prepared) {
                    if (oldLoginDefs->appliedLine !=
                            newLoginDefs->appliedLine ||
                        oldLoginDefs->previousAppliedLine !=
                            newLoginDefs->previousAppliedLine) {
                        error = "identity_login_defs refresh conflicts with "
                                "an unresolved Prepared transition (fail "
                                "closed): recover or complete the existing "
                                "transaction first";
                        return false;
                    }
                } else if (existing.status ==
                           MutationStatus::RollbackFailed) {
                    error = "identity_login_defs RollbackFailed provenance "
                            "cannot be refreshed by ordinary apply (fail "
                            "closed)";
                    return false;
                } else if (existing.status == MutationStatus::Applied &&
                           newLoginDefs->previousAppliedLine !=
                               oldLoginDefs->appliedLine) {
                    error = "identity_login_defs refresh does not carry the "
                            "currently owned applied line as previous state "
                            "(fail closed)";
                    return false;
                }
            }
            // SUDO scoped-defaults refresh guards: a repeated reconciliation must GROW the
            // ownership set, never replace it. A wrapper FIC already created
            // must never lose its journal permission.
            if (record.undo.backend == MutationBackend::Sudo) {
                const auto* nextGlobal = std::get_if<UndoReleaseSudoGlobalDefault>(&record.undo.payload);
                const auto* oldGlobal = std::get_if<UndoReleaseSudoGlobalDefault>(&existing.undo.payload);
                if (nextGlobal || oldGlobal) {
                    if (!nextGlobal || !oldGlobal || nextGlobal->key != oldGlobal->key ||
                        nextGlobal->containerId != oldGlobal->containerId ||
                        nextGlobal->addedSeparator != oldGlobal->addedSeparator ||
                        nextGlobal->separatorPrefixDigest != oldGlobal->separatorPrefixDigest ||
                        (existing.status == MutationStatus::Prepared
                            ? (nextGlobal->appliedLine != oldGlobal->appliedLine ||
                               nextGlobal->previousLine != oldGlobal->previousLine)
                            : nextGlobal->previousLine != oldGlobal->appliedLine)) {
                        error = "SUDO global refresh conflicts with durable ownership";
                        return false;
                    }
                }
                const auto* nextAuth = std::get_if<UndoReleaseSudoAuthentication>(&record.undo.payload);
                const auto* oldAuth = std::get_if<UndoReleaseSudoAuthentication>(&existing.undo.payload);
                if (nextAuth || oldAuth) {
                    if (!nextAuth || !oldAuth || existing.status == MutationStatus::RollbackFailed ||
                        (existing.status == MutationStatus::Prepared
                            ? nextAuth->previousProofs != oldAuth->previousProofs || nextAuth->targetProofs != oldAuth->targetProofs
                            : nextAuth->previousProofs != oldAuth->targetProofs)) {
                        error = "Authentication refresh conflicts with durable ownership"; return false;
                    }
                }
                const auto* newSudo = std::get_if<
                    UndoReleaseSudoScopedDefaults>(&record.undo.payload);
                const auto* oldSudo = std::get_if<
                    UndoReleaseSudoScopedDefaults>(&existing.undo.payload);
                if (newSudo != nullptr || oldSudo != nullptr) {
                    if (oldSudo == nullptr || newSudo == nullptr) {
                        error = "SUDO refresh changed the undo payload type "
                                "(fail closed)";
                        return false;
                    }
                    if (existing.status == MutationStatus::Prepared) {
                        // An unresolved Prepared transition whose filesystem
                        // write may already have happened may only be
                        // re-prepared with the EXACT same transition.
                        if (!sameSudoScopedDefaultsTransition(*oldSudo,
                                                               *newSudo)) {
                            error = "SUDO scoped-defaults refresh conflicts "
                                    "with an unresolved Prepared transition "
                                    "(fail closed): recover or complete the "
                                    "existing transaction first";
                            return false;
                        }
                    } else if (existing.status ==
                               MutationStatus::RollbackFailed) {
                        error = "SUDO scoped-defaults RollbackFailed provenance "
                                "cannot be refreshed by ordinary apply (fail "
                                "closed)";
                        return false;
                    } else {
                        // Applied provenance: the new transition must carry
                        // the currently owned proofs as its previous state.
                        if (newSudo->previousProofs != oldSudo->targetProofs) {
                            error = "SUDO scoped-defaults refresh does not carry "
                                    "the currently owned wrapper proofs as its "
                                    "previous state (fail closed)";
                            return false;
                        }
                        std::set<std::string> targetIds;
                        for (const SudoScopedDefaultsWrapperProof& proof :
                             newSudo->targetProofs) {
                            targetIds.insert(proof.wrapperId);
                        }
                        for (const SudoScopedDefaultsWrapperProof& proof :
                             oldSudo->targetProofs) {
                            if (targetIds.count(proof.wrapperId) == 0) {
                                error = "SUDO scoped-defaults refresh would drop "
                                        "ownership of existing wrapper '" +
                                        proof.wrapperId + "' (fail closed)";
                                return false;
                            }
                        }
                    }
                }
            }
            // PAM provider refresh guards: deterministic transition
            // semantics, no provenance loss on an in-place refresh.
            if (record.undo.backend == MutationBackend::Pam) {
                if (const auto* newEntry = std::get_if<
                        UndoRemovePamProviderManagedEntry>(
                        &record.undo.payload)) {
                    const auto* oldEntry = std::get_if<
                        UndoRemovePamProviderManagedEntry>(
                        &existing.undo.payload);
                    if (oldEntry == nullptr ||
                        oldEntry->providerName != newEntry->providerName) {
                        error = "PAM provider managed-entry refresh changed "
                                "the undo payload identity (fail closed)";
                        return false;
                    }
                    if (existing.status == MutationStatus::Prepared) {
                        // An unresolved Prepared transition must be
                        // recovered/completed first: only the EXACT same
                        // idempotent re-prepare is allowed. Silently
                        // replacing the previous state, the target body,
                        // the placement or any identity field would lose
                        // the durable recovery provenance of a transition
                        // whose physical write may already have happened.
                        if (!samePamProviderPreparedTransition(*oldEntry,
                                                               *newEntry)) {
                            error = "PAM provider managed-entry refresh "
                                    "conflicts with an unresolved Prepared "
                                    "transition (fail closed): recover or "
                                    "complete the existing transaction first";
                            return false;
                        }
                    } else if (newEntry->previousAppliedBody !=
                               oldEntry->appliedBody) {
                        // Applied/RollbackFailed provenance: a refresh must
                        // carry the currently FIC-owned body as the previous
                        // state of the new transition.
                        error = "PAM provider managed-entry refresh does "
                                "not carry the currently owned applied body "
                                "as its previous state (fail closed)";
                        return false;
                    }
                } else if (const auto* newFlag = std::get_if<
                               UndoRemovePamProviderManagedFlag>(
                               &record.undo.payload)) {
                    // Step 7E: the same deterministic refresh semantics for
                    // the set-only flag provenance.
                    const auto* oldFlag = std::get_if<
                        UndoRemovePamProviderManagedFlag>(
                        &existing.undo.payload);
                    if (oldFlag == nullptr ||
                        oldFlag->providerName != newFlag->providerName) {
                        error = "PAM provider managed-flag refresh changed "
                                "the undo payload identity (fail closed)";
                        return false;
                    }
                    if (existing.status == MutationStatus::Prepared) {
                        // An unresolved Prepared flag transition must be
                        // recovered/completed first: only the EXACT same
                        // idempotent re-prepare is allowed (Step 7E §31 —
                        // target/previous bool states, placement and both
                        // suppression id sets must match exactly).
                        if (!samePamProviderPreparedFlagTransition(
                                *oldFlag, *newFlag)) {
                            error = "PAM provider managed-flag refresh "
                                    "conflicts with an unresolved Prepared "
                                    "transition (fail closed): recover or "
                                    "complete the existing transaction first";
                            return false;
                        }
                    } else if (newFlag->previousAppliedEnabled !=
                                   oldFlag->appliedEnabled ||
                               newFlag->previousSuppressionIds !=
                                   oldFlag->suppressionIds) {
                        // Applied/RollbackFailed provenance: a refresh must
                        // carry the currently owned flag state and the
                        // currently owned suppression id set as the previous
                        // state of the new transition.
                        error = "PAM provider managed-flag refresh does "
                                "not carry the currently owned applied "
                                "state as its previous state (fail closed)";
                        return false;
                    }
                } else if (std::get_if<UndoOwnPamProviderContainer>(
                               &record.undo.payload) != nullptr) {
                    if (existing.status == MutationStatus::Applied) {
                        // Container provenance is already durably Applied
                        // (the container physically exists): re-Preparing
                        // it would falsify the lifecycle.
                        error = "own_pam_provider_container provenance is "
                                "already Applied and must not be re-Prepared "
                                "(fail closed)";
                        return false;
                    }
                }
            }
            const MutationRecord previous = existing;
            existing.undo = record.undo;
            existing.status = MutationStatus::Prepared;
            existing.error.clear();
            existing.updatedAtEpoch = currentEpochSeconds();
            id = existing.id;
            const PersistOutcome outcome = persist(error);
            if (outcome == PersistOutcome::Persisted) {
                return true;
            }
            if (outcome == PersistOutcome::NotInstalled) {
                // Pre-install failure: the persistent journal definitely
                // still holds the previous document, so the in-memory state
                // is safely restored (strong in-memory consistency holds).
                existing = previous;
                return false;
            }
            // Indeterminate: the new document already occupies the journal
            // target. Restoring the previous in-memory state would contradict
            // the installed document; the new state is kept and the journal
            // becomes fail closed until a successful load().
            health_ = JournalHealth::Indeterminate;
            return false;
        }
    }

    record.id = nextId_;
    record.status = MutationStatus::Prepared;
    record.error.clear();
    const std::int64_t now = currentEpochSeconds();
    record.createdAtEpoch = now;
    record.updatedAtEpoch = now;
    id = record.id;
    nextId_ += 1;
    records_.push_back(std::move(record));
    const PersistOutcome outcome = persist(error);
    if (outcome == PersistOutcome::Persisted) {
        return true;
    }
    if (outcome == PersistOutcome::NotInstalled) {
        // Do not keep an unpersisted in-memory record: the caller must see the
        // failure and refuse the system mutation (fail closed). The persistent
        // journal definitely still holds the previous document.
        records_.pop_back();
        nextId_ -= 1;
        return false;
    }
    // Indeterminate: keep the new record (it matches the installed document)
    // and poison the journal.
    health_ = JournalHealth::Indeterminate;
    return false;
}

bool MutationJournal::normalizeUserCreationPreparedToProvenState(
    MutationId id,
    const std::vector<UserCreationManagedAssignment>& provenAssignments,
    std::string& error) {
    if (!loaded_) {
        error = "Mutation journal не загружен";
        return false;
    }
    if (health_ == JournalHealth::Indeterminate) {
        error = "Mutation journal в состоянии Indeterminate: normalization "
                "запрещена до успешного reload";
        return false;
    }
    MutationRecord* record = find(id);
    if (record == nullptr || record->status != MutationStatus::Prepared ||
        record->undo.backend != MutationBackend::UserCreation) {
        error = "USER_CREATION rollback normalization requires its existing "
                "Prepared record";
        return false;
    }
    auto* payload = std::get_if<UndoRemoveUserCreationManagedPolicy>(
        &record->undo.payload);
    if (payload == nullptr || payload->previousAppliedAssignments.empty() ||
        payload->previousAppliedAssignments != provenAssignments) {
        error = "USER_CREATION rollback normalization does not match the "
                "durable previous-side provenance";
        return false;
    }
    const MutationRecord previous = *record;
    payload->appliedAssignments = provenAssignments;
    payload->previousAppliedAssignments.clear();
    record->error.clear();
    record->updatedAtEpoch = currentEpochSeconds();
    if (!validateUserCreationUndoPayload(*payload, error)) {
        *record = previous;
        return false;
    }
    const PersistOutcome outcome = persist(error);
    if (outcome == PersistOutcome::Persisted) return true;
    if (outcome == PersistOutcome::NotInstalled) {
        *record = previous;
        return false;
    }
    health_ = JournalHealth::Indeterminate;
    return false;
}

bool MutationJournal::normalizeIdentityLoginDefsPreparedToProvenState(
    MutationId id,
    const std::string& provenAppliedLine,
    std::string& error) {
    if (!loaded_) {
        error = "Mutation journal не загружен";
        return false;
    }
    if (health_ == JournalHealth::Indeterminate) {
        error = "Mutation journal в состоянии Indeterminate: normalization "
                "запрещена до успешного reload";
        return false;
    }
    MutationRecord* record = find(id);
    if (record == nullptr || record->status != MutationStatus::Prepared ||
        record->undo.backend != MutationBackend::IdentityLoginDefs) {
        error = "identity_login_defs rollback normalization requires its "
                "existing Prepared record";
        return false;
    }
    auto* payload = std::get_if<UndoRemoveIdentityLoginDefsManagedPolicy>(
        &record->undo.payload);
    if (payload == nullptr || payload->previousAppliedLine.empty() ||
        payload->previousAppliedLine != provenAppliedLine) {
        error = "identity_login_defs rollback normalization does not match "
                "the durable previous-side provenance";
        return false;
    }
    const MutationRecord previous = *record;
    payload->appliedLine = provenAppliedLine;
    payload->previousAppliedLine.clear();
    record->error.clear();
    record->updatedAtEpoch = currentEpochSeconds();
    if (!validateIdentityLoginDefsUndoPayload(*payload, error)) {
        *record = previous;
        return false;
    }
    const PersistOutcome outcome = persist(error);
    if (outcome == PersistOutcome::Persisted) return true;
    if (outcome == PersistOutcome::NotInstalled) {
        *record = previous;
        return false;
    }
    health_ = JournalHealth::Indeterminate;
    return false;
}

bool MutationJournal::normalizeSudoScopedDefaultsPreparedToPrevious(
    MutationId id,
    const std::vector<SudoScopedDefaultsWrapperProof>& provenPrevious,
    std::string& error) {
    if (!loaded_) {
        error = "Mutation journal не загружен";
        return false;
    }
    if (health_ == JournalHealth::Indeterminate) {
        error = "Mutation journal в состоянии Indeterminate: normalization "
                "запрещена до успешного reload";
        return false;
    }
    MutationRecord* record = find(id);
    if (record == nullptr || record->status != MutationStatus::Prepared ||
        record->undo.backend != MutationBackend::Sudo ||
        record->resource != fic::sudoers::kScopedDefaultsResource) {
        error = "SUDO refresh normalization требует существующую Prepared-запись "
                "для канонического scoped-defaults ресурса";
        return false;
    }
    auto* payload = std::get_if<UndoReleaseSudoScopedDefaults>(
        &record->undo.payload);
    // This API exists ONLY for a refresh: with an empty previous side there is
    // no pre-existing ownership to preserve and a plain discard is correct.
    if (payload == nullptr || payload->previousProofs.empty() ||
        payload->previousProofs != provenPrevious) {
        error = "SUDO refresh normalization does not match the proven "
                "previous-side provenance";
        return false;
    }
    if (record->policy.moduleName != fic::sudoers::kSudoModuleName ||
        record->policy.submoduleName != fic::sudoers::kSudoSubmoduleName ||
        record->policy.policyName != payload->policyName ||
        payload->policyName != fic::sudoers::kScopedDefaultsPolicyName) {
        error = "SUDO refresh normalization: несовпадение policy identity "
                "(fail closed)";
        return false;
    }
    const MutationRecord previous = *record;
    // Canonical post-state: the surviving ownership IS the target again.
    payload->targetProofs = provenPrevious;
    payload->previousProofs.clear();
    record->status = MutationStatus::Applied;
    record->error.clear();
    record->updatedAtEpoch = currentEpochSeconds();
    if (!validateSudoScopedDefaultsUndoPayload(*payload, error)) {
        *record = previous;
        return false;
    }
    const PersistOutcome outcome = persist(error);
    if (outcome == PersistOutcome::Persisted) {
        return true;
    }
    if (outcome == PersistOutcome::NotInstalled) {
        *record = previous;
        return false;
    }
    // Indeterminate: keep the installed logical state and poison the journal,
    // exactly like the other normalization APIs.
    health_ = JournalHealth::Indeterminate;
    return false;
}

bool MutationJournal::normalizeSudoAuthenticationPreparedToPrevious(
    MutationId id,
    const std::vector<fic::sudoers::AuthenticationProof>& provenPrevious,
    std::string& error) {
    if (!loaded_) {
        error = "Mutation journal не загружен";
        return false;
    }
    if (health_ == JournalHealth::Indeterminate) {
        error = "Mutation journal в состоянии Indeterminate: normalization "
                "запрещена до успешного reload";
        return false;
    }
    MutationRecord* record = find(id);
    if (record == nullptr || record->status != MutationStatus::Prepared ||
        record->undo.backend != MutationBackend::Sudo ||
        record->resource != fic::sudoers::kAuthenticationResource) {
        error = "SUDO refresh normalization требует существующую Prepared-запись "
                "для канонического authentication ресурса";
        return false;
    }
    auto* payload = std::get_if<UndoReleaseSudoAuthentication>(
        &record->undo.payload);
    // This API exists ONLY for a refresh: with an empty previous side there is
    // no pre-existing ownership to preserve and a plain discard is correct.
    if (payload == nullptr || payload->previousProofs.empty() ||
        payload->previousProofs != provenPrevious) {
        error = "SUDO refresh normalization does not match the proven "
                "previous-side provenance";
        return false;
    }
    if (record->policy.moduleName != fic::sudoers::kSudoModuleName ||
        record->policy.submoduleName != fic::sudoers::kSudoSubmoduleName ||
        record->policy.policyName != fic::sudoers::kAuthenticationPolicy) {
        error = "SUDO refresh normalization: несовпадение policy identity "
                "(fail closed)";
        return false;
    }
    const MutationRecord previous = *record;
    // Canonical post-state: the surviving ownership IS the target again.
    payload->targetProofs = provenPrevious;
    payload->previousProofs.clear();
    record->status = MutationStatus::Applied;
    record->error.clear();
    record->updatedAtEpoch = currentEpochSeconds();
    if (!validateSudoAuthenticationPayload(*payload, error)) {
        *record = previous;
        return false;
    }
    const PersistOutcome outcome = persist(error);
    if (outcome == PersistOutcome::Persisted) {
        return true;
    }
    if (outcome == PersistOutcome::NotInstalled) {
        *record = previous;
        return false;
    }
    // Indeterminate: keep the installed logical state and poison the journal,
    // exactly like the other normalization APIs.
    health_ = JournalHealth::Indeterminate;
    return false;
}

bool MutationJournal::persistSshChange(const MutationRecord& previous,std::string& error) {
    auto* record=find(previous.id);
    if(!record||!validSshRecord(*record,error)) {
        if(record)*record=previous;
        return false;
    }
    record->updatedAtEpoch=currentEpochSeconds();
    const auto outcome=persist(error);
    if(outcome==PersistOutcome::Persisted)return true;
    if(outcome==PersistOutcome::NotInstalled)*record=previous;
    else health_=JournalHealth::Indeterminate;
    return false;
}
bool MutationJournal::beginSshRefresh(MutationId id,const UndoRemoveSshManagedPolicy& target,
    const std::string& before,const std::string& after,std::string& error) {
    if(!usable()||!lifecycleInitialized_){error="SSH transition requires healthy initialized journal/witness";return false;}
    auto* record=find(id);
    auto* old=record?std::get_if<UndoRemoveSshManagedPolicy>(&record->undo.payload):nullptr;
    if(!old||record->status!=MutationStatus::Applied||sshTransitionPending(*old)||
       target.policyName!=old->policyName||target.directive!=old->directive||target.transition||
       old->operationSequence==std::numeric_limits<std::uint64_t>::max()) {
        error="SSH refresh requires one proven Applied predecessor";return false;
    }
    const auto split=record->resource.rfind(':');
    const auto prefix=record->resource.substr(0,split+1);
    for(const auto& other:records_) {
        const auto* ssh=std::get_if<UndoRemoveSshManagedPolicy>(&other.undo.payload);
        if(ssh&&other.resource.rfind(prefix,0)==0&&
           (other.status==MutationStatus::Prepared||sshTransitionPending(*ssh))) {
            error="SSH recovery required: unresolved shared-resource transition";return false;
        }
    }
    const MutationRecord previous=*record;
    SshOwnershipTransition t;t.sequence=old->operationSequence+1;
    t.previous=sshOwnedProjection(*old);t.target=sshOwnedProjection(target);
    t.beforeSha256=before;t.targetSha256=after;
    old->operationSequence=t.sequence;old->transition=std::move(t);
    record->status=MutationStatus::Prepared;record->error.clear();
    return persistSshChange(previous,error);
}
bool MutationJournal::beginSshRelease(MutationId id,const std::string& before,const std::string& target,
    bool fileReplacement,std::string& error) {
    if(!usable()||!lifecycleInitialized_){error="SSH release requires healthy initialized journal/witness";return false;}
    auto* record=find(id);auto* old=record?std::get_if<UndoRemoveSshManagedPolicy>(&record->undo.payload):nullptr;
    if(!old||(record->status!=MutationStatus::Applied&&record->status!=MutationStatus::RollbackFailed)||sshTransitionPending(*old)||
       old->operationSequence==std::numeric_limits<std::uint64_t>::max()) {
        error="SSH release requires proven previous ownership";return false;
    }
    const auto prefix=record->resource.substr(0,record->resource.rfind(':')+1);
    for(const auto& other:records_)if(const auto* p=std::get_if<UndoRemoveSshManagedPolicy>(&other.undo.payload);
        p&&other.resource.rfind(prefix,0)==0&&(other.status==MutationStatus::Prepared||sshTransitionPending(*p))) {
        error="SSH recovery required: unresolved shared-resource transition";return false;
    }
    const MutationRecord previous=*record;
    SshOwnershipTransition t;t.version=2;t.intent=SshTransitionIntent::Release;t.sequence=old->operationSequence+1;
    t.previous=sshOwnedProjection(*old);t.beforeSha256=before;t.targetSha256=target;t.fileReplacement=fileReplacement;
    t.predecessorStatus=record->status;t.predecessorError=record->error;
    old->operationSequence=t.sequence;old->transition=std::move(t);record->status=MutationStatus::Prepared;record->error.clear();
    return persistSshChange(previous,error);
}
bool MutationJournal::finishSshReleaseVerification(MutationId id,std::string& error) {
    if(!usable()||!lifecycleInitialized_){error="SSH release requires healthy journal";return false;}
    auto* record=find(id);auto* p=record?std::get_if<UndoRemoveSshManagedPolicy>(&record->undo.payload):nullptr;
    if(!p||!p->transition||p->transition->intent!=SshTransitionIntent::Release||record->status!=MutationStatus::Prepared||
       (p->transition->phase!=SshTransitionPhase::RuntimeVerified&&p->transition->phase!=SshTransitionPhase::OfflineVerified)||!record->error.empty()) {
        error="SSH release verification incomplete; intent retained";return false;
    }
    const MutationRecord previous=*record;p->transition->phase=SshTransitionPhase::ReleasedAwaitingDisable;
    return persistSshChange(previous,error);
}
bool MutationJournal::commitSshRelease(MutationId id,std::string& error) {
    if(!usable()||!lifecycleInitialized_){error="SSH release acknowledgement requires healthy journal";return false;}
    auto* record=find(id);auto* p=record?std::get_if<UndoRemoveSshManagedPolicy>(&record->undo.payload):nullptr;
    if(!p||!sshReleaseAwaitingDisable(*p)||record->status!=MutationStatus::Prepared||!record->error.empty()) {
        error="SSH release cannot finalize before verification and durable policy/lifecycle acknowledgement";return false;
    }
    const MutationRecord previous=*record;p->transition->phase=SshTransitionPhase::Completed;record->status=MutationStatus::RolledBack;
    return persistSshChange(previous,error);
}
bool MutationJournal::noteSshPublication(MutationId id,const AtomicTargetState& installed,bool durable,std::string& error) {
    if(!usable()||!lifecycleInitialized_){error="SSH publication facts require healthy journal";return false;}
    auto* record=find(id);auto* p=record?std::get_if<UndoRemoveSshManagedPolicy>(&record->undo.payload):nullptr;
    if(!p||!p->transition||record->status!=MutationStatus::Prepared||
       static_cast<int>(p->transition->phase)>static_cast<int>(SshTransitionPhase::DurablePublished)) {
        error="SSH publication checkpoint has no Prepared transition";return false;
    }
    const MutationRecord previous=*record;
    SshPublicationProof proof{static_cast<std::uint64_t>(installed.identity.device),static_cast<std::uint64_t>(installed.identity.inode),
        static_cast<std::uint32_t>(installed.mode&07777),installed.owner,installed.group,
        fic::core::ContentDigest::sha256Hex(installed.content),durable};
    if(p->transition->publication) {
        const auto& old=*p->transition->publication;
        if(old.device!=proof.device||old.inode!=proof.inode||old.sha256!=proof.sha256||
           old.mode!=proof.mode||old.owner!=proof.owner||old.group!=proof.group|| (old.durable&&!durable)) {
            error="SSH publication proof changed during transition";return false;
        }
    }
    p->transition->publication=std::move(proof);
    p->transition->phase=durable?SshTransitionPhase::DurablePublished:SshTransitionPhase::Published;
    return persistSshChange(previous,error);
}
bool MutationJournal::noteSshRuntime(MutationId id,bool verified,
    const std::map<std::string,std::string>& facts,std::string& error) {
    if(!usable()||!lifecycleInitialized_){error="SSH activation facts require healthy journal";return false;}
    auto* record=find(id);auto* p=record?std::get_if<UndoRemoveSshManagedPolicy>(&record->undo.payload):nullptr;
    if(!p||!p->transition||record->status!=MutationStatus::Prepared||(p->transition->phase!=SshTransitionPhase::DurablePublished&&!sshReleaseAwaitingDisable(*p))) {
        error="SSH runtime checkpoint requires durable publication";return false;
    }
    const MutationRecord previous=*record;
    const bool awaiting=sshReleaseAwaitingDisable(*p);
    if(verified&&!record->error.empty()){error="failed SSH transition requires manual resolution";return false;}
    p->transition->runtimeFacts=facts;
    if(verified) {
        if(!awaiting)p->transition->phase=p->transition->intent==SshTransitionIntent::Release&&facts.count("offline")&&facts.at("offline")=="true"?
            SshTransitionPhase::OfflineVerified:SshTransitionPhase::RuntimeVerified;
    } else if(awaiting)p->transition->phase=SshTransitionPhase::DurablePublished;
    return persistSshChange(previous,error);
}
bool MutationJournal::commitSshRefresh(MutationId id,std::string& error) {
    if(!usable()||!lifecycleInitialized_){error="SSH finalization requires healthy journal";return false;}
    auto* record=find(id);auto* p=record?std::get_if<UndoRemoveSshManagedPolicy>(&record->undo.payload):nullptr;
    if(!p||!p->transition||record->status!=MutationStatus::Prepared||p->transition->phase!=SshTransitionPhase::RuntimeVerified||p->transition->intent!=SshTransitionIntent::Refresh||!record->error.empty()) {
        error="SSH refresh cannot commit without verified runtime";return false;
    }
    const MutationRecord previous=*record;
    const auto target=p->transition->target;
    p->appliedValue=target.value;p->disabledMutationIds=target.disabledIds;
    p->ownershipVersion=target.ownershipVersion;p->wrapperFingerprints=target.wrapperFingerprints;
    p->transition->phase=SshTransitionPhase::Completed;record->status=MutationStatus::Applied;record->error.clear();
    return persistSshChange(previous,error);
}
bool MutationJournal::failSshTransition(MutationId id,const std::string& diagnostic,std::string& error) {
    if(!usable()||!lifecycleInitialized_){error="SSH failure checkpoint requires healthy journal";return false;}
    auto* record=find(id);auto* p=record?std::get_if<UndoRemoveSshManagedPolicy>(&record->undo.payload):nullptr;
    if(!p||!sshTransitionPending(*p)||record->status!=MutationStatus::Prepared||diagnostic.empty()||diagnostic.size()>4096) {
        error="SSH failure checkpoint has no unresolved transition";return false;
    }
    const MutationRecord previous=*record;
    if(sshReleaseAwaitingDisable(*p))p->transition->phase=SshTransitionPhase::DurablePublished;
    record->error=diagnostic;
    return persistSshChange(previous,error);
}
bool MutationJournal::abortSshTransitionNoEffect(MutationId id,std::string& error) {
    if(!usable()||!lifecycleInitialized_){error="SSH no-effect abort requires healthy journal";return false;}
    auto* record=find(id);auto* p=record?std::get_if<UndoRemoveSshManagedPolicy>(&record->undo.payload):nullptr;
    if(!p||!p->transition||record->status!=MutationStatus::Prepared||p->transition->phase!=SshTransitionPhase::Prepared||
       p->transition->publication||!p->transition->runtimeFacts.empty()) {
        error="SSH abort refused: publication/service effect is possible; manual recovery required";return false;
    }
    const MutationRecord previous=*record;
    // Clear only the no-effect attempted transition; old permission/record ID
    // remains. Never infer a previous value from current filesystem bytes.
    if(p->transition->intent==SshTransitionIntent::Release) {
        record->status=p->transition->predecessorStatus;record->error=p->transition->predecessorError;
    } else {record->status=MutationStatus::Applied;record->error.clear();}
    p->transition.reset();
    return persistSshChange(previous,error);
}

bool MutationJournal::setStatus(MutationId id, MutationStatus status,
                                std::string& error) {
    return setStatusWithMessage(id, status, std::string(), error);
}

bool MutationJournal::setStatusWithMessage(MutationId id, MutationStatus status,
                                           const std::string& message,
                                           std::string& error) {
    if (!loaded_) {
        error = "Mutation journal не загружен";
        return false;
    }
    if (health_ == JournalHealth::Indeterminate) {
        error = "Mutation journal в состоянии Indeterminate: результат "
                "последней persist-операции не был надёжно завершён; "
                "требуется успешный reload journal";
        return false;
    }
    MutationRecord* record = find(id);
    if (record == nullptr) {
        error = "Mutation record не найден: " + std::to_string(id);
        return false;
    }
    if(const auto* ssh=std::get_if<UndoRemoveSshManagedPolicy>(&record->undo.payload);ssh&&sshTransitionPending(*ssh)) {
        error="SSH transition requires typed completion/no-effect abort; manual recovery for unresolved effects";return false;
    }
    const MutationRecord previous = *record;
    record->status = status;
    if (status == MutationStatus::Applied) {
        if (auto* global = std::get_if<UndoReleaseSudoGlobalDefault>(&record->undo.payload))
            global->previousLine.clear();
    }
    if ((record->undo.backend == MutationBackend::Desktop ||
         std::holds_alternative<UndoRestoreDesktopScalar>(record->undo.payload) ||
         std::holds_alternative<UndoOwnDesktopArtifact>(record->undo.payload)) &&
        !validDesktopRecord(*record, error)) {
        *record = previous;
        return false;
    }
    if (record->undo.backend == MutationBackend::Scope &&
        !validScopeRecord(*record, error)) {
        *record = previous;
        return false;
    }
    if ((record->undo.backend == MutationBackend::DisplayManager || std::holds_alternative<UndoRemoveDisplayManagerBlock>(record->undo.payload)) &&
        !validDmRecord(*record, error)) { *record = previous; return false; }
    if(!validSshRecord(*record,error)){*record=previous;return false;}
    record->error = message;
    record->updatedAtEpoch = currentEpochSeconds();
    const PersistOutcome outcome = persist(error);
    if (outcome == PersistOutcome::Persisted) {
        return true;
    }
    if (outcome == PersistOutcome::NotInstalled) {
        // Pre-install persist failure: the persistent journal definitely
        // still holds the previous document, so the journal keeps its
        // pre-operation logical state and retries still see the original
        // active record (fail closed).
        *record = previous;
        return false;
    }
    // Indeterminate: the new document already occupies the journal target.
    // Keep the in-memory record identical to the installed document and fail
    // closed until a successful load() re-parses the disk.
    health_ = JournalHealth::Indeterminate;
    return false;
}

bool MutationJournal::discard(MutationId id, std::string& error) {
    if (!loaded_) {
        error = "Mutation journal не загружен";
        return false;
    }
    if (health_ == JournalHealth::Indeterminate) {
        error = "Mutation journal в состоянии Indeterminate: результат "
                "последней persist-операции не был надёжно завершён; "
                "требуется успешный reload journal";
        return false;
    }
    for (std::size_t index = 0; index < records_.size(); ++index) {
        if (records_[index].id == id) {
            if(const auto* ssh=std::get_if<UndoRemoveSshManagedPolicy>(&records_[index].undo.payload);ssh&&sshTransitionPending(*ssh)) {
                error="cannot discard unresolved SSH ownership transition";return false;
            }
            const MutationRecord removed = records_[index];
            records_.erase(records_.begin() +
                           static_cast<std::ptrdiff_t>(index));
            const PersistOutcome outcome = persist(error);
            if (outcome == PersistOutcome::Persisted) {
                return true;
            }
            if (outcome == PersistOutcome::NotInstalled) {
                // Restore the record at its original position: the journal
                // must stay logically identical (including record ordering)
                // to the state before the failed operation; the persistent
                // journal definitely still holds the previous document.
                records_.insert(records_.begin() +
                                    static_cast<std::ptrdiff_t>(index),
                                removed);
                return false;
            }
            // Indeterminate: keep the removal (it matches the installed
            // document) and fail closed until a successful load().
            health_ = JournalHealth::Indeterminate;
            return false;
        }
    }
    error = "Mutation record не найден: " + std::to_string(id);
    return false;
}

std::vector<MutationRecord> MutationJournal::activeRecords(
    const PolicyRef& policy) const {
    std::vector<MutationRecord> result;
    for (const MutationRecord& record : records_) {
        if (record.isActive() && record.policy == policy) {
            result.push_back(record);
        }
    }
    return result;
}

void MutationJournal::setLoadAfterCaptureHookForTests(
    std::function<void()> hook) {
    loadAfterCaptureHook() = std::move(hook);
}

void MutationJournal::setBeforeVirginJournalInstallHookForTests(
    std::function<void()> hook) {
    beforeVirginJournalInstallHook() = std::move(hook);
}

void MutationJournal::setBeforeFinalJournalProofHookForTests(
    std::function<void()> hook) {
    beforeFinalJournalProofHook() = std::move(hook);
}

} // namespace fic::rollback
