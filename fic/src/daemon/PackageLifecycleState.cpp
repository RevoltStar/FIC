#include "daemon/PackageLifecycleState.h"
#include <fic/core/fs/SecureStateFile.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <set>
#include <sys/stat.h>
namespace fic::daemon {
namespace {
using json = nlohmann::json;
bool compatible(PackageOperation op, PackagePhase phase) {
    const auto release = phase >= PackagePhase::Fencing && phase <= PackagePhase::ReleaseComplete;
    const auto installed = phase == PackagePhase::InstalledButFenced ||
        phase == PackagePhase::InfrastructureProven || phase == PackagePhase::Installed;
    switch (op) {
    case PackageOperation::Install: return phase == PackagePhase::Installing || installed;
    // Upgrade quiesces writers but NEVER releases policy ownership/PAM hooks.
    case PackageOperation::Upgrade: return phase==PackagePhase::Fencing ||
        phase==PackagePhase::Quiescent || phase == PackagePhase::Recovering || installed;
    case PackageOperation::Remove: return release || phase==PackagePhase::RemovedTombstone;
    case PackageOperation::Recover: return phase == PackagePhase::Recovering || installed;
    }
    return false;
}
bool validBootId(const std::string& id) {
    if (id.size()!=36) return false;
    for (std::size_t i=0;i<id.size();++i) {
        const bool dash=i==8 || i==13 || i==18 || i==23;
        const auto c=id[i];
        if (dash ? c!='-' : !((c>='0' && c<='9') || (c>='a' && c<='f'))) return false;
    }
    return true;
}
bool valid(const PackageLifecycleState& s) {
    return s.operationId.size() == 32 && std::all_of(s.operationId.begin(), s.operationId.end(),
        [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }) &&
        !s.packageVersion.empty() && s.packageVersion.size() <= 128 &&
        s.packageVersion.find_first_of("\r\n\0", 0, 3) == std::string::npos &&
        static_cast<unsigned>(s.operation) <= static_cast<unsigned>(PackageOperation::Recover) &&
        static_cast<unsigned>(s.phase) <= static_cast<unsigned>(PackagePhase::RemovedTombstone) &&
        compatible(s.operation, s.phase) &&
        (!structuralFinalizerFailure(s.lastFailure) || s.phase==PackagePhase::InstalledButFenced ||
         (s.operation==PackageOperation::Remove && s.phase==PackagePhase::ReleaseComplete)) &&
        static_cast<unsigned>(s.lastFailure)<=static_cast<unsigned>(FinalizerFailure::UnprovableOwnership) &&
        (s.lastAttemptBoot.empty() ? (s.lastAttemptMs==0 && s.lastFailure==FinalizerFailure::None) :
         validBootId(s.lastAttemptBoot));
}
std::string encode(const PackageLifecycleState& s) {
    return json{{"version",1},{"operation",static_cast<unsigned>(s.operation)},
        {"phase",static_cast<unsigned>(s.phase)},{"id",s.operationId},
        {"package_version",s.packageVersion},{"generation",s.generation},
        {"attempt_boot",s.lastAttemptBoot},{"attempt_ms",s.lastAttemptMs},
        {"failure",static_cast<unsigned>(s.lastFailure)}}.dump() + "\n";
}
bool parentTrusted(const std::filesystem::path& path, std::string& error) {
    if (!path.is_absolute() || path.lexically_normal() != path) { error="invalid lifecycle path"; return false; }
    auto parent = path.parent_path();
    while (!parent.empty()) {
        struct stat st{};
        if (::lstat(parent.c_str(), &st) || !S_ISDIR(st.st_mode) || st.st_uid || (st.st_mode & 0022)) {
            error="lifecycle parent is not a trusted root-controlled directory"; return false;
        }
        if (parent == parent.root_path()) break;
        parent = parent.parent_path();
    }
    return true;
}
bool read(const std::filesystem::path& path, std::optional<PackageLifecycleState>& state,
          std::optional<AtomicTargetState>& snapshot, std::string& error) {
    state.reset(); snapshot.reset();
    if (!parentTrusted(path,error)) return false;
    fic::core::SecureStateFileExpectation options;
    options.owner=0; options.group=0; options.exactMode=0600;
    options.requireSingleLink=true; options.parentOwner=0;
    const auto result = fic::core::readSecureStateFile(path, options);
    if (result.status == fic::core::SecureStateReadStatus::Missing) {
        error.clear(); return true;
    }
    if (result.status != fic::core::SecureStateReadStatus::Proven) {
        error=result.detail; return false;
    }
    const auto& content=result.content;
    try {
        std::set<std::string> keys; bool duplicate=false;
        auto j=json::parse(content,[&](int, json::parse_event_t event, json& value) {
            if(event==json::parse_event_t::key && !keys.insert(value.get<std::string>()).second) duplicate=true;
            return true;
        });
        if (duplicate || !j.is_object() || j.size()!=9 ||
            !j.at("version").is_number_unsigned() || j.at("version")!=1 || !j.at("operation").is_number_unsigned() ||
            !j.at("phase").is_number_unsigned() || !j.at("generation").is_number_unsigned() ||
            !j.at("attempt_ms").is_number_unsigned() || !j.at("failure").is_number_unsigned())
            throw std::runtime_error("schema");
        const auto op=j.at("operation").get<unsigned long long>(), phase=j.at("phase").get<unsigned long long>();
        if(op>3 || phase>13) throw std::runtime_error("enum");
        PackageLifecycleState parsed{static_cast<PackageOperation>(op), static_cast<PackagePhase>(phase),
            j.at("id").get<std::string>(),j.at("package_version").get<std::string>(),j.at("generation").get<unsigned long>()};
        parsed.lastAttemptBoot=j.at("attempt_boot").get<std::string>();
        parsed.lastAttemptMs=j.at("attempt_ms").get<std::uint64_t>();
        const auto failure=j.at("failure").get<unsigned long long>();
        if(failure>static_cast<unsigned>(FinalizerFailure::UnprovableOwnership)) throw std::runtime_error("failure");
        parsed.lastFailure=static_cast<FinalizerFailure>(failure);
        if(!valid(parsed)) throw std::runtime_error("invalid provenance");
        state=std::move(parsed); snapshot=result.targetState; error.clear(); return true;
    } catch (...) {error="unknown or corrupt lifecycle fence";return false;}
}
bool transition(PackageOperation op, PackagePhase from, PackagePhase to) {
    if (!compatible(op, to)) return false;
    if (from==PackagePhase::Installing || from==PackagePhase::Recovering)
        return to==PackagePhase::InstalledButFenced;
    if (from==PackagePhase::InstalledButFenced) return to==PackagePhase::InfrastructureProven;
    if (from==PackagePhase::ReleaseComplete && op==PackageOperation::Remove)
        return to==PackagePhase::RemovedTombstone;
    if (from==PackagePhase::Quiescent && op==PackageOperation::Upgrade)
        return to==PackagePhase::Recovering;
    if (from==PackagePhase::Fencing) return to==PackagePhase::Quiescent;
    if (from==PackagePhase::Quiescent) return to==PackagePhase::DmReleased;
    if (from==PackagePhase::DmReleased) return to==PackagePhase::DeReleased;
    if (from==PackagePhase::DeReleased) return to==PackagePhase::ProviderReleased;
    if (from==PackagePhase::ProviderReleased) return to==PackagePhase::PasswordReleased;
    if (from==PackagePhase::PasswordReleased) return to==PackagePhase::HooksDetached;
    if (from==PackagePhase::HooksDetached) return to==PackagePhase::ReleaseComplete;
    if (from==PackagePhase::InfrastructureProven) return to==PackagePhase::Installed;
    return false;
}
AtomicWriteOptions writeOptions() {
    AtomicWriteOptions o; o.rejectSymlink=true; o.metadataPolicy=FileMetadataPolicy::EnforceProvided;
    o.fileOwner=0; o.fileGroup=0; o.fileMode=0600; return o;
}
}
bool PackageLifecycleStore::inspect(std::optional<PackageLifecycleState>& state,std::string& error) const {
    std::optional<AtomicTargetState> snapshot; return read(path_,state,snapshot,error);
}
bool PackageLifecycleStore::create(const DaemonInstanceLock& guard,const PackageLifecycleState& state,std::string& error) {
    if(!guard.heldByCurrentProcess() || !valid(state) || state.generation!=0 || !state.lastAttemptBoot.empty() ||
       (state.phase!=PackagePhase::Installing && state.phase!=PackagePhase::Fencing)) {
        error="lifecycle creation requires instance admission and initial typed provenance";return false;
    }
    if(!parentTrusted(path_,error)) return false;
    auto options=writeOptions();options.createIfMissing=true;options.exclusiveCreate=true;
    AtomicWriteResult result;
    return AtomicFileWriter::writeWithResult(path_.string(),encode(state),options,&error,&result) && result.durabilityConfirmed;
}
bool PackageLifecycleStore::begin(const DaemonInstanceLock& guard,
                                  const PackageLifecycleState& expected,
                                  const PackageLifecycleState& next,std::string& error) {
    const bool recovery = next.operation==PackageOperation::Recover && next.phase==PackagePhase::Recovering;
    const bool release = expected.phase==PackagePhase::Installed &&
        (next.operation==PackageOperation::Remove || next.operation==PackageOperation::Upgrade) &&
        next.phase==PackagePhase::Fencing;
    if (!guard.heldByCurrentProcess() || !valid(next) || next.generation!=0 || !next.lastAttemptBoot.empty() ||
        next.operationId==expected.operationId || (!recovery && !release)) {
        error="invalid new lifecycle operation/admission"; return false;
    }
    return replace(guard,expected,next,error);
}
bool structuralFinalizerFailure(FinalizerFailure failure) {
    return failure==FinalizerFailure::InvalidJournal || failure==FinalizerFailure::ManifestConflict ||
        failure==FinalizerFailure::UnprovableOwnership;
}
FinalizerAdmission PackageLifecycleStore::admitFinalizerAttempt(const DaemonInstanceLock& guard,
    const PackageLifecycleState& expected,const std::string& bootId,
    std::uint64_t bootTimeMs,std::string& error) {
    if (!guard.heldByCurrentProcess() || !valid(expected) || !validBootId(bootId)) {
        error="invalid finalizer admission/clock"; return FinalizerAdmission::Invalid;
    }
    // Always re-read under admission before any decision, including cheap skips.
    std::optional<PackageLifecycleState> current;
    if (!inspect(current,error) || !current || encode(*current)!=encode(expected)) {
        if(error.empty()) error="stale finalizer state";
        return FinalizerAdmission::Invalid;
    }
    error.clear();
    if (expected.phase==PackagePhase::Installed ||
        expected.phase==PackagePhase::RemovedTombstone)
        return FinalizerAdmission::Terminal;
    if (structuralFinalizerFailure(expected.lastFailure)) return FinalizerAdmission::Blocked;
    const bool removal=expected.operation==PackageOperation::Remove && expected.phase==PackagePhase::ReleaseComplete;
    if (expected.phase!=PackagePhase::InstalledButFenced && !removal) return FinalizerAdmission::WaitingForConfiguration;
    if (expected.lastAttemptBoot==bootId) {
        if (bootTimeMs<expected.lastAttemptMs) {
            error="finalizer boot clock moved backwards"; return FinalizerAdmission::Invalid;
        }
        if (bootTimeMs-expected.lastAttemptMs<FINALIZER_RETRY_INTERVAL_MS) return FinalizerAdmission::Cooldown;
    }
    auto next=expected; next.lastAttemptBoot=bootId; next.lastAttemptMs=bootTimeMs;
    // Prior failure retained until result; crash cannot turn Blocked into Waiting.
    if(expected.generation==~0UL) {error="lifecycle generation exhausted";return FinalizerAdmission::Invalid;}
    ++next.generation;
    return replace(guard,expected,next,error) ? FinalizerAdmission::Admitted : FinalizerAdmission::Invalid;
}
bool PackageLifecycleStore::recordFinalizerFailure(const DaemonInstanceLock& guard,
    const PackageLifecycleState& expected,FinalizerFailure failure,std::string& error) {
    const bool removal=expected.operation==PackageOperation::Remove && expected.phase==PackagePhase::ReleaseComplete;
    if (!valid(expected) || (expected.phase!=PackagePhase::InstalledButFenced && !removal) ||
        expected.lastAttemptBoot.empty() || failure==FinalizerFailure::None ||
        structuralFinalizerFailure(expected.lastFailure) || expected.generation==~0UL) {
        error="invalid finalizer failure result"; return false;
    }
    auto next=expected;next.lastFailure=failure;++next.generation;
    return replace(guard,expected,next,error);
}
bool PackageLifecycleStore::advance(const DaemonInstanceLock& guard,const PackageLifecycleState& expected,
                                     PackagePhase next,std::string& error) {
    if(!guard.heldByCurrentProcess() || !valid(expected) || !transition(expected.operation,expected.phase,next)) {error="invalid lifecycle transition/admission";return false;}
    if(expected.generation==~0UL || structuralFinalizerFailure(expected.lastFailure)) {
        error="blocked/exhausted lifecycle transition"; return false;
    }
    auto target=expected; target.phase=next; ++target.generation;
    if(next==PackagePhase::Installed || next==PackagePhase::RemovedTombstone)
        target.lastFailure=FinalizerFailure::None;
    return replace(guard,expected,target,error);
}
bool PackageLifecycleStore::replace(const DaemonInstanceLock& guard,
    const PackageLifecycleState& expected,PackageLifecycleState next,std::string& error) {
    if (!guard.heldByCurrentProcess() || !valid(next)) {error="invalid lifecycle replacement";return false;}
    std::optional<PackageLifecycleState> current;std::optional<AtomicTargetState> snapshot;
    if (!read(path_,current,snapshot,error)) return false;
    if (!current || encode(*current)!=encode(expected)) {error="stale lifecycle replacement";return false;}
    auto options=writeOptions();options.createIfMissing=false;options.expectedTargetState=snapshot;
    AtomicWriteResult result;
    return AtomicFileWriter::writeWithResult(path_.string(),encode(next),options,&error,&result) && result.durabilityConfirmed;
}

}
